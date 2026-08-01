use amice_vm::isa::{HandlerSemantic, InstructionDesc, OperandDesc, OperandKind};
use amice_vm::profile::{DecoderStep, OperandEncoding};
use amice_vm::{ProfilePackage, isa::Opcode};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VmOperand {
    pub name: String,
    pub kind: OperandKind,
    pub value_type: String,
    pub value: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VmRecord {
    pub fn_index: usize,
    pub pc: usize,
    pub opcode: u16,
    pub mnemonic: String,
    pub semantic: HandlerSemantic,
    pub operands: Vec<VmOperand>,
    pub decoded_width: u8,
}

pub fn decode_function_records(
    profile: &ProfilePackage,
    fn_index: usize,
    code: &[u8],
    bytecode_key: u64,
) -> Result<Vec<VmRecord>> {
    let mut records = Vec::new();
    let mut pc = 0_usize;

    while pc < code.len() {
        let mut cursor = pc;
        let opcode = read_varint(profile, code, bytecode_key, &mut cursor)
            .with_context(|| format!("decode opcode at fn {fn_index} pc {pc}"))?;
        let desc = profile.isa.by_opcode(opcode as Opcode).with_context(|| {
            format!("opcode 0x{opcode:x} at fn {fn_index} pc {pc} is not in profile ISA")
        })?;
        let next_pc = pc
            .checked_add(desc.decoded_width as usize)
            .context("VM record offset overflow")?;
        if next_pc > code.len() {
            bail!(
                "{} at fn {} pc {} has decoded_width {} beyond code_len {}",
                desc.name,
                fn_index,
                pc,
                desc.decoded_width,
                code.len()
            );
        }
        if cursor > next_pc {
            bail!(
                "{} opcode at fn {} pc {} exceeds decoded_width {}",
                desc.name,
                fn_index,
                pc,
                desc.decoded_width
            );
        }
        let operands = read_operands(profile, desc, code, bytecode_key, &mut cursor, next_pc)
            .with_context(|| {
                format!("decode operands for {} at fn {fn_index} pc {pc}", desc.name)
            })?;
        for (padding_offset, raw) in code.iter().enumerate().take(next_pc).skip(cursor) {
            let decoded = decode_stream_byte(profile, *raw, bytecode_key, padding_offset);
            if decoded != 0 {
                bail!(
                    "{} at fn {} pc {} has non-zero decoded padding at offset {}",
                    desc.name,
                    fn_index,
                    pc,
                    padding_offset
                );
            }
        }
        records.push(VmRecord {
            fn_index,
            pc,
            opcode: opcode as u16,
            mnemonic: desc.name.clone(),
            semantic: desc.semantic.clone(),
            operands,
            decoded_width: desc.decoded_width,
        });
        pc = next_pc;
    }

    let record_pcs = records
        .iter()
        .map(|record| record.pc)
        .collect::<HashSet<_>>();
    for record in &mut records {
        for operand in &mut record.operands {
            if operand.kind != OperandKind::Label {
                continue;
            }
            let target = usize::try_from(operand.value)
                .with_context(|| format!("label target {} does not fit usize", operand.value))?;
            if target != code.len() && !record_pcs.contains(&target) {
                bail!(
                    "{} at fn {} pc {} targets non-record pc {}",
                    record.mnemonic,
                    fn_index,
                    record.pc,
                    operand.value
                );
            }
            operand.resolved = Some(format!("pc_{target:04x}"));
        }
    }

    Ok(records)
}

fn read_operands(
    profile: &ProfilePackage,
    desc: &InstructionDesc,
    code: &[u8],
    bytecode_key: u64,
    cursor: &mut usize,
    record_end: usize,
) -> Result<Vec<VmOperand>> {
    if desc.operand_descs.len() != desc.operands as usize {
        bail!(
            "{} expected {} operands but desc carries {} declarations",
            desc.name,
            desc.operands,
            desc.operand_descs.len()
        );
    }

    let mut operands = Vec::with_capacity(desc.operand_descs.len());
    for operand_desc in &desc.operand_descs {
        let value = read_operand(profile, code, bytecode_key, cursor, record_end)?;
        validate_operand_value(operand_desc, value, &desc.name)?;
        operands.push(VmOperand {
            name: operand_desc.name.clone(),
            kind: operand_desc.kind.clone(),
            value_type: operand_desc.value_type.clone(),
            value,
            resolved: (operand_desc.kind == OperandKind::VReg).then(|| format!("x{value}")),
        });
    }
    Ok(operands)
}

fn read_operand(
    profile: &ProfilePackage,
    code: &[u8],
    bytecode_key: u64,
    cursor: &mut usize,
    record_end: usize,
) -> Result<u64> {
    match &profile.bytecode.instruction_record.operands {
        OperandEncoding::Bitpack { schema } if schema == "operand_stream" => {
            let bit_width = read_varint_until(profile, code, bytecode_key, cursor, record_end)?;
            if bit_width > 64 {
                bail!("bitpacked operand declares width {bit_width}");
            }
            let mut value = 0_u64;
            let mut shift = 0_u64;
            while shift < bit_width {
                let chunk =
                    read_varint_until(profile, code, bytecode_key, cursor, record_end)? & 0x7f;
                let remaining = bit_width - shift;
                if remaining < 7 && chunk >= (1_u64 << remaining) {
                    bail!("bitpacked operand has bits above declared width {bit_width}");
                }
                value |= chunk << shift;
                shift += 7;
            }
            Ok(value)
        }
        OperandEncoding::Bitpack { schema } => bail!("unsupported operand bitpack schema {schema}"),
    }
}

fn read_varint(
    profile: &ProfilePackage,
    code: &[u8],
    bytecode_key: u64,
    cursor: &mut usize,
) -> Result<u64> {
    read_varint_until(profile, code, bytecode_key, cursor, code.len())
}

fn read_varint_until(
    profile: &ProfilePackage,
    code: &[u8],
    bytecode_key: u64,
    cursor: &mut usize,
    limit: usize,
) -> Result<u64> {
    read_varint_from(cursor, limit, |offset| {
        decode_stream_byte(profile, code[offset], bytecode_key, offset)
    })
}

pub(crate) fn read_plain_varint(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    read_varint_from(cursor, bytes.len(), |offset| bytes[offset])
}

fn read_varint_from(
    cursor: &mut usize,
    limit: usize,
    mut decoded_byte_at: impl FnMut(usize) -> u8,
) -> Result<u64> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    loop {
        if *cursor >= limit {
            bail!("varint read ran past segment boundary");
        }
        let offset = *cursor;
        *cursor += 1;

        let decoded = decoded_byte_at(offset);
        let payload = u64::from(decoded & 0x7f);
        if shift == 63 && payload > 1 {
            bail!("varint exceeds u64 width");
        }
        value |= payload << shift;
        if decoded & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            bail!("varint exceeds u64 width");
        }
    }
}

pub fn decode_const_pool(bytes: &[u8], bytecode_key: u64) -> Result<Vec<u64>> {
    let mut cursor = 0_usize;
    let count = read_varint_from(&mut cursor, bytes.len(), |offset| {
        bytes[offset] ^ key_byte(bytecode_key, offset)
    })?;
    let count = usize::try_from(count).context("const_pool count does not fit usize")?;
    if count > bytes.len().saturating_sub(cursor) {
        bail!(
            "const_pool declares {count} values in {} bytes",
            bytes.len()
        );
    }

    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(read_varint_from(&mut cursor, bytes.len(), |offset| {
            bytes[offset] ^ key_byte(bytecode_key, offset)
        })?);
    }
    if cursor != bytes.len() {
        bail!("const_pool decoded {} of {} bytes", cursor, bytes.len());
    }
    Ok(values)
}

fn validate_operand_value(operand: &OperandDesc, value: u64, instruction_name: &str) -> Result<()> {
    match operand.kind {
        OperandKind::VReg if value > 31 => bail!(
            "{instruction_name} operand {} references x{value}, outside x0..x31",
            operand.name
        ),
        OperandKind::Imm => {
            let bits = immediate_value_bits(&operand.value_type)?;
            if bits < 64 && value >= (1_u64 << bits) {
                bail!(
                    "{instruction_name} operand {} value {value} does not fit {}",
                    operand.name,
                    operand.value_type
                );
            }
        }
        OperandKind::VReg
        | OperandKind::ConstPoolIndex
        | OperandKind::Label
        | OperandKind::Unknown => {}
    }
    Ok(())
}

fn immediate_value_bits(value_type: &str) -> Result<u32> {
    match value_type {
        "i1" | "u1" => Ok(1),
        "i7" | "u7" => Ok(7),
        "i8" | "u8" => Ok(8),
        "i16" | "u16" => Ok(16),
        "i32" | "u32" => Ok(32),
        "i64" | "u64" | "ptr" | "usize" | "label" | "const_pool_index" => Ok(64),
        other => bail!("unsupported immediate operand value type {other}"),
    }
}

pub fn decode_stream_byte(
    profile: &ProfilePackage,
    raw: u8,
    bytecode_key: u64,
    offset: usize,
) -> u8 {
    let mut decoded = raw;
    for step in &profile.decoder.steps {
        match step {
            DecoderStep::XorStream => decoded ^= key_byte(bytecode_key, offset),
            DecoderStep::AddStream => {
                decoded = decoded.wrapping_sub(key_byte(bytecode_key, offset))
            }
            DecoderStep::Rol { amount } => decoded = decoded.rotate_left(u32::from(*amount % 8)),
            DecoderStep::Ror { amount } => decoded = decoded.rotate_right(u32::from(*amount % 8)),
            DecoderStep::VarintDecode => break,
            DecoderStep::BitUnpack => {}
        }
    }
    decoded
}

pub fn key_byte(key: u64, index: usize) -> u8 {
    let index = index as u64;
    let rotate = ((index.wrapping_mul(13)) & 63) as u32;
    let index_rot = index.rotate_left(17);
    let mixed = key.rotate_left(rotate)
        ^ index.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ index_rot
        ^ (index >> 7);
    (mixed ^ (mixed >> 32) ^ (mixed >> 16) ^ (mixed >> 8)) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use amice_vm::ProfilePackage;

    #[test]
    fn key_byte_matches_known_formula() {
        assert_eq!(key_byte(0, 0), 0);
        assert_eq!(key_byte(0x1122_3344_5566_7788, 3), 0x27);
    }

    #[test]
    fn decodes_plain_padded_nop_record_from_builtin_profile() {
        let profile = ProfilePackage::builtin_test().unwrap();
        let nop = profile.isa.by_name("fake_nop").unwrap();
        let opcode = nop.opcode as u8;
        let mut code = vec![0_u8; nop.decoded_width as usize];
        code[0] = encode_stream_byte_for_test(&profile, opcode, 0, 0);

        let records = decode_function_records(&profile, 0, &code, 0).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].mnemonic, "fake_nop");
    }

    #[test]
    fn rejects_nonzero_record_padding() {
        let profile = ProfilePackage::builtin_test().unwrap();
        let nop = profile.isa.by_name("fake_nop").unwrap();
        let mut code = vec![0_u8; nop.decoded_width as usize];
        code[0] = encode_stream_byte_for_test(&profile, nop.opcode as u8, 0, 0);
        code[1] = encode_stream_byte_for_test(&profile, 1, 0, 1);

        let err = decode_function_records(&profile, 0, &code, 0).unwrap_err();
        assert!(err.to_string().contains("non-zero decoded padding"));
    }

    #[test]
    fn rejects_varint_above_u64() {
        let mut cursor = 0;
        let mut bytes = vec![0xff; 9];
        bytes.push(0x02);

        assert!(read_plain_varint(&bytes, &mut cursor).is_err());
    }

    #[test]
    fn rejects_trailing_const_pool_bytes() {
        assert!(decode_const_pool(&[0, 0], 0).is_err());
    }

    fn encode_stream_byte_for_test(
        profile: &ProfilePackage,
        decoded: u8,
        bytecode_key: u64,
        offset: usize,
    ) -> u8 {
        let mut encoded = decoded;
        let stop = profile
            .decoder
            .steps
            .iter()
            .position(|step| matches!(step, DecoderStep::VarintDecode))
            .unwrap_or(profile.decoder.steps.len());
        for step in profile.decoder.steps[..stop].iter().rev() {
            match step {
                DecoderStep::XorStream => encoded ^= key_byte(bytecode_key, offset),
                DecoderStep::AddStream => {
                    encoded = encoded.wrapping_add(key_byte(bytecode_key, offset))
                }
                DecoderStep::Rol { amount } => {
                    encoded = encoded.rotate_right(u32::from(*amount % 8))
                }
                DecoderStep::Ror { amount } => {
                    encoded = encoded.rotate_left(u32::from(*amount % 8))
                }
                DecoderStep::VarintDecode | DecoderStep::BitUnpack => {}
            }
        }
        encoded
    }
}
