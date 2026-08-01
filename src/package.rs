use crate::bytecode::{VmRecord, decode_const_pool, decode_function_records, read_plain_varint};
use crate::decode::{DecodedConstant, resolve_const_pool_operands};
use crate::llvm_ir::{ByteGlobal, LlModule};
use amice_vm::ProfilePackage;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::HashSet;

const PACKAGE_MAGIC: &[u8; 8] = b"AMICEVMP";
const PACKAGE_HEADER_LEN: usize = 64;
const PACKAGE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize)]
pub struct PackageRelocation {
    pub label: u64,
    pub pc: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodedPackage {
    pub fn_index: usize,
    pub function_name: String,
    pub global_name: String,
    pub version: u32,
    pub instruction_count: u32,
    pub bytecode_key: String,
    pub const_pool_offset: usize,
    pub const_pool_len: usize,
    pub code_offset: usize,
    pub code_len: usize,
    pub reloc_offset: usize,
    pub reloc_len: usize,
    pub const_pool: Vec<DecodedConstant>,
    pub relocations: Vec<PackageRelocation>,
}

#[derive(Debug, Clone)]
pub struct PackageReport {
    pub packages: Vec<DecodedPackage>,
    pub records: Vec<VmRecord>,
}

pub fn decode_packages(
    module: &LlModule,
    profile: &ProfilePackage,
    requested_global: Option<&str>,
) -> Result<PackageReport> {
    let package_globals = match requested_global {
        Some(name) => vec![
            module
                .byte_globals
                .iter()
                .find(|global| global.name == name)
                .with_context(|| format!("byte global {name} was not found"))?,
        ],
        None => module
            .byte_globals
            .iter()
            .filter(|global| global.bytes.starts_with(PACKAGE_MAGIC))
            .collect::<Vec<_>>(),
    };
    if package_globals.is_empty() {
        bail!("no AMICEVMP package globals found; use --global for markerless package bytes");
    }

    let mut packages = Vec::with_capacity(package_globals.len());
    let mut records = Vec::new();
    for (fn_index, global) in package_globals.into_iter().enumerate() {
        let (package, mut function_records) = decode_package_global(profile, fn_index, global)
            .with_context(|| format!("decode package global {}", global.name))?;
        records.append(&mut function_records);
        packages.push(package);
    }
    Ok(PackageReport { packages, records })
}

fn decode_package_global(
    profile: &ProfilePackage,
    fn_index: usize,
    global: &ByteGlobal,
) -> Result<(DecodedPackage, Vec<VmRecord>)> {
    let header = parse_package_header(&global.bytes)?;
    let const_pool_bytes =
        &global.bytes[header.const_pool_offset..header.const_pool_offset + header.const_pool_len];
    let const_pool = decode_const_pool(const_pool_bytes, header.bytecode_key)?;
    let code = &global.bytes[header.code_offset..header.code_offset + header.code_len];
    let mut records = decode_function_records(profile, fn_index, code, header.bytecode_key)?;
    if records.len() != header.instruction_count as usize {
        bail!(
            "header declares {} instructions but code decoded to {}",
            header.instruction_count,
            records.len()
        );
    }
    resolve_const_pool_operands(&mut records, &const_pool)?;

    let reloc_bytes = &global.bytes[header.reloc_offset..header.reloc_offset + header.reloc_len];
    let relocations = decode_relocations(reloc_bytes, &records, header.code_len)?;
    let function_name = global
        .name
        .strip_prefix(".amice.vm.bytecode.")
        .unwrap_or(&global.name)
        .to_owned();
    let package = DecodedPackage {
        fn_index,
        function_name,
        global_name: global.name.clone(),
        version: header.version,
        instruction_count: header.instruction_count,
        bytecode_key: format!("0x{:016x}", header.bytecode_key),
        const_pool_offset: header.const_pool_offset,
        const_pool_len: header.const_pool_len,
        code_offset: header.code_offset,
        code_len: header.code_len,
        reloc_offset: header.reloc_offset,
        reloc_len: header.reloc_len,
        const_pool: const_pool
            .into_iter()
            .enumerate()
            .map(|(index, value)| DecodedConstant {
                index,
                value: format!("0x{value:016x}"),
            })
            .collect(),
        relocations,
    };
    Ok((package, records))
}

#[derive(Debug, Clone, Copy)]
struct PackageHeader {
    version: u32,
    instruction_count: u32,
    bytecode_key: u64,
    const_pool_offset: usize,
    const_pool_len: usize,
    code_offset: usize,
    code_len: usize,
    reloc_offset: usize,
    reloc_len: usize,
}

fn parse_package_header(bytes: &[u8]) -> Result<PackageHeader> {
    if bytes.len() < PACKAGE_HEADER_LEN {
        bail!(
            "bytecode package has {} bytes, shorter than {}-byte header",
            bytes.len(),
            PACKAGE_HEADER_LEN
        );
    }
    let version = read_u32(bytes, 8)?;
    if version != PACKAGE_VERSION {
        bail!("unsupported bytecode package version {version}");
    }
    if read_u32(bytes, 12)? != 0 || read_u32(bytes, 20)? != 0 || read_u64(bytes, 56)? != 0 {
        bail!("bytecode package reserved header fields are not zero");
    }
    let header = PackageHeader {
        version,
        instruction_count: read_u32(bytes, 16)?,
        bytecode_key: read_u64(bytes, 24)?,
        const_pool_offset: read_u32(bytes, 32)? as usize,
        const_pool_len: read_u32(bytes, 36)? as usize,
        code_offset: read_u32(bytes, 40)? as usize,
        code_len: read_u32(bytes, 44)? as usize,
        reloc_offset: read_u32(bytes, 48)? as usize,
        reloc_len: read_u32(bytes, 52)? as usize,
    };
    let code_offset = header
        .const_pool_offset
        .checked_add(header.const_pool_len)
        .context("const_pool range overflow")?;
    let reloc_offset = header
        .code_offset
        .checked_add(header.code_len)
        .context("code range overflow")?;
    let package_end = header
        .reloc_offset
        .checked_add(header.reloc_len)
        .context("reloc range overflow")?;
    if header.const_pool_offset != PACKAGE_HEADER_LEN
        || header.code_offset != code_offset
        || header.reloc_offset != reloc_offset
        || package_end != bytes.len()
    {
        bail!(
            "package segments are not contiguous: const_pool={}+{}, code={}+{}, reloc={}+{}, total={}",
            header.const_pool_offset,
            header.const_pool_len,
            header.code_offset,
            header.code_len,
            header.reloc_offset,
            header.reloc_len,
            bytes.len()
        );
    }
    Ok(header)
}

fn decode_relocations(
    bytes: &[u8],
    records: &[VmRecord],
    code_len: usize,
) -> Result<Vec<PackageRelocation>> {
    let mut cursor = 0_usize;
    let count = usize::try_from(read_plain_varint(bytes, &mut cursor)?)
        .context("relocation count does not fit usize")?;
    if count > bytes.len().saturating_sub(cursor) / 2 {
        bail!(
            "relocation segment declares {count} entries in {} bytes",
            bytes.len()
        );
    }
    let record_pcs = records
        .iter()
        .map(|record| record.pc)
        .collect::<HashSet<_>>();
    let mut relocations = Vec::with_capacity(count);
    let mut previous_label = None;
    for _ in 0..count {
        let label = read_plain_varint(bytes, &mut cursor)?;
        let pc = read_plain_varint(bytes, &mut cursor)?;
        if previous_label.is_some_and(|previous| label <= previous) {
            bail!("relocation labels are not strictly increasing");
        }
        let pc_usize = usize::try_from(pc).context("relocation pc does not fit usize")?;
        if pc_usize != code_len && !record_pcs.contains(&pc_usize) {
            bail!("relocation label {label} targets non-record pc {pc}");
        }
        previous_label = Some(label);
        relocations.push(PackageRelocation { label, pc });
    }
    if cursor != bytes.len() {
        bail!(
            "relocation table decoded {} of {} bytes",
            cursor,
            bytes.len()
        );
    }
    Ok(relocations)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .context("truncated u32 package header field")?
        .try_into()
        .expect("slice length checked");
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let raw: [u8; 8] = bytes
        .get(offset..offset + 8)
        .context("truncated u64 package header field")?
        .try_into()
        .expect("slice length checked");
    Ok(u64::from_le_bytes(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use amice_vm::bytecode::BytecodeEncoder;
    use amice_vm::lowering::{VmFunctionBuilder, VmInstruction};

    #[test]
    fn decodes_encoder_package_header_pool_code_and_relocations() {
        let profile = ProfilePackage::builtin_test().unwrap();
        let mut builder = VmFunctionBuilder::new("package_fixture", 1, 64);
        builder.push(VmInstruction::ConstLoad {
            dst: 0,
            value: 0x1234_5678_9abc_def0,
            width: 64,
        });
        builder.push(VmInstruction::Ret { src: 0 });
        let function = builder.finish().unwrap();
        let image = BytecodeEncoder::new(&profile).encode(&function).unwrap();
        let global = ByteGlobal {
            name: ".amice.vm.bytecode.package_fixture".to_owned(),
            len: image.bytes.len(),
            bytes: image.bytes,
            section: None,
        };

        let (package, records) = decode_package_global(&profile, 0, &global).unwrap();
        assert_eq!(package.bytecode_key, format!("0x{:016x}", image.key));
        assert_eq!(package.const_pool[0].value, "0x123456789abcdef0");
        assert_eq!(records.len(), image.instruction_count as usize);
        assert_eq!(records[0].mnemonic, "const_load");
    }

    #[test]
    fn rejects_non_contiguous_package_segments() {
        let mut bytes = vec![0_u8; PACKAGE_HEADER_LEN + 3];
        bytes[..8].copy_from_slice(PACKAGE_MAGIC);
        bytes[8..12].copy_from_slice(&PACKAGE_VERSION.to_le_bytes());
        bytes[32..36].copy_from_slice(&(PACKAGE_HEADER_LEN as u32).to_le_bytes());
        bytes[36..40].copy_from_slice(&1_u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&66_u32.to_le_bytes());
        bytes[44..48].copy_from_slice(&1_u32.to_le_bytes());
        bytes[48..52].copy_from_slice(&67_u32.to_le_bytes());

        assert!(parse_package_header(&bytes).is_err());
    }
}
