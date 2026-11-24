use crate::crypto::{obfuscated_fn_token, obfuscated_fn_token_parts};
use crate::decode::DecodeReport;
use crate::pe::SectionView;
use crate::pe_symbols::PeSymbolMap;
use amice_vm::isa::HandlerSemantic;
use anyhow::{Context, Result};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use object::endian::LittleEndian as LE;
use object::pe;
use object::read::pe::PeFile64;
use object::{NameOrOrdinal, Object, read::ExportTarget};
use std::collections::HashMap;

const MAX_THUNK_BYTES: usize = 512;

pub(crate) fn resolve_wrappers(
    sections: &[SectionView<'_>],
    image_base: u64,
    report: &mut DecodeReport,
) {
    let ranges = runtime_function_ranges(sections, image_base);
    for descriptor in &mut report.descriptors {
        let token = obfuscated_fn_token(report.descriptor_seed, descriptor.fn_index);
        let [split_a, split_b] =
            obfuscated_fn_token_parts(report.descriptor_seed, descriptor.fn_index);
        let expected = [token, token.rotate_right(13), split_a, split_b];
        let mut matches = HashMap::<u64, u8>::new();
        for section in sections.iter().filter(|section| section.executable) {
            let mut decoder =
                Decoder::with_ip(64, section.data, section.address, DecoderOptions::NONE);
            while decoder.can_decode() {
                let instruction = decoder.decode();
                let mut flags = 0_u8;
                for index in 0..instruction.op_count() {
                    if !is_immediate(instruction.op_kind(index)) {
                        continue;
                    }
                    let value = instruction.immediate(index);
                    for (expected_index, expected_value) in expected.iter().enumerate() {
                        if value == *expected_value {
                            flags |= 1 << expected_index;
                        }
                    }
                }
                if flags == 0 {
                    continue;
                }
                let wrapper = ranges
                    .iter()
                    .find(|(start, end)| instruction.ip() >= *start && instruction.ip() < *end)
                    .map(|(start, _)| *start)
                    .or_else(|| padded_function_start(*section, instruction.ip()))
                    .unwrap_or(instruction.ip());
                *matches.entry(wrapper).or_default() |= flags;
            }
        }
        let mut wrappers = matches
            .into_iter()
            .filter_map(|(wrapper, flags)| {
                (flags & 0b0011 != 0 || flags & 0b1100 == 0b1100).then_some(wrapper)
            })
            .collect::<Vec<_>>();
        wrappers.sort_unstable();
        if let [wrapper] = wrappers.as_slice() {
            descriptor.wrapper_va = Some(format!("0x{wrapper:016x}"));
            descriptor.function_name = Some(format!("sub_{wrapper:016x}"));
        }
    }
}

fn padded_function_start(section: SectionView<'_>, address: u64) -> Option<u64> {
    let offset = usize::try_from(address.checked_sub(section.address)?).ok()?;
    let floor = offset.saturating_sub(1024);
    if let Some(start) = (floor..offset)
        .rev()
        .find(|index| {
            *index >= 2
                && section.data[*index] != 0xcc
                && section.data[*index - 1] == 0xcc
                && section.data[*index - 2] == 0xcc
        })
        .map(|index| section.address + index as u64)
    {
        return Some(start);
    }
    let mut candidate = offset & !0xf;
    loop {
        let mut decoder = Decoder::with_ip(
            64,
            section.data.get(candidate..)?,
            section.address + candidate as u64,
            DecoderOptions::NONE,
        );
        let first = decoder.decode();
        let stack_frame = (first.mnemonic() == Mnemonic::Sub
            && first.op0_kind() == OpKind::Register
            && first.op0_register().full_register() == Register::RSP)
            || first.mnemonic() == Mnemonic::Push;
        if stack_frame {
            return Some(section.address + candidate as u64);
        }
        if candidate < floor + 16 {
            return None;
        }
        candidate -= 16;
    }
}

#[derive(Debug, Clone)]
struct ResolvedCall {
    name: String,
    evidence: String,
}

pub(crate) fn resolve_native_targets(
    bytes: &[u8],
    sections: &[SectionView<'_>],
    report: &mut DecodeReport,
) -> Result<()> {
    let file = object::File::parse(bytes).context("parse PE symbols")?;
    let imports = import_map(bytes, file.relative_address_base())?;
    let exports = export_map(&file)?;

    for descriptor in &mut report.descriptors {
        for native in &mut descriptor.native_targets {
            let Some(thunk) = native.thunk.as_deref().and_then(parse_hex) else {
                continue;
            };
            if let Some(call) = resolve_thunk(thunk, sections, &imports, &exports) {
                native.callee = Some(call.name);
                native.resolution = Some(call.evidence);
            }
        }
    }

    refresh_native_operands(report);
    Ok(())
}

pub(crate) fn apply_symbol_names(report: &mut DecodeReport, symbols: &PeSymbolMap) {
    for descriptor in &mut report.descriptors {
        if let Some(address) = descriptor.wrapper_va.as_deref().and_then(parse_hex)
            && let Some(name) = symbols.name_at(address)
        {
            descriptor.function_name = Some(name);
        }
        for native in &mut descriptor.native_targets {
            let Some(address) = native
                .callee
                .as_deref()
                .and_then(|name| name.strip_prefix("sub_"))
                .and_then(|value| u64::from_str_radix(value, 16).ok())
            else {
                continue;
            };
            if let Some(name) = symbols.name_at(address) {
                native.callee = Some(name);
                let previous = native.resolution.take().unwrap_or_default();
                native.resolution = Some(if previous.is_empty() {
                    "pdb".to_owned()
                } else {
                    format!("{previous}+pdb")
                });
            }
        }
    }
    refresh_native_operands(report);
}

fn runtime_function_ranges(sections: &[SectionView<'_>], image_base: u64) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    for section in sections.iter().filter(|section| section.name == ".pdata") {
        let (entries, _) = section.data.as_chunks::<12>();
        for entry in entries {
            let begin = u32::from_le_bytes(entry[0..4].try_into().expect("four-byte RVA"));
            let end = u32::from_le_bytes(entry[4..8].try_into().expect("four-byte RVA"));
            if begin < end {
                ranges.push((image_base + u64::from(begin), image_base + u64::from(end)));
            }
        }
    }
    ranges
}

fn refresh_native_operands(report: &mut DecodeReport) {
    for record in &mut report.records {
        if record.semantic != HandlerSemantic::CallNative {
            continue;
        }
        let Some(callee) = record
            .operands
            .iter_mut()
            .find(|operand| operand.name == "callee")
        else {
            continue;
        };
        let Ok(local_index) = usize::try_from(callee.value) else {
            continue;
        };
        if let Some(name) = report
            .descriptors
            .get(record.fn_index)
            .and_then(|descriptor| descriptor.native_targets.get(local_index))
            .and_then(|native| native.callee.as_ref())
        {
            callee.resolved = Some(name.clone());
        }
    }
}

fn resolve_thunk(
    thunk: u64,
    sections: &[SectionView<'_>],
    imports: &HashMap<u64, String>,
    exports: &HashMap<u64, String>,
) -> Option<ResolvedCall> {
    let section = sections
        .iter()
        .find(|section| section.executable && contains_va(**section, thunk))?;
    let offset = usize::try_from(thunk - section.address).ok()?;
    let end = section.data.len().min(offset + MAX_THUNK_BYTES);
    let mut decoder = Decoder::with_ip(64, &section.data[offset..end], thunk, DecoderOptions::NONE);
    let mut values = HashMap::<Register, u64>::new();

    while decoder.can_decode() {
        let instruction = decoder.decode();
        if let Some((target, evidence)) = call_target(&instruction, &values, sections, imports) {
            let name = target_name(target, sections, imports, exports);
            return Some(ResolvedCall { name, evidence });
        }
        update_values(&instruction, sections, &mut values);
        if instruction.mnemonic() == Mnemonic::Ret {
            break;
        }
    }
    None
}

fn call_target(
    instruction: &Instruction,
    values: &HashMap<Register, u64>,
    sections: &[SectionView<'_>],
    imports: &HashMap<u64, String>,
) -> Option<(u64, String)> {
    if instruction.mnemonic() != Mnemonic::Call {
        return None;
    }
    match instruction.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some((instruction.near_branch_target(), "direct_call".to_owned()))
        }
        OpKind::Register => values
            .get(&instruction.op0_register().full_register())
            .copied()
            .map(|target| (target, "register_call".to_owned())),
        OpKind::Memory => {
            let address = memory_address(instruction, values)?;
            if imports.contains_key(&address) {
                return Some((address, "import_address_call".to_owned()));
            }
            read_u64(sections, address).map(|target| {
                let evidence = if instruction.memory_index_scale() == 8
                    && instruction.memory_index() != Register::None
                {
                    "amice_indirect_call_table"
                } else {
                    "indirect_call"
                };
                (target, evidence.to_owned())
            })
        }
        _ => None,
    }
}

fn update_values(
    instruction: &Instruction,
    sections: &[SectionView<'_>],
    values: &mut HashMap<Register, u64>,
) {
    if instruction.op0_kind() != OpKind::Register {
        return;
    }
    let destination = instruction.op0_register().full_register();
    let value = match instruction.mnemonic() {
        Mnemonic::Mov => match instruction.op1_kind() {
            OpKind::Register => values
                .get(&instruction.op1_register().full_register())
                .copied(),
            kind if is_immediate(kind) => Some(instruction.immediate(1)),
            OpKind::Memory if instruction.is_ip_rel_memory_operand() => {
                read_u64(sections, instruction.ip_rel_memory_address())
            }
            _ => None,
        },
        Mnemonic::Movsxd => {
            if instruction.op1_kind() == OpKind::Memory && instruction.is_ip_rel_memory_operand() {
                read_u32(sections, instruction.ip_rel_memory_address())
                    .map(|value| i64::from(value as i32) as u64)
            } else {
                None
            }
        }
        Mnemonic::Lea => {
            if instruction.op1_kind() == OpKind::Memory {
                memory_address(instruction, values)
            } else {
                None
            }
        }
        Mnemonic::Xor => match instruction.op1_kind() {
            OpKind::Register => {
                let source = instruction.op1_register().full_register();
                if source == destination {
                    Some(0)
                } else {
                    values
                        .get(&destination)
                        .zip(values.get(&source))
                        .map(|(left, right)| left ^ right)
                }
            }
            kind if is_immediate(kind) => values
                .get(&destination)
                .map(|left| left ^ instruction.immediate(1)),
            _ => None,
        },
        Mnemonic::Add => immediate_rhs(instruction).and_then(|right| {
            values
                .get(&destination)
                .map(|left| left.wrapping_add(right))
        }),
        Mnemonic::Sub => immediate_rhs(instruction).and_then(|right| {
            values
                .get(&destination)
                .map(|left| left.wrapping_sub(right))
        }),
        _ => None,
    };
    if let Some(value) = value {
        values.insert(destination, value);
    } else {
        values.remove(&destination);
    }
}

fn target_name(
    target: u64,
    sections: &[SectionView<'_>],
    imports: &HashMap<u64, String>,
    exports: &HashMap<u64, String>,
) -> String {
    if let Some(name) = imports.get(&target) {
        return name.clone();
    }
    if let Some(name) = exports.get(&target) {
        return name.clone();
    }
    if let Some(name) = import_thunk_name(target, sections, imports) {
        return name;
    }
    format!("sub_{target:016x}")
}

fn import_thunk_name(
    target: u64,
    sections: &[SectionView<'_>],
    imports: &HashMap<u64, String>,
) -> Option<String> {
    let section = sections
        .iter()
        .find(|section| section.executable && contains_va(**section, target))?;
    let offset = usize::try_from(target - section.address).ok()?;
    let bytes = section
        .data
        .get(offset..section.data.len().min(offset + 24))?;
    let mut decoder = Decoder::with_ip(64, bytes, target, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.mnemonic() != Mnemonic::Jmp
        || instruction.op0_kind() != OpKind::Memory
        || !instruction.is_ip_rel_memory_operand()
    {
        return None;
    }
    imports.get(&instruction.ip_rel_memory_address()).cloned()
}

fn import_map(bytes: &[u8], image_base: u64) -> Result<HashMap<u64, String>> {
    let file = PeFile64::parse(bytes).context("parse PE import directory")?;
    let Some(table) = file.import_table().context("read PE import table")? else {
        return Ok(HashMap::new());
    };
    let mut result = HashMap::new();
    let mut descriptors = table.descriptors().context("read PE import descriptors")?;
    while let Some(descriptor) = descriptors.next().context("read PE import descriptor")? {
        let library = String::from_utf8_lossy(table.name(descriptor.name.get(LE))?).into_owned();
        let lookup = match descriptor.original_first_thunk.get(LE) {
            0 => descriptor.first_thunk.get(LE),
            value => value,
        };
        let iat = descriptor.first_thunk.get(LE);
        let mut thunks = table.thunks(lookup).context("read PE import thunks")?;
        let mut index = 0_u64;
        while let Some(thunk) = thunks
            .next::<pe::ImageNtHeaders64>()
            .context("read PE import thunk")?
        {
            let name = match table
                .import::<pe::ImageNtHeaders64>(thunk)
                .context("read PE import name")?
            {
                object::read::pe::Import::Name(_, name) => {
                    String::from_utf8_lossy(name).into_owned()
                }
                object::read::pe::Import::Ordinal(ordinal) => format!("#{ordinal}"),
            };
            result.insert(
                image_base + u64::from(iat) + index * 8,
                format!("{library}!{name}"),
            );
            index += 1;
        }
    }
    Ok(result)
}

fn export_map(file: &object::File<'_>) -> Result<HashMap<u64, String>> {
    let mut result = HashMap::new();
    for export in file.exports().context("read PE exports")? {
        let export = export.context("read PE export")?;
        let ExportTarget::Address { address } = export.target() else {
            continue;
        };
        let name = match export.name() {
            NameOrOrdinal::Name(name) => String::from_utf8_lossy(name).into_owned(),
            NameOrOrdinal::Ordinal(ordinal) => format!("export#{ordinal}"),
        };
        result.insert(address, name);
    }
    Ok(result)
}

fn memory_address(instruction: &Instruction, values: &HashMap<Register, u64>) -> Option<u64> {
    if instruction.is_ip_rel_memory_operand() {
        return Some(instruction.ip_rel_memory_address());
    }
    let base = match instruction.memory_base() {
        Register::None => 0,
        register => *values.get(&register.full_register())?,
    };
    let index = match instruction.memory_index() {
        Register::None => 0,
        register => values
            .get(&register.full_register())?
            .wrapping_mul(instruction.memory_index_scale() as u64),
    };
    Some(
        base.wrapping_add(index)
            .wrapping_add(instruction.memory_displacement64()),
    )
}

fn read_u32(sections: &[SectionView<'_>], address: u64) -> Option<u32> {
    let bytes = read_va(sections, address, 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn read_u64(sections: &[SectionView<'_>], address: u64) -> Option<u64> {
    let bytes = read_va(sections, address, 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn read_va<'a>(sections: &'a [SectionView<'a>], address: u64, len: usize) -> Option<&'a [u8]> {
    let section = sections
        .iter()
        .find(|section| contains_range(**section, address, len))?;
    let offset = usize::try_from(address - section.address).ok()?;
    section.data.get(offset..offset + len)
}

fn contains_va(section: SectionView<'_>, address: u64) -> bool {
    contains_range(section, address, 1)
}

fn contains_range(section: SectionView<'_>, address: u64, len: usize) -> bool {
    address >= section.address
        && address
            .checked_add(len as u64)
            .is_some_and(|end| end <= section.address + section.data.len() as u64)
}

fn immediate_rhs(instruction: &Instruction) -> Option<u64> {
    is_immediate(instruction.op1_kind()).then(|| instruction.immediate(1))
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

fn parse_hex(value: &str) -> Option<u64> {
    u64::from_str_radix(value.strip_prefix("0x")?, 16).ok()
}
