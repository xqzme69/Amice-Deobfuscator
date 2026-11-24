use crate::pe::SectionView;
use crate::strings::{
    RecoveredString, StringAlgorithm, StringReport, recovered_bytes, wide_prefix,
};
use anyhow::{Result, bail};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};
use std::collections::{BTreeMap, HashMap};

const XOR_KEY: u8 = 0xaa;
const MIN_PLAIN_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeyByte {
    key: u8,
    instruction_va: u64,
}

#[derive(Debug, Clone, Copy)]
struct StackByte {
    value: u8,
    instruction_va: u64,
}

#[derive(Debug, Clone, Copy)]
struct RelativeByte {
    base: Register,
    displacement: i64,
    key: Option<u8>,
    instruction_va: u64,
    age: usize,
}

#[derive(Debug, Clone, Copy)]
struct RelativeKey {
    displacement: i64,
    key: u8,
    instruction_va: u64,
}

pub(crate) fn recover_pe_strings(sections: &[SectionView<'_>]) -> Result<StringReport> {
    let mut keys = BTreeMap::new();
    for section in sections.iter().filter(|section| section.executable) {
        collect_key_bytes(*section, sections, &mut keys)?;
    }
    collect_called_decryptors(sections, &mut keys)?;

    let mut evidence = Vec::new();
    if keys.is_empty() {
        let mut strings = recover_stack_containers(sections);
        if !strings.is_empty() {
            evidence.push("amice_stack_container_x86_64".to_owned());
        }
        let plain = recover_plain_sections(sections);
        if !plain.is_empty() {
            evidence.push("plain_pe_data".to_owned());
        }
        strings.extend(plain);
        for (index, string) in strings.iter_mut().enumerate() {
            string.literal_index = index;
        }
        return Ok(StringReport {
            algorithm: (!strings.is_empty()).then_some(StringAlgorithm::Plain),
            key_global: None,
            evidence,
            strings,
        });
    }

    let algorithm = if keys.values().all(|entry| entry.key == XOR_KEY) {
        extend_fixed_xor_sections(sections, &mut keys)?;
        StringAlgorithm::Xor
    } else {
        StringAlgorithm::SimdXor
    };
    evidence.push("x86_64_decrypt_writeback".to_owned());
    if algorithm == StringAlgorithm::Xor {
        evidence.push("amice_xor_key_aa".to_owned());
    } else {
        evidence.push("amice_simd_xor_key_bytes".to_owned());
    }

    Ok(StringReport {
        algorithm: Some(algorithm),
        key_global: None,
        evidence,
        strings: decode_key_runs(sections, &keys, algorithm)?,
    })
}

fn collect_called_decryptors(
    sections: &[SectionView<'_>],
    keys: &mut BTreeMap<u64, KeyByte>,
) -> Result<()> {
    let mut call_targets = std::collections::HashSet::new();
    for section in sections.iter().filter(|section| section.executable) {
        let mut decoder = Decoder::with_ip(64, section.data, section.address, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.mnemonic() == Mnemonic::Call
                && matches!(
                    instruction.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                )
            {
                call_targets.insert(instruction.near_branch_target());
            }
        }
    }

    let helpers = call_targets
        .into_iter()
        .filter_map(|target| {
            relative_decryptor(target, sections).map(|decryptor| (target, decryptor))
        })
        .collect::<HashMap<_, _>>();
    if helpers.is_empty() {
        return Ok(());
    }

    for section in sections.iter().filter(|section| section.executable) {
        let mut decoder = Decoder::with_ip(64, section.data, section.address, DecoderOptions::NONE);
        let mut addresses = HashMap::<Register, (u64, usize)>::new();
        while decoder.can_decode() {
            let instruction = decoder.decode();
            addresses.retain(|_, (_, age)| {
                *age += 1;
                *age <= 16
            });
            remember_call_address(&instruction, &mut addresses);
            if instruction.mnemonic() == Mnemonic::Call {
                if matches!(
                    instruction.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                ) && let Some(decryptor) = helpers.get(&instruction.near_branch_target())
                {
                    apply_relative_decryptor(decryptor, &addresses, sections, keys)?;
                }
                addresses.clear();
            } else if instruction.mnemonic() == Mnemonic::Ret
                || instruction.mnemonic() == Mnemonic::Jmp
                || instruction.is_jcc_short_or_near()
            {
                addresses.clear();
            }
        }
    }
    Ok(())
}

fn relative_decryptor(target: u64, sections: &[SectionView<'_>]) -> Option<Vec<RelativeKey>> {
    let section = sections
        .iter()
        .find(|section| section.executable && contains_range(**section, target, 1))?;
    let offset = usize::try_from(target - section.address).ok()?;
    let end = section.data.len().min(offset + 1024);
    let mut decoder =
        Decoder::with_ip(64, &section.data[offset..end], target, DecoderOptions::NONE);
    let mut bytes = HashMap::<Register, RelativeByte>::new();
    let mut keys = BTreeMap::<i64, RelativeKey>::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        bytes.retain(|_, value| {
            value.age += 1;
            value.age <= 8
        });
        if matches!(instruction.mnemonic(), Mnemonic::Mov | Mnemonic::Movzx)
            && instruction.op0_kind() == OpKind::Register
            && instruction.op1_kind() == OpKind::Memory
            && !instruction.is_ip_rel_memory_operand()
            && instruction.memory_index() == Register::None
            && instruction.memory_size().size() == 1
        {
            bytes.insert(
                instruction.op0_register().full_register(),
                RelativeByte {
                    base: instruction.memory_base().full_register(),
                    displacement: instruction.memory_displacement64() as i64,
                    key: None,
                    instruction_va: instruction.ip(),
                    age: 0,
                },
            );
        } else if instruction.mnemonic() == Mnemonic::Xor
            && instruction.op0_kind() == OpKind::Register
            && is_immediate(instruction.op1_kind())
        {
            if let Some(value) = bytes.get_mut(&instruction.op0_register().full_register()) {
                value.key = Some(instruction.immediate(1) as u8);
                value.age = 0;
            }
        } else if instruction.mnemonic() == Mnemonic::Mov
            && instruction.op0_kind() == OpKind::Memory
            && instruction.op1_kind() == OpKind::Register
            && !instruction.is_ip_rel_memory_operand()
            && instruction.memory_index() == Register::None
            && instruction.memory_size().size() == 1
        {
            let Some(value) = bytes
                .get(&instruction.op1_register().full_register())
                .copied()
            else {
                continue;
            };
            let displacement = instruction.memory_displacement64() as i64;
            let Some(key) = value.key else {
                continue;
            };
            if value.base != Register::RCX
                || instruction.memory_base().full_register() != Register::RDX
                || value.displacement != displacement
            {
                continue;
            }
            if keys
                .insert(
                    displacement,
                    RelativeKey {
                        displacement,
                        key,
                        instruction_va: value.instruction_va,
                    },
                )
                .is_some_and(|previous| previous.key != key)
            {
                return None;
            }
        }
        if instruction.mnemonic() == Mnemonic::Ret {
            break;
        }
    }
    (keys.len() >= MIN_PLAIN_LEN).then(|| keys.into_values().collect())
}

fn remember_call_address(
    instruction: &Instruction,
    addresses: &mut HashMap<Register, (u64, usize)>,
) {
    if instruction.mnemonic() == Mnemonic::Lea
        && instruction.op0_kind() == OpKind::Register
        && instruction.op1_kind() == OpKind::Memory
        && instruction.is_ip_rel_memory_operand()
    {
        addresses.insert(
            instruction.op0_register().full_register(),
            (instruction.ip_rel_memory_address(), 0),
        );
    } else if instruction.mnemonic() == Mnemonic::Mov
        && instruction.op0_kind() == OpKind::Register
        && instruction.op1_kind() == OpKind::Register
    {
        let source = instruction.op1_register().full_register();
        let destination = instruction.op0_register().full_register();
        if let Some((address, _)) = addresses.get(&source).copied() {
            addresses.insert(destination, (address, 0));
        } else {
            addresses.remove(&destination);
        }
    }
}

fn apply_relative_decryptor(
    decryptor: &[RelativeKey],
    addresses: &HashMap<Register, (u64, usize)>,
    sections: &[SectionView<'_>],
    keys: &mut BTreeMap<u64, KeyByte>,
) -> Result<()> {
    let Some((source, _)) = addresses.get(&Register::RCX).copied() else {
        return Ok(());
    };
    let Some((destination, _)) = addresses.get(&Register::RDX).copied() else {
        return Ok(());
    };
    if !writable_va(sections, source) || !writable_va(sections, destination) {
        return Ok(());
    }
    for relative in decryptor {
        let address = destination.wrapping_add_signed(relative.displacement);
        let source_address = source.wrapping_add_signed(relative.displacement);
        if !writable_va(sections, address) || !writable_va(sections, source_address) {
            return Ok(());
        }
        insert_key(
            keys,
            address,
            KeyByte {
                key: relative.key,
                instruction_va: relative.instruction_va,
            },
        )?;
    }
    Ok(())
}

fn recover_stack_containers(sections: &[SectionView<'_>]) -> Vec<RecoveredString> {
    let mut strings = Vec::new();
    for section in sections.iter().filter(|section| section.executable) {
        let mut decoder = Decoder::with_ip(64, section.data, section.address, DecoderOptions::NONE);
        let mut pending = HashMap::<Register, BTreeMap<i64, StackByte>>::new();
        let mut info = InstructionInfoFactory::new();
        let mut history = Vec::new();
        while decoder.can_decode() {
            let instruction = decoder.decode();
            remember_stack_immediate(&instruction, &history, &mut info, sections, &mut pending);
            if history.len() == 12 {
                history.remove(0);
            }
            history.push(instruction);
            if stack_flush_boundary(&instruction) {
                flush_stack_bytes(*section, &mut pending, &mut strings);
            }
        }
        flush_stack_bytes(*section, &mut pending, &mut strings);
    }
    strings
}

fn remember_stack_immediate(
    instruction: &Instruction,
    history: &[Instruction],
    info: &mut InstructionInfoFactory,
    sections: &[SectionView<'_>],
    pending: &mut HashMap<Register, BTreeMap<i64, StackByte>>,
) {
    if !copy_instruction(instruction)
        || instruction.op0_kind() != OpKind::Memory
        || instruction.memory_index() != Register::None
    {
        return;
    }
    let base = instruction.memory_base().full_register();
    if !matches!(base, Register::RSP | Register::RBP) {
        return;
    }
    let width = instruction.memory_size().size();
    let immediate;
    let value = if is_immediate(instruction.op1_kind()) && width <= 8 {
        immediate = instruction.immediate(1).to_le_bytes();
        &immediate[..width]
    } else if instruction.op1_kind() == OpKind::Register {
        let reg = instruction.op1_register();
        let Some((load, _)) = last_register_write(history, reg, info) else {
            return;
        };
        if !copy_instruction(load) || load.op0_register() != reg {
            return;
        }
        if is_immediate(load.op1_kind()) && width <= 8 {
            immediate = load.immediate(1).to_le_bytes();
            &immediate[..width]
        } else if load.is_ip_rel_memory_operand() && load.memory_size().size() >= width {
            let address = load.ip_rel_memory_address();
            let Some(section) = sections
                .iter()
                .find(|s| !s.writable && !s.executable && contains_range(**s, address, width))
            else {
                return;
            };
            let offset = (address - section.address) as usize;
            &section.data[offset..offset + width]
        } else {
            return;
        }
    } else {
        return;
    };
    let displacement = instruction.memory_displacement64() as i64;
    let bytes = pending.entry(base).or_default();
    for (offset, byte) in value[..width].iter().copied().enumerate() {
        bytes.insert(
            displacement.saturating_add(offset as i64),
            StackByte {
                value: byte,
                instruction_va: instruction.ip(),
            },
        );
    }
}

fn stack_flush_boundary(instruction: &Instruction) -> bool {
    matches!(
        instruction.mnemonic(),
        Mnemonic::Call | Mnemonic::Jmp | Mnemonic::Ret
    ) || instruction.is_jcc_short_or_near()
}

fn flush_stack_bytes(
    section: SectionView<'_>,
    pending: &mut HashMap<Register, BTreeMap<i64, StackByte>>,
    strings: &mut Vec<RecoveredString>,
) {
    for (base, bytes) in pending.drain() {
        let mut runs = Vec::<Vec<(i64, StackByte)>>::new();
        for (offset, byte) in bytes {
            if let Some(run) = runs.last_mut()
                && run
                    .last()
                    .is_some_and(|(last, _)| last.saturating_add(1) == offset)
            {
                run.push((offset, byte));
            } else {
                runs.push(vec![(offset, byte)]);
            }
        }

        for run in runs {
            let raw: Vec<_> = run.iter().map(|(_, b)| b.value).collect();
            let mut cursor = 0;
            while cursor < raw.len() {
                if let Some((width, len)) = wide_prefix(&raw[cursor..]) {
                    let slice = &raw[cursor..cursor + len];
                    let (offset, byte) = run[cursor];
                    let mut item = recovered_bytes(
                        format!("pe.stack_{:016x}_{offset:x}", byte.instruction_va),
                        strings.len(),
                        Some(section.name.to_owned()),
                        StringAlgorithm::Plain,
                        slice,
                        slice,
                        vec![
                            "amice_stack_container_x86_64".to_owned(),
                            "inferred_wide_code_units".to_owned(),
                            format!("base:{base:?}"),
                            format!("stack_offset:{offset:+#x}"),
                        ],
                    );
                    item.set_wide_text(slice, width);
                    strings.push(item);
                    cursor += len;
                    continue;
                }
                let Some(nul) = raw[cursor..]
                    .iter()
                    .position(|b| *b == 0)
                    .map(|n| n + cursor)
                else {
                    break;
                };
                let lower = cursor;
                cursor = nul + 1;
                let mut start = nul;
                while start > lower && plain_byte(run[start - 1].1.value) {
                    start -= 1;
                }
                let body = &run[start..nul];
                if body.len() < MIN_PLAIN_LEN
                    || !body
                        .iter()
                        .any(|(_, byte)| byte.value.is_ascii_alphabetic())
                {
                    continue;
                }
                let mut plain = body.iter().map(|(_, byte)| byte.value).collect::<Vec<_>>();
                plain.push(0);
                let instruction_va = body
                    .iter()
                    .map(|(_, byte)| byte.instruction_va)
                    .min()
                    .unwrap_or(section.address);
                let stack_offset = body[0].0;
                strings.push(recovered_bytes(
                    format!("pe.stack_{instruction_va:016x}_{stack_offset:x}"),
                    strings.len(),
                    Some(section.name.to_owned()),
                    StringAlgorithm::Plain,
                    &plain,
                    &plain,
                    vec![
                        "amice_stack_container_x86_64".to_owned(),
                        format!("section:{}", section.name),
                        format!("instruction_va:0x{instruction_va:016x}"),
                        format!("base:{base:?}"),
                        format!("stack_offset:{stack_offset:+#x}"),
                        "boundary:nul_terminator".to_owned(),
                    ],
                ));
            }
        }
    }
}

fn collect_key_bytes(
    code: SectionView<'_>,
    sections: &[SectionView<'_>],
    keys: &mut BTreeMap<u64, KeyByte>,
) -> Result<()> {
    let mut decoder = Decoder::with_ip(64, code.data, code.address, DecoderOptions::NONE);
    let mut address_registers = HashMap::<Register, (u64, usize)>::new();
    let mut info = InstructionInfoFactory::new();
    let mut instructions = Vec::new();
    while decoder.can_decode() {
        instructions.push(decoder.decode());
    }

    for (index, instruction) in instructions.iter().enumerate() {
        address_registers.retain(|_, (_, age)| {
            *age += 1;
            *age <= 16
        });
        remember_address(instruction, &mut address_registers);
        let history = &instructions[index.saturating_sub(12)..index];
        recover_xor_store(instruction, history, &mut info, sections, keys)?;
        remember_memory_xor(
            instruction,
            &instructions[index + 1..instructions.len().min(index + 10)],
            sections,
            &address_registers,
            history,
            &mut info,
            keys,
        )?;
    }
    Ok(())
}

fn remember_address(instruction: &Instruction, addresses: &mut HashMap<Register, (u64, usize)>) {
    if instruction.mnemonic() != Mnemonic::Lea
        || instruction.op0_kind() != OpKind::Register
        || instruction.op1_kind() != OpKind::Memory
        || !instruction.is_ip_rel_memory_operand()
    {
        return;
    }
    addresses.insert(
        instruction.op0_register().full_register(),
        (instruction.ip_rel_memory_address(), 0),
    );
}

fn last_register_write<'a>(
    history: &'a [Instruction],
    reg: Register,
    info: &mut InstructionInfoFactory,
) -> Option<(&'a Instruction, &'a [Instruction])> {
    for (index, inst) in history.iter().enumerate().rev() {
        if inst.flow_control() != FlowControl::Next {
            break;
        }
        if info.info(inst).used_registers().iter().any(|used| {
            used.register().full_register() == reg.full_register()
                && matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                )
        }) {
            return Some((inst, &history[..index]));
        }
    }
    None
}

fn copy_instruction(inst: &Instruction) -> bool {
    matches!(
        inst.mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Movzx
            | Mnemonic::Movss
            | Mnemonic::Movsd
            | Mnemonic::Movaps
            | Mnemonic::Movups
            | Mnemonic::Movdqa
            | Mnemonic::Movdqu
            | Mnemonic::Movapd
            | Mnemonic::Movupd
            | Mnemonic::Movq
            | Mnemonic::Movd
    )
}

fn constant_register(
    history: &[Instruction],
    reg: Register,
    info: &mut InstructionInfoFactory,
) -> Option<u64> {
    let (load, _) = last_register_write(history, reg, info)?;
    (load.mnemonic() == Mnemonic::Mov
        && load.op0_register() == reg
        && is_immediate(load.op1_kind()))
    .then(|| load.immediate(1))
}

fn record_mask(
    keys: &mut BTreeMap<u64, KeyByte>,
    address: u64,
    mask: &[u8],
    ip: u64,
) -> Result<()> {
    for (offset, &key) in mask.iter().enumerate() {
        insert_key(
            keys,
            address + offset as u64,
            KeyByte {
                key,
                instruction_va: ip,
            },
        )?;
    }
    Ok(())
}

fn recover_xor_store(
    store: &Instruction,
    history: &[Instruction],
    info: &mut InstructionInfoFactory,
    sections: &[SectionView<'_>],
    keys: &mut BTreeMap<u64, KeyByte>,
) -> Result<()> {
    if !copy_instruction(store)
        || store.op0_kind() != OpKind::Memory
        || store.op1_kind() != OpKind::Register
    {
        return Ok(());
    }
    let stack = matches!(store.memory_base(), Register::RSP | Register::RBP)
        && store.memory_index() == Register::None;
    if !stack && !store.is_ip_rel_memory_operand() {
        return Ok(());
    }
    let reg = store.op1_register();
    let Some((xor, before)) = last_register_write(history, reg, info) else {
        return Ok(());
    };
    if !matches!(
        xor.mnemonic(),
        Mnemonic::Xor | Mnemonic::Xorps | Mnemonic::Xorpd | Mnemonic::Pxor
    ) || xor.op0_register() != reg
    {
        return Ok(());
    }
    let Some((load, _)) = last_register_write(before, reg, info) else {
        return Ok(());
    };
    if !copy_instruction(load)
        || load.op0_register().full_register() != reg.full_register()
        || (load.op0_register() != reg
            && (load.mnemonic() != Mnemonic::Movzx
                || matches!(
                    reg,
                    Register::AH | Register::BH | Register::CH | Register::DH
                )))
    {
        return Ok(());
    }
    let width = store.memory_size().size();
    let immediate;
    let (address, mask) = if load.is_ip_rel_memory_operand() && load.memory_size().size() >= width {
        let source = load.ip_rel_memory_address();
        if is_immediate(xor.op1_kind()) && width <= 8 {
            immediate = xor.immediate(1).to_le_bytes();
            (source, &immediate[..width])
        } else if xor.is_ip_rel_memory_operand() && xor.memory_size().size() >= width {
            let key = xor.ip_rel_memory_address();
            // The optimizer may load the read-only mask first.
            let (source, key) = if writable_va(sections, key) {
                (key, source)
            } else {
                (source, key)
            };
            let Some(section) = sections
                .iter()
                .find(|s| !s.writable && !s.executable && contains_range(**s, key, width))
            else {
                return Ok(());
            };
            let offset = (key - section.address) as usize;
            (source, &section.data[offset..offset + width])
        } else {
            return Ok(());
        }
    } else if is_immediate(load.op1_kind())
        && load.op0_register() == reg
        && xor.is_ip_rel_memory_operand()
        && xor.memory_size().size() >= width
        && width <= 8
    {
        immediate = load.immediate(1).to_le_bytes();
        (xor.ip_rel_memory_address(), &immediate[..width])
    } else {
        return Ok(());
    };
    if !stack && store.ip_rel_memory_address() != address {
        return Ok(());
    }
    if sections
        .iter()
        .any(|s| !s.executable && (s.writable || stack) && contains_range(*s, address, width))
    {
        record_mask(keys, address, mask, xor.ip())?;
    }
    Ok(())
}

fn remember_memory_xor(
    instruction: &Instruction,
    following: &[Instruction],
    sections: &[SectionView<'_>],
    addresses: &HashMap<Register, (u64, usize)>,
    history: &[Instruction],
    info: &mut InstructionInfoFactory,
    keys: &mut BTreeMap<u64, KeyByte>,
) -> Result<()> {
    if instruction.mnemonic() != Mnemonic::Xor || instruction.op0_kind() != OpKind::Memory {
        return Ok(());
    }
    let mask = if is_immediate(instruction.op1_kind()) {
        instruction.immediate(1)
    } else if instruction.op1_kind() == OpKind::Register {
        let Some(value) = constant_register(history, instruction.op1_register(), info) else {
            return Ok(());
        };
        value
    } else {
        return Ok(());
    };
    let width = instruction.memory_size().size();
    if instruction.is_ip_rel_memory_operand() {
        let address = instruction.ip_rel_memory_address();
        if (1..=8).contains(&width)
            && sections
                .iter()
                .any(|s| s.writable && !s.executable && contains_range(*s, address, width))
        {
            record_mask(
                keys,
                address,
                &mask.to_le_bytes()[..width],
                instruction.ip(),
            )?;
        }
        return Ok(());
    }
    if width != 1 {
        return Ok(());
    }
    let key = mask as u8;
    let base = instruction.memory_base().full_register();
    let index = instruction.memory_index().full_register();
    let (known, variable) = match (addresses.get(&base), addresses.get(&index)) {
        (Some((address, _)), None) => (*address, index),
        (None, Some((address, _))) => (*address, base),
        _ => return Ok(()),
    };
    if variable == Register::None || instruction.memory_index_scale() != 1 {
        return Ok(());
    }
    let start = known.wrapping_add(instruction.memory_displacement64());
    let Some(len) = loop_length(following, variable, instruction.ip()) else {
        return Ok(());
    };
    if len == 0 || len > 1024 * 1024 {
        return Ok(());
    }
    for offset in 0..len {
        let address = start + offset;
        if !writable_va(sections, address) {
            return Ok(());
        }
        insert_key(
            keys,
            address,
            KeyByte {
                key,
                instruction_va: instruction.ip(),
            },
        )?;
    }
    Ok(())
}

fn loop_length(following: &[Instruction], variable: Register, body_ip: u64) -> Option<u64> {
    for (index, instruction) in following.iter().enumerate() {
        if instruction.mnemonic() != Mnemonic::Cmp || instruction.op0_kind() != OpKind::Register {
            continue;
        }
        if instruction.op0_register().full_register() != variable
            || !is_immediate(instruction.op1_kind())
        {
            continue;
        }
        let branch = following.get(index + 1)?;
        if branch.is_jcc_short_or_near() && branch.near_branch_target() <= body_ip {
            return Some(instruction.immediate(1));
        }
    }
    None
}

fn insert_key(keys: &mut BTreeMap<u64, KeyByte>, address: u64, value: KeyByte) -> Result<()> {
    if let Some(previous) = keys.get(&address)
        && previous.key != value.key
    {
        bail!(
            "conflicting StringEncryption keys for VA 0x{address:016x}: 0x{:02x} at 0x{:016x}, 0x{:02x} at 0x{:016x}",
            previous.key,
            previous.instruction_va,
            value.key,
            value.instruction_va
        );
    }
    keys.entry(address).or_insert(value);
    Ok(())
}

fn extend_fixed_xor_sections(
    sections: &[SectionView<'_>],
    keys: &mut BTreeMap<u64, KeyByte>,
) -> Result<()> {
    for section in sections
        .iter()
        .filter(|section| section.writable && section.name.contains(".str"))
    {
        let evidence = keys
            .range(section.address..section.address.saturating_add(section.data.len() as u64))
            .find(|(_, value)| value.key == XOR_KEY)
            .map(|(_, value)| value.instruction_va);
        let Some(instruction_va) = evidence else {
            continue;
        };
        for offset in 0..section.data.len() {
            insert_key(
                keys,
                section.address + offset as u64,
                KeyByte {
                    key: XOR_KEY,
                    instruction_va,
                },
            )?;
        }
    }
    Ok(())
}

fn decode_key_runs(
    sections: &[SectionView<'_>],
    keys: &BTreeMap<u64, KeyByte>,
    algorithm: StringAlgorithm,
) -> Result<Vec<RecoveredString>> {
    let mut runs = Vec::<Vec<(u64, KeyByte)>>::new();
    for (address, key) in keys {
        if let Some(run) = runs.last_mut()
            && run.last().is_some_and(|(last, _)| *last + 1 == *address)
        {
            run.push((*address, *key));
        } else {
            runs.push(vec![(*address, *key)]);
        }
    }

    let mut strings = Vec::new();
    for run in runs {
        let start = run[0].0;
        let section = sections
            .iter()
            .find(|section| contains_range(**section, start, run.len()))
            .ok_or_else(|| {
                anyhow::anyhow!("StringEncryption run at 0x{start:016x} is outside PE sections")
            })?;
        let offset = usize::try_from(start - section.address).expect("validated section offset");
        let encrypted = section.data[offset..offset + run.len()].to_vec();
        let plaintext = encrypted
            .iter()
            .zip(&run)
            .map(|(byte, (_, key))| byte ^ key.key)
            .collect::<Vec<_>>();
        let mut segment_start = 0;
        while segment_start < plaintext.len() {
            let rest = &plaintext[segment_start..];
            let wide = wide_prefix(rest);
            let len = wide.map(|(_, len)| len).unwrap_or_else(|| {
                rest.iter()
                    .position(|b| *b == 0)
                    .map_or(rest.len(), |i| i + 1)
            });
            let segment_end = segment_start + len;
            let plain = &rest[..len];
            let encrypted = &encrypted[segment_start..segment_end];
            if plain.iter().all(|byte| *byte == 0) {
                segment_start = segment_end;
                continue;
            }
            let va = start + segment_start as u64;
            let mut item_evidence = vec![
                format!("section:{}", section.name),
                format!("va:0x{va:016x}"),
                "x86_64_decrypt_writeback".to_owned(),
            ];
            if segment_end == plaintext.len() && plain.last() != Some(&0) {
                item_evidence.push("boundary:contiguous_write_range".to_owned());
            } else {
                item_evidence.push("boundary:nul_terminator".to_owned());
            }
            let mut item = recovered_bytes(
                format!("pe.va_{va:016x}"),
                strings.len(),
                Some(section.name.to_owned()),
                algorithm,
                encrypted,
                plain,
                item_evidence,
            );
            if let Some((width, _)) = wide {
                item.set_wide_text(plain, width);
                item.evidence.push("inferred_wide_code_units".to_owned());
            }
            strings.push(item);
            segment_start = segment_end;
        }
    }
    Ok(strings)
}

fn recover_plain_sections(sections: &[SectionView<'_>]) -> Vec<RecoveredString> {
    let mut strings = Vec::new();
    for section in sections
        .iter()
        .filter(|section| section.writable && !section.executable)
    {
        let mut start = 0;
        while start < section.data.len() {
            while start < section.data.len() && !plain_byte(section.data[start]) {
                start += 1;
            }
            let separated = start == 0 || section.data[start - 1] == 0;
            if separated && let Some((width, len)) = wide_prefix(&section.data[start..]) {
                let bytes = &section.data[start..start + len];
                let va = section.address + start as u64;
                let mut item = recovered_bytes(
                    format!("pe.va_{va:016x}"),
                    strings.len(),
                    Some(section.name.to_owned()),
                    StringAlgorithm::Plain,
                    bytes,
                    bytes,
                    vec![
                        "plain_pe_data".to_owned(),
                        format!("va:0x{va:016x}"),
                        "inferred_wide_code_units".to_owned(),
                    ],
                );
                item.set_wide_text(bytes, width);
                strings.push(item);
                start += len;
                continue;
            }
            let mut end = start;
            while end < section.data.len() && plain_byte(section.data[end]) {
                end += 1;
            }
            let terminated = end < section.data.len() && section.data[end] == 0;
            let body = &section.data[start..end];
            if body.len() >= MIN_PLAIN_LEN
                && terminated
                && separated
                && body.iter().any(u8::is_ascii_alphabetic)
            {
                let mut bytes = section.data[start..end].to_vec();
                bytes.push(0);
                let va = section.address + start as u64;
                strings.push(recovered_bytes(
                    format!("pe.va_{va:016x}"),
                    strings.len(),
                    Some(section.name.to_owned()),
                    StringAlgorithm::Plain,
                    &bytes,
                    &bytes,
                    vec!["plain_pe_data".to_owned(), format!("va:0x{va:016x}")],
                ));
            }
            start = end.saturating_add(1);
        }
    }
    strings
}

fn plain_byte(byte: u8) -> bool {
    matches!(byte, b' '..=b'~' | b'\n' | b'\r' | b'\t')
}

fn writable_va(sections: &[SectionView<'_>], address: u64) -> bool {
    sections
        .iter()
        .any(|section| section.writable && contains_range(*section, address, 1))
}

fn contains_range(section: SectionView<'_>, address: u64, len: usize) -> bool {
    address
        .checked_sub(section.address)
        .and_then(|offset| offset.checked_add(len as u64))
        .is_some_and(|end| end <= section.data.len() as u64)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn section<'a>(
        name: &'a str,
        address: u64,
        data: &'a [u8],
        executable: bool,
        writable: bool,
    ) -> SectionView<'a> {
        SectionView {
            name,
            address,
            file_offset: 0,
            raw_size: data.len() as u64,
            virtual_size: data.len() as u64,
            data,
            executable,
            writable,
        }
    }

    #[test]
    fn decodes_direct_rip_xor_writeback() {
        let image = 0x140001000_u64;
        let data_va = image + 0x100;
        let mut code = vec![0x80, 0x35];
        let next_ip = image + 7;
        code.extend_from_slice(&((data_va as i64 - next_ip as i64) as i32).to_le_bytes());
        code.push(XOR_KEY);
        code.push(0xc3);
        let encrypted = [b'h' ^ XOR_KEY];
        let sections = [
            section(".text", image, &code, true, false),
            section(".str", data_va, &encrypted, false, true),
        ];

        let report = recover_pe_strings(&sections).unwrap();

        assert_eq!(report.algorithm, Some(StringAlgorithm::Xor));
        assert_eq!(report.strings[0].text.as_deref(), Some("h"));
    }

    #[test]
    fn conflicting_keys_fail_closed() {
        let mut keys = BTreeMap::new();
        insert_key(
            &mut keys,
            0x1000,
            KeyByte {
                key: 1,
                instruction_va: 0x2000,
            },
        )
        .unwrap();
        assert!(
            insert_key(
                &mut keys,
                0x1000,
                KeyByte {
                    key: 2,
                    instruction_va: 0x3000,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn decodes_called_relative_simd_decryptor() {
        let image = 0x140001000_u64;
        let helper = image + 0x40;
        let data_va = image + 0x200;
        let key = [0x11, 0x22, 0x33, 0x44, 0x55];
        let plaintext = *b"hey!\0";
        let encrypted = plaintext
            .iter()
            .zip(key)
            .map(|(byte, key)| byte ^ key)
            .collect::<Vec<_>>();

        let mut code = vec![0x48, 0x8d, 0x0d];
        code.extend_from_slice(&((data_va as i64 - (image + 7) as i64) as i32).to_le_bytes());
        code.extend_from_slice(&[0x48, 0x8d, 0x15]);
        code.extend_from_slice(&((data_va as i64 - (image + 14) as i64) as i32).to_le_bytes());
        code.push(0xe8);
        code.extend_from_slice(&((helper as i64 - (image + 19) as i64) as i32).to_le_bytes());
        code.push(0xc3);
        code.resize(0x40, 0xcc);
        for (offset, key) in key.into_iter().enumerate() {
            if offset == 0 {
                code.extend_from_slice(&[0x0f, 0xb6, 0x01, 0x34, key, 0x88, 0x02]);
            } else {
                let offset = offset as u8;
                code.extend_from_slice(&[0x0f, 0xb6, 0x41, offset, 0x34, key, 0x88, 0x42, offset]);
            }
        }
        code.push(0xc3);
        let sections = [
            section(".text", image, &code, true, false),
            section(".str", data_va, &encrypted, false, true),
        ];

        let report = recover_pe_strings(&sections).unwrap();

        assert_eq!(report.algorithm, Some(StringAlgorithm::SimdXor));
        assert_eq!(report.strings[0].text.as_deref(), Some("hey!"));
    }

    #[test]
    fn recovers_stack_container_immediates() {
        let image = 0x140001000_u64;
        let code = [
            0xc6, 0x44, 0x24, 0x20, b'd', 0xc6, 0x44, 0x24, 0x21, b'e', 0xc6, 0x44, 0x24, 0x22,
            b'o', 0xc6, 0x44, 0x24, 0x23, b'b', 0xc6, 0x44, 0x24, 0x24, b'f', 0xc6, 0x44, 0x24,
            0x25, 0, 0xc3,
        ];
        let sections = [section(".text", image, &code, true, false)];

        let report = recover_pe_strings(&sections).unwrap();

        assert_eq!(report.algorithm, Some(StringAlgorithm::Plain));
        assert_eq!(report.strings[0].text.as_deref(), Some("deobf"));
        assert!(
            report
                .evidence
                .contains(&"amice_stack_container_x86_64".to_owned())
        );
    }
}
