use crate::bytecode::{VmRecord, decode_const_pool, decode_function_records};
use crate::crypto::{
    DESCRIPTOR_FIELD_COUNT, DescriptorFields, decrypt_descriptor_words, descriptor_table_seed,
    obfuscated_fn_token_parts, safe_symbol_suffix,
};
use crate::llvm_ir::{ByteGlobal, I64Global, LlModule, PtrGlobal, marker_seed_from_name};
use amice_vm::ProfilePackage;
use amice_vm::isa::{HandlerSemantic, OperandKind};
use anyhow::{Context, Result, bail};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DecodedConstant {
    pub index: usize,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodedNativeTarget {
    pub local_index: usize,
    pub table_index: usize,
    pub thunk: Option<String>,
    pub callee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodedDescriptor {
    pub fn_index: usize,
    pub function_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapper_va: Option<String>,
    pub code_offset: u64,
    pub code_len: u64,
    pub const_pool_offset: u64,
    pub const_pool_len: u64,
    pub bytecode_key: String,
    pub native_base: u64,
    pub native_count: u64,
    pub guard: String,
    pub guard_valid: bool,
    pub const_pool: Vec<DecodedConstant>,
    pub native_targets: Vec<DecodedNativeTarget>,
}

#[derive(Debug, Clone)]
pub struct DecodeInput {
    pub module: LlModule,
    pub profile: ProfilePackage,
    pub seed: u64,
}

#[derive(Debug, Clone)]
pub struct DecodeReport {
    pub bytecode_global: String,
    pub descriptor_global: String,
    pub native_global: Option<String>,
    pub descriptor_seed: u64,
    pub descriptors: Vec<DecodedDescriptor>,
    pub records: Vec<VmRecord>,
}

pub fn seed_from_args(
    profile: &ProfilePackage,
    safe_names: Option<&str>,
    seed: Option<u64>,
) -> Result<u64> {
    if let Some(seed) = seed {
        return Ok(seed);
    }
    let safe_names = safe_names.context("decode needs --descriptor-seed or --safe-names")?;
    let names = safe_names
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(safe_symbol_suffix)
        .collect::<Vec<_>>();
    if names.is_empty() {
        bail!("--safe-names did not contain any names");
    }
    Ok(descriptor_table_seed(profile, &names))
}

pub fn marker_seed(module: &LlModule) -> Option<u64> {
    let seeds = marker_seeds(module);
    match seeds.as_slice() {
        [seed] => Some(*seed),
        _ => None,
    }
}

pub fn marker_seeds(module: &LlModule) -> Vec<u64> {
    let mut seeds = module
        .i64_globals
        .iter()
        .filter_map(|global| marker_seed_from_name(&global.name))
        .collect::<Vec<_>>();
    seeds.sort_unstable();
    seeds.dedup();
    seeds
}

pub fn seed_from_wrappers(profile: &ProfilePackage, module: &LlModule) -> Option<u64> {
    if module.wrapper_safe_names.is_empty() {
        return None;
    }
    Some(descriptor_table_seed(profile, &module.wrapper_safe_names))
}

pub fn decode_module(input: DecodeInput) -> Result<DecodeReport> {
    let descriptor_candidates = valid_descriptor_tables(&input.module.i64_globals, input.seed);
    if descriptor_candidates.is_empty() {
        bail!(
            "no i64 descriptor table passed guard validation for seed 0x{:016x}",
            input.seed
        );
    }

    let mut decoded_candidates = Vec::new();
    let mut rejected_candidates = Vec::new();
    for (descriptor_global, fields) in descriptor_candidates {
        for bytecode_global in &input.module.byte_globals {
            if !descriptors_match_blob_layout(&fields, bytecode_global.bytes.len()) {
                continue;
            }
            match decode_candidate(&input.profile, bytecode_global, &fields) {
                Ok((const_pools, records)) => decoded_candidates.push(ModuleCandidate {
                    bytecode_global,
                    descriptor_global,
                    fields: fields.clone(),
                    const_pools,
                    records,
                }),
                Err(err) => rejected_candidates.push(format!(
                    "{}/{}: {err:#}",
                    descriptor_global.name, bytecode_global.name
                )),
            }
        }
    }

    if decoded_candidates.is_empty() {
        if rejected_candidates.is_empty() {
            bail!("descriptor guards matched, but no byte array matches the compact blob layout");
        }
        bail!(
            "descriptor/blob pairs matched layout but failed bytecode validation: {}",
            rejected_candidates
                .into_iter()
                .take(3)
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    if decoded_candidates.len() > 1 {
        let names = decoded_candidates
            .iter()
            .map(|candidate| {
                format!(
                    "{}/{}",
                    candidate.descriptor_global.name, candidate.bytecode_global.name
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        bail!("multiple descriptor/blob pairs passed full validation: {names}");
    }
    let ModuleCandidate {
        bytecode_global,
        descriptor_global,
        fields,
        const_pools,
        mut records,
    } = decoded_candidates.remove(0);

    let wrapper_names = matching_wrapper_names(
        &input.profile,
        &input.module.wrapper_safe_names,
        input.seed,
        fields.len(),
    )
    .map(<[String]>::to_vec)
    .or_else(|| matching_wrapper_names_from_parts(&input.module, input.seed, fields.len()));
    let native_global = find_native_table(
        &input.module,
        descriptor_global,
        &fields,
        wrapper_names.as_deref(),
    )?;
    let native_targets = build_native_targets(&input.module, native_global, &fields)?;
    resolve_native_operands(&mut records, &native_targets)?;

    let mut descriptors = Vec::with_capacity(fields.len());
    for (fn_index, descriptor) in fields.iter().copied().enumerate() {
        descriptors.push(render_descriptor(
            fn_index,
            wrapper_names
                .as_ref()
                .and_then(|names| names.get(fn_index))
                .cloned(),
            descriptor,
            &const_pools[fn_index],
            native_targets[fn_index].clone(),
        ));
    }

    Ok(DecodeReport {
        bytecode_global: bytecode_global.name.clone(),
        descriptor_global: descriptor_global.name.clone(),
        native_global: native_global.map(|global| global.name.clone()),
        descriptor_seed: input.seed,
        descriptors,
        records,
    })
}

fn matching_wrapper_names_from_parts(
    module: &LlModule,
    seed: u64,
    descriptor_count: usize,
) -> Option<Vec<String>> {
    (0..descriptor_count)
        .map(|fn_index| {
            let parts = obfuscated_fn_token_parts(seed, fn_index);
            let matches = module
                .functions
                .iter()
                .filter(|function| {
                    parts
                        .iter()
                        .all(|part| function.vm_token_parts.contains(part))
                })
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [function] => Some(safe_symbol_suffix(&function.name)),
                _ => None,
            }
        })
        .collect()
}

fn matching_wrapper_names<'a>(
    profile: &ProfilePackage,
    safe_names: &'a [String],
    seed: u64,
    descriptor_count: usize,
) -> Option<&'a [String]> {
    (safe_names.len() == descriptor_count && descriptor_table_seed(profile, safe_names) == seed)
        .then_some(safe_names)
}

struct ModuleCandidate<'a> {
    bytecode_global: &'a ByteGlobal,
    descriptor_global: &'a I64Global,
    fields: Vec<DescriptorFields>,
    const_pools: Vec<Vec<u64>>,
    records: Vec<VmRecord>,
}

fn decode_candidate(
    profile: &ProfilePackage,
    bytecode_global: &ByteGlobal,
    fields: &[DescriptorFields],
) -> Result<(Vec<Vec<u64>>, Vec<VmRecord>)> {
    decode_blob(
        profile,
        &bytecode_global.bytes,
        &bytecode_global.name,
        fields,
    )
}

pub(crate) fn decode_blob(
    profile: &ProfilePackage,
    bytes: &[u8],
    name: &str,
    fields: &[DescriptorFields],
) -> Result<(Vec<Vec<u64>>, Vec<VmRecord>)> {
    let mut const_pools = Vec::with_capacity(fields.len());
    let mut records = Vec::new();
    for (fn_index, descriptor) in fields.iter().copied().enumerate() {
        let const_pool_bytes = blob_range(
            bytes,
            name,
            descriptor.const_pool_offset,
            descriptor.const_pool_len,
            "const_pool",
        )?;
        let const_pool = decode_const_pool(const_pool_bytes, descriptor.bytecode_key)
            .with_context(|| format!("decode const_pool for fn {fn_index}"))?;
        let code = blob_range(
            bytes,
            name,
            descriptor.code_offset,
            descriptor.code_len,
            "code",
        )?;
        let mut function_records =
            decode_function_records(profile, fn_index, code, descriptor.bytecode_key)
                .with_context(|| {
                    format!(
                        "decode function {} from {} offset {} length {}",
                        fn_index, name, descriptor.code_offset, descriptor.code_len
                    )
                })?;
        resolve_const_pool_operands(&mut function_records, &const_pool)?;
        validate_native_operands(&mut function_records, descriptor)?;
        const_pools.push(const_pool);
        records.extend(function_records);
    }
    Ok((const_pools, records))
}

fn blob_range<'a>(
    bytes: &'a [u8],
    name: &str,
    offset: u64,
    len: u64,
    segment: &str,
) -> Result<&'a [u8]> {
    let start = usize::try_from(offset)
        .with_context(|| format!("{segment} offset {offset} does not fit usize"))?;
    let len = usize::try_from(len)
        .with_context(|| format!("{segment} length {len} does not fit usize"))?;
    let end = start
        .checked_add(len)
        .with_context(|| format!("{segment} range overflow"))?;
    bytes
        .get(start..end)
        .with_context(|| format!("{segment} range [{start}..{end}) is outside {name}"))
}

pub(crate) fn resolve_const_pool_operands(
    records: &mut [VmRecord],
    const_pool: &[u64],
) -> Result<()> {
    for record in records {
        for operand in &mut record.operands {
            if operand.kind != OperandKind::ConstPoolIndex {
                continue;
            }
            let index = usize::try_from(operand.value).with_context(|| {
                format!("const_pool index {} does not fit usize", operand.value)
            })?;
            let value = const_pool.get(index).with_context(|| {
                format!(
                    "{} at fn {} pc {} references const_pool[{}], but pool has {} values",
                    record.mnemonic,
                    record.fn_index,
                    record.pc,
                    index,
                    const_pool.len()
                )
            })?;
            operand.resolved = Some(format!("0x{value:016x}"));
        }
    }
    Ok(())
}

fn validate_native_operands(records: &mut [VmRecord], descriptor: DescriptorFields) -> Result<()> {
    for record in records {
        if record.semantic != HandlerSemantic::CallNative {
            continue;
        }
        let callee = record
            .operands
            .iter_mut()
            .find(|operand| operand.name == "callee")
            .with_context(|| format!("{} has no callee operand", record.mnemonic))?;
        if callee.value >= descriptor.native_count {
            bail!(
                "{} at fn {} pc {} references native {} outside count {}",
                record.mnemonic,
                record.fn_index,
                record.pc,
                callee.value,
                descriptor.native_count
            );
        }
        let table_index = descriptor
            .native_base
            .checked_add(callee.value)
            .context("native table index overflow")?;
        callee.resolved = Some(format!("native[{table_index}]"));
    }
    Ok(())
}

fn find_native_table<'a>(
    module: &'a LlModule,
    descriptor_global: &I64Global,
    fields: &[DescriptorFields],
    wrapper_names: Option<&[String]>,
) -> Result<Option<&'a PtrGlobal>> {
    let required_len = fields
        .iter()
        .map(|descriptor| {
            descriptor
                .native_base
                .checked_add(descriptor.native_count)
                .context("native range overflow")
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .unwrap_or(0);
    if required_len == 0 {
        return Ok(None);
    }
    let required_len =
        usize::try_from(required_len).context("native table length does not fit usize")?;

    if let Some(suffix) = descriptor_global
        .name
        .strip_prefix(".amice.vm.descriptor_table.")
    {
        let marker_name = format!(".amice.vm.native_table.module.{suffix}");
        if let Some(global) = module
            .ptr_globals
            .iter()
            .find(|global| global.name == marker_name && global.len == required_len)
        {
            return Ok(Some(global));
        }
    }

    let candidates = module
        .ptr_globals
        .iter()
        .filter(|global| global.len == required_len)
        .collect::<Vec<_>>();
    if let [global] = candidates.as_slice() {
        return Ok(Some(*global));
    }
    let Some(wrapper_names) = wrapper_names else {
        return Ok(None);
    };
    let reachable = reachable_globals(module, wrapper_names);
    let matched = candidates
        .into_iter()
        .filter(|global| reachable.contains(&global.name))
        .collect::<Vec<_>>();
    Ok(match matched.as_slice() {
        [global] => Some(*global),
        _ => None,
    })
}

fn reachable_globals(
    module: &LlModule,
    wrapper_names: &[String],
) -> std::collections::HashSet<String> {
    let mut pending = module
        .functions
        .iter()
        .filter(|function| wrapper_names.contains(&safe_symbol_suffix(&function.name)))
        .map(|function| function.name.clone())
        .collect::<Vec<_>>();
    let mut visited = std::collections::HashSet::new();
    let mut globals = std::collections::HashSet::new();
    while let Some(name) = pending.pop() {
        if !visited.insert(name.clone()) {
            continue;
        }
        let Some(function) = module
            .functions
            .iter()
            .find(|function| function.name == name)
        else {
            continue;
        };
        globals.extend(function.global_refs.iter().cloned());
        for callee in &function.direct_callees {
            if !visited.contains(callee) {
                pending.push(callee.clone());
            }
        }
    }
    globals
}

fn build_native_targets(
    module: &LlModule,
    native_global: Option<&PtrGlobal>,
    fields: &[DescriptorFields],
) -> Result<Vec<Vec<DecodedNativeTarget>>> {
    fields
        .iter()
        .map(|descriptor| {
            let native_base = usize::try_from(descriptor.native_base)
                .context("native_base does not fit usize")?;
            let native_count = usize::try_from(descriptor.native_count)
                .context("native_count does not fit usize")?;
            (0..native_count)
                .map(|local_index| {
                    let table_index = native_base
                        .checked_add(local_index)
                        .context("native table index overflow")?;
                    let thunk = native_global
                        .and_then(|global| global.targets.get(table_index))
                        .cloned();
                    let callee = thunk.as_deref().and_then(|thunk| {
                        module
                            .functions
                            .iter()
                            .find(|function| function.name == thunk)
                            .and_then(|function| match function.direct_callees.as_slice() {
                                [callee] => Some(callee.clone()),
                                _ => None,
                            })
                    });
                    Ok(DecodedNativeTarget {
                        local_index,
                        table_index,
                        thunk,
                        callee,
                        resolution: None,
                    })
                })
                .collect()
        })
        .collect()
}

fn resolve_native_operands(
    records: &mut [VmRecord],
    native_targets: &[Vec<DecodedNativeTarget>],
) -> Result<()> {
    for record in records {
        if record.semantic != HandlerSemantic::CallNative {
            continue;
        }
        let callee = record
            .operands
            .iter_mut()
            .find(|operand| operand.name == "callee")
            .context("call_native record lost callee operand")?;
        let local_index =
            usize::try_from(callee.value).context("native local index does not fit usize")?;
        let target = native_targets
            .get(record.fn_index)
            .and_then(|targets| targets.get(local_index))
            .context("validated native target is missing from report")?;
        if let Some(name) = target.callee.as_ref().or(target.thunk.as_ref()) {
            callee.resolved = Some(name.clone());
        }
    }
    Ok(())
}

fn valid_descriptor_tables(
    globals: &[I64Global],
    seed: u64,
) -> Vec<(&I64Global, Vec<DescriptorFields>)> {
    globals
        .iter()
        .filter(|global| {
            global.len >= DESCRIPTOR_FIELD_COUNT && global.len % DESCRIPTOR_FIELD_COUNT == 0
        })
        .filter_map(|global| {
            let mut descriptors = Vec::with_capacity(global.len / DESCRIPTOR_FIELD_COUNT);
            for (fn_index, row) in global
                .words
                .chunks_exact(DESCRIPTOR_FIELD_COUNT)
                .enumerate()
            {
                let fields = decrypt_descriptor_words(seed, fn_index, row)?;
                descriptors.push(fields);
            }
            Some((global, descriptors))
        })
        .collect()
}

pub(crate) fn descriptors_match_blob_layout(
    descriptors: &[DescriptorFields],
    blob_len: usize,
) -> bool {
    let mut expected_blob_offset = 0_u64;
    let mut expected_native_base = 0_u64;
    for descriptor in descriptors {
        if descriptor.const_pool_offset != expected_blob_offset
            || descriptor.native_base != expected_native_base
        {
            return false;
        }
        let Some(code_offset) = descriptor
            .const_pool_offset
            .checked_add(descriptor.const_pool_len)
        else {
            return false;
        };
        if descriptor.code_offset != code_offset {
            return false;
        }
        let Some(next_blob_offset) = descriptor.code_offset.checked_add(descriptor.code_len) else {
            return false;
        };
        let Some(next_native_base) = descriptor.native_base.checked_add(descriptor.native_count)
        else {
            return false;
        };
        expected_blob_offset = next_blob_offset;
        expected_native_base = next_native_base;
    }
    expected_blob_offset == blob_len as u64
}

fn render_descriptor(
    fn_index: usize,
    function_name: Option<String>,
    descriptor: DescriptorFields,
    const_pool: &[u64],
    native_targets: Vec<DecodedNativeTarget>,
) -> DecodedDescriptor {
    DecodedDescriptor {
        fn_index,
        function_name,
        wrapper_va: None,
        code_offset: descriptor.code_offset,
        code_len: descriptor.code_len,
        const_pool_offset: descriptor.const_pool_offset,
        const_pool_len: descriptor.const_pool_len,
        bytecode_key: format!("0x{:016x}", descriptor.bytecode_key),
        native_base: descriptor.native_base,
        native_count: descriptor.native_count,
        guard: format!("0x{:016x}", descriptor.guard),
        guard_valid: true,
        const_pool: const_pool
            .iter()
            .enumerate()
            .map(|(index, value)| DecodedConstant {
                index,
                value: format!("0x{value:016x}"),
            })
            .collect(),
        native_targets,
    }
}

pub fn likely_bytecode_blobs(module: &LlModule) -> Vec<&ByteGlobal> {
    let mut blobs = module
        .byte_globals
        .iter()
        .filter(|global| global.len >= 64)
        .collect::<Vec<_>>();
    blobs.sort_by_key(|global| usize::MAX - global.len);
    blobs
}
