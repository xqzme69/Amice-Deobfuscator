use crate::crypto::{
    DESCRIPTOR_FIELD_COUNT, DescriptorFields, decrypt_descriptor_words, descriptor_guard,
    encrypt_descriptor_field,
};
use crate::decode::{DecodeInput, DecodeReport, decode_blob, decode_module};
use crate::llvm_ir::{ByteGlobal, I64Global, LlModule, PtrGlobal};
use crate::pe_native::{apply_symbol_names, resolve_native_targets, resolve_wrappers};
use crate::pe_strings::recover_pe_strings;
use crate::pe_symbols::load_pdb_symbols;
use crate::strings::StringReport;
use amice_vm::ProfilePackage;
use anyhow::{Context, Result, bail};
use iced_x86::{Decoder, DecoderOptions, OpKind};
use object::{Architecture, BinaryFormat, Object, ObjectSection, SectionFlags, pe};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

const MAX_DESCRIPTOR_COUNT: usize = 4096;
const MAX_BLOB_LEN: u64 = 256 * 1024 * 1024;
const MAX_NATIVE_COUNT: u64 = 1_000_000;
const MAX_SEED_CANDIDATES: usize = 65_536;
const MAX_RUNTIME_GRAPH_FUNCTIONS: usize = 256;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PeLocation {
    pub section: String,
    pub file_offset: u64,
    pub rva: u64,
    pub va: String,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PeSeedEvidence {
    pub seed: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_va: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PeSectionReport {
    pub name: String,
    pub rva: u64,
    pub va: String,
    pub file_offset: u64,
    pub raw_size: u64,
    pub virtual_size: u64,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PeLayoutReport {
    pub format: String,
    pub architecture: String,
    pub image_base: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_file: Option<String>,
    pub groups: Vec<PeGroupLayoutReport>,
    pub sections: Vec<PeSectionReport>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PeGroupLayoutReport {
    pub group_index: usize,
    pub profile: String,
    pub seed: PeSeedEvidence,
    pub bytecode: PeLocation,
    pub descriptors: PeLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_table: Option<PeLocation>,
}

#[derive(Debug, Clone)]
pub struct PeProfile {
    pub name: String,
    pub package: ProfilePackage,
}

#[derive(Debug, Clone)]
pub struct PeGroupDecodeReport {
    pub layout: PeGroupLayoutReport,
    pub decode: DecodeReport,
}

#[derive(Debug, Clone)]
pub struct PeDecodeReport {
    pub layout: PeLayoutReport,
    pub groups: Vec<PeGroupDecodeReport>,
    pub strings: StringReport,
}

#[derive(Clone, Copy)]
pub(crate) struct SectionView<'a> {
    pub(crate) name: &'a str,
    pub(crate) address: u64,
    pub(crate) file_offset: u64,
    pub(crate) raw_size: u64,
    pub(crate) virtual_size: u64,
    pub(crate) data: &'a [u8],
    pub(crate) executable: bool,
    pub(crate) writable: bool,
}

#[derive(Debug, Clone, Copy)]
struct SeedCandidate {
    value: u64,
    instruction_va: Option<u64>,
}

#[derive(Clone)]
struct DescriptorCandidate<'a> {
    seed: SeedCandidate,
    section: SectionView<'a>,
    offset: usize,
    words: Vec<u64>,
    fields: Vec<DescriptorFields>,
}

#[derive(Clone)]
struct BlobCandidate<'a> {
    descriptors: DescriptorCandidate<'a>,
    section: SectionView<'a>,
    offset: usize,
    len: usize,
}

pub fn decode_pe64_path(
    path: &Path,
    profile: &ProfilePackage,
    seed_override: Option<u64>,
) -> Result<PeDecodeReport> {
    decode_pe64_path_with_pdb(path, profile, seed_override, None)
}

pub fn decode_pe64_path_with_pdb(
    path: &Path,
    profile: &ProfilePackage,
    seed_override: Option<u64>,
    pdb_override: Option<&Path>,
) -> Result<PeDecodeReport> {
    let profile = PeProfile {
        name: "selected profile".to_owned(),
        package: profile.clone(),
    };
    let seeds = seed_override.into_iter().collect::<Vec<_>>();
    decode_pe64_path_with_profiles(path, &[profile], &seeds, pdb_override)
}

pub fn decode_pe64_path_with_profiles(
    path: &Path,
    profiles: &[PeProfile],
    seed_overrides: &[u64],
    pdb_override: Option<&Path>,
) -> Result<PeDecodeReport> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut report = decode_pe64_profiles(&bytes, profiles, seed_overrides)
        .with_context(|| format!("decode PE64 {}", path.display()))?;
    let sibling = path.with_extension("pdb");
    let pdb_path = pdb_override.or_else(|| sibling.exists().then_some(sibling.as_path()));
    if let Some(pdb_path) = pdb_path {
        let image_base = u64::from_str_radix(report.layout.image_base.trim_start_matches("0x"), 16)
            .context("parse decoded PE image base")?;
        let symbols = load_pdb_symbols(pdb_path, image_base)?;
        for group in &mut report.groups {
            apply_symbol_names(&mut group.decode, &symbols);
        }
        report.layout.symbol_file = Some(pdb_path.display().to_string());
    }
    Ok(report)
}

pub fn recover_pe64_strings_path(path: &Path) -> Result<StringReport> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    recover_pe64_strings(&bytes).with_context(|| format!("recover PE64 strings {}", path.display()))
}

pub fn recover_pe64_strings(bytes: &[u8]) -> Result<StringReport> {
    let file = object::File::parse(bytes).context("parse input executable")?;
    validate_pe64(&file)?;
    let image_base = file.relative_address_base();
    let sections = collect_sections(&file, image_base)?;
    recover_pe_strings(&sections)
}

pub fn decode_pe64(
    bytes: &[u8],
    profile: &ProfilePackage,
    seed_override: Option<u64>,
) -> Result<PeDecodeReport> {
    let profile = PeProfile {
        name: "selected profile".to_owned(),
        package: profile.clone(),
    };
    let seeds = seed_override.into_iter().collect::<Vec<_>>();
    decode_pe64_profiles(bytes, &[profile], &seeds)
}

pub fn decode_pe64_profiles(
    bytes: &[u8],
    profiles: &[PeProfile],
    seed_overrides: &[u64],
) -> Result<PeDecodeReport> {
    if profiles.is_empty() {
        bail!("decode-pe needs at least one VMP profile");
    }
    let file = object::File::parse(bytes).context("parse input executable")?;
    validate_pe64(&file)?;

    let image_base = file.relative_address_base();
    let sections = collect_sections(&file, image_base)?;
    let mut seen_seeds = HashSet::new();
    let mut seeds = seed_overrides
        .iter()
        .copied()
        .filter(|seed| seen_seeds.insert(*seed))
        .map(|value| SeedCandidate {
            value,
            instruction_va: None,
        })
        .collect::<Vec<_>>();
    seeds.extend(
        immediate64_seeds(&sections)?
            .into_iter()
            .filter(|candidate| seen_seeds.insert(candidate.value)),
    );
    if seeds.is_empty() {
        bail!("no x86-64 imm64 seed candidates found; use --descriptor-seed");
    }

    let descriptor_candidates = find_descriptor_tables(&sections, &seeds);
    if descriptor_candidates.is_empty() {
        let source = if !seed_overrides.is_empty() {
            "the supplied descriptor seeds or any x86-64 imm64 candidate"
        } else {
            "any x86-64 imm64 candidate"
        };
        bail!("no descriptor table passed guard and layout validation with {source}");
    }
    let descriptor_tables = descriptor_candidates
        .iter()
        .map(|candidate| (candidate.section.address, candidate.offset))
        .collect::<HashSet<_>>();

    let mut groups_by_table = BTreeMap::<(u64, usize), Vec<(usize, BlobCandidate<'_>)>>::new();
    let mut rejected_blobs = Vec::new();
    for descriptors in descriptor_candidates {
        for (profile_index, profile) in profiles.iter().enumerate() {
            match find_compact_blobs(&sections, &profile.package, descriptors.clone()) {
                Ok(candidates) => groups_by_table
                    .entry((descriptors.section.address, descriptors.offset))
                    .or_default()
                    .extend(
                        candidates
                            .into_iter()
                            .map(|candidate| (profile_index, candidate)),
                    ),
                Err(err) => rejected_blobs.push(format!("{}: {err}", profile.name)),
            }
        }
    }
    let matched_tables = groups_by_table.keys().copied().collect::<HashSet<_>>();
    let unmatched_tables = descriptor_tables
        .difference(&matched_tables)
        .copied()
        .collect::<Vec<_>>();
    if !unmatched_tables.is_empty() {
        bail!(
            "{} guarded PE descriptor table(s) did not decode with the supplied profiles: {}",
            unmatched_tables.len(),
            unmatched_tables
                .iter()
                .map(|(address, offset)| format!("0x{:016x}+0x{offset:x}", address))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if groups_by_table.is_empty() {
        let reason = rejected_blobs
            .into_iter()
            .take(3)
            .collect::<Vec<_>>()
            .join("; ");
        bail!(
            "descriptor tables passed guards, but no compact blob passed bytecode validation: {reason}"
        );
    }

    let mut selected = Vec::with_capacity(groups_by_table.len());
    for candidates in groups_by_table.into_values() {
        let blob_locations = candidates
            .iter()
            .map(|(_, candidate)| (candidate.section.address, candidate.offset))
            .collect::<HashSet<_>>();
        if blob_locations.len() != 1 {
            bail!(
                "descriptor table {}+0x{:x} matches multiple compact blobs: {}",
                candidates[0].1.descriptors.section.name,
                candidates[0].1.descriptors.offset,
                candidates
                    .iter()
                    .map(|(_, candidate)| format!(
                        "{}+0x{:x}",
                        candidate.section.name, candidate.offset
                    ))
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let seeds = candidates
            .iter()
            .map(|(_, candidate)| candidate.descriptors.seed.value)
            .collect::<HashSet<_>>();
        if seeds.len() != 1 {
            bail!(
                "descriptor table {}+0x{:x} validates with multiple seeds",
                candidates[0].1.descriptors.section.name,
                candidates[0].1.descriptors.offset
            );
        }
        let first_profile = candidates[0].0;
        if candidates.iter().any(|(profile_index, _)| {
            profiles[*profile_index].package != profiles[first_profile].package
        }) {
            bail!(
                "descriptor table {}+0x{:x} validates with multiple distinct profiles: {}",
                candidates[0].1.descriptors.section.name,
                candidates[0].1.descriptors.offset,
                candidates
                    .iter()
                    .map(|(profile_index, _)| profiles[*profile_index].name.as_str())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        selected.push((first_profile, candidates[0].1.clone()));
    }

    let mut groups = Vec::with_capacity(selected.len());
    for (group_index, (profile_index, candidate)) in selected.into_iter().enumerate() {
        let profile = &profiles[profile_index];
        let native_total = candidate
            .descriptors
            .fields
            .last()
            .and_then(|descriptor| descriptor.native_base.checked_add(descriptor.native_count))
            .context("descriptor table has no rows or native range overflow")?;
        let native_candidates = find_native_tables(&sections, native_total)?;
        let mut native = match native_candidates.as_slice() {
            [native] => Some(native.clone()),
            _ => None,
        };
        let module = synthetic_module(&candidate, native.as_ref());
        let mut decode = decode_module(DecodeInput {
            module,
            profile: profile.package.clone(),
            seed: candidate.descriptors.seed.value,
        })?;
        resolve_wrappers(&sections, image_base, &mut decode);
        if native.is_none() {
            native = referenced_native_table(&sections, image_base, &decode, &native_candidates);
            if native.is_some() {
                let module = synthetic_module(&candidate, native.as_ref());
                decode = decode_module(DecodeInput {
                    module,
                    profile: profile.package.clone(),
                    seed: candidate.descriptors.seed.value,
                })?;
                resolve_wrappers(&sections, image_base, &mut decode);
            }
        }
        resolve_native_targets(bytes, &sections, &mut decode)?;
        let layout = group_layout_report(
            group_index,
            &profile.name,
            image_base,
            &candidate,
            native.as_ref(),
        );
        groups.push(PeGroupDecodeReport { layout, decode });
    }

    let strings = recover_pe_strings(&sections)?;
    Ok(PeDecodeReport {
        layout: image_layout_report(&sections, image_base, &groups),
        groups,
        strings,
    })
}

fn validate_pe64(file: &object::File<'_>) -> Result<()> {
    if file.format() != BinaryFormat::Pe || !file.is_64() {
        bail!("input is not a PE32+ executable");
    }
    if file.architecture() != Architecture::X86_64 {
        bail!(
            "PE architecture {:?} is not supported; expected x86_64",
            file.architecture()
        );
    }
    Ok(())
}

pub fn write_pe_layout(layout: &PeLayoutReport, out_dir: &Path) -> Result<()> {
    fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    let path = out_dir.join("pe-layout.json");
    fs::write(&path, serde_json::to_string_pretty(layout)?)
        .with_context(|| format!("write {}", path.display()))
}

fn collect_sections<'data>(
    file: &object::File<'data>,
    image_base: u64,
) -> Result<Vec<SectionView<'data>>> {
    let mut sections = Vec::new();
    for section in file.sections() {
        let Some((file_offset, raw_size)) = section.file_range() else {
            continue;
        };
        let name = section.name().context("read PE section name")?;
        let raw = section
            .data()
            .with_context(|| format!("read PE section {name}"))?;
        let virtual_size = section.size();
        if section.address() < image_base {
            bail!(
                "PE section {name} address 0x{:x} is below image base 0x{image_base:x}",
                section.address()
            );
        }
        let data_len = usize::try_from(virtual_size)
            .unwrap_or(usize::MAX)
            .min(raw.len());
        let executable = matches!(
            section.flags(),
            SectionFlags::Coff { characteristics }
                if characteristics.contains(pe::IMAGE_SCN_MEM_EXECUTE)
        );
        let writable = matches!(
            section.flags(),
            SectionFlags::Coff { characteristics }
                if characteristics.contains(pe::IMAGE_SCN_MEM_WRITE)
        );
        sections.push(SectionView {
            name,
            address: section.address(),
            file_offset,
            raw_size,
            virtual_size,
            data: &raw[..data_len],
            executable,
            writable,
        });
    }
    if sections.is_empty() {
        bail!("PE has no file-backed sections");
    }
    Ok(sections)
}

fn immediate64_seeds(sections: &[SectionView<'_>]) -> Result<Vec<SeedCandidate>> {
    let mut seeds = Vec::new();
    let mut seen = HashSet::new();
    for section in sections.iter().filter(|section| section.executable) {
        let mut decoder = Decoder::with_ip(64, section.data, section.address, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction = decoder.decode();
            for index in 0..instruction.op_count() {
                if instruction.op_kind(index) != OpKind::Immediate64 {
                    continue;
                }
                let value = instruction.immediate64();
                if seen.insert(value) {
                    seeds.push(SeedCandidate {
                        value,
                        instruction_va: Some(instruction.ip()),
                    });
                    if seeds.len() > MAX_SEED_CANDIDATES {
                        bail!(
                            "PE contains more than {MAX_SEED_CANDIDATES} unique imm64 candidates"
                        );
                    }
                }
            }
        }
    }
    Ok(seeds)
}

fn find_descriptor_tables<'a>(
    sections: &[SectionView<'a>],
    seeds: &[SeedCandidate],
) -> Vec<DescriptorCandidate<'a>> {
    let row_len = DESCRIPTOR_FIELD_COUNT * 8;
    let mut starts_by_const_pool_zero = HashMap::<u64, Vec<(SectionView<'a>, usize)>>::new();
    // Amice emits the blob, descriptor table, and native table as constant globals.
    for section in sections
        .iter()
        .filter(|section| !section.executable && !section.writable)
    {
        if section.data.len() < row_len {
            continue;
        }
        for offset in (0..=section.data.len().saturating_sub(row_len)).step_by(8) {
            let encrypted_const_pool_offset = descriptor_word(section.data, offset, 2);
            starts_by_const_pool_zero
                .entry(encrypted_const_pool_offset)
                .or_default()
                .push((*section, offset));
        }
    }

    let mut candidates = Vec::new();
    for seed in seeds {
        let const_pool_zero = encrypt_descriptor_field(seed.value, 0, 2, 0);
        let Some(starts) = starts_by_const_pool_zero.get(&const_pool_zero) else {
            continue;
        };
        let native_base_zero = encrypt_descriptor_field(seed.value, 0, 5, 0);
        let valid_guard =
            encrypt_descriptor_field(seed.value, 0, 7, descriptor_guard(seed.value, 0));
        for (section, offset) in starts {
            if descriptor_word(section.data, *offset, 5) != native_base_zero
                || descriptor_word(section.data, *offset, 7) != valid_guard
            {
                continue;
            }
            let Some(first) = descriptor_row(section.data, *offset, seed.value, 0) else {
                continue;
            };
            if !descriptor_extends_layout(&first, 0, 0) {
                continue;
            }
            let mut fields = vec![first];
            let mut cursor = *offset + row_len;
            while fields.len() < MAX_DESCRIPTOR_COUNT && cursor + row_len <= section.data.len() {
                let fn_index = fields.len();
                let Some(next) = descriptor_row(section.data, cursor, seed.value, fn_index) else {
                    break;
                };
                let previous = fields.last().expect("first descriptor was added");
                let blob_offset = previous.code_offset + previous.code_len;
                let native_base = previous.native_base + previous.native_count;
                if !descriptor_extends_layout(&next, blob_offset, native_base) {
                    break;
                }
                fields.push(next);
                cursor += row_len;
            }
            let (chunks, _) = section.data[*offset..*offset + fields.len() * row_len].as_chunks();
            let words = chunks.iter().copied().map(u64::from_le_bytes).collect();
            candidates.push(DescriptorCandidate {
                seed: *seed,
                section: *section,
                offset: *offset,
                words,
                fields,
            });
        }
    }
    candidates
}

fn descriptor_word(data: &[u8], row_offset: usize, field_index: usize) -> u64 {
    let start = row_offset + field_index * 8;
    u64::from_le_bytes(
        *data[start..]
            .first_chunk()
            .expect("eight-byte descriptor word"),
    )
}

fn descriptor_row(
    data: &[u8],
    offset: usize,
    seed: u64,
    fn_index: usize,
) -> Option<DescriptorFields> {
    let bytes = data.get(offset..offset + DESCRIPTOR_FIELD_COUNT * 8)?;
    let (chunks, _) = bytes.as_chunks();
    let words = chunks
        .iter()
        .copied()
        .map(u64::from_le_bytes)
        .collect::<Vec<_>>();
    decrypt_descriptor_words(seed, fn_index, &words)
}

fn descriptor_extends_layout(
    descriptor: &DescriptorFields,
    expected_blob_offset: u64,
    expected_native_base: u64,
) -> bool {
    descriptor.const_pool_offset == expected_blob_offset
        && descriptor.native_base == expected_native_base
        && descriptor.const_pool_len > 0
        && descriptor.code_len > 0
        && descriptor
            .const_pool_offset
            .checked_add(descriptor.const_pool_len)
            == Some(descriptor.code_offset)
        && descriptor
            .code_offset
            .checked_add(descriptor.code_len)
            .is_some_and(|end| end <= MAX_BLOB_LEN)
        && descriptor
            .native_base
            .checked_add(descriptor.native_count)
            .is_some_and(|end| end <= MAX_NATIVE_COUNT)
}

fn find_compact_blobs<'a>(
    sections: &[SectionView<'a>],
    profile: &ProfilePackage,
    descriptors: DescriptorCandidate<'a>,
) -> Result<Vec<BlobCandidate<'a>>> {
    let blob_len = descriptors
        .fields
        .last()
        .and_then(|descriptor| descriptor.code_offset.checked_add(descriptor.code_len))
        .context("descriptor blob range overflow")?;
    let blob_len = usize::try_from(blob_len).context("compact blob length does not fit usize")?;
    let mut locations = Vec::new();
    for section in sections
        .iter()
        .filter(|section| !section.executable && !section.writable)
    {
        if section.data.len() < blob_len {
            continue;
        }
        for offset in 0..=section.data.len() - blob_len {
            let blob = &section.data[offset..offset + blob_len];
            if decode_blob(
                profile,
                blob,
                "PE compact blob candidate",
                &descriptors.fields,
            )
            .is_ok()
            {
                locations.push((*section, offset));
            }
        }
    }
    if locations.is_empty() {
        bail!(
            "seed 0x{:016x} table {}+0x{:x} describes {} bytes, but no PE data range decoded",
            descriptors.seed.value,
            descriptors.section.name,
            descriptors.offset,
            blob_len
        );
    }
    Ok(locations
        .into_iter()
        .map(|(section, offset)| BlobCandidate {
            descriptors: DescriptorCandidate {
                seed: descriptors.seed,
                section: descriptors.section,
                offset: descriptors.offset,
                words: descriptors.words.clone(),
                fields: descriptors.fields.clone(),
            },
            section,
            offset,
            len: blob_len,
        })
        .collect())
}

#[derive(Clone)]
struct NativeTable<'a> {
    section: SectionView<'a>,
    offset: usize,
    targets: Vec<u64>,
}

fn find_native_tables<'a>(
    sections: &[SectionView<'a>],
    count: u64,
) -> Result<Vec<NativeTable<'a>>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let count = usize::try_from(count).context("native table count does not fit usize")?;
    let byte_len = count
        .checked_mul(8)
        .context("native table byte length overflow")?;
    let mut candidates = Vec::new();
    for section in sections
        .iter()
        .filter(|section| !section.executable && !section.writable)
    {
        if section.data.len() < byte_len {
            continue;
        }
        for offset in (0..=section.data.len() - byte_len).step_by(8) {
            let (chunks, _) = section.data[offset..offset + byte_len].as_chunks();
            let targets = chunks
                .iter()
                .copied()
                .map(u64::from_le_bytes)
                .collect::<Vec<_>>();
            if targets
                .iter()
                .all(|target| executable_va(sections, *target))
            {
                candidates.push(NativeTable {
                    section: *section,
                    offset,
                    targets,
                });
            }
        }
    }
    Ok(candidates)
}

fn referenced_native_table<'a>(
    sections: &[SectionView<'a>],
    image_base: u64,
    report: &DecodeReport,
    candidates: &[NativeTable<'a>],
) -> Option<NativeTable<'a>> {
    if candidates.is_empty() {
        return None;
    }
    let ranges = pe_function_ranges(sections, image_base);
    let roots = report
        .descriptors
        .iter()
        .filter_map(|descriptor| descriptor.wrapper_va.as_deref())
        .filter_map(parse_hex)
        .filter_map(|wrapper| function_range(&ranges, wrapper).map(|(start, _)| start))
        .collect::<HashSet<_>>();
    let references = reachable_data_references(sections, &ranges, roots);
    let mut matched = candidates
        .iter()
        .filter(|candidate| {
            let start = candidate.section.address + candidate.offset as u64;
            let end = start + candidate.targets.len() as u64 * 8;
            references
                .iter()
                .any(|reference| *reference >= start && *reference < end)
        })
        .cloned()
        .collect::<Vec<_>>();
    (matched.len() == 1).then(|| matched.remove(0))
}

fn reachable_data_references(
    sections: &[SectionView<'_>],
    ranges: &[(u64, u64)],
    roots: HashSet<u64>,
) -> HashSet<u64> {
    let mut references = HashSet::new();
    let mut pending = roots.into_iter().collect::<Vec<_>>();
    let mut visited = HashSet::new();
    while let Some(start) = pending.pop() {
        if !visited.insert(start) || visited.len() > MAX_RUNTIME_GRAPH_FUNCTIONS {
            continue;
        }
        let Some((_, end)) = function_range(ranges, start) else {
            continue;
        };
        let Some(section) = sections.iter().find(|section| {
            section.executable
                && start >= section.address
                && end <= section.address + section.data.len() as u64
        }) else {
            continue;
        };
        let offset = usize::try_from(start - section.address).expect("validated function offset");
        let len = usize::try_from(end - start).expect("validated function length");
        let mut decoder = Decoder::with_ip(
            64,
            &section.data[offset..offset + len],
            start,
            DecoderOptions::NONE,
        );
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_ip_rel_memory_operand() {
                references.insert(instruction.ip_rel_memory_address());
            }
            for operand in 0..instruction.op_count() {
                if instruction.op_kind(operand) == OpKind::Immediate64 {
                    references.insert(instruction.immediate64());
                }
            }
            if instruction.mnemonic() == iced_x86::Mnemonic::Call
                && matches!(
                    instruction.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                )
                && let Some((callee, _)) = function_range(ranges, instruction.near_branch_target())
                && !visited.contains(&callee)
            {
                pending.push(callee);
            }
        }
    }
    references
}

fn pe_function_ranges(sections: &[SectionView<'_>], image_base: u64) -> Vec<(u64, u64)> {
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

fn function_range(ranges: &[(u64, u64)], address: u64) -> Option<(u64, u64)> {
    ranges
        .iter()
        .copied()
        .find(|(start, end)| address >= *start && address < *end)
}

fn parse_hex(value: &str) -> Option<u64> {
    u64::from_str_radix(value.strip_prefix("0x")?, 16).ok()
}

fn executable_va(sections: &[SectionView<'_>], address: u64) -> bool {
    sections.iter().any(|section| {
        section.executable
            && address >= section.address
            && address < section.address.saturating_add(section.virtual_size)
    })
}

fn synthetic_module(candidate: &BlobCandidate<'_>, native: Option<&NativeTable<'_>>) -> LlModule {
    let bytecode = &candidate.section.data[candidate.offset..candidate.offset + candidate.len];
    let mut module = LlModule {
        byte_globals: vec![ByteGlobal {
            name: format!(
                "pe.bytecode.va_{:x}",
                candidate.section.address + candidate.offset as u64
            ),
            len: bytecode.len(),
            bytes: bytecode.to_vec(),
            section: Some(candidate.section.name.to_owned()),
        }],
        i64_globals: vec![I64Global {
            name: format!(
                "pe.descriptors.va_{:x}",
                candidate.descriptors.section.address + candidate.descriptors.offset as u64
            ),
            len: candidate.descriptors.words.len(),
            words: candidate.descriptors.words.clone(),
        }],
        ..LlModule::default()
    };
    if let Some(native) = native {
        module.ptr_globals.push(PtrGlobal {
            name: format!(
                "pe.native.va_{:x}",
                native.section.address + native.offset as u64
            ),
            len: native.targets.len(),
            targets: native
                .targets
                .iter()
                .map(|target| format!("0x{target:016x}"))
                .collect(),
        });
    }
    module
}

fn group_layout_report(
    group_index: usize,
    profile: &str,
    image_base: u64,
    candidate: &BlobCandidate<'_>,
    native: Option<&NativeTable<'_>>,
) -> PeGroupLayoutReport {
    let location = |section: SectionView<'_>, offset: usize, size: usize| PeLocation {
        section: section.name.to_owned(),
        file_offset: section.file_offset + offset as u64,
        rva: section.address + offset as u64 - image_base,
        va: format!("0x{:016x}", section.address + offset as u64),
        size,
    };
    PeGroupLayoutReport {
        group_index,
        profile: profile.to_owned(),
        seed: PeSeedEvidence {
            seed: format!("0x{:016x}", candidate.descriptors.seed.value),
            source: if candidate.descriptors.seed.instruction_va.is_none() {
                "argument".to_owned()
            } else {
                "x86_64_imm64".to_owned()
            },
            instruction_va: candidate
                .descriptors
                .seed
                .instruction_va
                .map(|address| format!("0x{address:016x}")),
        },
        bytecode: location(candidate.section, candidate.offset, candidate.len),
        descriptors: location(
            candidate.descriptors.section,
            candidate.descriptors.offset,
            candidate.descriptors.words.len() * 8,
        ),
        native_table: native
            .map(|table| location(table.section, table.offset, table.targets.len() * 8)),
    }
}

fn image_layout_report(
    sections: &[SectionView<'_>],
    image_base: u64,
    groups: &[PeGroupDecodeReport],
) -> PeLayoutReport {
    PeLayoutReport {
        format: "PE32+".to_owned(),
        architecture: "x86_64".to_owned(),
        image_base: format!("0x{image_base:016x}"),
        symbol_file: None,
        groups: groups.iter().map(|group| group.layout.clone()).collect(),
        sections: sections
            .iter()
            .map(|section| PeSectionReport {
                name: section.name.to_owned(),
                rva: section.address - image_base,
                va: format!("0x{:016x}", section.address),
                file_offset: section.file_offset,
                raw_size: section.raw_size,
                virtual_size: section.virtual_size,
                executable: section.executable,
                writable: section.writable,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_movabs_immediate_as_seed_evidence() {
        let seed = 0xf9e6_0352_f5b5_e4ba_u64;
        let mut code = vec![0x48, 0xb9];
        code.extend_from_slice(&seed.to_le_bytes());
        code.push(0xc3);
        let section = SectionView {
            name: ".text",
            address: 0x140001000,
            file_offset: 0x400,
            raw_size: code.len() as u64,
            virtual_size: code.len() as u64,
            data: &code,
            executable: true,
            writable: false,
        };

        let seeds = immediate64_seeds(&[section]).unwrap();

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].value, seed);
        assert_eq!(seeds[0].instruction_va, Some(0x140001000));
    }

    #[test]
    fn descriptor_scan_requires_guards_and_contiguous_layout() {
        let seed = 0x1234_5678_9abc_def0;
        let plain = [
            DescriptorFields {
                code_offset: 1,
                code_len: 32,
                const_pool_offset: 0,
                const_pool_len: 1,
                bytecode_key: 0x1111,
                native_base: 0,
                native_count: 2,
                guard: descriptor_guard(seed, 0),
            },
            DescriptorFields {
                code_offset: 34,
                code_len: 64,
                const_pool_offset: 33,
                const_pool_len: 1,
                bytecode_key: 0x2222,
                native_base: 2,
                native_count: 1,
                guard: descriptor_guard(seed, 1),
            },
        ];
        let mut bytes = vec![0u8; 16];
        for (fn_index, descriptor) in plain.iter().enumerate() {
            let fields = [
                descriptor.code_offset,
                descriptor.code_len,
                descriptor.const_pool_offset,
                descriptor.const_pool_len,
                descriptor.bytecode_key,
                descriptor.native_base,
                descriptor.native_count,
                descriptor.guard,
            ];
            for (field_index, value) in fields.into_iter().enumerate() {
                bytes.extend_from_slice(
                    &encrypt_descriptor_field(seed, fn_index, field_index, value).to_le_bytes(),
                );
            }
        }
        bytes.extend_from_slice(&[0u8; 64]);
        let section = SectionView {
            name: ".rdata",
            address: 0x140010000,
            file_offset: 0x1000,
            raw_size: bytes.len() as u64,
            virtual_size: bytes.len() as u64,
            data: &bytes,
            executable: false,
            writable: false,
        };

        let tables = find_descriptor_tables(
            &[section],
            &[SeedCandidate {
                value: seed,
                instruction_va: Some(0x140001000),
            }],
        );

        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].offset, 16);
        assert_eq!(tables[0].fields, plain);
    }

    #[test]
    fn native_table_ignores_writable_pointer_arrays() {
        let text = [0u8; 0x100];
        let targets = [0x140001010_u64, 0x140001020, 0x140001030];
        let readonly_bytes = targets
            .iter()
            .flat_map(|target| target.to_le_bytes())
            .collect::<Vec<_>>();
        let writable_bytes = readonly_bytes.clone();
        let sections = [
            SectionView {
                name: ".text",
                address: 0x140001000,
                file_offset: 0x400,
                raw_size: text.len() as u64,
                virtual_size: text.len() as u64,
                data: &text,
                executable: true,
                writable: false,
            },
            SectionView {
                name: ".rdata",
                address: 0x140002000,
                file_offset: 0x800,
                raw_size: readonly_bytes.len() as u64,
                virtual_size: readonly_bytes.len() as u64,
                data: &readonly_bytes,
                executable: false,
                writable: false,
            },
            SectionView {
                name: ".data",
                address: 0x140003000,
                file_offset: 0xc00,
                raw_size: writable_bytes.len() as u64,
                virtual_size: writable_bytes.len() as u64,
                data: &writable_bytes,
                executable: false,
                writable: true,
            },
        ];

        let tables = find_native_tables(&sections, targets.len() as u64).unwrap();
        assert_eq!(tables.len(), 1);
        let table = &tables[0];

        assert_eq!(table.section.name, ".rdata");
        assert_eq!(table.targets, targets);
    }

    #[test]
    fn short_data_section_cannot_be_a_descriptor_table() {
        let data = [0u8; DESCRIPTOR_FIELD_COUNT * 8 - 1];
        let section = SectionView {
            name: ".tiny",
            address: 0x140002000,
            file_offset: 0x800,
            raw_size: data.len() as u64,
            virtual_size: data.len() as u64,
            data: &data,
            executable: false,
            writable: false,
        };

        let tables = find_descriptor_tables(
            &[section],
            &[SeedCandidate {
                value: 1,
                instruction_va: None,
            }],
        );

        assert!(tables.is_empty());
    }

    #[test]
    fn rejects_non_pe_input() {
        let profile = ProfilePackage::builtin_test().unwrap();
        let error = decode_pe64(b"not a PE", &profile, None).unwrap_err();

        assert!(error.to_string().contains("parse input executable"));
    }
}
