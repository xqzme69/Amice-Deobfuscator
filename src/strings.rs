use crate::llvm_ir::{ByteLiteralGlobal, LlFunction, LlModule};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StringAlgorithm {
    Plain,
    Xor,
    SimdXor,
}

impl StringAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Xor => "xor",
            Self::SimdXor => "simd_xor",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringDecodeOptions {
    pub algorithm: Option<StringAlgorithm>,
    pub key_global: Option<String>,
    pub globals: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RecoveredString {
    pub global: String,
    pub literal_index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    pub algorithm: StringAlgorithm,
    pub evidence: Vec<String>,
    pub encrypted_hex: String,
    pub plaintext_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    pub escaped: String,
    pub nul_terminated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StringReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<StringAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_global: Option<String>,
    pub evidence: Vec<String>,
    pub strings: Vec<RecoveredString>,
}

pub fn recover_strings(module: &LlModule, options: &StringDecodeOptions) -> Result<StringReport> {
    let (detected, mut report_evidence) = detect_algorithm(module)?;
    let mut algorithm = options.algorithm.or(detected);
    if options.key_global.is_some() && algorithm != Some(StringAlgorithm::SimdXor) {
        bail!("--string-key-global requires simd_xor string algorithm");
    }
    if options.algorithm.is_some() {
        report_evidence.push("algorithm_override".to_owned());
    }

    let requested = requested_globals(module, options.globals.as_deref())?;
    let mut key_global = None;
    let mut strings = Vec::new();
    if let Some(selected_algorithm) = algorithm {
        let refs = decryptor_global_refs(module, selected_algorithm);
        let (selected_key_global, key, key_evidence) = match selected_algorithm {
            StringAlgorithm::Plain => (None, Vec::new(), None),
            StringAlgorithm::Xor => (None, vec![0xaa], None),
            StringAlgorithm::SimdXor => {
                let selected = select_simd_key(module, &refs, options.key_global.as_deref())?;
                (selected.global, selected.bytes, Some(selected.evidence))
            }
        };
        key_global = selected_key_global;
        if let Some(evidence) = key_evidence {
            report_evidence.push(evidence);
        }

        for literal in &module.byte_literals {
            if key_global.as_deref() == Some(literal.name.as_str()) {
                continue;
            }
            let marked = is_string_marked(literal);
            let referenced = refs.contains(&literal.name);
            let selected = requested
                .as_ref()
                .is_some_and(|names| names.contains(&literal.name));
            if requested.is_some() {
                if !selected {
                    continue;
                }
            } else if !marked && !referenced {
                continue;
            }
            if literal.len <= 1 || literal.bytes.iter().all(|byte| *byte == 0) {
                continue;
            }
            if selected_algorithm == StringAlgorithm::SimdXor && key.len() < literal.len.min(32) {
                bail!(
                    "inlined simd_xor key proves only {} bytes, but {}[{}] needs {}; use --string-key-global",
                    key.len(),
                    literal.name,
                    literal.literal_index,
                    literal.len.min(32)
                );
            }

            let plaintext = match selected_algorithm {
                StringAlgorithm::Plain => literal.bytes.clone(),
                StringAlgorithm::Xor | StringAlgorithm::SimdXor => literal
                    .bytes
                    .iter()
                    .zip(key.iter().cycle())
                    .map(|(byte, key_byte)| byte ^ key_byte)
                    .collect::<Vec<_>>(),
            };
            if selected_algorithm == StringAlgorithm::Plain && !is_plain_string(&plaintext) {
                continue;
            }
            strings.push(recovered_literal(
                literal,
                selected_algorithm,
                plaintext,
                referenced,
                selected,
            ));
        }
    } else {
        strings.extend(recover_plain_globals(module, requested.as_ref()));
        if requested.is_none() {
            strings.extend(recover_stack_strings(module));
        }
        if !strings.is_empty() {
            algorithm = Some(StringAlgorithm::Plain);
            report_evidence.push("optimized_plaintext".to_owned());
        }
    }

    if options.globals.is_some() && strings.is_empty() {
        bail!("requested string globals contain no decodable byte literals");
    }
    Ok(StringReport {
        algorithm,
        key_global,
        evidence: report_evidence,
        strings,
    })
}

pub fn write_string_report(report: &StringReport, out_dir: &Path) -> Result<()> {
    fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    let json_path = out_dir.join("strings.json");
    fs::write(&json_path, serde_json::to_string_pretty(report)?)
        .with_context(|| format!("write {}", json_path.display()))?;

    let text_path = out_dir.join("strings.txt");
    let mut text = String::new();
    for recovered in &report.strings {
        writeln!(
            text,
            "{}[{}] {} \"{}\"",
            recovered.global,
            recovered.literal_index,
            recovered.algorithm.as_str(),
            recovered.escaped
        )?;
    }
    fs::write(&text_path, text).with_context(|| format!("write {}", text_path.display()))
}

fn detect_algorithm(module: &LlModule) -> Result<(Option<StringAlgorithm>, Vec<String>)> {
    let xor = module.functions.iter().any(is_xor_function)
        || source_has_label(&module.source, "__amice__decrypt_strings_");
    let simd = module.functions.iter().any(is_simd_function)
        || source_has_label(&module.source, "simd_xor_cipher_");
    match (xor, simd) {
        (true, true) => bail!("IR contains both xor and simd_xor Amice decryptor markers"),
        (true, false) => Ok((
            Some(StringAlgorithm::Xor),
            vec!["amice_xor_decryptor".to_owned()],
        )),
        (false, true) => Ok((
            Some(StringAlgorithm::SimdXor),
            vec!["amice_simd_xor_decryptor".to_owned()],
        )),
        (false, false) => Ok((None, vec!["no_amice_string_decryptor".to_owned()])),
    }
}

fn source_has_label(source: &str, prefix: &str) -> bool {
    let branch_label = format!("%{prefix}");
    source.lines().any(|line| {
        let line = line.trim_start();
        !line.starts_with(['@', '!']) && (line.starts_with(prefix) || line.contains(&branch_label))
    })
}

fn decryptor_global_refs(module: &LlModule, algorithm: StringAlgorithm) -> HashSet<String> {
    let decryptors = module
        .functions
        .iter()
        .filter(|function| match algorithm {
            StringAlgorithm::Plain => false,
            StringAlgorithm::Xor => is_xor_function(function),
            StringAlgorithm::SimdXor => is_simd_function(function),
        })
        .map(|function| function.name.as_str())
        .collect::<HashSet<_>>();

    module
        .functions
        .iter()
        .filter(|function| {
            decryptors.contains(function.name.as_str())
                || function
                    .direct_callees
                    .iter()
                    .any(|callee| decryptors.contains(callee.as_str()))
        })
        .flat_map(|function| function.global_refs.iter().cloned())
        .collect()
}

fn is_xor_function(function: &LlFunction) -> bool {
    let name = function.name.as_str();
    name.contains("decrypt_strings_stub") || name.starts_with("__amice__decrypt_strings_")
}

fn is_simd_function(function: &LlFunction) -> bool {
    let name = function.name.as_str();
    name.contains("simd_xor_decrypt_stub") || name.starts_with("simd_xor_cipher_")
}

fn is_string_marked(literal: &ByteLiteralGlobal) -> bool {
    if literal.section.as_deref() == Some("llvm.metadata") {
        return false;
    }
    literal.name.contains(".str")
        || literal
            .section
            .as_deref()
            .is_some_and(|section| section.contains(".str"))
}

struct SimdKey {
    global: Option<String>,
    bytes: Vec<u8>,
    evidence: String,
}

fn select_simd_key(
    module: &LlModule,
    refs: &HashSet<String>,
    override_name: Option<&str>,
) -> Result<SimdKey> {
    if let Some(name) = override_name {
        let global = module
            .byte_globals
            .iter()
            .find(|global| global.name == name)
            .with_context(|| format!("string key global {name} was not found"))?;
        if global.len != 32 {
            bail!(
                "string key global {name} has {} bytes, expected 32",
                global.len
            );
        }
        return Ok(SimdKey {
            global: Some(global.name.clone()),
            bytes: global.bytes.clone(),
            evidence: "key_global_override".to_owned(),
        });
    }

    let candidates = module
        .byte_globals
        .iter()
        .filter(|global| global.len == 32 && refs.contains(&global.name))
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [global] => Ok(SimdKey {
            global: Some(global.name.clone()),
            bytes: global.bytes.clone(),
            evidence: "referenced_key_global".to_owned(),
        }),
        [] => inline_simd_key(&module.source)
            .map(|bytes| SimdKey {
                global: None,
                bytes,
                evidence: "inlined_key_immediates".to_owned(),
            })
            .context(
                "simd_xor decryptor found, but neither a referenced 32-byte key global nor a consistent inlined key was found; use --string-key-global",
            ),
        _ => bail!(
            "simd_xor decryptor references multiple 32-byte globals: {}; use --string-key-global",
            candidates
                .iter()
                .map(|global| global.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn inline_simd_key(source: &str) -> Option<Vec<u8>> {
    let mut runs = BTreeMap::<String, BTreeMap<usize, u8>>::new();
    for line in source.lines() {
        let line = line.trim();
        let Some((result, rhs)) = line.split_once(" = xor i8 ") else {
            continue;
        };
        if !result.starts_with('%') || !result.contains("xored_rest") {
            continue;
        }
        let Some((_, immediate)) = rhs.rsplit_once(',') else {
            continue;
        };
        let Some(immediate) = immediate.split_whitespace().next() else {
            continue;
        };
        let Some(value) = immediate.parse::<i16>().ok() else {
            continue;
        };
        if !(-128..=255).contains(&value) {
            return None;
        }
        let (base, index) = local_sequence_name(result);
        runs.entry(base).or_default().insert(index, value as u8);
    }

    let mut key = Vec::<u8>::new();
    for run in runs.values() {
        let bytes = contiguous_bytes(run);
        for (index, byte) in bytes.iter().copied().enumerate() {
            if let Some(previous) = key.get(index) {
                if *previous != byte {
                    return None;
                }
            } else {
                key.push(byte);
            }
        }
    }
    (!key.is_empty()).then_some(key)
}

fn local_sequence_name(name: &str) -> (String, usize) {
    if let Some((base, suffix)) = name.rsplit_once('.')
        && !suffix.is_empty()
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
    {
        return (base.to_owned(), suffix.parse().unwrap_or(0));
    }
    (name.to_owned(), 0)
}

fn contiguous_bytes(values: &BTreeMap<usize, u8>) -> Vec<u8> {
    (0..)
        .map_while(|index| values.get(&index).copied())
        .collect()
}

fn recover_plain_globals(
    module: &LlModule,
    requested: Option<&HashSet<String>>,
) -> Vec<RecoveredString> {
    module
        .byte_literals
        .iter()
        .filter(|literal| {
            requested
                .map(|names| names.contains(&literal.name))
                .unwrap_or_else(|| is_string_marked(literal))
                && is_plain_string(&literal.bytes)
        })
        .map(|literal| {
            recovered_literal(
                literal,
                StringAlgorithm::Plain,
                literal.bytes.clone(),
                false,
                false,
            )
        })
        .collect()
}

fn recover_stack_strings(module: &LlModule) -> Vec<RecoveredString> {
    #[derive(Default)]
    struct Container {
        len: usize,
        bytes: BTreeMap<usize, u8>,
    }

    let mut function = String::new();
    let mut containers = BTreeMap::<(String, String), Container>::new();
    let mut geps = HashMap::<(String, String), (String, usize)>::new();
    for line in module.source.lines() {
        let line = line.trim();
        if line.starts_with("define ") {
            function = function_name(line).unwrap_or_else(|| "unknown".to_owned());
            continue;
        }
        if line == "}" {
            function.clear();
            continue;
        }
        if function.is_empty() {
            continue;
        }
        if let Some((name, len)) = stack_alloca(line) {
            containers.entry((function.clone(), name)).or_default().len = len;
            continue;
        }
        if let Some((gep, container, index)) = stack_gep(line) {
            geps.insert((function.clone(), gep), (container, index));
            continue;
        }
        let Some((pointer, value)) = constant_byte_store(line) else {
            continue;
        };
        let target = if containers.contains_key(&(function.clone(), pointer.clone())) {
            Some((pointer, 0))
        } else {
            geps.get(&(function.clone(), pointer)).cloned()
        };
        if let Some((container, index)) = target
            && let Some(entry) = containers.get_mut(&(function.clone(), container))
        {
            entry.bytes.insert(index, value);
        }
    }

    containers
        .into_iter()
        .filter_map(|((function, name), container)| {
            let bytes = contiguous_bytes(&container.bytes);
            if bytes.len() < 2 || bytes.len() > container.len || !is_plain_string(&bytes) {
                return None;
            }
            Some(recovered_bytes(
                format!("stack:{function}:{name}"),
                0,
                None,
                StringAlgorithm::Plain,
                bytes.clone(),
                bytes,
                vec!["amice_stack_container".to_owned()],
            ))
        })
        .collect()
}

fn stack_alloca(line: &str) -> Option<(String, usize)> {
    let (name, rhs) = line.split_once(" = alloca [")?;
    if !name.starts_with('%') || !name.contains("string_container") {
        return None;
    }
    let len = rhs.split_once(" x i8]")?.0.trim().parse().ok()?;
    Some((name.to_owned(), len))
}

fn stack_gep(line: &str) -> Option<(String, String, usize)> {
    let (name, rhs) = line.split_once(" = getelementptr ")?;
    let pointer = rhs.split("ptr ").nth(1)?.split([',', ' ']).next()?;
    if !pointer.starts_with('%') || !pointer.contains("string_container") {
        return None;
    }
    let index = rhs
        .rsplit_once(", i64 ")?
        .1
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some((name.to_owned(), pointer.to_owned(), index))
}

fn constant_byte_store(line: &str) -> Option<(String, u8)> {
    let rest = line.strip_prefix("store i8 ")?;
    let (value, pointer) = rest.split_once(", ptr ")?;
    let value = value.trim().parse::<i16>().ok()?;
    if !(-128..=255).contains(&value) {
        return None;
    }
    let pointer = pointer.split([',', ' ']).next()?;
    pointer
        .starts_with('%')
        .then(|| (pointer.to_owned(), value as u8))
}

fn function_name(line: &str) -> Option<String> {
    let after_at = line.split_once('@')?.1;
    if let Some(quoted) = after_at.strip_prefix('"') {
        return Some(quoted.split('"').next()?.to_owned());
    }
    Some(after_at.split('(').next()?.to_owned())
}

fn recovered_literal(
    literal: &ByteLiteralGlobal,
    algorithm: StringAlgorithm,
    plaintext: Vec<u8>,
    referenced: bool,
    selected: bool,
) -> RecoveredString {
    let mut evidence = Vec::new();
    if let Some(section) = &literal.section
        && section.contains(".str")
    {
        evidence.push(format!("section:{section}"));
    }
    if literal.name.contains(".str") {
        evidence.push("global_name:.str".to_owned());
    }
    if algorithm == StringAlgorithm::Plain {
        evidence.push("plain_global".to_owned());
    }
    if referenced {
        evidence.push("decryptor_reference".to_owned());
    }
    if selected {
        evidence.push("global_override".to_owned());
    }
    recovered_bytes(
        literal.name.clone(),
        literal.literal_index,
        literal.section.clone(),
        algorithm,
        literal.bytes.clone(),
        plaintext,
        evidence,
    )
}

pub(crate) fn recovered_bytes(
    global: String,
    literal_index: usize,
    section: Option<String>,
    algorithm: StringAlgorithm,
    encrypted: Vec<u8>,
    plaintext: Vec<u8>,
    evidence: Vec<String>,
) -> RecoveredString {
    let nul_terminated = plaintext.last() == Some(&0);
    let display_len = plaintext
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    let display = &plaintext[..display_len];
    RecoveredString {
        global,
        literal_index,
        section,
        algorithm,
        evidence,
        encrypted_hex: hex_bytes(&encrypted),
        plaintext_hex: hex_bytes(&plaintext),
        text: String::from_utf8(display.to_vec()).ok(),
        escaped: escape_bytes(display),
        nul_terminated,
    }
}

fn is_plain_string(bytes: &[u8]) -> bool {
    let display_len = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    let display = &bytes[..display_len];
    !display.is_empty()
        && std::str::from_utf8(display).is_ok_and(|text| {
            text.chars()
                .all(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
        })
}

fn requested_globals(
    module: &LlModule,
    requested: Option<&[String]>,
) -> Result<Option<HashSet<String>>> {
    let Some(requested) = requested else {
        return Ok(None);
    };
    let names = requested.iter().cloned().collect::<HashSet<_>>();
    for name in &names {
        if !module
            .byte_literals
            .iter()
            .any(|literal| literal.name == *name)
        {
            bail!("string global {name} was not found or has no byte literal");
        }
    }
    Ok(Some(names))
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    hex
}

fn escape_bytes(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text
            .chars()
            .flat_map(|ch| ch.escape_default())
            .collect::<String>();
    }
    let mut escaped = String::new();
    for byte in bytes {
        match byte {
            b' '..=b'~' if !matches!(byte, b'\\' | b'"') => escaped.push(char::from(*byte)),
            b'\\' => escaped.push_str("\\\\"),
            b'"' => escaped.push_str("\\\""),
            b'\n' => escaped.push_str("\\n"),
            b'\r' => escaped.push_str("\\r"),
            b'\t' => escaped.push_str("\\t"),
            _ => write!(escaped, "\\x{byte:02x}").expect("writing to String cannot fail"),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llvm_ir::parse_ll_module;

    #[test]
    fn recovers_source_xor_string() {
        let module = parse_ll_module(
            r#"
@.str = internal global [6 x i8] c"\C2\CF\C6\C6\C5\AA", section ".str.test"
define internal void @decrypt_strings_stub() {
  %decoded = xor i8 0, -86
  ret void
}
"#,
        )
        .unwrap();
        let report = recover_strings(&module, &StringDecodeOptions::default()).unwrap();

        assert_eq!(report.algorithm, Some(StringAlgorithm::Xor));
        assert_eq!(report.strings.len(), 1);
        assert_eq!(report.strings[0].text.as_deref(), Some("hello"));
        assert!(report.strings[0].nul_terminated);
    }

    #[test]
    fn recovers_source_simd_xor_string_and_key() {
        let module = parse_ll_module(
            r#"
@0 = internal constant [32 x i8] c"\01\02\03\04\05\06\07\08\09\0A\0B\0C\0D\0E\0F\10\11\12\13\14\15\16\17\18\19\1A\1B\1C\1D\1E\1F\20"
@.str = internal global [6 x i8] c"igohj\06", section ".str.test"
define internal void @simd_xor_decrypt_stub() {
  %key = load i8, ptr @0
  ret void
}
"#,
        )
        .unwrap();
        let report = recover_strings(&module, &StringDecodeOptions::default()).unwrap();

        assert_eq!(report.algorithm, Some(StringAlgorithm::SimdXor));
        assert_eq!(report.key_global.as_deref(), Some("0"));
        assert_eq!(report.strings[0].text.as_deref(), Some("hello"));
    }

    #[test]
    fn reports_plain_string_after_optimizer_removed_decryptor() {
        let module =
            parse_ll_module(r#"@.str = private constant [5 x i8] c"hello", section ".str.test""#)
                .unwrap();
        let report = recover_strings(&module, &StringDecodeOptions::default()).unwrap();

        assert_eq!(report.algorithm, Some(StringAlgorithm::Plain));
        assert_eq!(report.strings[0].text.as_deref(), Some("hello"));
    }

    #[test]
    fn does_not_treat_binary_dot_str_as_plaintext() {
        let module = parse_ll_module(
            r#"@.str = private constant [3 x i8] c"\FF\80\00", section ".str.test""#,
        )
        .unwrap();
        let report = recover_strings(&module, &StringDecodeOptions::default()).unwrap();

        assert_eq!(report.algorithm, None);
        assert!(report.strings.is_empty());
    }

    #[test]
    fn ignores_annotation_strings_in_llvm_metadata() {
        let module = parse_ll_module(
            r#"@.str = private constant [15 x i8] c"+vm_virtualize\00", section "llvm.metadata""#,
        )
        .unwrap();
        let report = recover_strings(&module, &StringDecodeOptions::default()).unwrap();

        assert!(report.strings.is_empty());
    }

    #[test]
    fn recovers_inlined_simd_key_from_source_named_operations() {
        let module = parse_ll_module(
            r#"
@.str = internal global [6 x i8] c"igohj\06", section ".str.test"
define i32 @main() {
entry:
  br label %simd_xor_cipher_123.exit
work:
  %xored_rest.i = xor i8 %cur.i, 1
  %xored_rest.i.1 = xor i8 %cur.i.1, 2
  %xored_rest.i.2 = xor i8 %cur.i.2, 3
  %xored_rest.i.3 = xor i8 %cur.i.3, 4
  %xored_rest.i.4 = xor i8 %cur.i.4, 5
  %xored_rest.i.5 = xor i8 %cur.i.5, 6
simd_xor_cipher_123.exit:
  ret i32 0
}
"#,
        )
        .unwrap();
        let report = recover_strings(&module, &StringDecodeOptions::default()).unwrap();

        assert_eq!(report.algorithm, Some(StringAlgorithm::SimdXor));
        assert_eq!(report.key_global, None);
        assert!(
            report
                .evidence
                .contains(&"inlined_key_immediates".to_owned())
        );
        assert_eq!(report.strings[0].text.as_deref(), Some("hello"));
    }

    #[test]
    fn rejects_incomplete_inlined_simd_key() {
        let module = parse_ll_module(
            r#"
@.str = internal global [4 x i8] c"igoh", section ".str.test"
define i32 @main() {
entry:
  %xored_rest.i = xor i8 %cur.i, 1
  %xored_rest.i.1 = xor i8 %cur.i.1, 2
  br label %simd_xor_cipher_123.exit
simd_xor_cipher_123.exit:
  ret i32 0
}
"#,
        )
        .unwrap();
        let error = recover_strings(&module, &StringDecodeOptions::default()).unwrap_err();

        assert!(error.to_string().contains("proves only 2 bytes"));
    }

    #[test]
    fn recovers_optimizer_folded_amice_stack_container() {
        let module = parse_ll_module(
            r#"
define i32 @main() {
entry:
  %string_container2 = alloca [7 x i8], align 1
  store i8 104, ptr %string_container2, align 1
  %dst_gep.i.1 = getelementptr inbounds nuw i8, ptr %string_container2, i64 1
  store i8 101, ptr %dst_gep.i.1, align 1
  %dst_gep.i.2 = getelementptr inbounds nuw i8, ptr %string_container2, i64 2
  store i8 108, ptr %dst_gep.i.2, align 1
  %dst_gep.i.3 = getelementptr inbounds nuw i8, ptr %string_container2, i64 3
  store i8 108, ptr %dst_gep.i.3, align 1
  %dst_gep.i.4 = getelementptr inbounds nuw i8, ptr %string_container2, i64 4
  store i8 111, ptr %dst_gep.i.4, align 1
  %dst_gep.i.5 = getelementptr inbounds nuw i8, ptr %string_container2, i64 5
  store i8 0, ptr %dst_gep.i.5, align 1
  ret i32 0
}
"#,
        )
        .unwrap();
        let report = recover_strings(&module, &StringDecodeOptions::default()).unwrap();

        assert_eq!(report.algorithm, Some(StringAlgorithm::Plain));
        assert_eq!(report.strings.len(), 1);
        assert_eq!(report.strings[0].text.as_deref(), Some("hello"));
        assert_eq!(
            report.strings[0].evidence,
            ["amice_stack_container".to_owned()]
        );
    }
}
