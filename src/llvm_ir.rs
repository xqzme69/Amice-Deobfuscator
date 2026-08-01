use crate::crypto::safe_symbol_suffix;
use anyhow::{Context, Result, bail};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteGlobal {
    pub name: String,
    pub len: usize,
    pub bytes: Vec<u8>,
    pub section: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteLiteralGlobal {
    pub name: String,
    pub literal_index: usize,
    pub len: usize,
    pub bytes: Vec<u8>,
    pub section: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I64Global {
    pub name: String,
    pub len: usize,
    pub words: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtrGlobal {
    pub name: String,
    pub len: usize,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlFunction {
    pub name: String,
    pub direct_callees: Vec<String>,
    pub global_refs: Vec<String>,
    pub vm_token_parts: Vec<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LlModule {
    pub source: String,
    pub byte_globals: Vec<ByteGlobal>,
    pub byte_literals: Vec<ByteLiteralGlobal>,
    pub i64_globals: Vec<I64Global>,
    pub ptr_globals: Vec<PtrGlobal>,
    pub functions: Vec<LlFunction>,
    pub wrapper_safe_names: Vec<String>,
}

impl LlModule {
    pub fn load(path: &Path) -> Result<Self> {
        let source =
            fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        parse_ll_module(&source)
    }
}

pub fn parse_ll_module(source: &str) -> Result<LlModule> {
    let mut module = LlModule {
        source: source.to_owned(),
        ..LlModule::default()
    };
    let mut current_function = None::<usize>;
    for line in source.lines() {
        let line = line.trim_start();
        if line.starts_with("define ")
            && let Some(name) = parse_function_name(line)
        {
            module.functions.push(LlFunction {
                name,
                direct_callees: Vec::new(),
                global_refs: Vec::new(),
                vm_token_parts: Vec::new(),
            });
            current_function = Some(module.functions.len() - 1);
        }
        if line.contains("amice.vm.fn.token.parts")
            && let Some(function_index) = current_function
        {
            let safe_name = safe_symbol_suffix(&module.functions[function_index].name);
            if !module.wrapper_safe_names.contains(&safe_name) {
                module.wrapper_safe_names.push(safe_name);
            }
        }
        if line.contains("amice.vm.fn.token.part.ptr")
            && let Some(function_index) = current_function
            && let Some(value) = parse_stored_i64(line)
            && !module.functions[function_index]
                .vm_token_parts
                .contains(&value)
        {
            module.functions[function_index].vm_token_parts.push(value);
        }
        if let Some(function_index) = current_function
            && let Some(callee) = parse_direct_callee(line)
            && !module.functions[function_index]
                .direct_callees
                .contains(&callee)
        {
            module.functions[function_index].direct_callees.push(callee);
        }
        if let Some(function_index) = current_function {
            for global_ref in parse_at_names(line) {
                if global_ref != module.functions[function_index].name
                    && !module.functions[function_index]
                        .global_refs
                        .contains(&global_ref)
                {
                    module.functions[function_index]
                        .global_refs
                        .push(global_ref);
                }
            }
        }
        if line.trim_end() == "}" {
            current_function = None;
        }
        if !line.starts_with('@') {
            continue;
        }
        module.byte_literals.extend(parse_byte_literals(line)?);
        if let Some(global) = parse_byte_global(line)? {
            module.byte_globals.push(global);
            continue;
        }
        if let Some(global) = parse_i64_global(line)? {
            module.i64_globals.push(global);
            continue;
        }
        if let Some(global) = parse_ptr_global(line)? {
            module.ptr_globals.push(global);
        }
    }
    Ok(module)
}

fn parse_stored_i64(line: &str) -> Option<u64> {
    let value = line.strip_prefix("store i64 ")?.split(',').next()?.trim();
    if value.starts_with('-') {
        value.parse::<i64>().ok().map(|value| value as u64)
    } else {
        value.parse().ok()
    }
}

fn parse_function_name(line: &str) -> Option<String> {
    parse_at_name(line)
}

fn parse_global_name(line: &str) -> Option<String> {
    let (name, _) = line.split_once(" = ")?;
    parse_at_name(name)
}

fn parse_direct_callee(line: &str) -> Option<String> {
    let call = if line.starts_with("call ") {
        0
    } else {
        line.find(" call ")? + 1
    };
    parse_at_name(&line[call + 5..])
}

fn parse_at_name(text: &str) -> Option<String> {
    parse_at_name_with_len(text).map(|(name, _)| name)
}

fn parse_at_name_with_len(text: &str) -> Option<(String, usize)> {
    let at = text.find('@')?;
    let after_at = &text[at + 1..];
    if after_at.starts_with('"') {
        let len = llvm_c_string_len(after_at).ok()?;
        return Some((parse_quoted_name(after_at)?, at + 1 + len));
    }
    let end = after_at
        .find(|ch: char| ch.is_ascii_whitespace() || matches!(ch, '(' | ')' | ',' | '='))
        .unwrap_or(after_at.len());
    (end > 0).then(|| (after_at[..end].to_owned(), at + 1 + end))
}

fn parse_at_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut cursor = 0;
    while cursor < text.len() {
        let Some((name, consumed)) = parse_at_name_with_len(&text[cursor..]) else {
            break;
        };
        if !names.contains(&name) {
            names.push(name);
        }
        cursor += consumed;
    }
    names
}

fn parse_quoted_name(text: &str) -> Option<String> {
    let mut escaped = false;
    for (offset, ch) in text.char_indices().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => {
                let bytes = parse_llvm_c_string(&text[..=offset]).ok()?;
                return Some(String::from_utf8_lossy(&bytes).into_owned());
            }
            _ => {}
        }
    }
    None
}

fn parse_array_len(line: &str, element: &str) -> Option<usize> {
    let marker = format!(" x {element}]");
    let end = line.find(&marker)?;
    let before = &line[..end];
    let start = before.rfind('[')?;
    before[start + 1..].trim().parse().ok()
}

fn parse_byte_global(line: &str) -> Result<Option<ByteGlobal>> {
    let Some(len) = parse_array_len(line, "i8") else {
        return Ok(None);
    };
    let Some(c_pos) = line.find(" c\"") else {
        return Ok(None);
    };
    let name = parse_global_name(line).context("byte global without name")?;
    let bytes = parse_llvm_c_string(&line[c_pos + 2..])?;
    if bytes.len() != len {
        bail!(
            "{} declares {} bytes but literal decoded to {}",
            name,
            len,
            bytes.len()
        );
    }
    Ok(Some(ByteGlobal {
        name,
        len,
        bytes,
        section: parse_section(line)?,
    }))
}

fn parse_byte_literals(line: &str) -> Result<Vec<ByteLiteralGlobal>> {
    let Some(name) = parse_global_name(line) else {
        return Ok(Vec::new());
    };
    let section = parse_section(line)?;
    let mut literals = Vec::new();
    let mut cursor = 0;

    while let Some(relative_c) = line[cursor..].find(" c\"") {
        let c_pos = cursor + relative_c;
        let before = &line[..c_pos];
        let Some(type_end) = before.rfind(']') else {
            cursor = c_pos + 2;
            continue;
        };
        let Some(type_start) = before[..type_end].rfind('[') else {
            cursor = c_pos + 2;
            continue;
        };
        let array_type = before[type_start + 1..type_end].trim();
        let Some(len_text) = array_type.strip_suffix(" x i8") else {
            cursor = c_pos + 2;
            continue;
        };
        let len = len_text
            .trim()
            .parse::<usize>()
            .with_context(|| format!("invalid byte array length in {name}"))?;
        let literal_start = c_pos + 2;
        let bytes = parse_llvm_c_string(&line[literal_start..])?;
        if bytes.len() != len {
            bail!(
                "{} byte literal {} declares {} bytes but decoded to {}",
                name,
                literals.len(),
                len,
                bytes.len()
            );
        }
        literals.push(ByteLiteralGlobal {
            name: name.clone(),
            literal_index: literals.len(),
            len,
            bytes,
            section: section.clone(),
        });
        cursor = literal_start + llvm_c_string_len(&line[literal_start..])?;
    }

    Ok(literals)
}

fn parse_section(line: &str) -> Result<Option<String>> {
    let Some(section_pos) = line.find("section ") else {
        return Ok(None);
    };
    let after = &line[section_pos + "section ".len()..];
    let quote = after
        .find('"')
        .context("LLVM section without quoted name")?;
    let bytes = parse_llvm_c_string(&after[quote..])?;
    Ok(Some(
        String::from_utf8(bytes).context("LLVM section name is not UTF-8")?,
    ))
}

fn llvm_c_string_len(literal: &str) -> Result<usize> {
    if !literal.starts_with('"') {
        bail!("LLVM c-string must start with quote");
    }
    let mut escaped = false;
    for (offset, ch) in literal.char_indices().skip(1) {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return Ok(offset + 1),
            _ => {}
        }
    }
    bail!("unterminated LLVM c-string")
}

fn parse_i64_global(line: &str) -> Result<Option<I64Global>> {
    let Some(len) = parse_array_len(line, "i64") else {
        return Ok(None);
    };
    let Some(array_start) = line.find("] [") else {
        return Ok(None);
    };
    let name = parse_global_name(line).context("i64 global without name")?;
    let array_text = line[array_start + 3..]
        .strip_suffix(']')
        .unwrap_or(&line[array_start + 3..]);
    let mut words = Vec::new();
    for part in array_text.split(',') {
        let part = part.trim();
        let Some(value) = part.strip_prefix("i64 ") else {
            return Ok(None);
        };
        let Ok(word) = parse_i64_word(value.trim()) else {
            return Ok(None);
        };
        words.push(word);
    }
    if words.len() != len {
        bail!(
            "{} declares {} i64 words but parser found {}",
            name,
            len,
            words.len()
        );
    }
    Ok(Some(I64Global { name, len, words }))
}

fn parse_ptr_global(line: &str) -> Result<Option<PtrGlobal>> {
    let Some(len) = parse_array_len(line, "ptr") else {
        return Ok(None);
    };
    let Some(array_start) = line.find("] [") else {
        return Ok(None);
    };
    let name = parse_global_name(line).context("ptr global without name")?;
    let array_text = line[array_start + 3..]
        .strip_suffix(']')
        .unwrap_or(&line[array_start + 3..]);
    let mut targets = Vec::new();
    for part in array_text.split(',') {
        let part = part.trim();
        let Some(target) = part.strip_prefix("ptr ") else {
            return Ok(None);
        };
        targets.push(parse_at_name(target).unwrap_or_else(|| target.to_owned()));
    }
    if targets.len() != len {
        bail!(
            "{} declares {} ptrs but parser found {}",
            name,
            len,
            targets.len()
        );
    }
    Ok(Some(PtrGlobal { name, len, targets }))
}

fn parse_i64_word(value: &str) -> Result<u64> {
    if let Some(hex) = value.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).with_context(|| format!("invalid i64 hex {value}"));
    }
    let signed = value
        .parse::<i128>()
        .with_context(|| format!("invalid i64 constant {value}"))?;
    Ok(signed as i64 as u64)
}

pub fn parse_llvm_c_string(literal: &str) -> Result<Vec<u8>> {
    let mut chars = literal.chars().peekable();
    if chars.next() != Some('"') {
        bail!("LLVM c-string must start with quote");
    }

    let mut bytes = Vec::new();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => return Ok(bytes),
            '\\' => {
                let first = chars.next().context("dangling escape in LLVM c-string")?;
                if first.is_ascii_hexdigit()
                    && chars
                        .peek()
                        .copied()
                        .is_some_and(|second| second.is_ascii_hexdigit())
                {
                    let second = chars.next().expect("peek checked second hex digit");
                    let hex = format!("{first}{second}");
                    bytes.push(u8::from_str_radix(&hex, 16)?);
                    continue;
                }
                bytes.push(escaped_byte(first));
            }
            other => bytes.push(other as u8),
        }
    }
    bail!("unterminated LLVM c-string")
}

fn escaped_byte(ch: char) -> u8 {
    match ch {
        'n' => b'\n',
        'r' => b'\r',
        't' => b'\t',
        '\\' => b'\\',
        '"' => b'"',
        '0' => 0,
        other => other as u8,
    }
}

pub fn marker_seed_from_name(name: &str) -> Option<u64> {
    let (_, hex) = name.rsplit_once(".h")?;
    if hex.len() != 16 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_llvm_c_string_hex_and_text() {
        assert_eq!(parse_llvm_c_string("\"AMICE\\00x\"").unwrap(), b"AMICE\0x");
        assert_eq!(parse_llvm_c_string("\"a\\\\b\\22\"").unwrap(), b"a\\b\"");
    }

    #[test]
    fn parses_needed_globals() {
        let source = r#"
@blob = private constant [4 x i8] c"A\00B\FF"
@desc = private constant [8 x i64] [i64 -1, i64 2, i64 3, i64 4, i64 5, i64 6, i64 7, i64 8]
@native = private constant [2 x ptr] [ptr @a, ptr @b]
define void @foo-bar() {
  %amice.vm.fn.token.parts = alloca [2 x i64], align 8
  ret void
}
"#;
        let module = parse_ll_module(source).unwrap();
        assert_eq!(module.byte_globals[0].bytes, vec![b'A', 0, b'B', 255]);
        assert_eq!(module.i64_globals[0].words[0], u64::MAX);
        assert_eq!(module.ptr_globals[0].targets, ["a", "b"]);
        assert_eq!(module.wrapper_safe_names, ["foo_bar"]);
    }

    #[test]
    fn parses_quoted_function_names_and_direct_callees() {
        let source = r#"
define void @"foo\20bar"() {
  %amice.vm.fn.token.parts = alloca [2 x i64], align 8
  call void @"callee\2Dname"()
  ret void
}
"#;
        let module = parse_ll_module(source).unwrap();
        assert_eq!(module.functions[0].name, "foo bar");
        assert_eq!(module.functions[0].direct_callees, ["callee-name"]);
        assert_eq!(module.wrapper_safe_names, ["foo_bar"]);
    }

    #[test]
    fn parses_amice_wrapper_token_parts() {
        let source = r#"
define i32 @simple_vm(i32 %value) {
  %amice.vm.fn.token.parts = alloca [2 x i64], align 8
  %amice.vm.fn.token.part.ptr = getelementptr [2 x i64], ptr %amice.vm.fn.token.parts, i64 0, i64 0
  store i64 -8537392746400371464, ptr %amice.vm.fn.token.part.ptr, align 8
  %amice.vm.fn.token.part.ptr1 = getelementptr [2 x i64], ptr %amice.vm.fn.token.parts, i64 0, i64 1
  store i64 1887828393854850671, ptr %amice.vm.fn.token.part.ptr1, align 8
  ret i32 %value
}
"#;
        let module = parse_ll_module(source).unwrap();

        assert_eq!(
            module.functions[0].vm_token_parts,
            [0x8985_1687_bacf_2cf8, 0x1a32_e9ec_0c9d_566f]
        );
    }

    #[test]
    fn does_not_split_at_signs_inside_quoted_cpp_names() {
        let source = r#"
@"?global@@3HA" = internal global [2 x i8] c"x\00"
define void @"?caller@@YAXXZ"() {
  %value = load i8, ptr @"?global@@3HA"
  call void @"?callee@@YAXXZ"()
  ret void
}
"#;
        let module = parse_ll_module(source).unwrap();

        assert_eq!(module.functions[0].name, "?caller@@YAXXZ");
        assert_eq!(module.functions[0].direct_callees, ["?callee@@YAXXZ"]);
        assert_eq!(
            module.functions[0].global_refs,
            ["?global@@3HA", "?callee@@YAXXZ"]
        );
    }

    #[test]
    fn ignores_unrelated_complex_array_initializers() {
        let source = r#"
@words = private constant [1 x i64] [i64 ptrtoint (ptr @target to i64)]
@pointers = private constant [1 x ptr] [ptr getelementptr (i8, ptr @target, i64 1)]
"#;
        let module = parse_ll_module(source).unwrap();
        assert!(module.i64_globals.is_empty());
        assert!(module.ptr_globals.is_empty());
    }

    #[test]
    fn marker_seed_reads_group_suffix() {
        let name = ".amice.vm.descriptor_table.main.n3.h356b517d6b1ddb25";
        assert_eq!(marker_seed_from_name(name), Some(0x356b_517d_6b1d_db25));
        assert_eq!(marker_seed_from_name(&format!("{name}.extra")), None);
    }
}
