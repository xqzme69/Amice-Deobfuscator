use crate::bytecode::{VmOperand, VmRecord};
use crate::decode::{DecodeReport, DecodedDescriptor};
use crate::package::PackageReport;
use amice_vm::isa::{HandlerSemantic, OperandKind, SuperOp};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LiftCoverage {
    pub meaningful_records: usize,
    pub lifted_records: usize,
    pub unknown_records: usize,
    pub percent: f64,
    pub unknown_mnemonics: Vec<String>,
}

pub fn lift_coverage(records: &[VmRecord]) -> LiftCoverage {
    let meaningful = records
        .iter()
        .filter(|record| record.semantic != HandlerSemantic::Nop)
        .collect::<Vec<_>>();
    let unknown = meaningful
        .iter()
        .filter(|record| lift_record(record).starts_with("vm_unknown"))
        .collect::<Vec<_>>();
    let meaningful_records = meaningful.len();
    let unknown_records = unknown.len();
    let lifted_records = meaningful_records - unknown_records;
    let percent = if meaningful_records == 0 {
        100.0
    } else {
        lifted_records as f64 * 100.0 / meaningful_records as f64
    };
    LiftCoverage {
        meaningful_records,
        lifted_records,
        unknown_records,
        percent,
        unknown_mnemonics: unknown
            .into_iter()
            .map(|record| record.mnemonic.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    }
}

pub fn write_report(report: &DecodeReport, out_dir: &Path) -> Result<()> {
    fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    write_descriptors(&report.descriptors, &out_dir.join("descriptors.json"))?;
    write_vm_jsonl(&report.records, &out_dir.join("vm.jsonl"))?;
    write_vm_text(report, &out_dir.join("vm.txt"))?;
    write_lift(report, &out_dir.join("lift.ll.txt"))?;
    write_lift_coverage(&report.records, &out_dir.join("lift-coverage.json"))?;
    Ok(())
}

pub fn write_package_report(report: &PackageReport, out_dir: &Path) -> Result<()> {
    fs::create_dir_all(out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    let packages_json = serde_json::to_string_pretty(&report.packages)?;
    fs::write(out_dir.join("packages.json"), packages_json)
        .with_context(|| format!("write {}", out_dir.join("packages.json").display()))?;
    write_vm_jsonl(&report.records, &out_dir.join("vm.jsonl"))?;
    write_package_text(report, &out_dir.join("vm.txt"))?;
    write_package_lift(report, &out_dir.join("lift.ll.txt"))?;
    write_lift_coverage(&report.records, &out_dir.join("lift-coverage.json"))?;
    Ok(())
}

fn write_descriptors(descriptors: &[DecodedDescriptor], path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(descriptors)?;
    fs::write(path, json).with_context(|| format!("write {}", path.display()))
}

fn write_vm_jsonl(records: &[VmRecord], path: &Path) -> Result<()> {
    let mut file = File::create(path).with_context(|| format!("write {}", path.display()))?;
    for record in records {
        writeln!(file, "{}", serde_json::to_string(record)?)?;
    }
    Ok(())
}

fn write_lift_coverage(records: &[VmRecord], path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(&lift_coverage(records))?;
    fs::write(path, json).with_context(|| format!("write {}", path.display()))
}

fn write_vm_text(report: &DecodeReport, path: &Path) -> Result<()> {
    let mut file = File::create(path).with_context(|| format!("write {}", path.display()))?;
    writeln!(file, "bytecode_global = {}", report.bytecode_global)?;
    writeln!(file, "descriptor_global = {}", report.descriptor_global)?;
    if let Some(native_global) = &report.native_global {
        writeln!(file, "native_global = {native_global}")?;
    }
    writeln!(file, "descriptor_seed = 0x{:016x}", report.descriptor_seed)?;
    for descriptor in &report.descriptors {
        let function_name = descriptor
            .function_name
            .as_deref()
            .map(|name| format!(" {name}"))
            .unwrap_or_default();
        writeln!(
            file,
            "\nfn {}{} code=[{}..{}) key={}",
            descriptor.fn_index,
            function_name,
            descriptor.code_offset,
            descriptor.code_offset + descriptor.code_len,
            descriptor.bytecode_key
        )?;
        if !descriptor.const_pool.is_empty() {
            let constants = descriptor
                .const_pool
                .iter()
                .map(|constant| format!("[{}]={}", constant.index, constant.value))
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(file, "  const_pool: {constants}")?;
        }
        for target in &descriptor.native_targets {
            let name = target
                .callee
                .as_deref()
                .or(target.thunk.as_deref())
                .unwrap_or("unresolved");
            writeln!(
                file,
                "  native[{}] table[{}] = {}",
                target.local_index, target.table_index, name
            )?;
        }
        for record in report
            .records
            .iter()
            .filter(|record| record.fn_index == descriptor.fn_index)
        {
            write_record_line(&mut file, record)?;
        }
    }
    Ok(())
}

fn write_lift(report: &DecodeReport, path: &Path) -> Result<()> {
    let mut file = File::create(path).with_context(|| format!("write {}", path.display()))?;
    writeln!(file, "; amice-devirt pseudo lift")?;
    writeln!(file, "; source bytecode global: {}", report.bytecode_global)?;
    for descriptor in &report.descriptors {
        let function_name = descriptor
            .function_name
            .as_deref()
            .map(sanitize_pseudo_name)
            .unwrap_or_else(|| format!("fn_{}", descriptor.fn_index));
        write_lift_function(
            &mut file,
            descriptor.fn_index,
            &function_name,
            &report.records,
        )?;
    }
    Ok(())
}

fn write_package_text(report: &PackageReport, path: &Path) -> Result<()> {
    let mut file = File::create(path).with_context(|| format!("write {}", path.display()))?;
    for package in &report.packages {
        writeln!(
            file,
            "fn {} {} global={} code=[{}..{}) key={} instructions={}",
            package.fn_index,
            package.function_name,
            package.global_name,
            package.code_offset,
            package.code_offset + package.code_len,
            package.bytecode_key,
            package.instruction_count
        )?;
        if !package.const_pool.is_empty() {
            let constants = package
                .const_pool
                .iter()
                .map(|constant| format!("[{}]={}", constant.index, constant.value))
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(file, "  const_pool: {constants}")?;
        }
        if !package.relocations.is_empty() {
            let relocations = package
                .relocations
                .iter()
                .map(|relocation| format!("label{}=pc_{:04x}", relocation.label, relocation.pc))
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(file, "  relocations: {relocations}")?;
        }
        for record in report
            .records
            .iter()
            .filter(|record| record.fn_index == package.fn_index)
        {
            write_record_line(&mut file, record)?;
        }
        writeln!(file)?;
    }
    Ok(())
}

fn write_package_lift(report: &PackageReport, path: &Path) -> Result<()> {
    let mut file = File::create(path).with_context(|| format!("write {}", path.display()))?;
    writeln!(file, "; amice-devirt pseudo lift from bytecode packages")?;
    for package in &report.packages {
        write_lift_function(
            &mut file,
            package.fn_index,
            &sanitize_pseudo_name(&package.function_name),
            &report.records,
        )?;
    }
    Ok(())
}

fn write_record_line(file: &mut File, record: &VmRecord) -> Result<()> {
    writeln!(
        file,
        "  {:#06x}: op={:#06x} {:<24} {}",
        record.pc,
        record.opcode,
        record.mnemonic,
        record
            .operands
            .iter()
            .map(format_operand)
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    Ok(())
}

fn write_lift_function(
    file: &mut File,
    fn_index: usize,
    function_name: &str,
    records: &[VmRecord],
) -> Result<()> {
    writeln!(file, "\ndefine vm @{function_name}() {{")?;
    let branch_targets = records
        .iter()
        .filter(|record| record.fn_index == fn_index)
        .flat_map(|record| &record.operands)
        .filter(|operand| operand.kind == OperandKind::Label)
        .filter_map(|operand| usize::try_from(operand.value).ok())
        .collect::<HashSet<_>>();
    for record in records.iter().filter(|record| record.fn_index == fn_index) {
        if record.semantic == HandlerSemantic::Nop && !branch_targets.contains(&record.pc) {
            continue;
        }
        writeln!(file, "pc_{:04x}:", record.pc)?;
        writeln!(file, "  {}", lift_record(record))?;
    }
    writeln!(file, "}}")?;
    Ok(())
}

fn format_operand(operand: &VmOperand) -> String {
    match (&operand.kind, &operand.resolved) {
        (OperandKind::VReg | OperandKind::Label, Some(resolved)) => {
            format!("{}={resolved}", operand.name)
        }
        (_, Some(resolved)) => format!("{}={} ({resolved})", operand.name, operand.value),
        _ => format!("{}={}", operand.name, operand.value),
    }
}

fn lift_record(record: &VmRecord) -> String {
    let unknown = || {
        format!(
            "vm_unknown \"{}\" opcode {:#x} {}",
            record.mnemonic,
            record.opcode,
            record
                .operands
                .iter()
                .map(format_operand)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    match &record.semantic {
        HandlerSemantic::MovImm => lift_assign(record, "dst", |record| {
            Some(format!(
                "imm {}, width {}",
                hex_operand(record, "imm")?,
                value(record, "width")?
            ))
        })
        .unwrap_or_else(unknown),
        HandlerSemantic::ConstLoad => lift_assign(record, "dst", |record| {
            let index = operand(record, "index")?;
            let resolved = index.resolved.as_deref().unwrap_or("unresolved");
            Some(format!("const_pool[{}] ; {resolved}", index.value))
        })
        .unwrap_or_else(unknown),
        HandlerSemantic::Super(op) => lift_super(record, op).unwrap_or_else(unknown),
        HandlerSemantic::Mov => lift_assign(record, "dst", |record| {
            Some(format!(
                "mov {}, width {}",
                register(record, "src")?,
                value(record, "width")?
            ))
        })
        .unwrap_or_else(unknown),
        HandlerSemantic::Bin(op) => lift_assign(record, "dst", |record| {
            Some(format!(
                "{} {}, {}, width {}",
                debug_name(op),
                register(record, "lhs")?,
                register(record, "rhs")?,
                value(record, "width")?
            ))
        })
        .unwrap_or_else(unknown),
        HandlerSemantic::IntUnary(op) => lift_assign(record, "dst", |record| {
            Some(format!(
                "{} {}, width {}",
                debug_name(op),
                register(record, "src")?,
                value(record, "width")?
            ))
        })
        .unwrap_or_else(unknown),
        HandlerSemantic::IntTernary(op) => lift_assign(record, "dst", |record| {
            Some(format!(
                "{} {}, {}, {}, width {}",
                debug_name(op),
                register(record, "lhs")?,
                register(record, "rhs")?,
                register(record, "third")?,
                value(record, "width")?
            ))
        })
        .unwrap_or_else(unknown),
        HandlerSemantic::Icmp => lift_assign(record, "dst", |record| {
            Some(format!(
                "icmp pred={}, {}, {}, width {}",
                value(record, "pred")?,
                register(record, "lhs")?,
                register(record, "rhs")?,
                value(record, "width")?
            ))
        })
        .unwrap_or_else(unknown),
        HandlerSemantic::Cast(op) => lift_assign(record, "dst", |record| {
            Some(format!(
                "{} {}, from_width {}, to_width {}",
                debug_name(op),
                register(record, "src")?,
                value(record, "from_width")?,
                value(record, "to_width")?
            ))
        })
        .unwrap_or_else(unknown),
        HandlerSemantic::Gep => lift_assign(record, "dst", |record| {
            Some(format!(
                "gep {}, offset {}",
                register(record, "base")?,
                hex_operand(record, "offset")?
            ))
        })
        .unwrap_or_else(unknown),
        HandlerSemantic::Alloca => lift_assign(record, "dst", |record| {
            Some(format!(
                "alloca bytes {}, align {}",
                value(record, "bytes")?,
                value(record, "align")?
            ))
        })
        .unwrap_or_else(unknown),
        HandlerSemantic::DynamicAlloca => lift_assign(record, "dst", |record| {
            Some(format!(
                "alloca_dyn count {}, elem_size {}, align {}",
                register(record, "count")?,
                value(record, "elem_size")?,
                value(record, "align")?
            ))
        })
        .unwrap_or_else(unknown),
        HandlerSemantic::Load | HandlerSemantic::VolatileLoad => {
            lift_load(record).unwrap_or_else(unknown)
        }
        HandlerSemantic::Store | HandlerSemantic::VolatileStore => {
            lift_store(record).unwrap_or_else(unknown)
        }
        HandlerSemantic::Br => operand(record, "target")
            .and_then(|target| target.resolved.clone())
            .map(|target| format!("br {target}"))
            .unwrap_or_else(unknown),
        HandlerSemantic::BrCond => match (
            register(record, "cond"),
            resolved(record, "then_pc"),
            resolved(record, "else_pc"),
        ) {
            (Some(cond), Some(then_pc), Some(else_pc)) => {
                format!("brcond {cond}, {then_pc}, {else_pc}")
            }
            _ => unknown(),
        },
        HandlerSemantic::VmCall => resolved(record, "target")
            .map(|target| format!("vm_call {target}"))
            .unwrap_or_else(unknown),
        HandlerSemantic::VmRet => "vm_ret".to_owned(),
        HandlerSemantic::CallNative => lift_native_call(record).unwrap_or_else(unknown),
        HandlerSemantic::Ret if record.mnemonic.contains("ret_void") => "ret void".to_owned(),
        HandlerSemantic::Ret => register(record, "src")
            .map(|src| format!("ret {src}"))
            .unwrap_or_else(unknown),
        HandlerSemantic::Nop => "; nop branch target".to_owned(),
        HandlerSemantic::Unreachable => "unreachable".to_owned(),
        HandlerSemantic::Trap => "trap".to_owned(),
        _ => unknown(),
    }
}

fn lift_super(record: &VmRecord, op: &SuperOp) -> Option<String> {
    match op {
        SuperOp::AddXor => lift_assign(record, "dst", |record| {
            Some(format!(
                "iadd_xor {}, {}, {}, width {}",
                register(record, "lhs")?,
                register(record, "rhs")?,
                register(record, "xor_rhs")?,
                value(record, "width")?
            ))
        }),
        SuperOp::IcmpBrIf => Some(format!(
            "icmp_br pred={}, {}, {}, width {}, {}, {}",
            value(record, "pred")?,
            register(record, "lhs")?,
            register(record, "rhs")?,
            value(record, "width")?,
            resolved(record, "then_pc")?,
            resolved(record, "else_pc")?
        )),
        SuperOp::GepLoad => lift_assign(record, "dst", |record| {
            Some(format!(
                "load gep {}, offset {}, width {}",
                register(record, "base")?,
                hex_operand(record, "offset")?,
                value(record, "width")?
            ))
        }),
        _ => {
            let rhs = record
                .operands
                .iter()
                .find(|operand| {
                    operand.kind == OperandKind::VReg
                        && !matches!(operand.name.as_str(), "dst" | "ptr")
                })
                .map(|operand| format!("x{}", operand.value))?;
            lift_assign(record, "dst", |record| {
                Some(format!(
                    "{:?} load {}, {}, width {}",
                    op,
                    register(record, "ptr")?,
                    rhs,
                    value(record, "width")?
                ))
            })
        }
    }
}

fn lift_assign(
    record: &VmRecord,
    dst_name: &str,
    expression: impl FnOnce(&VmRecord) -> Option<String>,
) -> Option<String> {
    Some(format!(
        "{} = {}",
        register(record, dst_name)?,
        expression(record)?
    ))
}

fn lift_load(record: &VmRecord) -> Option<String> {
    let align = value(record, "align")
        .map(|align| format!(", align {align}"))
        .unwrap_or_default();
    Some(format!(
        "{} = {}load {}, width {}{}",
        register(record, "dst")?,
        if record.semantic == HandlerSemantic::VolatileLoad {
            "volatile "
        } else {
            ""
        },
        register(record, "ptr")?,
        value(record, "width")?,
        align
    ))
}

fn lift_store(record: &VmRecord) -> Option<String> {
    let align = value(record, "align")
        .map(|align| format!(", align {align}"))
        .unwrap_or_default();
    Some(format!(
        "{}store {} -> {}, width {}{}",
        if record.semantic == HandlerSemantic::VolatileStore {
            "volatile "
        } else {
            ""
        },
        register(record, "src")?,
        register(record, "ptr")?,
        value(record, "width")?,
        align
    ))
}

fn lift_native_call(record: &VmRecord) -> Option<String> {
    let callee = operand(record, "callee")?;
    let target = callee
        .resolved
        .clone()
        .unwrap_or_else(|| format!("native[{}]", callee.value));
    let argc = usize::try_from(value(record, "argc")?).ok()?;
    let args = (0..argc)
        .map(|index| register(record, &format!("arg{index}")))
        .collect::<Option<Vec<_>>>()?
        .join(", ");
    let ret_count = usize::try_from(value(record, "ret_count")?).ok()?;
    let returns = (0..ret_count)
        .map(|index| register(record, &format!("ret{index}")))
        .collect::<Option<Vec<_>>>()?
        .join(", ");
    if returns.is_empty() {
        Some(format!("call {target}({args})"))
    } else {
        Some(format!("[{returns}] = call {target}({args})"))
    }
}

fn operand<'a>(record: &'a VmRecord, name: &str) -> Option<&'a VmOperand> {
    record.operands.iter().find(|operand| operand.name == name)
}

fn value(record: &VmRecord, name: &str) -> Option<u64> {
    operand(record, name).map(|operand| operand.value)
}

fn register(record: &VmRecord, name: &str) -> Option<String> {
    value(record, name).map(|value| format!("x{value}"))
}

fn resolved(record: &VmRecord, name: &str) -> Option<String> {
    operand(record, name)?.resolved.clone()
}

fn hex_operand(record: &VmRecord, name: &str) -> Option<String> {
    value(record, name).map(|value| format!("0x{value:x}"))
}

fn debug_name(value: &impl std::fmt::Debug) -> String {
    format!("{value:?}").to_ascii_lowercase()
}

fn sanitize_pseudo_name(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}
