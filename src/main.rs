use amice_devirt::bytecode::VmRecord;
use amice_devirt::decode::{
    DecodeInput, DecodeReport, decode_module, likely_bytecode_blobs, marker_seeds, seed_from_args,
    seed_from_wrappers,
};
use amice_devirt::llvm_ir::{LlModule, marker_seed_from_name};
use amice_devirt::package::{PackageReport, decode_packages};
use amice_devirt::pe::{
    PeDecodeReport, PeLocation, PeProfile, decode_pe64_path_with_profiles,
    recover_pe64_strings_path, write_pe_layout,
};
use amice_devirt::render::{lift_coverage, write_package_report, write_report};
use amice_devirt::strings::{
    StringAlgorithm, StringDecodeOptions, StringReport, recover_strings, write_string_report,
};
use amice_vm::ProfilePackage;
use amice_vm::verify::verify_profile;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};
use std::env;
use std::fs;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::time::Instant;

const BANNER: &str = r#"    _    __  __ ___ ____ _____       ____  _______     _____ ____ _____
   / \  |  \/  |_ _/ ___| ____|     |  _ \| ____\ \   / /_ _|  _ \_   _|
  / _ \ | |\/| || | |   |  _|      | | | |  _|  \ \ / / | || |_) || |
 / ___ \| |  | || | |___| |___     | |_| | |___  \ V /  | ||  _ < | |
/_/   \_\_|  |_|___\____|_____|    |____/|_____|  \_/  |___|_| \_\|_|"#;
const RULE: &str = "========================================================================================================";

fn main() {
    print_banner();
    let dropped = env::args()
        .nth(1)
        .is_some_and(|arg| Path::new(&arg).is_file());
    let failed = match run() {
        Ok(()) => false,
        Err(err) => {
            eprintln!("[-] {err:#}");
            true
        }
    };
    if dropped && io::stdin().is_terminal() && env::var_os("AMICE_DEVIRT_NO_PAUSE").is_none() {
        println!("\n[*] Press Enter to close...");
        let _ = io::stdin().read_line(&mut String::new());
    }
    if failed {
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let Some(command) = args.first().map(String::as_str) else {
        print_usage();
        return Ok(());
    };
    let dropped_path = PathBuf::from(command);
    if dropped_path.is_file() {
        if args.len() != 1 {
            bail!("drag-and-drop mode accepts one executable path");
        }
        return auto_decode_pe(&dropped_path);
    }
    if args[1..]
        .iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help"))
    {
        print_usage();
        return Ok(());
    }

    match command {
        "discover" => discover(&args[1..]),
        "decode" => decode(&args[1..]),
        "decode-pe" => decode_pe(&args[1..]),
        "strings-pe" => decode_pe_strings(&args[1..]),
        "package" => decode_package_globals(&args[1..]),
        "strings" => decode_string_globals(&args[1..]),
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(())
        }
        other => bail!("unknown command {other}"),
    }
}

fn decode_pe_strings(args: &[String]) -> Result<()> {
    let started = Instant::now();
    validate_value_options(args, &["--pe", "--out"])?;
    let pe_path = take_path_arg(args, "--pe")?;
    let out_dir = take_path_arg(args, "--out")?;

    println!("[*] Loaded: {}", pe_path.display());
    let report = recover_pe64_strings_path(&pe_path)?;
    write_string_report(&report, &out_dir)?;
    print_string_summary(&report);
    print_recovered_strings(&report);
    println!("[+] Output: {}", out_dir.display());
    println!("[+] Runtime: {:.2}s", started.elapsed().as_secs_f64());
    Ok(())
}

fn decode_pe(args: &[String]) -> Result<()> {
    let started = Instant::now();
    validate_value_options_with_repeats(
        args,
        &["--pe", "--profile", "--out", "--descriptor-seed", "--pdb"],
        &["--profile", "--descriptor-seed"],
    )?;
    let pe_path = take_path_arg(args, "--pe")?;
    let out_dir = take_path_arg(args, "--out")?;
    let descriptor_seeds = option_values(args, "--descriptor-seed")
        .into_iter()
        .map(parse_u64_arg)
        .collect::<Result<Vec<_>>>()?;
    if descriptor_seeds.iter().collect::<HashSet<_>>().len() != descriptor_seeds.len() {
        bail!("duplicate --descriptor-seed value");
    }

    println!("[*] Loaded: {}", pe_path.display());
    let profiles = load_pe_profiles(option_values(args, "--profile"))?;
    for profile in &profiles {
        println!("[*] Profile: {}", profile.name);
    }
    let pdb_path = optional_arg(args, "--pdb").map(PathBuf::from);
    let report = decode_pe64_path_with_profiles(
        &pe_path,
        &profiles,
        &descriptor_seeds,
        pdb_path.as_deref(),
    )?;
    write_pe_report(&report, &out_dir)?;
    print_pe_report(&report);
    println!("[+] Output: {}", out_dir.display());
    println!("[+] Runtime: {:.2}s", started.elapsed().as_secs_f64());
    Ok(())
}

fn write_pe_report(report: &PeDecodeReport, out_dir: &Path) -> Result<()> {
    write_pe_layout(&report.layout, out_dir)?;
    write_string_report(&report.strings, out_dir)?;
    for group in &report.groups {
        let group_out = if report.groups.len() == 1 {
            out_dir.to_path_buf()
        } else {
            out_dir.join(format!("group-{:03}", group.layout.group_index))
        };
        write_report(&group.decode, &group_out)?;
    }
    Ok(())
}

fn print_pe_report(report: &PeDecodeReport) {
    println!("[+] VMP groups: {}", report.groups.len());
    println!(
        "[+] Descriptors: {}",
        report
            .groups
            .iter()
            .map(|group| group.decode.descriptors.len())
            .sum::<usize>()
    );
    println!(
        "[+] VM records: {}",
        report
            .groups
            .iter()
            .map(|group| group.decode.records.len())
            .sum::<usize>()
    );
    print_string_summary(&report.strings);
    if let Some(symbol_file) = &report.layout.symbol_file {
        println!("[+] Symbols: {symbol_file}");
    }
    for group in &report.groups {
        print_section(&format!("VMP GROUP {:03}", group.layout.group_index));
        println!("  profile={}", group.layout.profile);
        println!(
            "  descriptor_seed={} ({})",
            group.layout.seed.seed, group.layout.seed.source
        );
        if let Some(instruction_va) = &group.layout.seed.instruction_va {
            println!("  seed_instruction={instruction_va}");
        }
        println!("  bytecode={}", format_pe_location(&group.layout.bytecode));
        println!(
            "  descriptors={}",
            format_pe_location(&group.layout.descriptors)
        );
        if let Some(native_table) = &group.layout.native_table {
            println!("  native_table={}", format_pe_location(native_table));
        }
        print_lift_summary(&group.decode.records);
        print_decoded_functions(&group.decode);
        print_native_calls(&group.decode);
    }
    print_recovered_strings(&report.strings);
}

#[derive(Serialize)]
struct AutoSummary {
    input: String,
    output: String,
    profiles: Vec<String>,
    vmp_decoded: bool,
    vmp_groups: usize,
    descriptors: usize,
    vm_records: usize,
    recovered_strings: usize,
    string_evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vmp_error: Option<String>,
}

fn auto_decode_pe(pe_path: &Path) -> Result<()> {
    let started = Instant::now();
    let stem = pe_path
        .file_stem()
        .context("dropped file has no file name")?
        .to_string_lossy();
    let out_dir = pe_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{stem}.amice-devirt"));
    let profiles = load_auto_profiles(pe_path)?;

    println!("[*] Auto mode: maximum static pass");
    println!("[*] Loaded: {}", pe_path.display());
    for profile in &profiles {
        println!("[*] Profile: {}", profile.name);
    }

    let strings = recover_pe64_strings_path(pe_path)?;
    write_string_report(&strings, &out_dir)?;
    let mut summary = AutoSummary {
        input: pe_path.display().to_string(),
        output: out_dir.display().to_string(),
        profiles: profiles
            .iter()
            .map(|profile| profile.name.clone())
            .collect(),
        vmp_decoded: false,
        vmp_groups: 0,
        descriptors: 0,
        vm_records: 0,
        recovered_strings: strings.strings.len(),
        string_evidence: strings.evidence.clone(),
        vmp_error: None,
    };

    match decode_pe64_path_with_profiles(pe_path, &profiles, &[], None) {
        Ok(report) => {
            write_pe_report(&report, &out_dir)?;
            print_pe_report(&report);
            summary.vmp_decoded = true;
            summary.vmp_groups = report.groups.len();
            summary.descriptors = report
                .groups
                .iter()
                .map(|group| group.decode.descriptors.len())
                .sum();
            summary.vm_records = report
                .groups
                .iter()
                .map(|group| group.decode.records.len())
                .sum();
            summary.recovered_strings = report.strings.strings.len();
            summary.string_evidence = report.strings.evidence.clone();
        }
        Err(err) => {
            let message = format!("{err:#}");
            println!("[!] VMP was not decoded: {message}");
            print_string_summary(&strings);
            print_recovered_strings(&strings);
            summary.vmp_error = Some(message);
        }
    }

    fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;
    let summary_path = out_dir.join("auto-summary.json");
    fs::write(&summary_path, serde_json::to_string_pretty(&summary)?)
        .with_context(|| format!("write {}", summary_path.display()))?;
    println!("[+] Output: {}", out_dir.display());
    println!("[+] Runtime: {:.2}s", started.elapsed().as_secs_f64());
    Ok(())
}

fn load_auto_profiles(pe_path: &Path) -> Result<Vec<PeProfile>> {
    let mut profiles = load_pe_profiles(Vec::new())?;
    for path in auto_profile_paths(pe_path) {
        match read_verified_profile(&path) {
            Ok((_, true)) => continue, // already covered by the built-in simple decoder
            Ok((package, false)) => {
                if profiles.iter().all(|profile| profile.package != package) {
                    profiles.push(PeProfile {
                        name: path.display().to_string(),
                        package,
                    });
                }
            }
            Err(err) => println!("[!] Skipped profile {}: {err:#}", path.display()),
        }
    }
    Ok(profiles)
}

fn auto_profile_paths(pe_path: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(executable) = env::current_exe()
        && let Some(parent) = executable.parent()
    {
        roots.push(parent.join("profiles"));
    }
    if let Some(parent) = pe_path.parent() {
        roots.push(parent.join("amice-profiles"));
        roots.push(parent.join("profiles"));
    }

    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    for root in roots {
        if root.join("manifest.toml").is_file() && seen.insert(root.clone()) {
            paths.push(root.clone());
        }
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.join("manifest.toml").is_file() && seen.insert(path.clone()) {
                paths.push(path);
            }
        }
    }
    paths.sort();
    paths
}

fn format_pe_location(location: &PeLocation) -> String {
    format!(
        "{} {} file+0x{:x} size={}",
        location.section, location.va, location.file_offset, location.size
    )
}

fn discover(args: &[String]) -> Result<()> {
    let started = Instant::now();
    validate_value_options(args, &["--ll"])?;
    let ll_path = take_path_arg(args, "--ll")?;
    let module = LlModule::load(&ll_path)?;

    println!("[*] Loaded: {}", ll_path.display());
    print_section("BYTE ARRAYS");
    for global in likely_bytecode_blobs(&module).into_iter().take(20) {
        let marker = if global.bytes.starts_with(b"AMICEVMP") {
            " package"
        } else {
            ""
        };
        println!("  {} len={}{}", global.name, global.len, marker);
    }

    print_section("I64 ARRAYS");
    for global in &module.i64_globals {
        let rows = if global.len % 8 == 0 {
            format!(" descriptor_rows={}", global.len / 8)
        } else {
            String::new()
        };
        let seed = marker_seed_from_name(&global.name)
            .map(|seed| format!(" marker_seed=0x{seed:016x}"))
            .unwrap_or_default();
        println!("  {} len={}{}{}", global.name, global.len, rows, seed);
    }

    print_section("POINTER ARRAYS");
    for global in &module.ptr_globals {
        println!("  {} len={}", global.name, global.len);
    }
    if !module.wrapper_safe_names.is_empty() {
        print_section("VM WRAPPER SAFE NAMES");
        for (index, name) in module.wrapper_safe_names.iter().enumerate() {
            println!("  {index}: {name}");
        }
    }
    println!("\n[+] Runtime: {:.2}s", started.elapsed().as_secs_f64());
    Ok(())
}

fn decode(args: &[String]) -> Result<()> {
    let started = Instant::now();
    validate_value_options_with_repeats(
        args,
        &[
            "--ll",
            "--profile",
            "--out",
            "--descriptor-seed",
            "--safe-names",
            "--string-algorithm",
            "--string-key-global",
            "--string-globals",
        ],
        &["--profile", "--descriptor-seed"],
    )?;
    let ll_path = take_path_arg(args, "--ll")?;
    let out_dir = take_path_arg(args, "--out")?;
    let descriptor_seeds = option_values(args, "--descriptor-seed")
        .into_iter()
        .map(parse_u64_arg)
        .collect::<Result<Vec<_>>>()?;
    if descriptor_seeds.iter().collect::<HashSet<_>>().len() != descriptor_seeds.len() {
        bail!("duplicate --descriptor-seed value");
    }
    let safe_names = optional_arg(args, "--safe-names");
    let string_options = parse_string_options(args)?;

    println!("[*] Loaded: {}", ll_path.display());
    let profiles = load_pe_profiles(option_values(args, "--profile"))?;
    for profile in &profiles {
        println!("[*] Profile: {}", profile.name);
    }
    let module = LlModule::load(&ll_path)?;
    let string_report = recover_strings(&module, &string_options)?;
    let seeds = if !descriptor_seeds.is_empty() {
        descriptor_seeds
    } else {
        let markers = marker_seeds(&module);
        if !markers.is_empty() {
            markers
        } else if profiles.len() == 1 {
            vec![match safe_names.as_deref() {
                Some(names) => seed_from_args(&profiles[0].package, Some(names), None)?,
                None => seed_from_wrappers(&profiles[0].package, &module).context(
                    "decode needs --descriptor-seed, --safe-names, marker seeds, or VM wrapper names in IR",
                )?,
            }]
        } else {
            bail!("markerless IR with multiple profiles needs one --descriptor-seed per VMP group");
        }
    };

    let groups = decode_ir_groups(&module, &profiles, &seeds)?;
    for (group_index, (_, report)) in groups.iter().enumerate() {
        let group_out = if groups.len() == 1 {
            out_dir.clone()
        } else {
            out_dir.join(format!("group-{group_index:03}"))
        };
        write_report(report, &group_out)?;
    }
    write_string_report(&string_report, &out_dir)?;

    println!("[+] VMP groups: {}", groups.len());
    println!(
        "[+] Descriptors: {}",
        groups
            .iter()
            .map(|(_, report)| report.descriptors.len())
            .sum::<usize>()
    );
    println!(
        "[+] VM records: {}",
        groups
            .iter()
            .map(|(_, report)| report.records.len())
            .sum::<usize>()
    );
    print_string_summary(&string_report);
    for (group_index, (profile, report)) in groups.iter().enumerate() {
        print_section(&format!("VMP GROUP {group_index:03}"));
        println!("  profile={profile}");
        println!("  bytecode={}", report.bytecode_global);
        println!("  descriptors={}", report.descriptor_global);
        if let Some(native_global) = &report.native_global {
            println!("  native_table={native_global}");
        }
        println!("  descriptor_seed=0x{:016x}", report.descriptor_seed);
        print_lift_summary(&report.records);
        print_decoded_functions(report);
        print_native_calls(report);
    }
    print_recovered_strings(&string_report);
    println!("[+] Output: {}", out_dir.display());
    println!("[+] Runtime: {:.2}s", started.elapsed().as_secs_f64());
    Ok(())
}

fn decode_ir_groups(
    module: &LlModule,
    profiles: &[PeProfile],
    seeds: &[u64],
) -> Result<Vec<(String, DecodeReport)>> {
    let mut decoded = Vec::<(usize, DecodeReport)>::new();
    let mut rejected = Vec::new();
    for (profile_index, profile) in profiles.iter().enumerate() {
        for seed in seeds {
            match decode_module(DecodeInput {
                module: module.clone(),
                profile: profile.package.clone(),
                seed: *seed,
            }) {
                Ok(report) => {
                    if let Some((previous_profile, previous)) =
                        decoded.iter().find(|(_, previous)| {
                            previous.descriptor_global == report.descriptor_global
                                && previous.bytecode_global == report.bytecode_global
                        })
                    {
                        if previous.descriptor_seed != report.descriptor_seed {
                            bail!(
                                "IR group {}/{} validates with multiple descriptor seeds",
                                report.descriptor_global,
                                report.bytecode_global
                            );
                        }
                        if profiles[*previous_profile].package != profile.package {
                            bail!(
                                "IR group {}/{} validates with multiple distinct profiles: {}, {}",
                                report.descriptor_global,
                                report.bytecode_global,
                                profiles[*previous_profile].name,
                                profile.name
                            );
                        }
                    } else {
                        decoded.push((profile_index, report));
                    }
                }
                Err(err) => rejected.push(format!("{} seed 0x{seed:016x}: {err:#}", profile.name)),
            }
        }
    }
    if decoded.is_empty() {
        bail!(
            "no IR descriptor/blob pair passed full validation: {}",
            rejected.into_iter().take(4).collect::<Vec<_>>().join("; ")
        );
    }
    decoded.sort_by_key(|(_, report)| {
        module
            .i64_globals
            .iter()
            .position(|global| global.name == report.descriptor_global)
            .unwrap_or(usize::MAX)
    });
    Ok(decoded
        .into_iter()
        .map(|(profile_index, report)| (profiles[profile_index].name.clone(), report))
        .collect())
}

fn decode_package_globals(args: &[String]) -> Result<()> {
    let started = Instant::now();
    validate_value_options(
        args,
        &[
            "--ll",
            "--profile",
            "--out",
            "--global",
            "--string-algorithm",
            "--string-key-global",
            "--string-globals",
        ],
    )?;
    let ll_path = take_path_arg(args, "--ll")?;
    let out_dir = take_path_arg(args, "--out")?;
    let requested_global = optional_arg(args, "--global");
    let string_options = parse_string_options(args)?;

    println!("[*] Loaded: {}", ll_path.display());
    let (profile, profile_name) = load_profile(optional_arg(args, "--profile"))?;
    println!("[*] Profile: {profile_name}");
    let module = LlModule::load(&ll_path)?;
    let string_report = recover_strings(&module, &string_options)?;
    let report = decode_packages(&module, &profile, requested_global.as_deref())?;
    write_package_report(&report, &out_dir)?;
    write_string_report(&string_report, &out_dir)?;

    println!("[+] Packages: {}", report.packages.len());
    println!("[+] VM records: {}", report.records.len());
    print_string_summary(&string_report);
    print_lift_summary(&report.records);
    print_package_functions(&report);
    print_recovered_strings(&string_report);
    println!("[+] Output: {}", out_dir.display());
    println!("[+] Runtime: {:.2}s", started.elapsed().as_secs_f64());
    Ok(())
}

fn decode_string_globals(args: &[String]) -> Result<()> {
    let started = Instant::now();
    validate_value_options(
        args,
        &[
            "--ll",
            "--out",
            "--string-algorithm",
            "--string-key-global",
            "--string-globals",
        ],
    )?;
    let ll_path = take_path_arg(args, "--ll")?;
    let out_dir = take_path_arg(args, "--out")?;
    let options = parse_string_options(args)?;

    println!("[*] Loaded: {}", ll_path.display());
    let module = LlModule::load(&ll_path)?;
    let report = recover_strings(&module, &options)?;
    write_string_report(&report, &out_dir)?;

    print_string_summary(&report);
    print_recovered_strings(&report);
    println!("[+] Output: {}", out_dir.display());
    println!("[+] Runtime: {:.2}s", started.elapsed().as_secs_f64());
    Ok(())
}

fn parse_string_options(args: &[String]) -> Result<StringDecodeOptions> {
    let algorithm = optional_arg(args, "--string-algorithm")
        .map(|value| match value.as_str() {
            "auto" => Ok(None),
            "plain" => Ok(Some(StringAlgorithm::Plain)),
            "xor" => Ok(Some(StringAlgorithm::Xor)),
            "simd_xor" | "simd-xor" => Ok(Some(StringAlgorithm::SimdXor)),
            _ => {
                bail!("invalid --string-algorithm {value}; expected auto, plain, xor, or simd_xor")
            }
        })
        .transpose()?
        .flatten();
    let key_global = optional_arg(args, "--string-key-global").map(normalize_global_arg);
    let globals = optional_arg(args, "--string-globals")
        .map(|value| parse_global_list(&value))
        .transpose()?;
    Ok(StringDecodeOptions {
        algorithm,
        key_global,
        globals,
    })
}

fn parse_global_list(value: &str) -> Result<Vec<String>> {
    let globals = value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(normalize_global_arg)
        .collect::<Vec<_>>();
    if globals.is_empty() {
        bail!("--string-globals did not contain any names");
    }
    let unique = globals.iter().collect::<HashSet<_>>();
    if unique.len() != globals.len() {
        bail!("--string-globals contains duplicate names");
    }
    Ok(globals)
}

fn load_profile(path: Option<String>) -> Result<(ProfilePackage, String)> {
    if let Some(path) = path {
        let path = PathBuf::from(path);
        let (profile, _) = read_verified_profile(&path)
            .with_context(|| format!("load profile {}", path.display()))?;
        return Ok((profile, path.display().to_string()));
    }
    let profile =
        ProfilePackage::builtin_test().context("load built-in amice-simple-vmp profile")?;
    verify_profile(&profile).context("verify VMP profile")?;
    Ok((profile, "built-in amice-simple-vmp".to_owned()))
}

fn read_verified_profile(path: &Path) -> Result<(ProfilePackage, bool)> {
    let read = |name: &str| {
        let file = path.join(name);
        fs::read_to_string(&file).with_context(|| format!("read {}", file.display()))
    };
    let manifest_text = read("manifest.toml")?;
    let manifest: amice_vm::profile::Manifest = toml::from_str(&manifest_text)?;
    let files = &manifest.profile;
    let abi = read(&files.abi)?;
    let isa = read(&files.isa)?;
    let lowering = read(&files.lowering)?;
    let bytecode = read(&files.bytecode)?;
    let decoder = read(&files.decoder)?;
    let runtime = read(&files.runtime)?;
    let profile = ProfilePackage::from_sources(
        manifest, &abi, &isa, &lowering, &bytecode, &decoder, &runtime,
    )?;
    if let Err(current_error) = verify_profile(&profile) {
        // Older packages predate four mandatory atomic handlers. Validate the
        // same source snapshot with their verifier before accepting one.
        let legacy = amice_vm_legacy::ProfilePackage::from_sources(
            toml::from_str(&manifest_text)?,
            &abi,
            &isa,
            &lowering,
            &bytecode,
            &decoder,
            &runtime,
        )
        .and_then(|legacy| {
            amice_vm_legacy::verify::verify_profile(&legacy)?;
            Ok(legacy == amice_vm_legacy::ProfilePackage::builtin_test()?)
        });
        let legacy_builtin = legacy.with_context(|| {
            format!("verify VMP profile ({current_error}); legacy verification also failed")
        })?;
        return Ok((profile, legacy_builtin));
    }
    Ok((profile, false))
}

fn load_pe_profiles(paths: Vec<String>) -> Result<Vec<PeProfile>> {
    let requested = if paths.is_empty() {
        vec![None]
    } else {
        paths.into_iter().map(Some).collect()
    };
    let mut profiles = Vec::<PeProfile>::new();
    for path in requested {
        let (package, name) = load_profile(path)?;
        if let Some(previous) = profiles.iter().find(|profile| profile.package == package) {
            bail!("profiles {} and {name} are identical", previous.name);
        }
        profiles.push(PeProfile { name, package });
    }
    Ok(profiles)
}

fn normalize_global_arg(name: impl AsRef<str>) -> String {
    name.as_ref()
        .strip_prefix('@')
        .unwrap_or(name.as_ref())
        .to_owned()
}

fn print_string_summary(report: &StringReport) {
    let algorithm = report
        .algorithm
        .map(StringAlgorithm::as_str)
        .unwrap_or("not detected");
    println!("[+] String algorithm: {algorithm}");
    if let Some(key_global) = &report.key_global {
        println!("[+] String key global: {key_global}");
    }
    println!("[+] Recovered strings: {}", report.strings.len());
}

fn print_lift_summary(records: &[VmRecord]) {
    let coverage = lift_coverage(records);
    println!(
        "[+] Lift coverage: {}/{} ({:.2}%)",
        coverage.lifted_records, coverage.meaningful_records, coverage.percent
    );
    if !coverage.unknown_mnemonics.is_empty() {
        println!(
            "[!] Unlifted mnemonics: {}",
            coverage.unknown_mnemonics.join(", ")
        );
    }
}

fn print_decoded_functions(report: &DecodeReport) {
    print_section("DECODED FUNCTIONS");
    for descriptor in &report.descriptors {
        let name = descriptor.function_name.as_deref().unwrap_or("unresolved");
        let records = report
            .records
            .iter()
            .filter(|record| record.fn_index == descriptor.fn_index)
            .count();
        println!(
            "  fn[{}] {} records={} consts={} native={} guard={}",
            descriptor.fn_index,
            name,
            records,
            descriptor.const_pool.len(),
            descriptor.native_targets.len(),
            if descriptor.guard_valid {
                "valid"
            } else {
                "invalid"
            }
        );
    }
}

fn print_package_functions(report: &PackageReport) {
    print_section("DECODED FUNCTIONS");
    for package in &report.packages {
        println!(
            "  fn[{}] {} records={} consts={} relocations={}",
            package.fn_index,
            package.function_name,
            package.instruction_count,
            package.const_pool.len(),
            package.relocations.len()
        );
    }
}

fn print_recovered_strings(report: &StringReport) {
    print_section("RECOVERED STRINGS");
    for recovered in &report.strings {
        println!(
            "  {}[{}] algorithm={} \"{}\"",
            recovered.global,
            recovered.literal_index,
            recovered.algorithm.as_str(),
            recovered.escaped
        );
    }
}

fn print_native_calls(report: &DecodeReport) {
    let mut calls = BTreeSet::new();
    let mut unresolved = 0;
    for descriptor in &report.descriptors {
        for target in &descriptor.native_targets {
            if let Some(name) = target.callee.as_deref().or(target.thunk.as_deref()) {
                calls.insert(format!(
                    "fn[{}] native[{}] table[{}] = {}",
                    descriptor.fn_index, target.local_index, target.table_index, name
                ));
            } else {
                unresolved += 1;
            }
        }
    }
    print_section("NATIVE CALLS");
    for call in calls {
        println!("  {call}");
    }
    if unresolved > 0 {
        println!("  unresolved={unresolved}");
    }
}

fn take_path_arg(args: &[String], name: &str) -> Result<PathBuf> {
    optional_arg(args, name)
        .map(PathBuf::from)
        .with_context(|| format!("missing {name}"))
}

fn optional_arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].to_owned())
}

fn option_values(args: &[String], name: &str) -> Vec<String> {
    let (pairs, _) = args.as_chunks::<2>();
    pairs
        .iter()
        .filter(|[key, _]| key == name)
        .map(|[_, value]| value.to_owned())
        .collect()
}

fn validate_value_options(args: &[String], allowed: &[&str]) -> Result<()> {
    validate_value_options_with_repeats(args, allowed, &[])
}

fn validate_value_options_with_repeats(
    args: &[String],
    allowed: &[&str],
    repeatable: &[&str],
) -> Result<()> {
    let mut seen = HashSet::new();
    let mut index = 0;
    while index < args.len() {
        let option = args[index].as_str();
        if !allowed.contains(&option) {
            bail!("unknown option {option}");
        }
        if !seen.insert(option) && !repeatable.contains(&option) {
            bail!("duplicate option {option}");
        }
        let value = args
            .get(index + 1)
            .with_context(|| format!("missing value for {option}"))?;
        if value.starts_with("--") {
            bail!("missing value for {option}");
        }
        index += 2;
    }
    Ok(())
}

fn parse_u64_arg(value: String) -> Result<u64> {
    if let Some(hex) = value.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).with_context(|| format!("invalid hex {value}"));
    }
    value
        .parse::<u64>()
        .with_context(|| format!("invalid integer {value}"))
}

fn print_usage() {
    println!("static Amice VMP PE64 and LLVM IR devirtualizer. zero execution.\n");
    println!("usage: amice-devirt <file.exe>");
    println!("       amice-devirt <command> [options]\n");
    println!("drag and drop:");
    println!("  drop one executable on amice-devirt.exe to run every PE pass");
    println!("  reports are written beside it to <file>.amice-devirt");
    println!("  custom profiles are loaded from profiles/ or amice-profiles/\n");
    println!("commands:");
    println!("  discover  inspect candidate globals and recoverable seed inputs");
    println!("  decode    decode production compact blob + descriptor table");
    println!("  decode-pe decode VMP directly from an x86-64 PE executable");
    println!("  strings-pe recover StringEncryption directly from an x86-64 PE");
    println!("  package   decode AMICEVMP per-function package globals");
    println!("  strings   recover Amice StringEncryption globals\n");
    println!("decode:");
    println!("  --ll <file.ll>             LLVM textual IR");
    println!("  --profile <profile-dir>    repeat for every custom VMP group");
    println!("  --out <dir>                report directory");
    println!("  --descriptor-seed <hex>    repeatable direct seed override");
    println!("  --safe-names <a,b,c>       ordered wrapper safe names\n");
    println!("decode-pe:");
    println!("  --pe <file.exe>            x86-64 PE32+ executable");
    println!("  --profile <profile-dir>    repeat for every custom VMP group");
    println!("  --out <dir>                report directory");
    println!("  --descriptor-seed <hex>    repeatable seed recovery fallback");
    println!("  --pdb <file.pdb>           optional private/public symbol names\n");
    println!("package:");
    println!("  --global <name>            decode one named byte global\n");
    println!("string options:");
    println!("  --string-algorithm <name>  auto, plain, xor, or simd_xor");
    println!("  --string-key-global <name> simd_xor key global override");
    println!("  --string-globals <a,b,c>   protected global override");
}

fn print_banner() {
    println!("{BANNER}");
    println!("                static Amice VMP devirtualizer");
}

fn print_section(title: &str) {
    println!("\n{RULE}");
    println!("{title}");
    println!("{RULE}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_options_reject_unknown_duplicate_and_missing_values() {
        assert!(validate_value_options(&["--wat".into(), "x".into()], &["--ll"]).is_err());
        assert!(
            validate_value_options(
                &["--ll".into(), "a.ll".into(), "--ll".into(), "b.ll".into()],
                &["--ll"]
            )
            .is_err()
        );
        assert!(validate_value_options(&["--ll".into()], &["--ll"]).is_err());
        assert!(
            validate_value_options_with_repeats(
                &[
                    "--profile".into(),
                    "simple".into(),
                    "--profile".into(),
                    "ruoke".into(),
                ],
                &["--profile"],
                &["--profile"],
            )
            .is_ok()
        );
    }

    #[test]
    fn parses_hex_and_decimal_seeds() {
        assert_eq!(parse_u64_arg("0xff".into()).unwrap(), 255);
        assert_eq!(parse_u64_arg("255".into()).unwrap(), 255);
    }
}
