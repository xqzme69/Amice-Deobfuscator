use amice_devirt::decode::{DecodeInput, decode_module, marker_seed, seed_from_wrappers};
use amice_devirt::llvm_ir::LlModule;
use amice_devirt::package::decode_packages;
use amice_devirt::pe::{PeProfile, decode_pe64, decode_pe64_profiles, recover_pe64_strings};
use amice_devirt::render::lift_coverage;
use amice_devirt::strings::{StringAlgorithm, StringDecodeOptions, recover_strings};
use amice_vm::ProfilePackage;
use std::{fs, path::PathBuf, process::Command};

fn work_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
#[ignore = "requires the local Amice-generated fixture corpus"]
fn decodes_marker_vmvirtualize_fixture() {
    let root = work_root();
    let ll_path = root
        .join("rev-meme-sample")
        .join("target-amice-llvm201-matrix")
        .join("VmVirtualize")
        .join("out.ll");
    assert!(ll_path.exists(), "missing fixture {}", ll_path.display());

    let module = LlModule::load(&ll_path).unwrap();
    let profile = ProfilePackage::builtin_test().unwrap();
    let package_report = decode_packages(&module, &profile, None).unwrap();
    let report = decode_module(DecodeInput {
        module,
        profile,
        seed: 0x356b_517d_6b1d_db25,
    })
    .unwrap();

    assert_eq!(report.descriptors.len(), 3);
    assert!(!report.records.is_empty());
    assert_eq!(package_report.packages.len(), 3);
    assert_eq!(
        record_signatures(&package_report.records),
        record_signatures(&report.records)
    );
    assert!(
        report
            .records
            .iter()
            .any(|record| record.mnemonic == "ret_void" || record.mnemonic == "ret")
    );
}

fn record_signatures(
    records: &[amice_devirt::bytecode::VmRecord],
) -> Vec<(usize, usize, u16, String, Vec<u64>)> {
    records
        .iter()
        .map(|record| {
            (
                record.fn_index,
                record.pc,
                record.opcode,
                record.mnemonic.clone(),
                record
                    .operands
                    .iter()
                    .map(|operand| operand.value)
                    .collect(),
            )
        })
        .collect()
}

#[test]
#[ignore = "requires the local Amice-generated fixture corpus"]
fn decodes_stage1_fixture_from_wrapper_names() {
    let root = work_root();
    let ll_path = root
        .join("rev-meme-sample")
        .join("target-amice-llvm201-final")
        .join("max-vmp")
        .join("stage1-vmp.ll");
    assert!(ll_path.exists(), "missing fixture {}", ll_path.display());

    let module = LlModule::load(&ll_path).unwrap();
    let profile = ProfilePackage::builtin_test().unwrap();
    let seed = amice_devirt::decode::seed_from_wrappers(&profile, &module).unwrap();
    let report = decode_module(DecodeInput {
        module,
        profile,
        seed,
    })
    .unwrap();

    assert_eq!(report.descriptors.len(), 8);
    assert_eq!(report.descriptor_seed, 0xf9e6_0352_f5b5_e4ba);
    assert!(report.records.len() > 1000);
}

#[test]
#[ignore = "requires the local Amice-generated fixture corpus"]
fn decodes_stage3_fixture_with_stage1_seed() {
    let root = work_root();
    let stage1_path = root
        .join("rev-meme-sample")
        .join("target-amice-llvm201-final")
        .join("max-vmp")
        .join("stage1-vmp.ll");
    let ll_path = root
        .join("rev-meme-sample")
        .join("target-amice-llvm201-final")
        .join("max-vmp")
        .join("stage3-vm-flatten.ll");
    assert!(ll_path.exists(), "missing fixture {}", ll_path.display());
    assert!(
        stage1_path.exists(),
        "missing fixture {}",
        stage1_path.display()
    );

    let module = LlModule::load(&ll_path).unwrap();
    let profile = ProfilePackage::builtin_test().unwrap();
    let report = decode_module(DecodeInput {
        module,
        profile,
        seed: 0xf9e6_0352_f5b5_e4ba,
    })
    .unwrap();

    assert_eq!(report.descriptors.len(), 8);
    assert_eq!(report.records.len(), 1768);

    let stage1_module = LlModule::load(&stage1_path).unwrap();
    let stage1_profile = ProfilePackage::builtin_test().unwrap();
    let stage1_report = decode_module(DecodeInput {
        module: stage1_module,
        profile: stage1_profile,
        seed: 0xf9e6_0352_f5b5_e4ba,
    })
    .unwrap();
    assert_eq!(
        record_signatures(&stage1_report.records),
        record_signatures(&report.records)
    );
}

#[test]
#[ignore = "requires the local Amice-generated fixture corpus"]
fn decodes_markerless_pe64_and_matches_stage3_ir() {
    let root = work_root();
    let pe_path = root
        .join("artifacts")
        .join("rev-meme-sample.amice-max-vmp.exe");
    let ll_path = root
        .join("rev-meme-sample")
        .join("target-amice-llvm201-final")
        .join("max-vmp")
        .join("stage3-vm-flatten.ll");
    assert!(pe_path.exists(), "missing fixture {}", pe_path.display());
    assert!(ll_path.exists(), "missing fixture {}", ll_path.display());

    let profile = ProfilePackage::builtin_test().unwrap();
    let pe = decode_pe64(&fs::read(&pe_path).unwrap(), &profile, None).unwrap();
    let stage3 = decode_module(DecodeInput {
        module: LlModule::load(&ll_path).unwrap(),
        profile: profile.clone(),
        seed: 0xf9e6_0352_f5b5_e4ba,
    })
    .unwrap();
    assert_eq!(pe.groups.len(), 1);
    let group = &pe.groups[0];

    assert_eq!(group.decode.descriptor_seed, 0xf9e6_0352_f5b5_e4ba);
    assert_eq!(group.layout.seed.source, "x86_64_imm64");
    assert!(group.layout.seed.instruction_va.is_some());
    assert_eq!(group.decode.descriptors.len(), 8);
    assert_eq!(group.decode.records.len(), 1768);
    assert_eq!(
        group.layout.native_table.as_ref().unwrap().section,
        ".rdata"
    );
    assert_eq!(
        group
            .decode
            .descriptors
            .iter()
            .map(|descriptor| descriptor.native_targets.len())
            .sum::<usize>(),
        29
    );
    assert!(
        group
            .decode
            .descriptors
            .iter()
            .all(|descriptor| descriptor.guard_valid)
    );
    assert!(
        group
            .decode
            .descriptors
            .iter()
            .all(|descriptor| descriptor.wrapper_va.is_some())
    );
    assert!(
        group
            .decode
            .descriptors
            .iter()
            .flat_map(|descriptor| &descriptor.native_targets)
            .all(|target| target.callee.is_some())
    );
    assert!(
        pe.strings
            .strings
            .iter()
            .filter_map(|string| string.text.as_deref())
            .any(|text| text.contains("deobf"))
    );
    assert_eq!(
        record_signatures(&group.decode.records),
        record_signatures(&stage3.records)
    );

    let explicit = decode_pe64(
        &fs::read(&pe_path).unwrap(),
        &profile,
        Some(0xf9e6_0352_f5b5_e4ba),
    )
    .unwrap();
    assert_eq!(explicit.groups.len(), 1);
    assert_eq!(explicit.groups[0].layout.seed.source, "argument");
    assert_eq!(
        record_signatures(&explicit.groups[0].decode.records),
        record_signatures(&group.decode.records)
    );
}

#[test]
#[ignore = "requires the local Amice-generated fixture corpus"]
fn rejects_pe64_without_amice_vmp() {
    let pe_path = work_root()
        .join("artifacts")
        .join("rev-meme-sample.amice-full-classic.exe");
    assert!(pe_path.exists(), "missing fixture {}", pe_path.display());

    let profile = ProfilePackage::builtin_test().unwrap();
    let error = decode_pe64(&fs::read(&pe_path).unwrap(), &profile, None).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("no descriptor table passed guard and layout validation")
    );
}

#[test]
#[ignore = "requires the local Amice-generated fixture corpus"]
fn recovers_all_generated_string_modes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("_generated_string_matrix");
    assert!(root.exists(), "missing fixture corpus {}", root.display());

    for (mode, expected_algorithm) in [
        ("xor-global", StringAlgorithm::Plain),
        ("xor-lazy", StringAlgorithm::Xor),
        ("xor-stack", StringAlgorithm::Plain),
        ("xor-inline", StringAlgorithm::Xor),
        ("simd-global", StringAlgorithm::Plain),
        ("simd-lazy", StringAlgorithm::SimdXor),
        ("simd-stack", StringAlgorithm::Plain),
        ("simd-inline", StringAlgorithm::SimdXor),
    ] {
        let ll_path = root.join(mode).join("out.ll");
        assert!(
            ll_path.exists(),
            "missing generated fixture {}",
            ll_path.display()
        );
        let module = LlModule::load(&ll_path).unwrap();
        let report = recover_strings(&module, &StringDecodeOptions::default()).unwrap();
        let texts = report
            .strings
            .iter()
            .filter_map(|string| string.text.as_deref())
            .collect::<Vec<_>>();

        assert_eq!(report.algorithm, Some(expected_algorithm), "mode {mode}");
        assert!(texts.contains(&"hello"), "mode {mode}: {texts:?}");
        assert!(texts.contains(&"static gang"), "mode {mode}: {texts:?}");

        let pe_path = root.join(mode).join("out.exe");
        assert!(
            pe_path.exists(),
            "missing generated fixture {}",
            pe_path.display()
        );
        let pe_report = recover_pe64_strings(&fs::read(&pe_path).unwrap()).unwrap();
        let pe_texts = pe_report
            .strings
            .iter()
            .filter_map(|string| string.text.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(
            pe_report.algorithm,
            Some(expected_algorithm),
            "PE mode {mode}"
        );
        assert!(pe_texts.contains(&"hello"), "PE mode {mode}: {pe_texts:?}");
        assert!(
            pe_texts.contains(&"static gang"),
            "PE mode {mode}: {pe_texts:?}"
        );
    }
}

#[test]
#[ignore = "requires the local Amice-generated fixture corpus"]
fn decodes_multiple_profile_groups_from_pe64() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pe_path = root.join("_generated_multi_profile").join("out.exe");
    let profile_root = work_root()
        .join("amice")
        .join("crates")
        .join("amice-vm")
        .join("profiles");
    assert!(pe_path.exists(), "missing fixture {}", pe_path.display());

    let profiles = [
        PeProfile {
            name: "amice-simple-vmp".to_owned(),
            package: ProfilePackage::load_from_path(&profile_root.join("amice-simple-vmp"))
                .unwrap(),
        },
        PeProfile {
            name: "ruoke".to_owned(),
            package: ProfilePackage::load_from_path(&profile_root.join("ruoke")).unwrap(),
        },
    ];
    let report = decode_pe64_profiles(&fs::read(&pe_path).unwrap(), &profiles, &[]).unwrap();

    assert_eq!(report.groups.len(), 2);
    assert_eq!(
        report
            .groups
            .iter()
            .map(|group| group.layout.profile.as_str())
            .collect::<Vec<_>>(),
        ["amice-simple-vmp", "ruoke"]
    );
    assert_eq!(
        report
            .groups
            .iter()
            .map(|group| group.decode.records.len())
            .collect::<Vec<_>>(),
        [18, 31]
    );
    assert!(report.groups.iter().all(|group| {
        group.decode.descriptors.len() == 1
            && group.decode.descriptors[0].guard_valid
            && group.decode.descriptors[0].wrapper_va.is_some()
            && group.layout.native_table.is_some()
            && group.decode.descriptors[0].native_targets.len() == 1
            && group.decode.descriptors[0].native_targets[0]
                .callee
                .is_some()
            && lift_coverage(&group.decode.records).unknown_records == 0
    }));
    assert_ne!(
        report.groups[0].layout.native_table,
        report.groups[1].layout.native_table
    );

    let with_simple_override = decode_pe64_profiles(
        &fs::read(&pe_path).unwrap(),
        &profiles,
        &[0xfbf4_30d5_3137_ed45],
    )
    .unwrap();
    assert_eq!(with_simple_override.groups.len(), 2);
    assert_eq!(
        with_simple_override
            .groups
            .iter()
            .find(|group| group.layout.profile == "amice-simple-vmp")
            .unwrap()
            .layout
            .seed
            .source,
        "argument"
    );
    assert_eq!(
        with_simple_override
            .groups
            .iter()
            .find(|group| group.layout.profile == "ruoke")
            .unwrap()
            .layout
            .seed
            .source,
        "x86_64_imm64"
    );

    let module = LlModule::load(&root.join("_generated_multi_profile").join("out.ll")).unwrap();
    for (profile, seed, name) in [
        (
            profiles[0].package.clone(),
            0xfbf4_30d5_3137_ed45,
            "simple_vm",
        ),
        (
            profiles[1].package.clone(),
            0xb519_8a22_755f_1938,
            "ruoke_vm",
        ),
    ] {
        let report = decode_module(DecodeInput {
            module: module.clone(),
            profile,
            seed,
        })
        .unwrap();
        assert_eq!(report.descriptors.len(), 1);
        assert_eq!(report.descriptors[0].function_name.as_deref(), Some(name));
        assert_eq!(
            report.descriptors[0].native_targets[0].callee.as_deref(),
            Some("native_mix")
        );
    }
}

#[test]
#[ignore = "requires the local Amice-generated fixture corpus"]
fn drag_and_drop_mode_writes_reports_next_to_the_executable() {
    let pe_path = work_root()
        .join("artifacts")
        .join("rev-meme-sample.amice-max-vmp.exe");
    assert!(pe_path.exists(), "missing fixture {}", pe_path.display());

    let output = Command::new(env!("CARGO_BIN_EXE_amice-devirt"))
        .arg(&pe_path)
        .env("AMICE_DEVIRT_NO_PAUSE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Auto mode: maximum static pass"));

    let out_dir = pe_path
        .parent()
        .unwrap()
        .join("rev-meme-sample.amice-max-vmp.amice-devirt");
    let summary: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out_dir.join("auto-summary.json")).unwrap())
            .unwrap();
    assert_eq!(summary["vmp_decoded"], true);
    assert_eq!(summary["vmp_groups"], 1);
    assert_eq!(summary["descriptors"], 8);
    assert_eq!(summary["vm_records"], 1768);
    for file in [
        "descriptors.json",
        "vm.jsonl",
        "vm.txt",
        "lift.ll.txt",
        "lift-coverage.json",
        "pe-layout.json",
        "strings.json",
        "strings.txt",
    ] {
        assert!(out_dir.join(file).is_file(), "missing auto output {file}");
    }
}

#[test]
#[ignore = "requires the local Amice-generated fixture corpus"]
fn decodes_generated_c_and_cpp_artifacts() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("_generated_language_matrix");
    assert!(root.exists(), "missing fixture corpus {}", root.display());

    for (language, expected_strings) in [
        ("c", ["c deobf", "c static gang"]),
        ("cpp", ["cpp deobf", "cpp static gang"]),
    ] {
        for (file, algorithm) in [
            ("xor-lazy.ll", StringAlgorithm::Xor),
            ("simd-lazy.ll", StringAlgorithm::SimdXor),
        ] {
            let ll_path = root.join(language).join(file);
            assert!(
                ll_path.exists(),
                "missing generated fixture {}",
                ll_path.display()
            );
            let module = LlModule::load(&ll_path).unwrap();
            let report = recover_strings(&module, &StringDecodeOptions::default()).unwrap();
            let texts = report
                .strings
                .iter()
                .filter_map(|string| string.text.as_deref())
                .collect::<Vec<_>>();

            assert_eq!(report.algorithm, Some(algorithm), "{language} {file}");
            for expected in expected_strings {
                assert!(texts.contains(&expected), "{language} {file}: {texts:?}");
            }
        }

        for (file, has_markers) in [("vmp.ll", true), ("vmp-markerless.ll", false)] {
            let ll_path = root.join(language).join(file);
            assert!(
                ll_path.exists(),
                "missing generated fixture {}",
                ll_path.display()
            );
            let module = LlModule::load(&ll_path).unwrap();
            let profile = ProfilePackage::builtin_test().unwrap();
            let seed = if has_markers {
                marker_seed(&module).expect("generated VMP fixture marker seed")
            } else {
                assert!(marker_seed(&module).is_none(), "{language} {file}");
                seed_from_wrappers(&profile, &module).expect("markerless wrapper seed")
            };
            let report = decode_module(DecodeInput {
                module,
                profile,
                seed,
            })
            .unwrap();
            let coverage = lift_coverage(&report.records);

            assert_eq!(report.descriptors.len(), 1, "{language} {file}");
            assert!(report.descriptors[0].guard_valid, "{language} {file}");
            assert!(
                report.descriptors[0]
                    .function_name
                    .as_deref()
                    .is_some_and(|name| name.contains("vm_math")),
                "{language} {file}"
            );
            assert_eq!(coverage.unknown_records, 0, "{language} {file}");
        }

        for (file, algorithm) in [
            ("xor-lazy.exe", StringAlgorithm::Xor),
            ("simd-lazy.exe", StringAlgorithm::SimdXor),
        ] {
            let pe_path = root.join(language).join(file);
            assert!(
                pe_path.exists(),
                "missing generated fixture {}",
                pe_path.display()
            );
            let report = recover_pe64_strings(&fs::read(&pe_path).unwrap()).unwrap();
            let texts = report
                .strings
                .iter()
                .filter_map(|string| string.text.as_deref())
                .collect::<Vec<_>>();

            assert_eq!(report.algorithm, Some(algorithm), "{language} {file}");
            for expected in expected_strings {
                assert!(texts.contains(&expected), "{language} {file}: {texts:?}");
            }
        }

        let pe_path = root.join(language).join("vmp-markerless.exe");
        assert!(
            pe_path.exists(),
            "missing generated fixture {}",
            pe_path.display()
        );
        let profile = ProfilePackage::builtin_test().unwrap();
        let report = decode_pe64(&fs::read(&pe_path).unwrap(), &profile, None).unwrap();
        assert_eq!(report.groups.len(), 1, "{language} PE");
        assert_eq!(
            report.groups[0].decode.descriptors.len(),
            1,
            "{language} PE"
        );
        assert!(
            report.groups[0].decode.descriptors[0].wrapper_va.is_some(),
            "{language} PE"
        );
        assert_eq!(
            lift_coverage(&report.groups[0].decode.records).unknown_records,
            0,
            "{language} PE"
        );
    }
}
