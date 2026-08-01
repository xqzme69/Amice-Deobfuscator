# amice-devirt

static VMP devirtualizer and StringEncryption extractor for [fuqiuluo/amice](https://github.com/fuqiuluo/amice) protected PE64 binaries and textual LLVM IR. zero execution.

the decoder follows Amice's descriptor, bytecode, profile, runtime, native thunk, and string encryption source. bad guards, ranges, opcodes, and operands stop the decode instead of turning into a convincing but wrong listing.

## install

build it directly from source:

```bash
git clone https://github.com/xqzme69/Amice-Deobfuscator.git
cd Amice-Deobfuscator
cargo build --release
```

the Windows binary will be at `target/release/amice-devirt.exe`. no LLVM checkout is needed to build or run it.

## drag and drop

drop a protected executable onto `amice-devirt.exe`. auto mode runs every PE pass, keeps the console open until Enter is pressed, and writes the reports beside the input:

```text
sample.exe
sample.amice-devirt/
  auto-summary.json
  pe-layout.json
  strings.json
  strings.txt
  descriptors.json
  vm.jsonl
  vm.txt
  lift.ll.txt
  lift-coverage.json
```

the official `amice-simple-vmp` profile is built in. for a custom profile, put its complete package in either of these locations:

```text
amice-devirt.exe
profiles/
  my-profile/
    manifest.toml

sample.exe
amice-profiles/
  my-profile/
    manifest.toml
```

auto mode loads every package it finds there. if a valid descriptor table belongs to a profile that is missing, string results and `auto-summary.json` are still saved, but the VMP decode is reported as failed. it never guesses an ISA.

## features

- markerless x86-64 PE32+ extraction
- multiple independently protected VMP groups in one executable or IR module
- descriptor seed and wrapper recovery from emitted code
- guard-checked descriptor, bytecode, const pool, and native table decoding
- native thunk, import, export, indirect-call table, and optional PDB resolution
- XOR and SIMD XOR strings in `global`, `lazy`, `stack`, and `inline` modes
- Rust, C, and C++ protected output
- readable listings, JSON records, PE locations, and honest pseudo-lift coverage

## cli usage

drag-and-drop mode is also available from a terminal:

```bash
amice-devirt protected.exe
```

run the PE pipeline with explicit paths:

```bash
amice-devirt decode-pe \
  --pe protected.exe \
  --out devirt_out
```

when an executable contains several profile groups, pass every profile package. explicit `--profile` values replace the built-in default for this command:

```bash
amice-devirt decode-pe \
  --pe protected.exe \
  --profile profiles/simple \
  --profile profiles/ruoke \
  --out devirt_out
```

seed recovery is automatic. `--descriptor-seed` is a repeatable fallback for compiler output where the seed is no longer materialized in a recognized form. `--pdb` supplies symbols manually; a sibling PDB is loaded automatically.

recover only PE strings:

```bash
amice-devirt strings-pe --pe protected.exe --out strings_out
```

decode textual LLVM IR:

```bash
amice-devirt decode --ll protected.ll --out devirt_out
```

the IR path also accepts repeated `--profile` and `--descriptor-seed` values, plus `--safe-names` for markerless wrappers. the remaining commands are:

```bash
amice-devirt discover --ll protected.ll
amice-devirt strings --ll protected.ll --out strings_out
amice-devirt package --ll protected.ll --out package_out
```

## sample output

this is auto mode running on the markerless Rust PE in the test corpus. no seed or address was supplied by hand:

```text
[*] Auto mode: maximum static pass
[*] Profile: built-in amice-simple-vmp
[+] VMP groups: 1
[+] Descriptors: 8
[+] VM records: 1768
[+] String algorithm: xor
[+] Recovered strings: 1

========================================================================================================
VMP GROUP 000
========================================================================================================
  descriptor_seed=0xf9e60352f5b5e4ba (x86_64_imm64)
  bytecode=.rdata 0x0000000140038d20 file+0x37720 size=23065
  descriptors=.rdata 0x000000014003e830 file+0x3d230 size=512
  native_table=.rdata 0x000000014003e740 file+0x3d140 size=232
[+] Lift coverage: 876/876 (100.00%)
```

the same run resolved all eight wrappers, all 29 native calls, and the protected `deobf` test strings.

## output

- `auto-summary.json`: drag-and-drop status, loaded profiles, totals, and any VMP error
- `pe-layout.json`: image sections, group locations, seed evidence, wrappers, and native tables
- `descriptors.json`: decrypted fields, guard state, const pools, and native targets
- `vm.jsonl`: one decoded VM instruction per line
- `vm.txt`: readable listing grouped by function
- `lift.ll.txt`: pseudo-IR for semantics described by the profile
- `lift-coverage.json`: lifted and `vm_unknown` counts
- `strings.json` / `strings.txt`: plaintext, raw bytes, algorithm, and static evidence
- `packages.json`: decoded `AMICEVMP` package headers and relocations from the IR command

one VMP group writes its files at the output root. several groups use deterministic `group-000`, `group-001`, and later directories while shared PE and string reports stay at the root.

## support boundary

the current binary path supports x86-64 PE32+ output. the IR path supports textual `.ll`; ELF, Mach-O, object files, and binary LLVM bitcode are outside the current input contract. the decoder works on emitted structures, so the source frontend can be Rust, C, or C++.

a custom Amice VMP profile is required to decode that profile because its opcode aliases and lowering rules are not embedded in the protected program. stripped binaries still get exact wrapper and target addresses, but names erased by the linker cannot be reconstructed; imports, exports, thunk targets, and PDB symbols are used when present.

`lift.ll.txt` is a reverse-engineering aid, not rebuilt source or a full SSA decompiler. unknown profile semantics remain visible as `vm_unknown` and are counted in `lift-coverage.json`.

the source contract is pinned to Amice [`2c019b0`](https://github.com/fuqiuluo/amice/commit/2c019b01679717657e820c9220342a0a19f214a9), tagged `v0.1.5-beta.3`. format changes in a later Amice revision need to be checked against that revision's source before updating the pin.

use it on your own or otherwise authorized artifacts.

## validation

the release gate covers Rust, C, and C++, marker and markerless wrappers, one and multiple profile groups, PE and IR parity, native resolution, drag-and-drop output, and all eight tested StringEncryption algorithm/mode combinations.

the exact commands, counts, hashes, and corpus results are in [TEST_RESULTS.md](TEST_RESULTS.md).
