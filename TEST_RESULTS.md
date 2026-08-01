# test results

last full run: 2026-08-01 on Windows x86-64.

this is the local corpus behind the release gate. generated binaries and IR are not committed because the largest fixture is 38 MB. corpus tests are marked `ignored` in a clean checkout, so a missing local corpus cannot be reported as a pass.

## toolchain

| component | version |
| --- | --- |
| Amice source | `2c019b01679717657e820c9220342a0a19f214a9` (`v0.1.5-beta.3`) |
| protection pipeline | LLVM `20.1.1` |
| Rust fixture frontend | `rustc 1.87.0` / LLVM 20 |
| C and C++ fixture frontend | `clang 22.1.6`, lowered through LLVM 20.1.1 |
| devirtualizer build | `rustc 1.95.0` / LLVM 22.1.2 |

the Cargo dependency, lockfile, local Amice checkout, and protected fixtures use the same pinned Amice revision.

## release gate

```powershell
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test -- --include-ignored
cargo build --release
```

| check | result |
| --- | --- |
| formatter | clean |
| Clippy | clean, warnings denied |
| normal suite | 37 passed, 9 corpus tests ignored |
| full suite | 46 passed, 0 failed |
| release build | passed |

`target/release/amice-devirt.exe` is `2,994,176` bytes, SHA-256 `eb2c69553851eb26f5415b5d825e45833f2f1621d49b548308e234c3da1620f7`.

## VMP corpus

| fixture | groups | descriptors | VM records | valid guards | meaningful lift |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rust `stage1-vmp.ll` | 1 | 8 | 1,768 | 8/8 | 876/876 |
| Rust `stage3-vm-flatten.ll` | 1 | 8 | 1,768 | 8/8 | 876/876 |
| Rust markerless PE64 | 1 | 8 | 1,768 | 8/8 | 876/876 |
| C marker VMP IR | 1 | 1 | 38 | 1/1 | 18/18 |
| C markerless VMP IR | 1 | 1 | 38 | 1/1 | 18/18 |
| C markerless PE64 | 1 | 1 | 38 | 1/1 | 18/18 |
| C++ marker VMP IR | 1 | 1 | 38 | 1/1 | 18/18 |
| C++ markerless VMP IR | 1 | 1 | 38 | 1/1 | 18/18 |
| C++ markerless PE64 | 1 | 1 | 38 | 1/1 | 18/18 |
| C simple + ruoke PE64 | 2 | 2 | 49 | 2/2 | 17/17 |

the stage1, stage3, and PE64 Rust record signatures match exactly. the PE pass recovered all eight wrappers and all 29 native targets. no manual seed was used for the markerless PE, C, or C++ cases.

the two-profile PE contains separate simple and ruoke descriptor, bytecode, wrapper, and native-table groups. their record counts are 18 and 31. both native thunks resolve to the same original C function, and the matching multi-profile IR resolves its source name as `native_mix`.

the debug `VmVirtualize` fixture also decoded three compact descriptors and three `AMICEVMP` packages with matching instruction signatures.

## drag-and-drop smoke

the release binary was invoked with only the executable path, which is the same argument shape Windows drag and drop supplies.

| input | loaded profiles | result |
| --- | --- | --- |
| maximum Rust PE | built-in simple | 1 group, 8 descriptors, 1,768 records, strings saved |
| simple + ruoke C PE | built-in simple + adjacent ruoke | 2 groups, 2 descriptors, 49 records, group directories saved |
| simple + ruoke C PE without ruoke package | built-in simple | strings and summary saved, VMP marked failed with the unmatched table address |

the maximum sample produced `auto-summary.json`, `pe-layout.json`, string reports, descriptor reports, VM JSONL and text listings, pseudo-lift, and lift coverage beside the input. the automated corpus test checks those files and the summary totals.

## PE64 extraction

the maximum markerless executable was decoded without `--descriptor-seed`:

| recovered item | location | size |
| --- | --- | ---: |
| seed instruction | VA `0x140017369` | 64-bit immediate |
| compact bytecode | `.rdata`, RVA `0x38d20`, file `0x37720` | 23,065 bytes |
| native table | `.rdata`, RVA `0x3e740`, file `0x3d140` | 29 pointers / 232 bytes |
| descriptor table | `.rdata`, RVA `0x3e830`, file `0x3d230` | 8 rows / 512 bytes |

the recovered seed is `0xf9e60352f5b5e4ba`. descriptor guards select the table, profile decoding selects the compact blob, and executable VA checks select the native table. supplying the seed explicitly produces identical VM records.

the negative Rust PE, which has no VMP descriptors, is rejected with `no descriptor table passed guard and layout validation`.

## StringEncryption corpus

all eight algorithm/mode combinations recovered both expected strings, `hello` and `static gang`, from IR and PE:

| algorithm | mode | PE report | result |
| --- | --- | --- | --- |
| XOR | global | `plain` after optimizer folding | 2/2 exact |
| XOR | lazy | `xor` | 2/2 exact |
| XOR | stack | `plain` stack container | 2/2 exact |
| XOR | inline | `xor` | 2/2 exact |
| SIMD XOR | global | `plain` after optimizer folding | 2/2 exact |
| SIMD XOR | lazy | `simd_xor` | 2/2 exact |
| SIMD XOR | stack | `plain` stack container | 2/2 exact |
| SIMD XOR | inline | `simd_xor` | 2/2 exact |

| frontend | XOR strings | SIMD XOR strings | markerless VMP PE |
| --- | --- | --- | --- |
| C | `c deobf`, `c static gang` | both exact | 1 descriptor, 38 records |
| C++ | `cpp deobf`, `cpp static gang` | both exact | 1 descriptor, 38 records |

the C++ fixture covers quoted MSVC-mangled names and fixed-size fields with trailing NUL padding. annotation strings from `llvm.metadata` are excluded from recovered user strings.

## artifact hashes

| input | bytes | SHA-256 |
| --- | ---: | --- |
| `stage1-vmp.ll` | 9,946,574 | `dbb9f0cb7061b78bfa61fd6feb8a67cd7ff0e8d794afd9510a561b6a7734eb25` |
| `stage3-vm-flatten.ll` | 38,187,842 | `fb52ca200337e10d69b3efbb29d8aad55b03dabddb2bc14efe8e773d33e2df2e` |
| maximum Rust PE | 327,680 | `c9ad3af4554fc83eef54f7c7ce9662fa632f1c828322de5e10923b40188e31ba` |
| negative Rust PE | 296,448 | `ce0d548b163aeae088d60d11f7f87f65527dbdcd82229f3e4b7eabe49a9252f1` |
| simple + ruoke C PE | 147,456 | `99d9420d1a175445a5f572b69c4c92d7b84498375c76c7cdb43b3ebe6ca5c3fb` |
| C markerless PE | 135,680 | `031a97da1cd05ccbea1385272cf0099965d9dcf95e3bfd044fec999988b0ace1` |
| C++ markerless PE | 135,680 | `ce8b0f851b352617bf2abec569636702b44f60a2886fe6f62bc6b3f845620986` |

## fail-closed checks

the suite rejects invalid descriptor guards, out-of-range blob segments, malformed and overflowing varints, non-zero record padding, unknown opcodes, invalid operands, incomplete profile coverage, conflicting string keys, invalid package layouts, writable native-table decoys, undersized PE sections, non-PE input, binary data mislabeled as plaintext, and incomplete inline SIMD keys.
