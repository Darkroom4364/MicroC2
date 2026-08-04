# Agent dependency hygiene inventory

## Audit boundary

- **Revision:** `2c52d705466a9e07820c34389a20ae5c16e478e6` (`origin/dev`), confirmed locally with `git rev-parse HEAD`.
- **Starting state:** the dedicated detached worktree was clean at the audited revision.
- **Scope:** `agent/Cargo.toml`, the locked resolution in `agent/Cargo.lock`, `agent/build.rs`, and a static read of the local `agent/src` module graph. This is a documentation-only audit: no manifest, source, feature, target, public-module, or runtime changes are made.

## Direct Cargo manifest inventory

`agent/Cargo.toml` names 24 unique direct packages. The table covers every direct declaration; the repeated `serde_json` and `winapi` declarations are combined into their respective scope cells.

| Package (manifest constraint) | Scope(s) | Concise local evidence | Disposition |
| --- | --- | --- | --- |
| `env_logger = 0.11.8` | normal | `src/main.rs` calls `env_logger::init()`. | Retain: main-entrypoint logging. |
| `get_if_addrs = 0.5.3` | normal | `src/commands/command_shell.rs` calls `get_if_addrs()`. | Retain: active command-loop host inventory. |
| `hostname = 0.4.1` | normal | `src/commands/command_shell.rs` uses `hostname`. | Retain: active command-loop host inventory. |
| `libc = 0.2.172` | normal | `src/commands/command_shell.rs` uses Unix `libc` process-group APIs. | Retain: active Unix-gated command handling. |
| `log = 0.4.27` | normal | `main`, config, OPSEC, and command code import logging macros. | Retain: active logging. |
| `once_cell = 1.21.3` | normal | `state`, `high_threat_tools`, and command code use `Lazy`. | Retain: active state and static initialization. |
| `os_info = 3.10.0` | normal | `src/commands/command_shell.rs` uses `os_info`. | Retain: active command-loop host inventory. |
| `rand = 0.9.1` | normal | Auth, identity, OPSEC, utility, and obfuscation code call `rand::random`. | Retain: active code and public module use. |
| `reqwest = 0.12.15` (`json`, `socks`) | normal | Config and command code construct HTTP clients; upload/download modules also import it. | Retain: active C2 transport and public file paths. |
| `serde = 1.0` (`derive`) | normal | Auth, config, task, and OPSEC types derive/import serde traits. | Retain: active serialization contract. |
| `serde_json = 1.0.140` | normal; build | Source serializes protocol/config data; `build.rs` parses and emits effective config data. | Retain: active runtime and build-script use. |
| `socks5-proxy = 0.1.1` | normal | No `use socks5_proxy` import was found in `agent/src`; the exact package name is present in the manifest and lockfile. `cargo tree --locked -e normal -i socks5-proxy` has only the direct `agent` edge. | **Retain: sole static manifest candidate; removal is blocked by the proof gate below.** |
| `tokio = 1.45.0` (`rt`, `macros`, `sync`, `net`, `io-util`, `time`, `fs`) | normal | `main` uses `#[tokio::main]`; command, network, and file modules use Tokio APIs. | Retain: active async runtime and public modules. |
| `tokio-socks = 0.5.2` | normal | `src/networking/socks5.rs` imports `tokio_socks::tcp::Socks5Stream`. | Retain: source-referenced public SOCKS module. |
| `zeroize = 1.8.1` | normal | Auth, dormant state, OPSEC, and command code use `Zeroize`/`Zeroizing`. | Retain: active secret and state handling. |
| `chrono = 0.4.41` | normal | OPSEC and command code use timestamps, dates, and times. | Retain: active timing/protocol fields. |
| `sysinfo = 0.35.0` | normal | OPSEC and Windows-gated startup code query process/system state. | Retain: active and platform-gated code. |
| `winapi = 0.3.9` | normal (`wtsapi32`, `sysinfoapi`); `cfg(windows)` (`winuser`, `libloaderapi`, `jobapi2`, `handleapi`, `fileapi`, `winbase`, `dpapi`, `wincrypt`) | Windows-gated auth, OPSEC, and `win_api_hiding` paths import its APIs. | Retain: target-specific surface has no native-Windows proof in this audit. |
| `obfstr = 0.4.4` | normal | Config, high-threat lists, Windows startup, and Windows API hiding use `obfstr!`. | Retain: active and Windows-gated source use. |
| `aes-gcm = 0.10.3` | normal | `src/dormant.rs` uses `Aes256Gcm`; `state` supplies its memory protector to active OPSEC code. | Retain: main-reachable state protection. |
| `base64 = 0.22.1` | normal | Auth and identity encode/decode credentials and identifiers. | Retain: active protocol handling. |
| `rand_core = 0.6.4` (`std`) | normal | No direct source import was found. The locked graph has a direct `agent -> rand_core@0.6.4` edge and another `aes-gcm -> crypto-common -> rand_core@0.6.4` path; it also contains `rand_core@0.9.5` through `rand`. | Retain: do not alter a direct declaration while feature/transitive and cross-target resolution remain unproven. |
| `bincode = 1.3` | normal | `src/dormant.rs` serializes/deserializes protected OPSEC state. | Retain: main-reachable state protection. |
| `url = 2.5.4` | build | `build.rs` imports `url::Url` to validate build inputs. | Retain: active build-script validation. |

## Static module classification

This is a local source walk, not a whole-program reachability proof. “Main-entrypoint-reached” means reachable from the `src/main.rs` calls inspected here; public `rlib`/`cdylib` consumers can reach library exports without appearing in that binary entrypoint.

| Classification | Local static observation | Audit treatment |
| --- | --- | --- |
| Active main-entrypoint path | `main` directly uses config, identity, auth, OPSEC, and `commands::command_shell`. Their local references include tasks, utility code, `networking::egress`, high-threat lists, and `state -> dormant` memory protection. | Retain associated dependencies and source. `dormant.rs` is named “dormant” but is source-referenced through active state/OPSEC code. |
| Source-referenced public module not reached from `main` | `networking::socks5_pivot_server` imports `networking::socks5_pivot`; both remain public through the library module graph, but no `main` call was found. | Retain: an internal non-entrypoint reference and public export are not deletion evidence. |
| Observed dormant public paths | No direct `main` call was found for `commands::obfuscated`, `file_handling::{download, upload}`, `networking::socks5`, or `networking::socks5_pivot_server`. Some compile and/or run under the local test suite; this category means only “not reached by the inspected production entrypoint,” not “unused.” | Retain all public modules and their dependencies. No source deletion is justified. |
| Target-conditioned paths not observed locally | `dormant_startup`, `win_api_hiding`, and Windows `winapi` uses are behind Windows configuration. | Retain: local macOS evidence cannot establish native-Windows behavior. |

### Retained manifest surfaces

| Surface | Local observation | Disposition |
| --- | --- | --- |
| `default = []` | Declared Cargo feature surface. | Retain unchanged. |
| `dll = []` | Declared Cargo feature surface; this static scan found no local `cfg(feature = "dll")` use. | Retain as a public manifest contract; absence of a local branch is not proof that consumers do not select it. |
| `crate-type = ["cdylib", "rlib"]` | The package exports a library as well as the binary entrypoint. | Retain: external library consumers are outside this static walk. |
| `cfg(windows)` `winapi` feature addendum | Supports Windows-gated source paths named above. | Retain until native-Windows evidence exists. |

## `socks5-proxy` candidate and exact future proof gate

`socks5-proxy` is the only static manifest candidate observed in this audit. It is **not approved for removal**.

A future change may remove it only after an isolated, otherwise-identical manifest trial (removing only that direct declaration) satisfies **all** of the following:

1. Static source/package review still finds no `socks5_proxy` import or package reference, and the locked resolved graph contains no required `socks5-proxy` edge.
2. On **Linux**, the trial passes `cd agent && cargo test --locked --all-features` and `cd agent && cargo build --locked --release --all-features`.
3. On **native Windows** (not a cross-compile), the same two `cd agent && cargo …` commands pass with the same public feature surface.
4. The existing SOCKS configuration tests and the public `rlib`/`cdylib` build surface remain successful in those trials.

The local macOS result below does not meet steps 2 or 3, so the package remains retained. `rand_core`, `tokio-socks`, all public modules, both feature flags, and target-specific dependencies also remain retained; this audit does not remove or feature-gate any of them.

## Local commands and measured results

All Cargo build/test targets below were isolated under `/tmp` except the formatter. Every Cargo command ran from the agent manifest directory, shown as `cd agent && …`. The mutation script was run from that directory with its temporary `target` path symlinked to `/tmp/microc2-issue79-audit-determinism-target` and removed afterward.

| Command | Actual local result |
| --- | --- |
| `cd <worktree> && git rev-parse HEAD` | `2c52d705466a9e07820c34389a20ae5c16e478e6` |
| `cd agent && rustc -vV` | `rustc 1.97.1 (8bab26f4f 2026-07-14)`; host `aarch64-apple-darwin`; LLVM `22.1.6`. |
| `cd agent && cargo --version` | `cargo 1.97.1 (c980f4866 2026-06-30)`. |
| `cd agent && uname -srm` | `Darwin 25.5.0 arm64`. |
| `cd agent && shasum -a 256 Cargo.lock` | `e7d2b6fff722e7ccbee5457984cc2436a8c5028067decd90c238b5133d52c6a8` for the locked `Cargo.lock`. |
| `cd agent && cargo tree --locked --depth 1` | Reported 23 normal direct roots plus build-dependency roots `serde_json` and `url`; duplicate direct-package names are merged in the inventory table. |
| `cd agent && cargo tree --locked -e normal -i socks5-proxy` | `socks5-proxy v0.1.1` with the sole reverse path `agent v0.1.0`. |
| `cd agent && cargo tree --locked -e normal -i rand_core@0.6.4` | Reported both a direct `agent` edge and an `aes-gcm -> crypto-common -> rand_core@0.6.4` path. A first unqualified `-i rand_core` query was ambiguous because the lock contains `0.6.4` and `0.9.5`; explicit-version queries resolved that query ambiguity. |
| `cd agent && cargo fmt --check` | Passed; no output. |
| `cd agent && env CARGO_TARGET_DIR=/tmp/microc2-issue79-audit-tests cargo test --locked` | Passed: 81 unit tests passed, 0 failed; main and doc-test targets contained 0 tests. |
| `cd agent && env CARGO_TARGET_DIR=/tmp/microc2-issue79-audit-clippy cargo clippy --locked --all-targets` | Passed with exit 0; emitted 10 warnings on the audited revision. They were not changed because this audit is dependency/dormant-code hygiene only. |
| `cd agent && env CARGO_TARGET_DIR=/tmp/microc2-issue79-audit-build cargo build --locked` | Passed; emitted the audited revision’s non-fatal compiler warnings. |
| `cd agent && ./check_mutation_determinism.sh` | Passed its variation assertions: repeated runs with the same mutation seed produced matching generated source and binary, and its second seed produced different outputs. The script randomizes `MICROC2_BUILD_NONCE` for each build, so this is **not** same-input reproducibility or seed-only-causality evidence. |
| `cd agent && env CARGO_TARGET_DIR=/tmp/microc2-issue79-audit-release cargo build --locked --release` | Passed; produced the provenance-incomplete observed baseline below. |

### Release artifact measurement

The earlier release command above produced `/tmp/microc2-issue79-audit-release/release/agent`:

- Size: **1,813,280 bytes**
- SHA-256: `f1d533369e00fa76fa5627e1af01e6c36f0fe4a837363913ba256d24cad4c1ed`

This is a **non-reproducible observed local baseline**, not a reproducibility claim: its build-input provenance was not explicitly controlled. It also is not a before/after footprint comparison.

### Controlled release-build provenance and comparison

`build.rs` consumes the following environment inputs. The fixed non-secret values and every forced-unset/defaulted input used for the two controlled release builds are recorded below; no credential or external configuration value was passed or recorded.

| `build.rs` input name(s) | Status in both controlled builds |
| --- | --- |
| `MICROC2_BUILD_NONCE` | Fixed to `issue79-audit-nonce` (non-secret). |
| `MUTATION_SEED` | Fixed to `0123456789abcdef` (non-secret). |
| `LISTENER_HOST`, `LISTENER_PORT`, `SERVER_URL`, `LISTENER_ID`, `PAYLOAD_ID` | Forced unset. |
| `ENROLLMENT_CREDENTIAL` | Forced unset; no sensitive value was passed or recorded. |
| `EFFECTIVE_CONFIG_PATH` | Forced unset. |
| `SLEEP_INTERVAL`, `JITTER`, `PROTOCOL`, `SOCKS5_ENABLED`, `SOCKS5_HOST`, `SOCKS5_PORT`, `ALLOW_INVALID_CERTS`, `ALLOW_INSECURE_ISOLATED_LAB`, `BASE_MAX_C2_FAILS`, `C2_THRESH_INC_FACTOR`, `C2_THRESH_DEC_FACTOR`, `C2_THRESH_ADJ_INTERVAL`, `C2_THRESH_MAX_MULT`, `PROC_SCAN_INTERVAL_SECS`, `BASE_SCORE_THRESHOLD_BG_TO_REDUCED`, `BASE_SCORE_THRESHOLD_REDUCED_TO_FULL`, `MIN_FULL_OPSEC_SECS`, `MIN_REDUCED_OPSEC_SECS`, `MIN_BG_OPSEC_SECS`, `REDUCED_ACTIVITY_SLEEP_SECS` | Defaulted by `build.rs` (explicitly absent). |
| `OUT_DIR` | Cargo-provided. |

The command below was executed from the audit-worktree root. It unsets every `build.rs` input that must be absent/defaulted, fixes the two non-secret inputs, isolates the target, and also removes inherited Rust/Cargo flag controls. It is an executable reproduction form for this local experiment:

```sh
build_controlled_release() {
  target_dir=$1
  (
    cd agent &&
    env \
      -u LISTENER_HOST \
      -u LISTENER_PORT \
      -u SERVER_URL \
      -u LISTENER_ID \
      -u PAYLOAD_ID \
      -u ENROLLMENT_CREDENTIAL \
      -u EFFECTIVE_CONFIG_PATH \
      -u SLEEP_INTERVAL \
      -u JITTER \
      -u PROTOCOL \
      -u SOCKS5_ENABLED \
      -u SOCKS5_HOST \
      -u SOCKS5_PORT \
      -u ALLOW_INVALID_CERTS \
      -u ALLOW_INSECURE_ISOLATED_LAB \
      -u BASE_MAX_C2_FAILS \
      -u C2_THRESH_INC_FACTOR \
      -u C2_THRESH_DEC_FACTOR \
      -u C2_THRESH_ADJ_INTERVAL \
      -u C2_THRESH_MAX_MULT \
      -u PROC_SCAN_INTERVAL_SECS \
      -u BASE_SCORE_THRESHOLD_BG_TO_REDUCED \
      -u BASE_SCORE_THRESHOLD_REDUCED_TO_FULL \
      -u MIN_FULL_OPSEC_SECS \
      -u MIN_REDUCED_OPSEC_SECS \
      -u MIN_BG_OPSEC_SECS \
      -u REDUCED_ACTIVITY_SLEEP_SECS \
      -u RUSTFLAGS \
      -u CARGO_ENCODED_RUSTFLAGS \
      -u CARGO_BUILD_TARGET \
      CARGO_INCREMENTAL=0 \
      SOURCE_DATE_EPOCH=0 \
      MICROC2_BUILD_NONCE=issue79-audit-nonce \
      MUTATION_SEED=0123456789abcdef \
      CARGO_TARGET_DIR="$target_dir" \
      cargo build --locked --release
  )
}

build_controlled_release /tmp/microc2-issue79-audit-controlled-release-c
build_controlled_release /tmp/microc2-issue79-audit-controlled-release-d
```

With the production-input gate variables and `ENROLLMENT_CREDENTIAL` forced unset, the build used `build.rs`’s fallback configuration path.

| Controlled build | Artifact size | SHA-256 | Result |
| --- | ---: | --- | --- |
| C | 1,813,280 bytes | `b82d1ac881563445a509b9741a7035d57db32d9879a6994fb9842cc46d4002da` | Passed. |
| D | 1,813,280 bytes | `b82d1ac881563445a509b9741a7035d57db32d9879a6994fb9842cc46d4002da` | Passed; byte-identical to C. |

This establishes matching bytes only for this controlled same-host, same-toolchain experiment. It does not establish cross-host, cross-target, production-input, or seed-only reproducibility.

## Limits

- Only the local native `aarch64-apple-darwin` target was built and tested. No Linux build/test and no native-Windows build/test were run or claimed.
- The controlled release pair fixes only the listed non-secret `build.rs` inputs on this host. It does not prove reproducibility for production inputs, other toolchains, or other targets.
- This static inventory does not prove the absence of external `rlib`/`cdylib` consumers, conditional-target consumers, or runtime paths not exercised by the local tests.
- No before/after artifact-size comparison applies: the only worktree change is this documentation file. Both recorded artifacts are baselines, not proof of a footprint reduction.
- The Clippy and compiler warnings were observed but are outside the requested no-source-change scope.
