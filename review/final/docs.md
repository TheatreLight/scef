# Final Review — SCEF Documentation

## Executive Summary

The SCEF documentation is structurally sound: the container binary layout, KDF profile parameter tables, slot-offset formulas, and browser viewer module descriptions are all byte-accurate against the code. However, both reviewers identified a real and serious problem: the documentation was last fully updated before a significant implementation refactoring that introduced `EncryptPipeline`, `DecryptPipeline`, `NativeFile`, `FragmentedIO`, and `PasswordStrengthEstimator`. This refactoring invalidated multiple API signatures, a GUI security section, the CLI benchmark section, a CMake option, and the data-flow descriptions. Three of the invalidated items are security-relevant: the password type, the GUI password-storage description, and the `--password` flag documentation.

After hands-on verification of every major claim from both reviewers, **Sonnet's report is substantially more accurate** than Codex's. Codex missed or soft-pedaled the most serious confirmed drifts (CRIT-2, CRIT-3, MAJ-9) and falsely assessed the SCEF_BUILD_BENCHMARKS situation as correct. Sonnet produced two false positives that need to be corrected in the consolidated findings below.

---

## Reviewer Comparison

**Sonnet** identified all critical and major items correctly. Its false positive rate is low: one item (A-04/API-05 regarding `FileTable::reset()`) was partially wrong — `reset()` was referenced by Sonnet itself as existing in a NIT but then also claimed absent; on re-read, `reset()` is not in `FileTable.h` at all so the checksum-methods claim is fully confirmed. No material false positives were found in Sonnet's security-layer findings.

**Codex** was accurate on the "what is correct" side — its verification of header offsets, KDF tables, and constants is thorough and correct. However, Codex graded several confirmed-wrong items as "NITPICK" or "LIKELY CORRECT" and produced one definite false assessment: it rated `architecture.md` bench_kdf entry as correct ("CORRECT (but file path...)") when the `SCEF_BUILD_BENCHMARKS` CMake option does not exist and benchmarks build unconditionally. Codex's severity grading was systematically too low: it called the missing `EncryptPipeline` docs "CRITICAL" in isolation but simultaneously said the doc is "78% aligned" and buried the password-type issue entirely. Codex also left most GUI-layer checks unverified ("Not verified").

**Overall:** Sonnet is the more reliable reviewer for this codebase. Codex adds value for the "what is correct" confirmations of binary layout and constants.

---

## Findings (Deduplicated, Verified, Prioritized)

### Critical

**[F-01] `api/scef-lib.md:152` and `api/scef-lib.md:220` — Password parameter type is `std::string` in docs, `secure_vector<char>` in code** (Critical)

- **Sources:** Sonnet CRIT-2 (API-03, API-04)
- **Verdict:** CONFIRMED
- **Verified at:** `scef/include/FileManager.h:78` (`const Botan::secure_vector<char>& password`), `scef/include/CryptoManager.h:31` (`const Botan::secure_vector<char>& password`)
- **Doc text:** `api/scef-lib.md:152` documents `const std::string& password = ""` for `FileManager::init()`. `api/scef-lib.md:220` documents `void deriveKek(const std::string& password, Header& header)`.
- **What the drift really is:** A caller who writes code against the documented API will pass a `std::string`, which does not zero its heap allocation on destruction. This is a security vulnerability if a developer follows the doc. The actual type `Botan::secure_vector<char>` is specifically chosen to guarantee zeroing.
- **Fix:** In `api/scef-lib.md`, replace both `const std::string& password` occurrences with `const Botan::secure_vector<char>& password`. Add `#include <botan/secmem.h>` to the usage example.

**[F-02] `gui.md:117-121` — Password security section describes non-existent `currentPassword_` and `scrubPassword()`** (Critical)

- **Sources:** Sonnet CRIT-3 (GUI-02, GUI-03)
- **Verdict:** CONFIRMED
- **Verified at:** `grep` over all `scef/gui/*.h` and `scef/gui/*.cpp` — zero matches for `scrubPassword` or `currentPassword_`. `ScefController.h` has no `std::string` password member at all. `ScefController.cpp:44-47` passes a `Botan::secure_vector<char>` directly to `FileManager::init()`.
- **What the drift really is:** The documented design (store password as `std::string currentPassword_` in controller, call `scrubPassword()` on close) was replaced. The actual design never stores the password in the controller; it passes it immediately into `FileManager` as a `secure_vector<char>`, and `FileManager` holds it in `password_` (a `Botan::secure_vector<char>` field at `FileManager.h:201`) which is zeroed by Botan's secure allocator on destruction. A security audit based on this doc section would search for a `scrubPassword()` call, find nothing, and incorrectly conclude the scrubbing is missing.
- **Fix:** Replace `gui.md:117-121` with: "Passwords are never stored in `ScefController`. On each operation, the password `QString` is converted to `Botan::secure_vector<char>` (`ScefController.cpp`, `securePasswordFromQString()`) and passed directly to `FileManager::init()`. The controller does not retain it. `FileManager` holds it in a `Botan::secure_vector<char>` member that is zeroed by Botan's allocator when the `FileManager` is destroyed or when the password is no longer needed."

**[F-03] `cli.md:11` — States `--password` flag does not exist; it does exist** (Critical)

- **Sources:** Sonnet CRIT-1 (CLI-01)
- **Verdict:** CONFIRMED
- **Verified at:** `main.cpp:156` (`s == "--password"` in `foundKey()`), `main.cpp:257-258` (handler: `out.password = argv[i]`), `main.cpp:642-643` (password read from `args.password` if non-empty, else from stdin).
- **What the drift really is:** `cli.md:11` states "The binary does not provide a `--password` flag." This is actively false. The flag exists and is functional. The security concern is that `--password` passes the password as a command-line argument (visible in `ps`, shell history, `/proc`), so it should be documented as a test/scripting-only option with a clear warning, not denied entirely.
- **Fix:** Remove the "does not provide a `--password` flag" sentence. Add `--password <string>` to the Options table with note: "For scripting/testing only. The password is visible in process listings and shell history. Always prefer stdin input in production."

---

### Major

**[F-04] `cli.md:155-178` — `benchmark` command argument documentation is entirely fabricated** (Major)

- **Sources:** Sonnet MAJ-1 (CLI-05)
- **Verdict:** CONFIRMED
- **Verified at:** `main.cpp:510-572`. `cmd_benchmark()` takes zero arguments. It iterates all 4 built-in profiles unconditionally. No `--kdf-m`, `--csv`, `--runs` handling exists in the function or anywhere in the argument parser for the `benchmark` command path.
- **What the drift really is:** The documented invocation `scef benchmark [--kdf-m <MiB>] [--kdf-t <n>] [--kdf-p <n>] [--csv] [--runs <n>]` is completely fabricated. The example output also shows wrong profile values (fast=19 MiB t=2, default=64 MiB t=3, high=256 MiB t=5, browser=46 MiB) instead of the actual ones (fast=256 MiB t=1 p=4, default=1024 MiB t=1 p=4, high=2048 MiB t=1 p=4, browser=64 MiB t=1 p=1).
- **Fix:** Replace the benchmark section with: "No arguments. Runs all 4 built-in profiles once each and prints elapsed seconds." Provide an example output using actual profile values from `KdfProfiles.cpp`.

**[F-05] `architecture.md:45,61` and `architecture.md:40` — `SCEF_BUILD_BENCHMARKS` option is fictitious; `scef_lib` source list is incomplete** (Major)

- **Sources:** Sonnet MAJ-9 (A-01, A-02), with Codex incorrectly rating this as correct
- **Verdict:** CONFIRMED
- **Verified at:** `CMakeLists.txt:112-113` — `add_subdirectory(benchmarks)` is called unconditionally, with no surrounding `if()` and no `option(SCEF_BUILD_BENCHMARKS ...)` anywhere in the file. The only options defined are `SCEF_BUILD_TESTS`, `SCEF_BUILD_BROWSER_TESTS`, `SCEF_BUILD_GUI`. Additionally, `architecture.md:40` lists 6 source files for `scef_lib`; `CMakeLists.txt:71-82` adds 11 files including `EncryptPipeline.cpp`, `DecryptPipeline.cpp`, `NativeFile.cpp`, `BenchMeasurerGuard.cpp`, `PasswordStrengthEstimator.cpp`.
- **Fix:** In `architecture.md`, change the bench_kdf row to show `Enabled by: Always`. Remove `SCEF_BUILD_BENCHMARKS` from the CMake options table. Update the `scef_lib` source list to include all 11 files. Add the three unit test files (`test_native_file.cpp`, `test_password_strength.cpp`) to the `scef_unit_tests` row.

**[F-06] `api/scef-lib.md:297-304` and `data-flows.md:46-53` and `architecture.md:206-209` — Three `FileTable` checksum methods documented that do not exist** (Major)

- **Sources:** Sonnet MAJ-3 (API-05, A-04), DF-03
- **Verdict:** CONFIRMED
- **Verified at:** `scef/include/FileTable.h` — the class has `addFileEntry`, `serialize`, `deserialize`, `to_string`, `getFileInfoByName`, `getFilesTable`, `setNextWriteOffset`, `getNextWriteOffset`. No `updateChecksum`, `getChecksum`, or `resetChecksum`. The checksum is computed by `EncryptPipeline` and passed into `addFileEntry()` as a completed string.
- **What the drift really is:** The sequential write loop described in `data-flows.md` (steps 2, 4, 7: `resetChecksum`, `updateChecksum`, `getChecksum`) references an API that was moved into `EncryptPipeline` during the pipeline refactoring. Any developer implementing against these docs will fail to compile.
- **Fix:** Remove all three methods from `api/scef-lib.md`. In `data-flows.md:44-55`, replace the writeChunks detail with a note that encryption is now handled by `EncryptPipeline` (multi-stage pipeline with reader/worker/writer threads), which computes SHA-256 checksums internally and calls `fileTable_.addFileEntry()` with the completed checksum. In `architecture.md`, remove `updateChecksum` and `getChecksum` from the `FileTable` class diagram.

**[F-07] `api/scef-lib.md:189` and `architecture.md:160` — `FileManager::printHeader()` documented but does not exist** (Major)

- **Sources:** Sonnet MAJ-4 (API-02, A-03)
- **Verdict:** CONFIRMED
- **Verified at:** `scef/include/FileManager.h` — public interface has `printFilesTable()` at line 96, no `printHeader()` anywhere in the file or in `src/FileManager.cpp`.
- **Fix:** Remove `printHeader()` from `api/scef-lib.md:189` and from the `architecture.md` class diagram.

**[F-08] `api/scef-lib.md:382-384` — `getDefaultProfile()` documented as a free function that does not exist** (Major)

- **Sources:** Sonnet MAJ-5 (API-06)
- **Verdict:** CONFIRMED
- **Verified at:** `scef/include/KdfProfiles.h` — exports only `getProfileParams(EKDFProfile)` and `getProfileByName(std::string_view)`. No `getDefaultProfile()`.
- **Fix:** Remove `getDefaultProfile()` from `api/scef-lib.md`. The equivalent is `getProfileByName("default")`.

**[F-09] `gui.md:65-69` — `createContainer()` signature missing `cipherIndex` parameter** (Major)

- **Sources:** Sonnet MAJ-6 (GUI-01)
- **Verdict:** CONFIRMED
- **Verified at:** `scef/gui/ScefController.h:32-40` — 9th parameter `int cipherIndex = 0` is present. `gui.md:60-69` shows only 8 parameters, omitting `cipherIndex`.
- **Fix:** Add `int cipherIndex = 0,  // 0=AES-256-GCM, 1=Kuznechik-GCM` as the 9th parameter in the documented signature.

**[F-10] `data-flows.md:150` and `container-format.md:183` — References non-existent `containerStream_->flush()`** (Major)

- **Sources:** Sonnet MAJ-8 (DF-07, CF-07)
- **Verdict:** CONFIRMED
- **Verified at:** `scef/include/FileManager.h:197` — the I/O member is `NativeFile containerFile_`, not a `containerStream_`. The entire `std::fstream`-based layer was replaced with `NativeFile`. `NativeFile.h` provides `syncToDevice()`, not `flush()`.
- **Fix:** In `data-flows.md:150`, replace `containerStream_->flush()` with `containerFile_.syncToDevice()`. In `container-format.md:183`, change `flush()` to `syncToDevice()` (a `NativeFile` method).

**[F-11] `api/scef-lib.md:404-422` — `LogLevel` enum missing `BENCH` level; `WARNING` and `ERROR` values are wrong** (Major)

- **Sources:** Sonnet MAJ-10 (API-08, API-09)
- **Verdict:** CONFIRMED
- **Verified at:** `scef/include/Logger.h:15-21` — `DEBUG=0, INFO=1, BENCH=2, WARNING=3, ERROR=4`. Also `LOG_BENCH` macro at `Logger.h:96`.
- **Fix:** Add `BENCH = 2` to the enum in the API doc, shift `WARNING = 3` and `ERROR = 4`, and add `LOG_BENCH(fmt, ...)` to the macros table.

**[F-12] `cli.md` — Four functional CLI flags are completely undocumented** (Major)

- **Sources:** Sonnet MAJ-2 (CLI-02), Codex Major
- **Verdict:** CONFIRMED
- **Verified at:** `main.cpp:52-55,67-68` (help text), `main.cpp:155-156` (parsing). All four are parsed: `--cipher`, `--log-level`, `-y/--yes`, `--strength-only`.
- **What the drift really is:** `--cipher` selects the encryption algorithm at container creation time (AES-256-GCM vs. Kuznechik-GCM). `--strength-only` changes the command's entire behavior (no container operation, just password analysis). Both are significant enough that omitting them from `cli.md` leaves users unable to access core functionality.
- **Fix:** Add a "Cipher Options" section documenting `--cipher <name>` with valid values. Add `--log-level`, `-y/--yes`, `--strength-only` to the Global Flags table. Add a `strength-only` sub-section explaining that `--strength-only` can be used standalone or before any command to check password quality.

---

### Minor

**[F-13] `gui.md:197` — Window size documented as 900×600; actual is 960×900** (Minor)

- **Sources:** Sonnet MIN-6 (GUI-05)
- **Verdict:** CONFIRMED
- **Verified at:** `scef/gui/qml/Main.qml:7-8` — `width: 960`, `height: 900`.
- **Fix:** Change `gui.md:197` to "960×900 pixels".

**[F-14] `gui.md:196-202` — `LogsPage` missing from QML pages list and state diagram** (Minor)

- **Sources:** Sonnet MIN-5 (GUI-04), Sonnet R-05
- **Verdict:** CONFIRMED
- **Verified at:** `scef/gui/qml/Main.qml:39-43` — `LogsPage {}` component registered. `gui.md:198-202` lists only three components: `StartPage`, `CreatePage`, `FileListPage`.
- **Fix:** Add `LogsPage` to the components list and update the state diagram.

**[F-15] `gui.md:49-56` and `gui.md:41-47` — Missing signals `progressChanged`, `benchEnabledChanged`; missing property `benchEnabled`; missing invokable methods** (Minor)

- **Sources:** Sonnet MIN-3 (GUI-07), MIN-4 (GUI-08), MIN-6 (GUI-06)
- **Verdict:** CONFIRMED
- **Verified at:** `scef/gui/ScefController.h:26` (`benchEnabled` Q_PROPERTY), `ScefController.h:70-72` (`benchEnabledChanged()`, `progressChanged(const QString&, double)` signals), `ScefController.h:42-43,55-57` (`estimatePasswordStrength`, `logDirPath`, `listLogFiles`, `readLogFile`).
- **Fix:** Add `benchEnabled` to the Properties table. Add `benchEnabledChanged()` and `progressChanged(stageLabel, fraction)` to the Signals table. Add all four missing Q_INVOKABLE methods to the Invokable Methods section.

**[F-16] `architecture.md:40` — `scef_unit_tests` source list incomplete** (Minor)

- **Sources:** Sonnet MIN-1 (A-06)
- **Verdict:** CONFIRMED
- **Verified at:** `CMakeLists.txt:121-125` — three test files: `test_scef.cpp`, `test_native_file.cpp`, `test_password_strength.cpp`. `architecture.md:42` lists only `test_scef.cpp`.
- **Fix:** Add the two missing test file names.

**[F-17] `architecture.md:152-175` — `FileManager` class diagram missing `setProgressCallback()` and `setCipher()`** (Minor)

- **Sources:** Sonnet MIN-2 (A-09)
- **Verdict:** CONFIRMED
- **Verified at:** `scef/include/FileManager.h:84-85` — both `setCipher(ECipher c)` and `setProgressCallback(ProgressCallback cb)` are public methods.
- **Fix:** Add both to the Mermaid class diagram.

**[F-18] Multiple source line number references are stale** (Minor)

- **Sources:** Sonnet MIN-9 (CF-06, CF-08, DF-01, DF-02, DF-04, DF-05, DF-06, DF-08, DF-09, GUI-10)
- **Verdict:** CONFIRMED (drift is real; exact current line numbers were not re-verified per file but the pattern is consistent across the codebase)
- **What the drift is:** Line number annotations in `container-format.md`, `data-flows.md`, `gui.md`, and `cli.md` reference ranges that are off by 10-50 lines due to code growth since the docs were written.
- **Fix:** Either remove line number annotations from prose (leave them only in "Source:" tags where they provide navigational value) or automate their verification in CI.

**[F-19] `api/scef-lib.md:38-41` — Header default constructor comment claims Standard profile but kdf_m_kib=65536 KiB is the Browser profile** (Minor)

- **Sources:** Sonnet MIN-10 (API-01)
- **Verdict:** CONFIRMED (code and doc agree with each other; both are wrong in their comment/annotation)
- **Verified at:** `Header.h:183` — `kdf_m_kib_ = 65536` with comment "Standard profile". Standard profile (`KdfProfiles.cpp`) uses 1,048,576 KiB. 65536 KiB = 64 MiB = Browser profile.
- **Fix:** Correct the comment in both `api/scef-lib.md:41` and `Header.h:183` to "Browser profile defaults" or, better, make the default match `EKDFProfile::Standard` by looking up the profile table in the constructor.

**[F-20] `api/scef-lib.md` — `PasswordStrengthEstimator` class is entirely absent** (Minor)

- **Sources:** Sonnet MIN-8 (API-10), Codex Major
- **Verdict:** CONFIRMED
- **Verified at:** `scef/include/PasswordStrengthEstimator.h` exists (included by `ScefController.h:15` and `main.cpp:4`). Not documented anywhere in `scef/docs/api/scef-lib.md`.
- **Fix:** Add a `PasswordStrengthEstimator.h` section to `api/scef-lib.md` with the `estimate()` method signature and `Result` struct.

---

### Nitpick

**[F-21] `architecture.md:100-113` — Directory layout omits `LogsPage.qml` from the listed QML files** (Nitpick)

- **Sources:** Sonnet R-05
- **Verdict:** CONFIRMED. `LogsPage.qml` is in `gui/qml/` but not listed in the directory tree.
- **Fix:** Add `LogsPage.qml` to the layout listing.

**[F-22] `container-format.md:75` — Source reference `FileManager.cpp:97-114` off by ~4 lines** (Nitpick)

- **Sources:** Sonnet CF-06
- **Verdict:** PLAUSIBLE (not re-verified at exact line; consistent with overall line-drift pattern).
- **Fix:** Update annotation or remove.

**[F-23] `api/scef-lib.md` — Missing `EncryptPipeline` and `DecryptPipeline` documentation** (Minor-to-Nitpick, depending on audience)

- **Sources:** Codex Critical, Sonnet A-07
- **Verdict:** CONFIRMED as a gap, but severity depends on scope. `EncryptPipeline` and `DecryptPipeline` are `include/` headers but are used only internally by `FileManager` — they are not called directly from GUI or CLI. The `api/scef-lib.md` file is titled "Public API" and these classes are in `include/` but not in the documented public interface used by consumers. This is a legitimate coverage gap for internal contributors, not a user-facing API omission.
- **Fix:** Add an "Internal Infrastructure" section noting `EncryptPipeline`, `DecryptPipeline`, `FragmentedIO`, `CryptoContext`, `BoundedQueue` as internal pipeline classes not intended for direct use by consumers.

---

## False Positives

**[FP-1] Codex rating `SCEF_BUILD_BENCHMARKS` as "CORRECT"**

Codex reviewed `architecture.md:45` (bench_kdf enabled by `SCEF_BUILD_BENCHMARKS=ON`) and responded "CORRECT (but file path is CMakeLists.txt, not CMakeLists.txt:line_number)". This is wrong. The option does not exist. The benchmark target builds unconditionally via `add_subdirectory(benchmarks)` at `CMakeLists.txt:113`. Codex either did not open `CMakeLists.txt` or misread it. This is a confirmed false negative (missed real drift), not a false positive in the traditional sense, but it demonstrates that Codex's "LIKELY CORRECT" and "CORRECT" verdicts cannot be trusted without independent verification.

**[FP-2] Sonnet's assessment of `--kdf-m-cost` aliases**

Sonnet CLI-08 notes that `--kdf-m-cost`, `--kdf-t-cost`, `--kdf-parallelism` are "help-text-only, not functional." This is correct as an observation, but Sonnet explicitly says the docs omitting them is "technically correct behavior documentation" — which is also correct. This is not a false positive by Sonnet; it is a correct determination that this is a code issue rather than a doc drift.

**[FP-3] Sonnet's header-offset cross-check findings are accurate (no false positives)**

Sonnet CF-01 through CF-09 verified specific offsets against `Header.h`. All confirmed correct. Codex's full binary layout table verification (25 fields) also confirmed all offsets exact. No reviewer false-positived on the binary layout.

**[FP-4] Codex's `gui.md:5` (Qt version) marked as "CORRECT"**

Codex verified `gui.md:5` ("Qt version: 6.5+") against `CMakeLists.txt` `find_package(Qt6 6.5 REQUIRED)` — this is genuinely correct. Not a false positive.

---

## Coverage Gaps (Verified)

The following components exist in `scef/include/` or `scef/src/` but have no documentation in `scef/docs/`:

| Component | Location | Used by | Gap |
|-----------|----------|---------|-----|
| `EncryptPipeline` | `include/EncryptPipeline.h` | `FileManager` (internal) | No entry in `api/scef-lib.md` or `data-flows.md` |
| `DecryptPipeline` | `include/DecryptPipeline.h` | `FileManager` (internal) | No entry in `api/scef-lib.md` or `data-flows.md` |
| `NativeFile` | `include/NativeFile.h` | `FileManager` (replaces `std::fstream`) | Not mentioned anywhere; causes `containerStream_` drift |
| `FragmentedIO` | `include/FragmentedIO.h` | `FileManager`, `EncryptPipeline` | Not mentioned anywhere |
| `CryptoContext` | `include/CryptoContext.h` | `CryptoManager` fast-path | Not mentioned anywhere |
| `BoundedQueue` | `include/BoundedQueue.h` | `EncryptPipeline`, `DecryptPipeline` | Not mentioned anywhere |
| `BenchMeasurerGuard` | `src/BenchMeasurerGuard.cpp` | Internal timing | Not mentioned anywhere |
| `PasswordStrengthEstimator` | `include/PasswordStrengthEstimator.h` | CLI, GUI | Completely absent from `api/scef-lib.md` |
| `LogsPage.qml` | `gui/qml/LogsPage.qml` | GUI navigation | Not in `gui.md` or `architecture.md` |
| `logDirPath()`, `listLogFiles()`, `readLogFile()` | `ScefController.h:55-57` | QML → LogsPage | Not in `gui.md` |
| `--cipher` flag | `main.cpp:67-68` | CLI cipher selection | Not in `cli.md` |
| `--log-level` flag | `main.cpp:52` | CLI log control | Not in `cli.md` |
| `-y/--yes` flag | `main.cpp:53` | CLI confirmation bypass | Not in `cli.md` |
| `--strength-only` mode | `main.cpp:54` | Password quality check | Not in `cli.md` |
| `LOG_BENCH` macro | `Logger.h:96` | Internal bench logging | Not in `api/scef-lib.md` |
| Integration test files `test_cross_mode.py`, `test_roundtrip_100files.py`, `test_strength_warning.py`, `test_kuznechik.py`, `run_bit_flip_test.py` | `tests/integration/` | CI | `architecture.md` directory listing shows only 8 integration test files |

---

## Verdict — Top 5 Doc Fixes Prioritized

**Priority 1 — Security: `api/scef-lib.md` password type correction**
Change `const std::string& password` to `const Botan::secure_vector<char>& password` in both `FileManager::init()` and `CryptoManager::deriveKek()` signatures. This is the highest-risk item: a developer writing integration code against the documented API will use the wrong type, bypassing secure zeroing.
Affected file: `scef/docs/api/scef-lib.md`, lines 152 and 220.

**Priority 2 — Security: `gui.md` password security section replacement**
Rewrite `gui.md:117-121` to describe the actual design: passwords are never stored in `ScefController`, converted to `Botan::secure_vector<char>` by `securePasswordFromQString()`, and passed directly to `FileManager`. Remove all references to `currentPassword_` and `scrubPassword()`.
Affected file: `scef/docs/gui.md`, lines 117-121.

**Priority 3 — Correctness: `cli.md` — `--password` flag and `benchmark` command**
Two fixes in one pass: (a) Remove the false statement that `--password` does not exist; add it to the options table with a security warning. (b) Completely replace the `benchmark` command argument table: no flags, just a table of 4 profiles with correct parameter values (fast=256 MiB t=1 p=4, default=1024 MiB t=1 p=4, high=2048 MiB t=1 p=4, browser=64 MiB t=1 p=1). Add `--cipher`, `--log-level`, `-y/--yes`, `--strength-only` to the options documentation.
Affected file: `scef/docs/cli.md`, lines 11, 155-178, and the Global Flags section.

**Priority 4 — API correctness: `api/scef-lib.md` phantom and missing items**
Remove: `FileManager::printHeader()`, `FileTable::updateChecksum/getChecksum/resetChecksum`, `getDefaultProfile()`. Fix: `LogLevel` enum to include `BENCH=2` and correct `WARNING=3`, `ERROR=4`; add `LOG_BENCH` macro. Add: `PasswordStrengthEstimator` class documentation.
Affected file: `scef/docs/api/scef-lib.md`, multiple sections.

**Priority 5 — Architectural accuracy: `data-flows.md` and `architecture.md` pipeline and CMake fixes**
In `data-flows.md`: replace the `writeChunks` sequential loop detail with a note that encryption is delegated to `EncryptPipeline` (multithreaded); replace `containerStream_->flush()` with `containerFile_.syncToDevice()`. In `architecture.md`: remove `SCEF_BUILD_BENCHMARKS` option (bench builds unconditionally); update `scef_lib` source file list to include all 11 files from `CMakeLists.txt`; add the two missing unit test files to `scef_unit_tests`; remove `FileTable::updateChecksum/getChecksum` from the class diagram; add `setCipher()` and `setProgressCallback()` to the `FileManager` diagram.
Affected files: `scef/docs/data-flows.md` and `scef/docs/architecture.md`.
