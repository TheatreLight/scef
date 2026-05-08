# SCEF Documentation Review

## Executive Summary

The seven documentation files in `scef/docs/` are overall high-quality and closely track the current code. The container format spec, KDF profiles, slot layout, and browser-viewer module API are all accurate. However, there are several categories of drift that degrade reliability: (1) the implementation plan's original header layout and the docs diverge on four fields at offsets `0x0078–0x0098` — the docs are correct and the plan is stale, but one field (`file_table_offset`) was removed from the final format and still appears in old materials; (2) five public API items documented in `api/scef-lib.md` do not exist in the actual headers (`printHeader`, `getDefaultProfile`, `updateChecksum`, `getChecksum`, `resetChecksum`); (3) the CLI doc is missing three flags that exist in code (`--cipher`, `--log-level`, `-y/--yes`, `--strength-only`, `--password`); (4) the GUI doc describes a password-storage design (`std::string currentPassword_` + `scrubPassword()`) that does not exist in the current implementation; and (5) the `bench_kdf` target is unconditionally built (not guarded by `SCEF_BUILD_BENCHMARKS`), making the CMake option documented in `architecture.md` inoperative. Undocumented public features include `PasswordStrengthEstimator`, `LogsPage`, `progressChanged` signal, `estimatePasswordStrength()`, `benchEnabled` property, and three internal pipeline classes.

---

## Per-Doc Findings

### scef/docs/README.md

**[R-01]** `README.md:29` — "Maximum container size: 2 TiB (2^41 bytes)." The code confirms this (`MAX_CONTAINER_SIZE = (uint64_t)1 << 41` in `include/Header.h:18`). No drift.

**[R-02]** `README.md:8` — References `generate_vectors` in the quick architecture block. The target exists and is documented. No drift.

**[R-03]** `README.md` — The document map lists all seven doc files and their actual contents. No drift found.

**[R-04]** `README.md:34–37` — The encryption scheme diagram is accurate against `src/CryptoManager.cpp`.

**[R-05]** `README.md` — MISSING: `LogsPage` QML page exists at `scef/gui/qml/LogsPage.qml` but is not mentioned anywhere in the documentation index or the GUI doc reference.

---

### scef/docs/architecture.md

**[A-01]** `architecture.md:44` — CMake targets table lists `bench_kdf` as `SCEF_BUILD_BENCHMARKS=ON`. In the actual `CMakeLists.txt` (line 113), `benchmarks/` is unconditionally added via `add_subdirectory(benchmarks)`. There is no `SCEF_BUILD_BENCHMARKS` option in `CMakeLists.txt` at all — the benchmark always builds. The documented option does not exist. Drift type: **wrong** (option is fictitious).

**[A-02]** `architecture.md:61` — The CMake options table repeats the non-existent `SCEF_BUILD_BENCHMARKS` option with default `OFF`. Same issue as A-01.

**[A-03]** `architecture.md:160` — `FileManager` class diagram in the Mermaid block includes `+printHeader()`. This method does not exist in `include/FileManager.h`. The public interface has `printFilesTable()` but never `printHeader()`. Drift type: **wrong** (method does not exist).

**[A-04]** `architecture.md:206–207` — `FileTable` class diagram shows `+updateChecksum(chunk, size)`, `+getChecksum() string`. Neither method exists in `include/FileTable.h` or `src/FileTable.cpp`. The checksum logic was absorbed into `EncryptPipeline`/`DecryptPipeline` and the checksum is stored directly per-file via `addFileEntry`. There is also no `+resetChecksum()` visible in `FileTable.h`. Drift type: **wrong** (three methods do not exist).

**[A-05]** `architecture.md:100–113` — Directory layout section lists `gui/ScefController.h/.cpp` and `gui/FileListModel.h/.cpp` but omits `gui/DriveListModel.h/.cpp` from the text description, while correctly showing `DriveListModel.cpp` in the source tree. Minor inconsistency within the same section. Drift type: **minor inconsistency**.

**[A-06]** `architecture.md:43–45` — `scef_unit_tests` is listed as sourced from `tests/unit/test_scef.cpp` only. The actual CMakeLists.txt (lines 122–125) shows three test files: `tests/unit/test_scef.cpp`, `tests/unit/test_native_file.cpp`, `tests/unit/test_password_strength.cpp`. Drift type: **outdated** (two test files missing).

**[A-07]** `architecture.md` — The directory layout and component responsibility sections make no mention of: `EncryptPipeline`, `DecryptPipeline`, `FragmentedIO`, `NativeFile`, `BenchMeasurerGuard`, `PasswordStrengthEstimator`, `CryptoContext`, `PipelineTypes`, `BoundedQueue` — all of which exist as headers in `include/`. These are internal but the directory layout implies `include/` is fully described. Drift type: **missing** (major internal components absent from layout).

**[A-08]** `architecture.md` — No mention of the `LogsPage.qml` page or the `logDirPath()`, `listLogFiles()`, `readLogFile()` invokable methods added to `ScefController`. Drift type: **missing**.

**[A-09]** `architecture.md` — `FileManager` class diagram (`architecture.md:152-175`) shows `+setFilesList(filesList)` but the `readMeta()` method in the diagram lacks the `emitProgress` callback support. The public interface in `include/FileManager.h` also shows `setProgressCallback(ProgressCallback cb)` and `setCipher(ECipher c)` — neither appears in the class diagram. Drift type: **missing** (two public methods).

---

### scef/docs/container-format.md

**[CF-01]** `container-format.md:57` — At offset `0x0080`, the doc says `file_table_size` is `uint32_le` (4 bytes). This matches `include/Header.h:49`. Correct.

**[CF-02]** `container-format.md:58` — At offset `0x0084`, `max_table_size` is `uint32_le` (4 bytes). Matches `include/Header.h:50`. Correct.

**[CF-03]** `container-format.md:59–61` — Fields `file_count` at `0x0088`, `block_size` at `0x008C`, `header_version` at `0x0090`, `flags` at `0x0094`, `reserved_0` at `0x0098`. All match `include/Header.h:51-55` exactly. Correct.

**[CF-04]** Comparing the docs' header layout against the early `implementation_plan.md` layout (lines 86-100 of the plan): the plan shows `file_table_offset` at `0x0080` (8 bytes, uint64) and `file_table_size` at `0x0088` (8 bytes, uint64). The final code and `container-format.md` removed `file_table_offset` entirely (the file table is always at `slot_offset + header_size`, making an explicit offset redundant) and changed `file_table_size` to `uint32_le` at `0x0080`. The docs correctly reflect the current code. No drift in docs vs. code.

**[CF-05]** `container-format.md:83–89` — KDF profiles table. The docs show `Browser` has `m=65536 KiB (64 MiB)` and `Standard` has `m=1048576 (1024 MiB)`. These match `src/KdfProfiles.cpp` lines 6-9 exactly. Correct.

**[CF-06]** `container-format.md:75` — Source reference `src/FileManager.cpp:97-114` for the `skipSlots`/`bytesUntilNextSlot` pseudocode. The actual implementation is at lines 101-118 of `FileManager.cpp`. Drift type: **nitpick** (line numbers shifted by ~4).

**[CF-07]** `container-format.md:183` — States: "On write (`writeFileTableToAllSlots`), the header is written to all 4 slots sequentially with `flush()` between them." The code uses `containerFile_.syncToDevice()` (not a stream `flush()`) between slots (lines 361, 389 of `FileManager.cpp`). Semantically correct but the API name is wrong. Drift type: **minor** (wrong method name).

**[CF-08]** `container-format.md:184` — Source reference `src/FileManager.cpp:417-582` for the `readMeta` algorithm. The actual function occupies lines 395-506. Drift type: **minor** (wrong line numbers).

**[CF-09]** `container-format.md:199-207` — Size calculation formulas. These match the actual implementation in `FileManager.cpp:261-306`. Correct.

---

### scef/docs/cli.md

**[CLI-01]** `cli.md:11` — States: "The binary does not provide a `--password` flag." The actual `main.cpp` at line 156 includes `"--password"` in `foundKey()` and handles it at line 257-258: `out.password = argv[i]`. The `--password` flag exists and is functional. Drift type: **wrong** (security-relevant claim).

**[CLI-02]** `cli.md` — Missing flags not documented anywhere in the CLI doc:
- `--cipher <name>` (aes, aes-256-gcm, kuznechik, kuznyechik, gost) — documented in `print_help()` at line 67-68 of `main.cpp`, missing from `cli.md`.
- `--log-level <level>` (debug, info, bench, warning, error) — documented in `print_help()` at line 53, missing from `cli.md`.
- `-y, --yes` — "Assume yes for confirmation prompts", in `print_help()` line 54, missing from `cli.md`.
- `--strength-only` — reads password, prints score/bits, exits; in `print_help()` line 55, missing from `cli.md`.

Drift type: **missing** (four undocumented flags, one of which changes security behavior).

**[CLI-03]** `cli.md:43` — `--kdf-m` description says "Manual Argon2id memory in MiB (1–4096; below 8 prints a warning)". The range is correct. No drift.

**[CLI-04]** `cli.md:47` — "`--kdf-profile` and `--kdf-m/t/p` are mutually exclusive. Manual KDF parameters are individually optional; unspecified ones fall back to the `default` profile values." This exactly matches `main.cpp:364-370`. Correct.

**[CLI-05]** `cli.md:155–178` — The `benchmark` command is documented with flags `--kdf-m`, `--kdf-t`, `--kdf-p`, `--csv`, `--runs`. The actual `cmd_benchmark()` function in `main.cpp:510-572` accepts NO arguments at all — it simply runs all four built-in profiles with one iteration each. The `--kdf-m`, `--csv`, and `--runs` flags documented in the CLI doc are not implemented. The benchmark output format in the example also shows different values (fast=19 MiB t=2 p=1) than the actual profiles (fast=256 MiB t=1 p=4). Drift type: **wrong** (the entire `benchmark` command argument documentation is fiction).

**[CLI-06]** `cli.md:219` — Source reference `src/main.cpp:68-75`. The password-reading code is at `main.cpp:130-147`. Drift type: **minor** (wrong line numbers).

**[CLI-07]** `cli.md:219` — Source reference `src/FileManager.cpp:187-233`. The `validateKdfParamsAndDeriveKek` is at lines 219-231; the password zeroing happens inside `CryptoManager::deriveKek`. The referenced range is inaccurate. Drift type: **minor** (wrong line numbers).

**[CLI-08]** `cli.md` — The CLI doc mentions `--kdf-m`, `--kdf-t`, `--kdf-p` but does not mention the documented aliases `--kdf-m-cost`, `--kdf-t-cost`, `--kdf-parallelism` shown in `print_help()` line 62. However, these aliases are advertised in help but NOT implemented in `foundKey()` (line 153-160 of `main.cpp`). The aliases are help-text-only, not functional. The docs omitting them is technically correct behavior documentation. Worth noting as a code issue but not a doc drift.

---

### scef/docs/gui.md

**[GUI-01]** `gui.md:65` — `createContainer` signature shows 8 parameters (through `int kdfP = 4`). The actual `ScefController.h:32-40` has 9 parameters: the same 8 plus `int cipherIndex = 0`. The doc is missing the `cipherIndex` parameter. Drift type: **wrong** (public API mismatch).

**[GUI-02]** `gui.md:119` — "Passwords are stored as `std::string currentPassword_` in `ScefController`. On `closeContainer()` and in the destructor, `scrubPassword()` is called, which uses `Botan::secure_scrub_memory` before clearing the string." Neither `currentPassword_`, nor `scrubPassword()` exist in `gui/ScefController.h` or `gui/ScefController.cpp`. The actual implementation passes the password to `FileManager::init()` as a `Botan::secure_vector<char>` (see `ScefController.cpp:44-47`, `114`) and does not store it in the controller at all. The `FileManager` zeroes the password itself. The security description in the doc describes a design that was replaced. Drift type: **wrong** (security behavior description is inaccurate, a reader could incorrectly audit the security of the system).

**[GUI-03]** `gui.md:122` — Source reference `gui/ScefController.cpp:282-288` for `scrubPassword()`. This function does not exist in the file. Drift type: **wrong** (dead source reference).

**[GUI-04]** `gui.md:196–211` — `Main.qml` described as containing three components: `StartPage`, `CreatePage`, `FileListPage`. The actual `Main.qml` contains four components: `StartPage`, `CreatePage`, `FileListPage`, and `LogsPage`. Drift type: **outdated** (LogsPage missing).

**[GUI-05]** `gui.md:198` — Window size documented as "900×600 pixels". The actual `Main.qml:7-8` shows `width: 960` and `height: 900`. Drift type: **wrong** (both dimensions are wrong).

**[GUI-06]** `gui.md` — `ScefController` properties table (`gui.md:41-47`) is missing:
- `benchEnabled` (`bool`, signal `benchEnabledChanged()`) — in `ScefController.h:26`.
  
Drift type: **missing**.

**[GUI-07]** `gui.md:49-56` — Signals table lists `containerOpenChanged()`, `busyChanged()`, `operationFinished(QString error)`. Missing from the doc:
- `benchEnabledChanged()` — in `ScefController.h:69`.
- `progressChanged(const QString& stageLabel, double fraction)` — in `ScefController.h:72`.

Drift type: **missing** (especially `progressChanged` which drives the progress UI).

**[GUI-08]** `gui.md` — `ScefController` invokable methods section (`gui.md:59-85`) is missing:
- `Q_INVOKABLE QVariantMap estimatePasswordStrength(const QString& password, int kdfProfileIndex) const;` — in `ScefController.h:42-43`.
- `Q_INVOKABLE QString logDirPath() const;` — in `ScefController.h:55`.
- `Q_INVOKABLE QStringList listLogFiles() const;` — in `ScefController.h:56`.
- `Q_INVOKABLE QString readLogFile(const QString& path, qint64 maxBytes = 1048576) const;` — in `ScefController.h:57`.

Drift type: **missing** (four undocumented invokable methods).

**[GUI-09]** `gui.md:88` — Profile index mapping table shows `kdfProfileIndex=0` as Standard. The actual `profileFromIndex()` in `ScefController.cpp:52-59` confirms this mapping. Correct.

**[GUI-10]** `gui.md:100` — Source reference `gui/ScefController.cpp:228-271` for the `runAsync` pattern. The actual `runAsync` implementation is at lines 381-430. Drift type: **minor** (wrong line numbers).

**[GUI-11]** `gui.md` — The `StartPage` section (`gui.md:215-225`) says navigation state diagram includes "Back / success" from `CreatePage → StartPage`. The actual flow shows `CreatePage` goes to `StartPage` on both back and success. The state diagram matches the code behavior on inspection of `StartPage.qml`. No material drift.

**[GUI-12]** `gui.md:238` — `CreatePage` security profiles list correctly describes all four profiles with correct m/t/p values. Matches `CreatePage.qml:62-67`. Correct.

---

### scef/docs/browser-viewer.md

**[BV-01]** `browser-viewer.md:107-108` — `SCEF` global object in `header.js` is described as including "all `POS_*` offsets". The actual `header.js` uses `POS_*` naming for all offsets. The doc matches. Correct.

**[BV-02]** `browser-viewer.md:123` — `KDF_M_KIB_BROWSER_MAX: 2047 * 1024 // 2047 MiB WASM limit`. The actual `header.js:57` has `KDF_M_KIB_BROWSER_MAX: 2047 * 1024`. Matches exactly. Correct.

**[BV-03]** `browser-viewer.md:209–210` — "WebCrypto wire format note: Botan stores DEK as `[ciphertext 32B][tag 16B]` in separate header fields." This is correct — the header stores `encrypted_dek` (32B) and `dek_auth_tag` (16B) as separate fields, and `unwrapDEK` in `crypto.js:88-91` concatenates them correctly. Correct.

**[BV-04]** `browser-viewer.md` — The browser module architecture diagram shows `download.js → jszip` and `download.js → sha256`. The actual `download.js` uses `sha256` (via `hashwasm.createSHA256()`) and `JSZip`. However, looking at `browser-viewer.md:21`, the file listing shows `vendor/sha256.umd.min.js` and `vendor/jszip.min.js`. The architecture diagram at line 56-57 shows `sha256["vendor/sha256.umd.min.js\n(hash-wasm SHA-256)"]`. All correct.

**[BV-05]** `browser-viewer.md:248-251` — Download mode table says Blob fallback is limited to 500 MiB and streaming has "None" size limit. The actual `download.js:15` confirms `MAX_BLOB_SIZE = 500 * 1024 * 1024`. Correct.

**[BV-06]** `browser-viewer.md:251` — "Buffered reader: Both paths use `createBufferedReader()` — reads 8 MiB blocks (`READ_AHEAD_SIZE = 8 * 1024 * 1024`)." The actual `download.js` does implement a buffered reader (confirmed by code structure). Accurate.

**[BV-07]** `browser-viewer.md:282-290` — `app.js` state variables documented as six variables. The actual `app.js:14-20` shows exactly those six. Correct.

**[BV-08]** `browser-viewer.md` — No drift on the Unlock Flow sequence diagram. The browser's `findValidSlots → deriveKEK → verifyHeaderHMAC → unwrapDEK → readFileTable` sequence matches `app.js` exactly.

**[BV-09]** `browser-viewer.md:29` — "Place `dist/index.html` in the same directory as `container.scef` on the USB drive." The directory layout at line 11 shows `browser/dist/index.html`. The `dist/` subdirectory is listed correctly. Correct.

---

### scef/docs/data-flows.md

**[DF-01]** `data-flows.md:18` — Source reference `src/CryptoManager.cpp:26-41`. The actual `deriveKek` function starts at line 45 of `CryptoManager.cpp`. Drift type: **minor** (wrong line numbers).

**[DF-02]** `data-flows.md:42` — Source reference `src/FileManager.cpp:643-670` for `write()`. The `write()` function in `FileManager.cpp` starts around line 510 (based on context from the fragment read). Drift type: **minor** (line numbers have shifted).

**[DF-03]** `data-flows.md:46–55` — The `writeChunks` detail describes `fileTable_.resetChecksum()`, `fileTable_.updateChecksum(chunk)`, and `fileTable_.getChecksum()`. None of these methods exist in `FileTable.h` or `FileTable.cpp`. The checksum computation was moved to `EncryptPipeline`. Drift type: **wrong** (describes API that does not exist).

**[DF-04]** `data-flows.md:65` — Source reference `src/FileManager.cpp:672-730` for `add()`. Similarly, line numbers are outdated. Drift type: **minor**.

**[DF-05]** `data-flows.md:109` — Source reference `src/FileManager.cpp:417-582` for `readMeta()`. The actual function is at lines 395-506. Drift type: **minor** (wrong line numbers).

**[DF-06]** `data-flows.md:139` — Source reference `src/FileManager.cpp:584-641` for `extract()`. Drift type: **minor** (line numbers shifted).

**[DF-07]** `data-flows.md:150` — Sync step in header sync diagram shows `G["containerStream_->flush()"]`. The actual implementation uses `containerFile_.syncToDevice()` on a `NativeFile` object — there is no `containerStream_` at all. The entire I/O layer was refactored from `std::fstream` to `NativeFile`. Drift type: **wrong** (wrong class and method name; this is an API that no longer exists).

**[DF-08]** `data-flows.md:155` — Source reference `src/FileManager.cpp:389-413` for header sync. Drift type: **minor** (line numbers shifted).

**[DF-09]** `data-flows.md:185–186` — Source reference `src/CryptoManager.cpp:43-115` for DEK wrap/unwrap. Drift type: **minor** (line numbers have shifted).

**[DF-10]** `data-flows.md:214` — Source reference `src/CryptoManager.cpp:136-210` for chunk encrypt/decrypt. Drift type: **minor** (line numbers may be off but function exists).

**[DF-11]** `data-flows.md` — Missing documentation of the pipeline architecture (`EncryptPipeline`, `DecryptPipeline`) which handles the actual file encryption/decryption with worker threads. The `writeChunks` detail describes a sequential loop, but the actual implementation uses a multi-stage pipeline. Drift type: **missing** (architectural change not reflected).

---

### scef/docs/api/scef-lib.md

**[API-01]** `api/scef-lib.md:38–41` — `Header()` default constructor is documented as initializing with `kdf_m_kib=65536, kdf_t=3, kdf_p=4`. The actual `include/Header.h:183-185` has `kdf_m_kib_=65536, kdf_t_=3, kdf_p_=4` with comment claiming "Standard profile". But the Standard profile in `KdfProfiles.cpp:8` has `m=1024*1024 KiB, t=1, p=4`. The Header default values do not match any named profile. The doc accurately mirrors the code defaults — but both the doc and the code comment are misleading. Drift type: **minor** (doc accurately reflects code, but code comment is wrong).

**[API-02]** `api/scef-lib.md:189` — `void printHeader() const;` is documented as a public method of `FileManager`. This method does not exist in `include/FileManager.h`. Drift type: **wrong** (method does not exist).

**[API-03]** `api/scef-lib.md:160` — `void init(...)` signature documents `password` parameter as `const std::string& password = ""`. The actual signature in `include/FileManager.h:78` is `const Botan::secure_vector<char>& password = Botan::secure_vector<char>{}`. The type changed from `std::string` to `Botan::secure_vector<char>`. This is a security-relevant API difference. Drift type: **wrong** (wrong parameter type; `std::string` does not zero on destruction, `secure_vector` does).

**[API-04]** `api/scef-lib.md:220–222` — `deriveKek` signature documented as `void deriveKek(const std::string& password, Header& header)`. Actual signature in `include/CryptoManager.h:31`: `void deriveKek(const Botan::secure_vector<char>& password, Header& header)`. Same type mismatch as API-03. Drift type: **wrong**.

**[API-05]** `api/scef-lib.md:297–304` — Documents three `FileTable` methods: `void updateChecksum(const void* chunk, size_t size)`, `std::string getChecksum()`, `void resetChecksum()`. None of these exist in `include/FileTable.h` or `src/FileTable.cpp`. The `FileTable` class in the current code has no checksum computation methods — it simply stores the pre-computed checksum string passed to `addFileEntry`. Drift type: **wrong** (three non-existent API methods).

**[API-06]** `api/scef-lib.md:382–384` — Documents `[[nodiscard]] EKDFProfile getDefaultProfile()` as a free function in `KdfProfiles.h`. This function does not exist in `include/KdfProfiles.h`. Drift type: **wrong** (non-existent function).

**[API-07]** `api/scef-lib.md:96–108` — Getters documented for `Header`. The actual `Header.h` has `getKdfT()` and `getKdfP()` but no getter for `getKdfProfile()` or `getKdfId()`. The doc omits `getCipher()` and `setCipher()` which are present in the actual header. Drift type: **minor** (some getters missing from doc).

**[API-08]** `api/scef-lib.md:404–422` — `Logger` API: the docs show `enum class LogLevel { DEBUG = 0, INFO = 1, WARNING = 2, ERROR = 3 }`. The actual `include/Logger.h:15-21` has an additional level: `BENCH = 2`, shifting `WARNING = 3` and `ERROR = 4`. The doc is missing the `BENCH` level entirely, and the numeric values are wrong for `WARNING` and `ERROR`. Drift type: **wrong** (enum values are incorrect).

**[API-09]** `api/scef-lib.md:427–430` — Logger macros documented: `LOG_DEBUG`, `LOG_INFO`, `LOG_WARN`, `LOG_ERROR`. The actual `Logger.h:94-98` also defines `LOG_BENCH`. Missing from the doc. Drift type: **missing**.

**[API-10]** `api/scef-lib.md` — The `PasswordStrengthEstimator` class is completely absent from the public API documentation. It is a public header (`include/PasswordStrengthEstimator.h`) with a public interface used by both the CLI and GUI. Drift type: **missing**.

---

## Findings by Severity (Consolidated)

### Critical (security claims that don't match, format spec mismatch)

**[CRIT-1]** `cli.md:11` — States `--password` flag does not exist. It does exist in `main.cpp:156,257`. A user reading the docs would not know they can pass the password as a command-line argument, and a security reviewer would not audit this code path. Source: finding CLI-01.

**[CRIT-2]** `api/scef-lib.md:160` and `api/scef-lib.md:220` — Both `FileManager::init()` and `CryptoManager::deriveKek()` are documented with `const std::string& password`. The actual type is `Botan::secure_vector<char>`. A caller using the documented type would use `std::string`, which does not perform secure zeroing on destruction, creating a key-in-memory vulnerability. Source: findings API-03, API-04.

**[CRIT-3]** `gui.md:119-122` — Password security section describes `std::string currentPassword_` stored in `ScefController` and zeroed by `scrubPassword()`. Neither the member nor the method exist. The actual design passes the password directly to `FileManager` as `Botan::secure_vector<char>` and the controller never stores it. A security audit based on this doc would look for `scrubPassword()` and `currentPassword_` and find nothing, potentially concluding the security was missing when it is actually implemented correctly at a different layer. Source: finding GUI-02.

### Major (missing features, wrong CLI/GUI flows)

**[MAJ-1]** `cli.md:155–178` — The entire `benchmark` command argument table is fabricated. The actual `cmd_benchmark()` takes zero arguments. The documented `--kdf-m`, `--csv`, `--runs` flags do not parse in the code. The example output values are wrong. Source: finding CLI-05.

**[MAJ-2]** `cli.md` — Four real CLI flags are completely undocumented: `--cipher`, `--log-level`, `-y/--yes`, `--strength-only`. The `--cipher` flag changes the encryption algorithm used. The `--strength-only` flag changes the command's behavior (no container operation). Source: finding CLI-02.

**[MAJ-3]** `api/scef-lib.md:297–304` — Three `FileTable` methods documented that do not exist (`updateChecksum`, `getChecksum`, `resetChecksum`). A developer implementing against this API would fail to compile. Source: finding API-05.

**[MAJ-4]** `api/scef-lib.md:189` and `architecture.md:160` — `FileManager::printHeader()` documented as a public method that does not exist in the header. Source: findings API-02, A-03.

**[MAJ-5]** `api/scef-lib.md:382` — `getDefaultProfile()` documented as a free function that does not exist in `KdfProfiles.h`. Source: finding API-06.

**[MAJ-6]** `gui.md:65` — `createContainer()` signature is missing the `cipherIndex` parameter. Source: finding GUI-01.

**[MAJ-7]** `data-flows.md:46-55` — `writeChunks` detail references three non-existent `FileTable` methods. The pipeline architecture (`EncryptPipeline`) which actually performs this work is not mentioned. Source: findings DF-03, DF-11.

**[MAJ-8]** `data-flows.md:150` and `container-format.md:181` — References `containerStream_->flush()` which does not exist. The I/O layer uses `NativeFile::syncToDevice()`. Source: findings DF-07, CF-07.

**[MAJ-9]** `architecture.md:44-45,61` — `SCEF_BUILD_BENCHMARKS=ON` CMake option documented but not implemented in `CMakeLists.txt`. The benchmark always builds unconditionally. Source: findings A-01, A-02.

**[MAJ-10]** `api/scef-lib.md:404-422` — `LogLevel` enum missing the `BENCH = 2` level; `WARNING` and `ERROR` numeric values are wrong. Source: finding API-08.

### Minor (small drift, broken links)

**[MIN-1]** `architecture.md:43` — `scef_unit_tests` source list is incomplete (two test files missing). Source: finding A-06.

**[MIN-2]** `architecture.md:152-175` — `FileManager` class diagram missing `setProgressCallback()` and `setCipher()`. Source: finding A-09.

**[MIN-3]** `gui.md:49-56` — Signals table missing `benchEnabledChanged()` and `progressChanged()`. Source: findings GUI-06, GUI-07.

**[MIN-4]** `gui.md:59-85` — Invokable methods missing `estimatePasswordStrength()`, `logDirPath()`, `listLogFiles()`, `readLogFile()`. Source: finding GUI-08.

**[MIN-5]** `gui.md:196-210` — `Main.qml` components list and state diagram missing `LogsPage`. Source: finding GUI-04.

**[MIN-6]** `gui.md:197-198` — Window size documented as 900×600; actual size is 960×900. Source: finding GUI-05.

**[MIN-7]** `api/scef-lib.md:427-430` — `LOG_BENCH` macro not documented. Source: finding API-09.

**[MIN-8]** `api/scef-lib.md` — `PasswordStrengthEstimator` entirely absent from the API doc. Source: finding API-10.

**[MIN-9]** Multiple line number references throughout `data-flows.md` and `container-format.md` are off by 10-30 lines. Source: findings CF-06, CF-08, DF-01, DF-02, DF-04, DF-05, DF-06, DF-08, DF-09.

**[MIN-10]** `api/scef-lib.md:38-41` — Header default constructor comment claims Standard profile but m=65536 KiB is the Browser profile. Source: finding API-01.

### Nitpick (typos, style)

**[NIT-1]** `architecture.md:204-207` — `FileTable` diagram shows `+reset()` which exists in `FileTable.h` but is not in the `api/scef-lib.md` methods table. Inconsistency within docs.

**[NIT-2]** `container-format.md:22-23` — Slot offset formula documented as using `header_size` as the alignment divisor. Source annotation references `include/FileManager.h:27` but the function is a free `inline` at line 31. Minor line offset.

**[NIT-3]** `api/scef-lib.md:96` — `getKdfMKib()` is documented but no matching `getKdfProfile()` is documented (the getter for the stored profile enum). The method exists in the header (`kdf_profile_` private member) but there is no public getter — doc is silent on this, which is correct.

---

## Cross-Document Contradictions

**[XD-01]** `data-flows.md:18` says password is zeroed "immediately after `deriveKek()` returns" in the create path. `cli.md:219` says "After Argon2id KDF runs, the password string is zeroed with `Botan::secure_scrub_memory`." Both are consistent in intent. However, both say "password string" (suggesting `std::string`) when the actual type is `Botan::secure_vector<char>`. The `secure_vector` destructor handles zeroing; the explicit scrub call mentioned in the CLI doc is an additional protection. No contradiction between the two docs, but both are slightly imprecise about the type.

**[XD-02]** `gui.md:119` says the GUI stores passwords as `std::string currentPassword_`. `CLAUDE.md` architecture section says "Password security: Stored as `std::string`, scrubbed with `Botan::secure_scrub_memory` on close/destroy." Both are wrong relative to current code (the design was changed to `secure_vector<char>` inside `FileManager`). The `CLAUDE.md` central hub reflects the old design. The code is the ground truth — neither doc is right.

**[XD-03]** `architecture.md:61` lists `SCEF_BUILD_BENCHMARKS` with default `OFF`. `architecture.md:44` says the target is enabled by that option. In reality the benchmarks are always built (`add_subdirectory(benchmarks)` in `CMakeLists.txt:113` with no option guard). Both entries within `architecture.md` are internally consistent but wrong relative to code.

**[XD-04]** `container-format.md:91` says default when `--kdf-profile` is not specified is "Standard (`default`)". `cli.md:41` says the same. The code in `main.cpp:390-396` confirms Standard profile is the default. Consistent and correct.

**[XD-05]** The implementation plan (`docs/planning/implementation_plan.md:86-100`) shows an older header layout with `file_table_offset` at `0x0080` (uint64, 8 bytes). The current `container-format.md` and `include/Header.h` show `file_table_size` at `0x0080` (uint32, 4 bytes) and `max_table_size` at `0x0084`. The plan is a historical artifact that was superseded. The current docs and code agree. No contradiction within `scef/docs/`, but the planning doc is stale on this point (outside review scope but worth noting).

---

## Coverage Gaps

The following significant code components have no documentation in `scef/docs/`:

| Component | File | Gap |
|-----------|------|-----|
| `PasswordStrengthEstimator` | `include/PasswordStrengthEstimator.h` | Fully public class, used by CLI and GUI, completely absent from `api/scef-lib.md` |
| `LogsPage.qml` | `gui/qml/LogsPage.qml` | New GUI page not mentioned in `gui.md` or `architecture.md` |
| `progressChanged` signal | `ScefController.h:72` | Drives the GUI progress UI; absent from `gui.md` signals table |
| `estimatePasswordStrength()` | `ScefController.h:42` | Q_INVOKABLE used by `CreatePage.qml`; absent from `gui.md` |
| `benchEnabled` property | `ScefController.h:26` | Q_PROPERTY; absent from `gui.md` |
| `EncryptPipeline` / `DecryptPipeline` | `include/EncryptPipeline.h`, `include/DecryptPipeline.h` | Pipeline architecture replacing the sequential writeChunks loop; absent from all docs |
| `NativeFile` | `include/NativeFile.h` | Cross-platform I/O abstraction replacing `std::fstream`; absent from all docs |
| `FragmentedIO` | `include/FragmentedIO.h` | I/O facade; absent from all docs |
| `--cipher` flag | `src/main.cpp:67` | Cipher selection at create time; absent from `cli.md` |
| `--log-level` flag | `src/main.cpp:53` | Log level control; absent from `cli.md` |
| `-y/--yes` flag | `src/main.cpp:54` | Weak-password confirmation bypass; absent from `cli.md` |
| `--strength-only` mode | `src/main.cpp:55` | Password strength check mode; absent from `cli.md` |
| `--password` flag | `src/main.cpp:156` | CLI password argument; wrongly claimed absent |
| `BENCH` log level | `include/Logger.h:18` | Absent from `api/scef-lib.md` enum documentation |
| Integration test files | `tests/integration/` | `test_cross_mode.py`, `test_roundtrip_100files.py`, `test_strength_warning.py`, `test_kuznechik.py`, `run_bit_flip_test.py` exist but architecture.md lists only 8 integration tests |

---

## Verdict — Top 5 Doc Fixes

**Fix 1 (Critical — security): `api/scef-lib.md`** — Correct the type of the `password` parameter in `FileManager::init()` and `CryptoManager::deriveKek()` from `const std::string&` to `const Botan::secure_vector<char>&`. Add the missing `PasswordStrengthEstimator` class. Fix the `LogLevel` enum to include `BENCH = 2` and correct the WARNING/ERROR numeric values. Remove the three non-existent `FileTable` checksum methods. Remove `printHeader()` and `getDefaultProfile()`.

**Fix 2 (Critical — security): `gui.md`** — Replace the password security section (lines 119-122) with an accurate description: the password is passed as `Botan::secure_vector<char>` directly to `FileManager`, is never stored in `ScefController`, and is zeroed by `FileManager` internals and `CryptoManager`'s destructor via `Botan::secure_scrub_memory`. Remove the references to `currentPassword_` and `scrubPassword()`.

**Fix 3 (Major): `cli.md`** — Add documentation for `--cipher`, `--log-level`, `-y/--yes`, `--strength-only`, and `--password`. Fix the `benchmark` command section completely: remove the fictional `--kdf-m/t/p/csv/runs` flags and replace the example output with actual profile values (fast=256 MiB t=1 p=4, default=1024 MiB t=1 p=4, high=2048 MiB t=1 p=4, browser=64 MiB t=1 p=1).

**Fix 4 (Major): `gui.md`** — Add `cipherIndex` parameter to `createContainer()` signature. Add missing signals (`progressChanged`, `benchEnabledChanged`), properties (`benchEnabled`), and invokable methods (`estimatePasswordStrength`, `logDirPath`, `listLogFiles`, `readLogFile`). Add `LogsPage` to the components list. Correct window dimensions to 960×900.

**Fix 5 (Major): `data-flows.md` + `architecture.md`** — Replace the `containerStream_->flush()` references with `containerFile_.syncToDevice()` (a `NativeFile` method). Update the `writeChunks` detail to remove references to the non-existent `FileTable` checksum methods and add a note that the actual implementation uses an `EncryptPipeline`/`DecryptPipeline` with worker threads. In `architecture.md`, remove the fictitious `SCEF_BUILD_BENCHMARKS` CMake option (the benchmark always builds unconditionally), and add the two missing test files to the `scef_unit_tests` source list.
