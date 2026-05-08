# SCEF Refactoring Plan

Branch: `refactoring` (off `main`).
Source: 5 final reviews in `scef/review/final/{src,gui,browser,tests,docs}.md`.
Scope: Critical + Major + trivial Minor (~40 items). Nitpick deferred.

## Locked Decisions

| # | Decision |
|---|----------|
| 1 | `FileManager::init()` accepts a full file path (gui F-4) |
| 2 | Container name is user-choosable; default `container.scef`, auto-numbered (`container_1.scef`, ...) on collision (gui F-3 expanded) |
| 3 | `FileManager::setKdfParams()` logs warning + clamps to min when below `KDF_M_KIB_MIN` (src F-9) |
| 4 | Browser F-1 (UTF-8 password) implemented in CLI `main.cpp` |
| 5 | POSIX F-2 written blind, validated later |
| 6 | New tests added; production bugs they expose are also fixed |
| 7 | Auto-numbering helper: free function `nextAvailableContainerPath(dir)` in `FileManager.h`, used by CLI and exposed to QML via `Q_INVOKABLE QString defaultContainerName(QString dir)` on `ScefController` |
| 8 | "Open from Drive": scan drive root for `*.scef`; if 1 → auto-open; if multiple → list/picker; if 0 → disabled |
| 9 | CLI `scef create` gets `--name <filename>` option; default uses auto-numbering |

## Files Touched (by group)

### Core C++ (must be coordinated — Wave 2 single coder)
- `scef/include/Header.h`, `scef/src/Header.cpp`
- `scef/include/FileTable.h`, `scef/src/FileTable.cpp`
- `scef/include/FileManager.h`, `scef/src/FileManager.cpp`
- `scef/src/EncryptPipeline.cpp`, `scef/src/DecryptPipeline.cpp`
- `scef/include/CryptoManager.h`, `scef/src/CryptoManager.cpp` (light)

### Wave 1 Independent (run all in parallel)

**A. Browser**
- `scef/browser/src/{app.js, download.js, kdf.js}` — F-2 slot-0 KEK, F-3 dead readFragmented, F-4 status msg, F-7 password field, F-8 ZIP sanitize
- `scef/browser/build.py` — F-5 re.DOTALL
- `scef/browser/index.html` — F-6 password-section display:none
- `scef/browser/test/test_e2e_unlock_node.js` — tests F-3 constant-time

**B. POSIX NativeFile**
- `scef/src/NativeFile.cpp` — src F-2 default constructor body in `#else` block

**C. Docs (entire `scef/docs/` rewrite)**
- `api/scef-lib.md` — password type, LogLevel enum, remove phantom methods, add PasswordStrengthEstimator
- `gui.md` — password security section rewrite, signature, signals/properties/invokables, window size, LogsPage
- `cli.md` — `--password`, benchmark fix, missing flags
- `data-flows.md` — pipeline note, syncToDevice
- `container-format.md` — syncToDevice, line numbers
- `architecture.md` — SCEF_BUILD_BENCHMARKS removal, scef_lib sources, etc.
- `README.md` — LogsPage mention

**D. Standalone QML fixes (no controller dependency)**
- `scef/gui/qml/CreatePage.qml` — F-2 password clear, F-6 Back button disabled, F-10 URL display, F-17 KDF profile mapping (read from controller)
- `scef/gui/qml/FileListPage.qml` — F-8 selectedIndicesChanged double-emission

**E. C++ unit tests**
- `scef/tests/unit/test_scef.cpp` — tests F-7 byte-identity, F-11 binary verify 0x0000-0x0078
- `scef/tests/unit/test_password_strength.cpp` — tests F-15 conditionally tautological

**F. GUI CMakeLists**
- `scef/gui/CMakeLists.txt` — F-13 Qt minimum 6.8

### Wave 2: Core C++ (single coder, depends on nothing in Wave 1)

Owns: `Header.{h,cpp}`, `FileTable.{h,cpp}`, `FileManager.{h,cpp}`, `EncryptPipeline.cpp`, `DecryptPipeline.cpp`. Findings:

**Header**
- src F-4 KDF defaults match Standard profile via `KdfProfiles::getProfileParams(EKDFProfile::Standard)`
- src F-15 `buffer()` const
- src F-19 `NONCE_SIZE`/`AUTH_TAG_SIZE` to `size_t`
- src F-24 keep `getSaltData()` mutable but document as write-only

**FileTable**
- src F-3 `FileEntry::{size, offset, chunks}` + `addFileEntry` parameters → `uint64_t`
- src F-3 deserialize uses `.get<uint64_t>()`
- src F-5 in `deserialize`: if `next_write_offset_` is 0 and entries non-empty, recompute
- src F-16 duplicate name resolution: `(2)`, `(3)` numeric suffix; `unordered_set` lookup

**FileManager**
- src F-1 move `readFilesTable()` inside slot recovery loop with try/catch
- src F-3 `writeChunks` signature `uint64_t`
- src F-6 remove dead `passwordCopy`/restore in `readMeta`
- src F-7 use `std::filesystem::path` for path concatenation
- src F-8 validate `getContainerSize() >= MINIMAL_CONTAINER_SIZE` after authenticated read
- src F-9 `setKdfParams` log+clamp
- src F-11 remove duplicate capacity check from `init()`
- src F-14 remove redundant 4-byte magic pre-check in `trySlotMagic`
- src F-17 reject `1 <= encSize <= NONCE+TAG`; accept only 0 or full
- src F-21 free `computeSlotOffsets` calls free `computeSlotOffset` per iteration; remove unused singular if not needed
- src F-22 remove dead `container_size_param_`
- **NEW** add `inline std::string nextAvailableContainerPath(const std::string& dir)` free function in `FileManager.h`
- **CHANGED** `init()` first parameter changes from "directory" to a full file path semantics (interpret existing semantics, document)

**EncryptPipeline**
- src F-10 split `(!push() || isLast)` into two clear conditions

**DecryptPipeline**
- src F-7 use `std::filesystem::path` for path concat (output dir + safe name)
- src F-18 remove second `skipSlots(entry.offset)`; `entry.offset` is already skip-adjusted

### Wave 3: CLI + GUI controller (parallel after Wave 2)

**A. `scef/src/main.cpp`**
- src F-12 scrub `args.password` after copy
- src F-13 benchmark zero salt comment + replace volatile loop with `Botan::secure_scrub_memory`
- browser F-1 UTF-8 password conversion on Windows (`MultiByteToWideChar` + `WideCharToMultiByte(CP_UTF8)`)
- **NEW** `--name <filename>` flag for `create`; default uses `nextAvailableContainerPath(dir)`
- pass full file path to `FileManager::init()` (per locked decision 1)

**B. `scef/gui/ScefController.{h,cpp}`**
- gui F-1 move `init()` and setup into `runAsync` worker lambda for `createContainer`
- gui F-4 accept full file path in `openContainer` and `createContainer`
- gui F-5 restore `fileManager_` on async error before clearing state
- gui F-9 scrub intermediate `QByteArray` in `securePasswordFromQString`
- gui F-12 give `currentContainerPath` its own NOTIFY signal
- gui F-15 move `PasswordStrengthEstimator.h` include from `.h` to `.cpp`
- **NEW** `Q_INVOKABLE QString defaultContainerName(QString dir)` returning `nextAvailableContainerPath(dir)` filename
- **NEW** `Q_INVOKABLE QStringList containerFilesAtRow(int row)` (delegates to DriveListModel)
- gui F-11 add typed enum or fraction-visibility property so QML doesn't compare progress strings

**C. `scef/gui/DriveListModel.{h,cpp}`**
- gui F-7 wrap Win32 + filesystem calls in try/catch + use `std::error_code` overloads
- gui F-14 add Linux/POSIX path using `QStorageInfo::mountedVolumes()` filtered by `isReady()` and removable hint
- **CHANGED** `hasContainerAtRow(row)` → also expose `containerFilesAtRow(row)` returning `QStringList` of `*.scef` files in drive root

### Wave 4: GUI QML pages (parallel after Wave 3)

**A. `scef/gui/qml/Main.qml` + `StartPage.qml`**
- gui F-3 use plain path (no manual `file:///` prefix)
- gui F-16 remove `driveListRevision >= 0` tautology
- **NEW** scanning drive: if multiple `*.scef` files → list/picker dialog; if 1 → proceed; if 0 → disabled with helpful tooltip

**B. `scef/gui/qml/CreatePage.qml`**
- **NEW** filename input field, defaulting to `controller.defaultContainerName(destDir)` and refreshed when user changes destination
- pass full file path (dir + filename) to `controller.createContainer(...)`

### Wave 5: Integration tests (after Wave 2-4 stabilize)

Files: `scef/tests/integration/`
- conftest.py — F-13 fix FAST_KDF_ARGS comment
- test_create.py — F-1 spec slot formula + non-power-of-2 size; **NEW** byte-identity all-4-slots test
- test_errors.py — F-2 unconditional `returncode != 0` + zero-size file assertion
- test_kdf_profiles.py — F-5 binary verification of KDF params; F-12 remove dup `_create_with_kdf_profile`
- test_strength_warning.py — F-8 standardize on `--kdf-m`/`--kdf-t`/`--kdf-p`
- test_capacity_overflow.py — F-9 module-level → fixture; F-10 add header_version/file_count atomicity check
- run_bit_flip_test.py — F-16 cross-platform exe path
- **NEW** `test_auth_decrypt_ordering.py` — verify HMAC-then-DEK ordering via DEK-only and salt-only corruption (tests F-4)
- **NEW** `test_next_write_offset.py` — round-trip persistence of `next_write_offset` across reopens
- **NEW** `test_container_naming.py` — auto-numbering: `container.scef` → `container_1.scef` → `container_2.scef`

### Wave 6: Build + run all tests
- CMake configure + build (Debug, GUI on)
- Run `ctest --output-on-failure` for unit tests
- Run `pytest scef/tests/integration -v` for integration
- Some new tests will fail → trigger Wave 6b

### Wave 6b: Fix exposed production bugs
Spec-compliance tests added in Wave 5 may expose real bugs. Fix iteratively until all pass.

### Wave 7: code_reviewer
Run sonnet `code_reviewer` agent on final state. Address findings.

## Out of Scope (deferred Nitpicks)
- src F-19 NONCE_SIZE/AUTH_TAG_SIZE size_t (handled in Wave 2 actually — kept as Major-adjacent)
- src F-20 duplicate `unsupported_cipher_message` (cosmetic)
- src F-23 stoull exception handling
- gui F-13 Qt minimum bump to 6.8 (handled in Wave 1 actually)
- docs F-22 line numbers (handled in Wave 1 docs sweep)
- Browser F-9 chunk_size/created/modified spec gap
- Browser F-12 CONTAINER_FILENAME duplication
- Browser F-15 HMAC=KEK key separation (architectural, post-MVP)

## Total Coders Estimated
- Wave 1: 6 parallel coders
- Wave 2: 1 sequential coder
- Wave 3: 3 parallel coders
- Wave 4: 2 parallel coders
- Wave 5: 1 coder (one set of test files, can sequence within)
- Wave 6: build/test runs
- Wave 6b: 1-2 coders for any exposed bugs
- Wave 7: code_reviewer

Total: ~14-15 coder invocations across 7 waves.
