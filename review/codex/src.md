# SCEF Core Library Review (src + include) — Codex

## Executive Summary

The SCEF core library implements encryption primitives (Botan AEAD/HMAC) correctly but has critical gaps in crash resilience, bounds enforcement, and error propagation. The container layer—slot recovery, metadata validation, and write serialization—needs hardening before merge. Codex identified 15 issues across 5 severity tiers.

---

## Findings by Severity

### CRITICAL

#### [SCEF-001] `scef/src/FileManager.cpp:477` — Slot recovery accepts a header before validating its file table

**What:** `readMeta()` accepts the first slot whose header HMAC passes, then reads/decrypts the file table later at `FileManager.cpp:502-503` / `695-712`. A slot with valid header but corrupt/torn file table blocks fallback to healthy backup slots.

**Why it matters:** A crash between `writeHeaderAt()` and `writeFileTableAt()` in `writeFileTableToAllSlots()` (`386-390`) can make the container fail to open despite 3 valid backups. The entire crash-resilience strategy is defeated if the first slot with a valid header has a broken file table.

**Fix:** In the per-slot loop, verify HMAC, unwrap DEK, decrypt and parse that slot's file table all together; accept only a valid header+table pair. Move file table read/validation into the candidate-slot loop so invalid tables cause fallback to the next slot. Update tests that currently expect failure on slot0 table corruption.

---

#### [SCEF-002] `scef/src/FileManager.cpp:121` — Data writes are not bounded by `container_size`

**What:** `writeFragmented()` skips slots but never checks `cur + canWrite <= header_->getContainerSize()`. Capacity is computed earlier from `std::filesystem::file_size()` (`291-300`), while `EncryptPipeline` re-reads file size/content later (`EncryptPipeline.cpp:103-120`).

**Why it matters:** If a source file grows after the capacity check, SCEF can extend the sparse container past its fixed size, corrupting the slot layout and data integrity.

**Fix:** Enforce a hard max physical offset in `writeFragmented()` before writing each chunk. Snapshot input file sizes at capacity approval time, and validate they have not grown before writing. Alternatively, make the container auto-resizable (post-MVP).

---

#### [SCEF-003] `scef/include/FileManager.h:75` — Core library allows empty passwords

**What:** `FileManager::init()` defaults password to empty, and `CryptoManager::deriveKek()` explicitly derives from empty input (`CryptoManager.cpp:56-60`).

**Why it matters:** Direct library/GUI/test callers can create passwordless containers. An attacker with physical access to the USB drive can trivially extract all files without guessing a password, violating the core security model.

**Fix:** Reject empty passwords in `FileManager::create()` and `FileManager::open()` before any crypto operations. Update all tests to pass explicit test passwords (e.g., "test123").

---

### MAJOR

#### [SCEF-004] `scef/src/EncryptPipeline.cpp:58` — Background task exceptions can deadlock the pipeline

**What:** Reader/worker tasks are detached; exceptions before queue close or before `activeWorkers_` decrement are not propagated. The same pattern exists in `DecryptPipeline.cpp:45-60`, with `io.read()` able to throw at `DecryptPipeline.cpp:106`.

**Why it matters:** A corrupt input file or I/O error in a background task can cause the pipeline to hang indefinitely, leaving worker threads and queues in undefined state.

**Fix:** Wrap every task body in `try/catch`. On exception, publish an error chunk to the queue (new `PipelineTypes::ChunkType::ERROR`), decrement `activeWorkers_`, and guarantee queue closure. Use RAII guards (`std::scope_exit` or scope-based cleanup) to ensure cleanup happens.

---

#### [SCEF-005] `scef/src/FileManager.cpp:162` — KDF bounds are not enforced on create for core callers

**What:** Custom KDF params are stored unchecked in `setKdfParams()` (`174-178`), and create derives KEK directly (`199-202`). Bounds are only checked on open (`219-230`).

**Why it matters:** Library/GUI callers can request invalid or weak Argon2 settings (e.g., m=1 KiB) without detection. The container becomes vulnerable before it is even written.

**Fix:** Validate m/t/p bounds in `setKdfParams()` or immediately before `deriveKek()` on create, mirroring the open-path checks.

---

#### [SCEF-006] `scef/include/Header.h:182` — Header default profile contradicts KDF profile table

**What:** Header hardcodes `Standard` with `65536 KiB, t=3`, but `KdfProfiles.cpp:8` defines Standard as `1024 MiB, t=1`. Library callers that do not call `setKdfParams()` create mislabeled containers.

**Why it matters:** Container metadata is inconsistent with actual KDF parameters, causing confusion on reopen and incorrect benchmark interpretation.

**Fix:** Initialize Header from `getProfileParams(EKDFProfile::Standard)` at construction time. Remove duplicate hardcoded defaults.

---

#### [SCEF-007] `scef/src/FileManager.cpp:315` — `max_table_size` is unbounded and unaligned

**What:** CLI/core accept arbitrary `max_table_size` parameter; spec expects file table ≤65536 B. Non-4096-aligned or oversized values can make slot ranges overlap. The `skipSlots()` function only skips once (`101-108`).

**Why it matters:** Data can land inside reserved slot space, corrupting or overwriting headers and file tables.

**Fix:** Require `max_table_size == DEFAULT_MAX_TABLE_SIZE (65536)` for v1.0, or strictly validate: nonzero, ≤65536, 4096-aligned, and that 4 slots fit without overlap in the container.

---

#### [SCEF-008] `scef/src/NativeFile.cpp:243` — POSIX build is incomplete

**What:** `NativeFile::NativeFile()` is declared in `NativeFile.h:24`, but only the Windows branch defines it (`NativeFile.cpp:32`). The POSIX/Linux branch is missing.

**Why it matters:** Linux build can fail to link.

**Fix:** Add the POSIX constructor using `open()`, set flags, and handle errors. Include `<algorithm>` for `std::min`.

---

#### [SCEF-009] `scef/src/NativeFile.cpp:70` — Windows paths use ANSI APIs

**What:** `CreateFileA` and `std::string` paths are used; `FileManager.cpp:62` also builds paths by string concatenation.

**Why it matters:** Non-ASCII filenames (e.g., Cyrillic, CJK) are unreliable on Windows.

**Fix:** Use `std::filesystem::path`, `CreateFileW`, and native UTF-16 conversion (e.g., `std::filesystem::path::native()`).

---

#### [SCEF-010] `scef/src/main.cpp:194` — `--password` stores secrets in `std::string` and argv

**What:** CLI parses password into `ParsedArgs::password` and later copies it into `secure_vector` (`257-258`, `642-643`). Password remains in process args, shell history, and unsanitized heap memory.

**Why it matters:** Compromises password confidentiality on multi-user systems.

**Fix:** Remove `--password` CLI flag entirely, or restrict it to test builds only (behind `-DBUILD_TESTING`). Use stdin/pipe or prompt for interactive entry in production.

---

#### [SCEF-011] `scef/src/FileTable.cpp:67` — Missing `next_write_offset` falls back to 0

**What:** Older/malformed tables with files but no `next_write_offset` JSON field cause `add()` to resume at offset 0 (see `FileManager.cpp:580`, `610`).

**Why it matters:** `add()` can overwrite existing data.

**Fix:** If `next_write_offset` is absent, recompute it by scanning all file entries and finding the maximum physical end offset.

---

### MINOR

#### [SCEF-012] `scef/include/FileTable.h:21` — On-disk sizes use `size_t` in memory

**What:** FileEntry members `size`, `offset`, `chunks` are `size_t`, which can differ between 32-bit and 64-bit platforms.

**Why it matters:** Container portability across architectures.

**Fix:** Use `uint64_t` for all on-disk sizes to match the serialized format.

---

#### [SCEF-013] `scef/src/main.cpp:236` — Numeric CLI parsing is exception/overflow-prone

**What:** `stoul`/`stoull` exceptions escape `parseArgs()`, and `kdf_m_mib * 1024` can overflow before validation.

**Why it matters:** Unclear error messages and undefined behavior if overflow occurs.

**Fix:** Use a safe wrapper for `stoul` that catches exceptions; validate bounds before arithmetic.

---

#### [SCEF-014] `scef/src/FileManager.cpp:85` — Existing containers always open read-write

**What:** `list` and `extract` modes always open the container in read-write mode.

**Why it matters:** Fails on read-only media (USB drives with write-protect switches).

**Fix:** Add an `openMode` parameter (read-only vs read-write) to `open()`. Validate that write operations are not attempted in read-only mode.

---

### NITPICK

#### [SCEF-015] `scef/src/Header.cpp:119` — `Header::validate()` name overpromises

**What:** Method is named `validate()` but only checks magic bytes, not HMAC.

**Why it matters:** Misleading API contract.

**Fix:** Rename to `validateMagic()` or clearly document that HMAC verification happens elsewhere.

---

## Dead Code & Unused Symbols

- `FileManager::container_size_param_` is set at `FileManager.cpp:63` but never read.
- `computeSlotOffset()` in `FileManager.h:31` appears unused; only `computeSlotOffsets()` is called.
- `Header::to_string()` appears unused in reviewed core files (may be used in GUI or tests).

---

## Cross-Cutting Concerns

1. **Validation Split:** Security invariants are split between CLI (`main.cpp`) and core (`FileManager`). Core must never trust CLI and must enforce all rules independently. Example: KDF bounds.

2. **Crash Resilience:** The design stores 4 redundant slot pairs to survive crashes, but recovery logic is incomplete. A header with a broken file table blocks fallback to healthy backups (SCEF-001).

3. **Pipeline Error Handling:** Background reader/worker tasks lack structured error channels. Exceptions can leave queues in undefined state (SCEF-004).

4. **Path Encoding:** Windows ANSI APIs and Linux stub incomplete prevent reliable non-ASCII path handling. Impacts usability in non-English locales (SCEF-008, SCEF-009).

5. **Password Handling:** Plaintext password in argv, environment, and unsanitized heap (SCEF-010) weakens the security model.

---

## Spec Compliance Check

| Component | Expected | Found | Status |
|-----------|----------|-------|--------|
| Slot offsets | `floor(size*N/100/4096)*4096` | `FileManager.h:31-44` | OK (overflow risk noted) |
| HMAC coverage | Bytes `[0x00..0x9F]` | `Header.h:61-62`, `Header.cpp:132-135` | OK |
| Nonce freshness | 12B random per chunk | `CryptoManager.cpp:163-166`, `239-240` | OK |
| Argon2 bounds | m: 1–4M KiB, t: 1–100, p: 1–64 | Checked only on open | **ISSUE** |
| KEK usage | HMAC verify then DEK unwrap | `CryptoManager.cpp:148`, `FileManager.cpp:477-479` | OK |
| All 4 slots written | Sequential with fsync | `FileManager.cpp:386-390` | PARTIAL (table fallback broken) |
| File table format | `[Nonce 12B][JSON][Tag 16B]` | `FileTable.cpp:56-75` | OK |
| Data block format | `[Nonce 12B][Data ≤65K][Tag 16B]` | `EncryptPipeline.cpp:115-130` | OK |

---

## Verdict

**CHANGES_REQUESTED**

The core AEAD/HMAC encryption is sound, but the container layer has critical correctness and resilience issues that must be fixed before release:

### Top 5 Fixes (Priority Order)

1. **Validate header+file-table per slot before accepting recovery** (SCEF-001).
   - Move file table read into candidate-slot loop.
   - Only accept a slot if both HMAC and file table decrypt/parse successfully.

2. **Enforce container write bounds in `writeFragmented()`** (SCEF-002).
   - Check `cur + size <= header_->getContainerSize()` before each write.
   - Snapshot input file sizes at capacity approval; validate no growth.

3. **Reject empty passwords in core API** (SCEF-003).
   - Add validation in `FileManager::create()` and `open()`.
   - Update tests to pass explicit passwords.

4. **Add robust exception propagation/queue closure in pipelines** (SCEF-004).
   - Wrap task bodies in `try/catch`.
   - Publish error chunks; close queues via RAII.

5. **Move KDF and `max_table_size` validation into FileManager** (SCEF-005, SCEF-007).
   - Validate on both create and open paths.
   - Fix `max_table_size` enforcement (require DEFAULT or validate strictly).

---

## Notes for Developer

- Tests were not run; this is a read-only code review.
- Issues are categorized by impact: CRITICAL blocks production use, MAJOR breaks important features, MINOR affects edge cases, NITPICK is style/naming.
- Codex analyzed ~16K lines of C++ across 20+ source and header files.
- Focus was on spec compliance, security isolation, error handling, and cross-platform portability.

**Codex Reasoning:**

The library's encryption (AEAD, nonce generation, KEK derivation) is implemented correctly per spec. However, the metadata layer—slot recovery, bounds enforcement, and error propagation—needs hardening to make the crash-resilience promise real and to prevent data corruption or loss of confidentiality through invalid parameters or incomplete writes.
