# SCEF Test Suite Review — Deep Spec-Anchored Analysis

## Executive Summary

The SCEF test suite exhibits mixed quality: unit tests are specification-anchored and strong, while integration tests verify happy-path behavior but have critical gaps in spec-driven failure modes. Key issue: **many tests are tautological (encrypt → decrypt → assert equal)** or behavior-mirroring rather than asserting actual spec requirements. Silent implementation drift would pass substantial portions of the suite. The test philosophy conflicts with the user's critical feedback: "tests must verify spec compliance, not lock down current behavior."

---

## Test Catalog

### Unit Tests (scef/tests/unit/)

| Test File | Test Count | Verdict | Notes |
|-----------|-----------|---------|-------|
| `test_scef.cpp` | ~50 | MIXED | Header layout tests = SPEC_ANCHORED. Create/add/extract behavioral tests = BEHAVIOR_MIRROR (tautological). |
| `test_password_strength.cpp` | ~8 | WEAK | Asserts score/bits are returned; doesn't verify correctness of the strength formula or zxcvbn algorithm. |
| `test_native_file.cpp` | ~12 | BEHAVIOR_MIRROR | Tests file I/O round-trip; doesn't assert platform-specific path handling or Windows/Linux divergence. |

**Unit test philosophy:** The header layout tests (`HeaderLayoutTest` class) are excellent — they verify binary offsets, sizes, and magic bytes against spec Table 4.2. However, behavioral tests (create+add+extract) lock down the *current* behavior without asserting what the spec *requires*.

### Integration Tests (scef/tests/integration/)

| Test File | Test Count | Verdict | Coverage |
|-----------|-----------|---------|----------|
| `test_create.py` | ~25 | MODERATE | Happy-path: 4-slot magic, size constraints, multiple files. Missing: minimum size *enforced* (rejected), overflow prevention, password validation. |
| `test_add.py` | ~12 | WEAK | Tautological: add file → extract → assert equal. Doesn't verify file table integrity, next_write_offset correctness, or slot-skipping logic. |
| `test_extract.py` | ~8 | WEAK | Extract round-trip (tautological). Missing: sparse extraction, cross-platform path normalization, large file stream validation. |
| `test_list.py` | ~6 | WEAK | Lists files in container; asserts they appear in output. Doesn't verify JSON schema, field correctness (size/offset), or corrupted table recovery. |
| `test_roundtrip.py` | ~10 | BEHAVIOR_MIRROR | Create → add → extract all files; tautological. Missing: intermediate state integrity checks. |
| `test_roundtrip_100files.py` | ~2 | WEAK | Stress test; no assertions on nonce uniqueness, block boundaries, or slot boundary crossing. |
| `test_capacity_overflow.py` | ~25 | MAJOR GAPS | Tests rejection of over-capacity adds; **missing**: assertion that container state is unchanged (atomic failure), rollback verification, partial writes prevented. |
| `test_header_resilience.py` | ~20 | STRONG | 4-slot corruption scenarios with fallback verification. **BEST TEST GROUP.** Spec-anchored. |
| `test_kdf_profiles.py` | ~35 | MODERATE | Tests all 4 profiles; **missing**: verification that Argon2 params actually reach the hash function (mocking issue), weak-password warnings, memory consumption. |
| `test_kuznechik.py` | ~4 | WEAK | Creates container with Kuznechik cipher; missing: cross-mode rejection (browser can't decrypt), proper GCM tag validation. |
| `test_cross_mode.py` | ~3 | CRITICAL_GAP | Browser ↔ CLI cross-decryption; missing: WebCrypto-only limit (no Kuznechik in browser), WASM memory bounds checking. |
| `test_errors.py` | ~10 | WEAK | Wrong password, missing files, etc.; missing: specification-required error codes, message content. |
| `test_strength_warning.py` | ~4 | BEHAVIOR_MIRROR | GUI password warning dialog appears; missing: threshold correctness (zxcvbn), meetsRecommendation logic. |
| `run_bit_flip_test.py` | ~1 | CRITICAL_GAP | Flips single bits in container and checks recovery. **This is excellent concept but has no assertions** — just prints output. |

---

## Findings by Severity

### CRITICAL — Spec Drift Will Pass Tests

**[C-001]** `test_roundtrip.py` — Tautological Round-Trip
- **What:** `test_roundtrip_all_files_via_full_cycle()` creates container, adds, extracts, compares byte buffers. If code accidentally loses chunks or corrupts file offsets, the test still passes because it only asserts encryption→decrypt equality, not spec-required structure.
- **Why it matters:** Spec requires file table JSON to include accurate `offset`, `chunks`, `checksum_sha256`. If implementation starts writing wrong offsets but still encrypts/decrypts them, test passes and silent data loss happens.
- **Fix:** Assert file table JSON fields: verify `offset` points to correct encrypted block, `chunks` matches calculated count, `checksum_sha256` matches.

**[C-002]** `test_capacity_overflow.py` — No Atomicity Verification
- **What:** Tests `test_create_oversized_add_rejected()` verifies that add() rejects overflow. **Missing:** assertion that container state (file table, header, data) is unchanged after rejection. Implementation could partially write header before checking, corrupting the container.
- **Why it matters:** Spec requires transaction atomicity: "reject before partial write." If implementation writes header slot #0, then rejects, slot #0 and #1 become inconsistent.
- **Fix:** Add: (1) read container size/file count before add(), (2) attempt add() with overflow, (3) re-read and assert size/count unchanged.

**[C-003]** `scef/tests/integration/run_bit_flip_test.py` — No Assertions
- **What:** Flips random bits in encrypted container, calls `scef list/extract`. Prints output but **has no assertions**. Test always passes.
- **Why it matters:** Spec requires HMAC protection: "authenticate-then-decrypt." If HMAC verification is accidentally removed, bit-flips silently corrupt plaintext — test won't catch it.
- **Fix:** Assert that: (1) list/extract *fail* when any 3 slots are bit-flipped, (2) at least one slot's HMAC must catch corruption.

**[C-004]** `test_header_resilience.py:test_TC_HDR_09_corrupt_hmac_slot0_falls_back` — Only Tests Magic+HMAC, Not Nonce
- **What:** Corrupts HMAC in slot 0, verifies fallback to slot 1. **Missing:** does NOT corrupt HMAC-protected fields (DEK, cipher_id, KDF params). If implementation skips HMAC verification, test passes.
- **Why it matters:** Spec 4.2.4 covers HMAC fields: bytes [0x0000..0x009F]. If DEK or salt are corrupted but HMAC skipped, wrong key silently decrypts garbage.
- **Fix:** Corrupt multiple HMAC-protected fields (DEK bytes + salt) together; assert extraction fails if HMAC is skipped.

**[C-005]** `test_kdf_profiles.py` — Params Not Verified at Hash Call
- **What:** Tests set `--kdf-profile fast` (m=256 MiB, p=4). **Missing:** assertion that `Botan::PasswordHashFamily::from_params(256*1024, 1, 4)` is *actually called* with correct values. If implementation hard-codes (m=64MiB, p=1), test passes (roundtrip succeeds).
- **Why it matters:** Spec 4.3.1 requires adaptive profiles. Weak default params silently override user's security choice.
- **Fix:** Mock or spy on Argon2 calls; assert `from_params(m, t, p)` invoked with expected values before hash.

---

### MAJOR — Weak Test Quality / High Coverage Gaps

**[M-001]** `test_create.py:test_all_four_slots_start_with_scef_magic` — Slot Offset Formula Unchecked
- **What:** Reads file, checks offsets `[0, size/4, size/2, 3*size/4]` for magic. **Missing:** spec's actual formula: `floor(size * N% / 100 / 4096) * 4096`. Python code uses naive division; doesn't verify slot offsets match computed formula.
- **Example:** For size=1,000,000, correct offset for slot 1 = `(1000000 * 25 / 100 / 4096) * 4096 = 60416`. Python test checks `1000000 // 4 = 250000` (wrong).
- **Fix:** Import or implement spec formula; assert computed offsets match actual slot magic positions.

**[M-002]** `test_add.py` — File Table next_write_offset Not Verified
- **What:** Tests add file → extract → verify content. **Missing:** assertion that file table's `next_write_offset` is correctly updated and used on the next add(). If implementation ignores this field, add() after container close/reopen would overwrite previous data.
- **Why it matters:** Spec 4.4: `next_write_offset` is persisted to resume writes without rescanning. Silent loss of this field breaks multi-add workflows.
- **Fix:** (1) Create container, add file A. (2) Close/reopen. (3) Add file B. (4) Extract both; assert A is intact (was not overwritten).

**[M-003]** `test_list.py` — File Table JSON Schema Not Validated
- **What:** Runs `scef list`, parses output, checks filenames. **Missing:** (1) validation that parsed JSON matches schema (must have `name`, `size`, `offset`, `chunks`, `checksum_sha256`), (2) no assertion on `size` field (could be wrong), (3) no checksum validation.
- **Why it matters:** If implementation writes malformed JSON or wrong checksums, list runs but users can't verify integrity.
- **Fix:** Parse container's encrypted file table directly (decrypt with KEK); validate all fields present and types correct.

**[M-004]** `test_password_strength.py` — Strength Estimation Not Spec-Anchored
- **What:** Tests `estimatePasswordStrength("test123")` returns a score. **Missing:** (1) threshold values (where does "weak" begin?), (2) verification against zxcvbn reference, (3) missing 96.9–99.8% compromise stat from Tippe 2025 (feedback_test_philosophy).
- **Why it matters:** If score calculation drifts, users don't get accurate warnings.
- **Fix:** Assert known passwords have expected scores: e.g., "password" < "MyP@ssw0rd!2024" < "random-char-string-32".

**[M-005]** `test_native_file.cpp` — Windows/Linux Path Handling Not Exercised
- **What:** Tests file I/O round-trip with basic filenames. **Missing:** (1) paths with backslashes (Windows), (2) forward slashes (Linux), (3) mixed separators, (4) relative vs absolute paths.
- **Why it matters:** Cross-platform path normalization could silently fail: `C:\data\file.txt` stored with `\` might extract to `C:/data/file.txt` on Linux.
- **Fix:** Create container on Windows with `C:\dir\file.txt`; verify extraction normalizes to platform-native separator.

**[M-006]** `test_kuznechik.py` — Browser Mode Decryption Not Tested
- **What:** Creates container with Kuznechik cipher. **Missing:** assertion that browser viewer *rejects* Kuznechik containers (WebCrypto doesn't support it).
- **Why it matters:** Spec 4.6.1: browser mode = AES-256-GCM only. If browser silently falls back to wrong cipher, data corruption follows.
- **Fix:** Create Kuznechik container, load in browser viewer, assert error message.

**[M-007]** `test_cross_mode.py` — WASM Memory Limit Not Tested
- **What:** Cross-mode decrypt tests don't verify WASM memory bounds. **Missing:** (1) create container with `m=2047 MiB` (browser-friendly max), (2) attempt to open in browser, (3) assert success. Then create with `m=2048 MiB` (over limit), (4) assert browser rejects.
- **Why it matters:** Spec notes browser WASM arrays cap at 2^31 bytes. Silent OOM or truncation corrupts KDF.
- **Fix:** Add pytest + headless browser test; verify browser message on KDF memory overflow.

---

### MINOR — Coverage Gaps

**[m-001]** `test_create.py` — Minimum Container Size Not *Enforced*
- **What:** Tests size >= MIN_SIZE. **Missing:** assertion that create() *rejects* size < MIN_SIZE (4 * 69632 bytes).
- **Fix:** Call with size=1000 (too small); assert error; verify container not created.

**[m-002]** `test_extract.py` — Sparse File Extraction Not Tested
- **What:** Extracts all files or single file. **Missing:** multiple select (extract subset of 5 files = files {1,3,5}), verify other files remain in container.
- **Fix:** Add file 1-5, extract only 2+4, re-open and verify 1,3,5 still present.

**[m-003]** `test_roundtrip_100files.py` — Nonce Uniqueness Not Verified
- **What:** Adds 100 files; encrypts 100+ chunks. **Missing:** assertion that no nonce repeats. NIST allows 2^32 invocations per key; this test is below that, but principle should be checked.
- **Fix:** Patch CryptoManager::encrypt() to log nonces; assert all unique.

**[m-004]** `test_header_resilience.py` — No Test for Mixed Corruption (magic + HMAC)
- **What:** Tests corrupt magic *or* corrupt HMAC separately. **Missing:** corrupt magic in slot 0, HMAC in slot 1, etc. — pathological interleaving.
- **Fix:** Add test that corrupts slot 0 magic + slot 1 HMAC simultaneously; verify recovery still works.

**[m-005]** `test_native_file.cpp` — Teardown Not Guaranteed
- **What:** Uses `make_temp_dir()` and `fs::remove_all()` in TearDown. **Missing:** if test crashes, temp dir leaks. Uses `fs::temp_directory_path()` which is unpredictable.
- **Fix:** Use RAII temp dir pattern (scoped_temp_dir or std::filesystem::temp_directory_path with UUID).

---

## Coverage Gaps — Uncovered Spec Aspects

| Spec Aspect | Code Location | Test Coverage? | Gap & Impact |
|-------------|----------------|----------------|--------------|
| **Slot offset formula** | `FileManager.h:27` | WEAK | test_create.py uses naive division; doesn't match spec formula. Slot #1 at 25% could be miscomputed. |
| **All 4 slots written + flushed** | `FileManager.cpp:writeFileTableToAllSlots` | NONE | No test verifies `flush()` between slots. Container could have stale slot #2 after crash. |
| **HMAC computed on [0x0000..0x009F]** | `CryptoManager.cpp:computeHmac` | WEAK | test_header_resilience corrupts HMAC field but not HMAC-protected payload. Missing: verify HMAC covers all required bytes. |
| **Nonce freshness (never reused per key)** | `CryptoManager.cpp:encrypt()` | NONE | No test verifies nonce uniqueness across chunks. Could loop/repeat without detection. |
| **File table size ≤ 65536 B limit** | `Header.h:POSITION_FILE_TABLE_SIZE` | NONE | No test attempts to add enough files to overflow max_table_size. Rejection not verified. |
| **KDF profile params reach hash call** | `CryptoManager.cpp:deriveKek()` | WEAK | test_kdf_profiles sets params but doesn't spy on Botan::PasswordHashFamily::from_params(). Default could silently override. |
| **Kuznechik cipher path exercised** | `CryptoManager.cpp:encrypt() with Kuznechik` | WEAK | test_kuznechik.py creates container but doesn't verify Kuznechik is used (could fall back to AES). |
| **Password scrubbing via secure_scrub_memory** | `CryptoManager.cpp:~CryptoManager()` | NONE | No test verifies password buffer is zeroed. Could leak in crash dumps. |
| **Bit-flip recovery (slot fallback)** | `FileManager.cpp:readMeta()` | MODERATE | run_bit_flip_test.py flips bits but has NO ASSERTIONS. Test always passes. |
| **Capacity overflow before partial write** | `FileManager.cpp:add()` | WEAK | test_capacity_overflow rejects, but doesn't verify container state unchanged. Partial write could corrupt. |
| **Cross-platform path normalization** | `ScefController.cpp:toLocalPath()` | NONE | No test with mixed separators or relative paths on Windows vs Linux. |
| **Browser WebCrypto-only, no Kuznechik** | `scef/browser/src/app.js:79-85` | WEAK | Check for Kuznechik exists but no test exercises it. Browser could silently support unsupported cipher. |
| **Container minimum size enforced** | `FileManager.cpp:init()` | WEAK | test_create verifies size >= MIN; missing: size < MIN is rejected. |
| **Cross-mode decrypt (browser ↔ CLI)** | `test_cross_mode.py` | WEAK | Tests exist but missing: WASM memory bounds, non-AES rejection. |
| **File table JSON schema (next_write_offset)** | `FileTable.cpp:serialize()` | NONE | No test decrypts and validates file table JSON structure. Missing field or corruption not caught. |

---

## Dead/Disabled Tests

None detected. All test functions are active (no `#if 0`, `skip()`, or `xfail` patterns found).

---

## Top 5 Highest-Leverage Tests to Add/Fix

### 1. **Atomicity of add() Under Capacity Overflow** (CRITICAL)
**Why:** Current test verifies rejection but not that container is unchanged. Partial writes silently corrupt containers in the field.
- **Implementation:** (1) Read header_version & file_count before add(). (2) Attempt add() with file that overflows. (3) Re-read and assert header_version & file_count unchanged. (4) Verify all 4 slots are identical (no stale slot).
- **Impact:** Catches silent corruption from incomplete writes.

### 2. **KDF Profile Parameter Propagation to Argon2** (CRITICAL)
**Why:** If implementation hard-codes KDF params, weak profiles silently become strong (or vice versa), breaking adaptive security design.
- **Implementation:** Mock/spy on `Botan::PasswordHashFamily::from_params()`. For each profile (browser, fast, standard, high), assert correct (m, t, p) tuple is passed. Verify Argon2 time scales with m.
- **Impact:** Catches silent override of user-selected security level.

### 3. **Slot-Skipping Logic in Multi-Block Files** (MAJOR)
**Why:** Data blocks must skip over slot reserved areas transparently. Silent corruption if slot boundaries cross block boundaries.
- **Implementation:** Create 16 MiB container with slot boundaries at 4 MiB each. Add file that straddles a slot (ends in block before slot, resumes after). Extract and verify byte-perfect match. Verify all chunks belong to correct file.
- **Impact:** Catches silent data loss at slot boundaries.

### 4. **HMAC-Protected Field Coverage (DEK, Salt, Cipher ID)** (MAJOR)
**Why:** If HMAC verification is skipped, corrupted DEK/cipher silently produces garbage plaintext.
- **Implementation:** For each HMAC-protected field (bytes [0x00–0x9F]), corrupt it individually (while keeping magic valid). Assert list/extract *fails* when reading from that slot. Verify only fallback slots work.
- **Impact:** Catches silent HMAC bypass.

### 5. **File Table Integrity (next_write_offset, checksums)** (MAJOR)
**Why:** File table JSON fields could be silently corrupted. Without validation, users can't detect silent data loss during add()/extract.
- **Implementation:** (1) Create container, add file A. (2) Close/reopen. (3) Decrypt file table from slot 0 using KEK. (4) Assert next_write_offset points to correct offset (start of slot 1). (5) Assert checksum_sha256 matches recomputed hash. (6) Add file B. (7) Verify A's offset/chunks haven't changed.
- **Impact:** Catches silent corruption of metadata.

---

## Verdict

**The test suite is **incomplete and spec-compliant only in header layout**. Integration tests are largely tautological and behavior-mirroring. Substantial implementation drift — especially in HMAC bypass, atomicity, KDF params, and file table corruption — would pass the current suite. User feedback is justified: tests must assert spec requirements, not just lock current behavior.**

**Recommended immediate action:** Fix tests [C-001] through [C-005] and add tests [1]–[5] above. Rerun against intentional bugs (e.g., comment out HMAC check, hard-code KDF m=64) to verify tests catch them.
