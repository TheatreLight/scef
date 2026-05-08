# SCEF Test Suite Review

## Executive Summary

The test suite is substantial and covers a wide range of scenarios, but it has a fundamental structural problem: **most tests verify behavior rather than spec compliance**. The integration tests are the worst offenders — they overwhelmingly test "does it round-trip?" and almost never pin down the binary format, crypto ordering, or invariants required by the spec. A silent drift in slot-offset arithmetic, HMAC placement, or nonce format would pass all integration tests as long as the CLI still round-trips. The unit tests in `test_scef.cpp` are meaningfully better but have their own gaps. Browser tests are diagnostic scripts masquerading as tests. The overall verdict: **this test suite would not catch a large class of spec divergences**.

---

## Test Catalog

### `scef/tests/unit/test_native_file.cpp`
**Count:** 14 tests | **Purpose:** NativeFile cross-platform I/O correctness | **Verdict:** Good

| Test | Assertion strength |
|---|---|
| `CreateTruncateNewFile_IsOpen` | Behavioral — verifies isOpen() after create |
| `CreateTruncateExistingFile_TruncatesToZero` | Spec-anchored — verifies truncate semantics |
| `OpenExistingNonExistent_Throws` | Error path — correct |
| `OpenReadOnly_WriteThrows` | Error path — correct |
| `RoundTripAtOffset0` | Tautological — write then read same data |
| `RoundTripAtOffset1000` | Tautological — write then read same data |
| `ReadAtPastEOF_Throws` | Error path — correct |
| `ReadSomePastEOF_ReturnsZero` | Spec-anchored — verifiable postcondition |
| `ReadSomePartial_ReturnsRemaining` | Weak — `EXPECT_LE(got, 5u)` allows returning 1 byte as pass |
| `PreallocateSparse_1MiB_SizeCorrect` | Good — verifies size AND zero content |
| `PreallocateSparse_200MiB_IsFast` | Time-dependent — flaky in slow CI/VM |
| `SyncToDevice_OpenFile_NoThrow` | Behavioral — no-throw is barely a spec assertion |
| `SyncToDevice_ClosedFile_NoThrow` | Behavioral — no-throw is barely a spec assertion |
| `MoveConstructor_SourceClosed_TargetUsable` | Good — verifies move semantics correctly |
| `MoveAssignment_OldTargetClosed_SourceClosed` | Good — verifies move semantics correctly |
| `AfterClose_IsOpenFalse` | Good |

---

### `scef/tests/unit/test_password_strength.cpp`
**Count:** 7 tests | **Purpose:** PasswordStrengthEstimator scoring | **Verdict:** Weak

| Test | Assertion strength |
|---|---|
| `KnownWeakPassword` | Good — checks score, bits, meetsRecommendation, warning |
| `WheelerExampleTr0ub4dor` | Weak — wide range `[25.0, 50.0]` passes with any reasonable estimator |
| `DicewarePassphrase` | Weak — checks score>=3, bits>30 but these are very loose bounds |
| `RandomLongPassword` | Behavioral — score == 4 locks current behavior, not a spec requirement |
| `ProfileThresholdsMatchTable` | Good spec-anchored — exact numeric values from the design table |
| `EmptyPasswordIsRejected` | Good |
| `HighProfileRequiresHigherScore` | Conditionally tautological — skips assertion if score != 3 |

---

### `scef/tests/unit/test_scef.cpp`
**Count:** 22 tests | **Purpose:** Header binary layout, slot arithmetic, container ops, Kuznechik | **Verdict:** Good, but gaps remain

| Test | Assertion strength |
|---|---|
| `FileTableSizeAt0x0080_IsUint32` | Spec-anchored — byte-exact at correct offset |
| `MaxTableSizeAt0x0084_Exists` | Spec-anchored — correct offset |
| `FileCountAt0x0088` | Spec-anchored — correct offset |
| `BlockSizeAt0x008C` | Spec-anchored — correct offset |
| `HeaderVersionAt0x0090` | Spec-anchored — correct offset |
| `FlagsAt0x0094` | Spec-anchored — checks zero, not arbitrary value |
| `Reserved0At0x0098_IsZero` | Spec-anchored — byte-by-byte zero check |
| `ReadAcceptsUnknownCipherIdByte` | Good design contract test |
| `NoFileTableOffsetField` | Spec-anchored — verifies removed field stays removed |
| `FileTableSizeIsUint32_Not64` | Spec-anchored — guards against width regression |
| `ContainerSizeIsFixedAtCreation` | Good — checks file size == header.container_size |
| `FourHeaderSlotsWithMagic` | Good but uses wrong formula (see Finding C-1 below) |
| `AddIncrementsHeaderVersion` | Good spec-anchored |
| `FileTableSizeIncludesNonceAndTag` | Spec-anchored — minimum 28 bytes |
| `FileTableStoredInSlotNotAfterData` | Weak — only checks that HEADER_SIZE offset is non-zero |
| `OriginalFileIntactAfterAdd` | Tautological roundtrip |
| `ThreeSequentialAddsAllExtractable` | Tautological roundtrip |
| `MultiBlockFileIntactAfterAdd` | Tautological roundtrip |
| `KuznechikRoundtrip` | Good — checks cipher_id byte == 0x02 after create |
| `CorruptCipherIdInSlot0FallsBackToSlot1` | Good — spec fallback behavior |
| `ValidateReturnsTrueForValidHeader` | Behavioral — trivially true after serialize |
| `InitDoesNotCreateContainerForRead` | Good spec-anchored error path |
| `KuznechikGCM_EnumValueExists` | Spec-anchored — exact byte value |
| `KDFProfiles_AllFourDefined` | Spec-anchored — exact enum values 1-4 |
| `EmptyFileAppearsInTable` | Good — checks size==0 AND chunks==0 |
| `EmptyFileExtractedCorrectly` | Good roundtrip with empty file edge case |

---

### `scef/tests/integration/conftest.py`
**Count:** 0 tests (infrastructure) | **Verdict:** Good overall, one issue

`FAST_KDF_ARGS = ["--kdf-m", "1", "--kdf-t", "1", "--kdf-p", "1"]` — passes m=1 KiB to Argon2id. This is 1 KiB, not 1 MiB. The comment says "m >= 8 MiB" is the CLI minimum, but then passes 1. Either the CLI silently accepts it (undocumented bypass) or these tests never run real KDF validation. This is a fixture-level bug that obscures whether the minimum enforcement works.

---

### `scef/tests/integration/test_create.py`
**Count:** 23 tests | **Purpose:** `scef create` CLI | **Verdict:** Weak

Most tests assert only that `container.scef` exists or that file size equals the requested size. The slot magic check in `test_all_four_slots_start_with_scef_magic` uses `size // 4`, `size // 2`, `(size * 3) // 4` — this is **not the spec formula**. The spec formula is `floor(container_size * N / 100 / HEADER_SIZE) * HEADER_SIZE`. For many container sizes these produce identical results but they diverge at non-power-of-two sizes.

| Test | Assertion strength |
|---|---|
| `test_container_file_is_created` | Trivially behavioral — file exists |
| `test_container_file_has_minimum_size` | Spec-anchored |
| `test_container_file_size_matches_requested` | Spec-anchored |
| `test_container_starts_with_scef_magic` | Spec-anchored |
| `test_all_four_slots_start_with_scef_magic` | Spec-anchored but **wrong slot formula** |
| `test_container_created_for_two_files` | Behavioral — file exists only |
| `test_container_created_for_three_files` | Behavioral — file exists only |
| `test_container_has_correct_size_with_multiple_files` | Spec-anchored |
| `test_binary_file_container_created` | Behavioral — file exists only |
| `test_all_zero_bytes_file` | Behavioral — file exists only |
| `test_all_ones_bytes_file` | Behavioral — file exists only |
| `test_empty_file_container_created` | Behavioral — file exists only |
| `test_empty_file_container_has_minimum_size` | Spec-anchored |
| `test_large_file_two_blocks` | Behavioral — file exists only |
| `test_large_file_fractional_last_block` | Behavioral — file exists only |
| All custom max_table_size tests (6) | Mixed — some spec-anchored, some behavioral |
| All missing-argument error tests (5) | Good spec-anchored error paths |

---

### `scef/tests/integration/test_add.py`
**Count:** 14 tests | **Purpose:** `scef add` CLI | **Verdict:** Mostly behavioral

All happy-path tests reduce to "does the filename appear in `scef list` output?" and "does extract return the right bytes?". No test checks that the header_version incremented, that all 4 slots were updated, that the file table was not written past `max_table_size`, or that `next_write_offset` was advanced correctly.

---

### `scef/tests/integration/test_roundtrip.py`
**Count:** 17 tests | **Purpose:** End-to-end create→extract data integrity | **Verdict:** Tautological

Every test is: write known bytes → create container → extract → compare bytes. The spec requires AES-256-GCM authenticated encryption. These tests pass even if the implementation used a broken cipher that produces the same ciphertext every time, as long as the round-trip is self-consistent. The only thing caught is total failure. These are important smoke tests but they are **not spec compliance tests**.

---

### `scef/tests/integration/test_header_resilience.py`
**Count:** 25 tests | **Purpose:** 4-slot fallback resilience | **Verdict:** Good to excellent

This is the best file in the integration suite. It directly tests the crash-resilience spec behavior by corrupting specific bytes. Tests TC-HDR-01 through TC-HDR-15d cover single/multiple slot corruption of magic, HMAC, DEK, and file table. Slot-offset arithmetic is verified in a dedicated class. The slot_offset() helper in Python mirrors the C++ formula correctly.

**Weakness:** `test_TC_HDR_12_corrupt_file_table_slot0_only_slot1_plus_intact` documents an incorrect design behavior (no file-table-level independent fallback) without testing that slots 1-3 file tables are used instead — it just asserts failure. This is spec-documenting, not spec-testing.

---

### `scef/tests/integration/test_errors.py`
**Count:** 21 tests | **Purpose:** Error paths, wrong password, corrupt containers | **Verdict:** Good

`test_wrong_password_does_not_extract_garbage` is the only test in the suite that even tries to assert a security property (auth enforcement). However, it has a critical weakness: it only checks `if extracted.exists()` and then asserts `actual != expected`. It does **not** assert `returncode != 0` when the file doesn't exist, only `result.returncode != 0` in the else branch. If AES-GCM authentication fails silently and writes zeros, the test passes because zeros != expected.

---

### `scef/tests/integration/test_kdf_profiles.py`
**Count:** 22 tests | **Purpose:** KDF profile CLI flags | **Verdict:** Mostly behavioral

Tests confirm that named profiles open containers correctly and that wrong passwords fail. `TestCrossProfileOpen` is the most important test here — it verifies that KDF params are read from the header, not from code defaults. However, **no test verifies that the correct KDF parameter bytes (m_kib, t, p) are actually stored in the header binary at offsets 0x0010–0x001B**. The suite only tests that a container created with profile X can be opened again — it would pass even if the profile name was stored but the params were always defaulted to Standard.

The benchmark output tests (`test_benchmark_output_contains_*`) are fragile string-in-string checks with no numeric assertion. A benchmark that prints "fast: 0ms" satisfies every test.

---

### `scef/tests/integration/test_kuznechik.py`
**Count:** 6 tests | **Purpose:** Kuznechik-GCM cipher path | **Verdict:** Good

`test_header_cipher_byte_for_kuznechik_and_aes` directly reads byte 0x000C and asserts it equals 0x02/0x01 — this is proper spec-anchored testing. `test_kuznechik_cipher_is_sticky` verifies that a subsequent `add` inherits the cipher from the header. `test_cipher_header_tamper_makes_container_unreadable` corrupts cipher_id in all 4 slots and verifies failure with "authentication" or "hmac" in output.

**Gap:** No test verifies that the cipher_id byte is written identically to all 4 slot headers — only slot 0 is read in `_header_cipher_byte`.

---

### `scef/tests/integration/test_cross_mode.py`
**Count:** 1 test | **Purpose:** CLI→browser cross-mode compatibility | **Verdict:** Good but infrastructure-dependent

The test is well-designed and important for the thesis claim. It skips gracefully when Node is unavailable. It checks three separate Node scripts and requires specific stdout substrings. However it uses `--kdf-profile fast` for create, meaning the cross-mode test only validates the "fast" profile. The "browser" profile (m=64 MiB, t=1, p=1) is the one most likely to be used in real cross-mode scenarios and is not tested here.

---

### `scef/tests/integration/test_list.py`
**Count:** 10 tests | **Purpose:** `scef list` output | **Verdict:** Behavioral

All tests check that filenames appear in stdout. No test parses the size, checksum, or chunk count from list output to verify they match the original file.

---

### `scef/tests/integration/test_extract.py`
**Count:** 13 tests | **Purpose:** `scef extract` correctness | **Verdict:** Good — tautological but important

Byte-for-byte comparison on extract is the most reliable correctness signal available from the CLI. Tests cover text, binary, empty, and large files. Error paths are well covered.

---

### `scef/tests/integration/test_capacity_overflow.py`
**Count:** 10 tests | **Purpose:** Container capacity enforcement | **Verdict:** Excellent spec-anchored

This file is the best example of spec-driven testing. It derives capacity constants from the spec formula, validates preconditions with module-level assertions, and tests both failure modes (too small) and success modes (just fits). TC-CAP-07 and TC-CAP-08 are particularly important and test the add-overflow and post-failure state invariants.

---

### `scef/tests/integration/test_roundtrip_100files.py`
**Count:** 1 test (marked `@pytest.mark.slow`) | **Purpose:** 100-file stress roundtrip | **Verdict:** Good stress test, tautological

Uses SHA-256 comparison after full extract. Verifies the file table stores 100 names and all match. This is important for catching issues at scale (file table overflow, next_write_offset bugs).

---

### `scef/tests/integration/test_strength_warning.py`
**Count:** 8 tests | **Purpose:** Password strength warning CLI behavior | **Verdict:** Good

Tests verify specific stderr substrings, exit codes, and absence of the container file after rejection. `FAST_STRENGTH_KDF_ARGS` uses flags `--kdf-m-cost`, `--kdf-t-cost`, `--kdf-parallelism` which differ from the flag names in conftest.py (`--kdf-m`, `--kdf-t`, `--kdf-p`) — this is either a dead code path or a naming inconsistency.

---

### `scef/tests/integration/run_bit_flip_test.py`
**Count:** 1 scenario | **Purpose:** Standalone regression script | **Verdict:** Redundant

Duplicates TC-HDR-01 in `test_header_resilience.py` and `test_list_container_single_bit_flip_in_header` in `test_errors.py`. Not integrated into the pytest suite. Has no teardown (relies on `tempfile.TemporaryDirectory` context manager, which is correct). The SCEF_BIN path uses `build/debug/scef.exe` with a hardcoded extension — fails on Linux.

---

### Browser Tests

#### `test_header_node.js`
**Count:** 1 scenario | **Purpose:** Parse slot-0 header from real container | **Verdict:** Diagnostic, not a test

Prints parsed values to stdout and checks `validCount > 0` for exit code 0. No assertion on field values against known-good expectations. If the JS parser reads the wrong offset for `kdf_m_kib`, it will print a wrong number and still pass.

#### `test_crypto_node.js`
**Count:** 2 checks | **Purpose:** KEK derivation + HMAC cross-implementation | **Verdict:** Good spec-anchored

This is the only test that verifies **byte-exact agreement** between C++ (Botan Argon2id) and JS (hash-wasm). Requires `test_vectors.json` generated by `generate_vectors.cpp`. Critical for the thesis claim of browser compatibility.

#### `test_filetable_node.js`
**Count:** 1 scenario | **Purpose:** File table decryption from real container | **Verdict:** Diagnostic

Decrypts and prints the file table. Only asserts "decrypted and parsed successfully" (no exception). Does not verify that parsed field values match what was written by the CLI. If the JSON key names changed, this test would fail — but if the offset arithmetic was wrong, it would still print garbage and pass.

#### `test_download_node.js`
**Count:** 1 scenario, N file sub-checks | **Purpose:** Full file decryption + SHA-256 | **Verdict:** Good spec-anchored

The SHA-256 comparison against the stored checksum is a real correctness check. This test would catch any broken cipher integration, wrong nonce/tag layout, or slot-skipping bug in JS. Used as a subprocess in `test_cross_mode.py`.

#### `test_e2e_unlock_node.js`
**Count:** 3 sequential checks | **Purpose:** KEK → HMAC → DEK unlock sequence | **Verdict:** Good but HMAC check is non-constant-time

The HMAC comparison at line 82-84 uses a plain byte loop with early exit — this is a timing side-channel in test infrastructure (not production, but documents the wrong pattern). The test correctly verifies the authenticate-then-decrypt order (HMAC before DEK unwrap).

---

### `scef/browser/test/generate_vectors.cpp`
**Count:** 0 tests (generator) | **Purpose:** Produce `test_vectors.json` | **Verdict:** Not a test — a fixture generator

The vectors are hardcoded with `m_kib = 19 * 1024` (19 MiB, `fast` profile). There are no vectors for the `browser` profile (64 MiB, t=1, p=1) — the most important cross-mode profile. The generator has no arguments (ignores `argv`), and the comment says "Read the test container created by the CLI" but the implementation doesn't do that.

---

## Findings by Severity

### Critical

**[C-1]** `scef/tests/integration/test_create.py:134` — `test_all_four_slots_start_with_scef_magic` uses wrong slot formula

The test computes slot offsets as `size // 4`, `size // 2`, `(size * 3) // 4`. The spec formula (from `container-format.md` and `FileManager.h:27`) is `floor(container_size * N / 100 / HEADER_SIZE) * HEADER_SIZE`. For the default 4 MiB container these are numerically close enough to land on the same 4096-aligned boundary, so the test always passes — even when the C++ implementation uses a completely different formula. A regression in the C++ slot placement would not be caught.

**[C-2]** `scef/tests/integration/test_errors.py:90-117` — `test_wrong_password_does_not_extract_garbage` has a false-negative trap

The test checks `if extracted.exists(): assert actual != expected`. If the implementation correctly rejects the wrong password (returncode != 0) and writes no file, the `else` branch only asserts `result.returncode != 0` — which is already guaranteed by `run_scef(..., expect_success=False)`. The intent is to verify authentication is enforced, but the test passes trivially when no file is written. The critical security property — that decrypted-with-wrong-key ciphertext is **never written to disk** — is not asserted.

**[C-3]** `scef/browser/test/test_e2e_unlock_node.js:82-84` — HMAC comparison uses non-constant-time loop

The HMAC verification uses `for (let i = 0; i < 32; i++) { if (computedHmac[i] !== storedHmac[i]) { match = false; break; } }` with early exit. This is a timing side-channel. In a Node.js test context this has no production impact, but it documents and normalizes the wrong pattern. The browser implementation may inherit this. The correct pattern is a constant-time comparison (`crypto.timingSafeEqual` in Node, or XOR-accumulate). Since HMAC verification is the *authenticate* step before decryption, this is security-critical if copied into production code.

**[C-4]** No test verifies that HMAC is verified **before** DEK decryption is attempted

The spec and `container-format.md` explicitly document the sequence: derive KEK → verify HMAC → unwrap DEK. This is the authenticate-then-decrypt ordering that prevents padding/decryption oracles. No test in the C++ or Python suite verifies this ordering. A developer could reorder these steps (verify HMAC after DEK unwrap, or skip HMAC on some code path) and no existing test would catch it.

---

### Major

**[M-1]** `scef/tests/unit/test_scef.cpp` — No test for the header binary layout of the first 10 fields

`test_scef.cpp` covers offsets 0x0080-0x00A0 (the "lower" fields) very well, but there is no test that verifies the binary bytes at offsets 0x0000-0x0078 (magic, version, header_size, cipher_id, kdf_id, kdf_profile_id, kdf_m_kib, kdf_t, kdf_p, salt, dek_nonce, encrypted_dek, dek_auth_tag, container_size). A regression in `write_le32` for kdf_m_kib (e.g., writing it big-endian) would not be caught.

**[M-2]** `scef/tests/integration/test_kdf_profiles.py` — No test reads the actual KDF parameter bytes from the container header

The KDF profile tests verify only that `scef list` succeeds with the correct password and fails with the wrong password. No test reads offsets 0x0010 (kdf_m_kib), 0x0014 (kdf_t), 0x0018 (kdf_p) from the binary and asserts they equal the profile's documented values. If the header always stored the Standard profile bytes regardless of which `--kdf-profile` was passed, all current tests would still pass.

**[M-3]** `scef/tests/unit/test_scef.cpp:243-281` — `FourHeaderSlotsWithMagic` uses wrong formula

Same issue as C-1 but in the C++ unit tests. `slot_offset = (container_size * pct / 100 / HEADER_SIZE) * HEADER_SIZE` is computed in the test using integer arithmetic, which is correct — but the test then labels it as the spec formula. The issue is that `container_size * pct / 100` can truncate differently than the C++ `FileManager` implementation. More critically, the test does not assert that **all 4 slots are byte-identical** — only that each starts with the magic.

**[M-4]** No test verifies that all 4 slots are byte-identical after write

The spec requires that on write, all 4 slots are updated with identical content (same header bytes, same file table bytes). No test in the suite reads all 4 slots and compares them byte-for-byte. A bug where only slot 0 is written (or slots are written with different header_version values) would not be detected by any existing test.

**[M-5]** No test verifies that the Argon2id parameters stored in the header actually reach the KDF call

`test_cross_profile_open` verifies that a container opened after creation works, which indirectly confirms the params were stored. But it does not confirm that the params were stored correctly. If the code stored `kdf_m_kib = 65536` in the header but called `Argon2id` with `m = 1048576`, the round-trip would still succeed (the stored params would just be wrong). The only test that would catch this is `test_crypto_node.js` + known vectors, but those vectors use the "fast" profile parameters, not the Standard/High/Browser profiles.

**[M-6]** `scef/tests/integration/test_strength_warning.py:9-11` — Flag names mismatch conftest

`FAST_STRENGTH_KDF_ARGS` uses `--kdf-m-cost`, `--kdf-t-cost`, `--kdf-parallelism`. The standard conftest uses `--kdf-m`, `--kdf-t`, `--kdf-p`. Either the strength test file uses deprecated/wrong flag names (meaning these tests always use the default KDF profile silently), or there are two different CLI flag names for the same params. This makes the strength-warning tests untestable as written.

**[M-7]** `scef/tests/integration/test_capacity_overflow.py:192` — Module-level assertion runs at collection time

`_verify_source_files_and_constants()` is called at module level. If the test data PDFs are absent, pytest fails during collection (before any test body runs), which reports as a collection error rather than a skip. This breaks CI for the entire test session, not just this file. The verification should be inside a fixture with `pytest.skip`.

**[M-8]** `scef/browser/test/test_header_node.js` — Not a test, no assertions on field values

This script parses a header and prints values. It exits 0 if `validCount > 0`, which means it passes even if every numeric field is parsed with wrong offsets (as long as the magic check still works). It needs parametric assertions: `header.kdfMKib === expected_m_kib` given a known container.

---

### Minor

**[m-1]** `scef/tests/unit/test_native_file.cpp:188-202` — `PreallocateSparse_200MiB_IsFast` is time-dependent

A 5-second timeout for sparse allocation is reasonable but will fail on heavily loaded CI systems or slow disk-backed environments. The test is not marked with any skip condition for slow environments.

**[m-2]** `scef/tests/integration/conftest.py:78` — `FAST_KDF_ARGS` passes m=1 KiB below the documented CLI minimum

The comment says "m >= 8 MiB is CLI-enforced minimum" but `FAST_KDF_ARGS` passes `--kdf-m 1` (1 MiB, not 1 KiB — the flag unit is MiB according to test_kdf_profiles.py which uses `m_mib=8`). However the conftest comment says "m >= 8 MiB" which suggests m=1 MiB should be rejected. Either the minimum is not enforced for integration tests (suggesting a bypass), or the validation is weaker than documented.

**[m-3]** `scef/tests/integration/test_roundtrip.py:399-427` — `test_different_passwords_produce_independent_containers` is tautological

Two separate containers are created with different passwords. Each is then decrypted with its own password. This does not test that container 1 cannot be decrypted with password 2 — it only tests that each container decrypts with its own key. A truly security-verifying test would attempt decryption of container 1 with password 2 and assert failure.

**[m-4]** `scef/tests/integration/test_kdf_profiles.py:265-278` — `_create_with_kdf_profile` is redefined

The function `_create_with_kdf_profile` is defined twice in the same file: once at lines 66-78 (module-level before the test classes) and again at lines 265-278 (after `TestNamedProfiles`). The second definition has an additional `timeout` parameter. The first definition is shadowed. This creates confusion about which version `TestNamedProfiles` calls — it calls the first definition since Python resolves names at call time and the second definition replaces the first.

**[m-5]** `scef/tests/integration/run_bit_flip_test.py:12` — Hardcoded `.exe` extension

`SCEF_BIN` is hardcoded as `build/debug/scef.exe`. This script fails on Linux without modification. It is not integrated into the pytest suite and has no cross-platform handling.

**[m-6]** `scef/tests/unit/test_password_strength.cpp:70-78` — `HighProfileRequiresHigherScore` is conditionally tautological

If `rStandard.score != 3`, the entire assertion block is skipped silently. The test body effectively says "if the score happens to be 3, assert these things; otherwise pass unconditionally." This means the test can never fail if the estimator scores "MoreSecure!42" as 2 or 4.

**[m-7]** `scef/tests/integration/test_header_resilience.py:405-430` — TC-HDR-12 documents design limitation without testing recovery

The test asserts that corrupting slot 0's file table causes failure. The comment says "this documents the current design: file table fallback is NOT independent of header fallback." But it does not test the inverse: that if slots 1-3 header+table are all healthy, the operation succeeds after slot 0 header+table is corrupted together. This would be the correct recovery scenario.

---

### Nitpick

**[N-1]** `scef/tests/integration/test_create.py` — Multiple test classes create container then only assert `container_file(cdir).exists()`. The filename check adds no value over checking the exit code (which `run_scef(expect_success=True)` already asserts). These could be collapsed.

**[N-2]** `scef/browser/test/generate_vectors.cpp:29` — Comment says "Read the test container created by the CLI. Expects: container at argv[1], password at argv[2]" but implementation ignores `argv` and uses hardcoded values. The comment is misleading.

**[N-3]** `scef/tests/integration/test_kdf_profiles.py:431-444` — `test_kdf_m_zero_falls_back_to_default` documents that `--kdf-m 0` is treated as "not specified" and silently falls back. This behavior is surprising (a value of 0 being treated as "use default") and the test encodes current behavior without questioning whether the design should instead reject 0 as an invalid value.

**[N-4]** `scef/tests/unit/test_scef.cpp:524-559` — `KuznechikRoundtrip` uses `make_secure_vector("kuznechik_unit_password")` as a password but the conftest integration tests use `DEFAULT_PASSWORD = "integration_test_password_123"`. Minor inconsistency, no functional impact.

---

## Coverage Gaps — Uncovered Spec Aspects

| Spec aspect | Where in code | Test? | Note |
|---|---|---|---|
| Slot offset formula correctness: `floor(size * N / 100 / HEADER_SIZE) * HEADER_SIZE` | `FileManager.h:27`, `FileManager.cpp` | Partial | `test_header_resilience.py::TestSlotOffsetArithmetic` tests the Python helper but doesn't compare against the C++ output for non-trivial sizes |
| All 4 slots are byte-identical after write | `FileManager.cpp::writeFileTableToAllSlots` | None | No test reads all 4 slots and compares them |
| HMAC verified BEFORE decryption (authenticate-then-decrypt ordering) | `FileManager.cpp:417-582` | None | Order of operations is not tested |
| Nonce uniqueness across chunks within a single container | `CryptoManager::encrypt` uses random nonce | None | No test generates many chunks and verifies nonces are distinct |
| File table size limit enforced (`file_table_size <= max_table_size`) | `FileManager.cpp` | None | No test adds enough files to approach the 65536-byte limit |
| Argon2id parameters from each profile reach the actual hash call | `CryptoManager::deriveKek` | Partial | `test_crypto_node.js` tests one profile; no C++ unit test verifies params at the Botan call site |
| Kuznechik path exercised in real encrypt+decrypt (cipher_id=0x02 used in data chunks, not just header) | `CryptoManager::encrypt` | Partial | `test_kuznechik.py::test_kuznechik_round_trip` does roundtrip but doesn't verify data blocks use Kuznechik |
| Password scrubbing actually happens (Botan::secure_scrub_memory called) | `CryptoManager::~CryptoManager` | None | No test verifies key material is zeroed after destruction |
| Bit-flip/corruption recovery: file table fallback when header is valid but table corrupted — should use backup slot's table | `FileManager.cpp::readMeta` | None | TC-HDR-12 asserts failure but doesn't test slot-level recovery |
| Capacity overflow rejected before partial write | `FileManager.cpp` | Partial | `test_capacity_overflow.py` tests this well via CLI; no C++ unit test |
| Cross-platform path handling (Windows backslashes, long paths) | `FileTable.cpp::addFileEntry` | None | Tests run only on Windows in current CI setup |
| Browser viewer decrypts CLI-produced container with "browser" KDF profile | `browser/src/` | None | `test_cross_mode.py` uses "fast" profile, not "browser" |
| header_version is monotonically increasing across all 4 slots | `Header::incrementHeaderVersion` | Partial | `AddIncrementsHeaderVersion` checks slot 0 only |
| `next_write_offset` in file table correctly tracks data position across slot boundaries | `FileManager.cpp` | None | No test adds data across a slot boundary and verifies the offset |
| KDF profile ID stored in header matches the named profile used | offsets 0x000E-0x0018 | None | No test reads these bytes from the binary |
| Magic bytes at exact offset 0x0000 are `'S','C','E','F'` (not `0x46454353` little-endian) | `Header.h:26, Header.cpp:162` | Partial | Checked as ASCII chars in integration tests |
| Reserved fields (0x00C0-0x01FF) are zeroed in serialized output | `Header::createBuffer` | Partial | `Reserved0At0x0098_IsZero` only checks 8 bytes at 0x0098 |
| `json_metadata` field content and null-termination | `Header.h` offset 0x0200 | None | Never tested |

---

## Dead/Disabled Tests

No tests are marked `@pytest.mark.skip`, `@pytest.mark.xfail`, or `GTEST_SKIP()` unconditionally. However:

- `@pytest.mark.slow` on `test_roundtrip_100_files_byte_compare` — this test is disabled by default unless `pytest -m slow` is passed. It is the only stress test and it should be re-enabled in a dedicated CI job, not left as a manual trigger.
- `test_TC_HDR_15c_corrupt_slot0_real_pdf_file` — conditionally skipped with `pytest.skip()` when `pdf_c.pdf` is absent. This is correct behavior, but the test should be documented as a required CI dependency.
- `test_high_profile_container_opens` and `test_high_profile_file_extracts_correctly` — not skipped, but they take ~6 seconds each and run `create` twice (once per test). A single parametrized test with shared container would be cleaner and faster.

---

## Verdict: Top 5 Highest-Leverage Tests to Add or Fix

**1. Slot byte-identity test (fixes C-1, M-3, M-4)**
After `scef create`, read all 4 slots from the container binary. Compute the correct slot offsets using `floor(size * N / 100 / HEADER_SIZE) * HEADER_SIZE`. Assert that all 4 slots start with `SCEF` magic AND that the 4096-byte header blocks at all 4 offsets are byte-for-byte identical. This is the single highest-value missing test in the suite.

**2. KDF parameter binary verification (fixes M-2, M-5)**
For each named profile, create a container and read the raw bytes at offsets 0x000E (kdf_profile_id), 0x0010 (kdf_m_kib), 0x0014 (kdf_t), 0x0018 (kdf_p) from the container file. Assert they equal the values documented in the spec table. This ensures the header serialization actually stores the profile values rather than silently using defaults.

**3. Authenticate-then-decrypt ordering test (fixes C-4)**
Create a container, then corrupt only the encrypted DEK bytes (0x0048-0x0067) in slot 0 but leave the HMAC intact. Verify that `scef list` falls back to slot 1 (HMAC check passes on slot 1). Then corrupt the HMAC in all 4 slots but leave the DEK intact. Verify failure. This directly tests that HMAC rejection prevents DEK unwrap — i.e., the code path does not attempt DEK decryption when HMAC fails.

**4. Security property test for wrong password (fixes C-2)**
Create a container with known content. Attempt extract with wrong password. Assert `returncode != 0` AND assert the output file either does not exist OR has zero bytes. The existing `test_wrong_password_does_not_extract_garbage` does not assert that no file is written; it only conditionally checks content if the file happens to exist.

**5. Cross-mode browser profile test (fixes coverage gap)**
Add a `test_cross_mode` variant that creates a container with `--kdf-profile browser` (m=64 MiB, t=1, p=1) — the exact profile intended for browser use — and verifies that `test_download_node.js` can decrypt it. Currently only the "fast" profile is tested cross-mode. The "browser" profile is the primary use case and is untested end-to-end.
