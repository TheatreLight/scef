# Final Review — SCEF Test Suite

## Executive Summary

The SCEF test suite is substantial (~200 tests across unit and integration layers) and shows clear engineering intent. However, measured against the project's test philosophy — **"tests must verify spec compliance and FAIL when code diverges from the spec"** — the suite has systematic gaps. The unit tests in `test_scef.cpp` are legitimately spec-anchored. The integration tests overwhelmingly verify behavioral round-trips: they would pass if AES-256-GCM was replaced by a broken cipher that self-decrypts, if slot offsets drifted slightly, or if HMAC was skipped on some code paths.

The three highest-severity gaps are: (1) `test_create.py` uses a wrong slot-offset formula that masks real implementation bugs, (2) no test reads KDF parameter bytes from the container binary to verify they match the named profile, and (3) no test proves authenticate-then-decrypt ordering is enforced. All other gaps are real but lower priority.

---

## Reviewer Comparison

**Sonnet** tracked the test philosophy more faithfully. Its findings are more precisely located (exact line numbers, exact formulas), and its analysis of the tautological round-trip problem is sharper. The slot formula analysis in [C-1] is correct and verified. The `run_bit_flip_test.py` "no assertions" claim is wrong — the script does assert — but all other Critical/Major findings verified out.

**Codex** produced useful finds on atomicity and file table integrity, but several claims are imprecise. The claim that `run_bit_flip_test.py` "has no assertions" is false — it calls `sys.exit(1)` and checks return codes. The claim that `test_capacity_overflow.py` "misses atomicity entirely" is partially false — TC-CAP-07 and TC-CAP-08 do test post-failure functional state; header-level atomicity invariants are the real gap. Codex also raised valid issues (HMAC-protected field coverage, `next_write_offset` validation) that Sonnet listed as coverage gaps rather than findings; those are elevated here.

---

## Findings (Deduplicated, Verified, Prioritized)

### Critical

**[F-1] `scef/tests/integration/test_create.py:133-138` — Wrong slot-offset formula in slot magic test** (Critical)

**Source:** Sonnet [C-1], Codex [M-001].
**Verdict:** CONFIRMED.

The formula `size // 4`, `size // 2`, `(size * 3) // 4` at lines 133-138 (also at lines 425-430 in `TestCreateWithMaxTableSize.test_all_four_slots_have_scef_magic_with_custom_table`) is not the spec formula. The spec formula (`FileManager.h:31-34`, `container-format.md:25`) is `floor(size * N / 100 / 4096) * 4096`. For DEFAULT_CONTAINER_SIZE (4 MiB = 4194304), these happen to produce identical results because 4194304 is a power-of-2 multiple of 4096. For any non-power-of-2 size — such as the `CONTAINER_JUST_FITS = 794624` used in `test_capacity_overflow.py` — the formulas diverge:

- Spec: slot 1 at `(794624 * 25 // 100 // 4096) * 4096 = (198656 // 4096) * 4096 = 48 * 4096 = 196608`
- Test: `794624 // 4 = 198656`

An implementation that placed slots at the wrong offsets for non-standard container sizes would pass this test indefinitely because the tests exclusively use DEFAULT_CONTAINER_SIZE (4 MiB) for the slot magic check. The C++ unit test `FourHeaderSlotsWithMagic` (line 261-263 of `test_scef.cpp`) correctly uses the spec formula — but only runs with a single container size too.

**What spec invariant to test instead:** Create a container with a non-power-of-2 size (e.g., `1_000_000` or `794624`), compute slot offsets via `(size * N // 100 // 4096) * 4096`, and assert SCEF magic at those exact bytes.

---

**[F-2] `scef/tests/integration/test_errors.py:110-117` — Wrong-password test does not assert the critical security property** (Critical)

**Source:** Sonnet [C-2].
**Verdict:** CONFIRMED.

`test_wrong_password_does_not_extract_garbage` at lines 90-117 has this logic: if the output file exists, assert `actual != expected`; else assert `returncode != 0`. The `else` branch is already guaranteed by `expect_success=False` on line 104 (which calls `run_scef` without asserting success). The test passes trivially when the implementation correctly rejects the wrong password and writes no file — the else branch fires, asserting `returncode != 0`, which is already the only non-success outcome `run_scef` can return in that call.

The security property that matters is: **AES-GCM authentication rejected the ciphertext, so no plaintext was written.** The test encodes this as "if a file was written, its content differs from the original." But it never asserts: "regardless of whether a file was written, `returncode != 0`." An implementation that silently truncates to 0 bytes and exits 0 would satisfy the current test.

**What spec invariant to test instead:** After extracting with wrong password, assert `returncode != 0` unconditionally, AND assert that the output file either does not exist or has size 0. The authentication property is binary: either extraction was rejected, or it was not.

---

**[F-3] `scef/browser/test/test_e2e_unlock_node.js:82-84` — HMAC comparison uses early-exit loop** (Critical)

**Source:** Sonnet [C-3].
**Verdict:** CONFIRMED. The loop at lines 82-84 exits on the first mismatched byte: `if (computedHmac[i] !== storedHmac[i]) { match = false; break; }`. This is a timing side-channel.

In Node.js test infrastructure the timing leakage is immeasurable in practice. The problem is that this code documents the pattern — the HMAC comparison logic here may be copied or referenced when implementing the browser production path. `crypto.timingSafeEqual` is available in Node.js and `SubtleCrypto` in browsers provides constant-time operations via HMAC `verify()`. The production code path must use constant-time comparison; this test normalizes the wrong approach.

**What spec invariant to test instead:** Replace the loop with `crypto.timingSafeEqual(computedHmac, storedHmac)` for correctness. More importantly, verify that the browser's `app.js` HMAC verification path uses `SubtleCrypto.verify()` or a constant-time XOR accumulate — this test is a proxy for that guarantee.

---

**[F-4] No test verifies HMAC-then-DEK ordering (authenticate-then-decrypt)** (Critical)

**Source:** Sonnet [C-4], Codex [C-004].
**Verdict:** CONFIRMED. The spec (`container-format.md:72-74`, `FileManager.h:164-168`) explicitly documents the sequence: `validateKdfParamsAndDeriveKek()` → `verifyHeaderHmac()` → `unwrapDekFromHeader()`. No test in the C++ or Python suite verifies this ordering.

The existing `test_header_resilience.py` tests corrupt the HMAC *field* and verify fallback — but those tests do not verify that a corrupted HMAC-*protected payload* (e.g., the `salt` or `encrypted_dek` bytes at `0x001C` or `0x0048`) is caught by the HMAC check. They also do not verify that HMAC rejection happens before DEK decryption is attempted. A developer who moved `unwrapDekFromHeader()` before `verifyHeaderHmac()` would not be caught by any existing test.

**What spec invariant to test instead:** Corrupt a single byte of `encrypted_dek` (bytes `0x0048-0x0067`) in slot 0 while leaving HMAC intact; verify slot 0 fails and slot 1 is used. Then corrupt a single byte of `salt` (bytes `0x001C-0x003B`) in slot 0; verify same fallback. These two tests together prove the HMAC covers DEK and salt, and that HMAC failure causes slot rejection (not AES-GCM failure on the DEK, which could be conflated).

---

### Major

**[F-5] `scef/tests/integration/test_kdf_profiles.py` — No test reads KDF parameter bytes from the container binary** (Major)

**Source:** Sonnet [M-2], Codex [C-005].
**Verdict:** CONFIRMED. The KDF profile tests verify only that a container created with `--kdf-profile fast` can be listed and extracted. They do not read bytes `0x000E` (kdf_profile_id), `0x0010` (kdf_m_kib), `0x0014` (kdf_t), `0x0018` (kdf_p) from the container binary and assert they match the spec profile table. An implementation that stored `kdf_m_kib = 1024*1024` (Standard profile) regardless of the selected profile, but still used the stored value for KDF, would pass all current profile tests. The profile selector would be silently broken.

The spec KDF profile table (`container-format.md:85-89`) gives exact values: Browser = `m=65536 KiB`, Fast = `m=262144 KiB`. These are verifiable at specific byte offsets in the binary.

**What spec invariant to test instead:** For each named profile, create a container, then `open(container_path, 'rb').read()` and read `struct.unpack_from('<I', data, 0x0010)[0]` and assert it equals the profile's documented `m_kib`. Same for `0x0014` (t) and `0x0018` (p).

---

**[F-6] No test verifies all 4 slots are byte-identical after write** (Major)

**Source:** Sonnet [M-4].
**Verdict:** CONFIRMED. `FileManager.writeFileTableToAllSlots()` and `writeAllSlots()` are supposed to write identical content to all four slot positions. No test reads the 4096-byte header block at each slot offset and compares them. A bug where slot 0 receives a different `header_version` than slots 1-3, or where one slot is not written at all, would be invisible to the entire test suite (as long as `readMeta()` reads slot 0 successfully).

**What spec invariant to test instead:** After any write operation, compute slot offsets using the spec formula, read 4096 bytes at each offset, and assert all four are byte-for-byte identical.

---

**[F-7] `scef/tests/unit/test_scef.cpp:261-263` — `FourHeaderSlotsWithMagic` only checks magic, not slot byte-identity** (Major)

**Source:** Sonnet [M-3].
**Verdict:** PARTIAL. Sonnet's claim that the C++ unit test uses "the wrong formula" is FALSE — the formula at line 261-263 is `(container_size * pct / 100 / HEADER_SIZE) * HEADER_SIZE` which is correct. However, the substantive gap is real: the test checks only the 4-byte magic at each slot offset. It does not compare the full 4096-byte header blocks across all 4 slots for byte-identity. This is a real gap, but it is a separate finding from the formula issue.

**What spec invariant to test instead:** After `fm.write()`, read all four 4096-byte header blocks and assert `slot0_header == slot1_header == slot2_header == slot3_header`.

---

**[F-8] `scef/tests/integration/test_strength_warning.py:8-11` — Flag names mismatch conftest, tests likely use wrong or unsupported flags** (Major)

**Source:** Sonnet [M-6].
**Verdict:** CONFIRMED. `FAST_STRENGTH_KDF_ARGS` at lines 8-11 uses `--kdf-m-cost`, `--kdf-t-cost`, `--kdf-parallelism`. Every other test file (conftest, test_kdf_profiles, run_bit_flip_test) uses `--kdf-m`, `--kdf-t`, `--kdf-p`. One of two things is true: (a) the flag names in test_strength_warning.py are wrong, and the binary either rejects them (causing test failures) or silently ignores them (causing the tests to run with the slow default profile, making them take ~1-2 seconds each and rendering the "fast" intent moot); or (b) there are two sets of flag aliases in the binary. Either way, the strength tests are not testing what they claim to test with respect to KDF parameters.

**What spec invariant to test instead:** Standardize to `--kdf-m`, `--kdf-t`, `--kdf-p` throughout. If the binary provides both aliases, document this explicitly.

---

**[F-9] `test_capacity_overflow.py:192` — Module-level assertion runs at pytest collection time** (Major)

**Source:** Sonnet [M-7].
**Verdict:** CONFIRMED. `_verify_source_files_and_constants()` is called unconditionally at module level (line 192). If the test data PDFs are absent, pytest reports a collection error (`ERROR collecting test_capacity_overflow.py`) rather than a skip, and this error propagates to every test run regardless of which tests were selected. It breaks CI for sessions that do not include this test file.

**What spec invariant to test instead:** Wrap the verification in a session-scoped fixture with `pytest.skip(reason=..., allow_module_level=True)`.

---

**[F-10] `test_capacity_overflow.py` TC-CAP-07 — Post-failure atomicity is functionally tested but not at header level** (Major)

**Source:** Codex [C-002]. Sonnet described the test as "EXCELLENT spec-anchored."
**Verdict:** PARTIALLY CONFIRMED — reconciled below.

Both reviewers are partially right. TC-CAP-07 (`test_add_overflow_does_not_corrupt_original_file`) and TC-CAP-08 (`test_failed_create_does_not_leave_valid_container`) do test post-failure functional state: TC-CAP-07 verifies the original file is still extractable after a failed `add`; TC-CAP-08 verifies a failed `create` does not leave a listable container. Sonnet calling these "EXCELLENT" is warranted for what they do test.

However, Codex's concern is also valid: neither test reads `header_version` or `file_count` from the binary before and after the failed operation. If a partial write increments `header_version` in slot 0 but not slots 1-3, the container is inconsistent at the header level but still functionally extractable (because `readMeta` reads whichever slot passes HMAC). This specific failure mode passes TC-CAP-07 without being caught.

**What spec invariant to test instead:** Read `struct.unpack_from('<I', data, 0x0088)[0]` (file_count) and `struct.unpack_from('<I', data, 0x0090)[0]` (header_version) from slot 0 before and after the failed operation, and assert both are unchanged.

---

**[F-11] `scef/tests/unit/test_scef.cpp` — No binary verification of fields at offsets `0x0000`-`0x0078`** (Major)

**Source:** Sonnet [M-1].
**Verdict:** CONFIRMED. The `HeaderLayoutTest` class in `test_scef.cpp` covers offsets `0x0080`-`0x009F` thoroughly. There is no test that reads and verifies the serialized byte values at `0x0000` (magic), `0x0008` (header_size), `0x000C` (cipher_id), `0x0010` (kdf_m_kib), `0x001C` (salt), `0x0048` (encrypted_dek) etc. The magic is checked in integration tests but never with a `EXPECT_EQ(raw[0], 'S')` pattern in the unit tests for the first 128 bytes. A regression that serialized `kdf_m_kib` as big-endian would not be caught at the unit level.

---

**[F-12] `scef/tests/integration/test_kdf_profiles.py:66-78` and `265-278` — `_create_with_kdf_profile` is defined twice; second definition shadows the first** (Major)

**Source:** Sonnet [m-4], elevated here.
**Verdict:** CONFIRMED. Python module-level name resolution means all callers see the *last* definition at the time of the call. The second definition at line 265 adds a `timeout` parameter. All calls from `TestNamedProfiles` (lines 66-240 range) use the first definition when the call executes, but after line 265 is executed at import time the second definition is active. This means `TestHighProfile` (lines 242-262) already calls the second definition since the module is fully loaded before any test runs. The duplicate is confusing but functionally produces the same behavior for existing callers since `timeout=60` was added as a default. The first definition is unreachable dead code.

---

### Minor

**[F-13] `scef/tests/integration/conftest.py:78` — `FAST_KDF_ARGS` passes `m=1` which may be below or at the documented minimum** (Minor)

**Source:** Sonnet [m-2].
**Verdict:** CONFIRMED WITH CORRECTION. The conftest comment says "m >= 8 MiB is CLI-enforced minimum." The flag `--kdf-m 1` passes `m=1 MiB` (not 1 KiB, as the unit is MiB per the `--kdf-m` flag convention used throughout). Per `container-format.md:97`, the minimum is `m >= 1 KiB`. The minimum *warning* threshold is `8192 KiB = 8 MiB`. So `m=1 MiB` is below the warning threshold but above the hard minimum. The comment in conftest is misleading — 1 MiB should pass the hard minimum check but trigger a warning. The real concern is whether these tests implicitly suppress or ignore the warning. This is a documentation/clarity issue, not a correctness issue, since the strength warning tests in `test_strength_warning.py` bypass the conftest args entirely.

---

**[F-14] `scef/tests/unit/test_native_file.cpp:~202` — `PreallocateSparse_200MiB_IsFast` is time-gated** (Minor)

**Source:** Sonnet [m-1].
**Verdict:** CONFIRMED. A 5-second wall-clock assertion will fail on slow/overloaded CI systems. No skip guard is present.

---

**[F-15] `scef/tests/unit/test_password_strength.cpp:70-78` — `HighProfileRequiresHigherScore` skips assertion when score is not exactly 3** (Minor)

**Source:** Sonnet [m-6].
**Verdict:** CONFIRMED. `if (rStandard.score != 3) { /* skip */ }` makes the test unconditionally pass whenever the estimator returns any score other than 3 for the "MoreSecure!42" input. This is a silently vacuous test.

---

**[F-16] `scef/tests/integration/run_bit_flip_test.py:12` — Hardcoded `.exe` extension, not integrated into pytest** (Minor)

**Source:** Sonnet [m-5], Codex [C-003 partially].
**Verdict:** CONFIRMED WITH CORRECTION. Codex's claim that "the script has no assertions" is FALSE — it calls `sys.exit(1)` on failure and checks return codes at lines 47-50 and 60-63. The script is functionally correct as a standalone tool. The real issues are: (1) hardcoded `.exe` fails on Linux; (2) not integrated into the pytest session; (3) duplicates `test_list_container_single_bit_flip_in_header` in `test_errors.py`.

---

### Nitpick

**[F-17] `scef/tests/integration/test_header_resilience.py:405-430` — TC-HDR-12 documents design limitation without testing recovery through other slots** (Nitpick)

**Source:** Sonnet [m-7].
**Verdict:** CONFIRMED. The test asserts failure when slot 0's file table is corrupted (which is correct current behavior — file table is slot-coupled). What it does not test is the positive case: if slot 0 *header* is also corrupted (magic zeroed), does the system fall back to slot 1's header+table and succeed? This would be the recovery scenario that TC-HDR-12 implies is unsupported, but no test verifies it either way.

---

## Verified Coverage Gaps

These spec invariants have no real test coverage, confirmed by grep across the full test suite:

| Spec invariant | Location | Confirmed absence |
|---|---|---|
| All 4 slot headers are byte-identical after write | `FileManager::writeAllSlots()` | No grep match for byte-identical slot comparison anywhere |
| KDF parameter bytes at `0x0010`-`0x001B` match named profile values | `Header.cpp` serialization | Only `run_bit_flip_test.py` references `0x0010` as a byte to flip, not to verify |
| HMAC-protected payload fields (salt, encrypted_dek) are caught when corrupted | `FileManager::verifyHeaderHmac()` | No test corrupts bytes `0x001C`-`0x0067` and asserts HMAC failure |
| Authenticate-then-decrypt ordering (HMAC before DEK unwrap) | `FileManager.h:164-168` | No test verifies call order; no ordering test of any kind found |
| `next_write_offset` in file table JSON is persisted and reloaded correctly | `FileTable.h:43-44` | No test closes/reopens a container and verifies `next_write_offset` from the decrypted JSON |
| Nonce uniqueness across all chunks in a single container | `CryptoManager::encrypt()` | No nonce-collection test found |
| Browser "browser" profile (m=64 MiB) cross-mode decryption | `test_cross_mode.py` | Only `--kdf-profile fast` is tested cross-mode |
| `json_metadata` field at `0x0200` content and null-termination | `Header.h:0x0200` | No test for this field |
| Reserved fields `0x00C0`-`0x01FF` are zero in serialized output | `Header::createBuffer()` | `Reserved0At0x0098_IsZero` covers only 8 bytes; 320-byte block at `0x00C0` unchecked |
| `header_version` is identical across all 4 slot headers | `Header::header_version` | Only slot 0 is read in `AddIncrementsHeaderVersion` |
| Capacity enforcement verified at unit test level (no CLI subprocess) | `FileManager::computeAvailableDataCapacity()` | Only CLI-level tests; no direct unit test of the capacity function |

---

## False Positives

**Codex [C-003] — `run_bit_flip_test.py` has no assertions.**
FALSE. The script at lines 47-50 checks the return code of `create` and exits 1 on failure. Lines 60-63 check the return code of `list` and print FAIL/PASS accordingly. The script is a functional regression script with correct assertions. The real issues are its non-integration into pytest and the hardcoded `.exe` path (addressed in [F-16]).

**Codex [C-002] — "test_capacity_overflow.py misses atomicity entirely."**
PARTIALLY FALSE. TC-CAP-07 and TC-CAP-08 do test post-failure functional state (original file remains extractable; failed create leaves no listable container). The gap is narrower than Codex claims: header-level atomicity invariants (`header_version`, `file_count` unchanged across all slots) are not tested, but functional post-failure state is. The finding is elevated but with the precise scope clarified in [F-10].

**Sonnet [M-3] — `FourHeaderSlotsWithMagic` "uses wrong formula."**
PARTIALLY FALSE. The C++ unit test at `test_scef.cpp:261-263` uses `(container_size * pct / 100 / HEADER_SIZE) * HEADER_SIZE` — this is the correct spec formula. The claim that it "uses wrong formula" is incorrect. The real gap (no byte-identity check across slots) is real and captured in [F-7].

---

## Verdict — Top 5 Highest-Leverage Tests to Add or Fix

**1. Fix slot formula in `test_create.py` and add byte-identity assertion** (Fixes [F-1], [F-6], [F-7])

In `test_all_four_slots_start_with_scef_magic` (line 119), replace the formula `size // 4` etc. with `(size * N // 100 // 4096) * 4096`. Run the test with at least one non-power-of-2 container size (e.g., 1_000_000 bytes) to expose drift. Separately, add a test that reads the full 4096-byte header block at each of the four computed slot offsets and asserts all four are byte-for-byte identical.

**2. Add KDF parameter binary verification test** (Fixes [F-5])

For each named profile (browser, fast, standard, high), create a container, read the raw container bytes, and assert:
- `struct.unpack_from('<H', data, 0x000E)[0]` == profile ID (1, 2, 3, 4)
- `struct.unpack_from('<I', data, 0x0010)[0]` == profile's `kdf_m_kib` (65536, 262144, 1048576, 2097152)
- `struct.unpack_from('<I', data, 0x0014)[0]` == 1 (t)
- `struct.unpack_from('<I', data, 0x0018)[0]` == 1 or 4 (p per profile)

This directly tests whether `setKdfParams()` serializes into the header correctly.

**3. Add authenticate-then-decrypt ordering test** (Fixes [F-4])

Create a container. Corrupt 4 bytes of `encrypted_dek` (bytes `0x0048-0x004B`) in slot 0 only — do not touch the HMAC. Assert that `scef list` falls back to slot 1 and succeeds. Next, corrupt 4 bytes of `salt` (bytes `0x001C-0x001F`) in slot 0 only — do not touch the HMAC. Assert the same fallback. These two tests together prove the HMAC covers these fields and that HMAC failure causes slot rejection independently of AES-GCM failure on the DEK. An implementation that skipped HMAC and went straight to DEK unwrap would fail on the salt-corruption test (since salt is not covered by AES-GCM) — but would silently produce the wrong DEK rather than rejecting the slot.

**4. Fix `test_wrong_password_does_not_extract_garbage`** (Fixes [F-2])

Add an unconditional assertion: `assert result.returncode != 0` (before the `if extracted.exists()` branch). Add: `assert not extracted.exists() or extracted.stat().st_size == 0`. The test currently passes trivially when the implementation correctly rejects wrong passwords — but never proves the negative (no plaintext written). The unconditional return-code assert is the spec guarantee; the file non-existence assert is the confidentiality guarantee.

**5. Add `next_write_offset` persistence test** (Fixes coverage gap)

Create a container with file A. Read the raw container binary and decrypt the file table from slot 0 (using the known KEK). Parse the `next_write_offset` JSON field and record its value. Close the container. Re-open and add file B. Extract both files and assert byte-perfect match. Then read the file table again and assert `next_write_offset` advanced by `encrypted_size(file_B)`. This catches any bug where `next_write_offset` is not persisted or not read on reopen, which would cause `add()` to silently overwrite existing data blocks.
