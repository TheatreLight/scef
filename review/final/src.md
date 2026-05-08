# Final Review — SCEF Core Library (src + include)

## Executive Summary

After verifying every cited finding against the actual code, the SCEF core library is in better shape than either reviewer implied in their opening summaries, but it has two genuine structural gaps that require attention before any production use. The cryptographic design (authenticate-then-decrypt, constant-time HMAC comparison, CSPRNG nonces, `Botan::secure_scrub_memory` on key destruction) is implemented correctly. The pipeline architecture (producer → worker pool → sequence-reordered writer) is sound and its exception-handling wrapper in `run()` is present.

The verified critical issues are: (1) a crash-resilience gap where a slot with a valid HMAC but corrupt file table blocks fallback to healthy backup slots, defeating the entire 4-header redundancy design; (2) the POSIX build has a missing `NativeFile::NativeFile()` definition that will fail to link on Linux; (3) `FileEntry::size`/`offset`/`chunks` use `size_t` throughout which truncates to 32 bits on 32-bit targets, and `writeChunks` has the same issue; (4) `Header` default KDF parameters (64 MiB, t=3) match no defined profile and are serialised if `setKdfParams` is not called. Beyond these, there is a TOCTOU window in `add()` for the `next_write_offset` field and several valid minor findings.

## Reviewer Comparison

**Sonnet** was more thorough, more accurate on details, and caught several issues Codex missed (dead `passwordCopy`/restore pattern, double-skipSlots, duplicate capacity check, EncryptPipeline short-circuit analysis). Sonnet's C-03 (Header KDF defaults), C-01/C-02 (size_t truncation), and the dead-code list are all CONFIRMED. Sonnet's framing of the `readerTask` short-circuit (M-03) is partially correct in identifying the code smell but overstates the risk; the actual worst-case is handled by the queue-close path.

**Codex** caught two findings Sonnet missed: the POSIX constructor linker gap (SCEF-008) and the file-table recovery bypass (SCEF-001). However, Codex produced several false positives: the POSIX implementation is complete except for the constructor (not "incomplete" as a whole), the empty-password claim ignores that `read_password()` rejects empty passwords at the CLI layer, and the "data writes unbounded" claim ignores the pre-check that already exists. Codex's tone is more alarmist than the code warrants.

Codex accuracy: approximately 60% of CRITICAL/MAJOR findings confirmed or partially confirmed. Sonnet accuracy: approximately 80%.

---

## Findings (deduplicated, verified, prioritized)

---

### CRITICAL

---

**[F-1] `scef/src/FileManager.cpp:502-503` — Crash-resilience defeated by file-table read outside recovery loop** (CRITICAL)

- Source: Codex (SCEF-001)
- Verdict: CONFIRMED
- Best description: Codex (correctly identified the structural gap)
- What it really is: `readMeta()` loops over slots (lines 443-487) and breaks as soon as a slot passes HMAC verification and DEK unwrap. It then calls `readFilesTable()` at line 503 using `activeSlotOffset_` — the one accepted slot. If that slot's file table was torn by a crash (e.g., header written but file table write interrupted), `readFilesTable` reads corrupt or zero ciphertext from that slot and either throws or returns an empty table. The three healthy backup slots are never consulted because the loop already `break`-ed. This negates the entire redundancy promise of the 4-slot design.
- Fix: Move `readFilesTable()` inside the per-slot loop, after `unwrapDekFromHeader()`. If `readFilesTable()` throws, catch it, log a warning, and `continue` to the next slot. Accept only a slot where both HMAC and file table decrypt successfully.

---

**[F-2] `scef/src/NativeFile.cpp` — POSIX build missing default constructor definition** (CRITICAL)

- Source: Codex (SCEF-008), not raised by Sonnet
- Verdict: CONFIRMED
- Best description: Yours (Codex misdiagnosed the scope)
- What it really is: `NativeFile.h:24` declares `NativeFile()` unconditionally. The Windows branch of `NativeFile.cpp` (lines 32-35) provides a definition. The POSIX branch (`#else` starting at line 234) provides no `NativeFile::NativeFile()` body — only `~NativeFile`, `open`, `close`, `isOpen`, `writeAt`, `readAt`, `readSome`, `preallocateSparse`, `size`, `syncToDevice`, and move operations. On Linux, the linker will fail with "undefined reference to `NativeFile::NativeFile()`" because the declaration requires a definition. The rest of the POSIX implementation is complete and correct.
- Fix: Add inside the `#else` branch:
  ```cpp
  NativeFile::NativeFile() {
      LOG_INFO("NativeFile::NativeFile()");
  }
  ```

---

**[F-3] `scef/include/FileTable.h:19-24` and `scef/src/FileTable.cpp:71-74` — `FileEntry` uses `size_t` for on-disk fields** (CRITICAL)

- Source: Both (Sonnet C-02, Codex SCEF-012)
- Verdict: CONFIRMED
- Best description: Sonnet
- What it really is: `FileEntry::size`, `::offset`, `::chunks` are all `size_t`. On a 64-bit build (Win64 or Linux x86_64) `size_t` is 64 bits and no truncation occurs. On a 32-bit build `size_t` is 32 bits; any container or file exceeding 4 GiB silently truncates. The deserialization at `FileTable.cpp:71-74` calls `.get<size_t>()` on JSON fields — on a 32-bit reader this wraps values that were written as 64-bit integers. Additionally, `FileTable::addFileEntry` at line 22 takes `size_t offset, size_t actual_size`, so the caller must already have truncated before the call. The same issue appears in `writeChunks` signature at `FileManager.h:138` and `FileManager.cpp:641`.
- Fix: Change all three `FileEntry` fields to `uint64_t`. Change `addFileEntry` parameters to `uint64_t`. Change `writeChunks` return type and parameter to `uint64_t`. Use `.get<uint64_t>()` in `deserialize`. Update `add()` at line 610 which currently does `static_cast<size_t>(dataEnd)` — change to pass `dataEnd` directly as `uint64_t`.

---

**[F-4] `scef/include/Header.h:183-185` — Default KDF parameters match no defined profile** (CRITICAL)

- Source: Both (Sonnet C-03, Codex SCEF-006)
- Verdict: CONFIRMED
- Best description: Sonnet (more precise)
- What it really is: `Header` field defaults at lines 183-185: `kdf_m_kib_ = 65536` (64 MiB), `kdf_t_ = 3`, `kdf_p_ = 4`. `KdfProfiles.cpp:6` defines the Browser profile as `64 * 1024` MiB with `t=1, p=1`. The Browser profile is 64 MiB but `t=1`, not `t=3`. The Standard profile (`KdfProfiles.cpp:8`) is `1024 * 1024, t=1, p=4`. No defined profile uses 64 MiB + t=3. The comment in `Header.h` says "Standard profile" which is plainly wrong. The CLI always calls `setKdfParams` before `write()`, so this does not affect CLI usage. However, any caller using the API directly (e.g., the GUI's `ScefController`) who forgets `setKdfParams` creates a container with undocumented, subtly weak parameters. Since `Header.cpp:34` initialises with `DEFAULT_CONTAINER_SIZE` in the constructor, `createBuffer()` is called immediately with these broken defaults.
- Fix: In `Header.cpp`'s constructor, after `createBuffer()`, call `setKdfMKib(1024 * 1024)`, `setKdfT(1)`, `setKdfP(4)` to match Standard, or — better — initialise directly from `getProfileParams(EKDFProfile::Standard)`. Update the comment.

---

### MAJOR

---

**[F-5] `scef/src/FileTable.cpp:67` — Missing `next_write_offset` defaults to 0, enabling data overwrite in `add()`** (MAJOR)

- Source: Codex (SCEF-011)
- Verdict: CONFIRMED
- Best description: Codex
- What it really is: `FileTable::deserialize` at line 67 uses `tmp.value("next_write_offset", uint64_t{0})`. A container written by software that predates this field (or a container where the file table was somehow truncated before this key) will deserialise `next_write_offset_ = 0`. `FileManager::add()` at line 580 reads `dataEnd = fileTable_.getNextWriteOffset()` which returns 0. The capacity check at line 584 passes if `containerSize > 0`. Then `writeChunks(static_cast<size_t>(dataEnd), ...)` at line 610 starts writing at offset 0, which is the start of slot 0 — overwriting the primary header. The HMAC of slot 0 then becomes invalid, and the container appears corrupt.
- Fix: If `next_write_offset_` is 0 and `filesTable_` is non-empty after deserialization, recompute `next_write_offset_` by scanning file entries: for each entry, the end position is `entry.offset + entry.chunks * ENCRYPTED_BLOCK_SIZE`. Take the maximum. Add this recomputation to `FileTable::deserialize()` as a recovery step, and log a warning that the field was absent.

---

**[F-6] `scef/src/FileManager.cpp:421-422` — Dead `passwordCopy`/restore pattern in `readMeta`** (MAJOR)

- Source: Sonnet (m-05, categorised as Minor; severity should be Major due to unnecessary sensitive buffer)
- Verdict: CONFIRMED
- Best description: Sonnet
- What it really is: `passwordCopy` is created at line 422 and `password_.assign(passwordCopy.begin(), passwordCopy.end())` is called at line 466 before re-derivation. The purpose is apparently to restore `password_` in case `deriveKek` consumes or mutates it. However, `CryptoManager::deriveKek` (line 45 of `CryptoManager.cpp`) takes `const Botan::secure_vector<char>&` and never modifies it. `password_` is never modified by any callee. The restore assign is dead code. The `passwordCopy` secure buffer is an unnecessary allocation of sensitive material with an extra copy that is never zeroed explicitly (it relies on `Botan::secure_vector`'s destructor). The dead code obscures the actual recovery logic.
- Fix: Remove `passwordCopy` at line 422 and the `password_.assign(...)` at line 466. The `password_` member is unchanged across slots and can be used directly.

---

**[F-7] `scef/src/FileManager.cpp:62` — Raw string path concatenation instead of `std::filesystem::path`** (MAJOR)

- Source: Both (Sonnet M-08, Codex SCEF-009 partially)
- Verdict: CONFIRMED
- Best description: Sonnet
- What it really is: Line 62: `containerFilePath_ = pathToDir + "/" + CONTAINER_FILE_NAME`. On Windows with `CreateFileA` (used at `NativeFile.cpp:70`), forward-slash paths work for most cases but break for UNC paths (`\\server\share`). More importantly, if `pathToDir` already ends with `\`, the result is `path\\` which `CreateFileA` may or may not handle. The same issue appears at `DecryptPipeline.cpp:189`: `std::string outputPath = outputDir + "/" + safeName`. Separately, `CreateFileA` does not handle non-ASCII (Cyrillic, CJK) directory names — this is the Codex concern. These are distinct: the concatenation issue and the ANSI API issue.
- Fix for concatenation: `containerFilePath_ = (std::filesystem::path(pathToDir) / CONTAINER_FILE_NAME).string()`. Same in `DecryptPipeline.cpp:189`.
- Fix for ANSI API (Windows Unicode): Change `NativeFile::open` to use `std::filesystem::path::native()` (which returns `std::wstring` on Windows) and `CreateFileW`. This is a larger change but necessary for non-ASCII container paths.

---

**[F-8] `scef/src/FileManager.cpp:111-118` — `bytesUntilNextSlot` assumes `slotOffsets_` sorted; no minimum-size guard on open** (MAJOR)

- Source: Sonnet (M-05)
- Verdict: CONFIRMED
- Best description: Sonnet
- What it really is: `bytesUntilNextSlot` iterates `slotOffsets_` and breaks on the first slot offset greater than `cur`. Correctness depends on `slotOffsets_` being sorted ascending. For valid containers this is always true, but after `readMeta` authenticates a header with a pathologically small or corrupted `container_size`, the slot offsets could all be equal (e.g., all 0 for a container_size of 0). `computeAvailableDataCapacity` handles `containerSize <= slotTotal` by returning 0, but there is no check in `readMeta` that the authenticated `container_size` meets the minimum. A crafted or corrupted container can set `container_size` to a small value after a valid HMAC (the HMAC covers bytes 0x00-0x9F which include `container_size` at 0x0078, so this would only pass if the attacker knows the KEK — making it not an adversarial concern but a corruption scenario).
- Fix: After `readMeta` successfully authenticates a slot, validate `header_->getContainerSize() >= MINIMAL_CONTAINER_SIZE`. Throw a descriptive error if not.

---

**[F-9] `scef/src/main.cpp:236-258` — KDF bounds only enforced on open path, not on create path for custom params** (MAJOR)

- Source: Codex (SCEF-005)
- Verdict: PARTIAL — confirmed for direct API callers, NOT confirmed for the CLI
- Best description: Yours (neither reviewer captured the full picture)
- What it really is: The CLI at `main.cpp:373-388` validates KDF bounds (`KDF_M_KIB_MIN`, `KDF_M_KIB_MAX`, etc.) before calling `setKdfParams`. However, `FileManager::setKdfParams` at `FileManager.cpp:162-179` performs no validation — it accepts any values. A direct library caller (GUI, test) passing `setKdfParams(EKDFProfile::None, 1, 1, 1)` writes a container with m=1 KiB, which Argon2id may accept (minimum is 8 KiB in practice). `validateKdfParamsAndDeriveKek` at line 219-231 checks bounds on open — so the container would fail to open on a correct implementation but would have been created with weak params. The open-path check uses `KDF_M_KIB_MIN = 1` which is permissive. Codex's framing is correct in principle.
- Fix: Add the same bounds check inside `setKdfParams` for the `EKDFProfile::None` branch, mirroring `validateKdfParamsAndDeriveKek`. At minimum add `KDF_M_KIB_WARN` enforcement (warn if m < 8 MiB).

---

**[F-10] `scef/src/EncryptPipeline.cpp:143` — `readerTask` short-circuit bundles queue-close and end-of-file** (MAJOR downgraded from Critical)

- Source: Sonnet (M-03)
- Verdict: PARTIAL — the described edge case (lost end_of_file sentinel) is real but the described hang is prevented
- Best description: Sonnet (correctly identified the conceptual problem, overstated the hang risk)
- What it really is: `if (!readQueue_.push(std::move(task)) || isLast) break;` — when `push` returns false (queue closed by writer exception), the task is dropped. If this happens on the final chunk with `end_of_file = true`, the writer never sees the EOF sentinel for that file. However, when `writerLoop` throws, it calls `readQueue_.close()` and `writeQueue_.close()` at lines 71-72. Workers then drain `readQueue_` (getting `nullopt`) and close `writeQueue_`. The `writerLoop` has already thrown, so no hang occurs. The real issue is that the `||` short-circuit means the code reads as "break if either queue closed OR this is the last chunk" which conflates two distinct exit conditions and may drop a successful push on the last chunk (though in practice the task is already pushed before `isLast` is evaluated, so the push result is checked first and if true, `isLast` is evaluated next). The code is correct but confusing.
- Fix: Separate into two conditions for clarity: `bool pushed = readQueue_.push(std::move(task)); if (!pushed || isLast) break;` — this changes nothing functionally but makes the two exit conditions explicit.

---

**[F-11] `scef/src/FileManager.cpp:74-83` and `scef/src/FileManager.cpp:556-562` — Duplicate capacity check** (MAJOR downgraded)

- Source: Sonnet (M-02)
- Verdict: CONFIRMED
- Best description: Sonnet
- What it really is: `init()` checks capacity at lines 74-83 only when `createNew && !filesList.empty()`. `write()` checks again at lines 556-562 unconditionally. Both call `computeRequiredDataBytes()` which stats all files. The check in `init()` is asymmetric: it can be bypassed by calling `setFilesList` after `init`. The authoritative check is in `write()`. Having both creates confusion about which is the contract.
- Fix: Remove the pre-check from `init()`. Document in the header that `write()` throws if files don't fit.

---

### MINOR

---

**[F-12] `scef/src/main.cpp:642-643` — `std::string args.password` not scrubbed after copy to `secure_vector`** (MINOR)

- Source: Both (Sonnet C-05, Codex SCEF-010)
- Verdict: CONFIRMED — but severity is MINOR, not CRITICAL
- Best description: Sonnet (Codex overstates by suggesting removing `--password` entirely)
- What it really is: `ParsedArgs::password` is `std::string` (line 194). When `--password` is used, the password flows through `argv` → `args.password` → `secure_vector`. The `std::string` is not scrubbed afterward. In CI/test usage this is a real concern. Note: `read_password()` path already correctly uses `secure_vector<char>` throughout. The `--password` flag is documented and present in help text, clearly a testing convenience.
- Fix: After line 643, add: `Botan::secure_scrub_memory(args.password.data(), args.password.size()); args.password.clear();`

---

**[F-13] `scef/src/main.cpp:490-504` — Benchmark uses zero salt and volatile-loop scrub instead of `secure_scrub_memory`** (MINOR)

- Source: Sonnet (m-08, m-09)
- Verdict: CONFIRMED both sub-issues
- Best description: Sonnet
- What it really is: `const uint8_t salt[salt_len] = {};` at line 493 uses an all-zeros salt. Argon2id's timing is independent of salt value, so the benchmark timing is accurate, but the code looks like a mistake. At line 503-504, `volatile uint8_t* vk = key; for (size_t i = 0; i < key_len; ++i) { vk[i] = 0; }` inconsistently diverges from the rest of the codebase which uses `Botan::secure_scrub_memory`.
- Fix: Add a comment explaining the zero salt is intentional for benchmarking. Replace the volatile loop with `Botan::secure_scrub_memory(key, key_len)`.

---

**[F-14] `scef/src/FileManager.cpp:409-418` — `trySlotMagic` lambda performs redundant 4-byte pre-check before `header_->validate()`** (MINOR)

- Source: Sonnet (m-01)
- Verdict: CONFIRMED
- Best description: Sonnet
- What it really is: Lines 411-418 manually check `hdrBuf[0..3]` against `HEADER_MAGIC`, then call `header_->read(hdrBuf)` and `return header_->validate()`. `Header::validate()` at `Header.cpp:119-124` checks `buffer_[0..3]` against `HEADER_MAGIC` — the same check performed by the lambda two lines earlier. One check is redundant.
- Fix: Remove the manual 4-byte check from `trySlotMagic`. Rely solely on `header_->read(hdrBuf); return header_->validate();`.

---

**[F-15] `scef/include/Header.h:119` — `buffer()` getter is not `const`** (MINOR)

- Source: Sonnet (m-03)
- Verdict: CONFIRMED — `Header.cpp:138`: `const HeaderBuffer& Header::buffer() { return buffer_; }` — no mutation, not marked `const`
- Best description: Sonnet
- Fix: Change to `const HeaderBuffer& buffer() const;` in the header; add `const` to the definition.

---

**[F-16] `scef/src/FileTable.cpp:27-29` — O(n²) duplicate name check with confusing naming convention** (MINOR)

- Source: Sonnet (m-10)
- Verdict: CONFIRMED
- Best description: Sonnet
- What it really is: `while (std::any_of(...)) { fileName = "(copy)" + fileName; }` — each collision prepends "(copy)". For N collisions the result is `"(copy)(copy)...(copy)file"`. This is O(n²) for N same-named files and produces non-intuitive names. In practice containers rarely have thousands of duplicate names, but the naming is unusual.
- Fix: Use a numeric suffix approach: detect collision, then try `filename (2)`, `filename (3)`, etc. Use a `std::unordered_set` for O(1) name lookup.

---

**[F-17] `scef/src/FileManager.cpp:695-704` — `readFilesTable` accepts corrupt partial table sizes silently** (MINOR)

- Source: Sonnet (m-12)
- Verdict: CONFIRMED
- Best description: Sonnet
- What it really is: `if (encSize <= NONCE_SIZE + AUTH_TAG_SIZE) { ... return; }` at line 701 accepts `encSize` of 0 (empty table, legitimate) but also 1-28 (invalid — no valid encrypted table can be that small). The check treats any value ≤28 as "empty table", silently returning instead of raising a corruption error for the 1-28 range.
- Fix: `if (encSize == 0) { return; }` for the empty case; `if (encSize > 0 && encSize <= NONCE_SIZE + AUTH_TAG_SIZE) { throw std::runtime_error("corrupt file table size"); }` for the invalid range.

---

**[F-18] `scef/src/DecryptPipeline.cpp:89` — `skipSlots` applied to already-skip-adjusted `entry.offset`** (MINOR)

- Source: Sonnet (m-13)
- Verdict: PARTIAL — conceptually wrong, not a data corruption bug
- Best description: Sonnet
- What it really is: `EncryptPipeline::writerLoop` stores `currentFileStartOffset = io.skipSlots(currentOffset)` and passes it to `fileTable.addFileEntry(...)` — so `entry.offset` is already past any slot boundary. `DecryptPipeline::readerTask` at line 89 calls `io.skipSlots(entry.offset)` again. Since `entry.offset` is already outside all slot areas, `skipSlots` returns it unchanged (the `if (pos >= slot && pos < slot + slotReserved)` condition is false). No data corruption occurs. But the double-call is conceptually wrong and will become a real bug if `entry.offset` is ever stored as a raw container position rather than a skip-adjusted one.
- Fix: Remove `io.skipSlots(entry.offset)` at line 89; use `entry.offset` directly. Add a comment: "entry.offset is already skip-adjusted (stored by EncryptPipeline::writerLoop after skipSlots)".

---

### NITPICK

---

**[F-19] `scef/include/Header.h:26-31` — `NONCE_SIZE` and `AUTH_TAG_SIZE` declared as `uint16_t` inconsistently with other size constants** (NITPICK)

- Source: Sonnet (m-11)
- Verdict: CONFIRMED — minor type inconsistency, no UB risk on any target
- Fix: Change to `constexpr size_t` to match `BLOCK_SIZE` pattern.

---

**[F-20] Duplicate `unsupported_cipher_message` in `Header.cpp` and `FileManager.cpp`** (NITPICK)

- Source: Sonnet (N-05)
- Verdict: CONFIRMED — identical functions in separate anonymous namespaces
- Fix: Move to a shared internal header, or expose from `ECiphers.h`.

---

**[F-21] `scef/include/FileManager.h:31-35` — `computeSlotOffset` (singular, free function) is defined but never called** (NITPICK)

- Source: Both (Sonnet dead code section, Codex dead code section)
- Verdict: CONFIRMED — `computeSlotOffsets` free function at line 42-44 reimplements the formula inline rather than calling `computeSlotOffset`
- Fix: Have the free `computeSlotOffsets` loop call `computeSlotOffset` at each iteration, or remove the singular function.

---

**[F-22] `scef/include/FileManager.h:205` — `container_size_param_` written but never read** (NITPICK)

- Source: Both (Sonnet dead code section, Codex dead code section)
- Verdict: CONFIRMED — assigned at `FileManager.cpp:63`, never read by any code path
- Fix: Remove.

---

**[F-23] `scef/src/main.cpp:236-258` — `stoull`/`stoul` in `parseArgs` can throw uncaught exceptions on malformed input** (NITPICK)

- Source: Codex (SCEF-013)
- Verdict: CONFIRMED (minor)
- Best description: Codex
- What it really is: `std::stoull(argv[i])` and `std::stoul(argv[i])` throw `std::invalid_argument` or `std::out_of_range` on bad input. These exceptions propagate out of `parseArgs` and through `main()` as unhandled, producing a terminate with no helpful message.
- Fix: Wrap each conversion in a try/catch that prints a user-friendly error and returns `EXIT_FAILURE`.

---

**[F-24] `scef/include/Header.h:141` — Mutable salt getter breaks encapsulation** (NITPICK)

- Source: Sonnet (m-04)
- Verdict: CONFIRMED — `std::array<uint8_t, 32>& getSaltData()` returns a non-const reference; any caller can modify the salt post-creation
- Fix: Keep `getSaltData()` but document it as the write-only salt-generation accessor. Add a comment that the only legitimate caller is `CryptoManager::generateSalt`.

---

## False Positives (rejected findings)

**Codex SCEF-002 — "Data writes unbounded by container_size":**
`writeFragmented` does not have an internal bound check, but `write()` at lines 556-562 and `add()` at lines 596-608 both compute required vs. available capacity and throw before calling `writeChunks` if files don't fit. There is a theoretical TOCTOU window if the source file grows after the stat, but this is a narrow edge case already noted by the capacity check design. Calling this CRITICAL is an overstatement. REJECTED as critical; noted as a design gap under F-11.

**Codex SCEF-003 — "Core library allows empty passwords":**
`CryptoManager::deriveKek` at line 56-57 explicitly handles empty password input (uses a null byte pointer), which is technically correct Argon2id behavior. The CLI's `read_password()` at lines 143-145 rejects empty passwords with a thrown exception. The concern is real only for direct library callers who bypass the CLI, and deserves a library-level guard — but calling it CRITICAL misframes it. REJECTED as critical; the existing CLI protection is confirmed, library-level enforcement is a Minor design issue.

**Codex SCEF-008 — "POSIX build is incomplete":**
The claim that "only the Windows branch defines [the constructor]" is accurate and CONFIRMED (see F-2). However, the broader claim that "the POSIX/Linux branch is missing" is false — all other POSIX methods (`open`, `close`, `isOpen`, `writeAt`, `readAt`, `readSome`, `preallocateSparse`, `size`, `syncToDevice`, move ctor/assign, dtor) are fully implemented in the `#else` block. The only missing piece is the default constructor body.

**Sonnet C-01 framing as "Critical" for 64-bit builds:**
On x86_64 Linux and Win64 (the two targets the project explicitly targets), `size_t` is 64 bits and no truncation occurs for `writeChunks`. The bug is real and should be fixed (for correctness, future 32-bit portability, and code clarity), but framing it as causing data corruption on the stated target platforms is inaccurate. Confirmed as MAJOR; classified as part of F-3.

**Sonnet M-07 — "CryptoManager creates new `AutoSeeded_RNG` and `AEAD_Mode` per call":**
This is true for the non-context encrypt/decrypt paths (`CryptoManager.cpp:158-189`). These paths are used only for the file table (one call per write) and DEK wrapping (one call per create/open). The pipeline uses `CryptoContext` (pre-created per worker). The overhead is negligible and deliberate. REJECTED as a meaningful performance issue.

---

## Spec Compliance Verdict

| Spec invariant | Status | Notes |
|---|---|---|
| 4 slots at 0/25/50/75% | PASS | `FileManager.h:25`, formula verified |
| Slot offset = `floor(size * N / 100 / 4096) * 4096` | PASS | `FileManager.h:31-44` |
| Header = 4096 bytes, magic "SCEF" | PASS | `Header.h:13`, `Header.cpp:119-124` |
| KDF = Argon2id | PASS | `CryptoManager.cpp:51` |
| KDF profile table (browser/fast/default/high) | PASS | `KdfProfiles.cpp:5-10` |
| Header default params = Standard profile | **FAIL** | F-4: defaults are 64 MiB/t=3, not 1024 MiB/t=1 |
| Per-slot HMAC over [0x0000..0x009F] | PASS | `Header.h:62`, `FileManager.cpp:243-245` |
| HMAC verified before DEK decrypt | PASS | `FileManager.cpp:476-479` |
| Constant-time HMAC comparison | PASS | `FileManager.cpp:255` |
| Data block = [Nonce 12B][CT][Tag 16B] | PASS | `CryptoManager.cpp:168-186` |
| File table = [Nonce 12B][JSON][Tag 16B] | PASS | `FileManager.cpp:369-391` |
| All 4 slots written with fsync between | PASS | `FileManager.cpp:386-390` |
| First valid slot used for recovery | **PARTIAL** | F-1: file-table corruption blocks fallback |
| Nonces: 96-bit CSPRNG, never reused | PASS | `CryptoContext.h:22`, `CryptoManager.cpp:78` |
| Key material zeroed on destruction | PASS | `CryptoManager.cpp:26-27` |
| Min container size = 4 × (4096 + 65536) | PASS | `FileManager.cpp:315-320` |
| POSIX build compiles | **FAIL** | F-2: missing default constructor on Linux |
| Cross-arch portability for >4 GiB | **FAIL** | F-3: `size_t` in FileEntry, writeChunks |

---

## Verdict — Top 5 Fixes Prioritized

**1. [F-1] Move file-table read inside the slot recovery loop.**
This is the highest-priority fix because it defeats the entire design goal of 4-slot crash resilience. A container that survives a crash mid-write currently cannot be recovered by the 3 backup slots if the primary slot's file table is torn. Fix complexity: medium — requires restructuring `readMeta` to loop over `readFilesTable` attempts and continue on exception.

**2. [F-2] Add the POSIX `NativeFile::NativeFile()` constructor body.**
The Linux build currently fails to link. This is a one-line fix that unblocks the Linux target entirely. Fix complexity: trivial.

**3. [F-3] Change `FileEntry` fields and `writeChunks` from `size_t` to `uint64_t`.**
On the stated 64-bit targets this is latent rather than active, but it is the correct type for on-disk sizes and future-proofs the code. The `add()` path at line 610 has an explicit `static_cast<size_t>(dataEnd)` that is already suspicious. Fix complexity: low — mechanical search-and-replace in `FileTable.h`, `FileTable.cpp`, `FileManager.h`, `FileManager.cpp`.

**4. [F-4] Fix `Header` default KDF parameters to match the Standard profile.**
Any direct API caller that creates a container without calling `setKdfParams` produces a container with undocumented, non-standard parameters that will cause user confusion and incorrect security assumptions. Fix complexity: trivial — change three lines in `Header.h` or initialise from `getProfileParams`.

**5. [F-5] Handle missing `next_write_offset` in `deserialize` by recomputing from file entries.**
An `add()` operation on a container that lacks this field (edge case but possible with format evolution) will silently overwrite the primary header. Fix complexity: low — scan entries for maximum end offset in `FileTable::deserialize`.
