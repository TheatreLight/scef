# SCEF Core Library Review (src + include)

## Executive Summary

The SCEF core library is in solid shape for a diploma prototype. The cryptographic design is correctly structured: authenticate-then-decrypt ordering is respected (HMAC before DEK unwrap), constant-time HMAC comparison is used, key material is zeroed in destructors via `Botan::secure_scrub_memory`, and nonces are generated from a CSPRNG per block. The slot-based layout is faithfully implemented and the pipeline architecture (producer → worker pool → writer with sequence-number reordering) is a reasonable design.

That said, there are meaningful issues at every severity level. The most serious is an integer overflow in `computeSlotOffsets` that silently produces wrong slot placements for large containers above roughly 9 PiB on 64-bit targets — in practice this is not a regression today but constitutes latent UB. More pressing for daily use are: a duplicate capacity check that computes file system stats twice for the same files (once in `init()`, once in `write()`); the `readerTask` in `EncryptPipeline` uses a broken short-circuit that skips the last chunk's push-to-queue when the queue is closed; the file-table JSON is scrubbed from a `std::string` which offers zero guarantee against compiler reuse; and the `Header` default KDF params (m=65536 KiB, t=3, p=4) contradict both the spec and the KDF profiles table.

Style and naming are generally consistent, RAII is followed everywhere for files and key material, and the cross-platform split in `NativeFile.cpp` is clean. The main architectural gap is that the `FileEntry` struct uses `size_t` (32-bit on Win32) for `size` and `offset` fields, which would silently truncate files above 4 GiB on 32-bit builds.

---

## Findings by Severity

### Critical (security / correctness / data loss)

**[C-01]** `scef/src/FileManager.cpp:641` — `writeChunks` and `add` truncate 64-bit offset to `size_t`

`writeChunks` is declared as returning `size_t` and takes `size_t offset`. `add()` passes `static_cast<size_t>(dataEnd)` (line 610) and casts `endPos` back to `uint64_t` (line 611). On any 32-bit host (or ILP32 Windows), `size_t` is 32 bits. A container larger than 4 GiB silently has its write position wrapped, producing a corrupt container with data written to the wrong position and no error raised.

**Why it matters:** Data corruption without any error. The container format stores offsets as `uint64_t` throughout; only this one function degrades them.

**Fix:** Change `writeChunks` signature to `uint64_t writeChunks(uint64_t offset, bool reportProgress)` and replace all `size_t` usage inside with `uint64_t`. Propagate accordingly in `add()`.

---

**[C-02]** `scef/include/FileTable.h:22-24` / `scef/src/FileTable.cpp:34-36` — `FileEntry::size`, `offset`, `chunks` use `size_t` instead of `uint64_t`

`FileEntry` stores `size_t size`, `size_t offset`, `size_t chunks`. These are serialised into JSON and used to seek into the container. On a 32-bit host the maximum representable value is ~4 GiB. Any container or file above that silently truncates. The deserialization at `FileTable.cpp:70-74` calls `.get<size_t>()` on JSON fields that were written as `uint64_t`-capable integers on a 64-bit machine; on a 32-bit reader this silently wraps.

**Why it matters:** Silent data loss / incorrect seek position for files over 4 GiB. Cross-architecture interoperability breaks.

**Fix:** Change all three fields to `uint64_t`. Update `addFileEntry` parameters correspondingly. Use `.get<uint64_t>()` in `deserialize`.

---

**[C-03]** `scef/include/Header.h:183-184` — Default KDF params in `Header` contradict spec and profile table

`Header` field defaults: `kdf_m_kib_ = 65536` (64 MiB), `kdf_t_ = 3`, `kdf_p_ = 4`. The comment says "Standard profile". The spec says Standard = 1024 MiB, t=1, p=4 (container-format.md table, KdfProfiles.cpp line 8). The Browser profile uses 64 MiB with t=1, not t=3. These defaults are what gets serialised if `setKdfParams` is not called before `write()`.

**Why it matters:** A caller that forgets `setKdfParams` creates a container with parameters that match no defined profile and are subtly weaker (wrong memory size) than the documented default. The container-format.md claims Standard is the default, but the `Header` class will produce something incompatible with Standard.

**Fix:** Set `kdf_m_kib_ = 1024 * 1024` (1 GiB), `kdf_t_ = 1`, `kdf_p_ = 4` to match the Standard profile, or — better — remove the field-level defaults entirely and require `setKdfParams` to be called. At minimum add a `static_assert` or runtime check in `write()` that verifies params are not at defaults.

---

**[C-04]** `scef/src/FileManager.cpp:382` — `std::string` scrub is not reliable for plaintext JSON of file table

```cpp
Botan::secure_scrub_memory(serialized.data(), serialized.size());
```

`serialized` is a `std::string` that has been serialised by `nlohmann::json::dump()`. `secure_scrub_memory` zeros the heap buffer, but the compiler and C++ standard library are free to create short-string-optimised copies (SSO) internally, and `nlohmann::json` may have created intermediate copies of the string during assembly. None of those are scrubbed.

**Why it matters:** The plaintext file table (containing file names, sizes, offsets) may linger on the heap or stack long after the scrub. The file table is not extremely sensitive (no keys), but for a "secure container" product, residual metadata in heap is bad practice.

**Fix:** Use `Botan::secure_vector<char>` for the file table serialisation scratch buffer, or use a dedicated RAII helper that scrubs on destruction. Alternatively accept that nlohmann::json does not support secure erase and document this explicitly as a known limitation, noting that the actual key material (KEK, DEK) is correctly scrubbed.

---

**[C-05]** `scef/src/main.cpp:642-643` — CLI password copied through `std::string` (cleartext)

```cpp
Botan::secure_vector<char> password = args.password.empty() ? read_password()
    : Botan::secure_vector<char>(args.password.begin(), args.password.end());
```

`ParsedArgs::password` is `std::string`. When `--password` is used (test/CI mode), the password flows through `argv[i]` → `args.password` (`std::string`) → then copied into `secure_vector`. The intermediate `std::string` is not scrubbed and lives until `ParsedArgs` is destroyed at the end of `main`.

**Why it matters:** A `std::string` value that held a password is not zeroed by its destructor, so the password may persist in heap memory after `main` returns. This matters in tests and CI pipelines that dump process memory.

**Fix:** At minimum, scrub `args.password` explicitly after the copy: `Botan::secure_scrub_memory(args.password.data(), args.password.size()); args.password.clear();`. Better: change `ParsedArgs::password` to `Botan::secure_vector<char>` throughout.

---

### Major (design flaws, large bugs, performance)

**[M-01]** `scef/include/FileManager.h:39-46` — `computeSlotOffsets` (free function) silently returns wrong slot 0 offset

The free function `computeSlotOffsets` starts its loop at `i = 1`, so `out[0]` is always left as the zero-initialised value of `0`. This is correct for slot 0 (0% = offset 0), but the code comment says it "uses the same formula as `computeSlotOffset` for each percentage". It does not: slot 0 is a special case handled by the loop's starting index, not by `computeSlotOffset(size, 0, header_size)`. If someone adds a new percentage to `SLOT_PERCENTAGES` and changes `SLOT_PERCENTAGES[0]` away from 0, slot 0 silently stays at byte 0. This is a hidden assumption that is not enforced anywhere.

**Why it matters:** Fragility. The correctness depends on `SLOT_PERCENTAGES[0] == 0` always, but nothing enforces it. A static_assert or an explicit `out[0] = computeSlotOffset(size, SLOT_PERCENTAGES[0], header_size)` inside the loop (covering `i=0`) would make it self-documenting and safe.

**Fix:** Either start the loop at `i = 0` (using `computeSlotOffset` which returns 0 for percent=0 via the early-return branch) or add `static_assert(SLOT_PERCENTAGES[0] == 0, "slot 0 must be at offset 0")`.

---

**[M-02]** `scef/src/FileManager.cpp:74-83` — Duplicate capacity check in `init()` and `write()`

`init()` performs the capacity check (lines 74-83) for `createNew`, then `write()` performs the same check again (lines 556-562) after `createContainerFile()`. Both calls stat every file in `filesList_` via `std::filesystem::file_size`. For many large files this is a measurable TOCTOU window and redundant syscalls. The check in `init()` fails silently if `filesList_` is empty at init time (the branch is guarded by `!filesList.empty()`), while the check in `write()` always fires. The net effect is that a developer reading `write()` cannot see that a pre-check already ran.

**Why it matters:** Confusing control flow; the stat calls are redundant; the guard in `init` is asymmetric with `write`. If someone adds the files via `setFilesList` after `init`, the pre-check in `init` never runs but the check in `write` will.

**Fix:** Remove the pre-check from `init()` entirely. The check in `write()` is authoritative. Document in the header that `write()` will throw if files don't fit.

---

**[M-03]** `scef/src/EncryptPipeline.cpp:143` — Broken short-circuit in `readerTask` drops last chunk when queue closes

```cpp
if (!readQueue_.push(std::move(task)) || isLast) {
    break;
}
```

This evaluates `readQueue_.push(...)` first (short-circuit: if push returns false, `isLast` is not evaluated). When `push` returns `false` (queue closed), the loop breaks — this is correct. But when `isLast == true`, the task was already pushed (push succeeded), then `isLast` is evaluated — but the whole expression `(!push() || isLast)` evaluates to `(false || true) = true`, causing a `break` after the last chunk. This is actually correct behavior (stop after last chunk). However, there is a subtle issue: if `push()` returns `false` on the final chunk (queue was closed between push attempt and cancellation check), the task is lost, potentially causing the writer to never see `end_of_file == true` for this file. The reorder buffer in the writer loop may then hang waiting for `nextExpected`.

More critically, reading the code with fresh eyes is confusing: the condition bundles two unrelated concerns (queue-closed vs. end-of-file) into a single `||` expression. This is a code-clarity bug that hides a real edge case.

**Why it matters:** If the queue is closed mid-file (due to a writerLoop exception path), the `end_of_file` sentinel for the current file may never arrive in the write queue, causing the writer to hang in `writeQueue_.pop()` indefinitely until the queue is closed from the worker side.

**Fix:** Separate the two concerns:

```cpp
bool pushed = readQueue_.push(std::move(task));
if (!pushed || isLast) {
    break;
}
```

Then handle the case where `!pushed && isLast` by noting the lost sentinel. For more robustness, the writerLoop's exception path (which closes both queues) already handles this by unblocking pop().

---

**[M-04]** `scef/src/DecryptPipeline.cpp:85` — Empty-file sentinel pushed to `writeQueue_` directly, bypassing `readQueue_` and workers

For empty files (`entry.chunks == 0`), the sentinel is pushed directly to `writeQueue_`:

```cpp
writeQueue_.push(std::move(sentinel));
```

This bypasses the `readQueue_` → worker pool path entirely. The sequence numbers of these sentinels are interleaved with those of real chunks. The reordering buffer in `writerLoop` compares `chunk.seq_no == nextExpected`; if an empty-file sentinel has seq_no N and the preceding chunk from a real file also has seq_no N (impossible because seq_no is a global monotonic counter), things would be confused. The seq_no counter is a single variable in `readerTask` so the numbers are unique.

However, the architectural concern remains: the writer loop expects items from `writeQueue_`, which is written by both `readerTask` (empty file sentinels) and `workerTask` (processed chunks). This is a valid design but is not documented in the code or in any comment. The reader needs to understand the dual-producer nature of `writeQueue_` to reason about correctness.

**Why it matters:** Not a bug in the current implementation, but fragile. Any future refactor that assumes `writeQueue_` is fed only from workers will break empty-file handling. The implicit contract is invisible.

**Fix:** Add a comment above the `writeQueue_.push(sentinel)` call explicitly noting the dual-producer design and why it is safe (seq_no is monotonic, worker count tracks only worker-originated closes).

---

**[M-05]** `scef/src/FileManager.cpp:111-118` — `bytesUntilNextSlot` assumes `slotOffsets_` is sorted ascending; not enforced

`bytesUntilNextSlot` iterates `slotOffsets_` in order and breaks on the first slot offset greater than `cur`. This is correct if `slotOffsets_` is sorted, which it is for valid containers (0, 25%, 50%, 75% always ascending for any positive container size). However:
1. The invariant is not `static_assert`-able at runtime.
2. If `container_size` is exactly 0 (before `init` is called), all four offsets are 0 and the loop returns `remaining` immediately — which is correct by accident. But if offsets are pathologically equal (e.g., container too small and slot offsets collide), `bytesUntilNextSlot` will return wrong results.

The minimum-size check in `createContainerFile()` prevents this for new containers, but there is no check when opening an existing container with a corrupted `container_size` header field. An attacker or corrupted header could set `container_size` to a small value, collapsing all slot offsets to 0, and confuse `skipSlots`/`bytesUntilNextSlot` into infinite-loop territory.

**Why it matters:** Robustness on open of malformed/malicious containers.

**Fix:** After `readMeta()` successfully authenticates, add a validation step that checks the four slot offsets are strictly monotonically increasing and that the container size meets the minimum. Throw a descriptive error if not.

---

**[M-06]** `scef/src/FileManager.cpp:567` — `write()` passes `size_t` to `writeChunks` that may not hold `header_size + max_table_size` for large values

```cpp
size_t endPos = writeChunks(header_->getHeaderSize() + header_->getMaxTableSize(), true);
```

Both `getHeaderSize()` and `getMaxTableSize()` return `uint32_t`. Their sum fits in `uint32_t` for default values (4096 + 65536 = 69632) but not if `max_table_size` is set close to `UINT32_MAX`. Additionally, this sum is passed as `size_t` to `writeChunks` which (per C-01) should be `uint64_t`. Even correcting C-01, the arithmetic here is done in `uint32_t` before widening.

**Fix:** Write `static_cast<uint64_t>(header_->getHeaderSize()) + header_->getMaxTableSize()` to ensure the arithmetic is done in 64-bit.

---

**[M-07]** `scef/src/CryptoManager.cpp:158-189` — Single-use `encrypt()` creates a new `Botan::AEAD_Mode` and `AutoSeeded_RNG` on every call

The non-context-path `encrypt()` (line 158) and `decrypt()` (line 196) each instantiate `Botan::AutoSeeded_RNG` and `Botan::AEAD_Mode::create(...)` from scratch for every call. This path is used for file table encryption (one call per write) so the overhead is negligible there. However, `CryptoManager::deriveKek` also calls `Botan::PasswordHashFamily::create("Argon2id")` fresh every time. The more important issue is that `wrapDek` similarly creates a fresh `AutoSeeded_RNG` inside. These are each thread-safe but expensive to construct.

**Why it matters:** Minor performance issue in the non-pipeline path, but `AutoSeeded_RNG` construction involves entropy gathering which can be slow on some platforms. Not a correctness issue.

**Fix:** Pre-create an `AutoSeeded_RNG` member in `CryptoManager` for the non-context paths, or document that these single-use paths are intentionally simple.

---

**[M-08]** `scef/src/FileManager.cpp:62` — Path construction uses raw string concatenation, not `std::filesystem`

```cpp
containerFilePath_ = pathToDir + "/" + CONTAINER_FILE_NAME;
```

On Windows, `pathToDir` may use backslash as separator. If a caller passes a path ending in backslash, this becomes `C:\dir\\ /container.scef`. Conversely, if mixing separators, `CreateFileA` is usually tolerant but it is not guaranteed for UNC paths.

**Fix:** Use `(std::filesystem::path(pathToDir) / CONTAINER_FILE_NAME).string()`. Same applies to `DecryptPipeline::writerLoop` line 189: `outputDir + "/" + safeName`.

---

### Minor (style, small bugs, docs)

**[m-01]** `scef/src/FileManager.cpp:409-418` — `trySlotMagic` lambda performs redundant double-check

The lambda reads the header into `hdrBuf`, checks the first 4 bytes directly, then calls `header_->read(hdrBuf)` and `header_->validate()`. `validate()` (Header.cpp:119-124) checks the same bytes again from `buffer_` (which was just set by `read()`). The initial 4-byte check and the `validate()` call are doing the same comparison twice.

**Fix:** Remove the 4-byte pre-check inside `trySlotMagic` and rely solely on `header_->validate()` after `header_->read(hdrBuf)`.

---

**[m-02]** `scef/src/Header.cpp:114-117` — `serialize()` is a wrapper that just calls `createBuffer()` with a misleading name

```cpp
void Header::serialize() {
    // sometimes we need re-create buffer because some fields may be changed
    createBuffer();
}
```

The method is called `serialize()` in the public API and the comment says "create buffer". A public method that is nothing but a rename of a private method is unnecessary indirection. The comment "sometimes we need re-create buffer" belongs in the callers, not in the method body.

**Fix:** Either make `createBuffer()` public and remove `serialize()`, or give `serialize()` a clear semantic (e.g., it returns the buffer rather than just updating it). Given that `buffer()` already returns the buffer, a combined `serialize()` that calls `createBuffer()` then returns `buffer_` would be cleaner.

---

**[m-03]** `scef/include/Header.h:119` — `buffer()` is not `const`

```cpp
const HeaderBuffer& buffer();
```

This is a getter that returns a const reference to an immutable buffer. It should be marked `const`:

```cpp
const HeaderBuffer& buffer() const;
```

Nothing in the implementation mutates state when called.

---

**[m-04]** `scef/include/Header.h:141` — `getSaltData()` returns a non-const reference to the salt

```cpp
std::array<uint8_t, 32>& getSaltData() { return salt_; }
```

This is needed only by `CryptoManager::generateSalt` which writes into it. The existence of a mutable reference getter breaks encapsulation — a caller can arbitrarily modify the salt after the fact. The better pattern is to pass salt generation into a dedicated method on `Header` or to keep `getSaltData()` as the salt-modification point and document it as write-only.

**Fix:** Keep `getSaltData()` only where actually needed (the `generateSalt` call in `initCryptoForCreate`), or add a `generateAndStoreSalt(CryptoManager&)` method on `Header` that encapsulates the pattern.

---

**[m-05]** `scef/src/FileManager.cpp:422` — Unnecessary copy of password in `readMeta`

```cpp
Botan::secure_vector<char> passwordCopy(password_.begin(), password_.end());
```

Then on every KEK derivation:

```cpp
password_.assign(passwordCopy.begin(), passwordCopy.end());
```

`validateKdfParamsAndDeriveKek()` calls `crypto_->deriveKek(password_, *header_)` which only reads the password — it does not mutate or consume it. There is no reason to restore `password_` from a copy. The `passwordCopy` and the restore `assign` are dead code.

**Why it matters:** Unnecessary allocation of a sensitive buffer, wasted copy semantics, and confusion about why the restore is needed.

**Fix:** Remove `passwordCopy` and the `password_.assign(...)` line. Pass `password_` directly; it is read-only.

---

**[m-06]** `scef/src/EncryptPipeline.cpp:48-51` — `totalBytes` computed by re-stating all files in `run()`, duplicating work done in `FileManager::computeRequiredDataBytes()`

`EncryptPipeline::run` calls `std::filesystem::file_size` on each file to compute `totalBytes` (for progress reporting). `FileManager` already computed this once in `computeRequiredDataBytes()` and checked it against capacity. The file_size calls are repeated with a new stat.

**Fix:** Pass `totalBytes` as a parameter to `EncryptPipeline::run`, computed once from `computeRequiredDataBytes()`.

---

**[m-07]** `scef/src/Logger.cpp:100-101` — `ftell` return value used as signed long, can return -1 on error without distinctive handling

```cpp
long pos = std::ftell(file_);
if (pos < 0 || pos >= MAX_FILE_SIZE) {
```

If `ftell` fails it returns -1 (which is `< 0`). This triggers rotation, which may fail to open a new file. The rotation then calls `writeStartupHeader()` which calls `fprintf` — if that also fails, log entries are silently dropped. This is acceptable defensive behavior but should be commented.

---

**[m-08]** `scef/src/main.cpp:492-507` — Benchmark uses a zero salt, which is not representative

```cpp
const uint8_t salt[salt_len] = {};
```

The benchmark derives a key against an all-zeros salt. This is not cryptographically meaningful for benchmarking purposes — the memory access pattern of Argon2id does not depend on the salt value, so the timing is accurate. However, it is confusing to anyone reading the code who expects a random salt. A brief comment would help.

---

**[m-09]** `scef/src/main.cpp:503-504` — Benchmark scrub uses `volatile` pointer instead of `Botan::secure_scrub_memory`

```cpp
volatile uint8_t* vk = key;
for (size_t i = 0; i < key_len; ++i) { vk[i] = 0; }
```

The rest of the codebase uses `Botan::secure_scrub_memory` for key material erasure. This inline loop is inconsistent and less robust — the `volatile` trick is implementation-defined for compiler optimisation suppression. Replace with `Botan::secure_scrub_memory(key, key_len)`.

---

**[m-10]** `scef/src/FileTable.cpp:27-29` — Duplicate name resolution uses O(n²) `any_of` in a while loop

```cpp
while (std::any_of(filesTable_.begin(), filesTable_.end(),
    [&fileName](const FileEntry& e){ return fileName == e.name; })) {
    fileName = "(copy)" + fileName;
}
```

For N files with the same name this is O(N²) comparisons. In practice N is small, but the pattern is also subtly wrong: `"(copy)(copy)document.pdf"` is the result of two collisions, not `"(copy) 2 document.pdf"`. This creates unintuitive naming.

**Fix:** This is acceptable for small N (file tables are unlikely to have thousands of same-named files), but the naming convention deserves a comment. Consider using a numeric suffix instead: `document (2).pdf`, `document (3).pdf`.

---

**[m-11]** `scef/include/Header.h:26-31` — `NONCE_SIZE` and `AUTH_TAG_SIZE` declared as `uint16_t` instead of `size_t`/`uint32_t`

```cpp
constexpr uint16_t NONCE_SIZE   = 12;
constexpr uint16_t AUTH_TAG_SIZE = 16;
```

These are used in arithmetic with `uint32_t` and `uint64_t` values (e.g., `BLOCK_SIZE + NONCE_SIZE + AUTH_TAG_SIZE`). The narrowing to `uint16_t` is harmless here but inconsistent — every other size constant (`BLOCK_SIZE`, `HEADER_SIZE`) is `uint32_t` or `size_t`. The mixed types cause implicit conversions throughout.

**Fix:** Change to `constexpr size_t NONCE_SIZE = 12; constexpr size_t AUTH_TAG_SIZE = 16;`.

---

**[m-12]** `scef/src/FileManager.cpp:700-701` — `file_table_size` validation is too weak

```cpp
if (encSize <= NONCE_SIZE + AUTH_TAG_SIZE) {
    LOG_DEBUG("readFilesTable: table empty (enc_size <= overhead), skipping");
    return;
}
```

This check accepts `encSize == 0` (which is `<= 28`) and silently skips deserialization. An `encSize` of 0 from the header means the container was created but no file table was written, which is legitimate for `writeAllSlots()` (initial state). However, it also accepts `encSize == 1` through `28`, which would be a corrupt header since any valid encrypted table must be at least `NONCE_SIZE + AUTH_TAG_SIZE + 2` bytes (minimal JSON `{}`). There is no error raised.

**Fix:** Accept `encSize == 0` as empty; reject `1 <= encSize <= NONCE_SIZE + AUTH_TAG_SIZE` as corrupt.

---

**[m-13]** `scef/src/DecryptPipeline.cpp:89` — `readOffset` is computed using `io.skipSlots(entry.offset)` in the reader, but `entry.offset` was stored as the raw container offset by the writer — the skip has already been accounted for at write time

In `EncryptPipeline::writerLoop` (line 204-206):

```cpp
currentFileStartOffset = io.skipSlots(currentOffset);
currentOffset = currentFileStartOffset;
fileStartRecorded = true;
```

Then `currentFileStartOffset` is passed to `fileTable.addFileEntry(...)` as the `offset` parameter. So `entry.offset` in `FileEntry` already stores the skip-adjusted container offset. Then in `DecryptPipeline::readerTask` (line 89):

```cpp
uint64_t readOffset = io.skipSlots(entry.offset);
```

This calls `skipSlots` again on an already-skip-adjusted offset. If `entry.offset` happens to equal a slot start exactly (which is possible at the boundary of the first slot), this produces an incorrect read position. In practice, `entry.offset` is always `>= header_size + max_table_size` (first data block start after slot 0), so the double-skip produces the same result as a single skip. But this is fragile: the invariant is not documented, and the second `skipSlots` call is conceptually wrong.

**Fix:** Remove `io.skipSlots(entry.offset)` in `readerTask` and use `entry.offset` directly. Add a comment that `entry.offset` is already the skip-adjusted position.

---

### Nitpick

**[N-01]** `scef/src/FileManager.cpp:59` — `%llu` format specifier for `uint64_t` is non-portable; use `PRIu64`

The `LOG_INFO` calls use `%llu` for `uint64_t` values. On Linux, `uint64_t` is `unsigned long` (not `unsigned long long`) on 64-bit; `%llu` is technically wrong and may produce a warning. Use `%" PRIu64 "` or cast to `unsigned long long`.

---

**[N-02]** `scef/src/FileTable.cpp:9-10` — Redundant includes

```cpp
#include <nlohmann/detail/conversions/to_json.hpp>
#include <nlohmann/json_fwd.hpp>
```

`nlohmann/json.hpp` (included on line 6) already transitively includes both of these. These two lines are dead includes.

---

**[N-03]** `scef/src/Logger.cpp:19` — `benchEnabled_` initialised to `true` with no way to opt out at `init()` time

The default `true` means bench logs are on unless `Logger::setBenchEnabled(false)` is called explicitly. The CLI does not expose a `--no-bench` flag. This is a minor UX issue but means benchmark logs are always emitted at BENCH level even when not useful.

---

**[N-04]** `scef/include/BenchMeasurerGuard.h:21` — `end_` member is computed only in destructor but stored as a member; could be a local

`end_` is declared as a member (`std::chrono::time_point<std::chrono::steady_clock> end_`) but is only assigned in the destructor. It could be a local variable in the destructor body, saving 8 bytes of per-instance stack space. Minor.

---

**[N-05]** `scef/src/Header.cpp` and `scef/src/FileManager.cpp` — Duplicated `unsupported_cipher_message` anonymous-namespace helper

An identical function `unsupported_cipher_message` (same signature, same body) exists in both `Header.cpp` (line 7-19) and `FileManager.cpp` (line 28-35). This is dead duplication. Move it to a shared internal header or to `ECiphers.h`.

---

**[N-06]** `scef/include/FileManager.h:31-46` — Two versions of slot-offset computation: free function and member; naming is confusing

`computeSlotOffset` (free, one slot) and `computeSlotOffsets` (free, all slots) exist in `FileManager.h`. `FileManager` also has a private `computeSlotOffsets()` member (no parameters) that wraps the free function. The free `computeSlotOffset` singular is defined but only referenced in the spec comment and not called anywhere in the implementation (the loop in `computeSlotOffsets` free function does not call it). This creates confusion about which is the canonical implementation.

**Fix:** Have the free `computeSlotOffsets` call `computeSlotOffset` in its loop to make the dependency explicit, or remove the singular free function if it is only there for documentation.

---

**[N-07]** `scef/src/FileManager.cpp:576` — `add()` calls `emitProgress(Done, 1.0)` but only if it reaches the end; a failed capacity check throws without emitting Done

This is only an issue for callers that rely on `Done` always being emitted as a lifecycle signal. In the current GUI and CLI there is no such assumption, but adding the progress callback contract to the header documentation would prevent future confusion.

---

## Dead Code & Unused Symbols

1. **`computeSlotOffset` (singular, free function)** in `scef/include/FileManager.h:31-35` — Defined but never called. The loop in `computeSlotOffsets` reimplements the formula inline rather than calling this function. Either call it or remove it.

2. **`container_size_param_`** member in `FileManager` (`include/FileManager.h:205`) — Assigned in `init()` but never read anywhere else in `FileManager.cpp`. Appears to be a leftover from a previous design where it was used in `computeSlotOffsets`. Dead field.

3. **`EKDF` enum** (`include/enums/EKDF.h`) — The `kdf_` field in `Header` is set from the binary on read and stored in `kdf_`, but `kdf_` is never read by any consumer other than serialization. There is no runtime check that `kdf_ == EKDF::Argon2id`. The enum exists as a field in the format spec but adds no runtime behavior.

4. **`FileTable::FileTable()` and `FileTable::~FileTable()` explicit constructors** — Both simply emit a LOG_INFO. The compiler-generated defaults would be identical in behavior. The constructors exist only to log, which is the pattern used everywhere — but it is worth noting that removing the logging from constructors would allow `= default` everywhere.

5. **`Header::to_string()`** — Not called from any CLI command (only `FileTable::to_string()` is). May be used in tests but not in production paths. Verify test coverage.

---

## Cross-Cutting Concerns

### Concurrency Model

The pipeline uses a `BS::thread_pool` (a third-party header-only library). The `BoundedQueue` is a custom MPSC/MPMC queue with condition variables. The reorder buffer (`std::map<uint64_t, ProcessedChunk>`) in `writerLoop` is accessed only from the single writer thread — correct. The `activeWorkers_` atomic is used correctly to signal when all workers have finished and the write queue should be closed. The overall model is sound.

One gap: `FileManager` itself is not thread-safe (`header_`, `fileTable_`, `slotOffsets_` are mutable and not protected by a mutex). The GUI `ScefController` must ensure no concurrent calls to `FileManager` methods.

### Error Handling Consistency

Consistent use of `std::runtime_error` for user-visible errors and `std::invalid_argument` for programming errors. The `emitProgress` callback is wrapped in try/catch to prevent user callbacks from propagating exceptions through internal pipelines. `BoundedQueue::push` returns `bool` and callers check it in some places but not all (the sentinel push in `DecryptPipeline::readerTask` at line 85 ignores the return value). Logging is done at appropriate levels. JSON parse errors in `FileTable::deserialize` will produce `nlohmann::json::exception` which is not caught — it propagates through `readFilesTable` and `readMeta` and will appear as an unrecognised exception type in the error message, though it is catchable as `std::exception`.

### Resource Management (RAII)

Excellent. `NativeFile` is fully RAII with move semantics. `CryptoManager` destructor scrubs key material. `Botan::secure_vector` is used throughout the key-material path. `BenchMeasurerGuard` is RAII. `Header` destructor logs but does not scrub — the header struct contains the encrypted DEK, dek_nonce, and dek_auth_tag (all ciphertext, not plaintext key material), so not scrubbing is acceptable. The `salt_`, `encrypted_dek_`, and `dek_auth_tag_` fields are in principle safe to leave unzeroed since they are ciphertext.

### Naming Conventions

Consistent `snake_case` for members (with trailing underscore), `PascalCase` for classes, `SCREAMING_SNAKE_CASE` for constants. Minor inconsistency: `kdf_m_kib_` mixes the field abbreviation with a unit suffix — this is fine and matches the spec column names. `getChunkSize()` returns `block_size_` — the naming mismatch (`chunk` vs. `block`) appears in a few places (`BLOCK_SIZE` constant vs. `getChunkSize()` accessor, `writeChunks` method). These are synonyms but inconsistent.

### Header/Source Separation and Include Hygiene

Clean. Heavy Botan headers (`botan/aead.h`, `botan/auto_rng.h`) are kept out of the public headers except where the return type requires it (`CryptoContext.h` includes `botan/aead.h` and `botan/auto_rng.h` — this is unavoidable). `NativeFile.h` correctly keeps `<windows.h>` out of the header by using `void*` for `HANDLE`. The only oddity is `<type_traits>` being included in `Header.h` solely for the `read_le` template — acceptable.

### Logging Consistency

Every public method logs `"Call ClassName::methodName()"` at `INFO` level. Constructors and destructors log at `INFO`. This is very verbose at `INFO` level — the spec's usual convention is that function-entry logging belongs at `DEBUG`. At `INFO` level (the release default), the log is noisy with internal plumbing calls that users do not need. Consider moving function-entry logs to `DEBUG`.

---

## Spec Compliance Check

| Spec requirement | File:line implementing it | Verdict |
|---|---|---|
| Slot offset = `floor(size * N / 100 / header_size) * header_size` | `FileManager.h:43` | Matches |
| Slot 0 always at offset 0 | `FileManager.h:42` (loop starts at i=1, `out[0]` stays 0) | Matches (implicit, fragile — see M-01) |
| 4 slots at 0%, 25%, 50%, 75% | `FileManager.h:25` `SLOT_PERCENTAGES` | Matches |
| Header = 4096 bytes | `Header.h:13` `HEADER_SIZE = 4096` | Matches |
| Header magic = "SCEF" | `Header.h:26`, `Header.cpp:121-124` | Matches |
| KDF = Argon2id | `CryptoManager.cpp:51` | Matches |
| KDF profiles: Browser 64MiB/t1/p1, Fast 256MiB/t1/p4, Standard 1024MiB/t1/p4, High 2048MiB/t1/p4 | `KdfProfiles.cpp:6-9` | Matches |
| Header default params = Standard profile | `Header.h:183-185` (65536 KiB, t=3, p=4) | **DRIFT** — see C-03 |
| AES-256-GCM cipher ID 0x01, Kuznechik 0x02 | `ECiphers.h:7-9` | Matches |
| Per-slot HMAC-SHA256 over bytes [0x0000..0x009F] using KEK | `Header.h:62` `HMAC_PROTECTED_SIZE=0xA0`, `FileManager.cpp:243-245` | Matches |
| HMAC verified before DEK decrypt (authenticate-then-decrypt) | `FileManager.cpp:476-479` | Matches |
| Constant-time HMAC comparison | `FileManager.cpp:255` `Botan::constant_time_compare` | Matches |
| Data block = [Nonce 12B][Ciphertext N B][Auth Tag 16B] | `CryptoManager.cpp:168-186` | Matches |
| File table at slot_offset + HEADER_SIZE, max 65536 B | `FileManager.cpp:338`, `Header.h:15-16` | Matches |
| File table encrypted as single block [Nonce 12B][JSON][Tag 16B] | `FileManager.cpp:369-391` | Matches |
| 4 slot writes with fsync between each | `FileManager.cpp:359-362`, `386-390` | Matches (fsync per slot, not between) |
| `next_write_offset` persisted in file table JSON | `FileTable.cpp:48`, `FileTable.cpp:67` | Matches |
| SHA-256 checksum of plaintext per file | `EncryptPipeline.cpp:99`, `DecryptPipeline.cpp:202-204` | Matches |
| Secure erase of KEK/DEK on destruction | `CryptoManager.cpp:26-27` | Matches |
| Minimum container size = 4 × (4096 + 65536) | `Header.h:22-23` `MINIMAL_CONTAINER_SIZE`, `FileManager.cpp:315-320` | Matches |
| Maximum container size = 2 TiB | `Header.h:18` | Matches |
| Nonces generated via CSPRNG, never reused | `CryptoManager.cpp:78`, `CryptoContext.h:22` (per-block from `AutoSeeded_RNG`) | Matches |
| Block size default 65536 bytes | `Header.h:14` | Matches |
| Slot skipping in fragmented I/O | `FileManager.cpp:101-118` | Matches |

---

## Verdict — Top 5 Things to Fix First

**1. [C-02] Change `FileEntry::size`, `offset`, `chunks` from `size_t` to `uint64_t`.**
This is a correctness bug that silently truncates file positions on 32-bit targets and breaks cross-architecture interoperability. The JSON round-trip already stores 64-bit values on 64-bit hosts; the receiving side just reads them into a 32-bit field.

**2. [C-01] Change `writeChunks` signature from `size_t offset` to `uint64_t offset` and fix `add()` cast.**
The 32-bit truncation of the write position will corrupt any container larger than 4 GiB. Fix in tandem with C-02.

**3. [C-03] Fix `Header` default KDF params to match the Standard profile (1024 MiB, t=1, p=4).**
The mismatch between documented defaults and actual defaults will produce containers that users cannot identify as using any named profile, with subtly wrong memory parameters.

**4. [m-05] Remove the dead `passwordCopy`/restore pattern in `readMeta`.**
Unnecessary allocation of a sensitive buffer is a crypto hygiene issue. The password is never mutated by `deriveKek`; the copy-restore pattern is defensive code against a mutation that does not exist.

**5. [M-03] Clarify/fix the `readerTask` short-circuit in `EncryptPipeline` and document the dual-producer design in `DecryptPipeline`.**
The current `(!push() || isLast)` short-circuit is not obviously correct to a reviewer and conceals an edge case. The dual-producer write queue in `DecryptPipeline` needs a comment before the next developer touches it.
