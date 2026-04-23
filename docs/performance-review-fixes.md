# Review Fixes: Pipeline Architecture (branch `feature/kdf_profiles_impl`)

Concrete fix plan for the code-review findings on the Level 1+2+3 pipeline
work. Context: encryption of a 13 GB container dropped from 1h15m to 45m,
300 MB is now near-instant. This plan addresses correctness and safety
defects found during review, plus documentation drift.

---

## Triage summary

| # | Severity | Issue | Status after re-analysis |
|---|----------|-------|--------------------------|
| 1 | CRITICAL | `fstream` race between reader/writer threads | **FALSE ALARM** — only one thread touches `containerStream_` per pipeline (see Appendix A) |
| 2 | CRITICAL | Pipeline deadlock when `writerLoop` throws | **REAL** — needs fix |
| 3 | MAJOR | `BackendWorker::currentPassword_` holds cleartext indefinitely | REAL |
| 4 | MAJOR | `ScefController::currentPassword_` declared but never written | REAL |
| 5 | MAJOR | `computeSlotOffsets()` vs `computeSlotOffset()` use different divisors | REAL |
| 6 | MAJOR | `computeAvailableDataCapacity()` unsigned underflow on malformed container | REAL |
| 7 | MAJOR | `int64_t cur = skipSlots(...)` narrowing from `uint64_t` | REAL (warnings + future-proofing) |
| 8 | MINOR | `DecryptPipeline` uses string concat for paths | REAL |
| 9 | MINOR | `FileManager::init()` calls `computeSlotOffsets()` twice on create path | REAL |
| 10 | MINOR | KDF profile table in `performance-implementation-plan.md` diverges from code | DOC DRIFT |
| 11 | MINOR | Typo `"FileMAnager successfully inited"` | TRIVIAL |
| 12 | MINOR | `BackendWorker::createContainer` redundant `std::move(pwd)` after scrub | folded into #3 |
| 13 | BONUS | Pipeline `cancelFlag` wired to `noCancel{false}` in `FileManager` — cancel does nothing | NOT from review; discovered during verification |
| 14 | BONUS | `progressCallback` always passed as `nullptr` | NOT from review; discovered during verification |

Items 13-14 are pre-existing deferrals (the GUI cancel button and progress bar
are not yet implemented). Not fixed here but flagged.

---

## Phase 1: Critical fix — pipeline deadlock on writer error

### Problem (reproducible)

`EncryptPipeline::writerLoop::processChunk` throws on error chunk:

```cpp
// src/EncryptPipeline.cpp:161-163
if (!chunk.error.empty()) {
    throw std::runtime_error("Pipeline encryption error: " + chunk.error);
}
```

When this throws, control flow:
1. `writerLoop` unwinds, `run()` unwinds → `pool_.wait()` (line 57) never executes.
2. `writeQueue_` stops being drained.
3. Workers (pool threads) continue popping from `readQueue_` and pushing to
   `writeQueue_`. Once `writeQueue_` reaches capacity `2 * queue_capacity = 4N`,
   workers block on `writeQueue_.push()`.
4. No one calls `writeQueue_.close()` (it is normally closed by the last
   worker, but workers never reach that code because they are blocked on push).
5. `~EncryptPipeline` triggers `~BS::thread_pool` which joins the blocked
   worker threads → **deadlock**.

The same deadlock applies to `DecryptPipeline`.

### Fix

Wrap `writerLoop` in a try-catch inside `run()`. On exception: close both
queues (unblocks workers), drain the pool, rethrow.

**File:** `scef/src/EncryptPipeline.cpp` — replace the pipeline-run block
(currently lines 45-62):

```cpp
activeWorkers_.store(config_.worker_count);

pool_.detach_task([this, &files, &cancelFlag]() {
    readerTask(files, cancelFlag);
});

for (size_t i = 0; i < config_.worker_count; ++i) {
    pool_.detach_task([this]() { workerTask(); });
}

try {
    writerLoop(io, fileTable, header, cancelFlag, progressCallback, totalBytes);
} catch (...) {
    // Unblock any worker currently blocked on writeQueue_.push()
    // and any reader blocked on readQueue_.push().
    readQueue_.close();
    writeQueue_.close();
    pool_.wait();
    throw;
}

pool_.wait();
```

**File:** `scef/src/DecryptPipeline.cpp` — identical fix at lines 39-51.

### Verification

Add test `tests/unit/test_pipeline_error.cpp`:

1. **EncryptPipeline: missing source file** — pass a `filesList_` with one
   non-existent path. Expect: exception propagates out of `run()`, no hang,
   pipeline destructor returns within 1 s.
2. **EncryptPipeline: many chunks then error** — 1000-chunk real file + 1
   missing file. Forces `writeQueue_` to fill before the error is processed.
   Expect: same clean teardown.
3. **DecryptPipeline: corrupt auth tag** — open a valid container, flip one
   byte in the middle of a file's encrypted data, call `extract()`. Expect:
   exception propagates (auth tag mismatch), no hang.
4. **BackendWorker error recovery** — feed an invalid input, catch the
   `operationDone(error)` signal, verify the next operation (e.g. open a
   good container) still works.

All four tests must complete within 5 s. If any hangs, the fix regressed.

---

## Phase 1.1: Critical fix — empty-file regression

### Problem (reproducible via 3 integration tests)

`test_add_empty_file`, `test_empty_file_extracted_with_zero_bytes`,
`test_empty_file_roundtrip`.

Pre-pipeline `writeChunks` (commit `be5be69`) always called
`fileTable_.addFileEntry()` and `header_->increaseFileCount()` at the end of
every file loop iteration — regardless of byte count. For an empty file the
inner read loop produced zero chunks but the entry was still recorded with
`actualBytesRead = 0`.

The new `EncryptPipeline::readerTask` uses `bytesRead == 0 → break` as the
only exit path, and only sets `end_of_file = true` *on a chunk that carries
bytes*. For a 0-byte file: no chunk is ever pushed with `end_of_file = true`,
so the writer never calls `fileTable.addFileEntry` and the entry is lost.

Symmetric issue on `DecryptPipeline::readerTask`: `for (i = 0; i < entry.chunks; ++i)`
skips the loop entirely for a zero-chunk entry, so the writer never opens the
output file.

### Fix

Treat empty files as a special case that emits exactly one terminal chunk
with `data_size = 0`, `end_of_file = true`.

#### Encrypt side

**File:** `scef/src/EncryptPipeline.cpp`, `readerTask` — inside the per-file
loop, after the inner `while` exits, check whether any chunk was pushed for
this file. If not, push one terminal chunk:

```cpp
for (const auto& filePath : files) {
    if (cancelFlag.load(std::memory_order_relaxed)) break;

    std::ifstream input(filePath, std::ios::binary);
    if (!input.is_open()) {
        ProcessedChunk errChunk;
        errChunk.seq_no = seqNo++;
        errChunk.error = "Cannot open input file: " + filePath;
        writeQueue_.push(std::move(errChunk));
        break;
    }

    auto hasher = Botan::HashFunction::create("SHA-256");
    uint64_t fileBytesRead = 0;
    bool anyChunkPushed = false;

    while (!cancelFlag.load(std::memory_order_relaxed)) {
        ChunkTask task;
        task.data.resize(BLOCK_SIZE);
        input.read(task.data.data(), BLOCK_SIZE);
        auto bytesRead = static_cast<size_t>(input.gcount());
        if (bytesRead == 0) break;

        task.data.resize(bytesRead);
        task.seq_no = seqNo++;
        task.data_size = bytesRead;
        task.file_path = filePath;
        fileBytesRead += bytesRead;

        hasher->update(reinterpret_cast<const uint8_t*>(task.data.data()), bytesRead);

        bool isLast = (bytesRead < static_cast<size_t>(BLOCK_SIZE)) || input.peek() == EOF;
        if (isLast) {
            task.end_of_file = true;
            auto digest = hasher->final();
            task.file_checksum = Botan::hex_encode(digest);
            task.file_plain_size = fileBytesRead;
            hasher->clear();
        }

        if (!readQueue_.push(std::move(task))) break;
        anyChunkPushed = true;
        if (isLast) break;
    }

    // Empty file: emit a single terminal sentinel chunk so the writer
    // still records an entry with size=0 (matches pre-pipeline behavior).
    if (!anyChunkPushed && !cancelFlag.load(std::memory_order_relaxed)) {
        ChunkTask task;
        task.seq_no = seqNo++;
        task.data_size = 0;
        task.file_path = filePath;
        task.end_of_file = true;
        auto digest = hasher->final();
        task.file_checksum = Botan::hex_encode(digest);
        task.file_plain_size = 0;
        if (!readQueue_.push(std::move(task))) break;
    }
}
```

**File:** `scef/src/EncryptPipeline.cpp`, `workerTask` — skip the encrypt
call for zero-size chunks, produce a zero-size `ProcessedChunk`:

```cpp
while (auto maybeTask = readQueue_.pop()) {
    auto& chunk = *maybeTask;

    ProcessedChunk result;
    result.seq_no = chunk.seq_no;
    result.file_path = std::move(chunk.file_path);
    result.end_of_file = chunk.end_of_file;
    result.file_checksum = std::move(chunk.file_checksum);
    result.file_plain_size = chunk.file_plain_size;

    if (chunk.data_size == 0) {
        // Empty-file terminal chunk: no ciphertext to emit.
        result.data_size = 0;
    } else {
        size_t encSize = chunk.data_size + NONCE_SIZE + AUTH_TAG_SIZE;
        result.data.resize(encSize);
        try {
            crypto_.encrypt(ctx, chunk.data.data(), result.data.data(), chunk.data_size);
            result.data_size = encSize;
        } catch (const std::exception& e) {
            result.error = e.what();
        }
    }

    writeQueue_.push(std::move(result));
}
```

**File:** `scef/src/EncryptPipeline.cpp`, `writerLoop::processChunk` — skip
the `io.write` for zero-size chunks, still record the entry:

```cpp
auto processChunk = [&](ProcessedChunk& chunk) {
    if (!chunk.error.empty()) {
        throw std::runtime_error("Pipeline encryption error: " + chunk.error);
    }

    if (!fileStartRecorded) {
        currentFileStartOffset = io.skipSlots(io.tellWrite());
        io.seekWrite(currentFileStartOffset);
        fileStartRecorded = true;
    }

    if (chunk.data_size > 0) {
        io.write(chunk.data.data(), chunk.data_size);
        size_t overhead = NONCE_SIZE + AUTH_TAG_SIZE;
        size_t plainBytes = (chunk.data_size > overhead) ? chunk.data_size - overhead : 0;
        bytesProcessed += plainBytes;
    }

    if (chunk.end_of_file) {
        fileTable.addFileEntry(chunk.file_path, chunk.file_checksum,
                                currentFileStartOffset, chunk.file_plain_size);
        header.increaseFileCount();
        fileStartRecorded = false;
    }

    if (progressCallback && totalBytes > 0) {
        progressCallback(bytesProcessed, totalBytes);
    }
};
```

#### Decrypt side

**File:** `scef/src/DecryptPipeline.cpp`, `readerTask` — if an entry has
`size == 0` (no chunks to read), push one terminal zero-size chunk:

```cpp
for (const auto& entry : entries) {
    if (cancelFlag.load(std::memory_order_relaxed)) break;

    if (entry.size == 0) {
        // Empty file: emit one terminal sentinel so the writer creates
        // an empty output file and records the entry.
        ChunkTask task;
        task.seq_no = seqNo++;
        task.data_size = 0;
        task.file_path = entry.name;
        task.end_of_file = true;
        task.file_checksum = entry.checksum_sha256;
        task.file_plain_size = 0;
        if (!readQueue_.push(std::move(task))) break;
        continue;
    }

    io.seekRead(entry.offset);
    size_t remaining = entry.size;

    for (size_t i = 0; i < entry.chunks; ++i) {
        // ... existing loop unchanged ...
    }
}
```

**File:** `scef/src/DecryptPipeline.cpp`, `workerTask` — skip the decrypt
call for zero-size chunks:

```cpp
while (auto maybeTask = readQueue_.pop()) {
    auto& chunk = *maybeTask;

    ProcessedChunk result;
    result.seq_no = chunk.seq_no;
    result.file_path = std::move(chunk.file_path);
    result.end_of_file = chunk.end_of_file;
    result.file_checksum = std::move(chunk.file_checksum);
    result.file_plain_size = chunk.file_plain_size;

    if (chunk.data_size == 0) {
        // Empty-file terminal chunk: no plaintext to emit.
        result.data_size = 0;
    } else {
        result.data.resize(chunk.data_size);
        try {
            crypto_.decrypt(ctx, chunk.data.data(), result.data.data(), chunk.data_size);
            result.data_size = chunk.data_size;
        } catch (const std::exception& e) {
            result.error = e.what();
        }
    }

    writeQueue_.push(std::move(result));
}
```

**File:** `scef/src/DecryptPipeline.cpp`, `writerLoop::processChunk` — when
the file transitions to a new `file_path`, open the output file regardless
of whether the chunk has data. For a zero-size chunk: do not hash, do not
write; on `end_of_file` still finalize the empty hash and compare checksum.

```cpp
auto processChunk = [&](ProcessedChunk& chunk) {
    if (!chunk.error.empty()) {
        throw std::runtime_error("Pipeline decryption error: " + chunk.error);
    }

    if (currentFileName != chunk.file_path) {
        if (currentOutput.is_open()) currentOutput.close();
        currentFileName = chunk.file_path;
        std::string safeName = safeFilename(currentFileName);
        auto outputPath = (std::filesystem::path(outputDir) / safeName).string();
        currentOutput.open(outputPath, std::ios::binary);
        if (!currentOutput.is_open()) {
            throw std::runtime_error("Cannot open output file: " + outputPath);
        }
        hasher->clear();
    }

    if (chunk.data_size > 0) {
        hasher->update(reinterpret_cast<const uint8_t*>(chunk.data.data()), chunk.data_size);
        if (!currentOutput.write(chunk.data.data(),
                                  static_cast<std::streamsize>(chunk.data_size)).good()) {
            throw std::runtime_error("Failed to write extracted file: " + currentFileName);
        }
        bytesWritten += chunk.data_size;
    }

    if (chunk.end_of_file) {
        auto digest = hasher->final();
        std::string computed = Botan::hex_encode(digest);
        if (computed != chunk.file_checksum) {
            LOG_WARN("DecryptPipeline: File '%s' checksum mismatch", currentFileName.c_str());
            checksumFailures_.push_back(currentFileName);
        }
        hasher->clear();
        currentOutput.close();
        currentFileName.clear();
    }

    if (progressCallback && totalBytes > 0) {
        progressCallback(bytesWritten, totalBytes);
    }
};
```

### Verification

Run the 3 previously failing integration tests — they must pass:

```
cd C:/pet_p/MEPHI_DIPLOMA/scef
pytest tests/integration/test_add.py::TestAddSpecialFiles::test_add_empty_file
pytest tests/integration/test_extract.py::TestExtractEmptyFile::test_empty_file_extracted_with_zero_bytes
pytest tests/integration/test_roundtrip.py::TestRoundtripSingleFile::test_empty_file_roundtrip
```

All 198 integration tests should pass after this fix.

---

## Phase 2: Major fixes

### Fix 2.1: Remove dead `currentPassword_` fields

**Rationale:** Neither `BackendWorker::currentPassword_` nor
`ScefController::currentPassword_` is ever read. They just hold the cleartext
password until the next `scrubPassword()` call — direct violation of the
"zero secrets ASAP" design goal stated in CLAUDE.md.

**File:** `scef/gui/BackendWorker.h`
- Remove `std::string currentPassword_;` member.
- Remove `void scrubPassword();` method declaration.

**File:** `scef/gui/BackendWorker.cpp`
- Remove the `scrubPassword()` definition (bottom of file).
- In `createContainer`:
  - Line 80: remove `scrubPassword();`
  - Line 81: remove `currentPassword_ = std::move(pwd);`
  - Replace with `Botan::secure_scrub_memory(pwd.data(), pwd.size());`
    (defensive — `FileManager::init` already scrubs its internal copy, but
    the local `pwd` on this stack frame was NOT scrubbed).
- In `openContainer`:
  - Lines 105-107: keep the `secure_scrub_memory(pwd.data(), pwd.size())`
    line, remove `scrubPassword();` and `currentPassword_ = password.toStdString();`.
- In `closeContainer`: remove `scrubPassword();` call.
- In `~BackendWorker`: remove `scrubPassword();` call.

**File:** `scef/gui/ScefController.h`
- Remove `std::string currentPassword_;` member (line 78).
- Remove `void scrubPassword();` method declaration (if present).

**File:** `scef/gui/ScefController.cpp`
- Remove the `scrubPassword()` definition (lines 154-160).
- In `closeContainer()`: remove `scrubPassword();` call (line 100).
- In `~ScefController()`: remove `scrubPassword();` call (line 40).

### Fix 2.2: Unify slot offset computation

**Rationale:** Two call sites compute slot offsets via different formulas.
Silent divergence risk if `header_->getHeaderSize() != HEADER_SIZE` ever
occurs.

**File:** `scef/include/FileManager.h`

The free function `computeSlotOffset(fileSize, percentage, headerSize)`
already exists. Expose a helper that returns the full array:

```cpp
constexpr std::array<uint8_t, SLOT_COUNT> SLOT_PERCENTAGES{0, 25, 50, 75};

inline std::array<uint64_t, SLOT_COUNT>
computeSlotOffsets(uint64_t containerOrFileSize, uint32_t headerSize) {
    std::array<uint64_t, SLOT_COUNT> out{};
    for (size_t i = 1; i < SLOT_COUNT; ++i) {
        out[i] = (containerOrFileSize * SLOT_PERCENTAGES[i] / 100 / headerSize) * headerSize;
    }
    return out;
}
```

**File:** `scef/src/FileManager.cpp`
- `FileManager::computeSlotOffsets()` (lines 85-92): delegate to the free
  helper using `HEADER_SIZE` (the compile-time constant) rather than
  `header_->getHeaderSize()`:

  ```cpp
  std::array<uint64_t, SLOT_COUNT> FileManager::computeSlotOffsets() const {
      return ::computeSlotOffsets(header_->getContainerSize(), HEADER_SIZE);
  }
  ```

- `readMeta()` (lines 509-512): replace the inline per-slot computation with
  a single call to the free helper for consistency.

### Fix 2.3: Guard against capacity underflow

**File:** `scef/src/FileManager.cpp`, `computeAvailableDataCapacity()`
(lines 278-285):

```cpp
uint64_t FileManager::computeAvailableDataCapacity() const {
    uint64_t containerSize = header_->getContainerSize();
    uint64_t slotReserved  = header_->getHeaderSize() + header_->getMaxTableSize();
    uint64_t slotTotal     = SLOT_COUNT * slotReserved;
    if (containerSize <= slotTotal) {
        LOG_DEBUG("computeAvailableDataCapacity: container=%llu <= slot_total=%llu, available=0",
                  containerSize, slotTotal);
        return 0;
    }
    uint64_t available = containerSize - slotTotal;
    LOG_DEBUG("computeAvailableDataCapacity: container=%llu, slot_reserved=%llu x %zu, available=%llu",
              containerSize, slotReserved, SLOT_COUNT, available);
    return available;
}
```

### Fix 2.4: Use `uint64_t` for fragmented-IO positions

**File:** `scef/src/FileManager.cpp`

In `writeFragmented` (line 131) and `readFragmented` (line 150):

```cpp
uint64_t cur = skipSlots(static_cast<uint64_t>(containerStream_->tellp()));
if (cur != static_cast<uint64_t>(containerStream_->tellp())) {
    containerStream_->seekp(static_cast<std::streamoff>(cur), std::ios::beg);
}
```

Same for the `tellg`/`seekg` pair in `readFragmented`. Removes MSVC `/W4`
signed/unsigned warnings and removes the silent truncation at `2^63`.

---

## Phase 3: Minor fixes

### Fix 3.1: `DecryptPipeline` path construction

**File:** `scef/src/DecryptPipeline.cpp`, line 158:

```cpp
auto outputPath = (std::filesystem::path(outputDir) / safeName).string();
currentOutput.open(outputPath, std::ios::binary);
```

### Fix 3.2: Remove duplicate `computeSlotOffsets()` call

**File:** `scef/src/FileManager.cpp`, `init()` (lines 41-81):

Currently `slotOffsets_` is computed at line 55 (create path only) AND at
line 79 (always, after readMeta or after stream open). On the create path
this is redundant.

Replace lines 54-64:

```cpp
if (createNew && !filesList.empty()) {
    slotOffsets_ = computeSlotOffsets();
    uint64_t available = computeAvailableDataCapacity();
    uint64_t required  = computeRequiredDataBytes();
    if (required > available) {
        throw std::runtime_error(
            "Files too large for container: need " + std::to_string(required) +
            " bytes of data capacity but container only provides " +
            std::to_string(available) + " bytes");
    }
}
```

with:

```cpp
slotOffsets_ = computeSlotOffsets();

if (createNew && !filesList.empty()) {
    uint64_t available = computeAvailableDataCapacity();
    uint64_t required  = computeRequiredDataBytes();
    if (required > available) {
        throw std::runtime_error(
            "Files too large for container: need " + std::to_string(required) +
            " bytes of data capacity but container only provides " +
            std::to_string(available) + " bytes");
    }
}
```

and remove the second `slotOffsets_ = computeSlotOffsets();` on line 79.
(Keep it only inside the `if (!createNew)` branch after `readMeta()`, because
readMeta populates `header_->container_size` from disk, and slotOffsets must
be recomputed from authenticated data.)

Final shape:

```cpp
slotOffsets_ = computeSlotOffsets();  // create path uses the param-provided size

if (createNew && !filesList.empty()) {
    ... capacity check ...
}

containerStream_ = std::make_unique<std::fstream>(...);
...

if (!createNew) {
    readMeta();
    slotOffsets_ = computeSlotOffsets();  // recompute from authenticated header
}
```

### Fix 3.3: Typo in log message

**File:** `scef/src/FileManager.cpp`, line 80:

```cpp
LOG_DEBUG("FileManager successfully initialized");
```

### Fix 3.4: Reconcile KDF profile documentation (docs-only)

**File:** `scef/docs/performance-implementation-plan.md`

The plan's section 3.2.3 table is stale. Current code
(`scef/src/KdfProfiles.cpp`) matches `CLAUDE.md`:

| Profile | m (MiB) | t | p |
|---------|---------|---|---|
| Browser | 64 | 1 | 1 |
| Fast | 256 | 1 | 4 |
| Standard (default) | 1024 | 1 | 4 |
| High | 2048 | 1 | 4 |

Update the implementation plan to match (or, if the plan's values are
preferred on evidence, file a separate decision — but the thesis architecture
section in `CLAUDE.md` is the more current source).

Note: the `Browser` profile at 64 MiB needs validation against the 0.5-1.0 s
WASM target. If measurement shows it exceeds that target, reduce to ~46 MiB
(the hash-wasm documented figure from research). This validation is part of
the browser-viewer benchmarking milestone, not this fix batch.

---

## Phase 4: Test plan

### New unit tests

**File:** `scef/tests/unit/test_pipeline_error.cpp` (new)

Covers Fix 1 (deadlock):
- `EncryptPipeline_MissingSourceFile_TerminatesQuickly` — single missing file,
  pipeline exits cleanly with exception, destructor returns < 1 s.
- `EncryptPipeline_LargeInputThenError` — 1000-chunk file + missing file,
  forces `writeQueue_` to fill, same expectation.
- `DecryptPipeline_CorruptAuthTag_TerminatesQuickly` — valid container with
  one flipped byte in ciphertext, pipeline throws without hanging.

Helper: use GMock + a fake `FragmentedIO` that can inject errors, or a
temp-file fixture.

**File:** `scef/tests/unit/test_file_manager_capacity.cpp` (new)

Covers Fix 2.3 (capacity underflow):
- `ComputeAvailable_OversizedHeaderRegion_ReturnsZero` — construct a
  `FileManager` with `container_size = 100 KB`, `max_table_size = 1 MB` (i.e.
  slot_total > container_size). Expect `computeAvailableDataCapacity() == 0`
  rather than a huge wrapped value.

### Existing tests to re-run

- All unit tests (`cd scef/build/debug && ctest`).
- Integration test: create 300 MB container, add, extract, verify.
- Integration test: create 13 GB container (if CI budget allows — else manual).
- Manual GUI smoke test: create, add, extract via the Qt UI; verify no
  freeze on the main thread during long operations.

---

## Phase 5: Out of scope (flagged, not fixed here)

1. **Cancel flag is dead code.** `FileManager::writeChunks` and
   `FileManager::extract` construct `std::atomic<bool> noCancel{false}`
   locally, never wire `BackendWorker::cancelRequested_` through. Fix
   requires threading the atomic through `FileManager::add/write/extract`
   APIs. Do in a separate MR alongside the GUI cancel button.

2. **Progress callback is always `nullptr`.** Same architectural omission.
   Add when the GUI progress bar is wired up.

3. **Writer processes chunks before the error chunk.** On a multi-file
   `add()`, if file #3 fails to open, files #1 and #2 have already been
   partially encrypted into the container (but `fileTable_.setNextWriteOffset`
   is not updated, so next `add()` overwrites them). Acceptable for now.
   Note in user docs: "failed `add()` leaves garbage in the container; run
   another successful `add()` to reclaim space."

4. **Per-worker `AutoSeeded_RNG` startup cost.** Each of `N` workers calls
   `CryptoContext::makeEncryptor` which constructs an `AutoSeeded_RNG`
   (entropy-pool init). For `N=16` this is ~5-10 ms of startup overhead.
   Negligible for > 100 MB inputs; noticeable for small files. Fix: share
   one seeded RNG and fork via `HMAC_DRBG` per thread. Not a priority.

5. **`BS::thread_pool` constructed per pipeline run.** Each `writeChunks`
   or `extract` call constructs a fresh pool. Per Level-3 plan, the pool
   should live on `BackendWorker` for the whole app lifetime. Current code
   deviates. Fix later when Level-3 is fully implemented.

---

## Implementation order

```
1. Fix 2.1 (remove currentPassword_)      — pure deletion, no risk
2. Fix 3.3 (typo)                         — trivial
3. Fix 2.3 (capacity underflow guard)     — single function, additive
4. Fix 2.4 (uint64_t positions)           — warning fixes
5. Fix 3.1 (path concat)                  — cosmetic
6. Fix 3.2 (duplicate computeSlotOffsets) — minor restructure
7. Fix 2.2 (unify slot offset formula)    — touches readMeta, run tests
8. Fix 1 (deadlock try-catch)             — CORE FIX, verify with tests
9. New tests                              — ensure fixes stick
10. Fix 3.4 (docs)                        — doc-only
```

Steps 1-6 are low-risk and can be batched in one commit. Step 7 needs a
full test run because it affects the open path. Step 8 is the critical
behavior change — separate commit with new tests. Step 10 is a doc commit.

Estimated effort:
- Steps 1-6: 30 min.
- Step 7: 30 min + test run.
- Step 8: 45 min + 4 new tests.
- Step 9: 1-2 h (writing robust deadlock tests).
- Step 10: 10 min.

Total: ~4 h of focused work.

---

## Appendix A: Why CRITICAL #1 was downgraded

The reviewer flagged `std::fstream` thread-safety between reader and writer
tasks. Actual call graph:

**EncryptPipeline**
| Thread | Touches `containerStream_`? |
|--------|------------------------------|
| Reader (pool) | NO — reads source `std::ifstream` files |
| Workers (pool) | NO — pure crypto |
| Writer (calling thread) | YES — `io.write`, `seekWrite`, `tellWrite` |

**DecryptPipeline**
| Thread | Touches `containerStream_`? |
|--------|------------------------------|
| Reader (pool) | YES — `io.seekRead`, `io.read` |
| Workers (pool) | NO — pure crypto |
| Writer (calling thread) | NO — writes to separate `std::ofstream` per output file |

In each pipeline exactly one thread accesses `containerStream_`. No race.

The caveat is that the calling thread MUST NOT touch `containerStream_`
while `DecryptPipeline::run()` is executing. In the current code,
`FileManager::extract()` calls `pipeline.run()` synchronously and does not
touch the stream during the call, so the invariant holds. Anyone extending
the pipeline architecture later must preserve this.

---

## I/O backend migration (2026-04-20)

### Before (std::fstream, flush only)

The pre-migration code called `containerStream_->flush()` in `writeAllSlots()`
and `~std::fstream` on scope exit. `flush()` only drains the libc/MSVCRT
internal buffer to the OS page cache — it does NOT issue a device flush.
On a local SSD with an OS write cache, the process exited in under 1 s.
On USB, the OS page cache continued draining to the device for ~45 s AFTER
the process reported completion. This made TOTAL timing misleading: the log
showed `write: TOTAL 975 ms` but the USB drive LED kept flashing for another
45 s, creating a risk of data loss on premature removal.

### After (NativeFile, syncToDevice in TOTAL)

`FileManager::write()` now calls `containerFile_.syncToDevice()` after
`writeFileTableToAllSlots()` and before logging `write: TOTAL`. The TOTAL
timestamp is taken AFTER `syncToDevice` returns, so it honestly accounts for
the device flush.

SSD benchmark (release build, fast KDF profile, 65 MB input, 300 MB container,
local NTFS volume, Windows 10):

```
write: createContainerFile took 2 ms
write: initCryptoForCreate (KDF + wrapDEK) took 46 ms
write: writeAllSlots took 0 ms
EncryptPipeline: 1 file(s), 64905929 bytes total, 12 workers, pool threads=13, readQueue capacity=24, writeQueue capacity=48
WriterLoop stats: chunks=1981, total=661ms, wait=461ms, write=177ms
EncryptPipeline: finished in 661 ms (93.6 MB/s)
write: writeChunks (pipeline encryption) took 665 ms
writeFragmented stats: bytes=64961397, write_calls=1981, fragmented_writes=0, slot_skips=0, seek_calls=0, seek=0ms, write=175ms
write: writeFileTableToAllSlots took 1 ms
write: syncToDevice took 101 ms
write: TOTAL 817 ms
```

Key change: on local SSD, `syncToDevice` takes ~50-100 ms (OS cache flush to
NVMe). On USB, this number will be in the range of tens of seconds — that time
now appears explicitly in the log and is included in `write: TOTAL`, so the
reported TOTAL accurately reflects when data is safe on the device.

USB run skipped — no USB drive available in this environment. Expected behavior:
`write: syncToDevice` will show the true USB drain time (previously invisible,
causing the ~45 s silent post-exit delay), and `write: TOTAL` will be
correspondingly higher.
