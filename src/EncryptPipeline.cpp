#include "EncryptPipeline.h"
#include "BenchMeasurerGuard.h"
#include "CryptoContext.h"
#include "Logger.h"
#include "NativeFile.h"

#include "botan/hash.h"
#include "botan/hex.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>

EncryptPipeline::EncryptPipeline(CryptoManager& crypto, Config config)
    : crypto_(crypto)
    , config_(config)
    , pool_(config.worker_count + 1)
    , readQueue_(config.queue_capacity)
    , writeQueue_(config.queue_capacity * 2)
{
    LOG_INFO("EncryptPipeline::EncryptPipeline()");
}

EncryptPipeline::~EncryptPipeline()
{
    LOG_INFO("EncryptPipeline::~EncryptPipeline()");
}

void EncryptPipeline::run(const std::vector<std::string>& files, FragmentedIO& io,
    FileTable& fileTable, Header& header, uint64_t startOffset, const std::atomic<bool>& cancelFlag,
    std::function<void(uint64_t, uint64_t)> progressCallback)
{
    LOG_INFO("Call EncryptPipeline::run()");
    uint64_t totalBytes = 0;
    for (const auto& path : files) {
        std::error_code ec;
        uint64_t fileSize = std::filesystem::file_size(path, ec);
        if (ec) {
            LOG_ERROR("EncryptPipeline: failed to get file size for %s: %s", path.c_str(), ec.message().c_str());
            continue;
        }
        totalBytes += fileSize;
    }

    // Apply startOffset: advance past any slot the starting position falls inside.
    startOffset_ = io.skipSlots(startOffset);

    LOG_BENCH("EncryptPipeline: %zu file(s), %llu bytes total, %zu workers, pool threads=%zu, "
              "readQueue capacity=%zu, writeQueue capacity=%zu",
              files.size(), totalBytes, config_.worker_count,
              config_.worker_count + 1, config_.queue_capacity, config_.queue_capacity * 2);

    BenchMeasurerGuard guard("EncryptPipeline::run", totalBytes);

    activeWorkers_.store(config_.worker_count);
    LOG_DEBUG("EncryptPipeline::run: activeWorkers=%zu", config_.worker_count);

    pool_.detach_task([this, &files, &cancelFlag]() {
        readerTask(files, cancelFlag);
    });

    for (size_t i = 0; i < config_.worker_count; ++i) {
        pool_.detach_task([this]() { workerTask(); });
    }

    // If writerLoop throws, close both queues so workers/reader don't block
    // forever on push(), then drain the pool before rethrowing.
    try {
        writerLoop(io, fileTable, header, cancelFlag, progressCallback, totalBytes);
    } catch (...) {
        readQueue_.close();
        writeQueue_.close();
        pool_.wait();
        throw;
    }

    pool_.wait();
}

void EncryptPipeline::readerTask(const std::vector<std::string>& files, const std::atomic<bool>& cancelFlag) {
    BenchMeasurerGuard guard("EncryptPipeline::readerTask");
    uint64_t seqNo = 0;

    for (const auto& filePath : files) {
        if (cancelFlag.load(std::memory_order_relaxed)) {
            break;
        }
        NativeFile input;
        try {
            input.open(filePath, NativeFile::OpenMode::OpenReadOnly);
        } catch (const std::exception& ex) {
            ProcessedChunk errChunk;
            errChunk.seq_no = seqNo++;
            errChunk.error = std::string("Cannot open input file: ") + filePath + " (" + ex.what() + ")";
            writeQueue_.push(std::move(errChunk));
            break;
        }

        auto hasher = Botan::HashFunction::create("SHA-256");
        uint64_t readOffset = 0;
        uint64_t fileBytesRead = 0;

        // Read file size to detect empty files without consuming data.
        uint64_t fileSize = input.size();

        if (fileSize == 0) {
            // Empty file — emit a zero-size sentinel with empty checksum.
            ProcessedChunk sentinel;
            sentinel.seq_no = seqNo++;
            sentinel.file_path = filePath;
            sentinel.end_of_file = true;
            sentinel.file_checksum = Botan::hex_encode(hasher->final());
            writeQueue_.push(std::move(sentinel));
            continue;
        }

        while (!cancelFlag.load(std::memory_order_relaxed)) {
            ProcessedChunk task;
            task.data.resize(BLOCK_SIZE);
            size_t got = input.readSome(readOffset, task.data.data(), BLOCK_SIZE);
            if (got == 0) break;  // EOF

            task.data.resize(got);
            task.seq_no = seqNo++;
            task.data_size = got;
            task.file_path = filePath;
            fileBytesRead += got;
            readOffset += got;

            hasher->update(reinterpret_cast<const uint8_t*>(task.data.data()), got);

            // This is the last chunk if we've read all bytes of the file.
            bool isLast = (readOffset >= fileSize);

            if (isLast) {
                task.end_of_file = true;
                auto digest = hasher->final();
                task.file_checksum = Botan::hex_encode(digest);
                task.file_plain_size = fileBytesRead;
                hasher->clear();
            }

            if (!readQueue_.push(std::move(task)) || isLast) {
                break;
            }
        }
    }

    readQueue_.close();
}

void EncryptPipeline::workerTask() {
    BenchMeasurerGuard guard("EncryptPipeline::workerTask");
    CryptoContext ctx = CryptoContext::makeEncryptor(
        crypto_.getDek(), crypto_.getDekSize());

    while (std::optional<ProcessedChunk> maybeTask = readQueue_.pop()) {
        auto& chunk = *maybeTask;

        size_t encSize = chunk.data_size + NONCE_SIZE + AUTH_TAG_SIZE;
        ProcessedChunk result;
        result.seq_no = chunk.seq_no;
        result.file_path = std::move(chunk.file_path);
        result.end_of_file = chunk.end_of_file;
        result.file_checksum = std::move(chunk.file_checksum);
        result.file_plain_size = chunk.file_plain_size;
        result.data.resize(encSize);

        try {
            crypto_.encrypt(ctx, chunk.data.data(), result.data.data(), chunk.data_size);
            result.data_size = encSize;
        } catch (const std::exception& e) {
            result.error = e.what();
        }

        writeQueue_.push(std::move(result));
    }

    if (activeWorkers_.fetch_sub(1) == 1) {
        writeQueue_.close();
    }
}

void EncryptPipeline::writerLoop(FragmentedIO& io, FileTable& fileTable, Header& header,
    const std::atomic<bool>& cancelFlag, std::function<void(uint64_t, uint64_t)> progressCallback,
    uint64_t totalBytes)
{
    LOG_INFO("Call EncryptPipeline::writerLoop(): totalBytes=%zu", totalBytes);
    BenchMeasurerGuard guard("EncryptPipeline::writerLoop");
    uint64_t nextExpected = 0;
    std::map<uint64_t, ProcessedChunk> reorderBuf;
    uint64_t bytesProcessed = 0;

    uint64_t currentOffset = startOffset_;
    uint64_t currentFileStartOffset = 0;
    bool fileStartRecorded = false;

    auto processChunk = [&](ProcessedChunk& chunk) {
        if (!chunk.error.empty()) {
            throw std::runtime_error("Pipeline encryption error: " + chunk.error);
        }

        if (!fileStartRecorded) {
            currentFileStartOffset = io.skipSlots(currentOffset);
            currentOffset = currentFileStartOffset;
            fileStartRecorded = true;
        }

        currentOffset = io.write(currentOffset, chunk.data.data(), chunk.data_size);

        size_t overhead = NONCE_SIZE + AUTH_TAG_SIZE;
        size_t plainBytes = (chunk.data_size > overhead) ? chunk.data_size - overhead : 0;
        bytesProcessed += plainBytes;

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

    while (!cancelFlag.load(std::memory_order_relaxed)) {
        auto maybeChunk = writeQueue_.pop();
        if (!maybeChunk) break;

        auto& chunk = *maybeChunk;

        if (chunk.seq_no == nextExpected) {
            processChunk(chunk);
            nextExpected++;

            while (reorderBuf.count(nextExpected)) {
                auto node = reorderBuf.extract(nextExpected);
                processChunk(node.mapped());
                nextExpected++;
            }
        } else {
            reorderBuf.emplace(chunk.seq_no, std::move(chunk));
        }
    }

    endOffset_ = currentOffset;
}
