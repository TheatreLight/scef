#include "DecryptPipeline.h"
#include "BenchMeasurerGuard.h"
#include "CryptoContext.h"
#include "Header.h"
#include "Logger.h"
#include "NativeFile.h"

#include "botan/hash.h"
#include "botan/hex.h"

#include <algorithm>
#include <filesystem>
#include <map>

DecryptPipeline::DecryptPipeline(CryptoManager& crypto, Config config)
    : crypto_(crypto)
    , config_(config)
    , pool_(config.worker_count + 1)
    , readQueue_(config.queue_capacity)
    , writeQueue_(config.queue_capacity * 2)
{
    LOG_INFO("DecryptPipeline::DecryptPipeline()");
}

DecryptPipeline::~DecryptPipeline() {
    LOG_INFO("DecryptPipeline::~DecryptPipeline()");
}

void DecryptPipeline::run(const std::vector<FileEntry>& entries, FragmentedIO& io,
    const std::string& outputDir, const std::atomic<bool>& cancelFlag,
    std::function<void(uint64_t, uint64_t)> progressCallback)
{
    LOG_INFO("Call DecryptPipeline::run(): entries.size=%zu", entries.size());
    uint64_t totalBytes = 0;
    for (const auto& e : entries) totalBytes += e.size;

    checksumFailures_.clear();

    LOG_BENCH("DecryptPipeline: %zu file(s), %llu bytes total, %zu workers, pool threads=%zu",
              entries.size(), totalBytes, config_.worker_count, config_.worker_count + 1);

    BenchMeasurerGuard guard("DecryptPipeline::run", totalBytes);
    activeWorkers_.store(config_.worker_count);

    pool_.detach_task([this, &entries, &io, &cancelFlag]() {
        readerTask(entries, io, cancelFlag);
    });

    for (size_t i = 0; i < config_.worker_count; ++i) {
        pool_.detach_task([this]() { workerTask(); });
    }

    // If writerLoop throws, close both queues so workers/reader don't block
    // forever on push(), then drain the pool before rethrowing.
    try {
        writerLoop(outputDir, cancelFlag, progressCallback, totalBytes);
    } catch (...) {
        readQueue_.close();
        writeQueue_.close();
        pool_.wait();
        throw;
    }

    pool_.wait();
}

void DecryptPipeline::readerTask(const std::vector<FileEntry>& entries, FragmentedIO& io,
    const std::atomic<bool>& cancelFlag)
{
    BenchMeasurerGuard guard("DecryptPipeline::readerTask");
    uint64_t seqNo = 0;

    for (const auto& entry : entries) {
        if (cancelFlag.load(std::memory_order_relaxed)) break;

        if (entry.chunks == 0) {
            ProcessedChunk sentinel;
            sentinel.seq_no = seqNo++;
            sentinel.data.clear();
            sentinel.data_size = 0;
            sentinel.file_path = entry.name;
            sentinel.end_of_file = true;
            sentinel.file_checksum = entry.checksum_sha256;
            sentinel.file_plain_size = 0;
            writeQueue_.push(std::move(sentinel));
            continue;
        }

        uint64_t readOffset = io.skipSlots(entry.offset);
        size_t remaining = entry.size;

        for (size_t i = 0; i < entry.chunks; ++i) {
            if (cancelFlag.load(std::memory_order_relaxed)) break;

            size_t plainSize = std::min(remaining, static_cast<size_t>(BLOCK_SIZE));
            size_t encSize = plainSize + NONCE_SIZE + AUTH_TAG_SIZE;

            ProcessedChunk task;
            task.seq_no = seqNo++;
            task.data.resize(encSize);
            task.data_size = plainSize;
            task.file_path = entry.name;

            // io.read reads encSize bytes at readOffset, skipping slots internally,
            // and returns the new physical offset after the read.
            readOffset = io.read(readOffset, task.data.data(), encSize);

            if (i == entry.chunks - 1) {
                task.end_of_file = true;
                task.file_checksum = entry.checksum_sha256;
                task.file_plain_size = entry.size;
            }

            remaining -= plainSize;

            if (!readQueue_.push(std::move(task))) break;
        }
    }

    readQueue_.close();
}

void DecryptPipeline::workerTask() {
    BenchMeasurerGuard guard("DecryptPipeline::workerTask");
    CryptoContext ctx = CryptoContext::makeDecryptor(
        crypto_.getDek(), crypto_.getDekSize());

    while (auto maybeTask = readQueue_.pop()) {
        auto& chunk = *maybeTask;

        ProcessedChunk result;
        result.seq_no = chunk.seq_no;
        result.file_path = std::move(chunk.file_path);
        result.end_of_file = chunk.end_of_file;
        result.file_checksum = std::move(chunk.file_checksum);
        result.file_plain_size = chunk.file_plain_size;
        result.data.resize(chunk.data_size);

        try {
            crypto_.decrypt(ctx, chunk.data.data(), result.data.data(), chunk.data_size);
            result.data_size = chunk.data_size;
        } catch (const std::exception& e) {
            result.error = e.what();
        }

        writeQueue_.push(std::move(result));
    }

    if (activeWorkers_.fetch_sub(1) == 1) {
        writeQueue_.close();
    }
}

void DecryptPipeline::writerLoop(const std::string& outputDir, const std::atomic<bool>& cancelFlag,
    std::function<void(uint64_t, uint64_t)> progressCallback, uint64_t totalBytes)
{
    LOG_INFO("Call DecryptPipeline::writerLoop(): totalBytes=%zu", totalBytes);
    BenchMeasurerGuard guard("DecryptPipeline::writerLoop");
    uint64_t nextExpected = 0;
    std::map<uint64_t, ProcessedChunk> reorderBuf;
    uint64_t bytesWritten = 0;

    NativeFile currentOutput;
    uint64_t currentOutputOffset = 0;
    std::string currentFileName;
    auto hasher = Botan::HashFunction::create("SHA-256");

    auto safeFilename = [](const std::string& name) -> std::string {
        auto safe = std::filesystem::path(name).filename();
        if (safe.empty() || safe == "." || safe == "..") {
            throw std::runtime_error("Unsafe file name in container: " + name);
        }
        return safe.string();
    };

    auto processChunk = [&](ProcessedChunk& chunk) {
        if (!chunk.error.empty()) {
            throw std::runtime_error("Pipeline decryption error: " + chunk.error);
        }

        if (currentFileName != chunk.file_path) {
            if (currentOutput.isOpen()) {
                currentOutput.syncToDevice();
                currentOutput.close();
                currentOutputOffset = 0;
            }
            currentFileName = chunk.file_path;
            std::string safeName = safeFilename(currentFileName);
            std::string outputPath = outputDir + "/" + safeName;
            currentOutput.open(outputPath, NativeFile::OpenMode::CreateTruncate);
            hasher->clear();
        }

        if (chunk.data_size > 0) {
            hasher->update(reinterpret_cast<const uint8_t*>(chunk.data.data()), chunk.data_size);
            currentOutput.writeAt(currentOutputOffset, chunk.data.data(), chunk.data_size);
            currentOutputOffset += chunk.data_size;
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
            currentOutput.syncToDevice();
            currentOutput.close();
            currentOutputOffset = 0;
            currentFileName.clear();
        }

        if (progressCallback && totalBytes > 0) {
            progressCallback(bytesWritten, totalBytes);
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

    if (currentOutput.isOpen()) {
        currentOutput.syncToDevice();
        currentOutput.close();
    }
}
