#ifndef DECRYPT_PIPELINE_H
#define DECRYPT_PIPELINE_H

#include "BoundedQueue.h"
#include "CryptoManager.h"
#include "enums/EHash.h"
#include "FileTable.h"
#include "FragmentedIO.h"
#include "PipelineTypes.h"

#include <BS_thread_pool.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

class DecryptPipeline {
public:
    struct Config {
        size_t worker_count;
        size_t queue_capacity;
    };

    DecryptPipeline(CryptoManager& crypto, Config config, EHash hash_algo);
    ~DecryptPipeline();

    void run(const std::vector<FileEntry>& entries,
             FragmentedIO& io,
             const std::string& outputDir,
             const std::atomic<bool>& cancelFlag,
             std::function<void(uint64_t, uint64_t)> progressCallback);

    const std::vector<std::string>& checksumFailures() const { return checksumFailures_; }

private:
    void readerTask(const std::vector<FileEntry>& entries,
                    FragmentedIO& io,
                    const std::atomic<bool>& cancelFlag);

    void workerTask();

    void writerLoop(const std::string& outputDir,
                    const std::atomic<bool>& cancelFlag,
                    std::function<void(uint64_t, uint64_t)> progressCallback,
                    uint64_t totalBytes);

    CryptoManager& crypto_;
    Config config_;
    EHash hash_algo_;
    BS::thread_pool<> pool_;
    BoundedQueue<ProcessedChunk> readQueue_;
    BoundedQueue<ProcessedChunk> writeQueue_;
    std::atomic<size_t> activeWorkers_{0};
    std::vector<std::string> checksumFailures_;
};

#endif // DECRYPT_PIPELINE_H
