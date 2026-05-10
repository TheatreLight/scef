#ifndef ENCRYPT_PIPELINE_H
#define ENCRYPT_PIPELINE_H

#include "BoundedQueue.h"
#include "CryptoManager.h"
#include "enums/EHash.h"
#include "FileTable.h"
#include "FragmentedIO.h"
#include "Header.h"
#include "PipelineTypes.h"

#include <BS_thread_pool.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

class EncryptPipeline {
public:
    struct Config {
        size_t worker_count;
        size_t queue_capacity;
    };

    EncryptPipeline(CryptoManager& crypto, Config config, EHash hash_algo);
    ~EncryptPipeline();

    void run(const std::vector<std::string>& files,
             FragmentedIO& io,
             FileTable& fileTable,
             Header& header,
             uint64_t startOffset,
             const std::atomic<bool>& cancelFlag,
             std::function<void(uint64_t, uint64_t)> progressCallback);

    uint64_t endOffset() const { return endOffset_; }

private:
    void readerTask(const std::vector<std::string>& files,
                    const std::atomic<bool>& cancelFlag);

    void workerTask();

    void writerLoop(FragmentedIO& io,
                    FileTable& fileTable,
                    Header& header,
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
    uint64_t startOffset_ = 0;  // slot-adjusted start offset set by run()
    uint64_t endOffset_ = 0;
};

#endif // ENCRYPT_PIPELINE_H
