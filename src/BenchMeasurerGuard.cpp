#include "BenchMeasurerGuard.h"
#include "Logger.h"

BenchMeasurerGuard::BenchMeasurerGuard(const std::string& func, uint64_t throughputBytes) 
: begin_(std::chrono::steady_clock::now())
, func_(func)
, throughput_(throughputBytes > 0)
, totalBytes_(throughputBytes)
{}

BenchMeasurerGuard::~BenchMeasurerGuard() {
    end_ = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_ - begin_).count();
    if (throughput_) {
        double throughput = (duration > 0) ? (static_cast<double>(totalBytes_) / 1024.0 / 1024.0) / (duration / 1000.0) : 0;
        LOG_BENCH("%s: finished in %lld ms (%.1f MB/s)", func_.c_str(), duration, throughput);
    } else {
        LOG_BENCH("%s: took %lld ms", func_.c_str(), duration);
    }
}
