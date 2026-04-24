#include "BenchMeasurerGuard.h"
#include "Logger.h"

BenchMeasurerGuard::BenchMeasurerGuard(const std::string& func) 
: begin_(std::chrono::steady_clock::now())
, func_(func)
{}

BenchMeasurerGuard::~BenchMeasurerGuard() {
    end_ = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_ - begin_);
    LOG_BENCH("%s: took %lld ms", func_.c_str(), duration.count());
}
