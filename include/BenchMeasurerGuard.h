#ifndef BENCHMEASURERGUARD_H
#define BENCHMEASURERGUARD_H

#include <chrono>
#include <string>

class BenchMeasurerGuard {
public:
    BenchMeasurerGuard() = delete;
    BenchMeasurerGuard(const std::string& func, uint64_t throughputBytes=0);
    ~BenchMeasurerGuard();
    BenchMeasurerGuard(const BenchMeasurerGuard&) = delete;
    BenchMeasurerGuard& operator=(const BenchMeasurerGuard&) = delete;
    BenchMeasurerGuard(BenchMeasurerGuard&&) = delete;
    BenchMeasurerGuard& operator=(BenchMeasurerGuard&&) = delete;

private:
    std::chrono::time_point<std::chrono::steady_clock> begin_;
    std::chrono::time_point<std::chrono::steady_clock> end_;
    std::string func_;
    bool throughput_=false;
    uint64_t totalBytes_ = 0;
};

#endif // BENCHMEASURERGUARD_H
