#ifndef BENCHMEASURERGUARD_H
#define BENCHMEASURERGUARD_H

#include <chrono>
#include <string>

class BenchMeasurerGuard {
public:
    BenchMeasurerGuard(const std::string& func);
    ~BenchMeasurerGuard();
    BenchMeasurerGuard(const BenchMeasurerGuard&) = delete;
    BenchMeasurerGuard& operator=(const BenchMeasurerGuard&) = delete;
    BenchMeasurerGuard(BenchMeasurerGuard&&) = delete;
    BenchMeasurerGuard& operator=(BenchMeasurerGuard&&) = delete;

private:
    std::chrono::time_point<std::chrono::steady_clock> begin_;
    std::chrono::time_point<std::chrono::steady_clock> end_;
    std::string func_;
};

#endif // BENCHMEASURERGUARD_H
