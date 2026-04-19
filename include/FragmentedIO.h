#ifndef FRAGMENTED_IO_H
#define FRAGMENTED_IO_H

#include <cstdint>
#include <functional>

struct FragmentedIO {
    std::function<uint64_t(const char* data, size_t size)> write;
    std::function<void(char* buf, size_t size)> read;
    std::function<uint64_t(uint64_t pos)> skipSlots;
    std::function<void(uint64_t pos)> seekWrite;
    std::function<uint64_t()> tellWrite;
    std::function<void(uint64_t pos)> seekRead;
};

#endif // FRAGMENTED_IO_H
