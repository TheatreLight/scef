#ifndef FRAGMENTED_IO_H
#define FRAGMENTED_IO_H

#include <cstddef>
#include <cstdint>
#include <functional>

struct FragmentedIO {
    // Write 'size' bytes at absolute 'offset'; returns new offset after slot-skipping.
    std::function<uint64_t(uint64_t offset, const char* data, size_t size)> write;
    // Read 'size' bytes from 'offset'; returns new offset after slot-skipping.
    // Throws on short read.
    std::function<uint64_t(uint64_t offset, char* buf, size_t size)> read;
    // Advance past any slot region the offset lands inside.
    std::function<uint64_t(uint64_t pos)> skipSlots;
};

#endif // FRAGMENTED_IO_H
