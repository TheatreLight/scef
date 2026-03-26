#ifndef EKDF_H
#define EKDF_H

#include <cstdint>

enum class EKDF : uint8_t {
    None = 0x00,
    Argon2id = 0x01,
};

#endif // EKDF_H
