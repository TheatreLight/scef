#ifndef ECIPHERS_H
#define ECIPHERS_H

#include <cstdint>

enum class ECipher : uint8_t {
    None = 0x00,
    AES_256_GCM = 0x01,
};

#endif // ECIPHERS_H
