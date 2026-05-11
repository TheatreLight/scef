#ifndef ECIPHERS_H
#define ECIPHERS_H

#include <cstdint>
#include <string_view>

enum class ECipher : uint8_t {
    None           = 0x00,
    AES_256_GCM    = 0x01,
    Kuznechik_GCM  = 0x02,
};

[[nodiscard]] constexpr bool isSupportedCipher(ECipher c) noexcept {
    return c == ECipher::AES_256_GCM || c == ECipher::Kuznechik_GCM;
}

[[nodiscard]] constexpr std::string_view cipherDisplayName(ECipher c) noexcept {
    switch (c) {
        case ECipher::None:          return "None";
        case ECipher::AES_256_GCM:   return "AES-256-GCM";
        case ECipher::Kuznechik_GCM: return "Kuznechik-GCM";
        default:                     return "Unknown";
    }
}

#endif // ECIPHERS_H
