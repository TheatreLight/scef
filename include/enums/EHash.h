#ifndef EHASH_H
#define EHASH_H

#include "ECiphers.h"

#include <cstddef>
#include <cstdint>
#include <string_view>

enum class EHash : uint8_t {
    None         = 0x00,
    SHA_256      = 0x01,
    Streebog_256 = 0x02,
    Streebog_512 = 0x03,
};

[[nodiscard]] constexpr bool isKnownHash(EHash h) noexcept {
    return h == EHash::None ||
           h == EHash::SHA_256 ||
           h == EHash::Streebog_256 ||
           h == EHash::Streebog_512;
}

[[nodiscard]] constexpr bool isSupportedHash(EHash h) noexcept {
    return h == EHash::SHA_256 ||
           h == EHash::Streebog_256 ||
           h == EHash::Streebog_512;
}

[[nodiscard]] constexpr std::string_view botanHashName(EHash h) noexcept {
    switch (h) {
        case EHash::SHA_256:      return "SHA-256";
        case EHash::Streebog_256: return "Streebog-256";
        case EHash::Streebog_512: return "Streebog-512";
        default:                  return "";
    }
}

[[nodiscard]] constexpr std::string_view botanHmacName(EHash h) noexcept {
    switch (h) {
        case EHash::SHA_256:      return "HMAC(SHA-256)";
        case EHash::Streebog_256: return "HMAC(Streebog-256)";
        case EHash::Streebog_512: return "HMAC(Streebog-512)";
        default:                  return "";
    }
}

[[nodiscard]] constexpr std::string_view hashDisplayName(EHash h) noexcept {
    switch (h) {
        case EHash::None:         return "None";
        case EHash::SHA_256:      return "SHA-256";
        case EHash::Streebog_256: return "Streebog-256";
        case EHash::Streebog_512: return "Streebog-512";
        default:                  return "Unknown";
    }
}

[[nodiscard]] constexpr size_t hashOutputSize(EHash h) noexcept {
    switch (h) {
        case EHash::SHA_256:
        case EHash::Streebog_256:
            return 32;
        case EHash::Streebog_512:
            return 64;
        default:
            return 0;
    }
}

// Returns the default hash algorithm for a given cipher.
// AES-256-GCM → SHA-256; Kuznechik-GCM → Streebog-512.
[[nodiscard]] constexpr EHash defaultHashForCipher(ECipher c) noexcept {
    return c == ECipher::Kuznechik_GCM ? EHash::Streebog_512 : EHash::SHA_256;
}

#endif // EHASH_H
