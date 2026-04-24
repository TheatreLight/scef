#pragma once

#include "enums/EKDFProfile.h"

#include <cstdint>
#include <string_view>

// Validation bounds for Argon2id parameters — used on both write and read paths.
constexpr uint32_t KDF_M_KIB_MIN =    1u;            // absolute Argon2id minimum (1 KiB)
constexpr uint32_t KDF_M_KIB_WARN =   8u * 1024u;   // 8 MiB — below this, warn about weak security
constexpr uint32_t KDF_M_KIB_MAX = 4096u * 1024u;   // 4096 MiB
constexpr uint32_t KDF_T_MIN     = 1u;
constexpr uint32_t KDF_T_MAX     = 100u;
constexpr uint32_t KDF_P_MIN     = 1u;
constexpr uint32_t KDF_P_MAX     = 64u;

struct KdfProfileParams {
    EKDFProfile  id;
    const char*  name;    // CLI name used in --kdf-profile <name>
    uint32_t     m_kib;   // Argon2id memory in KiB
    uint32_t     t;       // Argon2id iterations
    uint32_t     p;       // Argon2id parallelism
};

// Returns the params table entry for a predefined profile, or nullptr if
// id is EKDFProfile::None (custom) or an unrecognized value.
[[nodiscard]] const KdfProfileParams* getProfileParams(EKDFProfile id);

// Looks up a profile by its CLI name (e.g. "fast", "default", "high", "browser").
// Returns nullptr if the name is not recognized.
[[nodiscard]] const KdfProfileParams* getProfileByName(std::string_view name);

