#ifndef EKDF_PROFILE_H
#define EKDF_PROFILE_H

#include <cstdint>

enum class EKDFProfile : uint16_t {
    None         = 0x0000,
    FastAccess   = 0x0001,
    Standard     = 0x0002,
    HighSecurity = 0x0003,
    Archive      = 0x0004,
    Browser      = 0x0005,
};

#endif // EKDF_PROFILE_H