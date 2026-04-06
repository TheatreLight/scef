#ifndef EKDF_PROFILE_H
#define EKDF_PROFILE_H

#include <cstdint>

enum class EKDFProfile : uint16_t {
    None         = 0x0000,  // custom / manual params
    FastAccess   = 0x0001,
    Standard     = 0x0002,
    HighSecurity = 0x0003,
    Browser      = 0x0004,
};

#endif // EKDF_PROFILE_H