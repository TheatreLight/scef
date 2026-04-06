#include "KdfProfiles.h"

#include <array>
#include <cstring>

// NOTE: all parameter values are TEMPORARY stubs that will be recalibrated
// after the benchmark command is used to measure real timings on target hardware.
static constexpr std::array<KdfProfileParams, 4> kProfiles{{
    { EKDFProfile::FastAccess,   "fast",    19 * 1024,  2, 1 },
    { EKDFProfile::Standard,     "default", 64 * 1024,  3, 4 },
    { EKDFProfile::HighSecurity, "high",   256 * 1024,  5, 8 },
    { EKDFProfile::Browser,      "browser", 46 * 1024,  1, 1 },
}};

const KdfProfileParams* getProfileParams(EKDFProfile id) {
    for (const auto& p : kProfiles) {
        if (p.id == id) {
            return &p;
        }
    }
    return nullptr;
}

const KdfProfileParams* getProfileByName(std::string_view name) {
    for (const auto& p : kProfiles) {
        if (name == p.name) {
            return &p;
        }
    }
    return nullptr;
}

EKDFProfile getDefaultProfile() {
    return EKDFProfile::Standard;
}
