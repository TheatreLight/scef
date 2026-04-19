#include "KdfProfiles.h"

#include <array>

static constexpr std::array<KdfProfileParams, 4> kProfiles{{
    { EKDFProfile::Browser,  "browser",    64 * 1024,  1, 1 },
    { EKDFProfile::Fast,     "fast",      256 * 1024,  1, 4 },
    { EKDFProfile::Standard, "default",  1024 * 1024,  1, 4 },
    { EKDFProfile::High,     "high",     2048 * 1024,  1, 4 },
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
