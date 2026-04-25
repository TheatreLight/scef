#ifndef PASSWORD_STRENGTH_ESTIMATOR_H
#define PASSWORD_STRENGTH_ESTIMATOR_H

#include "enums/EKDFProfile.h"

#include <string>

class PasswordStrengthEstimator {
public:
    struct Result {
        int    score;                  // 0..4
        double bits;                   // log2(guesses)
        int    recommendedMin;         // for the requested profile
        bool   meetsRecommendation;
        std::string warning;           // English; empty if meetsRecommendation
        std::string crackTimeOffline;  // human-readable, e.g. "instant", "13 minutes"
    };

    PasswordStrengthEstimator();
    ~PasswordStrengthEstimator();

    PasswordStrengthEstimator(const PasswordStrengthEstimator&) = delete;
    PasswordStrengthEstimator& operator=(const PasswordStrengthEstimator&) = delete;
    PasswordStrengthEstimator(PasswordStrengthEstimator&&) = delete;
    PasswordStrengthEstimator& operator=(PasswordStrengthEstimator&&) = delete;

    // Pure function: does NOT log the password; does NOT keep a copy after return.
    Result estimate(const std::string& password, EKDFProfile profile) const;

    // Single source of truth for the profile threshold table.
    static int recommendedMinScore(EKDFProfile profile) noexcept;
};

#endif // PASSWORD_STRENGTH_ESTIMATOR_H
