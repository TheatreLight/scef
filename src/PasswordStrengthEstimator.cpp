#include "PasswordStrengthEstimator.h"

#include "zxcvbn.h"

#include <cmath>
#include <cstdio>
#include <sstream>
#include <string>

namespace {

constexpr double OFFLINE_GUESSES_PER_SECOND = 1.0e10;

const char* profileName(EKDFProfile profile) noexcept
{
    switch (profile) {
        case EKDFProfile::Standard: return "Standard";
        case EKDFProfile::Fast:     return "Fast";
        case EKDFProfile::High:     return "High";
        case EKDFProfile::Browser:  return "Browser";
        case EKDFProfile::None:     return "Custom";
    }
    return "Custom";
}

int scoreFromBits(double bits) noexcept
{
    if (bits < 12.0) {
        return 0;
    }
    if (bits < 28.0) {
        return 1;
    }
    if (bits < 36.0) {
        return 2;
    }
    if (bits < 60.0) {
        return 3;
    }
    return 4;
}

std::string pluralize(long long value, const char* singular, const char* plural)
{
    std::ostringstream out;
    out << value << ' ' << (value == 1 ? singular : plural);
    return out.str();
}

std::string formatCrackTime(double bits)
{
    const double seconds = std::exp2(bits) / OFFLINE_GUESSES_PER_SECOND;
    if (!std::isfinite(seconds)) {
        return "many years";
    }
    if (seconds < 1.0) {
        return "instant";
    }

    constexpr double SECONDS_PER_MINUTE = 60.0;
    constexpr double SECONDS_PER_HOUR = 60.0 * SECONDS_PER_MINUTE;
    constexpr double SECONDS_PER_DAY = 24.0 * SECONDS_PER_HOUR;
    constexpr double SECONDS_PER_YEAR = 365.0 * SECONDS_PER_DAY;

    if (seconds < SECONDS_PER_HOUR) {
        const auto minutes = static_cast<long long>(std::max(1.0, std::round(seconds / SECONDS_PER_MINUTE)));
        return pluralize(minutes, "minute", "minutes");
    }
    if (seconds < SECONDS_PER_DAY) {
        const auto hours = static_cast<long long>(std::max(1.0, std::round(seconds / SECONDS_PER_HOUR)));
        return pluralize(hours, "hour", "hours");
    }
    if (seconds < SECONDS_PER_YEAR) {
        const auto days = static_cast<long long>(std::max(1.0, std::round(seconds / SECONDS_PER_DAY)));
        return pluralize(days, "day", "days");
    }

    const auto years = static_cast<long long>(std::max(1.0, std::round(seconds / SECONDS_PER_YEAR)));
    return pluralize(years, "year", "years");
}

} // namespace

PasswordStrengthEstimator::PasswordStrengthEstimator() = default;

PasswordStrengthEstimator::~PasswordStrengthEstimator() = default;

PasswordStrengthEstimator::Result
PasswordStrengthEstimator::estimate(const Botan::secure_vector<char>& password, EKDFProfile profile) const
{
    Botan::secure_vector<char> nulTerminated(password.begin(), password.end());
    nulTerminated.push_back('\0');

    ZxcMatch_t* matches = nullptr;
    const double bits = ZxcvbnMatch(nulTerminated.data(), nullptr, &matches);
    ZxcvbnFreeInfo(matches);

    Result result{};
    result.bits = bits;
    result.score = scoreFromBits(bits);
    result.recommendedMin = recommendedMinScore(profile);
    result.meetsRecommendation = result.score >= result.recommendedMin;
    result.crackTimeOffline = formatCrackTime(bits);

    if (!result.meetsRecommendation) {
        char buffer[256];
        std::snprintf(buffer, sizeof(buffer),
                      "Password score %d/4 (~%.0f bits) is below recommended minimum %d for profile '%s'. "
                      "Estimated offline crack time: %s.",
                      result.score,
                      result.bits,
                      result.recommendedMin,
                      profileName(profile),
                      result.crackTimeOffline.c_str());
        result.warning = buffer;
    }

    return result;
}

int PasswordStrengthEstimator::recommendedMinScore(EKDFProfile profile) noexcept
{
    switch (profile) {
        case EKDFProfile::High:
            return 4;
        case EKDFProfile::Browser:
        case EKDFProfile::Fast:
        case EKDFProfile::Standard:
        case EKDFProfile::None:
            return 3;
    }
    return 3;
}
