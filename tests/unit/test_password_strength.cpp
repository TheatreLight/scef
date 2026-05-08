#include "PasswordStrengthEstimator.h"

#include <botan/secmem.h>

#include <gtest/gtest.h>

#include <string_view>

// GUI coverage note: the weak-password modal in gui/qml/CreatePage.qml depends
// on the Qt event loop and a real window, so it is not covered by these
// headless unit tests. The underlying ScefController::estimatePasswordStrength
// facade can be covered later with Qt Test if needed post-MVP.

namespace {

Botan::secure_vector<char> make_secure_vector(std::string_view text) {
    return Botan::secure_vector<char>(text.begin(), text.end());
}

} // namespace

TEST(PasswordStrengthEstimatorTest, KnownWeakPassword) {
    PasswordStrengthEstimator est;
    auto r = est.estimate(make_secure_vector("password"), EKDFProfile::Standard);
    EXPECT_LE(r.score, 1);
    EXPECT_LT(r.bits, 12.0);
    EXPECT_FALSE(r.meetsRecommendation);
    EXPECT_FALSE(r.warning.empty());
}

TEST(PasswordStrengthEstimatorTest, WheelerExampleTr0ub4dor) {
    PasswordStrengthEstimator est;
    // zxcvbn-c master with its generated dictionary rates this higher than
    // the report's approximate value for Wheeler's example.
    auto r = est.estimate(make_secure_vector("Tr0ub4dor&3"), EKDFProfile::Standard);
    EXPECT_GE(r.bits, 25.0);
    EXPECT_LE(r.bits, 50.0);
}

TEST(PasswordStrengthEstimatorTest, DicewarePassphrase) {
    PasswordStrengthEstimator est;
    auto r = est.estimate(make_secure_vector("correct horse battery staple"), EKDFProfile::High);
    EXPECT_GE(r.score, 3);
    EXPECT_GT(r.bits, 30.0);
}

TEST(PasswordStrengthEstimatorTest, RandomLongPassword) {
    PasswordStrengthEstimator est;
    auto r = est.estimate(make_secure_vector("a8K!92xQp$Lm7vRn4eY*hT"), EKDFProfile::High);
    EXPECT_EQ(r.score, 4);
    EXPECT_TRUE(r.meetsRecommendation);
    EXPECT_TRUE(r.warning.empty());
}

TEST(PasswordStrengthEstimatorTest, ProfileThresholdsMatchTable) {
    EXPECT_EQ(PasswordStrengthEstimator::recommendedMinScore(EKDFProfile::Browser),  3);
    EXPECT_EQ(PasswordStrengthEstimator::recommendedMinScore(EKDFProfile::Fast),     3);
    EXPECT_EQ(PasswordStrengthEstimator::recommendedMinScore(EKDFProfile::Standard), 3);
    EXPECT_EQ(PasswordStrengthEstimator::recommendedMinScore(EKDFProfile::High),     4);
    EXPECT_EQ(PasswordStrengthEstimator::recommendedMinScore(EKDFProfile::None),     3);
}

TEST(PasswordStrengthEstimatorTest, EmptyPasswordIsRejected) {
    PasswordStrengthEstimator est;
    auto r = est.estimate(make_secure_vector(""), EKDFProfile::Standard);
    EXPECT_EQ(r.score, 0);
    EXPECT_FALSE(r.meetsRecommendation);
}

// Spec: Standard profile minimum score = 3; High profile minimum score = 4.
// A password that scores exactly 3 must meet Standard but NOT meet High.
// This test is unconditional: we first assert the score is exactly 3 so any
// regression in the estimator (e.g., dictionary changes) is surfaced immediately
// rather than silently skipping the threshold assertion.
//
// "MoreSecure!42" was chosen because the original conditional test expected it to
// score 3. We make that expectation explicit with ASSERT_EQ so the test fails
// loudly if the estimator changes, instead of becoming vacuous.
TEST(PasswordStrengthEstimatorTest, ScoreThree_MeetsStandard_NotHigh) {
    PasswordStrengthEstimator est;
    auto rStandard = est.estimate(make_secure_vector("MoreSecure!42"), EKDFProfile::Standard);
    auto rHigh     = est.estimate(make_secure_vector("MoreSecure!42"), EKDFProfile::High);

    // If this assertion fires, the estimator changed and the password must be updated
    // to one that reliably produces score 3 (bits in [36, 60)).
    ASSERT_EQ(rStandard.score, 3)
        << "Precondition: 'MoreSecure!42' must score exactly 3 for this test to be meaningful. "
           "If the estimator changed, update the password to one that scores 3.";

    EXPECT_TRUE(rStandard.meetsRecommendation)
        << "Spec: score 3 must meet Standard profile (recommendedMin = 3).";
    EXPECT_FALSE(rHigh.meetsRecommendation)
        << "Spec: score 3 must NOT meet High profile (recommendedMin = 4). "
           "Both profiles must use the same password; only the threshold differs.";
}

// Spec: the threshold table is the single source of truth for meetsRecommendation.
// A password that scores 4 (the maximum) must meet ALL profiles, including High.
// This is the complementary test: it exercises the path where score == recommendedMin for High.
TEST(PasswordStrengthEstimatorTest, ScoreFour_MeetsAllProfiles) {
    PasswordStrengthEstimator est;
    // "a8K!92xQp$Lm7vRn4eY*hT" is verified by RandomLongPassword test to score 4.
    auto rHigh     = est.estimate(make_secure_vector("a8K!92xQp$Lm7vRn4eY*hT"), EKDFProfile::High);
    auto rStandard = est.estimate(make_secure_vector("a8K!92xQp$Lm7vRn4eY*hT"), EKDFProfile::Standard);

    ASSERT_EQ(rHigh.score, 4)
        << "Precondition: 'a8K!92xQp$Lm7vRn4eY*hT' must score exactly 4.";

    EXPECT_TRUE(rHigh.meetsRecommendation)
        << "Spec: score 4 must meet High profile (recommendedMin = 4).";
    EXPECT_TRUE(rStandard.meetsRecommendation)
        << "Spec: score 4 must also meet Standard profile (recommendedMin = 3).";
}
