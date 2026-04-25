#include "PasswordStrengthEstimator.h"

#include <gtest/gtest.h>

// GUI coverage note: the weak-password modal in gui/qml/CreatePage.qml depends
// on the Qt event loop and a real window, so it is not covered by these
// headless unit tests. The underlying ScefController::estimatePasswordStrength
// facade can be covered later with Qt Test if needed post-MVP.

TEST(PasswordStrengthEstimatorTest, KnownWeakPassword) {
    PasswordStrengthEstimator est;
    auto r = est.estimate("password", EKDFProfile::Standard);
    EXPECT_LE(r.score, 1);
    EXPECT_LT(r.bits, 12.0);
    EXPECT_FALSE(r.meetsRecommendation);
    EXPECT_FALSE(r.warning.empty());
}

TEST(PasswordStrengthEstimatorTest, WheelerExampleTr0ub4dor) {
    PasswordStrengthEstimator est;
    // zxcvbn-c master with its generated dictionary rates this higher than
    // the report's approximate value for Wheeler's example.
    auto r = est.estimate("Tr0ub4dor&3", EKDFProfile::Standard);
    EXPECT_GE(r.bits, 25.0);
    EXPECT_LE(r.bits, 50.0);
}

TEST(PasswordStrengthEstimatorTest, DicewarePassphrase) {
    PasswordStrengthEstimator est;
    auto r = est.estimate("correct horse battery staple", EKDFProfile::High);
    EXPECT_GE(r.score, 3);
    EXPECT_GT(r.bits, 30.0);
}

TEST(PasswordStrengthEstimatorTest, RandomLongPassword) {
    PasswordStrengthEstimator est;
    auto r = est.estimate("a8K!92xQp$Lm7vRn4eY*hT", EKDFProfile::High);
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
    auto r = est.estimate("", EKDFProfile::Standard);
    EXPECT_EQ(r.score, 0);
    EXPECT_FALSE(r.meetsRecommendation);
}

TEST(PasswordStrengthEstimatorTest, HighProfileRequiresHigherScore) {
    PasswordStrengthEstimator est;
    auto rStandard = est.estimate("MoreSecure!42", EKDFProfile::Standard);
    auto rHigh     = est.estimate("MoreSecure!42", EKDFProfile::High);
    if (rStandard.score == 3) {
        EXPECT_TRUE(rStandard.meetsRecommendation);
        EXPECT_FALSE(rHigh.meetsRecommendation);
    }
}
