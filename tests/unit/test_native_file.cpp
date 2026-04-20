// =============================================================================
// NativeFile Unit Tests
//
// Tests verify correctness of cross-platform positional I/O, sparse prealloc,
// move semantics, syncToDevice, and error handling.
// =============================================================================

#include <gtest/gtest.h>

#include "NativeFile.h"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

fs::path make_temp_dir(const std::string& suffix) {
    fs::path base = fs::temp_directory_path() / ("nf_test_" + suffix);
    fs::remove_all(base);
    fs::create_directories(base);
    return base;
}

} // namespace

// ===========================================================================
// Fixture
// ===========================================================================

class NativeFileTest : public ::testing::Test {
protected:
    fs::path dir_;

    void SetUp() override {
        dir_ = make_temp_dir("nativefile");
    }

    void TearDown() override {
        fs::remove_all(dir_);
    }
};

// ===========================================================================
// Tests
// ===========================================================================

// open(CreateTruncate) on new path => isOpen() returns true.
TEST_F(NativeFileTest, CreateTruncateNewFile_IsOpen) {
    NativeFile f;
    f.open((dir_ / "new.bin").string(), NativeFile::OpenMode::CreateTruncate);
    EXPECT_TRUE(f.isOpen());
}

// open(CreateTruncate) on existing file => size becomes 0 (truncation).
TEST_F(NativeFileTest, CreateTruncateExistingFile_TruncatesToZero) {
    fs::path p = dir_ / "existing.bin";
    // Seed file with some bytes.
    {
        NativeFile seed;
        seed.open(p.string(), NativeFile::OpenMode::CreateTruncate);
        const char data[] = "hello world";
        seed.writeAt(0, data, sizeof(data) - 1);
    }
    ASSERT_GT(fs::file_size(p), 0u);

    // Reopen with CreateTruncate should truncate.
    NativeFile f;
    f.open(p.string(), NativeFile::OpenMode::CreateTruncate);
    EXPECT_EQ(f.size(), 0u);
}

// open(OpenExisting) on non-existent path => throws.
TEST_F(NativeFileTest, OpenExistingNonExistent_Throws) {
    NativeFile f;
    EXPECT_THROW(
        f.open((dir_ / "no_such_file.bin").string(), NativeFile::OpenMode::OpenExisting),
        std::exception);
}

// open(OpenReadOnly) then writeAt => throws (write on read-only handle).
TEST_F(NativeFileTest, OpenReadOnly_WriteThrows) {
    fs::path p = dir_ / "readonly.bin";
    {
        NativeFile seed;
        seed.open(p.string(), NativeFile::OpenMode::CreateTruncate);
        const char data[] = "data";
        seed.writeAt(0, data, 4);
    }

    NativeFile f;
    f.open(p.string(), NativeFile::OpenMode::OpenReadOnly);
    ASSERT_TRUE(f.isOpen());
    const char buf[] = "fail";
    EXPECT_THROW(f.writeAt(0, buf, 4), std::exception);
}

// Round-trip at offset 0.
TEST_F(NativeFileTest, RoundTripAtOffset0) {
    NativeFile f;
    f.open((dir_ / "rt0.bin").string(), NativeFile::OpenMode::CreateTruncate);

    const char src[] = "hello";
    f.writeAt(0, src, 5);

    char dst[5] = {};
    f.readAt(0, dst, 5);
    EXPECT_EQ(std::memcmp(src, dst, 5), 0);
}

// Round-trip at non-zero offset.
TEST_F(NativeFileTest, RoundTripAtOffset1000) {
    NativeFile f;
    f.open((dir_ / "rt1000.bin").string(), NativeFile::OpenMode::CreateTruncate);
    f.preallocateSparse(2000);

    const char src[] = "offset_data";
    f.writeAt(1000, src, 11);

    char dst[11] = {};
    f.readAt(1000, dst, 11);
    EXPECT_EQ(std::memcmp(src, dst, 11), 0);
}

// readAt past EOF => throws.
TEST_F(NativeFileTest, ReadAtPastEOF_Throws) {
    NativeFile f;
    f.open((dir_ / "small.bin").string(), NativeFile::OpenMode::CreateTruncate);
    f.writeAt(0, "ab", 2);

    char buf[10] = {};
    EXPECT_THROW(f.readAt(0, buf, 10), std::exception);
}

// readSome past EOF => returns 0.
TEST_F(NativeFileTest, ReadSomePastEOF_ReturnsZero) {
    NativeFile f;
    f.open((dir_ / "rsome.bin").string(), NativeFile::OpenMode::CreateTruncate);
    f.writeAt(0, "xyz", 3);

    char buf[10] = {};
    size_t got = f.readSome(100, buf, 10);
    EXPECT_EQ(got, 0u);
}

// readSome partial: request more than available => returns actual count.
TEST_F(NativeFileTest, ReadSomePartial_ReturnsRemaining) {
    NativeFile f;
    f.open((dir_ / "partial.bin").string(), NativeFile::OpenMode::CreateTruncate);
    f.writeAt(0, "ABCDE", 5);

    char buf[20] = {};
    size_t got = f.readSome(0, buf, 20);
    EXPECT_GE(got, 1u);
    EXPECT_LE(got, 5u);
    EXPECT_EQ(buf[0], 'A');
}

// preallocateSparse(1 MiB) => size() returns 1 MiB; region reads as zeros.
TEST_F(NativeFileTest, PreallocateSparse_1MiB_SizeCorrect) {
    constexpr uint64_t SIZE = 1024 * 1024;
    NativeFile f;
    f.open((dir_ / "sparse1m.bin").string(), NativeFile::OpenMode::CreateTruncate);
    f.preallocateSparse(SIZE);
    EXPECT_EQ(f.size(), SIZE);

    // Read the first and last 4 bytes to verify they are zero.
    char buf[4] = {1, 1, 1, 1};
    f.readAt(0, buf, 4);
    EXPECT_EQ(buf[0], 0);
    EXPECT_EQ(buf[3], 0);

    char buf2[4] = {1, 1, 1, 1};
    f.readAt(SIZE - 4, buf2, 4);
    EXPECT_EQ(buf2[0], 0);
    EXPECT_EQ(buf2[3], 0);
}

// preallocateSparse(200 MiB) completes in well under 5 seconds (sparse check).
TEST_F(NativeFileTest, PreallocateSparse_200MiB_IsFast) {
    constexpr uint64_t SIZE = 200ULL * 1024 * 1024;
    NativeFile f;
    f.open((dir_ / "sparse200m.bin").string(), NativeFile::OpenMode::CreateTruncate);

    auto t0 = std::chrono::steady_clock::now();
    f.preallocateSparse(SIZE);
    auto elapsed = std::chrono::steady_clock::now() - t0;
    double seconds = std::chrono::duration<double>(elapsed).count();

    EXPECT_EQ(f.size(), SIZE);
    EXPECT_LT(seconds, 5.0)
        << "preallocateSparse(200 MiB) took " << seconds
        << "s — expected sparse allocation to be near-instant";
}

// syncToDevice on an open file does not throw.
TEST_F(NativeFileTest, SyncToDevice_OpenFile_NoThrow) {
    NativeFile f;
    f.open((dir_ / "sync.bin").string(), NativeFile::OpenMode::CreateTruncate);
    f.writeAt(0, "data", 4);
    EXPECT_NO_THROW(f.syncToDevice());
}

// syncToDevice on a closed file is a no-op (no throw).
TEST_F(NativeFileTest, SyncToDevice_ClosedFile_NoThrow) {
    NativeFile f;
    EXPECT_NO_THROW(f.syncToDevice());
}

// Move constructor: source becomes closed, target is usable.
TEST_F(NativeFileTest, MoveConstructor_SourceClosed_TargetUsable) {
    NativeFile src;
    src.open((dir_ / "move.bin").string(), NativeFile::OpenMode::CreateTruncate);
    src.writeAt(0, "move", 4);
    ASSERT_TRUE(src.isOpen());

    NativeFile dst(std::move(src));
    EXPECT_FALSE(src.isOpen());  // NOLINT(bugprone-use-after-move)
    EXPECT_TRUE(dst.isOpen());

    char buf[4] = {};
    dst.readAt(0, buf, 4);
    EXPECT_EQ(std::memcmp("move", buf, 4), 0);
}

// Move assignment: source becomes closed, target usable; old target closed.
TEST_F(NativeFileTest, MoveAssignment_OldTargetClosed_SourceClosed) {
    NativeFile f1;
    f1.open((dir_ / "ma1.bin").string(), NativeFile::OpenMode::CreateTruncate);
    f1.writeAt(0, "f1f1", 4);

    NativeFile f2;
    f2.open((dir_ / "ma2.bin").string(), NativeFile::OpenMode::CreateTruncate);
    f2.writeAt(0, "f2f2", 4);

    f2 = std::move(f1);
    EXPECT_FALSE(f1.isOpen());  // NOLINT(bugprone-use-after-move)
    EXPECT_TRUE(f2.isOpen());

    char buf[4] = {};
    f2.readAt(0, buf, 4);
    EXPECT_EQ(std::memcmp("f1f1", buf, 4), 0);
}

// After close(), isOpen() returns false.
TEST_F(NativeFileTest, AfterClose_IsOpenFalse) {
    NativeFile f;
    f.open((dir_ / "close.bin").string(), NativeFile::OpenMode::CreateTruncate);
    ASSERT_TRUE(f.isOpen());
    f.close();
    EXPECT_FALSE(f.isOpen());
}
