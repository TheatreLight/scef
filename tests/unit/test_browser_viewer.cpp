// =============================================================================
// BrowserViewer Unit Tests
//
// Tests verify the public copyBrowserViewer/getExecutableDir contract used by
// the CLI and GUI wrappers.
// =============================================================================

#include <gtest/gtest.h>

#include "BrowserViewer.h"

#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::string sanitize(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const unsigned char ch : text) {
        out.push_back(std::isalnum(ch) ? static_cast<char>(ch) : '_');
    }
    return out;
}

fs::path make_temp_dir(const testing::TestInfo* info) {
    const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path base = fs::temp_directory_path() /
        ("scef_browser_viewer_" + sanitize(info->test_suite_name()) + "_" +
         sanitize(info->name()) + "_" + std::to_string(ticks));
    fs::create_directories(base);
    return base;
}

void write_file(const fs::path& path, const std::vector<uint8_t>& data) {
    if (!path.parent_path().empty()) {
        fs::create_directories(path.parent_path());
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(out.good()) << "Cannot open " << path;
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    }
    ASSERT_TRUE(out.good()) << "Cannot write " << path;
}

std::vector<uint8_t> read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    EXPECT_TRUE(in.good()) << "Cannot open " << path;
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

} // namespace

class BrowserViewerTest : public ::testing::Test {
protected:
    fs::path tmp_dir_;

    void SetUp() override {
        tmp_dir_ = make_temp_dir(::testing::UnitTest::GetInstance()->current_test_info());
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(tmp_dir_, ec);
    }
};

TEST_F(BrowserViewerTest, CopyBrowserViewer_SourceMissing_ReturnsFailureWithPath) {
    const fs::path source_dir = tmp_dir_ / "source";
    const fs::path dest_dir = tmp_dir_ / "dest";
    fs::create_directories(source_dir);
    fs::create_directories(dest_dir);

    const auto result = scef::copyBrowserViewer(source_dir, dest_dir);

    EXPECT_FALSE(result.success);
    EXPECT_NE(result.errorMessage.find((source_dir / "index.html").string()),
              std::string::npos);
}

TEST_F(BrowserViewerTest, CopyBrowserViewer_SourceIsDirectory_ReturnsFailure) {
    const fs::path source_dir = tmp_dir_ / "source";
    const fs::path dest_dir = tmp_dir_ / "dest";
    fs::create_directories(source_dir / "index.html");
    fs::create_directories(dest_dir);

    const auto result = scef::copyBrowserViewer(source_dir, dest_dir);

    EXPECT_FALSE(result.success);
}

TEST_F(BrowserViewerTest, CopyBrowserViewer_DestDirExists_CopiesByteForByte) {
    const fs::path source_dir = tmp_dir_ / "source";
    const fs::path dest_dir = tmp_dir_ / "dest";
    const std::vector<uint8_t> source_bytes = {
        0x00, 0x01, 0x02, 0x53, 0x43, 0x45, 0x46, 0xFF, 0x7F
    };
    write_file(source_dir / "index.html", source_bytes);
    fs::create_directories(dest_dir);

    const auto result = scef::copyBrowserViewer(source_dir, dest_dir);

    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_EQ(read_file(dest_dir / "index.html"), source_bytes);
}

TEST_F(BrowserViewerTest, CopyBrowserViewer_DestHasDifferentContent_OverwritesSilently) {
    const fs::path source_dir = tmp_dir_ / "source";
    const fs::path dest_dir = tmp_dir_ / "dest";
    const std::vector<uint8_t> source_bytes = {'n', 'e', 'w', '\0', 'd', 'a', 't', 'a'};
    write_file(source_dir / "index.html", source_bytes);
    write_file(dest_dir / "index.html", {'o', 'l', 'd'});

    const auto result = scef::copyBrowserViewer(source_dir, dest_dir);

    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_EQ(read_file(dest_dir / "index.html"), source_bytes);
}

TEST_F(BrowserViewerTest, CopyBrowserViewer_SourceEqualsDest_NoOpSuccessLeavesFileUntouched) {
    const fs::path shared_dir = tmp_dir_ / "shared";
    const std::vector<uint8_t> original = {'u', 'n', 't', 'o', 'u', 'c', 'h', 'e', 'd'};
    write_file(shared_dir / "index.html", original);

    const auto result = scef::copyBrowserViewer(shared_dir, shared_dir);

    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_TRUE(result.errorMessage.empty());
    EXPECT_EQ(read_file(shared_dir / "index.html"), original);
}

TEST_F(BrowserViewerTest, CopyBrowserViewer_DestDirMissing_CreatesDirectoriesAndCopies) {
    const fs::path source_dir = tmp_dir_ / "source";
    const fs::path dest_dir = tmp_dir_ / "missing" / "nested" / "dest";
    const std::vector<uint8_t> source_bytes = {'<', 'h', 't', 'm', 'l', '>'};
    write_file(source_dir / "index.html", source_bytes);
    ASSERT_FALSE(fs::exists(dest_dir));

    const auto result = scef::copyBrowserViewer(source_dir, dest_dir);

    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_EQ(read_file(dest_dir / "index.html"), source_bytes);
}

TEST(BrowserViewerExecutableDirTest, GetExecutableDir_Smoke_ReturnsExistingDirectory) {
    const fs::path exe_dir = scef::getExecutableDir();

    EXPECT_FALSE(exe_dir.empty());
    EXPECT_TRUE(fs::exists(exe_dir));
    EXPECT_TRUE(fs::is_directory(exe_dir));
}
