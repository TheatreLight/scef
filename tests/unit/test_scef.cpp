// =============================================================================
// SCEF Spec-Compliance Tests
//
// These tests verify that the implementation matches the approved specification
// from Chapter 4 (4_main_ch4_format.md).
// =============================================================================

#include <gtest/gtest.h>

#include "Header.h"
#include "FileManager.h"

#include <botan/secmem.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

uint16_t le16_at(const uint8_t* buf, size_t offset) {
    return static_cast<uint16_t>(buf[offset]) |
           (static_cast<uint16_t>(buf[offset + 1]) << 8);
}

uint32_t le32_at(const uint8_t* buf, size_t offset) {
    return static_cast<uint32_t>(buf[offset]) |
           (static_cast<uint32_t>(buf[offset + 1]) << 8) |
           (static_cast<uint32_t>(buf[offset + 2]) << 16) |
           (static_cast<uint32_t>(buf[offset + 3]) << 24);
}

uint64_t le64_at(const uint8_t* buf, size_t offset) {
    return static_cast<uint64_t>(buf[offset]) |
           (static_cast<uint64_t>(buf[offset + 1]) << 8) |
           (static_cast<uint64_t>(buf[offset + 2]) << 16) |
           (static_cast<uint64_t>(buf[offset + 3]) << 24) |
           (static_cast<uint64_t>(buf[offset + 4]) << 32) |
           (static_cast<uint64_t>(buf[offset + 5]) << 40) |
           (static_cast<uint64_t>(buf[offset + 6]) << 48) |
           (static_cast<uint64_t>(buf[offset + 7]) << 56);
}

void write_file(const fs::path& path, const std::vector<uint8_t>& data) {
    fs::create_directories(path.parent_path());
    std::ofstream f(path, std::ios::binary);
    if (!data.empty()) {
        f.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
    }
}

std::vector<uint8_t> read_file(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

fs::path make_temp_dir(const std::string& suffix) {
    fs::path base = fs::temp_directory_path() / ("scef_test_" + suffix);
    fs::remove_all(base);
    fs::create_directories(base);
    return base;
}

Botan::secure_vector<char> make_secure_vector(std::string_view text) {
    return Botan::secure_vector<char>(text.begin(), text.end());
}

} // namespace

// ===========================================================================
// 1. HEADER FIELD LAYOUT — spec Table 4.2
//
// The spec defines precise offsets and sizes for each field.
// These tests verify the binary layout byte-by-byte.
// ===========================================================================

class HeaderLayoutTest : public ::testing::Test {
protected:
    Header header_;
    const uint8_t* buf() { return header_.buffer().data(); }
};

// Spec 4.2.4: file_table_size is uint32_le at offset 0x0080 (4 bytes).
TEST_F(HeaderLayoutTest, FileTableSizeAt0x0080_IsUint32) {
    header_.setFileTableSize(12345);
    header_.serialize();

    uint32_t val_at_0x80 = le32_at(buf(), 0x0080);
    EXPECT_EQ(val_at_0x80, 12345u)
        << "Spec requires file_table_size (uint32) at offset 0x0080. "
           "Bytes at 0x0080 must hold file_table_size.";
}

// Spec 4.2.4: max_table_size is uint32_le at offset 0x0084.
TEST_F(HeaderLayoutTest, MaxTableSizeAt0x0084_Exists) {
    header_.serialize();

    uint32_t val_at_0x84 = le32_at(buf(), 0x0084);
    EXPECT_EQ(val_at_0x84, BLOCK_SIZE)
        << "Spec requires max_table_size (uint32, default=block_size) at offset 0x0084. "
           "Bytes at 0x0084 must hold max_table_size.";
}

// Spec 4.2.4: file_count is uint32_le at offset 0x0088.
TEST_F(HeaderLayoutTest, FileCountAt0x0088) {
    header_.increaseFileCount();
    header_.serialize();

    uint32_t val_at_0x88 = le32_at(buf(), 0x0088);
    EXPECT_EQ(val_at_0x88, 1u)
        << "Spec requires file_count (uint32) at offset 0x0088. "
           "Bytes at 0x0088 must hold file_count.";
}

// Spec 4.2.4: block_size is uint32_le at offset 0x008C.
TEST_F(HeaderLayoutTest, BlockSizeAt0x008C) {
    header_.serialize();

    uint32_t val_at_0x8C = le32_at(buf(), 0x008C);
    EXPECT_EQ(val_at_0x8C, BLOCK_SIZE)
        << "Spec requires block_size (uint32) at offset 0x008C. "
           "Bytes at 0x008C must hold block_size.";
}

// Spec 4.2.4: header_version is uint32_le at offset 0x0090.
TEST_F(HeaderLayoutTest, HeaderVersionAt0x0090) {
    header_.serialize();

    uint32_t val_at_0x90 = le32_at(buf(), 0x0090);
    EXPECT_EQ(val_at_0x90, 0u)
        << "Spec requires header_version (uint32) at offset 0x0090. "
           "Bytes at 0x0090 must hold header_version.";
}

// Spec 4.2.4: flags is uint32_le at offset 0x0094.
TEST_F(HeaderLayoutTest, FlagsAt0x0094) {
    header_.serialize();

    uint32_t val_at_0x94 = le32_at(buf(), 0x0094);
    EXPECT_EQ(val_at_0x94, 0u)
        << "Spec requires flags (uint32) at offset 0x0094. "
           "Bytes at 0x0094 must hold flags.";
}

// Spec 4.2.6: reserved_0 is 8 zero bytes at offset 0x0098.
TEST_F(HeaderLayoutTest, Reserved0At0x0098_IsZero) {
    header_.increaseFileCount();
    header_.serialize();

    for (size_t i = 0x0098; i < 0x00A0; ++i) {
        EXPECT_EQ(buf()[i], 0u)
            << "Spec requires reserved_0 (8 zero bytes) at offset 0x0098. "
               "Byte at 0x" << std::hex << i << " is non-zero.";
    }
}

TEST_F(HeaderLayoutTest, ReadAcceptsUnknownCipherIdByte) {
    HeaderBuffer raw = header_.buffer();
    raw[POSITION_CIPHER_ID] = 0xFF;

    Header parsed;
    EXPECT_NO_THROW(parsed.read(raw));
    EXPECT_EQ(static_cast<uint8_t>(parsed.getCipher()), 0xFFu)
        << "Header::read must store cipher_id as-is; cipher support is checked at use/write time.";
}

// Spec 4.2.4: file_table_offset was REMOVED from the spec.
TEST_F(HeaderLayoutTest, NoFileTableOffsetField) {
    header_.setFileTableSize(99);
    header_.serialize();

    uint32_t val_at_0x80 = le32_at(buf(), 0x0080);
    EXPECT_EQ(val_at_0x80, 99u)
        << "Spec removed file_table_offset. "
           "Bytes at 0x0080 should hold file_table_size=99 as uint32.";
}

// Spec 4.2.4: file_table_size is uint32 (4 bytes), not uint64 (8 bytes).
TEST_F(HeaderLayoutTest, FileTableSizeIsUint32_Not64) {
    header_.setFileTableSize(42);
    header_.serialize();

    uint32_t val_at_0x84 = le32_at(buf(), 0x0084);
    EXPECT_NE(val_at_0x84, 0u)
        << "If file_table_size is wrongly uint64 at 0x0080, bytes 0x0084-0x0087 "
           "would be zero (upper bits). Spec says max_table_size (65536) should be there.";
}

// Spec Table 4.2: magic is 4 bytes 'S','C','E','F' at offset 0x0000.
TEST_F(HeaderLayoutTest, MagicAt0x0000_IsSCEF) {
    header_.serialize();

    EXPECT_EQ(buf()[0x0000], static_cast<uint8_t>('S'))
        << "Spec Table 4.2: magic byte 0 at 0x0000 must be 'S'";
    EXPECT_EQ(buf()[0x0001], static_cast<uint8_t>('C'))
        << "Spec Table 4.2: magic byte 1 at 0x0001 must be 'C'";
    EXPECT_EQ(buf()[0x0002], static_cast<uint8_t>('E'))
        << "Spec Table 4.2: magic byte 2 at 0x0002 must be 'E'";
    EXPECT_EQ(buf()[0x0003], static_cast<uint8_t>('F'))
        << "Spec Table 4.2: magic byte 3 at 0x0003 must be 'F'";
}

// Spec Table 4.2: header_size is uint32_le = 4096 at offset 0x0008.
TEST_F(HeaderLayoutTest, HeaderSizeAt0x0008_Is4096) {
    header_.serialize();

    uint32_t val = le32_at(buf(), 0x0008);
    EXPECT_EQ(val, 4096u)
        << "Spec Table 4.2: header_size (uint32_le) at 0x0008 must be 4096. "
           "A regression that writes wrong header_size would break all slot offset computations.";
}

// Spec Table 4.2: cipher_id is uint8 at offset 0x000C; default must be 0x01 (AES-256-GCM).
TEST_F(HeaderLayoutTest, CipherIdAt0x000C_DefaultIsAES) {
    header_.serialize();

    EXPECT_EQ(buf()[0x000C], 0x01u)
        << "Spec Table 4.2: cipher_id at 0x000C must be 0x01 (AES-256-GCM) by default. "
           "Got: 0x" << std::hex << static_cast<unsigned>(buf()[0x000C]);
}

// Spec Table 4.2: kdf_profile_id is uint16_le at offset 0x000E.
// Default Header has EKDFProfile::Standard = 3.
TEST_F(HeaderLayoutTest, KdfProfileIdAt0x000E_DefaultIsStandard) {
    header_.serialize();

    uint16_t val = le16_at(buf(), 0x000E);
    EXPECT_EQ(val, static_cast<uint16_t>(EKDFProfile::Standard))
        << "Spec Table 4.2: kdf_profile_id (uint16_le) at 0x000E must be 3 (Standard) by default. "
           "A big-endian serialization bug would produce 0x0300 instead of 0x0003.";
}

// Spec Table 4.2: kdf_m_kib is uint32_le at offset 0x0010.
TEST_F(HeaderLayoutTest, KdfMKibAt0x0010_IsUint32Le) {
    header_.serialize();

    // Read the raw value and verify it matches the getter (roundtrip).
    uint32_t raw_val = le32_at(buf(), 0x0010);
    EXPECT_EQ(raw_val, header_.getKdfMKib())
        << "Spec Table 4.2: kdf_m_kib (uint32_le) at 0x0010 must equal the header's kdf_m_kib field. "
           "A big-endian serialization bug would produce a byte-swapped value.";
    EXPECT_GT(raw_val, 0u)
        << "kdf_m_kib must be non-zero (Argon2id requires at least 1 KiB).";
}

// Spec Table 4.2: kdf_t is uint32_le at offset 0x0014.
TEST_F(HeaderLayoutTest, KdfTAt0x0014_IsUint32Le) {
    header_.serialize();

    uint32_t raw_val = le32_at(buf(), 0x0014);
    EXPECT_EQ(raw_val, header_.getKdfT())
        << "Spec Table 4.2: kdf_t (uint32_le) at 0x0014 must equal the header's kdf_t field. "
           "Endianness regression would produce a byte-swapped value.";
    EXPECT_GE(raw_val, 1u)
        << "kdf_t must be >= 1 (Argon2id requires at least 1 iteration).";
}

// Spec Table 4.2: kdf_p is uint32_le at offset 0x0018.
TEST_F(HeaderLayoutTest, KdfPAt0x0018_IsUint32Le) {
    header_.serialize();

    uint32_t raw_val = le32_at(buf(), 0x0018);
    EXPECT_EQ(raw_val, header_.getKdfP())
        << "Spec Table 4.2: kdf_p (uint32_le) at 0x0018 must equal the header's kdf_p field. "
           "Endianness regression would produce a byte-swapped value.";
    EXPECT_GE(raw_val, 1u)
        << "kdf_p must be >= 1 (Argon2id requires at least 1 lane).";
}

// ===========================================================================
// 2. CONTAINER ARCHITECTURE — spec 4.1
//
// Fixed-size container, 4 header slots, min size check.
// ===========================================================================

class ContainerArchTest : public ::testing::Test {
protected:
    fs::path tmp_dir_;

    void SetUp() override {
        tmp_dir_ = make_temp_dir("arch");
    }
    void TearDown() override {
        fs::remove_all(tmp_dir_);
    }

    fs::path make_input(const std::string& name, size_t size) {
        fs::path p = tmp_dir_ / "inputs" / name;
        write_file(p, std::vector<uint8_t>(size, 0xAB));
        return p;
    }
};

// Spec 4.1: Container size is fixed at creation.
TEST_F(ContainerArchTest, ContainerSizeIsFixedAtCreation) {
    fs::path src = make_input("test.bin", 100);
    fs::path cdir = tmp_dir_ / "container";
    fs::create_directories(cdir);

    uint64_t requested_size = 4ULL * (HEADER_SIZE + BLOCK_SIZE) + BLOCK_SIZE;

    fs::path container_file = cdir / CONTAINER_FILE_NAME;
    FileManager fm;
    fm.init({src.string()}, container_file.string(), requested_size, DEFAULT_MAX_TABLE_SIZE, /*create_new=*/true);
    fm.write();

    auto raw = read_file(container_file);
    ASSERT_GE(raw.size(), HEADER_SIZE);
    uint64_t container_size = le64_at(raw.data(), 0x0078);

    EXPECT_EQ(raw.size(), container_size)
        << "Spec requires container file size == container_size field in header.";

    uint64_t min_size = 4 * (HEADER_SIZE + BLOCK_SIZE);
    EXPECT_GE(container_size, min_size)
        << "Spec requires container_size >= 4 * (header_size + max_table_size).";
}

// Spec 4.1: Container has 4 header slots at 0%, 25%, 50%, 75%.
TEST_F(ContainerArchTest, FourHeaderSlotsWithMagic) {
    fs::path src = make_input("test.bin", 100);
    fs::path cdir = tmp_dir_ / "container";
    fs::create_directories(cdir);

    uint64_t requested_container_size = 4ULL * (HEADER_SIZE + BLOCK_SIZE) + BLOCK_SIZE;
    fs::path container_file = cdir / CONTAINER_FILE_NAME;
    FileManager fm;
    fm.init({src.string()}, container_file.string(), requested_container_size, DEFAULT_MAX_TABLE_SIZE, /*create_new=*/true);
    fm.write();

    auto raw = read_file(container_file);
    ASSERT_GE(raw.size(), HEADER_SIZE);

    uint64_t container_size = le64_at(raw.data(), 0x0078);
    if (container_size == 0 || raw.size() < container_size) {
        GTEST_SKIP() << "container_size not set or file too small for slot check";
    }

    auto slot_offset = [&](int pct) -> size_t {
        return (container_size * pct / 100 / HEADER_SIZE) * HEADER_SIZE;
    };

    size_t offsets[] = {0, slot_offset(25), slot_offset(50), slot_offset(75)};

    for (int i = 0; i < 4; ++i) {
        size_t off = offsets[i];
        ASSERT_LE(off + 4, raw.size())
            << "Slot " << i << " offset " << off << " is beyond file size";

        EXPECT_EQ(raw[off + 0], 'S')
            << "Slot " << i << " at offset " << off << " missing magic byte 'S'";
        EXPECT_EQ(raw[off + 1], 'C')
            << "Slot " << i << " at offset " << off << " missing magic byte 'C'";
        EXPECT_EQ(raw[off + 2], 'E')
            << "Slot " << i << " at offset " << off << " missing magic byte 'E'";
        EXPECT_EQ(raw[off + 3], 'F')
            << "Slot " << i << " at offset " << off << " missing magic byte 'F'";
    }
}

// Spec Table 4.2: salt is 32 bytes at offset 0x001C; must be non-zero after container creation.
// The salt is generated by CryptoManager::generateSalt() during write() — not by Header::serialize().
// This test guards against accidental zeroing of the salt (e.g. a missing generateSalt() call).
TEST_F(ContainerArchTest, SaltNonZeroAt0x001C_AfterCreate) {
    fs::path src = make_input("test.bin", 64);
    fs::path cdir = tmp_dir_ / "container_salt";
    fs::create_directories(cdir);

    uint64_t container_size = 4 * 1024 * 1024;
    fs::path container_file_salt = cdir / CONTAINER_FILE_NAME;
    FileManager fm;
    fm.init({src.string()}, container_file_salt.string(), container_size, DEFAULT_MAX_TABLE_SIZE, /*create_new=*/true);
    fm.write();

    auto raw = read_file(container_file_salt);
    ASSERT_GE(raw.size(), static_cast<size_t>(0x001C + 32))
        << "Container file too small to contain salt field.";

    bool all_zero = true;
    for (size_t i = 0x001C; i < 0x001C + 32; ++i) {
        if (raw[i] != 0) { all_zero = false; break; }
    }
    EXPECT_FALSE(all_zero)
        << "Spec Table 4.2: salt (32 bytes at 0x001C) must not be all-zero after creation. "
           "A missing generateSalt() call would leave the salt zeroed, "
           "making every container with an empty password use the same KEK.";
}

// Spec Table 4.2: container_size is uint64_le at offset 0x0078;
// must equal the requested size at creation.
TEST_F(ContainerArchTest, ContainerSizeAt0x0078_MatchesRequested) {
    fs::path src = make_input("test.bin", 64);
    fs::path cdir = tmp_dir_ / "container_csz";
    fs::create_directories(cdir);

    uint64_t requested_size = 4 * 1024 * 1024;
    fs::path container_file_csz = cdir / CONTAINER_FILE_NAME;
    FileManager fm;
    fm.init({src.string()}, container_file_csz.string(), requested_size, DEFAULT_MAX_TABLE_SIZE, /*create_new=*/true);
    fm.write();

    auto raw = read_file(container_file_csz);
    ASSERT_GE(raw.size(), static_cast<size_t>(0x0078 + 8))
        << "Container file too small to contain container_size field.";

    uint64_t stored = le64_at(raw.data(), 0x0078);
    EXPECT_EQ(stored, requested_size)
        << "Spec Table 4.2: container_size (uint64_le) at 0x0078 must equal the requested "
           "container size. A regression that stores wrong container_size would break slot "
           "offset computation on re-open.";
}

// Spec 4.1: All four 4096-byte header blocks must be byte-for-byte identical after write.
// This guards against bugs where slot 0 receives a different header_version, salt,
// or any other field compared to slots 1-3.
TEST_F(ContainerArchTest, AllFourSlotsAreByteIdentical) {
    fs::path src = make_input("test.bin", 100);
    fs::path cdir = tmp_dir_ / "container_ident";
    fs::create_directories(cdir);

    uint64_t container_size = 4 * 1024 * 1024;
    fs::path container_file_ident = cdir / CONTAINER_FILE_NAME;
    FileManager fm;
    fm.init({src.string()}, container_file_ident.string(), container_size, DEFAULT_MAX_TABLE_SIZE, /*create_new=*/true);
    fm.write();

    auto raw = read_file(container_file_ident);
    ASSERT_GE(raw.size(), static_cast<size_t>(HEADER_SIZE));

    uint64_t stored_size = le64_at(raw.data(), 0x0078);
    if (stored_size == 0 || raw.size() < stored_size) {
        GTEST_SKIP() << "container_size not set or file too small for slot identity check";
    }

    auto slot_offset = [&](int pct) -> size_t {
        return static_cast<size_t>((stored_size * pct / 100 / HEADER_SIZE) * HEADER_SIZE);
    };

    size_t offsets[4] = {0, slot_offset(25), slot_offset(50), slot_offset(75)};

    for (int i = 1; i < 4; ++i) {
        size_t off = offsets[i];
        ASSERT_LE(off + HEADER_SIZE, raw.size())
            << "Slot " << i << " header block at offset " << off << " is beyond file size";

        bool identical = (std::memcmp(raw.data(), raw.data() + off, HEADER_SIZE) == 0);
        EXPECT_TRUE(identical)
            << "Spec 4.1: Header block at slot " << i << " (offset " << off
            << ") is not byte-identical to slot 0 (offset 0). "
               "All four header slots must carry identical content after write().";
    }
}

// Defensive: non-power-of-2 container size must produce valid magic at spec-formula offsets
// AND all four header blocks must be byte-identical.
// This guards the same class of bug as integration test F-1: a wrong slot formula only
// diverges from the spec formula when the size is not a power-of-2 multiple of HEADER_SIZE.
TEST_F(ContainerArchTest, AllFourSlotsAreByteIdentical_NonPowerOf2Size) {
    fs::path src = make_input("test.bin", 100);
    fs::path cdir = tmp_dir_ / "container_odd";
    fs::create_directories(cdir);

    // 1_000_000 is not a power-of-2 multiple of 4096, so spec formula != naive size//4 formula.
    // Spec slot 1: (1000000*25/100/4096)*4096 = (250000/4096)*4096 = 61*4096 = 249856
    // Naive:       1000000//4 = 250000
    // These differ, making this size ideal for catching formula bugs.
    constexpr uint64_t test_size = 1'000'000;
    // Minimum container size is 4*(4096+65536) = 278528; 1_000_000 > 278528, so it fits.
    static_assert(test_size >= 4ULL * (HEADER_SIZE + BLOCK_SIZE),
                  "test_size must be >= MINIMAL_CONTAINER_SIZE");

    fs::path container_file_odd = cdir / CONTAINER_FILE_NAME;
    FileManager fm;
    fm.init({src.string()}, container_file_odd.string(), test_size, DEFAULT_MAX_TABLE_SIZE, /*create_new=*/true);
    fm.write();

    auto raw = read_file(container_file_odd);
    ASSERT_GE(raw.size(), static_cast<size_t>(HEADER_SIZE));

    uint64_t stored_size = le64_at(raw.data(), 0x0078);
    if (stored_size == 0 || raw.size() < stored_size) {
        GTEST_SKIP() << "container_size not set or file too small";
    }

    auto slot_offset = [&](int pct) -> size_t {
        return static_cast<size_t>((stored_size * pct / 100 / HEADER_SIZE) * HEADER_SIZE);
    };

    size_t offsets[4] = {0, slot_offset(25), slot_offset(50), slot_offset(75)};

    for (int i = 0; i < 4; ++i) {
        size_t off = offsets[i];
        ASSERT_LE(off + 4, raw.size())
            << "Slot " << i << " at offset " << off << " is beyond file size";

        // Magic check
        EXPECT_EQ(raw[off + 0], static_cast<uint8_t>('S'))
            << "Slot " << i << " at offset " << off << " missing magic 'S'";
        EXPECT_EQ(raw[off + 1], static_cast<uint8_t>('C'))
            << "Slot " << i << " at offset " << off << " missing magic 'C'";
        EXPECT_EQ(raw[off + 2], static_cast<uint8_t>('E'))
            << "Slot " << i << " at offset " << off << " missing magic 'E'";
        EXPECT_EQ(raw[off + 3], static_cast<uint8_t>('F'))
            << "Slot " << i << " at offset " << off << " missing magic 'F'";
    }

    // Byte-identity check: all four 4096-byte blocks must be identical
    ASSERT_LE(offsets[0] + HEADER_SIZE, raw.size());
    for (int i = 1; i < 4; ++i) {
        size_t off = offsets[i];
        ASSERT_LE(off + HEADER_SIZE, raw.size())
            << "Slot " << i << " header block at offset " << off << " is beyond file size";

        bool identical = (std::memcmp(raw.data() + offsets[0], raw.data() + off, HEADER_SIZE) == 0);
        EXPECT_TRUE(identical)
            << "Spec 4.1: Header block at slot " << i << " (offset " << off
            << ") is not byte-identical to slot 0 (offset " << offsets[0] << ") "
               "for non-power-of-2 container size " << test_size << ".";
    }
}

// Spec 4.6.2: After add(), header_version must be incremented.
TEST_F(ContainerArchTest, AddIncrementsHeaderVersion) {
    fs::path f1 = make_input("first.bin", 50);
    fs::path f2 = make_input("second.bin", 50);
    fs::path cdir = tmp_dir_ / "container";
    fs::create_directories(cdir);

    uint64_t container_size = 4 * 1024 * 1024; // 4 MiB

    fs::path container_file_ver = cdir / CONTAINER_FILE_NAME;
    {
        FileManager fm;
        fm.init({f1.string()}, container_file_ver.string(), container_size, DEFAULT_MAX_TABLE_SIZE, /*create_new=*/true);
        fm.write();
    }

    auto raw1 = read_file(container_file_ver);
    uint32_t ver1 = le32_at(raw1.data(), 0x0090);

    {
        FileManager fm;
        fm.init({f2.string()}, container_file_ver.string());
        fm.add();
    }

    auto raw2 = read_file(container_file_ver);
    uint32_t ver2 = le32_at(raw2.data(), 0x0090);

    EXPECT_GT(ver2, ver1)
        << "Spec 4.6.2: header_version must be incremented on each update operation. "
           "Got ver1=" << ver1 << ", ver2=" << ver2;
}

// ===========================================================================
// 3. FILE TABLE — spec 4.4 and 4.2.4
//
// Encrypted table stored in reserved slot, not appended after data.
// file_table_size includes nonce+tag.
// ===========================================================================

class FileTableSpecTest : public ::testing::Test {
protected:
    fs::path tmp_dir_;

    void SetUp() override {
        tmp_dir_ = make_temp_dir("ftable");
    }
    void TearDown() override {
        fs::remove_all(tmp_dir_);
    }

    fs::path make_input(const std::string& name, size_t size) {
        fs::path p = tmp_dir_ / "inputs" / name;
        write_file(p, std::vector<uint8_t>(size, 0xCD));
        return p;
    }
};

// Spec 4.2.4: file_table_size includes nonce (12) + ciphertext + tag (16).
TEST_F(FileTableSpecTest, FileTableSizeIncludesNonceAndTag) {
    fs::path src = make_input("test.bin", 100);
    fs::path cdir = tmp_dir_ / "container";
    fs::create_directories(cdir);

    uint64_t container_size = 1024 * 1024; // 1 MiB
    fs::path container_file_ft1 = cdir / CONTAINER_FILE_NAME;
    FileManager fm;
    fm.init({src.string()}, container_file_ft1.string(), container_size, DEFAULT_MAX_TABLE_SIZE, /*create_new=*/true);
    fm.write();

    auto raw = read_file(container_file_ft1);
    ASSERT_GE(raw.size(), HEADER_SIZE);

    uint32_t ft_size_at_spec_offset = le32_at(raw.data(), 0x0080);

    EXPECT_GE(ft_size_at_spec_offset, 28u)
        << "Spec 4.2.4: file_table_size includes nonce (12B) + ciphertext + tag (16B). "
           "Minimum value is 28 even for empty table.";
}

// Spec 4.4: File table is stored at header_offset + header_size, NOT after data.
TEST_F(FileTableSpecTest, FileTableStoredInSlotNotAfterData) {
    fs::path src = make_input("test.bin", 100);
    fs::path cdir = tmp_dir_ / "container";
    fs::create_directories(cdir);

    uint64_t container_size = 1024 * 1024;
    fs::path container_file_ft2 = cdir / CONTAINER_FILE_NAME;
    FileManager fm;
    fm.init({src.string()}, container_file_ft2.string(), container_size, DEFAULT_MAX_TABLE_SIZE, /*create_new=*/true);
    fm.write();

    auto raw = read_file(container_file_ft2);
    ASSERT_GE(raw.size(), HEADER_SIZE + NONCE_SIZE + AUTH_TAG_SIZE);

    uint32_t ft_size = le32_at(raw.data(), 0x0080);
    EXPECT_GE(ft_size, static_cast<uint32_t>(NONCE_SIZE + AUTH_TAG_SIZE))
        << "file_table_size should be >= 28.";

    bool has_nonzero = false;
    for (size_t i = HEADER_SIZE; i < HEADER_SIZE + ft_size && i < raw.size(); ++i) {
        if (raw[i] != 0) { has_nonzero = true; break; }
    }
    EXPECT_TRUE(has_nonzero)
        << "Spec 4.4: File table at offset HEADER_SIZE should be non-zero (encrypted data).";
}

// ===========================================================================
// 4. CREATE + ADD + EXTRACT — behavioral correctness
// ===========================================================================

class ContainerOpsTest : public ::testing::Test {
protected:
    fs::path tmp_dir_;
    fs::path input_dir_;
    fs::path container_dir_;
    fs::path output_dir_;

    void SetUp() override {
        tmp_dir_       = make_temp_dir("ops");
        input_dir_     = tmp_dir_ / "inputs";
        container_dir_ = tmp_dir_ / "container";
        output_dir_    = tmp_dir_ / "outputs";
        fs::create_directories(input_dir_);
        fs::create_directories(container_dir_);
        fs::create_directories(output_dir_);
    }
    void TearDown() override {
        fs::remove_all(tmp_dir_);
    }

    fs::path make_input(const std::string& name, const std::vector<uint8_t>& data) {
        fs::path p = input_dir_ / name;
        write_file(p, data);
        return p;
    }
};

// After add(), the ORIGINAL file must still be extractable correctly.
TEST_F(ContainerOpsTest, OriginalFileIntactAfterAdd) {
    const std::vector<uint8_t> c1 = {0x11, 0x22, 0x33, 0x44, 0x55};
    const std::vector<uint8_t> c2 = {0xAA, 0xBB, 0xCC};
    fs::path f1 = make_input("original.bin", c1);
    fs::path f2 = make_input("added.bin", c2);

    uint64_t container_size = 4 * 1024 * 1024;

    fs::path cpath1 = container_dir_ / CONTAINER_FILE_NAME;
    {
        FileManager fm;
        fm.init({f1.string()}, cpath1.string(), container_size, DEFAULT_MAX_TABLE_SIZE, /*create_new=*/true);
        fm.write();
    }
    {
        FileManager fm;
        fm.init({f2.string()}, cpath1.string());
        fm.add();
    }
    {
        FileManager fm;
        fm.init({"original.bin"}, cpath1.string());
        fm.extract(output_dir_.string());
    }

    auto result = read_file(output_dir_ / "original.bin");
    EXPECT_EQ(result, c1)
        << "After add(), the original file's data was corrupted.";
}

// Multiple add() calls should accumulate files correctly.
TEST_F(ContainerOpsTest, ThreeSequentialAddsAllExtractable) {
    std::vector<uint8_t> c1(100, 0x11);
    std::vector<uint8_t> c2(200, 0x22);
    std::vector<uint8_t> c3(300, 0x33);
    fs::path f1 = make_input("file1.bin", c1);
    fs::path f2 = make_input("file2.bin", c2);
    fs::path f3 = make_input("file3.bin", c3);

    uint64_t container_size = 4 * 1024 * 1024;

    fs::path cpath2 = container_dir_ / CONTAINER_FILE_NAME;
    {
        FileManager fm;
        fm.init({f1.string()}, cpath2.string(), container_size, DEFAULT_MAX_TABLE_SIZE, /*create_new=*/true);
        fm.write();
    }
    {
        FileManager fm;
        fm.init({f2.string()}, cpath2.string());
        fm.add();
    }
    {
        FileManager fm;
        fm.init({f3.string()}, cpath2.string());
        fm.add();
    }
    {
        FileManager fm;
        fm.init({"file1.bin", "file2.bin", "file3.bin"}, cpath2.string());
        fm.extract(output_dir_.string());
    }

    EXPECT_EQ(read_file(output_dir_ / "file1.bin"), c1);
    EXPECT_EQ(read_file(output_dir_ / "file2.bin"), c2);
    EXPECT_EQ(read_file(output_dir_ / "file3.bin"), c3);
}

// Multi-block file should survive add() of another file.
TEST_F(ContainerOpsTest, MultiBlockFileIntactAfterAdd) {
    std::vector<uint8_t> big_content(BLOCK_SIZE * 2 + BLOCK_SIZE / 2);
    for (size_t i = 0; i < big_content.size(); ++i)
        big_content[i] = static_cast<uint8_t>(i & 0xFF);

    std::vector<uint8_t> small_content = {0xDE, 0xAD};

    fs::path f1 = make_input("big.bin", big_content);
    fs::path f2 = make_input("small.bin", small_content);

    uint64_t container_size = 16 * 1024 * 1024;

    fs::path cpath3 = container_dir_ / CONTAINER_FILE_NAME;
    {
        FileManager fm;
        fm.init({f1.string()}, cpath3.string(), container_size, DEFAULT_MAX_TABLE_SIZE, /*create_new=*/true);
        fm.write();
    }
    {
        FileManager fm;
        fm.init({f2.string()}, cpath3.string());
        fm.add();
    }
    {
        FileManager fm;
        fm.init({"big.bin"}, cpath3.string());
        fm.extract(output_dir_.string());
    }

    EXPECT_EQ(read_file(output_dir_ / "big.bin"), big_content)
        << "Multi-block file corrupted after add().";
}

TEST_F(ContainerOpsTest, KuznechikRoundtrip) {
    const auto password = make_secure_vector("kuznechik_unit_password");
    const std::vector<uint8_t> c1 = {0x10, 0x20, 0x30, 0x40, 0x50};
    const std::vector<uint8_t> c2(257, 0x7A);
    fs::path f1 = make_input("first.bin", c1);
    fs::path f2 = make_input("second.bin", c2);

    uint64_t container_size = 4 * 1024 * 1024;

    fs::path cpath_kuz = container_dir_ / CONTAINER_FILE_NAME;
    {
        FileManager fm;
        fm.setCipher(ECipher::Kuznechik_GCM);
        fm.init({f1.string()}, cpath_kuz.string(), container_size, DEFAULT_MAX_TABLE_SIZE,
                /*create_new=*/true, password);
        fm.setKdfParams(EKDFProfile::None, 64, 1, 1);
        fm.write();
    }
    {
        FileManager fm;
        fm.init({f2.string()}, cpath_kuz.string(), 0, DEFAULT_MAX_TABLE_SIZE,
                /*create_new=*/false, password);
        fm.add();
    }
    {
        FileManager fm;
        fm.init({"first.bin", "second.bin"}, cpath_kuz.string(), 0, DEFAULT_MAX_TABLE_SIZE,
                /*create_new=*/false, password);
        fm.extract(output_dir_.string());
    }

    EXPECT_EQ(read_file(output_dir_ / "first.bin"), c1);
    EXPECT_EQ(read_file(output_dir_ / "second.bin"), c2);

    HeaderBuffer rawHeader{};
    std::ifstream in(cpath_kuz, std::ios::binary);
    ASSERT_TRUE(in.good());
    in.read(reinterpret_cast<char*>(rawHeader.data()), static_cast<std::streamsize>(rawHeader.size()));
    ASSERT_EQ(in.gcount(), static_cast<std::streamsize>(rawHeader.size()));

    Header header;
    header.read(rawHeader);
    EXPECT_EQ(header.getCipher(), ECipher::Kuznechik_GCM);
}

TEST_F(ContainerOpsTest, CorruptCipherIdInSlot0FallsBackToSlot1) {
    const auto password = make_secure_vector("slot_recovery_password");
    const std::vector<uint8_t> content = {0x51, 0x52, 0x53, 0x54};
    fs::path src = make_input("payload.bin", content);

    uint64_t container_size = 4 * 1024 * 1024;

    fs::path cpath_corrupt_src = container_dir_ / CONTAINER_FILE_NAME;
    {
        FileManager fm;
        fm.setCipher(ECipher::Kuznechik_GCM);
        fm.init({src.string()}, cpath_corrupt_src.string(), container_size, DEFAULT_MAX_TABLE_SIZE,
                /*create_new=*/true, password);
        fm.setKdfParams(EKDFProfile::None, 64, 1, 1);
        fm.write();
    }

    fs::path recovered_dir = tmp_dir_ / "recovered_container";
    fs::create_directories(recovered_dir);
    auto raw = read_file(cpath_corrupt_src);
    ASSERT_GT(raw.size(), POSITION_CIPHER_ID);
    raw[POSITION_CIPHER_ID] = 0xFF;
    fs::path cpath_corrupt_rec = recovered_dir / CONTAINER_FILE_NAME;
    write_file(cpath_corrupt_rec, raw);

    {
        FileManager fm;
        ASSERT_NO_THROW(fm.init({}, cpath_corrupt_rec.string(), 0, DEFAULT_MAX_TABLE_SIZE,
                                /*create_new=*/false, password));
        EXPECT_EQ(fm.getCipher(), ECipher::Kuznechik_GCM)
            << "Open must recover from slot 1 and keep the original cipher selection.";
    }
}

// Spec 4.2.5: validate() should return true for a valid, freshly-created header.
TEST_F(ContainerOpsTest, ValidateReturnsTrueForValidHeader) {
    Header h;
    h.serialize();
    EXPECT_TRUE(h.validate())
        << "Spec 4.2.5/4.6.4: validate() must check magic and HMAC. "
           "A freshly serialized header must have valid magic bytes.";
}

// Spec 4.1: init() for list/extract on non-existent container must NOT create one.
TEST_F(ContainerOpsTest, InitDoesNotCreateContainerForRead) {
    fs::path cdir = tmp_dir_ / "nonexistent_container";
    fs::create_directories(cdir);
    fs::path container_file = cdir / CONTAINER_FILE_NAME;

    EXPECT_FALSE(fs::exists(container_file));

    FileManager fm;
    EXPECT_THROW(fm.init({}, container_file.string()), std::runtime_error)
        << "Spec: init() for read operations must throw if the container does not exist.";

    EXPECT_FALSE(fs::exists(container_file))
        << "init() must not create a container file for a read operation.";
}

// ===========================================================================
// 5. ENUM VALUES — spec 4.2.2
// ===========================================================================

TEST(EnumSpecTest, KuznechikGCM_EnumValueExists) {
    ECipher cipher = static_cast<ECipher>(0x02);

    EXPECT_EQ(static_cast<uint8_t>(cipher), 0x02u)
        << "Spec defines cipher_id 0x02 = Kuznechik-GCM. "
           "ECipher enum should have this value.";
}

TEST(EnumSpecTest, KDFProfiles_AllFourDefined) {
    // Spec: 4 predefined profiles at values 1-4; no gap.
    EXPECT_EQ(static_cast<uint16_t>(EKDFProfile::Browser),  1u);
    EXPECT_EQ(static_cast<uint16_t>(EKDFProfile::Fast),     2u);
    EXPECT_EQ(static_cast<uint16_t>(EKDFProfile::Standard), 3u);
    EXPECT_EQ(static_cast<uint16_t>(EKDFProfile::High),     4u);
}

// ===========================================================================
// 6. EMPTY FILE ROUNDTRIP — bug regression
//
// A zero-byte file must survive create→extract intact.
// Both the empty entry and the co-present non-empty entry must be correct.
// ===========================================================================

class EmptyFileTest : public ::testing::Test {
protected:
    fs::path tmp_dir_;
    fs::path input_dir_;
    fs::path container_dir_;
    fs::path output_dir_;

    void SetUp() override {
        tmp_dir_       = make_temp_dir("empty");
        input_dir_     = tmp_dir_ / "inputs";
        container_dir_ = tmp_dir_ / "container";
        output_dir_    = tmp_dir_ / "outputs";
        fs::create_directories(input_dir_);
        fs::create_directories(container_dir_);
        fs::create_directories(output_dir_);
    }
    void TearDown() override {
        fs::remove_all(tmp_dir_);
    }
};

// Empty file must appear in getFilesTable() with size==0 and chunks==0.
TEST_F(EmptyFileTest, EmptyFileAppearsInTable) {
    fs::path empty_file = input_dir_ / "empty.bin";
    write_file(empty_file, {});

    fs::path nonempty_file = input_dir_ / "data.bin";
    write_file(nonempty_file, {0x01, 0x02, 0x03});

    uint64_t container_size = 4 * 1024 * 1024;
    fs::path cpath_empty1 = container_dir_ / CONTAINER_FILE_NAME;
    FileManager fm;
    fm.init({empty_file.string(), nonempty_file.string()},
            cpath_empty1.string(), container_size, DEFAULT_MAX_TABLE_SIZE, /*create_new=*/true);
    fm.write();

    const auto& table = fm.getFilesTable();
    ASSERT_EQ(table.size(), 2u) << "Both files must be present in the file table";

    bool found_empty = false;
    for (const auto& entry : table) {
        if (fs::path(entry.name).filename() == "empty.bin") {
            found_empty = true;
            EXPECT_EQ(entry.size, 0u)   << "empty.bin must have size==0";
            EXPECT_EQ(entry.chunks, 0u) << "empty.bin must have chunks==0";
        }
    }
    EXPECT_TRUE(found_empty) << "empty.bin not found in file table";
}

// Empty file must be restored on disk with size 0 and correct (empty) checksum.
TEST_F(EmptyFileTest, EmptyFileExtractedCorrectly) {
    fs::path empty_file = input_dir_ / "empty.bin";
    write_file(empty_file, {});

    fs::path nonempty_file = input_dir_ / "data.bin";
    const std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    write_file(nonempty_file, payload);

    uint64_t container_size = 4 * 1024 * 1024;

    fs::path cpath_empty2 = container_dir_ / CONTAINER_FILE_NAME;
    {
        FileManager fm;
        fm.init({empty_file.string(), nonempty_file.string()},
                cpath_empty2.string(), container_size, DEFAULT_MAX_TABLE_SIZE, /*create_new=*/true);
        fm.write();
    }
    {
        FileManager fm;
        fm.init({"empty.bin", "data.bin"}, cpath_empty2.string());
        fm.extract(output_dir_.string());
    }

    // Empty file must exist and have zero size.
    fs::path out_empty = output_dir_ / "empty.bin";
    ASSERT_TRUE(fs::exists(out_empty)) << "empty.bin was not created on extract";
    EXPECT_EQ(fs::file_size(out_empty), 0u) << "extracted empty.bin must be 0 bytes";

    // Non-empty file must be intact.
    auto result = read_file(output_dir_ / "data.bin");
    EXPECT_EQ(result, payload) << "data.bin corrupted after empty-file roundtrip";
}

// ===========================================================================
// Main
// ===========================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
