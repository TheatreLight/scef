#ifndef HEADER_H
#define HEADER_H

#include "enums/ECiphers.h"
#include "enums/EKDF.h"
#include "enums/EKDFProfile.h"

#include <array>
#include <vector>
#include <string>
#include <cstdint>

constexpr size_t HEADER_SIZE = 4096;
constexpr std::array<char, 4> HEADER_MAGIC = {'S', 'C', 'E', 'F'};
constexpr uint16_t HEADER_VERSION_MAJOR = 1;
constexpr uint16_t HEADER_VERSION_MINOR = 0;
constexpr uint32_t BLOCK_SIZE = 65536;
constexpr uint16_t NONCE_SIZE = 12;
constexpr uint16_t AUTH_TAG_SIZE = 16;
constexpr uint32_t ENCRYPTED_BLOCK_SIZE = BLOCK_SIZE + NONCE_SIZE + AUTH_TAG_SIZE;

constexpr size_t POSITION_MAGIC = 0x0000;
constexpr size_t POSITION_VERSION_MAJOR = 0x0004;
constexpr size_t POSITION_VERSION_MINOR = 0x0006;
constexpr size_t POSITION_HEADER_SIZE = 0x0008;
constexpr size_t POSITION_CIPHER_ID = 0x000C;
constexpr size_t POSITION_KDF_ID = 0x000D;
constexpr size_t POSITION_KDF_PROFILE_ID = 0x000E;
constexpr size_t POSITION_KDF_M_KIB = 0x0010;
constexpr size_t POSITION_KDF_T = 0x0014;
constexpr size_t POSITION_KDF_P = 0x0018;
constexpr size_t POSITION_SALT = 0x001C;
constexpr size_t POSITION_DEK_NONCE = 0x003C;
constexpr size_t POSITION_ENCRYPTED_DEK = 0x0048;
constexpr size_t POSITION_DEK_AUTH_TAG = 0x0068;
constexpr size_t POSITION_CONTAINER_SIZE = 0x0078;
constexpr size_t POSITION_FILE_TABLE_OFFSET = 0x0080;
constexpr size_t POSITION_FILE_TABLE_SIZE = 0x0088;
constexpr size_t POSITION_FILE_COUNT = 0x0090;
constexpr size_t POSITION_BLOCK_SIZE = 0x0094;
constexpr size_t POSITION_HEADER_VERSION = 0x0098;
constexpr size_t POSITION_FLAGS = 0x009C;
constexpr size_t POSITION_HEADER_HMAC = 0x00A0;
constexpr size_t POSITION_RESERVED = 0x00C0;
constexpr size_t POSITION_JSON_METADATA = 0x0200;
constexpr size_t POSITION_PADDING = 0x0400;

using HeaderBuffer = std::array<uint8_t, HEADER_SIZE>;

/*
| 0x0000 | 4 | magic | uint32_le | Magic number 0x46454353 ("SCEF" to ASCII) |
| 0x0004 | 2 | version_major | uint16_le | Major version format = 1 |
| 0x0006 | 2 | version_minor | uint16_le | Minor version format = 0 |
| 0x0008 | 4 | header_size | uint32_le | Header size in bytes = 4096 |
| 0x000C | 1 | cipher_id | uint8 | Cipher identifier: 0x01 = AES-256-GCM, 0x02 = Kuznechik-GCM |
| 0x000D | 1 | kdf_id | uint8 | KDF identifier: 0x01 = Argon2id |
| 0x000E | 2 | kdf_profile_id | uint16_le | KDF profile: 0 = user-defined, 1--5 = predefined |
| 0x0010 | 4 | kdf_m_kib | uint32_le | Argon2id memory volume in KiB |
| 0x0014 | 4 | kdf_t | uint32_le | Number of iterations (passes) Argon2id |
| 0x0018 | 4 | kdf_p | uint32_le | Degree of parallelism Argon2id |
| 0x001C | 32 | salt | uint8[32] | Random 256-bit salt |
| 0x003C | 12 | dek_nonce | uint8[12] | 96-bit nonce for DEK encryption |
| 0x0048 | 32 | encrypted_dek | uint8[32] | Encrypted DEK (AES-256-GCM under KEK) |
| 0x0068 | 16 | dek_auth_tag | uint8[16] | 128-bit GCM authentication tag for DEK |
| 0x0078 | 8 | container_size | uint64_le | Full container size in bytes |
| 0x0080 | 8 | file_table_offset | uint64_le | Absolute offset of the file table |
| 0x0088 | 8 | file_table_size | uint64_le | Size of the encrypted file table |
| 0x0090 | 4 | file_count | uint32_le | Number of files in the container |
| 0x0094 | 4 | block_size | uint32_le | Data block size in bytes (default 65536) |
| 0x0098 | 4 | header_version | uint32_le | Monotonic counter of the header version |
| 0x009C | 4 | flags | uint32_le | Bitfield of flags |
| 0x00A0 | 32 | header_hmac | uint8[32] | HMAC-SHA256 bytes [0x0000..0x009F] |
| 0x00C0 | 320 | reserved | uint8[320] | Reserved (zeros) |
| 0x0200 | 512 | json_metadata | uint8[512] | JSON metadata in UTF-8 encoding |
| 0x0400 | 3072 | padding | uint8[3072] | Padding to 4096 bytes (zeros) |
*/

class Header {
public:
    Header();
    void read(const HeaderBuffer& buf);
    void write();
    bool validate();

    const HeaderBuffer& buffer();
    std::string to_string() const;

    void setFileTableOffset(uint64_t offset);
    void setFileTableSize(uint64_t size);
    void setContainerSize(uint64_t size);
    void increaseFileCount();

    uint64_t getFileTableOffset() const { return file_table_offset_; }
    uint64_t getFileTableSize() const { return file_table_size_; }
    uint32_t getHeaderSize() const { return header_size_; }
    uint32_t getChunkSize() const { return block_size_; }

private:
    void createBuffer();
    void write_le16(uint8_t* buf, uint16_t value);
    void write_le32(uint8_t* buf, uint32_t value);
    void write_le64(uint8_t* buf, uint64_t value);
    void read_le16(const uint8_t* buf, uint16_t& value);
    void read_le32(const uint8_t* buf, uint32_t& value);
    void read_le64(const uint8_t* buf, uint64_t& value);


    HeaderBuffer buffer_;

    std::array<char, 4> header_magic_ = HEADER_MAGIC;
    uint16_t version_major_ = HEADER_VERSION_MAJOR;
    uint16_t version_minor_ = HEADER_VERSION_MINOR;
    uint32_t header_size_ = HEADER_SIZE;
    ECipher cipher_ = ECipher::None;
    EKDF kdf_ = EKDF::None;
    EKDFProfile kdf_profile_ = EKDFProfile::None;
    uint32_t kdf_m_kib_ = 0;
    uint32_t kdf_t_ = 0;
    uint32_t kdf_p_ = 0;
    std::array<uint8_t, 32> salt_ = {};
    std::array<uint8_t, NONCE_SIZE> dek_nonce_ = {};
    std::array<uint8_t, 32> encrypted_dek_ {};
    std::array<uint8_t, AUTH_TAG_SIZE> dek_auth_tag_ = {};
    uint64_t container_size_ = 0;
    uint64_t file_table_offset_ = 0;
    uint64_t file_table_size_ = 0;
    uint32_t file_count_ = 0;
    uint32_t block_size_ = BLOCK_SIZE;
    uint32_t header_version_ = 0;
    uint32_t flags_ = 0;
    std::array<uint8_t, 32> header_hmac_ = {};
    std::array<uint8_t, 320> reserved_ = {0};
    std::array<uint8_t, 512> json_metadata_ = {};
};

#endif // HEADER_H
