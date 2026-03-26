#include "Header.h"
#include <cstdint>
#include <sstream>
#include <iomanip>

Header::Header() {
    createBuffer();
}

void Header::read(const HeaderBuffer& buf) {
    // | 0x0000 | 4 | magic | uint32_le | Magic number 0x46454353 ("SCEF" to ASCII) |
    std::copy(buf.begin(), buf.begin()+ POSITION_VERSION_MAJOR, header_magic_.begin());
    // | 0x0004 | 2 | version_major | uint16_le | Major version format = 1 |
    read_le16(buf.data() + POSITION_VERSION_MAJOR, version_major_);
    // | 0x0006 | 2 | version_minor | uint16_le | Minor version format = 0 |
    read_le16(buf.data() + POSITION_VERSION_MINOR, version_minor_);
    // | 0x0008 | 4 | header_size | uint32_le | Header size in bytes = 4096 |
    read_le32(buf.data() + POSITION_HEADER_SIZE, header_size_);
    // | 0x000C | 1 | cipher_id | uint8 | Cipher identifier: 0x01 = AES-256-GCM, 0x02 = Kuznechik-GCM |
    cipher_ = static_cast<ECipher>(buf[POSITION_CIPHER_ID]);
    // | 0x000D | 1 | kdf_id | uint8 | KDF identifier: 0x01 = Argon2id |
    kdf_ = static_cast<EKDF>(buf[POSITION_KDF_ID]);
    // | 0x000E | 2 | kdf_profile_id | uint16_le | KDF profile: 0 = user-defined, 1--5 = predefined |
    read_le16(buf.data() + POSITION_KDF_PROFILE_ID, reinterpret_cast<uint16_t&>(kdf_profile_));
    // | 0x0010 | 4 | kdf_m_kib | uint32_le | Argon2id memory volume in KiB |
    read_le32(buf.data() + POSITION_KDF_M_KIB, kdf_m_kib_);
    // | 0x0014 | 4 | kdf_t | uint32_le | Number of iterations (passes) Argon2id |
    read_le32(buf.data() + POSITION_KDF_T, kdf_t_);
    // | 0x0018 | 4 | kdf_p | uint32_le | Degree of parallelism Argon2id |
    read_le32(buf.data() + POSITION_KDF_P, kdf_p_);
    // | 0x001C | 32 | salt | uint8[32] | Random 256-bit salt |
    std::copy(buf.begin() + POSITION_SALT, buf.begin() + POSITION_DEK_NONCE, salt_.begin());
    // | 0x003C | 12 | dek_nonce | uint8[12] | 96-bit nonce for DEK encryption |
    std::copy(buf.begin() + POSITION_DEK_NONCE, buf.begin() + POSITION_ENCRYPTED_DEK, dek_nonce_.begin());
    // | 0x0048 | 32 | encrypted_dek | uint8[32] | Encrypted DEK (AES-256-GCM under KEK) |
    std::copy(buf.begin() + POSITION_ENCRYPTED_DEK, buf.begin() + POSITION_DEK_AUTH_TAG, encrypted_dek_.begin());
    // | 0x0068 | 16 | dek_auth_tag | uint8[16] | 128-bit GCM authentication tag for DEK |
    std::copy(buf.begin() + POSITION_DEK_AUTH_TAG, buf.begin() + POSITION_CONTAINER_SIZE, dek_auth_tag_.begin());
    // | 0x0078 | 8 | container_size | uint64_le | Full container size in bytes |
    read_le64(buf.data() + POSITION_CONTAINER_SIZE, container_size_);
    // | 0x0080 | 8 | file_table_offset | uint64_le | Absolute offset of the file table |
    read_le64(buf.data() + POSITION_FILE_TABLE_OFFSET, file_table_offset_);
    // | 0x0088 | 8 | file_table_size | uint64_le | Size of the encrypted file table |
    read_le64(buf.data() + POSITION_FILE_TABLE_SIZE, file_table_size_);
    // | 0x0090 | 4 | file_count | uint32_le | Number of files in the container |
    read_le32(buf.data() + POSITION_FILE_COUNT, file_count_);
    // | 0x0094 | 4 | block_size | uint32_le | Data block size in bytes (default 65536) |
    read_le32(buf.data() + POSITION_BLOCK_SIZE, block_size_);
    // | 0x0098 | 4 | header_version | uint32_le | Monotonic counter of the header version |
    read_le32(buf.data() + POSITION_HEADER_VERSION, header_version_);
    // | 0x009C | 4 | flags | uint32_le | Bitfield of flags |
    read_le32(buf.data() + POSITION_FLAGS, flags_);
    // | 0x00A0 | 32 | header_hmac | uint8[32] | HMAC-SHA256 bytes [0x0000..0x009F] |
    std::copy(buf.begin() + POSITION_HEADER_HMAC, buf.begin() + POSITION_RESERVED, header_hmac_.begin());
    // | 0x00C0 | 320 | reserved | uint8[320] | Reserved (zeros) |
    std::copy(buf.begin() + POSITION_RESERVED, buf.begin() + POSITION_JSON_METADATA, reserved_.begin());
    // | 0x0200 | 512 | json_metadata | uint8[512] | JSON metadata in UTF-8 encoding |
    std::copy(buf.begin() + POSITION_JSON_METADATA, buf.begin() + POSITION_PADDING, json_metadata_.begin());
}

void Header::write() {
    createBuffer();
}

bool Header::validate() {
    return false;
}

const HeaderBuffer& Header::buffer() {
    return buffer_;
}

void Header::createBuffer() {

    // | 0x0000 | 4 | magic | uint32_le | Magic number 0x46454353 ("SCEF" to ASCII) |
    std::copy(HEADER_MAGIC.begin(), HEADER_MAGIC.end(), buffer_.begin() + POSITION_MAGIC);

    // | 0x0004 | 2 | version_major | uint16_le | Major version format = 1 |
    write_le16(&buffer_.at(POSITION_VERSION_MAJOR), version_major_);

    // | 0x0006 | 2 | version_minor | uint16_le | Minor version format = 0 |
    write_le16(&buffer_.at(POSITION_VERSION_MINOR), version_minor_);

    // | 0x0008 | 4 | header_size | uint32_le | Header size in bytes = 4096 |
    write_le32(&buffer_.at(POSITION_HEADER_SIZE), header_size_);

    // | 0x000C | 1 | cipher_id | uint8 | Cipher identifier: 0x01 = AES-256-GCM, 0x02 = Kuznechik-GCM |
    buffer_[POSITION_CIPHER_ID] = static_cast<uint8_t>(cipher_);

    // | 0x000D | 1 | kdf_id | uint8 | KDF identifier: 0x01 = Argon2id |
    buffer_[POSITION_KDF_ID] = static_cast<uint8_t>(kdf_);

    // | 0x000E | 2 | kdf_profile_id | uint16_le | KDF profile: 0 = user-defined, 1--5 = predefined |
    write_le16(&buffer_.at(POSITION_KDF_PROFILE_ID), static_cast<uint16_t>(kdf_profile_));

    // | 0x0010 | 4 | kdf_m_kib | uint32_le | Argon2id memory volume in KiB |
    write_le32(&buffer_.at(POSITION_KDF_M_KIB), kdf_m_kib_);

    // | 0x0014 | 4 | kdf_t | uint32_le | Number of iterations (passes) Argon2id |
    write_le32(&buffer_.at(POSITION_KDF_T), kdf_t_);

    // | 0x0018 | 4 | kdf_p | uint32_le | Degree of parallelism Argon2id |
    write_le32(&buffer_.at(POSITION_KDF_P), kdf_p_);

    // | 0x001C | 32 | salt | uint8[32] | Random 256-bit salt |
    std::copy(salt_.begin(), salt_.end(), buffer_.begin() + POSITION_SALT);

    // | 0x003C | 12 | dek_nonce | uint8[12] | 96-bit nonce for DEK encryption |
    std::copy(dek_nonce_.begin(), dek_nonce_.end(), buffer_.begin() + POSITION_DEK_NONCE);

    // | 0x0048 | 32 | encrypted_dek | uint8[32] | Encrypted DEK (AES-256-GCM under KEK) |
    std::copy(encrypted_dek_.begin(), encrypted_dek_.end(), buffer_.begin() + POSITION_ENCRYPTED_DEK);

    // | 0x0068 | 16 | dek_auth_tag | uint8[16] | 128-bit GCM authentication tag for DEK |
    std::copy(dek_auth_tag_.begin(), dek_auth_tag_.end(), buffer_.begin() + POSITION_DEK_AUTH_TAG);

    // | 0x0078 | 8 | container_size | uint64_le | Full container size in bytes |
    write_le64(&buffer_.at(POSITION_CONTAINER_SIZE), container_size_);

    // | 0x0080 | 8 | file_table_offset | uint64_le | Absolute offset of the file table |
    write_le64(&buffer_.at(POSITION_FILE_TABLE_OFFSET), file_table_offset_);

    // | 0x0088 | 8 | file_table_size | uint64_le | Size of the encrypted file table |
    write_le64(&buffer_.at(POSITION_FILE_TABLE_SIZE), file_table_size_);

    // | 0x0090 | 4 | file_count | uint32_le | Number of files in the container |
    write_le32(&buffer_.at(POSITION_FILE_COUNT), file_count_);

    // | 0x0094 | 4 | block_size | uint32_le | Data block size in bytes (default 65536) |
    write_le32(&buffer_.at(POSITION_BLOCK_SIZE), block_size_);

    // | 0x0098 | 4 | header_version | uint32_le | Monotonic counter of the header version |
    write_le32(&buffer_.at(POSITION_HEADER_VERSION), header_version_);

    // | 0x009C | 4 | flags | uint32_le | Bitfield of flags |
    write_le32(&buffer_.at(POSITION_FLAGS), flags_);

    // | 0x00A0 | 32 | header_hmac | uint8[32] | HMAC-SHA256 bytes [0x0000..0x009F] |
    std::copy(header_hmac_.begin(), header_hmac_.end(), buffer_.begin() + POSITION_HEADER_HMAC);

    // | 0x00C0 | 320 | reserved | uint8[320] | Reserved (zeros) |
    std::copy(reserved_.begin(), reserved_.end(), buffer_.begin() + POSITION_RESERVED);

    // | 0x0200 | 512 | json_metadata | uint8[512] | JSON metadata in UTF-8 encoding |
    std::copy(json_metadata_.begin(), json_metadata_.end(), buffer_.begin() + POSITION_JSON_METADATA);

    // | 0x0400 | 3072 | padding | uint8[3072] | Padding to 4096 bytes (zeros) |
    std::fill(buffer_.begin() + POSITION_PADDING, buffer_.begin() + POSITION_PADDING + 3072, 0);
}

namespace {
template<size_t N>
std::string hex_dump(const std::array<uint8_t, N>& arr) {
    std::ostringstream ss;
    for (size_t i = 0; i < N; ++i) {
        if (i > 0) ss << ' ';
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(arr[i]);
    }
    return ss.str();
}
}

std::string Header::to_string() const {
    std::ostringstream ss;
    ss << "=== SCEF Header ===\n";
    ss << "magic:             " << std::string(header_magic_.begin(), header_magic_.end()) << "\n";
    ss << "version:           " << version_major_ << "." << version_minor_ << "\n";
    ss << "header_size:       " << header_size_ << "\n";
    ss << "cipher_id:         0x" << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(cipher_) << "\n";
    ss << "kdf_id:            0x" << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(kdf_) << "\n";
    ss << "kdf_profile_id:    " << std::dec << static_cast<int>(kdf_profile_) << "\n";
    ss << "kdf_m_kib:         " << std::dec << kdf_m_kib_ << "\n";
    ss << "kdf_t:             " << kdf_t_ << "\n";
    ss << "kdf_p:             " << kdf_p_ << "\n";
    ss << "salt:              " << hex_dump(salt_) << "\n";
    ss << "dek_nonce:         " << hex_dump(dek_nonce_) << "\n";
    ss << "encrypted_dek:     " << hex_dump(encrypted_dek_) << "\n";
    ss << "dek_auth_tag:      " << hex_dump(dek_auth_tag_) << "\n";
    ss << "container_size:    " << std::dec << container_size_ << "\n";
    ss << "file_table_offset: " << file_table_offset_ << "\n";
    ss << "file_table_size:   " << file_table_size_ << "\n";
    ss << "file_count:        " << file_count_ << "\n";
    ss << "block_size:        " << block_size_ << "\n";
    ss << "header_version:    " << header_version_ << "\n";
    ss << "flags:             0x" << std::hex << std::setfill('0') << std::setw(8) << flags_ << "\n";
    ss << "header_hmac:       " << hex_dump(header_hmac_) << "\n";
    ss << "json_metadata:     " << std::string(json_metadata_.begin(),
            std::find(json_metadata_.begin(), json_metadata_.end(), '\0')) << "\n";
    return ss.str();
}

void Header::setFileTableOffset(uint64_t offset) {
    file_table_offset_ = offset;
}

void Header::setFileTableSize(uint64_t size) {
    file_table_size_ = size;
}

void Header::setContainerSize(uint64_t size) {
    container_size_ = size;
}

void Header::increaseFileCount() {
    file_count_++;
}

void Header::write_le16(uint8_t* buf, uint16_t value) {
    buf[0] = static_cast<uint8_t>(value);
    buf[1] = static_cast<uint8_t>(value >> 8);
}

void Header::write_le32(uint8_t* buf, uint32_t value) {
    buf[0] = static_cast<uint8_t>(value);
    buf[1] = static_cast<uint8_t>(value >> 8);
    buf[2] = static_cast<uint8_t>(value >> 16);
    buf[3] = static_cast<uint8_t>(value >> 24);
}

void Header::write_le64(uint8_t* buf, uint64_t value) {
    buf[0] = static_cast<uint8_t>(value);
    buf[1] = static_cast<uint8_t>(value >> 8);
    buf[2] = static_cast<uint8_t>(value >> 16);
    buf[3] = static_cast<uint8_t>(value >> 24);
    buf[4] = static_cast<uint8_t>(value >> 32);
    buf[5] = static_cast<uint8_t>(value >> 40);
    buf[6] = static_cast<uint8_t>(value >> 48);
    buf[7] = static_cast<uint8_t>(value >> 56);
}

void Header::read_le16(const uint8_t* buf, uint16_t& value) {
    value = static_cast<uint16_t>(buf[0]) | (static_cast<uint16_t>(buf[1]) << 8);
}

void Header::read_le32(const uint8_t* buf, uint32_t& value) {
    value = static_cast<uint32_t>(buf[0]) | (static_cast<uint32_t>(buf[1]) << 8) |
            (static_cast<uint32_t>(buf[2]) << 16) | (static_cast<uint32_t>(buf[3]) << 24);
}

void Header::read_le64(const uint8_t* buf, uint64_t& value) {
    value = static_cast<uint64_t>(buf[0]) | (static_cast<uint64_t>(buf[1]) << 8) |
            (static_cast<uint64_t>(buf[2]) << 16) | (static_cast<uint64_t>(buf[3]) << 24) |
            (static_cast<uint64_t>(buf[4]) << 32) | (static_cast<uint64_t>(buf[5]) << 40) |
            (static_cast<uint64_t>(buf[6]) << 48) | (static_cast<uint64_t>(buf[7]) << 56);
}
