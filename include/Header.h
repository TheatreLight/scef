#ifndef HEADER_H
#define HEADER_H

#include "enums/ECiphers.h"
#include "enums/EKDF.h"
#include "enums/EKDFProfile.h"

#include <array>
#include <string>
#include <cstdint>
#include <type_traits>

constexpr size_t   HEADER_SIZE        = 4096;
constexpr uint32_t BLOCK_SIZE         = 65536;
constexpr uint32_t DEFAULT_MAX_TABLE_SIZE = BLOCK_SIZE;

// Maximum practical container size: 2 TiB (2^41 bytes)
constexpr uint64_t MAX_CONTAINER_SIZE = (uint64_t)1 << 41;
// Minimum container size: 4 * (header_size + max_table_size).
// Computed at runtime because max_table_size is configurable.
// This constant uses the default max_table_size.
constexpr uint64_t MINIMAL_CONTAINER_SIZE =
    4ULL * (HEADER_SIZE + DEFAULT_MAX_TABLE_SIZE);
constexpr uint64_t DEFAULT_CONTAINER_SIZE = MINIMAL_CONTAINER_SIZE + 4ULL * BLOCK_SIZE;

constexpr std::array<char, 4> HEADER_MAGIC         = {'S', 'C', 'E', 'F'};
constexpr uint16_t            HEADER_VERSION_MAJOR = 1;
constexpr uint16_t            HEADER_VERSION_MINOR = 0;
constexpr size_t              NONCE_SIZE            = 12;
constexpr size_t              AUTH_TAG_SIZE         = 16;
constexpr uint32_t            ENCRYPTED_BLOCK_SIZE  = BLOCK_SIZE + NONCE_SIZE + AUTH_TAG_SIZE;

// ---- Binary layout offsets (spec Table 4.2) ----
constexpr size_t POSITION_MAGIC          = 0x0000;
constexpr size_t POSITION_VERSION_MAJOR  = 0x0004;
constexpr size_t POSITION_VERSION_MINOR  = 0x0006;
constexpr size_t POSITION_HEADER_SIZE    = 0x0008;
constexpr size_t POSITION_CIPHER_ID      = 0x000C;
constexpr size_t POSITION_KDF_ID         = 0x000D;
constexpr size_t POSITION_KDF_PROFILE_ID = 0x000E;
constexpr size_t POSITION_KDF_M_KIB      = 0x0010;
constexpr size_t POSITION_KDF_T          = 0x0014;
constexpr size_t POSITION_KDF_P          = 0x0018;
constexpr size_t POSITION_SALT           = 0x001C;
constexpr size_t POSITION_DEK_NONCE      = 0x003C;
constexpr size_t POSITION_ENCRYPTED_DEK  = 0x0048;
constexpr size_t POSITION_DEK_AUTH_TAG   = 0x0068;
constexpr size_t POSITION_CONTAINER_SIZE = 0x0078; // uint64_le
constexpr size_t POSITION_FILE_TABLE_SIZE = 0x0080; // uint32_le
constexpr size_t POSITION_MAX_TABLE_SIZE  = 0x0084; // uint32_le
constexpr size_t POSITION_FILE_COUNT      = 0x0088; // uint32_le
constexpr size_t POSITION_BLOCK_SIZE      = 0x008C; // uint32_le
constexpr size_t POSITION_HEADER_VERSION  = 0x0090; // uint32_le
constexpr size_t POSITION_FLAGS           = 0x0094; // uint32_le
constexpr size_t POSITION_RESERVED_0      = 0x0098; // uint8[8]
constexpr size_t POSITION_HEADER_HMAC     = 0x00A0; // uint8[32]
constexpr size_t POSITION_RESERVED        = 0x00C0; // uint8[320]
constexpr size_t POSITION_JSON_METADATA   = 0x0200; // uint8[512]
constexpr size_t POSITION_PADDING         = 0x0400;

// Number of bytes covered by header_hmac: [0x0000..0x009F].
constexpr size_t HMAC_PROTECTED_SIZE = 0x00A0;

using HeaderBuffer = std::array<uint8_t, HEADER_SIZE>;

/*
Spec Table 4.2 -- SCEF v1.0 header layout:

| 0x0000 | 4  | magic            | uint32_le   | 0x46454353 "SCEF"                              |
| 0x0004 | 2  | version_major    | uint16_le   | = 1                                            |
| 0x0006 | 2  | version_minor    | uint16_le   | = 0                                            |
| 0x0008 | 4  | header_size      | uint32_le   | = 4096                                         |
| 0x000C | 1  | cipher_id        | uint8       | 0x01 = AES-256-GCM, 0x02 = Kuznechik-GCM      |
| 0x000D | 1  | kdf_id           | uint8       | 0x01 = Argon2id                                |
| 0x000E | 2  | kdf_profile_id   | uint16_le   | 0 = custom, 1-4 = predefined                   |
| 0x0010 | 4  | kdf_m_kib        | uint32_le   | Argon2id memory in KiB                         |
| 0x0014 | 4  | kdf_t            | uint32_le   | Argon2id iterations                            |
| 0x0018 | 4  | kdf_p            | uint32_le   | Argon2id parallelism                           |
| 0x001C | 32 | salt             | uint8[32]   | 256-bit random salt                            |
| 0x003C | 12 | dek_nonce        | uint8[12]   | 96-bit nonce for DEK encryption                |
| 0x0048 | 32 | encrypted_dek    | uint8[32]   | AES-256-GCM encrypted DEK                      |
| 0x0068 | 16 | dek_auth_tag     | uint8[16]   | GCM auth tag for DEK                           |
| 0x0078 | 8  | container_size   | uint64_le   | Total container size in bytes                  |
| 0x0080 | 4  | file_table_size  | uint32_le   | Current encrypted file table size in bytes     |
| 0x0084 | 4  | max_table_size   | uint32_le   | Reserved space per slot for file table         |
| 0x0088 | 4  | file_count       | uint32_le   | Number of files in container                   |
| 0x008C | 4  | block_size       | uint32_le   | Data block size in bytes (default 65536)       |
| 0x0090 | 4  | header_version   | uint32_le   | Monotonic update counter                       |
| 0x0094 | 4  | flags            | uint32_le   | Bit flags                                      |
| 0x0098 | 8  | reserved_0       | uint8[8]    | Reserved (zeros)                               |
| 0x00A0 | 32 | header_hmac      | uint8[32]   | HMAC-SHA256 of bytes [0x0000..0x009F]          |
| 0x00C0 | 320| reserved         | uint8[320]  | Reserved (zeros)                               |
| 0x0200 | 512| json_metadata    | uint8[512]  | UTF-8 JSON metadata                            |
| 0x0400 | 3072| padding         | uint8[3072] | Zero padding to 4096 bytes                     |
*/

class Header {
public:
    Header();
    ~Header();
    void read(const HeaderBuffer& buf);
    void serialize();

    // Check magic bytes. Returns false if magic is not "SCEF".
    // This is the lightweight check safe to call without a crypto key.
    bool validate() const;

    // Store a pre-computed HMAC into the header_hmac field and
    // re-serialize the buffer so the stored bytes reflect it.
    void storeHmac(const std::array<uint8_t, 32>& hmac);

    // Return the raw bytes [0x0000..0x009F] that are covered by the HMAC.
    // The caller uses these to compute and verify the HMAC externally.
    [[nodiscard]] std::array<uint8_t, HMAC_PROTECTED_SIZE> hmacProtectedBytes() const;

    // Return the stored HMAC value (read from the header buffer).
    [[nodiscard]] const std::array<uint8_t, 32>& storedHmac() const { return header_hmac_; }

    const HeaderBuffer& buffer() const;
    std::string to_string() const;

    void setFileTableSize(uint32_t size);
    void setMaxTableSize(uint32_t size);
    void setContainerSize(uint64_t size);
    void increaseFileCount();
    void incrementHeaderVersion();
    ECipher getCipher() const noexcept { return cipher_; }
    void setCipher(ECipher c) noexcept { cipher_ = c; }

    // KDF parameter setters — call before initCryptoForCreate() on new containers.
    void setKdfProfile(EKDFProfile profile);
    void setKdfMKib(uint32_t m_kib);
    void setKdfT(uint32_t t);
    void setKdfP(uint32_t p);

    // DEK wrapping fields — set by CryptoManager::wrapDek(), read by unwrapDek().
    void setDekNonce(const std::array<uint8_t, NONCE_SIZE>& nonce);
    void setEncryptedDek(const std::array<uint8_t, 32>& enc_dek);
    void setDekAuthTag(const std::array<uint8_t, AUTH_TAG_SIZE>& tag);

    // Mutable salt accessor — only legitimate caller is CryptoManager::generateSalt
    // during initCryptoForCreate. Do not mutate elsewhere.
    std::array<uint8_t, 32>& getSaltData() { return salt_; }
    const std::array<uint8_t, 32>& getSalt() const { return salt_; }
    const std::array<uint8_t, NONCE_SIZE>& getDekNonce()  const { return dek_nonce_; }
    const std::array<uint8_t, 32>&        getEncryptedDek() const { return encrypted_dek_; }
    const std::array<uint8_t, AUTH_TAG_SIZE>& getDekAuthTag() const { return dek_auth_tag_; }

    uint32_t getFileTableSize()  const { return file_table_size_; }
    uint32_t getMaxTableSize()   const { return max_table_size_; }
    uint32_t getHeaderSize()     const { return header_size_; }
    uint32_t getChunkSize()      const { return block_size_; }
    uint64_t getContainerSize()  const { return container_size_; }
    uint32_t getKdfMKib()        const { return kdf_m_kib_; }
    uint32_t getKdfT()           const { return kdf_t_; }
    uint32_t getKdfP()           const { return kdf_p_; }

private:
    void createBuffer();
    void write_le16(uint8_t* buf, uint16_t value);
    void write_le32(uint8_t* buf, uint32_t value);
    void write_le64(uint8_t* buf, uint64_t value);

    template<typename T>
    T read_le(const uint8_t*& p) {
        static_assert(std::is_integral_v<T>, "read_le requires an integral type");

        T value = 0;
        for (size_t i = 0; i < sizeof(T); ++i) {
            value |= static_cast<T>(p[i]) << (8 * i);
        }
        p += sizeof(T);
        return value;
    }

    HeaderBuffer buffer_;

    std::array<char, 4> header_magic_                = HEADER_MAGIC;
    uint16_t version_major_                          = HEADER_VERSION_MAJOR;
    uint16_t version_minor_                          = HEADER_VERSION_MINOR;
    uint32_t header_size_                            = HEADER_SIZE;
    ECipher  cipher_                                 = ECipher::AES_256_GCM;
    EKDF     kdf_                                    = EKDF::Argon2id;
    // KDF parameters are initialised to the Standard profile in the constructor body
    // (via getProfileParams(EKDFProfile::Standard)) — single source of truth.
    EKDFProfile kdf_profile_                         = EKDFProfile::Standard;
    uint32_t kdf_m_kib_                              = 0;
    uint32_t kdf_t_                                  = 0;
    uint32_t kdf_p_                                  = 0;
    std::array<uint8_t, 32> salt_                    = {};
    std::array<uint8_t, NONCE_SIZE> dek_nonce_       = {};
    std::array<uint8_t, 32> encrypted_dek_           = {};
    std::array<uint8_t, AUTH_TAG_SIZE> dek_auth_tag_ = {};
    uint64_t container_size_                         = 0;
    uint32_t file_table_size_                        = 0;
    uint32_t max_table_size_                         = DEFAULT_MAX_TABLE_SIZE;
    uint32_t file_count_                             = 0;
    uint32_t block_size_                             = BLOCK_SIZE;
    uint32_t header_version_                         = 0;
    uint32_t flags_                                  = 0;
    std::array<uint8_t, 8> reserved_0_               = {};
    std::array<uint8_t, 32> header_hmac_             = {};
    std::array<uint8_t, 320> reserved_               = {};
    std::array<uint8_t, 512> json_metadata_          = {};
};

#endif // HEADER_H
