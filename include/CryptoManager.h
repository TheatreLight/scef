#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include <array>
#include <cstdint>
#include <string>

// AES-256-GCM key size in bytes.
constexpr size_t KEK_SIZE = 32;
// DEK (data encryption key) size in bytes.
constexpr size_t DEK_SIZE = 32;

class Header;

class CryptoManager {
public:
    CryptoManager();
    ~CryptoManager();
    CryptoManager(const CryptoManager&) = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;
    CryptoManager(CryptoManager&&) = delete;
    CryptoManager& operator=(CryptoManager&&) = delete;

    // Derive KEK from password + salt using Argon2id with the given KDF parameters.
    // Call before wrapDek() on create or unwrapDek() on open.
    // m_kib: Argon2id memory in KiB; t: iterations; p: parallelism.
    void deriveKek(const std::string& password, Header& header);

    // Wrap (encrypt) the zero DEK with the derived KEK using AES-256-GCM.
    // Fills dek_nonce, encrypted_dek, and dek_auth_tag in the provided buffers.
    // Call after deriveKek() on create.
    void wrapDek(std::array<uint8_t, 12>& dek_nonce_out,
                 std::array<uint8_t, DEK_SIZE>& encrypted_dek_out,
                 std::array<uint8_t, 16>& dek_auth_tag_out);

    // Unwrap (decrypt) the DEK using the derived KEK.
    // Throws std::runtime_error if authentication fails (wrong password).
    // Call after deriveKek() on open.
    void unwrapDek(const std::array<uint8_t, 12>& dek_nonce,
                   const std::array<uint8_t, DEK_SIZE>& encrypted_dek,
                   const std::array<uint8_t, 16>& dek_auth_tag);

    // Compute HMAC-SHA256 of data using the derived KEK as the HMAC key.
    // Used to produce the header_hmac field.
    [[nodiscard]] std::array<uint8_t, 32> computeHmac(
        const uint8_t* data, size_t size) const;

    // Encrypt one plaintext chunk (BLOCK_SIZE or less).
    // Output layout: [12-byte nonce][ciphertext][16-byte auth tag].
    // The output buffer must be at least dataSize + 12 + 16 bytes.
    void encrypt(const char* data, char* output, size_t dataSize);

    // Decrypt one encrypted chunk.
    // Input layout: [12-byte nonce][ciphertext][16-byte auth tag].
    // The output buffer must be at least dataSize bytes.
    void decrypt(const char* data, char* output, size_t dataSize);

    // Generate a cryptographically random 32-byte salt.
    void generateSalt(std::array<uint8_t, 32>& salt);

private:
    // Derived key-encryption key (32 bytes). Zeroed on destruction.
    std::array<uint8_t, KEK_SIZE> kek_ = {};
    // Decrypted DEK (32 bytes). Zeroed on destruction.
    std::array<uint8_t, DEK_SIZE> dek_ = {};

    bool kek_ready_ = false;
    bool dek_ready_ = false;
};

#endif // CRYPTO_MANAGER_H
