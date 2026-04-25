#include "CryptoManager.h"
#include "BenchMeasurerGuard.h"
#include "CryptoContext.h"
#include "Header.h"
#include "Logger.h"

#include "botan/aead.h"
#include "botan/auto_rng.h"
#include "botan/mac.h"
#include "botan/mem_ops.h"
#include "botan/pwdhash.h"

#include <cstring>
#include <span>
#include <stdexcept>

CryptoManager::CryptoManager() {
    kek_.fill(0);
    dek_.fill(0);
}

CryptoManager::~CryptoManager() {
    // Zero key material on destruction using Botan's scrub (resistant to optimizer removal).
    Botan::secure_scrub_memory(kek_.data(), KEK_SIZE);
    Botan::secure_scrub_memory(dek_.data(), DEK_SIZE);
}

void CryptoManager::deriveKek(const std::string& password, Header& header) {
    BenchMeasurerGuard bench("CryptoManager::deriveKek");
    LOG_DEBUG("deriveKek: Argon2id(m=%u KiB, t=%u, p=%u), password_len=%zu, salt[0..2]=%02x%02x%02x",
              header.getKdfMKib(), header.getKdfT(), header.getKdfP(), password.size(),
              header.getSaltData()[0], header.getSaltData()[1], header.getSaltData()[2]);
    auto pwdhash_fam = Botan::PasswordHashFamily::create("Argon2id");
    if (!pwdhash_fam) {
        throw std::runtime_error("Argon2id not available in this Botan build");
    }
    auto pwdhash = pwdhash_fam->from_params(header.getKdfMKib(), header.getKdfT(), header.getKdfP());
    pwdhash->derive_key(kek_.data(), KEK_SIZE,
                        password.c_str(), password.size(),
                        header.getSaltData().data(), header.getSaltData().size());
    kek_ready_ = true;
    dek_ready_ = false; // KEK changed; DEK must be re-derived via unwrapDek.
    LOG_DEBUG("deriveKek: KEK ready, kek[0..2]=%02x%02x%02x", kek_[0], kek_[1], kek_[2]);
}

void CryptoManager::wrapDek(std::array<uint8_t, 12>& dek_nonce_out, std::array<uint8_t, DEK_SIZE>& encrypted_dek_out,
    std::array<uint8_t, 16>& dek_auth_tag_out) {
    BenchMeasurerGuard bench("CryptoManager::wrapDek");
    if (!kek_ready_) {
        throw std::runtime_error("CryptoManager: KEK not derived; call deriveKek() first");
    }

    // Generate a cryptographically random DEK and nonce.
    Botan::AutoSeeded_RNG rng;
    rng.randomize(dek_.data(), DEK_SIZE);
    dek_ready_ = true;

    rng.randomize(dek_nonce_out.data(), dek_nonce_out.size());

    // Encrypt the random DEK with AES-256-GCM using the KEK.
    auto cipher = Botan::AEAD_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    if (!cipher) {
        throw std::runtime_error("AES-256/GCM not available");
    }
    cipher->set_key(kek_.data(), KEK_SIZE);
    cipher->set_associated_data(std::span<const uint8_t>{}); // no additional data
    cipher->start(dek_nonce_out.data(), dek_nonce_out.size());

    // Input: 32-byte DEK. Output: 32-byte ciphertext + 16-byte tag.
    Botan::secure_vector<uint8_t> buf(dek_.begin(), dek_.end());
    cipher->finish(buf);

    // buf now holds: 32 bytes ciphertext + 16 bytes tag (total 48 bytes).
    if (buf.size() != DEK_SIZE + 16) {
        throw std::runtime_error("Unexpected AES-GCM output size for DEK wrap");
    }
    std::copy(buf.begin(), buf.begin() + DEK_SIZE, encrypted_dek_out.begin());
    std::copy(buf.begin() + DEK_SIZE, buf.end(), dek_auth_tag_out.begin());
    LOG_DEBUG("wrapDek: DEK generated and wrapped, nonce[0..2]=%02x%02x%02x, tag[0..2]=%02x%02x%02x",
              dek_nonce_out[0], dek_nonce_out[1], dek_nonce_out[2],
              dek_auth_tag_out[0], dek_auth_tag_out[1], dek_auth_tag_out[2]);
}

void CryptoManager::unwrapDek(const std::array<uint8_t, 12>& dek_nonce,
                               const std::array<uint8_t, DEK_SIZE>& encrypted_dek,
                               const std::array<uint8_t, 16>& dek_auth_tag) {
    if (!kek_ready_) {
        throw std::runtime_error("CryptoManager: KEK not derived; call deriveKek() first");
    }

    auto cipher = Botan::AEAD_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    if (!cipher) {
        throw std::runtime_error("AES-256/GCM not available");
    }
    cipher->set_key(kek_.data(), KEK_SIZE);
    cipher->set_associated_data(std::span<const uint8_t>{});
    cipher->start(dek_nonce.data(), dek_nonce.size());

    // Input to finish(): ciphertext + tag (32 + 16 = 48 bytes).
    Botan::secure_vector<uint8_t> buf;
    buf.insert(buf.end(), encrypted_dek.begin(), encrypted_dek.end());
    buf.insert(buf.end(), dek_auth_tag.begin(), dek_auth_tag.end());

    try {
        cipher->finish(buf);
    } catch (const Botan::Invalid_Authentication_Tag&) {
        throw std::runtime_error("Wrong password: DEK authentication failed");
    }

    // buf now holds the 32-byte plaintext DEK.
    if (buf.size() != DEK_SIZE) {
        throw std::runtime_error("Unexpected decrypted DEK size");
    }
    std::copy(buf.begin(), buf.end(), dek_.begin());
    dek_ready_ = true;
    LOG_DEBUG("unwrapDek: DEK decrypted successfully, dek[0..2]=%02x%02x%02x",
              dek_[0], dek_[1], dek_[2]);
}

std::array<uint8_t, 32> CryptoManager::computeHmac(const uint8_t* data, size_t size) const {
    if (!kek_ready_) {
        throw std::runtime_error("CryptoManager: KEK not derived; call deriveKek() first");
    }
    auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
    if (!mac) {
        throw std::runtime_error("HMAC-SHA256 not available");
    }
    mac->set_key(kek_.data(), KEK_SIZE);
    mac->update(data, size);
    auto digest = mac->final();
    std::array<uint8_t, 32> result{};
    std::copy(digest.begin(), digest.end(), result.begin());
    LOG_DEBUG("computeHmac: input_size=%zu, hmac[0..2]=%02x%02x%02x",
        size, result[0], result[1], result[2]);
    return result;
}

void CryptoManager::encrypt(const char* data, char* output, size_t dataSize) {
    if (!dek_ready_) {
        throw std::runtime_error("CryptoManager: DEK not ready; call wrapDek() or unwrapDek() first");
    }

    // Generate a random 96-bit nonce for this block.
    Botan::AutoSeeded_RNG rng;
    std::array<uint8_t, NONCE_SIZE> nonce{};
    rng.randomize(nonce.data(), nonce.size());

    // Write nonce first.
    std::memcpy(output, nonce.data(), NONCE_SIZE);
    output += NONCE_SIZE;

    // Encrypt with AES-256-GCM.
    auto cipher = Botan::AEAD_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    if (!cipher) {
        throw std::runtime_error("AES-256/GCM not available");
    }
    cipher->set_key(dek_.data(), DEK_SIZE);
    cipher->set_associated_data(std::span<const uint8_t>{});
    cipher->start(nonce.data(), nonce.size());

    Botan::secure_vector<uint8_t> buf(reinterpret_cast<const uint8_t*>(data),
                                       reinterpret_cast<const uint8_t*>(data) + dataSize);
    cipher->finish(buf);

    // buf: dataSize bytes ciphertext + 16 bytes auth tag.
    std::memcpy(output, buf.data(), buf.size());
    LOG_DEBUG("encrypt: plain_size=%zu, nonce[0..2]=%02x%02x%02x",
              dataSize, nonce[0], nonce[1], nonce[2]);
}

void CryptoManager::generateSalt(std::array<uint8_t, 32>& salt) {
    Botan::AutoSeeded_RNG rng;
    rng.randomize(salt.data(), salt.size());
}

void CryptoManager::decrypt(const char* data, char* output, size_t dataSize) {
    if (!dek_ready_) {
        throw std::runtime_error("CryptoManager: DEK not ready; call wrapDek() or unwrapDek() first");
    }

    // Read nonce from the start of the block.
    std::array<uint8_t, NONCE_SIZE> nonce{};
    std::memcpy(nonce.data(), data, NONCE_SIZE);
    data += NONCE_SIZE;

    // Input: dataSize bytes ciphertext + 16 bytes tag.
    size_t enc_size = dataSize + AUTH_TAG_SIZE;
    Botan::secure_vector<uint8_t> buf(reinterpret_cast<const uint8_t*>(data),
                                       reinterpret_cast<const uint8_t*>(data) + enc_size);

    auto cipher = Botan::AEAD_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    if (!cipher) {
        throw std::runtime_error("AES-256/GCM not available");
    }
    cipher->set_key(dek_.data(), DEK_SIZE);
    cipher->set_associated_data(std::span<const uint8_t>{});
    cipher->start(nonce.data(), nonce.size());

    try {
        cipher->finish(buf);
    } catch (const Botan::Invalid_Authentication_Tag&) {
        throw std::runtime_error("Data block authentication failed");
    }

    if (buf.size() != dataSize) {
        throw std::runtime_error("Unexpected decrypted size");
    }

    std::memcpy(output, buf.data(), dataSize);
    LOG_DEBUG("decrypt: plain_size=%zu, nonce[0..2]=%02x%02x%02x",
              dataSize, nonce[0], nonce[1], nonce[2]);
}

void CryptoManager::encrypt(CryptoContext& ctx, const char* data, char* output, size_t dataSize) {
    if (!dek_ready_) {
        throw std::runtime_error("CryptoManager: DEK not ready; call wrapDek() or unwrapDek() first");
    }

    std::array<uint8_t, NONCE_SIZE> nonce{};
    ctx.rng.randomize(nonce.data(), nonce.size());
    std::memcpy(output, nonce.data(), NONCE_SIZE);
    output += NONCE_SIZE;

    ctx.buf.assign(reinterpret_cast<const uint8_t*>(data),
                   reinterpret_cast<const uint8_t*>(data) + dataSize);
    ctx.cipher->set_associated_data(std::span<const uint8_t>{});
    ctx.cipher->start(nonce.data(), nonce.size());
    ctx.cipher->finish(ctx.buf);

    std::memcpy(output, ctx.buf.data(), ctx.buf.size());
}

void CryptoManager::decrypt(CryptoContext& ctx, const char* data, char* output, size_t dataSize) {
    if (!dek_ready_) {
        throw std::runtime_error("CryptoManager: DEK not ready; call wrapDek() or unwrapDek() first");
    }

    std::array<uint8_t, NONCE_SIZE> nonce{};
    std::memcpy(nonce.data(), data, NONCE_SIZE);
    data += NONCE_SIZE;

    size_t enc_size = dataSize + AUTH_TAG_SIZE;
    ctx.buf.assign(reinterpret_cast<const uint8_t*>(data),
                   reinterpret_cast<const uint8_t*>(data) + enc_size);
    ctx.cipher->set_associated_data(std::span<const uint8_t>{});
    ctx.cipher->start(nonce.data(), nonce.size());

    try {
        ctx.cipher->finish(ctx.buf);
    } catch (const Botan::Invalid_Authentication_Tag&) {
        throw std::runtime_error("Data block authentication failed");
    }

    if (ctx.buf.size() != dataSize) {
        throw std::runtime_error("Unexpected decrypted size");
    }
    std::memcpy(output, ctx.buf.data(), dataSize);
}
