#ifndef CRYPTO_CONTEXT_H
#define CRYPTO_CONTEXT_H

#include "Header.h"

#include "botan/aead.h"
#include "botan/auto_rng.h"
#include "botan/secmem.h"

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

struct CryptoContext {
    Botan::AutoSeeded_RNG rng;
    std::unique_ptr<Botan::AEAD_Mode> cipher;
    Botan::secure_vector<uint8_t> buf;

    static CryptoContext makeEncryptor(const uint8_t* dek, size_t dekSize,
                                       const std::string& cipherAlgo = "AES-256/GCM") {
        CryptoContext ctx;
        ctx.cipher = Botan::AEAD_Mode::create(cipherAlgo, Botan::Cipher_Dir::Encryption);
        if (!ctx.cipher) {
            throw std::runtime_error("CryptoContext: " + cipherAlgo + " encryption not available");
        }
        ctx.cipher->set_key(dek, dekSize);
        ctx.buf.resize(BLOCK_SIZE + AUTH_TAG_SIZE);
        return ctx;
    }

    static CryptoContext makeDecryptor(const uint8_t* dek, size_t dekSize,
                                       const std::string& cipherAlgo = "AES-256/GCM") {
        CryptoContext ctx;
        ctx.cipher = Botan::AEAD_Mode::create(cipherAlgo, Botan::Cipher_Dir::Decryption);
        if (!ctx.cipher) {
            throw std::runtime_error("CryptoContext: " + cipherAlgo + " decryption not available");
        }
        ctx.cipher->set_key(dek, dekSize);
        ctx.buf.resize(BLOCK_SIZE + AUTH_TAG_SIZE);
        return ctx;
    }
};

#endif // CRYPTO_CONTEXT_H
