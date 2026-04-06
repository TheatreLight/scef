/**
 * Generate cross-implementation test vectors for SCEF browser viewer.
 *
 * This program creates a container with known password and files,
 * then dumps all intermediate crypto values as JSON so the JS
 * implementation can verify byte-identical results.
 *
 * Build:
 *   cd scef/build/debug
 *   cmake --build . --target generate_vectors
 *
 * Or manually:
 *   cl /std:c++20 /I../../include generate_vectors.cpp -link botan-3.lib
 */

#include "Header.h"
#include "CryptoManager.h"
#include "FileManager.h"

#include <botan/hex.h>
#include <botan/mac.h>
#include <botan/pwdhash.h>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>

int main() {
    // Read the test container created by the CLI.
    // Expects: container at argv[1], password at argv[2]
    // Outputs JSON test vectors to stdout.

    const char* containerPath = nullptr;
    const char* password = "testpass123";

    // Use a fixed known container or create one on the fly.
    // For simplicity, we derive KEK from known inputs using Botan directly.
    // This matches what CryptoManager::deriveKek() does internally.

    // --- Test vector 1: known password + salt → KEK ---
    // Use a deterministic salt for reproducible vectors.
    std::array<uint8_t, 32> salt{};
    for (int i = 0; i < 32; i++) salt[i] = static_cast<uint8_t>(i);

    uint32_t m_kib = 19 * 1024; // 19 MiB (FastAccess profile)
    uint32_t t = 2;
    uint32_t p = 1;

    // Derive KEK using Botan Argon2id — same code path as CryptoManager.
    auto pwdhash_fam = Botan::PasswordHashFamily::create("Argon2id");
    auto pwdhash = pwdhash_fam->from_params(m_kib, t, p);

    std::array<uint8_t, 32> kek{};
    pwdhash->derive_key(kek.data(), 32,
                        password, std::strlen(password),
                        salt.data(), salt.size());

    // --- Test vector 2: KEK → HMAC of known data ---
    // Use a simple known data block for HMAC.
    std::array<uint8_t, 160> hmacInput{};
    for (int i = 0; i < 160; i++) hmacInput[i] = static_cast<uint8_t>(i);

    auto mac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
    mac->set_key(kek.data(), 32);
    mac->update(hmacInput.data(), hmacInput.size());
    auto hmacResult = mac->final();

    // Output JSON
    std::cout << "{\n";
    std::cout << "  \"password\": \"" << password << "\",\n";
    std::cout << "  \"salt\": \"" << Botan::hex_encode(salt) << "\",\n";
    std::cout << "  \"kdf_m_kib\": " << m_kib << ",\n";
    std::cout << "  \"kdf_t\": " << t << ",\n";
    std::cout << "  \"kdf_p\": " << p << ",\n";
    std::cout << "  \"expected_kek\": \"" << Botan::hex_encode(kek) << "\",\n";
    std::cout << "  \"hmac_input\": \"" << Botan::hex_encode(hmacInput) << "\",\n";
    std::cout << "  \"expected_hmac\": \"" << Botan::hex_encode(hmacResult) << "\"\n";
    std::cout << "}\n";

    return 0;
}
