#include "CryptoManager.h"
#include "Header.h"

CryptoManager::CryptoManager() {}

CryptoManager::~CryptoManager() {}

void CryptoManager::encrypt(const char* data, char* output, size_t dataSize) {
    // TODO: it's just a stub
    // ADD NONCE
    for (int i = 0; i < 12; ++i) {
        *output++ = '\0';
    }
    // SIMULATE ENCRYPTING
    while (dataSize--) {
        *output++ = *data++;
    }
    // ADD AUTH TAG
    for (int i = 0; i < 16; ++i) {
        *output++ = '\0';
    }
}

void CryptoManager::decrypt(const char* data, char* output, size_t dataSize) {
    // TODO: it's just a stub
    // Remove Nonce
    for (int i = 0; i < 12; ++i) {
        data++;
    }
    // Simulate Decrypting
    while (dataSize--) {
        *output++ = *data++;
    }
    // Remove Auth tag (copied without it)
}
