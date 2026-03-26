#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

class CryptoManager {
public:
    CryptoManager();
    ~CryptoManager();
    CryptoManager(const CryptoManager&) = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;
    CryptoManager(CryptoManager&&) = delete;
    CryptoManager& operator=(CryptoManager&&) = delete;

    void encrypt(const char* data, char* output, size_t dataSize);
    void decrypt(const char* data, char* output, size_t dataSize);

private:

};

#endif // CRYPTO_MANAGER_H
