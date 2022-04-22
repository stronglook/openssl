#pragma once

#include "openssl/evp.h"
#include "openssl/err.h"
#include <stdexcept>
#include <utility>
#include <cstring>

class AES
{
public:
    AES(const EVP_CIPHER* cipher, unsigned char* key, unsigned char* iv);

    std::pair<unsigned char*, int> encrypt(unsigned char* text);
    std::pair<unsigned char*, int> decrypt(std::pair<unsigned char*, int> encrypted);

    ~AES();
private:
    EVP_CIPHER_CTX* m_ctx;
    const EVP_CIPHER* m_cipher;
    unsigned char* m_key;
    unsigned char* m_iv;
};
