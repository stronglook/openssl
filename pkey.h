#pragma once

#include "openssl/evp.h"
#include <string>
#include <cstring>
#include <utility>
#include <stdexcept>

class PKey
{
public:
    PKey(EVP_PKEY* pkey);
    std::pair<unsigned char*, std::size_t> encrypt(const unsigned char *pInText);
    std::pair<unsigned char*, std::size_t> decrypt(std::pair<unsigned char*, std::size_t>);
    ~PKey();
private:
    EVP_PKEY* m_pkey = nullptr;
    EVP_PKEY_CTX* m_ctx = nullptr;
};
