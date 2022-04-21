#pragma once

#include <string>
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"

class RSAKey
{
public:
    RSAKey(unsigned int keyBits);

    std::string getPublicKey();
    std::string getPrivateKey();
    EVP_PKEY* getPKey();

    ~RSAKey();

private:
    EVP_PKEY* m_pkey = nullptr;

    std::string BIOToString(BIO* bio);
    EVP_PKEY* generateRSAKey(unsigned int key_bits);
};
