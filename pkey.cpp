#include "pkey.h"

PKey::PKey(EVP_PKEY *pkey) : m_pkey(pkey)
{
    if (pkey == nullptr) {
        throw std::runtime_error("pkey is null");
    }

    m_ctx = EVP_PKEY_CTX_new(m_pkey, NULL);
    if (!m_ctx) {
       throw std::runtime_error("EVP_PKEY_CTX_new");
    }
}

std::pair<unsigned char*, std::size_t> PKey::encrypt(const unsigned char *text)
{
    if (EVP_PKEY_encrypt_init(m_ctx) <= 0) {
        throw std::runtime_error("EVP_PKEY_encrypt_init");
    }

    std::size_t outBytesLen;
    std::size_t textLen = (std::size_t)std::strlen((char*)text);

    if (EVP_PKEY_encrypt(m_ctx, NULL, &outBytesLen, text, textLen) <= 0) {
        throw std::runtime_error("EVP_PKEY_encrypt (out NULL)");
    }

    unsigned char *outBytes = new unsigned char[outBytesLen];

    if (EVP_PKEY_encrypt(m_ctx, outBytes, &outBytesLen, text, textLen) <= 0) {
        throw std::runtime_error("EVP_PKEY_encrypt");
    }

    return std::pair<unsigned char*, std::size_t>(outBytes, outBytesLen);
}

std::pair<unsigned char*, std::size_t> PKey::decrypt(std::pair<unsigned char*, std::size_t> encrypted)
{
    const unsigned char *encryptedBytes = encrypted.first;
    std::size_t encryptedBytesLen = encrypted.second;

    if (EVP_PKEY_decrypt_init(m_ctx) <= 0) {
        throw std::runtime_error("EVP_PKEY_decrypt_init");
    }

    std::size_t outlen;

    if (EVP_PKEY_decrypt(m_ctx, NULL, &outlen, encryptedBytes, encryptedBytesLen) <= 0) {
        throw std::runtime_error("EVP_PKEY_decrypt (out NULL)");
    }

    unsigned char *outText = new unsigned char[outlen];

    if (EVP_PKEY_decrypt(m_ctx, outText, &outlen, encryptedBytes, encryptedBytesLen) <= 0) {
        throw std::runtime_error("EVP_PKEY_decrypt");
    }

    return std::pair<unsigned char*, size_t>(outText, outlen);
}

PKey::~PKey()
{
    EVP_PKEY_CTX_free(m_ctx);
}
