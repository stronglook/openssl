#include "aes.h"

AES::AES(const EVP_CIPHER* cipher, unsigned char *key, unsigned char *iv)
    : m_ctx(EVP_CIPHER_CTX_new()), m_cipher(cipher), m_key(key), m_iv(iv)
{
    if (m_ctx == NULL) {
        throw std::runtime_error("EVP_CIPHER_CTX_new");
    }
}

std::pair<unsigned char*, int> AES::encrypt(unsigned char* text)
{
    if (EVP_EncryptInit_ex(m_ctx, m_cipher, NULL, m_key, m_iv) != ERR_LIB_NONE) {
        throw std::runtime_error("EVP_EncryptInit_ex");
    }

    int textLen = std::strlen((char*)text);
    int cipherTextLen = (textLen / 16 + 1) * 16;
    unsigned char* cipherText = new unsigned char[cipherTextLen];

    std::pair<unsigned char*, int> result;
    result.second = cipherTextLen;

    if (EVP_EncryptUpdate(m_ctx, cipherText, &cipherTextLen, text, textLen) != ERR_LIB_NONE) {
        throw std::runtime_error("EVP_EncryptUpdate");
    }

    if (EVP_EncryptFinal_ex(m_ctx, cipherText + cipherTextLen, &cipherTextLen) != ERR_LIB_NONE) {
        throw std::runtime_error("EVP_EncryptFinal_ex");
    }

    result.first = cipherText;

    return result;
}

std::pair<unsigned char *, int> AES::decrypt(std::pair<unsigned char *, int> encrypted)
{
    if (EVP_DecryptInit_ex(m_ctx, m_cipher, NULL, m_key, m_iv) != ERR_LIB_NONE) {
        throw std::runtime_error("EVP_DecryptInit_ex");
    }

    std::pair<unsigned char *, int> result;
    result.first = new unsigned char[encrypted.second];

    int outlen;

    if (EVP_DecryptUpdate(m_ctx, result.first, &outlen, encrypted.first, encrypted.second) != ERR_LIB_NONE) {
        throw std::runtime_error("EVP_DecryptUpdate");
    }

    result.second = outlen;

    if (EVP_DecryptFinal_ex(m_ctx, result.first + outlen, &outlen) != ERR_LIB_NONE) {
        throw std::runtime_error("EVP_DecryptFinal_ex");
    }

    result.second += outlen;

    return result;
}

AES::~AES()
{
    EVP_CIPHER_CTX_free(m_ctx);
}
