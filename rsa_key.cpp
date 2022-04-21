#include "rsa_key.h"

RSAKey::RSAKey(unsigned int keyBits)
{
    generateRSAKey(keyBits);
}

EVP_PKEY* RSAKey::generateRSAKey(unsigned int keyBits)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (ctx == NULL) {
        throw std::runtime_error("EVP_PKEY_CTX_new_id");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_free(m_pkey);
        throw std::runtime_error("EVP_PKEY_keygen_init");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keyBits) <= 0) {
        EVP_PKEY_free(m_pkey);
        throw std::runtime_error("EVP_PKEY_CTX_set_rsa_keygen_bits");
    }

    if (EVP_PKEY_keygen(ctx, &m_pkey) <= 0) {
        EVP_PKEY_free(m_pkey);
        throw std::runtime_error("EVP_PKEY_keygen");
    }

    EVP_PKEY_CTX_free(ctx);

    return m_pkey;
}

std::string RSAKey::getPublicKey()
{

    BIO* out = BIO_new(BIO_s_mem());
    if (out == NULL) {
        throw std::runtime_error("BIO_new");
    }

    if (PEM_write_bio_PUBKEY(out, m_pkey) == NULL) {
        throw std::runtime_error("PEM_write_bio_PUBKEY");
    }

    return BIOToString(out);
}

std::string RSAKey::getPrivateKey()
{
    BIO* out = BIO_new(BIO_s_mem());

    if (out == NULL) {
        throw std::runtime_error("BIO_new");
    }

    if (PEM_write_bio_PrivateKey(out, m_pkey, NULL, NULL, 0, 0, NULL) == NULL) {
        throw std::runtime_error("PEM_write_bio_PrivateKey");
    }

    return BIOToString(out);
}

EVP_PKEY *RSAKey::getPKey()
{
    return m_pkey;
}

std::string RSAKey::BIOToString(BIO* bio)
{
    char *buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    if (len <= 0) {
        throw std::runtime_error("BIO_get_mem_data");
    }

    std::string result(buf, len);

    return result;
}

RSAKey::~RSAKey()
{
    if (m_pkey) {
        EVP_PKEY_free(m_pkey);
    }
}
