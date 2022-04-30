#include <QCoreApplication>
#include "tls_server.h"
#include "rsa_key.h"
#include "pkey.h"
#include "aes.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    RSAKey key(2048);
    //qDebug() << key.getPublicKey().c_str();
    //qDebug() << key.getPrivateKey().c_str();

    PKey pkey(key.getPKey());
    unsigned char data[] = "hello";

    auto dataPair = pkey.decrypt(pkey.encrypt(data));
    std::size_t len = dataPair.second;
    unsigned char* decrypted = dataPair.first;

    for (std::size_t i = 0; i < len; i++)
    {
        //qDebug() << (char)decrypted[i];
    }

    EVP_aes_256_cbc();

    unsigned char aesKey[] = "01234567890123456789012345678901";
    unsigned char iv[] = "0123456789012349";
    AES aes(EVP_aes_256_cbc(), aesKey, iv);
    auto aesEncryptResult = aes.encrypt(data);
    //qDebug() << aesResult.second;

    auto aesDecryptResult = aes.decrypt(aesEncryptResult);
    for (int i = 0; i < aesDecryptResult.second; i++)
    {
        qDebug() << (char)aesDecryptResult.first[i];
    }

    // req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout privateKey.key -out certificate.crt

    TLSServer server;
    QObject::connect(&server, &TLSServer::accepted, [](void* ssl)
    {
        qDebug() << "Accepted!!!";
        const char reply[] = "Hello from TLS server!\n";
        SSL_write((SSL*)ssl, reply, strlen(reply));
    });

    QObject::connect(&server, &TLSServer::error, [](std::string e)
    {
        qDebug() << e.c_str();
    });

    server.start(4433, "./debug/cert.crt", "./debug/key.key");

    return a.exec();
}
