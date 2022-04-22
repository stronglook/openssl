#include <QCoreApplication>
#include "rsa_key.h"
#include "pkey.h"

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
        qDebug() << (char)decrypted[i];
    }

    return a.exec();
}
