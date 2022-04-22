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
    qDebug() << pkey.decrypt(pkey.encrypt(data)).second;

    for (int i = 0; i < pkey.decrypt(pkey.encrypt(data)).second; i++)
    {
        qDebug() << (char)pkey.decrypt(pkey.encrypt(data)).first[i];
    }

    return a.exec();
}
