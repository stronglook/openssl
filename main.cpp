#include <QCoreApplication>
#include "rsa_key.h"


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    RSAKey key(2048);
    qDebug() << key.getPublicKey().c_str();
    qDebug() << key.getPrivateKey().c_str();

    return a.exec();
}
