#pragma once

#include <winsock2.h>
#include <stdexcept>
#include <string>
#include <memory>

#include <openssl/ssl.h>
#include <QObject>
#include <QDebug>

#include "tls_connection.h"

class TLSClient
{
public:
    TLSClient();
    TLSConnection connect(const char* ip, unsigned short port, const std::string& host);
    void setMinProtoVersion(int version);
    void loadVerifyLocation(const std::string& certPath);

#ifdef WIN32
    void addWindowsRootCerts();
#endif

    ~TLSClient();

private:
    SSL_CTX* m_ctx;

    void createContext();
    void displayCert(SSL *ssl);
    void verifyCert(SSL *ssl, const std::string& host);
};
