#pragma once

#include <stdexcept>
#include <string>
#include <openssl/ssl.h>
#include <winsock2.h>


class TLSConnection
{
public:
    TLSConnection(SOCKET sock, SSL* ssl);
    int write(char* data, int datalen);
    int read(char* buf, int buflen);
    SOCKET getSocket();
    ~TLSConnection();

private:
    SOCKET m_sock;
    SSL* m_ssl;
};
