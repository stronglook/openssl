#include "tls_connection.h"

TLSConnection::TLSConnection(SOCKET sock, SSL* ssl)
    : m_sock(sock), m_ssl(ssl)
{

}

int TLSConnection::write(char *data, int datalen)
{
    int result = SSL_write(m_ssl, data, datalen);
    if (result > 0) {
        return result;
    }

    throw std::runtime_error("SSL_write error");
}

int TLSConnection::read(char *buf, int buflen)
{
    int result = SSL_read(m_ssl, buf, buflen);
    if (result > 0) {
        return result;
    }

    throw std::runtime_error("SSL_read error " + std::to_string(result));
}

SOCKET TLSConnection::getSocket()
{
    return m_sock;
}

TLSConnection::~TLSConnection()
{
    SSL_free(m_ssl);
    closesocket(m_sock);
}
