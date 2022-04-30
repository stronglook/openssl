#include "tls_server.h"
#include <QDebug>

TLSServer::TLSServer()
{
    WSADATA wsaData;
    WORD wVersionRequested = MAKEWORD(2, 2);
    if (WSAStartup(wVersionRequested, &wsaData) != 0) {
        throw std::runtime_error("WSAStartup error");
    }
}

void TLSServer::start(int port, const std::string &certPath, const std::string &pKeyPath)
{
    SSL_CTX* ctx = createContext();
    configure(ctx, certPath, pKeyPath);

    createSocket(port);

    m_isRunning = true;
    while (m_isRunning)
    {
        struct sockaddr_in addr;
        int len = sizeof(addr);

        SOCKET client = accept(m_socket, (struct sockaddr*)&addr, &len);
        if (client == INVALID_SOCKET) {
            emit error("Unable to accept");
            continue;
        }

        SSL* ssl = SSL_new(ctx);
        if (!ssl) {
            emit error("SSL_new error");
            continue;
        }

        if (SSL_set_fd(ssl, client) != 1) {
            emit error("SSL_set_fd error");
            continue;
        }

        if ((SSL_accept(ssl)) != 1) {
            emit error("SSL_accept error");
            continue;
        } else {
            qDebug() << "There...";
        }

        emit accepted(std::make_shared<TLSConnection>(client, ssl));
    }
}

void TLSServer::stop()
{
    m_isRunning = false;
}

TLSServer::~TLSServer()
{
    closesocket(m_socket);
    WSACleanup();
}

void TLSServer::createSocket(int port)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    m_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (m_socket == INVALID_SOCKET) {
        throw std::runtime_error("Unable to create socket");
    }

    if (bind(m_socket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        throw std::runtime_error("Unable to bind");
    }

    if (listen(m_socket, 1) == SOCKET_ERROR) {
        throw std::runtime_error("Unable to listen");
    }
}

SSL_CTX* TLSServer::createContext()
{
    const SSL_METHOD* method = TLS_server_method();

    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        throw std::runtime_error("Unable to create SSL context");
    }

    return ctx;
}

void TLSServer::configure(SSL_CTX *ctx, const std::string &certPath, const std::string &pKeyPath)
{
    if (SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        throw std::runtime_error("Certificate file error");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, pKeyPath.c_str(), SSL_FILETYPE_PEM) <= 0 ) {
        throw std::runtime_error("Private key file error");
    }
}
