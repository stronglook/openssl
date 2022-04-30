#pragma once

#include <stdexcept>
#include <string>
#include <atomic>
#include <memory>

#include <QObject>

#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "tls_connection.h"

class TLSServer : public QObject
{
    Q_OBJECT
public:
    TLSServer();
    void start(int port, const std::string &certPath, const std::string &pKeyPath);
    void stop();
    ~TLSServer();

private:
    void createSocket(int port);
    SSL_CTX* createContext();
    void configure(SSL_CTX* ctx,  const std::string& certPath, const std::string& pKeyPath);

    std::atomic<bool> m_isRunning;
    SOCKET m_socket;

signals:
    void accepted(std::shared_ptr<TLSConnection> connection);
    void error(std::string error);
};
