#pragma once

#include <stdexcept>
#include <string>
#include <atomic>

#include <QObject>

#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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
    void accepted(void* ssl);
    void error(std::string error);
};
