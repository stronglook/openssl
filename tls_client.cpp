#include "tls_client.h"

TLSClient::TLSClient()
{
    WSADATA wsaData;

    WORD wVersionRequested = MAKEWORD(2, 2);
    if (WSAStartup(wVersionRequested, &wsaData) != 0) {
        throw std::runtime_error("WSAStartup error");
    }

    createContext();
}

TLSConnection TLSClient::connect(const char *ip, unsigned short port, const std::string& host)
{
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        throw std::runtime_error("Socket create error");
    }

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(ip);
    servaddr.sin_port = htons(port);

    if (::connect(sock , (struct sockaddr *)&servaddr , sizeof(servaddr)) == SOCKET_ERROR) {
        throw std::runtime_error("Connection error");
    }

    SSL* ssl = SSL_new(m_ctx);
    if (!ssl) {
        throw std::runtime_error("SSL_new error");
    }

    if (SSL_set_tlsext_host_name(ssl, host.c_str()) != 1) {
        throw std::runtime_error("SSL_set_tlsext_host_name error");
    }

    if (SSL_set_fd(ssl, sock) != 1) {
        throw std::runtime_error("SSL_set_fd error");
    }

    int status = SSL_connect(ssl);
    if (status != 1) {
        throw std::runtime_error("SSL_connect error");
    }

#ifdef QT_DEBUG
    displayCert(ssl);
#endif

    verifyCert(ssl, host);

    return TLSConnection(sock, ssl);
}

void TLSClient::setMinProtoVersion(int version)
{
    switch (version)
    {
        case TLS1_2_VERSION:
            break;
        default:
            throw std::runtime_error("Incorrect protocol version");
    }

    if (SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION) != 1) {
        throw std::runtime_error("SSL_CTX_set_min_proto_version error");
    }
}

void TLSClient::loadVerifyLocation(const std::string &certPath)
{
    if (SSL_CTX_load_verify_locations(m_ctx, certPath.c_str(), nullptr) != 1) {
        throw std::runtime_error("verify location loading error");
    }
}

#ifdef WIN32

void TLSClient::addWindowsRootCerts()
{
    HCERTSTORE hStore = CertOpenSystemStore(0, L"ROOT");
    if (hStore == NULL) {
        throw std::runtime_error("CertOpenSystemStore error");
    }

    X509_STORE *store = X509_STORE_new();
    PCCERT_CONTEXT pContext = NULL;
    while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL) {
        X509 *x509 = d2i_X509(NULL,
                              (const unsigned char **)&pContext->pbCertEncoded,
                              pContext->cbCertEncoded);
        if(x509 != NULL) {
            X509_STORE_add_cert(store, x509);
            X509_free(x509);
        }
    }

    CertFreeCertificateContext(pContext);
    CertCloseStore(hStore, 0);

    SSL_CTX_set_cert_store(m_ctx, store);
}

#endif

TLSClient::~TLSClient()
{
    SSL_CTX_free(m_ctx);
    WSACleanup();
}

void TLSClient::createContext()
{
    const SSL_METHOD *method = TLS_client_method();
    if (!method) {
        throw std::runtime_error("TLS_client_method error");
    }

    m_ctx = SSL_CTX_new(method);
    if (!m_ctx) {
        throw std::runtime_error("SSL_CTX_new error");
    }
}

void TLSClient::displayCert(SSL *ssl)
{

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        qDebug() << "Server certificates:\n";
        qDebug() << "Subject: " << X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        qDebug() << "Issuer: " << X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

        X509_free(cert);
    } else {
        qDebug() << "SSL_get_peer_certificate error";
    }
}

void TLSClient::verifyCert(SSL *ssl, const std::string &expected_hostname)
{
    int err = SSL_get_verify_result(ssl);
    if (err != X509_V_OK) {
        const char *message = X509_verify_cert_error_string(err);
        throw std::runtime_error("Certificate verification error:" + std::string(message));
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        throw std::runtime_error("No certificate was presented by the server");
    }

    if (X509_check_host(cert, expected_hostname.data(), expected_hostname.size(), 0, nullptr) != 1) {
        throw std::runtime_error("Certificate verification error: Incorrect hostname");
    }
}
