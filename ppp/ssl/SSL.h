#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace ssl {
        class SSL final {
        public:
            typedef enum {
                tlsv13,
                tlsv12,
                tlsv11,
                tls,
                sslv23,
                sslv3,
                sslv2,
                ssl,
            } SSL_METHOD;
            static boost::asio::ssl::context::method                        SSL_C_METHOD(int method) noexcept;
            static boost::asio::ssl::context::method                        SSL_S_METHOD(int method) noexcept;

        public:
            static bool                                                     VerifySslCertificate(
                const std::string&                                          certificate_file,
                const std::string&                                          certificate_key_file,
                const std::string&                                          certificate_chain_file) noexcept;
            static const char*                                              GetSslCiphersuites() noexcept;

        public:
            static std::shared_ptr<boost::asio::ssl::context>               CreateServerSslContext(
                int                                                         method,
                const std::string&                                          certificate_file,
                const std::string&                                          certificate_key_file,
                const std::string&                                          certificate_chain_file,
                const std::string&                                          certificate_key_password,
                const std::string&                                          ciphersuites) noexcept;
            static std::shared_ptr<boost::asio::ssl::context>               CreateClientSslContext(
                int                                                         method,
                bool                                                        verify_peer,
                const std::string&                                          ciphersuites) noexcept;
        };
    }
}