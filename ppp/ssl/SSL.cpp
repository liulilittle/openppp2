#include <ppp/ssl/root_certificates.hpp>
#include <ppp/ssl/SSL.h>
#include <ppp/io/File.h>

namespace ppp {
    namespace ssl {
        boost::asio::ssl::context::method SSL::SSL_S_METHOD(int method) noexcept {
            switch (method) {
            case SSL_METHOD::tlsv13:
                return boost::asio::ssl::context::tlsv13_server;
            case SSL_METHOD::tlsv12:
                return boost::asio::ssl::context::tlsv12_server;
            case SSL_METHOD::tlsv11:
                return boost::asio::ssl::context::tlsv11_server;
            case SSL_METHOD::tls:
                return boost::asio::ssl::context::tls_server;
            case SSL_METHOD::sslv23:
                return boost::asio::ssl::context::sslv23_server;
            case SSL_METHOD::sslv3:
                return boost::asio::ssl::context::sslv3_server;
            case SSL_METHOD::sslv2:
                return boost::asio::ssl::context::sslv2_server;
            default:
                return boost::asio::ssl::context::tlsv12_server;
            };
        }

        boost::asio::ssl::context::method SSL::SSL_C_METHOD(int method) noexcept {
            switch (method) {
            case SSL_METHOD::tlsv13:
                return boost::asio::ssl::context::tlsv13_client;
            case SSL_METHOD::tlsv12:
                return boost::asio::ssl::context::tlsv12_client;
            case SSL_METHOD::tlsv11:
                return boost::asio::ssl::context::tlsv11_client;
            case SSL_METHOD::tls:
                return boost::asio::ssl::context::tls_client;
            case SSL_METHOD::sslv23:
                return boost::asio::ssl::context::sslv23_client;
            case SSL_METHOD::sslv3:
                return boost::asio::ssl::context::sslv3_client;
            case SSL_METHOD::sslv2:
                return boost::asio::ssl::context::sslv2_client;
            default:
                return boost::asio::ssl::context::tlsv12_client;
            };
        }

        bool SSL::VerifySslCertificate(
            const std::string& certificate_file,
            const std::string& certificate_key_file,
            const std::string& certificate_chain_file) noexcept {

            typedef ppp::io::File                       File;
            typedef ppp::io::FileAccess                 FileAccess;

            if (certificate_file.empty() ||
                certificate_key_file.empty() ||
                certificate_chain_file.empty()) {
                return false;
            }

            if (!File::CanAccess(certificate_file.data(), FileAccess::Read) ||
                !File::CanAccess(certificate_key_file.data(), FileAccess::Read) ||
                !File::CanAccess(certificate_chain_file.data(), FileAccess::Read)) {
                return false;
            }

            std::shared_ptr<boost::asio::ssl::context> ssl_context = make_shared_object<boost::asio::ssl::context>(
                ppp::ssl::SSL::SSL_S_METHOD(ppp::ssl::SSL::SSL_METHOD::ssl));
            if (!ssl_context) {
                return false;
            }

            boost::system::error_code ec;
            /*ssl_context_->set_options(boost::asio::ssl::context::default_workarounds |
                boost::asio::ssl::context::no_sslv2 |
                boost::asio::ssl::context::no_sslv3 |
                boost::asio::ssl::context::single_dh_use);*/
            ssl_context->use_certificate_chain_file(certificate_chain_file, ec);
            if (ec) {
                return false;
            }

            ssl_context->use_certificate_file(certificate_file, boost::asio::ssl::context::file_format::pem, ec);
            if (ec) {
                return false;
            }

            ssl_context->use_private_key_file(certificate_key_file, boost::asio::ssl::context::file_format::pem, ec);
            return ec ? false : true;
        }

        std::shared_ptr<boost::asio::ssl::context> SSL::CreateServerSslContext(
            int method,
            const std::string& certificate_file,
            const std::string& certificate_key_file,
            const std::string& certificate_chain_file,
            const std::string& certificate_key_password,
            const std::string& ciphersuites) noexcept {

            std::shared_ptr<boost::asio::ssl::context> ssl_context = make_shared_object<boost::asio::ssl::context>(
                ppp::ssl::SSL::SSL_S_METHOD(method));
            if (!ssl_context) {
                return NULL;
            }

            boost::system::error_code ec;
            /*ssl_context_->set_options(boost::asio::ssl::context::default_workarounds |
                boost::asio::ssl::context::no_sslv2 |
                boost::asio::ssl::context::no_sslv3 |
                boost::asio::ssl::context::single_dh_use);*/
            ssl_context->use_certificate_chain_file(certificate_chain_file, ec);
            ssl_context->use_certificate_file(certificate_file, boost::asio::ssl::context::file_format::pem, ec);
            ssl_context->use_private_key_file(certificate_key_file, boost::asio::ssl::context::file_format::pem, ec);

            // This function is used to specify a callback function to obtain password information about an encrypted key in PEM format.
            std::string certificate_key_password_ = certificate_key_password;
            ssl_context->set_password_callback([certificate_key_password_](
                std::size_t max_length, // The maximum size for a password.
                boost::asio::ssl::context_base::password_purpose purpose) noexcept -> std::string { // Whether password is for reading or writing.
                    return certificate_key_password_;
                }, ec);

            // This holds the root certificate used for verification.
            ssl_context->set_default_verify_paths();

            SSL_CTX_set_cipher_list(ssl_context->native_handle(), "DEFAULT");
            if (ciphersuites.size()) {
                // TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
                // TLS_AES_128_GCM_SHA256
                // TLS_AES_256_GCM_SHA384
                // TLS_CHACHA20_POLY1305_SHA256
                // TLS_AES_128_CCM_SHA256
                // TLS_AES_128_CCM_8_SHA256
                SSL_CTX_set_ciphersuites(ssl_context->native_handle(), ciphersuites.data());
            }
            SSL_CTX_set_ecdh_auto(ssl_context->native_handle(), 1);
            return ssl_context;
        }

        std::shared_ptr<boost::asio::ssl::context> SSL::CreateClientSslContext(
            int method, 
            bool verify_peer, 
            const std::string& ciphersuites) noexcept {

            std::shared_ptr<boost::asio::ssl::context> ssl_context = make_shared_object<boost::asio::ssl::context>(
                ppp::ssl::SSL::SSL_C_METHOD(ppp::ssl::SSL::SSL_METHOD::tlsv13));
            if (!ssl_context) {
                return NULL;
            }

            // This holds the root certificate used for verification.
            load_root_certificates(*ssl_context);

            // This holds the root certificate used for verification.
            ssl_context->set_default_verify_paths();
            ssl_context->set_verify_mode(verify_peer ? boost::asio::ssl::verify_peer : boost::asio::ssl::verify_none);

            SSL_CTX_set_cipher_list(ssl_context->native_handle(), "DEFAULT");
            if (ciphersuites.size()) {
                // TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
                // TLS_AES_128_GCM_SHA256
                // TLS_AES_256_GCM_SHA384
                // TLS_CHACHA20_POLY1305_SHA256
                // TLS_AES_128_CCM_SHA256
                // TLS_AES_128_CCM_8_SHA256
                SSL_CTX_set_ciphersuites(ssl_context->native_handle(), ciphersuites.data());
            }
            SSL_CTX_set_ecdh_auto(ssl_context->native_handle(), 1);
            return ssl_context;
        }

        const char* SSL::GetSslCiphersuites() noexcept {
#if !(defined(__aarch64__) || defined(_M_ARM64))
            if (strstr(GetPlatformCode(), "ARM")) {
                return "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
            }
#endif
            return "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
        }
    }
}