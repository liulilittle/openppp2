#pragma once

#include <ppp/stdafx.h>
#include <ppp/ssl/SSL.h>
#include <ppp/IDisposable.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace net {
        namespace asio {
            namespace templates {
                template <class T>
                class SslSocket : public IDisposable {
                public:
                    typedef ppp::coroutines::YieldContext               YieldContext;

                public:
                    SslSocket(
                        std::shared_ptr<boost::asio::ip::tcp::socket>&  tcp_socket,
                        std::shared_ptr<boost::asio::ssl::context>&     ssl_context,
                        T&                                              ssl_socket,
                        bool                                            verify_peer,
                        const ppp::string&                              host,
                        const std::string&                              certificate_file,
                        const std::string&                              certificate_key_file,
                        const std::string&                              certificate_chain_file,
                        const std::string&                              certificate_key_password,
                        const std::string&                              ciphersuites) noexcept 
                        : tcp_socket_(tcp_socket)
                        , ssl_context_(ssl_context)
                        , ssl_socket_(ssl_socket)
                        , verify_peer_(verify_peer)
                        , host_(host) 
                        , certificate_file_(certificate_file)
                        , certificate_key_file_(certificate_key_file)
                        , certificate_chain_file_(certificate_chain_file)
                        , certificate_key_password_(certificate_key_password)
                        , ciphersuites_(ciphersuites) {
                        
                    }
                    virtual ~SslSocket() noexcept = default;

                public:
                    bool                                                Run(bool handshaked_client, YieldContext& y) noexcept {
                        typedef typename stl::remove_pointer<T>::type SslSocket; /* decltype(*ssl_socket_); */

                        if (ssl_context_) {
                            return false;
                        }

                        std::shared_ptr<boost::asio::ip::tcp::socket>& tcpSocket = tcp_socket_;
                        if (!tcpSocket) {
                            return false;
                        }

                        if (!tcpSocket->is_open()) {
                            return false;
                        }

                        if (handshaked_client) {
                            ssl_context_ = ppp::ssl::SSL::CreateClientSslContext(ppp::ssl::SSL::SSL_METHOD::tlsv13, verify_peer_, ciphersuites_);
                        }
                        elif(certificate_file_.empty() || certificate_key_file_.empty() || certificate_chain_file_.empty()) {
                            return false;
                        }
                        else {
                            ssl_context_ = ppp::ssl::SSL::CreateServerSslContext(ppp::ssl::SSL::SSL_METHOD::tlsv13, certificate_file_, certificate_key_file_, certificate_chain_file_, certificate_key_password_, ciphersuites_);
                        }

                        boost::system::error_code ec;
                        if (!ssl_context_) {
                            return false;
                        }

                        ssl_socket_ = make_shared_object<SslSocket>(std::move(*tcpSocket), *ssl_context_);
                        if (!ssl_socket_) {
                            return false;
                        }

                        // Set SNI Hostname(many hosts need this to handshake successfully).
                        if (host_.size() > 0) {
                            if (!SSL_set_tlsext_host_name(GetSslHandle(), host_.data())) {
                                return false; /* throw boost::system::system_error{ { static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category() } }; */
                            }
                        }

                        return PerformSslHandshake(handshaked_client, y);
                    }

                protected:
                    T&                                                  GetSslSocket() noexcept { return ssl_socket_; }
                    virtual SSL*                                        GetSslHandle() noexcept = 0;
                    virtual bool                                        PerformSslHandshake(bool handshaked_client, YieldContext& y) noexcept = 0;

                public:
                    std::shared_ptr<boost::asio::ip::tcp::socket>&      tcp_socket_;
                    std::shared_ptr<boost::asio::ssl::context>&         ssl_context_;
                    T&                                                  ssl_socket_;
                    bool                                                verify_peer_ = false;
                    ppp::string                                         host_;
                    std::string                                         certificate_file_;
                    std::string                                         certificate_key_file_;
                    std::string                                         certificate_chain_file_;
                    std::string                                         certificate_key_password_;
                    std::string                                         ciphersuites_;
                };
            }
        }
    }
}