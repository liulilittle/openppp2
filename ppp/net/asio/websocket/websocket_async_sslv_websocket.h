#pragma once 

#include <ppp/net/asio/websocket.h>
#include <ppp/net/asio/templates/SslSocket.h>
#include <ppp/net/asio/templates/WebSocket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/coroutines/asio/asio.h>

namespace ppp {
    namespace net {
        namespace asio {
            class AsyncSslvWebSocket final : public ppp::net::asio::templates::SslSocket<std::shared_ptr<sslwebsocket::SslvWebSocket>/**/> {
            public:
                AsyncSslvWebSocket(
                    const std::shared_ptr<sslwebsocket>&                        reference,
                    std::shared_ptr<boost::asio::ip::tcp::socket>&              tcp_socket,
                    std::shared_ptr<boost::asio::ssl::context>&                 ssl_context,
                    std::shared_ptr<sslwebsocket::SslvWebSocket>&               ssl_websocket,
                    bool                                                        verify_peer,
                    bool                                                        binary,
                    const ppp::string&                                          host,
                    const ppp::string&                                          path,
                    const std::string&                                          certificate_file,
                    const std::string&                                          certificate_key_file,
                    const std::string&                                          certificate_chain_file,
                    const std::string&                                          certificate_key_password,
                    const std::string&                                          ciphersuites) noexcept;

            public:
                bool                                                            PerformWebSocketHandshake(bool handshaked_client, YieldContext& y) noexcept;
                virtual void                                                    Dispose() noexcept override;
                virtual SSL*                                                    GetSslHandle() noexcept override;
                virtual bool                                                    PerformSslHandshake(bool handshaked_client, YieldContext& y) noexcept override;

            private:
                ppp::string                                                     path_;
                std::shared_ptr<sslwebsocket>                                   reference_;
                bool                                                            binary_;
            };
        }
    }
}