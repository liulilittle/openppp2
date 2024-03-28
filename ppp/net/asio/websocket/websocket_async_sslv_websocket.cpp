#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>

namespace ppp {
    namespace net {
        namespace asio {
            typedef sslwebsocket::SslvTcpSocket                             SslvTcpSocket;
            typedef sslwebsocket::SslvWebSocket                             SslvWebSocket;
            typedef std::shared_ptr<SslvWebSocket>                          SslvWebSocketPtr;

            AsyncSslvWebSocket::AsyncSslvWebSocket(
                const std::shared_ptr<sslwebsocket>&                        reference,
                std::shared_ptr<boost::asio::ip::tcp::socket>&              tcp_socket,
                std::shared_ptr<boost::asio::ssl::context>&                 ssl_context,
                SslvWebSocketPtr&                                           ssl_websocket,
                bool                                                        verify_peer,
                bool                                                        binary,
                const ppp::string&                                          host,
                const ppp::string&                                          path,
                const std::string&                                          certificate_file,
                const std::string&                                          certificate_key_file,
                const std::string&                                          certificate_chain_file,
                const std::string&                                          certificate_key_password,
                const std::string&                                          ciphersuites) noexcept
                : SslSocket(tcp_socket, ssl_context, ssl_websocket, verify_peer, host, certificate_file, certificate_key_file, certificate_chain_file, certificate_key_password, ciphersuites)
                , path_(path)
                , reference_(reference)
                , binary_(binary) {

            }

            void AsyncSslvWebSocket::Dispose() noexcept {
                std::shared_ptr<sslwebsocket> reference = std::move(reference_);
                if (reference) {
                    reference_.reset();
                    reference->Dispose();
                }
            }

            SSL* AsyncSslvWebSocket::GetSslHandle() noexcept {
                SslvWebSocketPtr& ssl_websocket = GetSslSocket();
                if (NULL == ssl_websocket) {
                    return NULL;
                }

                SslvTcpSocket& ssl_socket = ssl_websocket->next_layer();
                return ssl_socket.native_handle();
            }
        };
    }
}