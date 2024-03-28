#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>

namespace ppp {
    namespace net {
        namespace asio {
            static bool sslwebsocket_async_shutdown(const std::shared_ptr<sslwebsocket>& ws, const std::shared_ptr<sslwebsocket::SslvWebSocket>& websocket) noexcept {
                if (NULL == ws || NULL == websocket) {
                    return false;
                }
                
                sslwebsocket::SslvTcpSocket* ssl_socket = addressof(websocket->next_layer());
                if (NULL == ssl_socket) {
                    return false;
                }

                ssl_socket->async_shutdown(
                    [ws, ssl_socket](const boost::system::error_code& ec_) noexcept {
                        Socket::Closesocket(ssl_socket->next_layer());
                    });
                return true;
            }

            static bool sslwebsocket_async_close(const std::shared_ptr<sslwebsocket>& ws, const std::shared_ptr<sslwebsocket::SslvWebSocket>& websocket) noexcept {
                if (NULL == ws || NULL == websocket) {
                    return false;
                }

                websocket->async_close(boost::beast::websocket::close_code::normal,
                    [ws, websocket](const boost::system::error_code& ec_) noexcept {
                        sslwebsocket_async_close(ws, websocket);
                    });
                return true;
            }

            void sslwebsocket::Dispose() noexcept {
                auto self = shared_from_this();
                context_->post(
                    [self, this]() noexcept {
                        exchangeof(disposed_, true); 
                        sslwebsocket_async_close(self, ssl_websocket_);
                    });
            }
        }
    }
}