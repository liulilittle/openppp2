#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>

namespace ppp {
    namespace net {
        namespace asio {
            typedef sslwebsocket::SslvTcpSocket                             SslvTcpSocket;
            typedef sslwebsocket::SslvWebSocket                             SslvWebSocket;
            typedef std::shared_ptr<SslvWebSocket>                          SslvWebSocketPtr;
            
            bool AsyncSslvWebSocket::PerformWebSocketHandshake(bool handshaked_client, YieldContext& y) noexcept {
                SslvWebSocketPtr& ssl_websocket = GetSslSocket();
                if (NULL == ssl_websocket) {
                    return false;
                }

                std::shared_ptr<AcceptSslvWebSocket> accept = make_shared_object<AcceptSslvWebSocket>(reference_, *ssl_websocket, binary_, host_, path_);
                if (NULL == accept) {
                    return false;
                }

                return accept->Run(handshaked_client, y);
            }
        }
    }
}