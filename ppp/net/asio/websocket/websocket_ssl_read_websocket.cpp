#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>

namespace ppp {
    namespace net {
        namespace asio {
            bool sslwebsocket::Read(const void* buffer, int offset, int length, YieldContext& y) noexcept {
                if (NULL == buffer || offset < 0 || length < 1) {
                    return false;
                }

                if (IsDisposed()) {
                    return false;
                }

                const std::shared_ptr<SslvWebSocket> ssl_websocket = ssl_websocket_;
                if (NULL == ssl_websocket) {
                    return false;
                }

                return ppp::coroutines::asio::async_read_post(*ssl_websocket, boost::asio::buffer((char*)buffer + offset, length), y);
            }
        }
    }
}