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
                if (NULL == ssl_websocket || !ssl_websocket->is_open()) {
                    return false;
                }

                return ppp::coroutines::asio::async_read(*ssl_websocket, boost::asio::buffer((Byte*)buffer + offset, length), y);
            }
        }
    }
}