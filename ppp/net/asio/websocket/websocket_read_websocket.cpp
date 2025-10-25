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
            bool websocket::Read(const void* buffer, int offset, int length, YieldContext& y) noexcept {
                if (NULL == buffer || offset < 0 || length < 1) {
                    return false;
                }

                if (IsDisposed() || !websocket_.is_open()) {
                    return false;
                }

                return ppp::coroutines::asio::async_read(websocket_, boost::asio::buffer((Byte*)buffer + offset, length), y);
            }
        }
    }
}