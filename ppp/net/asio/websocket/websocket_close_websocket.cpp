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
            static bool websocket_async_close(std::shared_ptr<websocket> ws, websocket::AsioWebSocket& websocket) noexcept {
                websocket.async_close(boost::beast::websocket::close_code::normal,
                    [ws, &websocket](const boost::system::error_code& ec_) noexcept {
                        Socket::Closesocket(websocket.next_layer());
                    });
                return true;
            }

            void websocket::Dispose() noexcept {
                auto self = shared_from_this();
                context_->post(
                    [self, this]() noexcept {
                        exchangeof(disposed_, true); 
                        websocket_async_close(self, websocket_);
                    });
            }
        }
    }
}