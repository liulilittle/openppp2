#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>

namespace ppp {
    namespace net {
        namespace asio {
            typedef sslwebsocket::SslvWebSocket                                 SslvWebSocket;
            typedef std::shared_ptr<SslvWebSocket>                              SslvWebSocketPtr;

            AcceptSslvWebSocket::AcceptSslvWebSocket(const std::shared_ptr<sslwebsocket>& reference, SslvWebSocket& websocket, bool binary, ppp::string& host, ppp::string& path) noexcept
                : WebSocket(websocket, binary, host, path)
                , reference_(reference) {

            }

            void AcceptSslvWebSocket::Dispose() noexcept {
                std::shared_ptr<sslwebsocket> reference = std::move(reference_);
                if (reference) {
                    reference_.reset();
                    reference->Dispose();
                }
            }

            void AcceptSslvWebSocket::SetAddressString(const ppp::string& address) noexcept {
                std::shared_ptr<sslwebsocket> reference = reference_;
                if (reference) {
                    reference->XForwardedFor = address;
                }
            }

            void AcceptSslvWebSocket::Decorator(boost::beast::websocket::request_type& req) noexcept {
                bool ok = reference_->Decorator(req);
                if (!ok) {
                    WebSocket::Decorator(req);
                }
            }

            void AcceptSslvWebSocket::Decorator(boost::beast::websocket::response_type& res) noexcept {
                bool ok = reference_->Decorator(res);
                if (!ok) {
                    WebSocket::Decorator(res);
                }
            }
        }
    }
}