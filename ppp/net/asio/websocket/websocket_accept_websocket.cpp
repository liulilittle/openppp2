#include <ppp/net/asio/websocket.h>
#include <ppp/net/asio/templates/SslSocket.h>
#include <ppp/net/asio/templates/WebSocket.h>
#include <ppp/net/asio/websocket/websocket_accept_websocket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>

namespace ppp {
    namespace net {
        namespace asio {
            typedef websocket::AsioWebSocket AsioWebSocket;
            
            AcceptWebSocket::AcceptWebSocket(const std::shared_ptr<websocket>& reference, AsioWebSocket& websocket, bool binary, const ppp::string& host, const ppp::string& path) noexcept
                : WebSocket(websocket, binary, host, path)
                , reference_(reference) {

            }

            void AcceptWebSocket::Dispose() noexcept {
                std::shared_ptr<websocket> reference = std::move(reference_);
                reference_.reset();
                
                if (reference) {
                    reference->Dispose();
                }
            }

            void AcceptWebSocket::SetAddressString(const ppp::string& address) noexcept {
                std::shared_ptr<websocket> reference = reference_;
                if (reference) {
                    reference->XForwardedFor = address;
                }
            }

            void AcceptWebSocket::Decorator(boost::beast::websocket::request_type& req) noexcept {
                bool ok = reference_->Decorator(req);
                if (!ok) {
                    WebSocket::Decorator(req);
                }
            }

            void AcceptWebSocket::Decorator(boost::beast::websocket::response_type& res) noexcept {
                bool ok = reference_->Decorator(res);
                if (!ok) {
                    WebSocket::Decorator(res);
                }
            }

            websocket::websocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, bool binary) noexcept
                : disposed_(false)
                , binary_(binary)
                , context_(context)
                , strand_(strand)
                , websocket_(std::move(*socket)) {
                boost::system::error_code ec;
                remoteEP_ = IPEndPoint::ToEndPoint(websocket_.next_layer().remote_endpoint(ec));
            }
        }
    }
}