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
            class AcceptWebSocket final : public ppp::net::asio::templates::WebSocket<websocket::AsioWebSocket> {
            public:
                AcceptWebSocket(const std::shared_ptr<websocket>& reference, websocket::AsioWebSocket& websocket, bool binary, const ppp::string& host, const ppp::string& path) noexcept;
            
            public:
                virtual void                                        Dispose() noexcept override;
                virtual void                                        SetAddressString(const ppp::string& address) noexcept override;
                virtual void                                        Decorator(boost::beast::websocket::request_type& req) noexcept override;
                virtual void                                        Decorator(boost::beast::websocket::response_type& res) noexcept override ;;

            private:
                std::shared_ptr<websocket>                          reference_;
            };
        }
    }
}