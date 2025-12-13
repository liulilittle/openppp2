#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>

namespace ppp {
    namespace net {
        namespace asio {
            void sslwebsocket::Dispose() noexcept {
                auto self = shared_from_this();
                ppp::threading::Executors::ContextPtr context = context_;
                ppp::threading::Executors::StrandPtr strand = strand_;

                ppp::threading::Executors::Post(context, strand,
                    [self, this, context, strand]() noexcept {
                        std::shared_ptr<SslvWebSocket> ssl_websocket = std::move(ssl_websocket_);
                        disposed_ = true;
                        ssl_websocket_.reset();

                        if (NULL == ssl_websocket) {
                            return false;
                        }

                        ssl_websocket->async_close(boost::beast::websocket::close_code::normal,
                            [self, this, ssl_websocket](const boost::system::error_code& ec_) noexcept {
                                sslwebsocket::SslvTcpSocket& ssl_socket = ssl_websocket->next_layer();
                                ssl_socket.async_shutdown(
                                    [self, this, ssl_websocket, &ssl_socket](const boost::system::error_code& ec_) noexcept {
                                        Socket::Closesocket(ssl_socket.next_layer());
                                    });
                                return true;
                            });
                        return true;
                    });
            }

            bool sslwebsocket::ShiftToScheduler() noexcept {
                std::shared_ptr<SslvWebSocket> ssl_websocket = ssl_websocket_;
                if (NULL == ssl_websocket) {
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket_new;
                ppp::threading::Executors::ContextPtr scheduler;
                ppp::threading::Executors::StrandPtr strand;

                auto& socket = ssl_websocket->next_layer().next_layer();
                bool ok = ppp::threading::Executors::ShiftToScheduler(socket, socket_new, scheduler, strand);
                if (ok) {
                    socket = std::move(*socket_new);
                    strand_ = strand;
                    context_ = scheduler;
                }

                return ok;
            }
        }
    }
}