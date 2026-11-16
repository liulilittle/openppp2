/**
 * @file websocket_close_websocket.cpp
 * @brief Implements WebSocket close and scheduler migration helpers.
 */

#include <ppp/net/asio/websocket.h>
#include <ppp/net/asio/templates/SslSocket.h>
#include <ppp/net/asio/templates/WebSocket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>

#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>

namespace ppp {
    namespace net {
        namespace asio {
            void websocket::AbortHandshake() noexcept {
                auto self = shared_from_this();
                ppp::threading::Executors::Post(context_, strand_, [self, this]() noexcept {
                    Socket::Closesocket(websocket_.next_layer());
                });
            }
            /**
             * @brief Asynchronously closes and disposes the WebSocket transport.
             */
            void websocket::Dispose() noexcept {
                auto self = shared_from_this();
                ppp::threading::Executors::ContextPtr context = context_;
                ppp::threading::Executors::StrandPtr strand = strand_;

                /**
                 * @brief Posts close logic to executor to preserve strand affinity.
                 */
                ppp::threading::Executors::Post(context, strand,
                    [self, this, context, strand]() noexcept {
                        disposed_ = true;
                        websocket_.async_close(boost::beast::websocket::close_code::normal,
                            [self, this](const boost::system::error_code& ec_) noexcept {
                                Socket::Closesocket(websocket_.next_layer());
                            });
                    });
            }

            /**
             * @brief Migrates socket execution to the configured scheduler context.
             * @return true when migration succeeds; otherwise false.
             */
            bool websocket::ShiftToScheduler() noexcept {
                std::shared_ptr<boost::asio::ip::tcp::socket> socket_new;
                ppp::threading::Executors::ContextPtr scheduler;
                ppp::threading::Executors::StrandPtr strand;

                auto& socket = websocket_.next_layer();
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
