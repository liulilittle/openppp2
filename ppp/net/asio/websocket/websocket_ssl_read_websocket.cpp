#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/threading/Executors.h>

#include <boost/asio/ssl/error.hpp>

/**
 * @file websocket_ssl_read_websocket.cpp
 * @brief Implements synchronous-style read operation wrappers for SSL WebSocket sessions.
 */

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Reads a fixed number of bytes from the SSL WebSocket stream.
             * @param buffer Destination buffer that receives incoming bytes.
             * @param offset Zero-based byte offset into @p buffer where writing starts.
             * @param length Number of bytes to read.
             * @param y Coroutine yield context used to suspend and resume the operation.
             * @return true if read succeeds; otherwise false.
             */
            bool sslwebsocket::Read(const void* buffer, int offset, int length, YieldContext& y) noexcept {
                if (NULLPTR == buffer || offset < 0 || length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SslWebSocketReadInvalidArguments);
                    return false;
                }

                if (IsDisposed()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
                    return false;
                }

                const std::shared_ptr<SslvWebSocket> ssl_websocket = ssl_websocket_;
                if (NULLPTR == ssl_websocket || !ssl_websocket->is_open()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
                    return false;
                }

                ppp::threading::Executors::ContextPtr context = context_;
                ppp::threading::Executors::StrandPtr strand = strand_;

                bool read_ok = false;
                boost::system::error_code read_ec;

                const YieldContext::Anchor anchor = y.Arm();
                if (!anchor) {
                    return false;
                }

                bool ok = ppp::threading::Executors::Post(context, strand,
                    [ssl_websocket, buffer, offset, length, anchor, &read_ok, &read_ec]() noexcept {
                        boost::asio::async_read(*ssl_websocket, boost::asio::buffer((Byte*)buffer + offset, length),
                            [anchor, length, &read_ok, &read_ec](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                read_ec = ec;
                                read_ok = boost::system::errc::success == ec && static_cast<std::size_t>(length) == sz;
                                anchor.R();
                            });
                    });

                if (false == ok) {
                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
                    }
                    return false;
                }

                y.Suspend(anchor);
                if (true == read_ok) {
                    return true;
                }

                if (boost::asio::error::operation_aborted == read_ec ||
                    boost::asio::error::eof == read_ec ||
                    boost::beast::websocket::error::closed == read_ec ||
                    boost::asio::ssl::error::stream_truncated == read_ec)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketClosed);
                    return false;
                }

                if (boost::asio::error::timed_out == read_ec) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketTimeout);
                }
                elif (boost::asio::error::connection_reset == read_ec ||
                      boost::asio::error::connection_aborted == read_ec ||
                      boost::asio::error::not_connected == read_ec ||
                      boost::asio::error::broken_pipe == read_ec ||
                      boost::asio::error::shut_down == read_ec)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
                }
                elif (boost::asio::error::invalid_argument == read_ec ||
                      boost::asio::error::message_size == read_ec)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                }
                elif (boost::beast::websocket::make_error_code(boost::beast::websocket::error::closed).category() == read_ec.category()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketReadFailed);
                }
                elif (boost::asio::error::get_ssl_category() == read_ec.category()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                }

                return false;
            }
        }
    }
}
