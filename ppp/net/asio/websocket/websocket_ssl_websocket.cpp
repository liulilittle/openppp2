#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/ssl/TlsSessionExporter.h>

/**
 * @file websocket_ssl_websocket.cpp
 * @brief Implements core lifecycle and handshake setup for SSL WebSocket sessions.
 */

// Split into multiple source files so that the compiler "-mlong-calls" command optional 
// Does not apply to resolve the "gcc: relocation truncated to fit." problem.
namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Initializes an SSL WebSocket wrapper around an accepted or connected TCP socket.
             * @param context I/O context that drives asynchronous execution.
             * @param strand Strand used to serialize callbacks for this connection.
             * @param socket Native TCP socket owned by this session.
             * @param binary true to enable binary websocket mode; false for text mode.
             */
            sslwebsocket::sslwebsocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, bool binary) noexcept
                : disposed_(false)
                , binary_(binary)
                , context_(context)
                , strand_(strand)
                , socket_native_(socket) {
                boost::system::error_code ec;
                remoteEP_ = IPEndPoint::ToEndPoint(socket->remote_endpoint(ec));
            }

            /**
             * @brief Determines whether the SSL WebSocket session can no longer be used.
             * @return true when disposed or when any required socket layer is closed; otherwise false.
             */
            bool sslwebsocket::IsDisposed() noexcept {
                if (disposed_) {
                    return true;
                }

                const std::shared_ptr<SslvWebSocket> ssl_websocket = ssl_websocket_;
                if (NULLPTR == ssl_websocket) {
                    return true;
                }

                if (!ssl_websocket->is_open()) {
                    return true;
                }

                auto& ssl_socket = ssl_websocket->next_layer();
                auto& socket = ssl_socket.next_layer();
                if (!socket.is_open()) {
                    return true;
                }

                return false;
            }

            bool sslwebsocket::HasSessionExporter() noexcept {
                std::lock_guard<std::mutex> lock(exporter_mutex_);
                return !disposed_ && tls_handshake_complete_.load(std::memory_order_acquire);
            }

            bool sslwebsocket::ExportSessionKey(
                const char* label,
                const std::uint8_t* context,
                std::size_t context_length,
                std::uint8_t* output,
                std::size_t output_length) noexcept {
                std::lock_guard<std::mutex> lock(exporter_mutex_);
                if (disposed_ || !tls_handshake_complete_.load(std::memory_order_acquire) ||
                    !strand_ || !strand_->running_in_this_thread() || !ssl_websocket_) {
                    return false;
                }

                return ppp::ssl::ExportTlsSessionKey(
                    ssl_websocket_->next_layer().native_handle(),
                    label,
                    context,
                    context_length,
                    output,
                    output_length);
            }

            /**
             * @brief Gets the currently stored local endpoint.
             * @return Local IP endpoint associated with this session.
             */
            sslwebsocket::IPEndPoint sslwebsocket::GetLocalEndPoint() noexcept {
                return localEP_;
            }

            /**
             * @brief Gets the currently stored remote endpoint.
             * @return Remote IP endpoint associated with this session.
             */
            sslwebsocket::IPEndPoint sslwebsocket::GetRemoteEndPoint() noexcept {
                return remoteEP_;
            }

            /**
             * @brief Updates the stored local endpoint.
             * @param value New local endpoint value.
             * @return This function does not return a value.
             */
            void sslwebsocket::SetLocalEndPoint(const IPEndPoint& value) noexcept {
                localEP_ = value;
            }

            /**
             * @brief Updates the stored remote endpoint.
             * @param value New remote endpoint value.
             * @return This function does not return a value.
             */
            void sslwebsocket::SetRemoteEndPoint(const IPEndPoint& value) noexcept {
                remoteEP_ = value;
            }

            /**
             * @brief Builds and runs the SSL/WebSocket handshake flow for this session.
             * @param type Handshake role that selects client or server behavior.
             * @param host Hostname used by websocket handshake and optional TLS verification.
             * @param path Request path used during websocket upgrade.
             * @param verify_peer true to enable peer certificate verification.
             * @param certificate_file Optional certificate file path.
             * @param certificate_key_file Optional private key file path.
             * @param certificate_chain_file Optional certificate chain file path.
             * @param certificate_key_password Password for encrypted key material.
             * @param ciphersuites TLS cipher suites string; defaults when empty.
             * @param y Coroutine yield context for asynchronous handshake execution.
             * @return true if handshake flow starts and completes successfully; otherwise false.
             */
            bool sslwebsocket::Run(
                HandshakeType                                                       type,
                const ppp::string&                                                  host,
                const ppp::string&                                                  path,
                bool                                                                verify_peer,
                std::string                                                         certificate_file,
                std::string                                                         certificate_key_file,
                std::string                                                         certificate_chain_file,
                std::string                                                         certificate_key_password,
                std::string                                                         ciphersuites,
                YieldContext&                                                       y) noexcept {
                if (host.empty() || path.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SslWebSocketRunInvalidHostOrPath);
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_native_;
                if (NULLPTR == socket) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                if (ciphersuites.empty()) {
                    ciphersuites = GetDefaultCipherSuites();
                }

                bool binary = binary_;
                std::shared_ptr<AsyncSslvWebSocket> accept = make_shared_object<AsyncSslvWebSocket>(
                    shared_from_this(),
                    socket,
                    ssl_context_,
                    ssl_websocket_,
                    verify_peer,
                    binary,
                    host,
                    path,
                    certificate_file,
                    certificate_key_file,
                    certificate_chain_file,
                    certificate_key_password,
                    ciphersuites);

                /**
                 * @brief The handshake helper encapsulates TLS and websocket upgrade sequencing.
                 */
                if (NULLPTR == accept) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                bool ok = accept->Run(type == HandshakeType::HandshakeType_Client, y);
                if (!ok && ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketHandshakeFailed);
                }
                {
                    std::lock_guard<std::mutex> lock(exporter_mutex_);
                    tls_handshake_complete_.store(ok && !disposed_, std::memory_order_release);
                }
                return ok;
            }
        }
    }
}
