#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>

// Split into multiple source files so that the compiler "-mlong-calls" command optional 
// Does not apply to resolve the "gcc: relocation truncated to fit." problem.
namespace ppp {
    namespace net {
        namespace asio {
            sslwebsocket::sslwebsocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, bool binary) noexcept
                : disposed_(false)
                , binary_(binary)
                , context_(context)
                , strand_(strand)
                , socket_native_(socket) {
                boost::system::error_code ec;
                remoteEP_ = IPEndPoint::ToEndPoint(socket->remote_endpoint(ec));
            }

            bool sslwebsocket::IsDisposed() noexcept {
                if (disposed_) {
                    return true;
                }

                const std::shared_ptr<SslvWebSocket> ssl_websocket = ssl_websocket_;
                if (NULL == ssl_websocket) {
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

            sslwebsocket::IPEndPoint sslwebsocket::GetLocalEndPoint() noexcept {
                return localEP_;
            }

            sslwebsocket::IPEndPoint sslwebsocket::GetRemoteEndPoint() noexcept {
                return remoteEP_;
            }

            void sslwebsocket::SetLocalEndPoint(const IPEndPoint& value) noexcept {
                localEP_ = value;
            }

            void sslwebsocket::SetRemoteEndPoint(const IPEndPoint& value) noexcept {
                remoteEP_ = value;
            }

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
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_native_;
                if (NULL == socket) {
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

                if (NULL == accept) {
                    return false;
                }
                
                return accept->Run(type == HandshakeType::HandshakeType_Client, y);
            }
        }
    }
}