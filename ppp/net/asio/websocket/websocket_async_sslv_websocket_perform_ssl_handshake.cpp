#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>

namespace ppp {
    namespace net {
        namespace asio {
            typedef sslwebsocket::SslvTcpSocket                             SslvTcpSocket;
            typedef sslwebsocket::SslvWebSocket                             SslvWebSocket;
            typedef std::shared_ptr<SslvWebSocket>                          SslvWebSocketPtr;
            
#if defined(_WIN32)
#pragma optimize("", off)
#pragma optimize("gsyb2", on) /* /O1 = /Og /Os /Oy /Ob2 /GF /Gy */
#else
// TRANSMISSIONO1 compiler macros are defined to perform O1 optimizations, 
// Otherwise gcc compiler version If <= 7.5.X, 
// The O1 optimization will also be applied, 
// And the other cases will not be optimized, 
// Because this will cause the program to crash, 
// Which is a fatal BUG caused by the gcc compiler optimization. 
// Higher-version compilers should not optimize the code for gcc compiling this section.
#if defined(__clang__)
#pragma clang optimize off
#else
#pragma GCC push_options
#if defined(TRANSMISSION_O1) || (__GNUC__ < 7) || (__GNUC__ == 7 && __GNUC_MINOR__ <= 5) /* __GNUC_PATCHLEVEL__ */
#pragma GCC optimize("O1")
#else
#pragma GCC optimize("O0")
#endif
#endif
#endif
            bool AsyncSslvWebSocket::PerformSslHandshake(bool handshaked_client, YieldContext& y) noexcept {
                // Perform the SSL handshake.
                const std::shared_ptr<Reference> reference = GetReference();
                const SslvWebSocketPtr& ssl_websocket = GetSslSocket();
                if (NULL == ssl_websocket) {
                    return false;
                }

                bool ok = false;
                auto& ssl_socket = ssl_websocket->next_layer();
                ssl_socket.async_handshake(handshaked_client ? boost::asio::ssl::stream_base::client : boost::asio::ssl::stream_base::server,
                    [reference, this, handshaked_client, &ok, &y](const boost::system::error_code& ec) noexcept {
                        ok = ec == boost::system::errc::success;
                        y.R();
                    });

                y.Suspend();
                if (!ok) {
                    return false;
                }

                return PerformWebSocketHandshake(handshaked_client, y);
            }
#if defined(_WIN32)
#pragma optimize("", on)
#else
#if defined(__clang__)
#pragma clang optimize on
#else
#pragma GCC pop_options
#endif
#endif
        }
    }
}