#include <ppp/net/http/HttpHeaderReader.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/net/native/ip.h>

namespace ppp {
    namespace net {
        namespace http {
            bool ReadHttpHeaders(ppp::io::MemoryStream& headers, ppp::coroutines::YieldContext& y, boost::asio::ip::tcp::socket& socket) noexcept {
                if (!socket.is_open()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                }

                char buffers[ppp::net::native::ip_hdr::MTU];
                for (;;) {
                    int bytes_transferred = ppp::coroutines::asio::async_read_some(socket, boost::asio::buffer(buffers, sizeof(buffers)), y);
                    if (bytes_transferred < 1) {
                        if (0 >= headers.GetPosition()) {
                            return false;
                        }

                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketReadFailed);
                    }

                    if (!headers.Write(buffers, 0, bytes_transferred)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    std::shared_ptr<Byte> headers_ptr = headers.GetBuffer();
                    if (NULLPTR == headers_ptr) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryBufferNull);
                    }

                    // Detect end-of-headers marker in the growing buffer.
                    int next[4];
                    int index = FindIndexOf(next, (char*)headers_ptr.get(), headers.GetPosition(), (char*)("\r\n\r\n"), 4);
                    if (index > -1) {
                        return true;
                    }
                }
            }

            bool SplitHttpHeaderLines(ppp::io::MemoryStream& headers, ppp::vector<ppp::string>& lines, ppp::string* raw) noexcept {
                std::shared_ptr<Byte> protocol = headers.GetBuffer();
                if (NULLPTR == protocol) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryBufferNull);
                }

                int protocol_size = headers.GetPosition();
                if (protocol_size < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::HttpHeaderInvalid);
                }

                if (NULLPTR != raw) {
                    *raw = ppp::string((char*)protocol.get(), protocol_size);
                    return Tokenize<ppp::string>(*raw, lines, "\r\n") > 0;
                }
                else {
                    return Tokenize<ppp::string>(ppp::string((char*)protocol.get(), protocol_size), lines, "\r\n") > 0;
                }
            }
        }
    }
}
