/**
 * @file sniproxy.cpp
 * @brief Implementation of SNI proxy.
 */

#include <ppp/net/proxies/sniproxy.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/diagnostics/Error.h>

#ifdef _LINUX
# include <netinet/tcp.h>
#endif

// TCP_FASTOPEN value (Linux 23, Windows 15 but we force 23 for consistency)
#ifndef TCP_FASTOPEN
# define TCP_FASTOPEN 23
#endif

// The following macros are expected to be defined in the precompiled header:
// PPP_HTTP_SYS_PORT  (default 80)
// PPP_HTTPS_SYS_PORT (default 443)
#ifndef PPP_HTTP_SYS_PORT
# define PPP_HTTP_SYS_PORT 80
#endif
#ifndef PPP_HTTPS_SYS_PORT
# define PPP_HTTPS_SYS_PORT 443
#endif

using ppp::net::Socket;
using ppp::threading::Timer;
using ppp::threading::Executors;

namespace ppp {
    namespace net {
        namespace proxies {

            // -----------------------------------------------------------------------------
            // Constructor / Destructor
            // -----------------------------------------------------------------------------

            /**
             * @brief Constructs an SNI/HTTP host based forwarding proxy.
             */
            sniproxy::sniproxy(int                                              cdn,
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<boost::asio::io_context>&                 context,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept
                : cdn_(cdn)
                , configuration_(configuration)
                , context_(context)
                , strand_(context->get_executor())
                , local_socket_(socket)
                , remote_socket_(*context)
                , last_(Executors::GetTickCount()) {
                // Tune client socket
                Socket::AdjustDefaultSocketOptional(*socket, configuration_->tcp.turbo);
                Socket::SetWindowSizeIfNotZero(socket->native_handle(),
                    configuration_->tcp.cwnd,
                    configuration_->tcp.rwnd);
            }

            /**
             * @brief Releases all socket and timer resources.
             */
            sniproxy::~sniproxy() noexcept {
                close();
            }

            // -----------------------------------------------------------------------------
            // Static helpers
            // -----------------------------------------------------------------------------

            /**
             * @brief Checks whether the incoming bytes look like an HTTP request line.
             */
            bool sniproxy::be_http(const void* p) noexcept {
                const char* data = static_cast<const char*>(p);
                if (NULLPTR == data) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SniProxyHttpProbeNullInput);
                    return false;
                }
                
                return (0 == strncasecmp(data, "GET ", 4)) ||
                    (0 == strncasecmp(data, "HEAD ", 5)) ||
                    (0 == strncasecmp(data, "POST ", 5)) ||
                    (0 == strncasecmp(data, "PUT ", 4)) ||
                    (0 == strncasecmp(data, "DELETE ", 7)) ||
                    (0 == strncasecmp(data, "CONNECT ", 8)) ||
                    (0 == strncasecmp(data, "TRACE ", 6)) ||
                    (0 == strncasecmp(data, "PATCH ", 6));
            }

            /**
             * @brief Posts a callback onto the proxy strand.
             */
            bool sniproxy::post(const ppp::function<void()>& callback) noexcept {
                if (NULLPTR == callback) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SniProxyPostNullCallback);
                    return false;
                }

                boost::asio::post(strand_, std::move(callback));
                return true;
            }

            /**
             * @brief Returns whether close/dispose was already executed.
             */
            bool sniproxy::is_disposed() const noexcept {
                return disposed_.load(std::memory_order_acquire);
            }

            /**
             * @brief Performs case-insensitive host/domain match.
             * @return true for exact match or subdomain match.
             */
            bool sniproxy::be_host(ppp::string host, ppp::string domain) noexcept {
                if (host.empty() || domain.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SniProxyHostMatchEmptyInput);
                    return false;
                }

                // Normalize to lower case for case-insensitive comparison
                domain = ToLower(domain);
                host = ToLower(host);
                
                // Exact match
                if (host == domain) {
                    return true;
                }

                // Subdomain match: host must end with ".domain"
                // Example: "sub.example.com" matches "example.com"
                if (host.length() > domain.length()) {
                    // Check if the host ends with '.' + domain
                    size_t offset = host.length() - domain.length();
                    if (host[offset - 1] == '.' && host.compare(offset, domain.length(), domain) == 0) {
                        return true;
                    }
                }
                return false;
            }

            // -----------------------------------------------------------------------------
            // TLS record helpers
            // -----------------------------------------------------------------------------

            /**
             * @brief Reads a 16-bit big-endian unsigned value.
             */
            UInt16 sniproxy::fetch_uint16(Byte*& data) noexcept {
                UInt16 r = (static_cast<UInt16>(data[0]) << 8) | static_cast<UInt16>(data[1]);
                data += 2;
                return r;
            }

            /**
             * @brief Reads a 24-bit big-endian length field.
             */
            int sniproxy::fetch_length(Byte*& data) noexcept {
                int r = (static_cast<int>(data[0]) << 16) |
                    (static_cast<int>(data[1]) << 8) |
                    static_cast<int>(data[2]);
                data += 3;
                return r;
            }

            /**
             * @brief Parses TLS ClientHello extensions and extracts SNI host_name.
             */
            ppp::string sniproxy::fetch_sniaddr(size_t tls_payload) noexcept {
                Byte* data = reinterpret_cast<Byte*>(local_socket_buf_);
                Byte* end = data + tls_payload;

                // Ensure at least one byte for handshake type
                if (data >= end) {
                    return "";
                }

                // Handshake type must be Client Hello (0x01)
                if (0x01 != *data++) {
                    return "";
                }

                // Handshake length (3 bytes)
                if ((data + 3) > end) {
                    return "";
                }

                int handshake_len = fetch_length(data);
                if ((data + handshake_len) > end) {
                    return "";
                }

                // Skip Version (2 bytes)
                if ((data + 2) > end) {
                    return "";
                }
                data += 2;

                // Skip Random (32 bytes)
                if ((data + 32) > end) {
                    return "";
                }
                data += 32;

                // Session ID length and data
                if (data >= end) {
                    return "";
                }

                Byte session_id_len = *data++;
                if ((data + session_id_len) > end) {
                    return "";
                }
                data += session_id_len;

                // Cipher Suites
                if ((data + 2) > end) {
                    return "";
                }

                int cipher_len = fetch_uint16(data);
                if ((data + cipher_len) > end) {
                    return "";
                }
                data += cipher_len;

                // Compression Methods
                if (data >= end) {
                    return "";
                }

                int comp_len = *data++;
                if ((data + comp_len) > end) {
                    return "";
                }
                data += comp_len;

                // Extensions
                if ((data + 2) > end) {
                    return "";
                }

                int extensions_len = fetch_uint16(data);
                if ((data + extensions_len) > end) {
                    return "";
                }

                Byte* extensions_end = data + extensions_len;
                while (data < extensions_end) {
                    // Extension type and length
                    if ((data + 4) > extensions_end) {
                        break;
                    }

                    int ext_type = fetch_uint16(data);
                    int ext_len = fetch_uint16(data);
                    if ((data + ext_len) > extensions_end) {
                        break;
                    }

                    if (0x0000 == ext_type) { // Server Name Indication
                        if ((data + 2) > extensions_end) {
                            break;
                        }

                        int server_list_len = fetch_uint16(data);
                        Byte* list_end = data + server_list_len;
                        if (list_end > extensions_end) {
                            break;
                        }

                        while (data < list_end) {
                            // Name type (0 = host_name)
                            if (data >= list_end) {
                                break;
                            }

                            int name_type = *data++;
                            if (0x00 != name_type) {
                                // Not host_name: skip name length + name data
                                if ((data + 2) > list_end) {
                                    break;
                                }

                                int name_len = fetch_uint16(data);
                                if ((data + name_len) > list_end) {
                                    break;
                                }

                                data += name_len;
                                continue;
                            }

                            // host_name entry
                            if ((data + 2) > list_end) {
                                break;
                            }

                            int name_len = fetch_uint16(data);
                            if ((data + name_len) > list_end) {
                                break;
                            }

                            return ppp::string(reinterpret_cast<char*>(data), 0, name_len);
                        }
                        break; // SNI extension processed
                    }
                    else {
                        // Unknown extension: skip
                        data += ext_len;
                    }
                }
                return "";
            }

            // -----------------------------------------------------------------------------
            // TLS handshake
            // -----------------------------------------------------------------------------

            /**
             * @brief Handles TLS pre-read, SNI extraction, and initial forwarding setup.
             */
            bool sniproxy::do_tlsvd_handshake(ppp::coroutines::YieldContext& y, MemoryStream& messages_) noexcept {
                tls_hdr* hdr = reinterpret_cast<tls_hdr*>(local_socket_buf_);
                if (0x16 != hdr->Content_Type) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return false; // Not a handshake record
                }

                size_t tls_payload = ntohs(hdr->Length);
                if ((0 == tls_payload) || (tls_payload > (FORWARD_MSS - sizeof(tls_hdr)))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return false;
                }

                // Read the TLS payload (Client Hello)
                if (!ppp::coroutines::asio::async_read(*local_socket_,
                    boost::asio::buffer(local_socket_buf_, tls_payload), y)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                    return false;
                }

                // Store the payload for later forwarding
                if (!messages_.Write(local_socket_buf_, 0, static_cast<int>(tls_payload))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SniProxyTlsHandshakeMessageWriteAllocFailed);
                    return false; // Memory allocation failure
                }

                ppp::string hostname = fetch_sniaddr(tls_payload);
                if (hostname.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed, false);
                }

                return do_connect_and_forward_to_host(y, hostname,
                    configuration_->websocket.listen.wss,
                    PPP_HTTPS_SYS_PORT,
                    messages_);
            }

            // -----------------------------------------------------------------------------
            // HTTP handshake
            // -----------------------------------------------------------------------------

            /**
             * @brief Handles HTTP header read, Host extraction, and forwarding setup.
             */
            bool sniproxy::do_httpd_handshake(ppp::coroutines::YieldContext& y, MemoryStream& messages_) noexcept {
                auto response = std::make_shared<boost::asio::streambuf>(16 * 1024);
                if (NULLPTR == response) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SniProxyHttpHandshakeResponseAllocFailed);
                    return false;
                }

                // Copy any already-read data (first 5 bytes) into the streambuf
                int existing = messages_.GetPosition();
                if (existing > 0) {
                    std::ostream os(response.get());
                    os.write(reinterpret_cast<const char*>(messages_.GetBuffer().get()), existing);
                }

                // Read until "\r\n\r\n" (end of HTTP headers)
                boost::system::error_code ec;
                std::size_t length = 0;
                const ppp::coroutines::YieldContext::Anchor anchor = y.Arm();
                if (!anchor) {
                    return false;
                }

                boost::asio::async_read_until(*local_socket_, *response, "\r\n\r\n",
                    [anchor, &ec, &length](const boost::system::error_code& e, std::size_t sz) noexcept {
                        ec = e;
                        length = sz;
                        anchor.R();
                    });
                y.Suspend(anchor);
                
                if (ec || (0 == length)) {
                    if ((boost::asio::error::operation_aborted == ec) || (boost::asio::error::eof == ec)) {
                        return false;
                    }

                    ppp::diagnostics::SetLastErrorCode(ec && ec != boost::asio::error::not_found ? ppp::diagnostics::ErrorCode::SocketReadFailed
                        : ppp::diagnostics::ErrorCode::HttpHeaderInvalid);
                    return false;
                }

                // Store all data read so far (headers + possibly partial body) into messages_
                auto buf = response->data();
                if (NULLPTR == buf.data()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryBufferNull);
                    return false;
                }

                if (!messages_.Write(buf.data(), 0, static_cast<int>(buf.size()))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SniProxyHttpHandshakeMessageWriteAllocFailed);
                    return false; // Memory allocation failure
                }

                int port = 0;
                ppp::string hostname;
                if (!do_httpd_handshake_host_trim(messages_, hostname, port)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpHeaderInvalid);
                    return false;
                }

                return do_connect_and_forward_to_host(y, hostname,
                    do_forward_websocket_port(),
                    port,
                    messages_);
            }

            /**
             * @brief Parses and normalizes HTTP Host header into host and port.
             */
            bool sniproxy::do_httpd_handshake_host_trim(MemoryStream& messages_, ppp::string& host, int& port) noexcept {
                port = PPP_HTTP_SYS_PORT; // default HTTP port
                host = do_httpd_handshake_host(messages_);
                if (host.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpHeaderInvalid);
                    return false;
                }

                host = RTrim(LTrim(host));
                if (host.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpHeaderInvalid);
                    return false;
                }

                // Support IPv6 address format [::1]:8080
                if ('[' == host.front()) {
                    size_t closing = host.find(']');
                    if (ppp::string::npos == closing) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpHeaderInvalid);
                        return false;
                    }

                    if ((closing + 1) < host.size() && (':' == host[closing + 1])) {
                        ppp::string port_str = host.substr(closing + 2);
                        if (!port_str.empty()) {
                            /**
                             * @brief Validate port number using strtol.
                             * @note Port must be in valid range.
                             */
                            char* endptr = NULLPTR;
                            long parsed_port = strtol(port_str.data(), &endptr, 10);
                            if (NULLPTR == endptr || endptr == port_str.data() || *endptr != '\x0') {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                                return false;
                            }

                            port = static_cast<int>(parsed_port);
                            if ((port <= IPEndPoint::MinPort) || (port > IPEndPoint::MaxPort)) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                                return false;
                            }
                        }

                        host = host.substr(1, closing - 1);
                        return true;
                    }

                    host = host.substr(1, closing - 1);
                    return true;
                }

                // IPv4 / domain name
                size_t idx = host.find(':');
                if (ppp::string::npos == idx) {
                    return true; // no port specified
                }

                ppp::string hoststr = host.substr(0, idx);
                ppp::string portstr = host.substr(idx + 1);
                if (hoststr.empty() || portstr.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpHeaderInvalid);
                    return false;
                }

                portstr = RTrim(LTrim(portstr));
                if (portstr.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpHeaderInvalid);
                    return false;
                }

                /**
                 * @brief Validate port number using strtol.
                 * @note Port must be in valid range.
                 */
                char* endptr = NULLPTR;
                long parsed_port = strtol(portstr.data(), &endptr, 10);
                if (NULLPTR == endptr || endptr == portstr.data() || *endptr != '\x0') {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                    return false;
                }
                
                port = static_cast<int>(parsed_port);
                if ((port <= IPEndPoint::MinPort) || (port > IPEndPoint::MaxPort)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                    return false;
                }

                host = std::move(hoststr);
                return true;
            }

            /**
             * @brief Extracts Host from HTTP request line/headers block.
             */
            ppp::string sniproxy::do_httpd_handshake_host(MemoryStream& messages_) noexcept {
                int size = messages_.GetPosition();
                if (size < 4) {
                    return "";
                }

                // Locate the end of headers: "\r\n\r\n"
                const char* data = reinterpret_cast<const char*>(messages_.GetBuffer().get());
                const char* end = data + size;
                const char* headers_end = NULLPTR;
                
                // Find the first occurrence of "\r\n\r\n"
                for (const char* p = data; p + 3 < end; ++p) {
                    if (p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n') {
                        headers_end = p + 4; // point to the start of body (or end)
                        break;
                    }
                }
                
                if (!headers_end) {
                    return ""; // Incomplete headers
                }
                
                // Extract only the headers part (up to headers_end)
                size_t headers_len = headers_end - data;
                ppp::string headers_data(data, headers_len);
                
                // Split headers by CRLF
                ppp::vector<ppp::string> headers;
                if (Tokenize<ppp::string>(headers_data, headers, "\r\n") < 1) {
                    return "";
                }

                // Parse request line: method url protocol
                ppp::vector<ppp::string> protocols;
                if (Tokenize<ppp::string>(headers[0], protocols, " ") < 3) {
                    return "";
                }

                ppp::string protocol = ToUpper(protocols[2]);
                if ((protocol != "HTTP/1.0") && (protocol != "HTTP/1.1") && (protocol != "HTTP/2.0")) {
                    return "";
                }

                const ppp::string& url = protocols[1];
                if (url.empty()) {
                    return "";
                }

                // Absolute URL? e.g., http://example.com/path
                if ('/' != url[0]) {
                    ppp::string lower_url = ToLower(url);
                    size_t left = lower_url.find("://");
                    if (ppp::string::npos != left) {
                        left += 3;

                        size_t next = lower_url.find("/", left);
                        if ((ppp::string::npos != next) && (next > left)) {
                            return url.substr(left, next - left);
                        }
                    }
                }

                // Look for Host header among headers (skip request line)
                for (size_t i = 1, header_count = headers.size(); i < header_count; ++i) {
                    const ppp::string& header = headers[i];
                    size_t colon = header.find(": ");
                    if ((ppp::string::npos == colon) || (0 == colon)) {
                        continue;
                    }

                    ppp::string key = ToUpper(header.substr(0, colon));
                    if ("HOST" == key) {
                        return header.substr(colon + 2);
                    }
                }
                
                return "";
            }

            // -----------------------------------------------------------------------------
            // Connection and forwarding
            // -----------------------------------------------------------------------------

            /**
             * @brief Resolves target, connects remote socket, and starts bidirectional relay.
             */
            bool sniproxy::do_connect_and_forward_to_host(
                ppp::coroutines::YieldContext&          y,
                const ppp::string                       hostname_,
                int                                     self_websocket_port,
                int                                     forward_connect_port,
                MemoryStream&                           messages_) noexcept {

                if (hostname_.empty() ||
                    (forward_connect_port <= IPEndPoint::MinPort) ||
                    (forward_connect_port > IPEndPoint::MaxPort)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SniProxyConnectForwardInvalidArguments);
                    return false;
                }

                boost::system::error_code ec;
                boost::asio::ip::address addr;
                boost::asio::ip::tcp::endpoint remote_ep;

                // Check if target is our own WebSocket endpoint (loopback)
                if (be_host(configuration_->websocket.host, hostname_)) {
                    if ((self_websocket_port <= IPEndPoint::MinPort) || (self_websocket_port > IPEndPoint::MaxPort)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                        return false;
                    }

                    // Choose loopback address family based on local socket
                    boost::system::error_code ignore_ec;
                    if (local_socket_->local_endpoint(ignore_ec).address().is_v6()) {
                        addr = boost::asio::ip::address_v6::loopback();
                    }
                    else {
                        addr = boost::asio::ip::address_v4::loopback();
                    }

                    remote_ep = boost::asio::ip::tcp::endpoint(addr, self_websocket_port);
                }
                else {
                    // Resolve hostname to IP
                    addr = StringToAddress(hostname_.data(), ec);
                    if (ec) {
                        addr = ppp::coroutines::asio::GetAddressByHostName<boost::asio::ip::tcp>(
                            hostname_.data(), IPEndPoint::MinPort, y).address();
                    }

                    if (IPEndPoint::IsInvalid(addr) || addr.is_loopback()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                        return false;
                    }

                    // Avoid CDN loop: if target port matches CDN port and IP equals public/interface IP
                    if ((configuration_->cdn[0] == forward_connect_port) || (configuration_->cdn[1] == forward_connect_port)) {
                        boost::system::error_code ignore;
                        boost::asio::ip::address iface = StringToAddress(configuration_->ip.interface_.data(), ignore);
                        boost::asio::ip::address pub = StringToAddress(configuration_->ip.public_.data(), ignore);
                        if ((addr == pub) || (addr == iface)) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SniProxyConnectForwardCdnLoopConflict);
                            return false;
                        }
                    }

                    remote_ep = boost::asio::ip::tcp::endpoint(addr, forward_connect_port);
                }

                // Open remote socket with appropriate protocol family
                if (addr.is_v4()) {
                    remote_socket_.open(boost::asio::ip::tcp::v4(), ec);
                }
                elif (addr.is_v6()) {
                    remote_socket_.open(boost::asio::ip::tcp::v6(), ec);
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressFamilyMismatch);
                    return false;
                }
                if (ec) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                    return false;
                }

                // Set socket options
                remote_socket_.set_option(boost::asio::ip::tcp::no_delay(configuration_->tcp.turbo), ec);

                if (configuration_->tcp.fast_open) {
                    int enable = 1;
                    if (0 != setsockopt(remote_socket_.native_handle(), IPPROTO_TCP, TCP_FASTOPEN, (char*)&enable, sizeof(enable))) {
                        // Non-critical, ignore error
                        remote_socket_.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec);
                    }
                }

                int handle = remote_socket_.native_handle();
                Socket::AdjustDefaultSocketOptional(handle, remote_ep.protocol() == boost::asio::ip::tcp::v4());
                Socket::SetTypeOfService(handle);
                Socket::SetSignalPipeline(handle, false);
                Socket::ReuseSocketAddress(handle, true);
                Socket::SetWindowSizeIfNotZero(handle, configuration_->tcp.cwnd, configuration_->tcp.rwnd);

                // Connect to remote (async_connect returns false on success)
                if (ppp::coroutines::asio::async_connect(remote_socket_, remote_ep, y)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketConnectFailed);
                    return false;
                }

                // Forward already-read handshake data (TLS Client Hello or HTTP headers)
                std::shared_ptr<Byte> buf = messages_.GetBuffer();
                if (NULLPTR == buf) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryBufferNull);
                    return false;
                }

                if (!ppp::coroutines::asio::async_write(remote_socket_,
                    boost::asio::buffer(buf.get(), messages_.GetPosition()), y)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                    return false;
                }

                // Handshake succeeded: cancel handshake timeout and start inactivity timer
                clear_timeout();
                reset_inactivity_timer();

                // Start bidirectional forwarding
                if (!local_to_remote()) {
                    close();
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
                    return false;
                }

                if (!remote_to_local()) {
                    close();
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
                    return false;
                }

                return true;
            }

            /**
             * @brief Returns configured plaintext WebSocket listen port.
             */
            int sniproxy::do_forward_websocket_port() const noexcept {
                return configuration_->websocket.listen.ws;
            }

            // -----------------------------------------------------------------------------
            // Timeout management
            // -----------------------------------------------------------------------------

            /**
             * @brief Disposes one-shot handshake timeout timer.
             */
            void sniproxy::clear_timeout() noexcept {
                if (timeout_) {
                    timeout_->Dispose();
                    timeout_.reset();
                }
            }

            /**
             * @brief Rearms inactivity timer according to TCP settings.
             */
            void sniproxy::reset_inactivity_timer() noexcept {
                cancel_inactivity_timer();

                uint64_t timeout_sec = configuration_->tcp.inactive.timeout;
                if (0 == timeout_sec) {
                    return; // disabled
                }

                auto self = shared_from_this();
                inactivity_timer_ = Timer::Timeout(context_, (int)(timeout_sec * 1000),
                    [this, self](Timer*) noexcept {
                        post([this, self]() noexcept {
                            close();
                        });
                    });
            }

            /**
             * @brief Cancels inactivity timeout timer if present.
             */
            void sniproxy::cancel_inactivity_timer() noexcept {
                if (inactivity_timer_) {
                    inactivity_timer_->Dispose();
                    inactivity_timer_.reset();
                }
            }

            // -----------------------------------------------------------------------------
            // Data forwarding (bidirectional)
            // -----------------------------------------------------------------------------

            /**
             * @brief Starts asynchronous forwarding loop from client to upstream.
             */
            bool sniproxy::local_to_remote() noexcept {
                if (is_disposed() || !socket_is_open()) {
                    ppp::diagnostics::SetLastErrorCode(is_disposed() ? ppp::diagnostics::ErrorCode::SessionDisposed
                        : ppp::diagnostics::ErrorCode::SocketDisconnected);
                    return false;
                }

                auto self = shared_from_this();
                local_socket_->async_read_some(boost::asio::buffer(local_socket_buf_, FORWARD_MSS),
                    boost::asio::bind_executor(strand_,
                    [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
                        if (is_disposed()) {
                            return;
                        }

                        int by = (ec || (0 == sz)) ? -1 : static_cast<int>(sz);
                        if (by < 1) {
                            close();
                            return;
                        }

                        last_ = Executors::GetTickCount(); // update activity timestamp
                        reset_inactivity_timer();          // reset timer on read activity

                        boost::asio::async_write(remote_socket_, boost::asio::buffer(local_socket_buf_, by),
                            boost::asio::bind_executor(strand_,
                            [self, this](const boost::system::error_code& ec, uint32_t) noexcept {
                                if (is_disposed()) {
                                    return;
                                }

                                if (ec) {
                                    close();
                                    return;
                                }

                                last_ = Executors::GetTickCount(); // update on write success
                                reset_inactivity_timer();          // reset timer on write activity
                                local_to_remote();                 // continue reading
                            }));
                    }));
                return true;
            }

            /**
             * @brief Starts asynchronous forwarding loop from upstream to client.
             */
            bool sniproxy::remote_to_local() noexcept {
                if (is_disposed() || !socket_is_open()) {
                    ppp::diagnostics::SetLastErrorCode(is_disposed() ? ppp::diagnostics::ErrorCode::SessionDisposed
                        : ppp::diagnostics::ErrorCode::SocketDisconnected);
                    return false;
                }

                auto self = shared_from_this();
                remote_socket_.async_read_some(boost::asio::buffer(remote_socket_buf_, FORWARD_MSS),
                    boost::asio::bind_executor(strand_,
                    [self, this](const boost::system::error_code& ec, uint32_t sz) noexcept {
                        if (is_disposed()) {
                            return;
                        }

                        int by = (ec || (0 == sz)) ? -1 : static_cast<int>(sz);
                        if (by < 1) {
                            close();
                            return;
                        }

                        last_ = Executors::GetTickCount(); // update activity timestamp
                        reset_inactivity_timer();          // reset timer on read activity

                        // close() resets local_socket_ while this composed write may still be in
                        // flight; the completion must keep the socket alive until write_op finishes.
                        std::shared_ptr<boost::asio::ip::tcp::socket> local_socket = local_socket_;
                        boost::asio::async_write(*local_socket, boost::asio::buffer(remote_socket_buf_, by),
                            boost::asio::bind_executor(strand_,
                            [self, this, local_socket](const boost::system::error_code& ec, uint32_t) noexcept {
                                if (is_disposed()) {
                                    return;
                                }

                                if (ec) {
                                    close();
                                    return;
                                }

                                last_ = Executors::GetTickCount(); // update on write success
                                reset_inactivity_timer();          // reset timer on write activity
                                remote_to_local();                 // continue reading
                            }));
                    }));
                return true;
            }

            /**
             * @brief Returns whether both relay endpoints are currently open.
             */
            bool sniproxy::socket_is_open() const noexcept {
                return local_socket_ && local_socket_->is_open() && remote_socket_.is_open();
            }

            /**
             * @brief Idempotently closes sockets and cancels all timers.
             */
            void sniproxy::close() noexcept {
                bool expected = false;
                if (!disposed_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                    return;
                }

                // All callers are strand-serialized; the atomic CAS on disposed_
                // is the sole re-entrancy guard.  The previous std::mutex caused a
                // Pattern-A deadlock: clear_timeout() / cancel_inactivity_timer()
                // call Timer::Dispose() (which posts onto the io_context) while the
                // mutex was held.  Fix: capture timer handles locally, clear members,
                // then Dispose() AFTER releasing all shared state.
                std::shared_ptr<Timer> timeout_snap    = std::move(timeout_);
                std::shared_ptr<Timer> inactivity_snap = std::move(inactivity_timer_);

                if (local_socket_) {
                    Socket::Closesocket(*local_socket_);
                    local_socket_.reset();
                }

                Socket::Closesocket(remote_socket_);
                last_ = Executors::GetTickCount();

                // Dispose timers after releasing member state; Dispose() posts onto
                // the io_context and must not be called while holding a mutex.
                if (NULLPTR != timeout_snap) {
                    timeout_snap->Dispose();
                }

                if (NULLPTR != inactivity_snap) {
                    inactivity_snap->Dispose();
                }
            }

            // -----------------------------------------------------------------------------
            // Handshake entry point
            // -----------------------------------------------------------------------------

            /**
             * @brief Probes protocol and dispatches TLS or HTTP handshake path.
             */
            bool sniproxy::do_handshake(ppp::coroutines::YieldContext& y) noexcept {
                const int hdr_sz = sizeof(tls_hdr); // 5 bytes
                if (!ppp::coroutines::asio::async_read(*local_socket_,
                    boost::asio::buffer(local_socket_buf_, hdr_sz), y)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                    return false;
                }

                MemoryStream ms;
                if (!ms.Write(local_socket_buf_, 0, hdr_sz)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SniProxyHandshakePrefetchWriteAllocFailed);
                    return false;
                }

                tls_hdr* hdr = reinterpret_cast<tls_hdr*>(local_socket_buf_);
                if (0x16 == hdr->Content_Type) {
                    if (do_tlsvd_handshake(y, ms)) {
                        return true;
                    }

                    // TLS handshake failed – do not fall through to HTTP because we already consumed 5 bytes.
                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                    }
                    return false;
                }

                static constexpr int http_probe_sz = 8;
                if (!ppp::coroutines::asio::async_read(*local_socket_,
                    boost::asio::buffer(local_socket_buf_ + hdr_sz, http_probe_sz - hdr_sz), y)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                    return false;
                }

                if (!ms.Write(local_socket_buf_ + hdr_sz, 0, http_probe_sz - hdr_sz)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SniProxyHandshakeHttpProbeWriteAllocFailed);
                    return false;
                }

                if (!be_http(local_socket_buf_)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpRequestFailed);
                    return false;
                }

                return do_httpd_handshake(y, ms);
            }

            /**
             * @brief Starts handshake coroutine and guard timeout timer.
             */
            bool sniproxy::handshake() noexcept {
                if ((NULLPTR == local_socket_) || (NULLPTR == context_)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::InternalLogicNullPointer);
                    return false;
                }

                auto self = shared_from_this();
                timeout_ = Timer::Timeout(context_, (int)(static_cast<uint64_t>(configuration_->tcp.connect.timeout) * 1000),
                    [this, self](Timer*) noexcept {
                        post([this, self]() noexcept {
                            close();
                        });
                    });
                if (NULLPTR == timeout_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                    return false;
                }

                auto ctx = context_;
                bool spawned = ppp::coroutines::YieldContext::Spawn(NULLPTR, *ctx, &strand_,
                    [this, self](ppp::coroutines::YieldContext& y) noexcept {
                        bool ok = do_handshake(y);
                        if (!ok) {
                            close();
                        }
                    });

                if (!spawned) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineSpawnFailed);
                    return false;
                }

                return true;
            }

        } // namespace proxies
    } // namespace net
} // namespace ppp
