#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetHttpProxyConnection.h>
#include <ppp/diagnostics/Error.h>

#include <ppp/IDisposable.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/net/http/HttpHeaderReader.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

/**
 * @file VEthernetHttpProxyConnection.cpp
 * @brief HTTP proxy connection parsing, handshake, and forwarding logic.
 * @author("OPENPPP2 Team")
 * @license("GPL-3.0")
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                /**
                 * @brief Holds immutable/shared static data for HTTP parsing.
                 */
                class VEthernetHttpProxyConnectionStaticVariable final {
                public:
                    typedef ppp::unordered_set<ppp::string>                         StringSet;
                    typedef ppp::unordered_map<ppp::string, ppp::string>            StringMap;

                public: 
                    std::size_t                                                     protocolMethodMaxBytes;
                    StringSet                                                       protocolMethods;
                    StringMap                                                       proxyHeaderToAgentHeader;

                public:
                    /**
                     * @brief Initializes supported methods and header remapping tables.
                     * @param None.
                     * @return None.
                     * @note Also precomputes the maximum method name length.
                     */
                    VEthernetHttpProxyConnectionStaticVariable() noexcept {
                        protocolMethods.emplace("CONNECT");
                        protocolMethods.emplace("DELETE");
                        protocolMethods.emplace("GET");
                        protocolMethods.emplace("HEAD");
                        protocolMethods.emplace("OPTIONS");
                        protocolMethods.emplace("PATCH");
                        protocolMethods.emplace("POST");
                        protocolMethods.emplace("PUT");
                        protocolMethods.emplace("TRACE");

                        proxyHeaderToAgentHeader["PROXY-CONNECTION"] = "";
                        proxyHeaderToAgentHeader["PROXY-AUTHORIZATION"] = "";

                        protocolMethodMaxBytes = 0;
                        for (auto& protocolMethod : protocolMethods) {
                            std::size_t protocolMethodSize = protocolMethod.size();
                            if (protocolMethodSize > protocolMethodMaxBytes) {
                                protocolMethodMaxBytes = protocolMethodSize;
                            }
                        }
                    }

                public:
                    /**
                     * @brief Checks whether a method token is supported.
                     * @param s HTTP method token in uppercase.
                     * @return True if method is supported; otherwise false.
                     * @note Empty method tokens are always rejected.
                     */
                    bool                                                            IsSupportMethodKey(const ppp::string& s) noexcept {
                        if (s.empty()) {
                            return false;
                        }

                        StringSet::iterator tail = protocolMethods.find(s);
                        StringSet::iterator endl = protocolMethods.end();
                        return tail != endl;
                    }
                };

                static std::shared_ptr<VEthernetHttpProxyConnectionStaticVariable>  gStaticVariable = NULLPTR;

                /**
                 * @brief Initializes static variables for HTTP proxy connections.
                 * @param None.
                 * @return None.
                 * @note Called during static initialization flow.
                 */
                void VEthernetHttpProxyConnection_cctor() noexcept {
                    gStaticVariable = ppp::make_shared_object<VEthernetHttpProxyConnectionStaticVariable>();
                }

                /**
                 * @brief Constructs an HTTP proxy connection.
                 * @param proxy Owning HTTP proxy switcher.
                 * @param exchanger Virtual ethernet exchanger.
                 * @param context Asio I/O context.
                 * @param strand Serialized executor strand.
                 * @param socket Accepted client socket.
                 * @return None.
                 * @note All parameters are forwarded to the base class.
                 */
                VEthernetHttpProxyConnection::VEthernetHttpProxyConnection(
                    const VEthernetHttpProxySwitcherPtr&                    proxy, 
                    const VEthernetExchangerPtr&                            exchanger, 
                    const std::shared_ptr<boost::asio::io_context>&         context, 
                    const ppp::threading::Executors::StrandPtr&             strand, 
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket) noexcept
                    : VEthernetLocalProxyConnection(proxy, exchanger, context, strand, socket) {
                    
                }

                /**
                 * @brief Converts buffered HTTP bytes into header lines.
                 * @param ms Source memory stream.
                 * @param headers Output header line vector.
                 * @param out_ Optional full raw protocol output.
                 * @return True when parsing yields at least one line.
                 * @note Uses CRLF splitting semantics.
                 */
                bool VEthernetHttpProxyConnection::ProtocolReadHeaders(ppp::io::MemoryStream& ms, ppp::vector<ppp::string>& headers, ppp::string* out_) noexcept {
                    return ppp::net::http::SplitHttpHeaderLines(ms, headers, out_);
                }

                /**
                 * @brief Sends an HTTP error response to the client.
                 * @param socket Target client socket.
                 * @param protocol HTTP protocol token.
                 * @param version HTTP version token.
                 * @param status_code HTTP status code.
                 * @param status_text HTTP status text.
                 * @param y Coroutine yield context.
                 * @return True when response bytes are written successfully.
                 * @note Falls back to HTTP/1.1 when protocol/version are empty.
                 */
                static bool SendHttpProxyErrorResponse(
                    const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                    const ppp::string& protocol,
                    const ppp::string& version,
                    int status_code,
                    const char* status_text,
                    VEthernetHttpProxyConnection::YieldContext& y) noexcept;

                /**
                 * @brief Builds a ProtocolRoot from current socket header buffer.
                 * @param ms Memory stream containing HTTP header bytes.
                 * @param socket Source client socket.
                 * @param y Coroutine yield context.
                 * @return Parsed ProtocolRoot on success; null on failure.
                 * @note Reads request line metadata and all header pairs.
                 */
                std::shared_ptr<VEthernetHttpProxyConnection::ProtocolRoot> VEthernetHttpProxyConnection::GetProtocolRootFromSocket(ppp::io::MemoryStream& ms, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, VEthernetHttpProxyConnection::YieldContext& y) noexcept {
                    std::shared_ptr<ProtocolRoot> protocolRoot = make_shared_object<ProtocolRoot>();
                    if (NULLPTR == protocolRoot) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed, std::shared_ptr<VEthernetHttpProxyConnection::ProtocolRoot>(NULLPTR));
                    }

                    ppp::vector<ppp::string> headers;
                    if (!ProtocolReadHeaders(ms, headers, &protocolRoot->RawRotocol)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::HttpHeaderInvalid, std::shared_ptr<VEthernetHttpProxyConnection::ProtocolRoot>(NULLPTR));
                    }

                    if (!ProtocolReadFirstRoot(headers, protocolRoot)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::HttpRequestFailed, std::shared_ptr<VEthernetHttpProxyConnection::ProtocolRoot>(NULLPTR));
                    }

                    if (!ProtocolReadAllHeaders(headers, protocolRoot->Headers)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::HttpHeaderInvalid, std::shared_ptr<VEthernetHttpProxyConnection::ProtocolRoot>(NULLPTR));
                    }

                    return protocolRoot;
                }

                static bool SendHttpProxyErrorResponse(
                    const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                    const ppp::string& protocol,
                    const ppp::string& version,
                    int status_code,
                    const char* status_text,
                    VEthernetHttpProxyConnection::YieldContext& y) noexcept {

                    if (NULLPTR == socket || !socket->is_open()) {
                        return false;
                    }

                    ppp::string response_protocol = protocol.empty() ? ppp::string("HTTP") : protocol;
                    ppp::string response_version = version.empty() ? ppp::string("1.1") : version;
                    ppp::string response_headers = response_protocol + "/" + response_version + " " + stl::to_string<ppp::string>(status_code) + " ";
                    response_headers += status_text;
                    response_headers += "\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                    bool ok = ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(response_headers.data(), response_headers.size()), y);
                    return ok ? true : ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                }

                /**
                 * @brief Reads complete HTTP headers from client socket.
                 * @param headers Destination memory stream.
                 * @param y Coroutine yield context.
                 * @param socket Source TCP socket.
                 * @return True when full headers are read.
                 * @note Socket must be open before reading.
                 */
                bool VEthernetHttpProxyConnection::ProtocolReadAllHeaders(ppp::io::MemoryStream& headers, VEthernetHttpProxyConnection::YieldContext& y, boost::asio::ip::tcp::socket& socket) noexcept {
                    return ppp::net::http::ReadHttpHeaders(headers, y, socket);
                }

                /**
                 * @brief Performs request parsing and upstream bridge handshake.
                 * @param y Coroutine yield context.
                 * @return True when handshake and initial forwarding succeed.
                 * @note Sends HTTP error responses for invalid parsing states.
                 */
                bool VEthernetHttpProxyConnection::Handshake(YieldContext& y) noexcept {
                    ppp::io::MemoryStream protocol_array;
                    if (IsDisposed()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket_ = GetSocket();
                    Update();

                    if (!ppp::net::http::ReadHttpHeaders(protocol_array, y, *socket_)) {
                        return false;
                    }

                    std::shared_ptr<Byte> protocol_array_ptr = protocol_array.GetBuffer();
                    if (NULLPTR == protocol_array_ptr) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryBufferNull);
                    }

                    int protocol_array_size = protocol_array.GetPosition();
                    if (protocol_array_size < 1) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::HttpHeaderInvalid);
                    }

                    ppp::string protocol = ppp::string((char*)protocol_array_ptr.get(), protocol_array_size);
                    std::size_t index = protocol.find(' ');
                    if (index == ppp::string::npos) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpRequestFailed);
                        (void)SendHttpProxyErrorResponse(socket_, "HTTP", "1.1", 400, "Bad Request", y);
                        return false;
                    }

                    protocol = protocol.substr(0, index);
                    protocol = ToUpper<ppp::string>(protocol);
                    if (!gStaticVariable->IsSupportMethodKey(protocol)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpRequestFailed);
                        (void)SendHttpProxyErrorResponse(socket_, "HTTP", "1.1", 501, "Not Implemented", y);
                        return false;
                    }

                    int next[4];
                    // Locate header boundary so trailing bytes can be forwarded.
                    int headers_index = FindIndexOf(next, (char*)protocol_array_ptr.get(), protocol_array_size, (char*)("\r\n\r\n"), arraysizeof(next)); // KMP
                    if (headers_index < 0) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpHeaderInvalid);
                        (void)SendHttpProxyErrorResponse(socket_, "HTTP", "1.1", 400, "Bad Request", y);
                        return false;
                    }

                    std::shared_ptr<ProtocolRoot> protocol_root = this->GetProtocolRootFromSocket(protocol_array, socket_, y);
                    if (!this->ConnectBridgeToPeer(protocol_root, y)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpConnectTunnelFailed);
                        if (NULLPTR != protocol_root) {
                            (void)SendHttpProxyErrorResponse(socket_, protocol_root->Protocol, protocol_root->Version, 502, "Bad Gateway", y);
                        }
                        else {
                            (void)SendHttpProxyErrorResponse(socket_, "HTTP", "1.1", 400, "Bad Request", y);
                        }
                        return false;
                    }

                    int headers_endoffset = headers_index + arraysizeof(next);
                    int pushfd_array_size = protocol_array_size - headers_endoffset;
                    
                    bool handshaked = this->ProcessHandshaked(protocol_root, protocol_array_ptr.get() + headers_endoffset, pushfd_array_size, y);
                    if (!handshaked && NULLPTR != protocol_root && !protocol_root->TunnelMode) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpProxyApplyFailed);
                        (void)SendHttpProxyErrorResponse(socket_, protocol_root->Protocol, protocol_root->Version, 502, "Bad Gateway", y);
                    }

                    return handshaked;
                }

                /**
                 * @brief Finalizes handshake and emits initial tunnel/request payload.
                 * @param protocolRoot Parsed protocol metadata.
                 * @param messages Optional buffered payload after headers.
                 * @param messages_size Payload size.
                 * @param y Coroutine yield context.
                 * @return True when follow-up write/forward succeeds.
                 * @note CONNECT sends a 200 response before data piping.
                 */
                bool VEthernetHttpProxyConnection::ProcessHandshaked(const std::shared_ptr<ProtocolRoot>& protocolRoot, const void* messages, int messages_size, YieldContext& y) noexcept {
                    if (IsDisposed()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = GetSocket();
                    if (NULLPTR == socket) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                    }

                    if (protocolRoot->TunnelMode) { // HTTP/1.1 200 Connection established
                        ppp::string response_headers = protocolRoot->Protocol + "/" + protocolRoot->Version + " 200 Connection established\r\n\r\n";
                        if (!ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(response_headers.data(), response_headers.size()), y)) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                        }

                        if (messages_size > 0) {
                            bool writed = ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(messages, messages_size), y);
                            return writed ? true : ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                        }

                        return true;
                    }
                    else {
                        // For normal HTTP proxy mode, rebuild the request head and
                        // append any buffered body bytes before forwarding upstream.
                        ppp::io::MemoryStream ms;
                        ms.BufferAllocator = this->GetBufferAllocator();

                        ppp::string request_headers = protocolRoot->ToString();
                        if (request_headers.empty()) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpHeaderInvalid);
                            (void)SendHttpProxyErrorResponse(socket, protocolRoot->Protocol, protocolRoot->Version, 500, "Internal Server Error", y);
                            return false;
                        }
                        
                        if (!ms.Write(request_headers.data(), 0, static_cast<int>(request_headers.size()))) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                            (void)SendHttpProxyErrorResponse(socket, protocolRoot->Protocol, protocolRoot->Version, 500, "Internal Server Error", y);
                            return false;
                        }

                        if (messages_size > 0 && !ms.Write(messages, 0, messages_size)) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                            (void)SendHttpProxyErrorResponse(socket, protocolRoot->Protocol, protocolRoot->Version, 502, "Bad Gateway", y);
                            return false;
                        }

                        int packet_size = ms.GetPosition();
                        if (packet_size < 1) {
                            return true;
                        }

                        std::shared_ptr<Byte> packet_array = ms.GetBuffer();
                        if (NULLPTR == packet_array) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryBufferNull);
                            (void)SendHttpProxyErrorResponse(socket, protocolRoot->Protocol, protocolRoot->Version, 500, "Internal Server Error", y);
                            return false;
                        }

                        bool ok = this->SendBufferToPeer(y, packet_array.get(), packet_size);
                        if (!ok) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpProxyApplyFailed);
                            (void)SendHttpProxyErrorResponse(socket, protocolRoot->Protocol, protocolRoot->Version, 502, "Bad Gateway", y);
                        }

                        return ok;
                    }
                }

                /**
                 * @brief Establishes upstream bridge using parsed protocol target.
                 * @param protocolRoot Parsed request metadata.
                 * @param y Coroutine yield context.
                 * @return True when upstream connection is established.
                 * @note Returns false when protocolRoot is null.
                 */
                bool VEthernetHttpProxyConnection::ConnectBridgeToPeer(const std::shared_ptr<ProtocolRoot>& protocolRoot, YieldContext& y) noexcept {
                    if (NULLPTR == protocolRoot) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::HttpRequestFailed);
                    }
                    
                    std::shared_ptr<ppp::app::protocol::AddressEndPoint> destinationEP = GetAddressEndPointByProtocol(protocolRoot);
                    return VEthernetLocalProxyConnection::ConnectBridgeToPeer(destinationEP, y);
                }

                /**
                 * @brief Resolves host and port from parsed HTTP protocol data.
                 * @param protocolRoot Parsed request metadata.
                 * @return Destination endpoint or null on invalid host.
                 * @note Defaults to port 80 for non-CONNECT requests.
                 */
                std::shared_ptr<ppp::app::protocol::AddressEndPoint> VEthernetHttpProxyConnection::GetAddressEndPointByProtocol(const std::shared_ptr<ProtocolRoot>& protocolRoot) noexcept {
                    if (NULLPTR == protocolRoot) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::HttpRequestFailed, std::shared_ptr<ppp::app::protocol::AddressEndPoint>(NULLPTR));
                    }

                    ppp::string host = protocolRoot->Host;
                    if (host.empty()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid, std::shared_ptr<ppp::app::protocol::AddressEndPoint>(NULLPTR));
                    }

                    int port = PPP_HTTP_SYS_PORT; 
                    if (!host.empty()) {
                        // Handle bracketed IPv6 literal form: [addr]:port.
                        if (host.front() == '[') {
                            std::size_t end = host.find(']');
                            if (end != ppp::string::npos) {
                                ppp::string literal = host.substr(1, end - 1);
                                if (!literal.empty()) {
                                    boost::system::error_code ec;
                                    boost::asio::ip::address parsed = StringToAddress(literal, ec);
                                    if (!ec && parsed.is_v6()) {
                                        host = literal;
                                        std::size_t colon = host.find(':', end + 1);
                                        if (colon != ppp::string::npos) {
                                            ppp::string port_str = host.substr(colon + 1);
                                            char* endptr = NULLPTR;
                                            long parsed_port = strtol(port_str.c_str(), &endptr, 10);
                                            if (NULLPTR != endptr && endptr != port_str.c_str() && *endptr == '\x0' && parsed_port > ppp::net::IPEndPoint::MinPort && parsed_port <= ppp::net::IPEndPoint::MaxPort) {
                                                port = static_cast<int>(parsed_port);
                                            }

                                            if (port <= ppp::net::IPEndPoint::MinPort || port > ppp::net::IPEndPoint::MaxPort) {
                                                port = PPP_HTTP_SYS_PORT;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        // Handle common host:port format (IPv4/domain).
                        elif (char* p = (char*)::strchr(host.data(), ':'); NULLPTR != p) {
                            ppp::string port_str(p + 1);
                            char* endptr = NULLPTR;
                            long parsed_port = strtol(port_str.c_str(), &endptr, 10);
                            if (NULLPTR != endptr && endptr != port_str.c_str() && *endptr == '\x0' && parsed_port > ppp::net::IPEndPoint::MinPort && parsed_port <= ppp::net::IPEndPoint::MaxPort) {
                                port = static_cast<int>(parsed_port);
                            }
                            if (port <= ppp::net::IPEndPoint::MinPort || port > ppp::net::IPEndPoint::MaxPort) {
                                port = PPP_HTTP_SYS_PORT;
                            }

                            *p = '\x0';
                            host = host.data();
                        }
                    }

                    return VEthernetLocalProxyConnection::GetAddressEndPointByProtocol(host, port);
                }

                /**
                 * @brief Parses HTTP request line and determines target host.
                 * @param headers Tokenized HTTP header lines.
                 * @param protocolRoot Output protocol root.
                 * @return True when parsing and validation succeed.
                 * @note Supports CONNECT, origin-form, and absolute-form URIs.
                 */
                bool VEthernetHttpProxyConnection::ProtocolReadFirstRoot(const ppp::vector<ppp::string>& headers, const std::shared_ptr<ProtocolRoot>& protocolRoot) noexcept {
                    static const ppp::string CONNECT_TEXT      = "CONNECT";
                    static const ppp::string HTTP_TEXT         = "HTTP";
                    static const ppp::string HOST_TEXT         = "HOST";
                    static const ppp::string HTTP_COLON_TEXT   = "HTTP:";
                    static const ppp::string DOUBLE_SLASH_TEXT = "//";

                    if (NULLPTR == protocolRoot) {
                        return false;
                    }

                    if (headers.empty()) {
                        return false;
                    }

                    const ppp::string& header_first = headers[0];
                    if (header_first.empty()) {
                        return false;
                    }

                    ppp::vector<ppp::string> segments;
                    if (Tokenize<ppp::string>(header_first, segments, " ") < 3) {
                        return false;
                    }

                    protocolRoot->Method = ToUpper(segments[0]);
                    if (protocolRoot->Method == CONNECT_TEXT) {
                        protocolRoot->TunnelMode = true;
                    }
                    elif(!gStaticVariable->IsSupportMethodKey(protocolRoot->Method)) {
                        return false;
                    }

                    const ppp::string& protocolVersion = segments[2]; {
                        size_t index = protocolVersion.find('/');
                        if (index == ppp::string::npos) {
                            return false;
                        }

                        protocolRoot->Protocol = protocolVersion.substr(0, index);
                        if (protocolRoot->Protocol != HTTP_TEXT) {
                            return false;
                        }

                        if (++index > protocolVersion.size()) {
                            return false;
                        }

                        protocolRoot->Version = protocolVersion.substr(index);
                        if (protocolRoot->Version.empty()) {
                            return false;
                        }
                    }

                    ppp::string& rawUri = constantof(segments[1]);
                    if (rawUri.empty()) {
                        return false;        
                    }
                    elif(protocolRoot->TunnelMode) {
                        // CONNECT uses host:port directly as request target.
                        protocolRoot->Host = rawUri;
                    }
                    elif(rawUri[0] == '/') {
                        // Origin-form requests rely on the Host header.
                        protocolRoot->RawUri = header_first;
                        for (std::size_t index = 1, length = headers.size(); index < length; index++) {
                            ppp::string line = LTrim(RTrim(headers[index]));
                            if (line.empty()) {
                                continue;
                            }

                            std::size_t left_index = line.find(':');
                            if (left_index == 0 || left_index == ppp::string::npos) {
                                continue;
                            }

                            ppp::string left = LTrim(RTrim(line.substr(0, left_index)));
                            if (left.empty()) {
                                continue;
                            }

                            left = ToUpper(left);
                            if (left != HOST_TEXT) {
                                continue;
                            }

                            ppp::string reft = LTrim(RTrim(line.substr(left_index + 1)));
                            if (reft.empty()) {
                                return false;
                            }

                            protocolRoot->Host = reft;
                            break;
                        }

                        if (protocolRoot->Host.empty()) {
                            return false;
                        }
                    }
                    else {
                        // Absolute-form URI: extract host and request path.
                        size_t left_index = rawUri.find(DOUBLE_SLASH_TEXT);
                        if (left_index == ppp::string::npos) {
                            return false;
                        }
                        
                        ppp::string left = ToUpper(rawUri.substr(0, left_index));
                        if (left != HTTP_COLON_TEXT) {
                            return false;
                        }
                        else {
                            left_index = left_index + 2;
                            if (left_index > rawUri.size()) {
                                return false;
                            }
                        }

                        size_t path_index = rawUri.find('/', left_index);
                        if (path_index == ppp::string::npos) {
                            protocolRoot->RawUri = "/";
                            protocolRoot->Host = rawUri.substr(left_index);
                        }
                        else {
                            size_t sz = path_index - left_index;
                            if (sz > 0) {
                                protocolRoot->Host = rawUri.substr(left_index, sz);
                            }

                            protocolRoot->RawUri = rawUri.substr(path_index);
                        }

                        if (protocolRoot->Host.empty() ||
                            protocolRoot->RawUri.empty() ||
                            protocolRoot->RawUri[0] != '/') {
                            return false;
                        }
                    }

                    const ppp::string& host = protocolRoot->Host;
                    if (protocolRoot->TunnelMode) {
                        if (host.find(':') == ppp::string::npos) {
                            protocolRoot->Host = host + ":443";
                        }
                    }
                    elif (host.find(':') == ppp::string::npos) {
                        protocolRoot->Host = host + ":80";
                    }

                    return true;
                }

                /**
                 * @brief Parses and normalizes HTTP headers into a map.
                 * @param headers Tokenized header lines.
                 * @param s Output header map.
                 * @return True when parsing completes.
                 * @note Proxy-specific headers can be removed.
                 */
                bool VEthernetHttpProxyConnection::ProtocolReadAllHeaders(const ppp::vector<ppp::string>& headers, ProtocolRoot::HeaderCollection& s) noexcept {
                    for (size_t i = 1, l = headers.size(); i < l; ++i) {
                        const ppp::string& str = headers[i];
                        size_t j = str.find(':');
                        if (j == ppp::string::npos) {
                            continue;
                        }

                        size_t n = j + 2;
                        if (n >= str.size()) {
                            continue;
                        }

                        ppp::string left = str.substr(0, j); 
                        for (;;) {
                            auto tail = gStaticVariable->proxyHeaderToAgentHeader.find(ToUpper(left));
                            auto endl = gStaticVariable->proxyHeaderToAgentHeader.end();
                            if (tail != endl) {
                                left = tail->second;
                            }

                            break;
                        }

                        if (left.empty()) {
                            continue;
                        }
                        else {
                            s[left] = str.substr(n);
                        }
                    }
                    
                    return true;
                }

                /**
                 * @brief Serializes protocol root fields into an HTTP header block.
                 * @param None.
                 * @return HTTP request string ending with CRLF CRLF.
                 * @note Uses Host as URI target in tunnel mode.
                 */
                ppp::string VEthernetHttpProxyConnection::ProtocolRoot::ToString() noexcept {
                    ppp::string protocol;
                    if (this->TunnelMode) {
                        protocol = this->Method + " " + this->Host + " " + this->Protocol + "/" + this->Version + "\r\n";
                    }
                    else {
                        protocol = this->Method + " " + this->RawUri + " " + this->Protocol + "/" + this->Version + "\r\n";
                    }

                    HeaderCollection::iterator headerTail = this->Headers.begin();
                    HeaderCollection::iterator headerEndl = this->Headers.end();
                    
                    for (; headerTail != headerEndl; ++headerTail) {
                        protocol += headerTail->first + ": " + headerTail->second + "\r\n";
                    }

                    protocol += "\r\n";
                    return protocol;
                }
            }
        }
    }
}
