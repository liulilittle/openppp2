#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetHttpProxyConnection.h>

#include <ppp/IDisposable.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                class VEthernetHttpProxyConnectionStaticVariable final {
                public:
                    typedef ppp::unordered_set<ppp::string>                         StringSet;
                    typedef ppp::unordered_map<ppp::string, ppp::string>            StringMap;

                public: 
                    std::size_t                                                     protocolMethodMaxBytes;
                    StringSet                                                       protocolMethods;
                    StringMap                                                       proxyHeaderToAgentHeader;

                public:
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
                    bool                                                            IsSupportMethodKey(const ppp::string& s) noexcept {
                        if (s.empty()) {
                            return false;
                        }

                        StringSet::iterator tail = protocolMethods.find(s);
                        StringSet::iterator endl = protocolMethods.end();
                        return tail != endl;
                    }
                };

                static std::shared_ptr<VEthernetHttpProxyConnectionStaticVariable>  gStaticVariable = NULL;

                // VEthernetHttpProxyConnection class's static constructor.
                void VEthernetHttpProxyConnection_cctor() noexcept {
                    gStaticVariable = ppp::make_shared_object<VEthernetHttpProxyConnectionStaticVariable>();
                }

                VEthernetHttpProxyConnection::VEthernetHttpProxyConnection(
                    const VEthernetHttpProxySwitcherPtr&                    proxy, 
                    const VEthernetExchangerPtr&                            exchanger, 
                    const std::shared_ptr<boost::asio::io_context>&         context, 
                    const ppp::threading::Executors::StrandPtr&             strand, 
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket) noexcept
                    : VEthernetLocalProxyConnection(proxy, exchanger, context, strand, socket) {
                    
                }

                bool VEthernetHttpProxyConnection::ProtocolReadHeaders(ppp::io::MemoryStream& ms, ppp::vector<ppp::string>& headers, ppp::string* out_) noexcept {
                    std::shared_ptr<Byte> protocol = ms.GetBuffer();
                    if (NULL == protocol) {
                        return false;
                    }

                    int protocol_size = ms.GetPosition();
                    if (protocol_size < 1) {
                        return false;
                    }

                    if (NULL != out_) {
                        *out_ = ppp::string((char*)protocol.get(), protocol_size);
                        return Tokenize<ppp::string>(*out_, headers, "\r\n") > 0;
                    }
                    else {
                        return Tokenize<ppp::string>(ppp::string((char*)protocol.get(), protocol_size), headers, "\r\n") > 0;
                    }
                }

                std::shared_ptr<VEthernetHttpProxyConnection::ProtocolRoot> VEthernetHttpProxyConnection::GetProtocolRootFromSocket(ppp::io::MemoryStream& ms) noexcept {
                    std::shared_ptr<ProtocolRoot> protocolRoot = make_shared_object<ProtocolRoot>();
                    if (NULL == protocolRoot) {
                        return NULL;
                    }

                    ppp::vector<ppp::string> headers;
                    if (!ProtocolReadHeaders(ms, headers, &protocolRoot->RawRotocol)) {
                        return NULL;
                    }

                    if (!ProtocolReadFirstRoot(headers, protocolRoot)) {
                        return NULL;
                    }

                    if (!ProtocolReadAllHeaders(headers, protocolRoot->Headers)) {
                        return NULL;
                    }

                    return protocolRoot;
                }

                static bool ProtocolReadHttpHeaders(ppp::io::MemoryStream& protocol_array, VEthernetHttpProxyConnection::YieldContext& y, boost::asio::ip::tcp::socket& socket) noexcept {
                    char buffers[ppp::tap::ITap::Mtu];
                    for (;;) {
                        int bytes_transferred = ppp::coroutines::asio::async_read_some(socket, boost::asio::buffer(buffers, sizeof(buffers)), y);
                        if (bytes_transferred < 1) {
                            return false;
                        }

                        if (!protocol_array.Write(buffers, 0, bytes_transferred)) {
                            return false;
                        }

                        std::shared_ptr<Byte> protocol_array_ptr = protocol_array.GetBuffer();
                        if (NULL == protocol_array_ptr) {
                            return false;
                        }

                        int next[4];
                        int index = FindIndexOf(next, (char*)protocol_array_ptr.get(), protocol_array.GetPosition(), (char*)("\r\n\r\n"), 4); 
                        if (index > -1) {
                            return true;
                        }
                    } /* nocall: boost::asio::async_read_until(...); */
                }

                bool VEthernetHttpProxyConnection::ProtocolReadAllHeaders(ppp::io::MemoryStream& headers, VEthernetHttpProxyConnection::YieldContext& y, boost::asio::ip::tcp::socket& socket) noexcept {
                    bool opened = socket.is_open();
                    if (!opened) {
                        return false;
                    }

                    return ProtocolReadHttpHeaders(headers, y, socket);
                }

                bool VEthernetHttpProxyConnection::Handshake(YieldContext& y) noexcept {
                    ppp::io::MemoryStream protocol_array;
                    if (IsDisposed()) {
                        return false;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket_ = GetSocket();
                    Update();

                    if (!ProtocolReadHttpHeaders(protocol_array, y, *socket_)) {
                        return false;
                    }

                    std::shared_ptr<Byte> protocol_array_ptr = protocol_array.GetBuffer();
                    if (NULL == protocol_array_ptr) {
                        return false;
                    }

                    int protocol_array_size = protocol_array.GetPosition();
                    if (protocol_array_size < 1) {
                        return false;
                    }
                    elif(protocol_array_size < (int64_t)gStaticVariable->protocolMethodMaxBytes) {
                        return false;
                    }
                    else {
                        ppp::string protocol = ppp::string((char*)protocol_array_ptr.get(), gStaticVariable->protocolMethodMaxBytes);
                        std::size_t index = protocol.find(' ');
                        if (index != ppp::string::npos) {
                            protocol = protocol.substr(0, index);
                        }

                        protocol = ToUpper<ppp::string>(protocol);
                        if (!gStaticVariable->IsSupportMethodKey(protocol)) {
                            return false;
                        }
                    }

                    int next[4];
                    int index = FindIndexOf(next, (char*)protocol_array_ptr.get(), protocol_array_size, (char*)("\r\n\r\n"), arraysizeof(next)); // KMP
                    if (index < 0) {
                        return false;
                    }

                    std::shared_ptr<ProtocolRoot> protocol_root = this->GetProtocolRootFromSocket(protocol_array);
                    if (!this->ConnectBridgeToPeer(protocol_root, y)) {
                        return false;
                    }

                    int headers_endoffset = index + arraysizeof(next);
                    int pushfd_array_size = protocol_array_size - headers_endoffset;
                    return this->ProcessHandshaked(protocol_root, protocol_array_ptr.get() + headers_endoffset, pushfd_array_size, y);
                }

                bool VEthernetHttpProxyConnection::ProcessHandshaked(const std::shared_ptr<ProtocolRoot>& protocolRoot, const void* messages, int messages_size, YieldContext& y) noexcept {
                    if (IsDisposed()) {
                        return false;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = GetSocket();
                    if (NULL == socket) {
                        return false;
                    }

                    if (protocolRoot->TunnelMode) { // HTTP/1.1 200 Connection established
                        ppp::string response_headers = protocolRoot->Protocol + "/" + protocolRoot->Version + " 200 Connection established\r\n\r\n";
                        if (!ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(response_headers.data(), response_headers.size()), y)) {
                            return false;
                        }

                        if (messages_size > 0) {
                            return ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(messages, messages_size), y);
                        }

                        return true;
                    }
                    else {
                        ppp::io::MemoryStream ms;
                        ms.BufferAllocator = this->GetBufferAllocator();

                        ppp::string request_headers = protocolRoot->ToString();
                        if (request_headers.empty()) {
                            return false;
                        }
                        
                        if (!ms.Write(request_headers.data(), 0, static_cast<int>(request_headers.size()))) {
                            return false;
                        }

                        if (messages_size > 0 && !ms.Write(messages, 0, messages_size)) {
                            return false;
                        }

                        int packet_size = ms.GetPosition();
                        if (packet_size < 1) {
                            return true;
                        }

                        std::shared_ptr<Byte> packet_array = ms.GetBuffer();
                        if (NULL == packet_array) {
                            return false;
                        }

                        return this->SendBufferToPeer(y, packet_array.get(), packet_size);
                    }
                }

                bool VEthernetHttpProxyConnection::ConnectBridgeToPeer(const std::shared_ptr<ProtocolRoot>& protocolRoot, YieldContext& y) noexcept {
                    if (NULL == protocolRoot) {
                        return false;
                    }
                    
                    std::shared_ptr<ppp::app::protocol::AddressEndPoint> destinationEP = GetAddressEndPointByProtocol(protocolRoot);
                    return VEthernetLocalProxyConnection::ConnectBridgeToPeer(destinationEP, y);
                }

                std::shared_ptr<ppp::app::protocol::AddressEndPoint> VEthernetHttpProxyConnection::GetAddressEndPointByProtocol(const std::shared_ptr<ProtocolRoot>& protocolRoot) noexcept {
                    if (NULL == protocolRoot) {
                        return NULL;
                    }

                    ppp::string host = protocolRoot->Host;
                    if (host.empty()) {
                        return NULL;
                    }

                    int port = PPP_HTTP_SYS_PORT; 
                    if (char* p = (char*)::strchr(host.data(), ':'); NULL != p) {
                        port = atoi(p + 1);
                        if (port <= ppp::net::IPEndPoint::MinPort || port > ppp::net::IPEndPoint::MaxPort) {
                            port = PPP_HTTP_SYS_PORT;
                        }

                        *p = '\x0';
                        host = host.data();
                    }

                    return VEthernetLocalProxyConnection::GetAddressEndPointByProtocol(host, port);
                }

                bool VEthernetHttpProxyConnection::ProtocolReadFirstRoot(const ppp::vector<ppp::string>& headers, const std::shared_ptr<ProtocolRoot>& protocolRoot) noexcept {
                    static const ppp::string CONNECT_TEXT      = "CONNECT";
                    static const ppp::string HTTP_TEXT         = "HTTP";
                    static const ppp::string HOST_TEXT         = "HOST";
                    static const ppp::string HTTP_COLON_TEXT   = "HTTP:";
                    static const ppp::string DOUBLE_SLASH_TEXT = "//";

                    if (NULL == protocolRoot) {
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
                        protocolRoot->Host = rawUri;
                    }
                    elif(rawUri[0] == '/') {
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
                    if (host.rfind(':') == ppp::string::npos) {
                        protocolRoot->Host = host + ":80";
                    }

                    return true;
                }

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