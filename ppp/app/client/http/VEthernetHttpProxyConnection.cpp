#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/http/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/http/VEthernetHttpProxyConnection.h>
#include <ppp/IDisposable.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace http {
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
                        proxyHeaderToAgentHeader["CONNECTION"] = "";

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

                VEthernetHttpProxyConnection::VEthernetHttpProxyConnection(const VEthernetHttpProxySwitcherPtr& proxy, const VEthernetExchangerPtr& exchanger, const std::shared_ptr<boost::asio::io_context>& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept
                    : disposed_(false)
                    , context_(context)
                    , timeout_(0)
                    , exchanger_(exchanger)
                    , socket_(socket)
                    , configuration_(proxy->GetConfiguration())
                    , proxy_(proxy)
                    , allocator_(configuration_->GetBufferAllocator()) {
                    Update();
                }

                VEthernetHttpProxyConnection::~VEthernetHttpProxyConnection() noexcept {
                    Finalize();
                }

                void VEthernetHttpProxyConnection::Dispose() noexcept {
                    auto self = this->shared_from_this();
                    std::shared_ptr<boost::asio::io_context> context = this->GetContext();
                    context->post(
                        [self, this]() noexcept {
                            Finalize();
                        });
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> VEthernetHttpProxyConnection::GetBufferAllocator() noexcept {
                    return allocator_;
                }

                void VEthernetHttpProxyConnection::Finalize() noexcept {
                    exchangeof(disposed_, true); {
                        std::shared_ptr<VirtualEthernetTcpipConnection> connection = std::move(connection_);
                        if (NULL != connection) {
                            connection_.reset();
                            connection->Dispose();
                        }

                        ppp::net::Socket::Closesocket(socket_);
                    }
                    proxy_->ReleaseConnection(this);
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> VEthernetHttpProxyConnection::GetSocket() noexcept {
                    return socket_;
                }

                VEthernetHttpProxyConnection::VEthernetExchangerPtr VEthernetHttpProxyConnection::GetExchanger() noexcept {
                    return exchanger_;
                }

                VEthernetHttpProxyConnection::ContextPtr VEthernetHttpProxyConnection::GetContext() noexcept {
                    return context_;
                }

                VEthernetHttpProxyConnection::AppConfigurationPtr VEthernetHttpProxyConnection::GetConfiguration() noexcept {
                    return configuration_;
                }

                VEthernetHttpProxyConnection::VEthernetHttpProxySwitcherPtr VEthernetHttpProxyConnection::GetProxy() noexcept {
                    return proxy_;
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
                    if (!this->ProtocolReadHeaders(ms, headers, &protocolRoot->RawRotocol)) {
                        return NULL;
                    }

                    if (!this->ProtocolReadFirstRoot(headers, protocolRoot)) {
                        return NULL;
                    }

                    if (!this->ProtocolReadAllHeaders(headers, protocolRoot->Headers)) {
                        return NULL;
                    }

                    return protocolRoot;
                }

                bool VEthernetHttpProxyConnection::Run(YieldContext& y) noexcept {
                    bool ok = this->ProcessHandshaking(y);
                    if (!ok) {
                        return false;
                    }
                    elif(disposed_) {
                        return false;
                    }
                    else {
                        return this->OnEstablish(y);
                    }
                }

                static bool ProtocolReadHttpHeaders(ppp::io::MemoryStream& protocol_array, VEthernetHttpProxyConnection::YieldContext& y, boost::asio::ip::tcp::socket& socket) noexcept {
                    boost::system::error_code ec_;
                    std::size_t length_;
                    std::shared_ptr<boost::asio::streambuf> response_ = make_shared_object<boost::asio::streambuf>();
                    if (NULL == response_) {
                        return false;
                    }

                    boost::asio::async_read_until(socket, *response_, "\r\n\r\n",
                        [&y, &ec_, &length_, response_](boost::system::error_code ec, std::size_t sz) noexcept {
                            boost::asio::io_context& context = y.GetContext();
                            ec_ = ec;
                            length_ = sz;
                            context.dispatch(std::bind(&VEthernetHttpProxyConnection::YieldContext::Resume, y.GetPtr()));
                        });

                    y.Suspend();
                    if (ec_) {
                        return false;
                    }

                    if (!length_) {
                        return false;
                    }

                    boost::asio::const_buffers_1 buff_ = response_->data();
                    return protocol_array.Write(buff_.data(), 0, (int)length_);
                }

                bool VEthernetHttpProxyConnection::ProcessHandshaking(YieldContext& y) noexcept {
                    ppp::io::MemoryStream protocol_array;
                    if (disposed_) {
                        return false;
                    }

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
                    int index = FindIndexOf(next, (char*)protocol_array_ptr.get(), protocol_array_size, (char*)("\r\n\r\n"), 4); // KMP
                    if (index < 0) {
                        return false;
                    }

                    std::shared_ptr<ProtocolRoot> protocol_root = this->GetProtocolRootFromSocket(protocol_array);
                    if (!this->ConnectBridgeToPeer(protocol_root, y)) {
                        return false;
                    }

                    int headers_endoffset = index + 4;
                    int pushfd_array_size = protocol_array_size - headers_endoffset;
                    return this->ProcessHandshaked(protocol_root, protocol_array_ptr.get() + headers_endoffset, pushfd_array_size, y);
                }

                bool VEthernetHttpProxyConnection::ProcessHandshaked(const std::shared_ptr<ProtocolRoot>& protocolRoot, const void* messages, int messages_size, YieldContext& y) noexcept {
                    if (disposed_) {
                        return false;
                    }

                    ppp::io::MemoryStream ms;
                    ms.BufferAllocator = this->GetBufferAllocator();

                    if (protocolRoot->TunnelMode) { // HTTP/1.1 200 Connection established
                        ppp::string response_headers = protocolRoot->Protocol + "/" + protocolRoot->Version + " 200 Connection established\r\n\r\n";
                        if (!ppp::coroutines::asio::async_write(*socket_, boost::asio::buffer(response_headers.data(), response_headers.size()), y)) {
                            return false;
                        }
                    }
                    else {
                        ppp::string request_headers = protocolRoot->ToString();
                        if (request_headers.empty()) {
                            return false;
                        }

                        if (!ms.Write(request_headers.data(), 0, (int)request_headers.size())) {
                            return false;
                        }
                    }

                    if (messages_size > 0 && !ms.Write(messages, 0, messages_size)) {
                        return false;
                    }
                    elif(ms.GetPosition() > 0 && !this->WriteToLocal(y, ms)) {
                        return false;
                    }
                    return true;
                }

                bool VEthernetHttpProxyConnection::WriteToLocal(YieldContext& y, ppp::io::MemoryStream& stream) noexcept {
                    if (!stream.CanRead()) {
                        return false;
                    }

                    if (disposed_) {
                        return false;
                    }

                    int messages_size = stream.GetLength();
                    if (messages_size < 1) {
                        return true;
                    }

                    std::shared_ptr<Byte> messages = stream.GetBuffer();
                    if (NULL == messages) {
                        return false;
                    }

                    void* messages_ptr = messages.get();
                    return WriteToLocal(y, messages_ptr, messages_size);
                }

                bool VEthernetHttpProxyConnection::WriteToLocal(YieldContext& y, const void* messages, int messages_size) noexcept {
                    if (NULL == messages || messages_size < 1) {
                        return false;
                    }

                    if (disposed_) {
                        return false;
                    }

                    VirtualEthernetTcpipConnectionPtr connection = this->connection_;
                    if (NULL == connection) {
                        return false;
                    }

                    return connection->SendBufferToPeer(y, messages, messages_size);
                }

                bool VEthernetHttpProxyConnection::ConnectBridgeToPeer(const std::shared_ptr<ProtocolRoot>& protocolRoot, YieldContext& y) noexcept {
                    if (NULL == protocolRoot) {
                        return false;
                    }

                    std::shared_ptr<ppp::app::protocol::AddressEndPoint> destinationEP = this->GetAddressEndPointByProtocol(protocolRoot);
                    if (NULL == destinationEP) {
                        return false;
                    }

                    VirtualEthernetTcpipConnectionPtr connection = this->OnConnect(protocolRoot, destinationEP, y);
                    if (NULL == connection) {
                        return false;
                    }
                    else {
                        this->connection_ = std::move(connection);
                        return true;
                    }
                }

                bool VEthernetHttpProxyConnection::OnEstablish(YieldContext& y) noexcept {
                    if (disposed_) {
                        return false;
                    }

                    VirtualEthernetTcpipConnectionPtr connection = this->connection_;
                    if (NULL == connection) {
                        return false;
                    }

                    this->Update();
                    return connection->Run(y);
                }

                VEthernetHttpProxyConnection::VirtualEthernetTcpipConnectionPtr VEthernetHttpProxyConnection::OnConnect(const std::shared_ptr<ProtocolRoot>& protocolRoot, const std::shared_ptr<ppp::app::protocol::AddressEndPoint>& destinationEP, YieldContext& y) noexcept {
                    using VEthernetTcpipConnection = ppp::app::protocol::templates::VEthernetTcpipConnection<VEthernetHttpProxyConnection>;

                    std::shared_ptr<boost::asio::io_context> context = GetContext();
                    if (NULL == context) {
                        return NULL;
                    }

                    auto configuration = exchanger_->GetConfiguration();
                    if (NULL == configuration) {
                        return NULL;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = GetSocket();
                    if (NULL == socket) {
                        return NULL;
                    }

                    std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger_->ConnectTransmission(context, y);
                    if (NULL == transmission) {
                        return NULL;
                    }

                    std::shared_ptr<VEthernetTcpipConnection> connection =
                        make_shared_object<VEthernetTcpipConnection>(shared_from_this(), configuration, context, exchanger_->GetId(), socket);
                    if (NULL == connection) {
                        IDisposable::DisposeReferences(transmission);
                        return NULL;
                    }

#if defined(_LINUX)
                    if (auto switcher = exchanger_->GetSwitcher(); NULL != switcher) {
                        connection->ProtectorNetwork = switcher->GetProtectorNetwork();
                    }
#endif

                    bool ok = connection->Connect(y, transmission, destinationEP->Host, destinationEP->Port);
                    if (!ok) {
                        IDisposable::DisposeReferences(connection, transmission);
                        return NULL;
                    }

                    return connection;
                }

                std::shared_ptr<ppp::app::protocol::AddressEndPoint> VEthernetHttpProxyConnection::GetAddressEndPointByProtocol(const std::shared_ptr<ProtocolRoot>& protocolRoot) noexcept {
                    if (NULL == protocolRoot) {
                        return NULL;
                    }

                    std::shared_ptr<ppp::app::protocol::AddressEndPoint> destinationEP = make_shared_object<ppp::app::protocol::AddressEndPoint>();
                    if (NULL == destinationEP) {
                        return NULL;
                    }
                    
                    ppp::string host = protocolRoot->Host;
                    int port = 0; {
                        const char* p = strchr(host.data(), ':');
                        if (NULL == p) {
                            return NULL;
                        }
                        else {
                            port = atoi(p + 1);
                            *const_cast<char*>(p) = '\x0';
                        }

                        host.erase(p - host.data());
                    }

                    ppp::net::IPEndPoint ep = ppp::net::IPEndPoint(host.data(), port);
                    if (ep.IsNone()) {
                        destinationEP->Type = ppp::app::protocol::AddressType::Domain;
                    }
                    else {
                        ppp::net::AddressFamily af = ep.GetAddressFamily();
                        switch (af)
                        {
                        case ppp::net::AddressFamily::InterNetwork:
                            destinationEP->Type = ppp::app::protocol::AddressType::IPv4;
                            break;
                        case ppp::net::AddressFamily::InterNetworkV6:
                            destinationEP->Type = ppp::app::protocol::AddressType::IPv6;
                            break;
                        default:
                            return NULL;
                        }
                    }

                    destinationEP->Host = host;
                    destinationEP->Port = port;
                    return destinationEP;
                }

                bool VEthernetHttpProxyConnection::ProtocolReadFirstRoot(const ppp::vector<ppp::string>& headers, const std::shared_ptr<ProtocolRoot>& protocolRoot) noexcept {
                    static ppp::string CONNECT_TEXT = "CONNECT";
                    static ppp::string HTTP_TEXT = "HTTP";
                    static ppp::string HTTP_COLON_TEXT = "HTTP:";
                    static ppp::string DOUBLE_SLASH_TEXT = "//";

                    if (headers.empty() || NULL == protocolRoot) {
                        return false;
                    }

                    ppp::vector<ppp::string> segments;
                    if (Tokenize<ppp::string>(headers[0], segments, " ") < 3) {
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

                    ppp::string& rawUri = const_cast<ppp::string&>(segments[1]);
                    if (protocolRoot->TunnelMode) {
                        protocolRoot->Host = rawUri;
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

                        ppp::string left = str.substr(0, j); {
                            auto tail = gStaticVariable->proxyHeaderToAgentHeader.find(ToUpper(left));
                            auto endl = gStaticVariable->proxyHeaderToAgentHeader.end();
                            if (tail != endl) {
                                left = tail->second;
                            }
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

                void VEthernetHttpProxyConnection::Update() noexcept {
                    VirtualEthernetTcpipConnectionPtr connection = connection_;
                    if (NULL != connection && connection->IsLinked()) {
                        timeout_ = Executors::GetTickCount() + (UInt64)configuration_->tcp.inactive.timeout * 1000;
                    }
                    else {
                        timeout_ = Executors::GetTickCount() + (UInt64)configuration_->tcp.connect.timeout * 1000;;
                    }
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