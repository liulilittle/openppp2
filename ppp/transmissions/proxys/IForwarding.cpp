#include <ppp/transmissions/proxys/IForwarding.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/IDisposable.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/io/MemoryStream.h>

#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>

#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/auxiliary/UriAuxiliary.h>
#include <ppp/app/client/proxys/VEthernetHttpProxyConnection.h>

#include <ppp/stdafx.h>
#include <common/base64/base64.h>

namespace ppp {
    namespace transmissions {
        namespace proxys {
            using ppp::app::client::proxys::VEthernetHttpProxyConnection;
            using ppp::collections::Dictionary;
            using ppp::io::MemoryStream;
            using ppp::net::Socket;
            using ppp::net::IPEndPoint;
            using ppp::net::asio::IAsynchronousWriteIoQueue;
            using ppp::coroutines::YieldContext;
            using ppp::threading::Executors;
            using ppp::threading::BufferswapAllocator;

            class IForwarding::ProxyConnection final : public std::enable_shared_from_this<ProxyConnection> {
            public:
#if defined(_WIN32)
                std::shared_ptr<ppp::net::QoSS>                             qoss_[2];
#endif
                bool                                                        disposed_;
                uint64_t                                                    timeout_;
                Socket::AsioContext                                         context_;
                Socket::AsioStrandPtr                                       strand_;
                std::shared_ptr<boost::asio::ip::tcp::socket>               sockets_[2];
                std::shared_ptr<Byte>                                       buffers_[2];
                IForwarding::AppConfigurationPtr                            configuration_;
                std::shared_ptr<IForwarding>                                forwarding_;

            public:
                ProxyConnection(const std::shared_ptr<IForwarding>& forwarding, const IForwarding::AppConfigurationPtr& configuration, const Socket::AsioContext& context, const Socket::AsioStrandPtr& strand) noexcept 
                    : disposed_(false)
                    , timeout_(UINT64_MAX)
                    , context_(context)
                    , strand_(strand)
                    , configuration_(configuration)
                    , forwarding_(forwarding) {
                    
                }
                ~ProxyConnection() noexcept {
                    Finalize();
                }

            public:
                void                                                        Dispose() noexcept {
                    auto self = shared_from_this();
                    ppp::threading::Executors::ContextPtr context = context_;
                    ppp::threading::Executors::StrandPtr strand = strand_;

                    ppp::threading::Executors::Post(context, strand, 
                        [self, this, context, strand]() noexcept {
                            Finalize();
                        });
                }
                void                                                        Finalize() noexcept {
                    for (int i = 0; i < arraysizeof(sockets_); i++) {
                        std::shared_ptr<boost::asio::ip::tcp::socket>& reference = sockets_[i];
                        if (std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::move(reference); NULL != socket) {
                            reference.reset();

                            Socket::Closesocket(socket);
                        }
                    }

                    disposed_ = false;
                    if (std::shared_ptr<IForwarding> forwarding = std::move(forwarding_); NULL != forwarding) {
                        forwarding_.reset();
                        forwarding->TryRemove(this, false);
                    }
                }
                bool                                                        Forward(const std::shared_ptr<boost::asio::ip::tcp::socket>& inx, const std::shared_ptr<boost::asio::ip::tcp::socket>& iny) noexcept {
                    if (disposed_) {
                        return false;
                    }

                    for (std::shared_ptr<boost::asio::ip::tcp::socket>& socket : sockets_) {
                        if (NULL != socket) {
                            return false;
                        }
                    }

                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = configuration_->GetBufferAllocator();
                    for (std::shared_ptr<Byte>& buff : buffers_) {
                        buff = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, PPP_BUFFER_SIZE);
                        if (NULL == buff) {
                            return false;
                        }
                    }

                    sockets_[0] = inx;
                    sockets_[1] = iny;
                    Update();

                    std::shared_ptr<boost::asio::ip::tcp::socket>& x = sockets_[0];
                    std::shared_ptr<boost::asio::ip::tcp::socket>& y = sockets_[1];

#if defined(_WIN32)
                    if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                        if (inx->is_open()) {
                            qoss_[0] = ppp::net::QoSS::New(inx->native_handle());
                        }
                    }
#endif
                    return Forward(x, y, buffers_[0]) && Forward(y, x, buffers_[1]);
                }
                void                                                        Update() noexcept {
                    uint64_t now = ppp::threading::Executors::GetTickCount();
                    timeout_ = now + (UInt64)configuration_->tcp.inactive.timeout * 1000;
                }
                bool                                                        IsPortAging(uint64_t now) noexcept { return disposed_ || now >= timeout_; }

            private:
                bool                                                        Forward(
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    x, 
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    y,
                    const std::shared_ptr<Byte>&                            buff) noexcept {

                    if (disposed_ || NULL == buff) {
                        return false;
                    }
                    
                    if (NULL == x || NULL == y) {
                        return false;
                    }

                    if (!x->is_open() || !y->is_open()) {
                        return false;
                    }

                    auto self = shared_from_this();
                    x->async_read_some(boost::asio::buffer(buff.get(), PPP_BUFFER_SIZE), 
                        [self, this, x, y, buff](const boost::system::error_code& ec, std::size_t sz) noexcept {
                            int bytes_transferred = std::max<int>(-1, ec ? -1 : static_cast<int>(sz));
                            if (bytes_transferred > 0) {
                                boost::asio::async_write(*y, boost::asio::buffer(buff.get(), bytes_transferred),
                                    [self, this, x, y, buff](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                        if (ec == boost::system::errc::success && Forward(x, y, buff)) {
                                            Update();
                                        }
                                        else {
                                            Dispose();
                                        }
                                    });
                                Update();
                            }
                            else {
                                Dispose();
                            }
                        });
                    return true;
                }
            };

            IForwarding::IForwarding(
                const ContextPtr&                               context, 
                const AppConfigurationPtr&                      configuration) noexcept 
                : disposed_(false)
                , context_(context)
                , configuration_(configuration)
                , acceptor_(*context) {
                ResetSS();
            }

            IForwarding::~IForwarding() noexcept {
                Finalize();
            }

            void IForwarding::ResetSS() noexcept {
                server_.protocol = ProtocolType_HttpProxy;
                server_.port = IPEndPoint::MinPort;
                server_.url = "";
                server_.host = "";
                server_.username = "";
                server_.password = "";
                server_.endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::any(), IPEndPoint::MinPort);
                local_endpoint_ = server_.endpoint;
            }

            void IForwarding::Dispose() noexcept {
                ContextPtr context = context_;
                if (NULL == context) {
                    Finalize();
                    return;
                }

                auto self = shared_from_this();
                boost::asio::post(*context, 
                    [self, this, context]() noexcept {
                        Finalize();
                    });
            }

            IForwarding& IForwarding::SetRemoteEndPoint(const ppp::string& host, int port) noexcept {
                if (disposed_ || host.empty() || port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    server_.host = "";
                    server_.port = IPEndPoint::MinPort;
                }
                else {
                    server_.host = host;
                    server_.port = port;
                }

                return *this;
            }

            template <class T> 
            static bool IFORWARDING_DISPOSING(T& p) noexcept {
                if (p) {
                    using TA = typename std::decay<decltype(*p)>::type;
                    using TB = typename std::remove_reference<TA>::type;

                    if constexpr (IDisposable::HAS_MEMBER_DISPOSE_FUNCTION<TB>::value) {
                        p->Dispose();
                    }
                    else {
                        Socket::Closesocket(p);
                    }

                    return true;
                }
                
                return false;
            }

            template <class TValue, class TKey, class TMap>
            static bool IFORWARDING_TRY_REMOVE(IForwarding::SynchronizedObject& lck, TMap& map, TKey key, bool disposing) noexcept {
                TValue r;
                bool b = false;

                for (;;) {
                    if (NULL == key) {
                        return false;
                    }

                    IForwarding::SynchronizedObjectScope scope(lck);
                    b = Dictionary::TryRemove(map, key, r);
                    break;
                }

                if (disposing && r) {
                    IFORWARDING_DISPOSING(r);
                }

                return b;
            }

            template <class TValue, class TKey, class TMap>
            static bool IFORWARDING_TRY_ADD(bool& disposed, IForwarding::SynchronizedObject& lck, TMap& map, TKey* key, const TValue& value) noexcept {
                if (NULL == key) {
                    return false;
                }

                if (disposed) {
                    return false;
                }

                IForwarding::SynchronizedObjectScope scope(lck);
                return Dictionary::TryAdd(map, key, value);
            }

            bool IForwarding::TryRemove(boost::asio::ip::tcp::socket* socket, bool disposing) noexcept {
                return IFORWARDING_TRY_REMOVE<SocketPtr>(syncobj_, sockets_, socket, disposing);
            }

            bool IForwarding::TryRemove(ProxyConnection* connection, bool disposing) noexcept {
                return IFORWARDING_TRY_REMOVE<ProxyConnectionPtr>(syncobj_, connections_, connection, disposing);
            }

            bool IForwarding::TryRemove(Timer* timer, bool disposing) noexcept {
                return IFORWARDING_TRY_REMOVE<TimerPtr>(syncobj_, timers_, timer, disposing);
            }

            bool IForwarding::TryAdd(const SocketPtr& socket) noexcept {
                return IFORWARDING_TRY_ADD(disposed_, syncobj_, sockets_, socket.get(), socket);
            }

            bool IForwarding::TryAdd(const ProxyConnectionPtr& connection) noexcept {
                return IFORWARDING_TRY_ADD(disposed_, syncobj_, connections_, connection.get(), connection);
            }

            bool IForwarding::TryAdd(const TimerPtr& timer) noexcept {
                return IFORWARDING_TRY_ADD(disposed_, syncobj_, timers_, timer.get(), timer);
            }

            typedef struct {
                std::shared_ptr<Byte>   buffer;
                int                     offset;
                int                     length;
            } IForwarding_HttpOverflowByteArray;

            static bool IFORWARDING_HTTP_VERIFY_HANDSHAKE_RESPONSE_PACKET(MemoryStream& protocol_array) noexcept {
                ppp::vector<ppp::string> headers;
                if (!VEthernetHttpProxyConnection::ProtocolReadHeaders(protocol_array, headers, NULL)) {
                    return false;
                }

                int header_count = headers.size(); /* HTTP/1.1 200 Connection established */
                if (header_count < 1) {
                    return false;
                }

                ppp::vector<ppp::string> segments; 
                Tokenize<ppp::string>(headers[0], segments, " ");

                int segment_count = segments.size();
                if (segment_count != 4) {
                    return false;
                }

                int status_code = atoi(segments[1].data());
                if (status_code < 200 || status_code >= 300) {
                    return false;
                }

                segments[2] = ToLower<ppp::string>(segments[2]);
                segments[3] = ToLower<ppp::string>(segments[3]);

                if (segments[2] != "connection" || segments[3] != "established") {
                    return false;
                }

                ppp::string& s = segments[0];
                std::size_t i = s.find('/');
                if (i == std::string::npos) {
                    return false;
                }

                int v = atoi(s.substr(i + 1).data());
                if (v < 1) {
                    return false;
                }

                ppp::string proto = ToLower(s.substr(0, i));
                if (proto != "http") {
                    return false;
                }

                return true;
            }

            static bool IFORWARDING_HTTP_VERIFY_HANDSHAKE_RESPONSE_PACKET(IForwarding_HttpOverflowByteArray& ov, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, YieldContext& y) noexcept {
                if (NULL == socket || !socket->is_open()) {
                    return false;
                }

                MemoryStream protocol_array;
                bool ok = VEthernetHttpProxyConnection::ProtocolReadAllHeaders(protocol_array, y, *socket);
                if (!ok) {
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

                int next[4];
                int index = FindIndexOf(next, (char*)protocol_array_ptr.get(), protocol_array_size, (char*)("\r\n\r\n"), 4); // KMP
                if (index < 0) {
                    return false;
                }

                if (!IFORWARDING_HTTP_VERIFY_HANDSHAKE_RESPONSE_PACKET(protocol_array)) {
                    return false;
                }

                int headers_endoffset = index + 4;
                int pushfd_array_size = protocol_array_size - headers_endoffset;
                if (pushfd_array_size < 0) {
                    return false;
                }

                ov.buffer = protocol_array_ptr;
                ov.length = pushfd_array_size;
                ov.offset = headers_endoffset;
                return true;
            }

            bool IForwarding::HTTP_ReadHandshakePacket(
                const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, 
                YieldContext&                                        y,
                std::shared_ptr<Byte>&                               overflow_buffer,
                int&                                                 overflow_offset,
                int&                                                 overflow_length) noexcept {

                if (disposed_) {
                    return false;
                }

                IForwarding_HttpOverflowByteArray overflow;
                if (IFORWARDING_HTTP_VERIFY_HANDSHAKE_RESPONSE_PACKET(overflow, socket, y)) {
                    overflow_buffer = overflow.buffer;
                    overflow_offset = overflow.offset;
                    overflow_length = overflow.length;
                    return true;
                }
                else {
                    overflow_offset = 0;
                    overflow_length = 0;
                    overflow_buffer = NULL;
                    return false;
                }
            }

            bool IForwarding::HTTP_SendHandshakePacket(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, YieldContext& y) noexcept {
                // Refer: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/CONNECT
                // The HTTP CONNECT method starts two-way communications with the requested resource. It can be used to open a tunnel.
                // 
                // For example, the CONNECT method can be used to access websites that use TLS (HTTPS). 
                // The client asks an HTTP Proxy server to tunnel the TCP connection to the desired destination. 
                // The proxy server then proceeds to make the connection on behalf of the client. 
                // Once the connection is established, the proxy server continues to relay the TCP stream to and from the client.

                if (NULL == socket || !socket->is_open()) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                ppp::string param = base64_encode(server_.username + ":" + server_.password);
                ppp::string host = server_.host + ":" + stl::to_string<ppp::string>(server_.port);
                ppp::string request = "CONNECT " + host +" HTTP/1.1\r\n";
                request += "Host: " + host + "\r\n";
                request += "Proxy-Authorization: Basic " + param + "\r\n";
                request += "\r\n";

                size_t request_size = request.size();
                std::shared_ptr<BufferswapAllocator> allocator = configuration_->GetBufferAllocator();
                std::shared_ptr<Byte> packet = IAsynchronousWriteIoQueue::Copy(allocator, request.data(), request_size);

                if (NULL == packet) {
                    return false;
                }

                return ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(packet.get(), request_size), y);
            }
        
            // HTTP/socks proxy servers must be anonymous because they need to support the proxy settings of the operating system's web browser.
            // 
            // openppp2 provides this support in order to address situations such as when large enterprises only provide 
            // HTTP/socks proxy access to the internet for their employees in order to prevent them from accessing restricted network resources.
            //
            // Considering that large enterprises also build their own DNS servers, 
            // They use self-built DNS servers to resolve internal IP addresses for the HTTP/socks proxy server.
            static bool IFORWARDING_VERIFY_PROXY_URI(const ppp::string& in, ppp::string& server_url, boost::asio::ip::tcp::endpoint& output_endpoint, IForwarding::ProtocolType& output_protocol) noexcept {
                typedef ppp::auxiliary::UriAuxiliary::ProtocolType ProtocolType;

                ppp::string  hostname;
                ppp::string  address;
                ppp::string  path;
                int          port;
                ProtocolType protocol = ProtocolType::ProtocolType_PPP;
                
                output_protocol = IForwarding::ProtocolType_HttpProxy;
                output_endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::any(), IPEndPoint::MinPort);
                server_url = ppp::auxiliary::UriAuxiliary::Parse(in, hostname, address, path, port, protocol, nullof<YieldContext>());

                if (server_url.empty()) {
                    return false;
                }

                if (hostname.empty()) {
                    return false;
                }

                if (address.empty()) {
                    return false;
                }

                if (protocol != ProtocolType::ProtocolType_Http && protocol != ProtocolType::ProtocolType_Socks) {
                    return false;
                }

                if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    return false;
                }

                IPEndPoint ipep(address.data(), port);
                if (IPEndPoint::IsInvalid(ipep)) {
                    return false;
                }
                elif(protocol == ProtocolType::ProtocolType_Http) {
                    output_protocol = IForwarding::ProtocolType_HttpProxy;
                }
                elif(protocol == ProtocolType::ProtocolType_Socks) {
                    output_protocol = IForwarding::ProtocolType_SocksProxy;
                }

                output_endpoint = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(ipep);
                return true;
            }

            bool IForwarding::OpenAcceptor() noexcept {
                if (disposed_) {
                    return false;
                }

                boost::asio::ip::address addresses[] = {
                    boost::asio::ip::address_v6::loopback(),
                    boost::asio::ip::address_v4::loopback()
                };
                
                for (boost::asio::ip::address& address : addresses) {
                    bool opened = Socket::OpenAcceptor(acceptor_, address, 
                        IPEndPoint::MinPort, configuration_->tcp.backlog, configuration_->tcp.fast_open, configuration_->tcp.turbo);
                    if (opened) {

                        boost::system::error_code ec;
                        boost::asio::ip::tcp::endpoint localEP = acceptor_.local_endpoint(ec);
                        if (ec) {
                            Socket::Closesocket(acceptor_);
                            return false;
                        }
                        
                        local_endpoint_ = localEP;
                        Socket::SetWindowSizeIfNotZero(acceptor_.native_handle(), configuration_->tcp.cwnd, configuration_->tcp.rwnd);
                        return true;
                    }

                    Socket::Closesocket(acceptor_);
                }

                return false;
            }

            static ppp::string IFORWARDING_REWRITE_PROXY_URI(const ppp::string& url, ppp::string& username, ppp::string& password) noexcept {
                username = "";
                password = "";

                if (url.empty()) {
                    return ppp::string();
                }

                std::size_t left_index = url.find("//");
                if (left_index == std::string::npos) {
                    return url;
                }

                ppp::string seg = url.substr(left_index + 2);
                if (seg.empty()) {
                    return url;
                }

                std::size_t reft_index = seg.find('@');
                if (reft_index == std::string::npos) {
                    return url;
                }

                ppp::string param = seg.substr(0, reft_index);
                if (!param.empty()) {
                    std::size_t coln_index = param.find(':');
                    if (coln_index != std::string::npos) {
                        username = param.substr(0, coln_index);
                        password = param.substr(coln_index + 1);

                        if (username.empty() || password.empty()) {
                            username = "";
                            password = "";
                        }
                    }
                }

                ppp::string new_url = url.substr(0, left_index) + "//" + seg.substr(reft_index + 1);
                return new_url;
            }

            int IForwarding::OpenInternal() noexcept {
                if (NULL == context_ || NULL == configuration_) {
                    return -1;
                }

                ppp::string proxy_uername;
                ppp::string proxy_password;
                ppp::string proxy_url = IFORWARDING_REWRITE_PROXY_URI(configuration_->client.server_proxy, proxy_uername, proxy_password);
                if (proxy_url.empty()) {
                    return -1;
                }

                if (acceptor_.is_open()) {
                    return -1;
                }

                ResetSS();
                if (!IFORWARDING_VERIFY_PROXY_URI(proxy_url, server_.url, server_.endpoint, server_.protocol)) {
                    return 0;
                }

                server_.username = proxy_uername;
                server_.password = proxy_password;
                return OpenAcceptor() ? 1 : 0;
            }

            bool IForwarding::LoopAcceptSocket() noexcept {
                auto self = shared_from_this();
                return Socket::AcceptLoopbackSchedulerAsync(acceptor_, 
                    [self, this](const Socket::AsioContext& context, const Socket::AsioStrandPtr& strand, const Socket::AsioTcpSocket& socket) noexcept {
                        bool accepted = ProcessAcceptSocket(context, strand, socket);
                        if (!accepted) {
                            Socket::Closesocket(socket);
                        }

                        return accepted;
                    });
            }

            bool IForwarding::Open() noexcept {
                if (disposed_) {
                    return false;
                }
                
                int status = OpenInternal();
                if (status < 0) {
                    return false;
                }
                elif(status > 0 && LoopAcceptSocket()) {
                    return true;
                }
                
                ResetSS();
                return false;
            }
        
            IForwarding::TimerPtr IForwarding::SetTimeoutHandler(const std::shared_ptr<boost::asio::io_context>& context, int milliseconds, const ppp::function<void()>& handler) noexcept {
                if (NULL == context || disposed_) {
                    return NULL;
                }

                if (milliseconds < 1) {
                    milliseconds = 1;
                }

                auto self = shared_from_this();
                TimerPtr timer = Timer::Timeout(context, milliseconds, 
                    [self, this, handler](Timer* t) noexcept {
                        bool removed = TryRemove(t, true);
                        if (removed) {
                            if (handler) {
                                handler();
                            }
                        }
                    });

                if (NULL == timer) {
                    return NULL;
                }

                bool added = TryAdd(timer);
                if (added) {
                    return timer;
                }

                timer->Stop();
                timer->Dispose();
                return NULL;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> IForwarding::NewAsynchronousSocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::net::Socket::AsioStrandPtr& strand) noexcept {
                if (NULL == context) {
                    return NULL;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> remote_socket = strand ? 
                    make_shared_object<boost::asio::ip::tcp::socket>(*strand) : 
                    make_shared_object<boost::asio::ip::tcp::socket>(*context);
                if (NULL == remote_socket) {
                    return NULL;
                }

                boost::asio::ip::tcp::endpoint& server_endpoint = server_.endpoint;
                boost::asio::ip::address server_address = server_endpoint.address();

                boost::system::error_code ec;
                remote_socket->open(server_endpoint.protocol(), ec);

                if (ec) {
                    return NULL;
                }

                int handle = remote_socket->native_handle();
                ppp::net::Socket::AdjustDefaultSocketOptional(handle, server_address.is_v4());
                ppp::net::Socket::SetTypeOfService(handle);
                ppp::net::Socket::SetSignalPipeline(handle, false);
                ppp::net::Socket::ReuseSocketAddress(handle, true);
                ppp::net::Socket::SetWindowSizeIfNotZero(handle, configuration_->tcp.cwnd, configuration_->tcp.rwnd);

                return remote_socket;
            }

            bool IForwarding::PROXY_SOCKET_SPECIAL_PROCESS(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, YieldContext& y, ProxyConnection& proxy_connection) noexcept {
                if (NULL == socket || !socket->is_open()) {
                    return false;
                }

                boost::asio::ip::tcp::endpoint& server_endpoint = server_.endpoint;
                boost::asio::ip::address server_address = server_endpoint.address();

#if defined(_WIN32)
                if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                    proxy_connection.qoss_[1] = ppp::net::QoSS::New(socket->native_handle(), server_address, server_endpoint.port());
                }
#elif defined(_LINUX)
                // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter. 
                // IPV6 does not need to be linked, because VPN is IPV4, 
                // And IPV6 does not affect the physical layer network communication of the VPN.
                if (server_address.is_v4() && !server_address.is_loopback()) {
                    auto protector_network = ProtectorNetwork; 
                    if (NULL != protector_network) {
                        if (!protector_network->Protect(socket->native_handle(), y)) {
                            return false;
                        }
                    }
                }
#endif

                return true;
            }

            bool IForwarding::ConnectToProxyServer(
                const std::shared_ptr<boost::asio::io_context>&         context, 
                const ppp::net::Socket::AsioStrandPtr&                  strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&    local_socket,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&    proxy_socket,
                YieldContext&                                           y,
                bool                                                    http_or_socks_protocol) noexcept {
                
                if (disposed_) {
                    return false;
                }

                auto self = shared_from_this();
                std::shared_ptr<ProxyConnection> proxy_connection = make_shared_object<ProxyConnection>(self, configuration_, context, strand);
                if (NULL == proxy_connection) {
                    return false;
                }

                if (!PROXY_SOCKET_SPECIAL_PROCESS(proxy_socket, y, *proxy_connection)) {
                    return false;
                }
                
                if (!ppp::coroutines::asio::async_connect(*proxy_socket, server_.endpoint, y)) {
                    return false;
                }

                if (http_or_socks_protocol) {
                    if (!HTTP_SendHandshakePacket(proxy_socket, y)) {
                        return false;
                    }

                    std::shared_ptr<Byte> overflow_buffer;
                    int overflow_offset = 0;
                    int overflow_length = 0;

                    if (!HTTP_ReadHandshakePacket(proxy_socket, y, overflow_buffer, overflow_offset, overflow_length)) {
                        return false;
                    }

                    if (overflow_length > 0) {
                        if (!ppp::coroutines::asio::async_write(*local_socket, boost::asio::buffer(overflow_buffer.get() + overflow_offset, overflow_length), y)) {
                            return false;
                        }
                    }
                }
                elif(!SOCKS_Handshake(proxy_socket, y)) {
                    return false;
                }

                if (proxy_connection->Forward(local_socket, proxy_socket)) {
                    if (TryAdd(proxy_connection)) {
                        return true;
                    }
                }

                proxy_connection->Dispose();
                return false;
            }

            bool IForwarding::ConnectToProxyServer(const std::shared_ptr<boost::asio::io_context>& context, const ppp::net::Socket::AsioStrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, Timer* timeout_key) noexcept {
                if (NULL == context || NULL == socket) {
                    return false;
                }
                
                ProtocolType protocol_type = server_.protocol;
                if (protocol_type != ProtocolType_HttpProxy && protocol_type != ProtocolType_SocksProxy) {
                    return false;
                }
                
                std::shared_ptr<boost::asio::ip::tcp::socket> proxy_socket = NewAsynchronousSocket(context, strand);
                if (NULL == proxy_socket) {
                    return false;
                }

                Timer* proxy_timeout_key = SetTimeoutAutoClosesocket(context, strand, proxy_socket);
                if (NULL == proxy_timeout_key) {
                    return false;
                }
                
                auto self = shared_from_this();
                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = configuration_->GetBufferAllocator();

                bool spawned = YieldContext::Spawn(allocator.get(), *context, strand.get(),
                    [self, this, socket, proxy_socket, timeout_key, proxy_timeout_key, context, strand](YieldContext& y) noexcept {
                        bool handshaked = false;
                        if (server_.protocol == ProtocolType_HttpProxy) {
                            handshaked = ConnectToProxyServer(context, strand, socket, proxy_socket, y, true);
                        }
                        elif(server_.protocol == ProtocolType_SocksProxy) {
                            handshaked = ConnectToProxyServer(context, strand, socket, proxy_socket, y, false);
                        }

                        TryRemove(timeout_key, true);
                        TryRemove(proxy_timeout_key, true);

                        if (!handshaked) {
                            Socket::Closesocket(socket);
                            Socket::Closesocket(proxy_socket);
                        }
                    });
                if (spawned) {
                    return true;
                }

                TryRemove(proxy_timeout_key, true);
                return spawned;
            }

            bool IForwarding::ProcessAcceptSocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::net::Socket::AsioStrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
                if (!ppp::net::Socket::AdjustDefaultSocketOptional(*socket, configuration_->tcp.turbo)) {
                    return false;
                }
                else {
                    ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration_->tcp.cwnd, configuration_->tcp.rwnd);
                }
                
                Timer* timeout_key = SetTimeoutAutoClosesocket(context, strand, socket);
                if (NULL == timeout_key) {
                    return false;
                }

                bool connected = ConnectToProxyServer(context, strand, socket, timeout_key);
                if (connected) {
                    return true;
                }

                TryRemove(timeout_key, true);
                return false;
            }

            IForwarding::Timer* IForwarding::SetTimeoutAutoClosesocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::net::Socket::AsioStrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
                if (NULL == context || disposed_) {
                    return NULL;
                }
                
                uint64_t timeout_milliseconds = ((uint64_t)configuration_->tcp.connect.timeout) * 1000ULL;
                timeout_milliseconds = std::min<uint64_t>(timeout_milliseconds, INT32_MAX);

                auto self = shared_from_this();
                return SetTimeoutHandler(context, static_cast<int>(timeout_milliseconds),
                    [self, this, socket, context, strand]() noexcept {
                        auto closesocket_cb = 
                            [self, this, socket]() noexcept {
                                Socket::Closesocket(socket);
                            };
                        Executors::Post(context, strand, closesocket_cb);
                    }).get();
            }

            boost::asio::ip::tcp::endpoint IForwarding::GetLocalEndPoint() noexcept {
                boost::asio::ip::address address_ip = local_endpoint_.address();
                if (address_ip.is_v4()) {
                    return boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), local_endpoint_.port());
                }
                elif(address_ip.is_v6()) {
                    return boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::loopback(), local_endpoint_.port());
                }
                else {
                    return boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4(IPEndPoint::AnyAddress), IPEndPoint::MinPort);
                }
            }

            void IForwarding::Update(UInt64 now) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                Dictionary::UpdateAllObjects(connections_, now);
            }

            void IForwarding::Finalize() noexcept {
                ProxyConnectionTable connections;
                SocketTable sockets;
                TimerTable timers;
                
                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    sockets = std::move(sockets_);
                    sockets_.clear();

                    timers = std::move(timers_);
                    timers_.clear();

                    connections = std::move(connections_);
                    connections_.clear();
                    break;
                }

                disposed_ = true;
                for (auto&& kv : sockets) {
                    Socket::Closesocket(kv.second);
                }

                ResetSS();
                Socket::Closesocket(acceptor_);

                Dictionary::ReleaseAllObjects(timers);
                Dictionary::ReleaseAllObjects(connections);
            }
        
            template <class Address>
            static inline void IFORWARDING_SOCKS_HANDSHAKE_CONCAT_ADDRESS(Byte* data, int& length, const Address& address) noexcept {
                auto bytes = address.to_bytes();
                auto bsize = bytes.size();

                memcpy(data + length, bytes.data(), bsize);
                length += bsize;
            }

            bool IForwarding::SOCKS_Handshake(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, YieldContext& y) noexcept {

                if (NULL == socket || !socket->is_open()) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                Byte method = 0;
                if (!server_.username.empty() && !server_.password.empty()) {
                    method = 2;
                }

                /*
                    +----+----------+----------+
                    | VER | NMETHODS | METHODS |
                    +----+----------+----------+
                    | 1 | 1 | 1 to 255 |
                    +----+----------+----------+
                 */
                static constexpr Byte ver = 5;

                Byte data[512];
                data[0] = ver;

                if (method != 0) {
                    data[1] = 1;
                    data[2] = method;
                }
                else {
                    data[1] = 0;
                    data[2] = 0;
                }

                for (;;) {
                    if (!ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(data, 3), y)) {
                        return false;
                    }

                    if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 2), y)) {
                        return false;
                    }

                    if (data[0] != ver) {
                        return false;
                    }

                    /*
                     * If the socks5 server does not require password authentication, then set method to 0, 
                     * Otherwise determine if socks5 has selected the user password authentication method.
                    */
                    Byte auth = data[1];
                    if (auth == 0) {
                        method = 0;
                        break;
                    }
                    elif(auth == method) {
                        break;
                    }

                    return false;
                }

                // Process user password authentication.
                if (method != 0) {
                    static constexpr Byte auth = 1;

                    std::size_t username_size = server_.username.size();
                    std::size_t password_size = server_.password.size();

                    MemoryStream ms;
                    ms.WriteByte(auth);

                    ms.WriteByte(static_cast<Byte>(username_size));
                    ms.Write(server_.username.data(), 0, username_size);

                    ms.WriteByte(static_cast<Byte>(password_size));
                    ms.Write(server_.password.data(), 0, password_size);

                    std::shared_ptr<Byte> buf = ms.GetBuffer();
                    if (NULL == buf) {
                        return false;
                    }

                    int buf_size = ms.GetPosition();
                    if (buf_size < 3) {
                        return false;
                    }

                    if (!ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(buf.get(), buf_size), y)) {
                        return false;
                    }

                    if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 2), y)) {
                        return false;
                    }

                    if (data[0] != auth) {
                        return false;
                    }

                    if (data[1] != 0) {
                        return false;
                    }
                }

                // Process connect to destination.
                for (;;) {
                    /*
                        +----+-----+-------+------+----------+----------+
    　　                |VER | CMD |　RSV　| ATYP | DST.ADDR | DST.PORT |
    　　                +----+-----+-------+------+----------+----------+
    　　                | 1　| 　1 | X'00' | 　1　| Variable |　　 2　　|
    　　                +----+-----+-------+------+----------+----------+
                    */

                    int length = 0;
                    data[length++] = ver;
                    data[length++] = 1; /* CONNECT: 1, BIND: 2, UDP: 3 */
                    data[length++] = 0;

                    boost::system::error_code ec;
                    boost::asio::ip::address address = StringToAddress(server_.host, ec);
                    if (ec) {
                        std::size_t host_size = server_.host.size();
                        data[length++] = 3; // DOMAIN
                        data[length++] = static_cast<Byte>(host_size);

                        std::size_t next_size = length + host_size;
                        if ((next_size) >= (sizeof(data) - 2)) {
                            return false;
                        }

                        memcpy(data + length, server_.host.data(), host_size);
                        length = next_size;
                    }
                    elif(address.is_v4()) {
                        data[length++] = 1; // IPV4

                        IFORWARDING_SOCKS_HANDSHAKE_CONCAT_ADDRESS(data, length, address.to_v4());
                    }
                    elif(address.is_v6()) {
                        data[length++] = 4; // IPV6

                        IFORWARDING_SOCKS_HANDSHAKE_CONCAT_ADDRESS(data, length, address.to_v6());
                    }
                    else {
                        return false;
                    }
                    
                    data[length++] = (Byte)(server_.port >> 8);
                    data[length++] = (Byte)(server_.port);

                    if (!ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(data, length), y)) {
                        return false;
                    }

                    break;
                }
            
                // +----+-----+-------+------+----------+----------+
                // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
                // +----+-----+-------+------+----------+----------+
                // | 1  |  1  | X'00' |  1   | Variable |    2     |
                // +----+-----+-------+------+----------+----------+
                for (;;) {
                    if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 4), y)) {
                        return false;
                    }

                    if (data[0] != ver) {
                        return false;
                    }

                    if (data[1] != 0) {
                        return false;
                    }

                    Byte address_size = 0;
                    Byte address_type = data[3];

                    if (address_type == 1) { // IPV4
                        address_size = 4;
                    }
                    elif(address_type == 4) { // IPV6
                        address_size = 16;
                    }
                    elif(address_type == 3) { // DOMIAN
                        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(&address_size, 1), y)) {
                            return false;
                        }
                    }
                    else {
                        return false;
                    }

                    std::size_t address_and_port_size = address_size + 2;
                    if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, address_and_port_size), y)) {
                        return false;
                    }

                    break;
                }

                return true;
            }
        }
    }
}