#pragma once 

#include <ppp/stdafx.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Socket.h>
#include <ppp/net/rinetd/RinetdConnection.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/configurations/AppConfiguration.h>

#if defined(_WIN32)
#include <windows/ppp/net/QoSS.h>
#elif defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace ppp {
    namespace transmissions {
        namespace proxys {
            class IForwarding : public std::enable_shared_from_this<IForwarding> {
                friend class                                                ProxyConnection;

            public:
                enum ProtocolType {
                    ProtocolType_HttpProxy,
                    ProtocolType_SocksProxy,
                };
                typedef ppp::configurations::AppConfiguration               AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                   AppConfigurationPtr;
                typedef ppp::coroutines::YieldContext                       YieldContext;
                typedef std::shared_ptr<boost::asio::io_context>            ContextPtr;
                typedef std::mutex                                          SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                 SynchronizedObjectScope;
#if defined(_LINUX)
                typedef std::shared_ptr<ppp::net::ProtectorNetwork>         ProtectorNetworkPtr;

            public:
                ProtectorNetworkPtr                                         ProtectorNetwork;
#endif

            private:
                class                                                       ProxyConnection;
                typedef std::shared_ptr<ProxyConnection>                    ProxyConnectionPtr;
                typedef ppp::unordered_map<void*, ProxyConnectionPtr>       ProxyConnectionTable;
                typedef std::shared_ptr<boost::asio::ip::tcp::socket>       SocketPtr;
                typedef ppp::unordered_map<void*, SocketPtr>                SocketTable;
                typedef ppp::threading::Timer                               Timer;
                typedef std::shared_ptr<Timer>                              TimerPtr;
                typedef ppp::unordered_map<void*, TimerPtr>                 TimerTable;

            public: 
                IForwarding(        
                    const ContextPtr&                                       context, 
                    const AppConfigurationPtr&                              configuration) noexcept;
                virtual ~IForwarding() noexcept;

            public:
                ContextPtr                                                  GetContext()                noexcept { return context_; }
                AppConfigurationPtr                                         GetConfiguration()          noexcept { return configuration_; }
                std::shared_ptr<IForwarding>                                GetReference()              noexcept { return shared_from_this(); }
                SynchronizedObject&                                         GetSynchronizedObject()     noexcept { return syncobj_; }
                bool                                                        Open()                      noexcept;
                void                                                        Dispose()                   noexcept;
                void                                                        Update(UInt64 now)          noexcept;
                ProtocolType&                                               GetProtocolType()           noexcept { return server_.protocol; }
                ppp::string&                                                GetProxyUrl()               noexcept { return server_.url; }
                boost::asio::ip::tcp::endpoint&                             GetProxyEndPoint()          noexcept { return server_.endpoint; }
                boost::asio::ip::tcp::endpoint                              GetLocalEndPoint()          noexcept;
                IForwarding&                                                SetRemoteEndPoint(          
                    const ppp::string&                                      host, 
                    int                                                     port)                       noexcept;
                ppp::string&                                                GetRemoteHost()             noexcept { return server_.host; }
                int&                                                        GetRemotePort()             noexcept { return server_.port; }

            private:
                TimerPtr                                                    SetTimeoutHandler(const std::shared_ptr<boost::asio::io_context>& context, int milliseconds, const ppp::function<void()>& handler) noexcept;
                Timer*                                                      SetTimeoutAutoClosesocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::net::Socket::AsioStrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
                void                                                        Finalize() noexcept; 
                void                                                        ResetSS() noexcept;
                bool                                                        OpenAcceptor() noexcept;
                int                                                         OpenInternal() noexcept;
                bool                                                        LoopAcceptSocket() noexcept;
                bool                                                        ProcessAcceptSocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::net::Socket::AsioStrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
                std::shared_ptr<boost::asio::ip::tcp::socket>               NewAsynchronousSocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::net::Socket::AsioStrandPtr& strand) noexcept;
                bool                                                        ConnectToProxyServer(const std::shared_ptr<boost::asio::io_context>& context, const ppp::net::Socket::AsioStrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, Timer* timeout_key) noexcept;
                bool                                                        ConnectToProxyServer(
                    const std::shared_ptr<boost::asio::io_context>&         context, 
                    const ppp::net::Socket::AsioStrandPtr&                  strand,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    local_socket,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    proxy_socket,
                    YieldContext&                                           y,
                    bool                                                    http_or_socks_protocol) noexcept;

            private:
                bool                                                        TryAdd(const SocketPtr& socket) noexcept;
                bool                                                        TryAdd(const ProxyConnectionPtr& connection) noexcept;
                bool                                                        TryAdd(const TimerPtr& connection) noexcept;
                bool                                                        TryRemove(boost::asio::ip::tcp::socket* socket, bool disposing) noexcept;
                bool                                                        TryRemove(ProxyConnection* connection, bool disposing) noexcept;
                bool                                                        TryRemove(Timer* timer, bool disposing) noexcept;

            private:
                bool                                                        PROXY_SOCKET_SPECIAL_PROCESS(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, YieldContext& y, ProxyConnection& proxy_connection) noexcept;
                bool                                                        SOCKS_Handshake(
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    YieldContext&                                           y) noexcept;
                bool                                                        HTTP_SendHandshakePacket(
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    YieldContext&                                           y) noexcept;
                bool                                                        HTTP_ReadHandshakePacket(
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    YieldContext&                                           y,
                    std::shared_ptr<Byte>&                                  overflow_buffer,
                    int&                                                    overflow_offset,
                    int&                                                    overflow_length) noexcept;

            private:
                SynchronizedObject                                          syncobj_;      
                bool                                                        disposed_ = false;          
                ContextPtr                                                  context_;
                AppConfigurationPtr                                         configuration_;
                struct {
                    ProtocolType                                            protocol;
                    ppp::string                                             host;
                    int                                                     port = 0;
                    ppp::string                                             username;
                    ppp::string                                             password;
                    ppp::string                                             url;
                    boost::asio::ip::tcp::endpoint                          endpoint;
                }                                                           server_;
                TimerTable                                                  timers_;
                SocketTable                                                 sockets_;
                ProxyConnectionTable                                        connections_;
                boost::asio::ip::tcp::acceptor                              acceptor_;
                boost::asio::ip::tcp::endpoint                              local_endpoint_;
            };
        }
    }
}