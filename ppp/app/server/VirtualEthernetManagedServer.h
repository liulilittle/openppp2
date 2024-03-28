#pragma once

#include <ppp/Int128.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Timer.h>
#include <ppp/net/asio/websocket.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetSwitcher;

            // Connect to Virtual Ethernet management servers and manage user authentication, QOS, and user traffic usage records.
            class VirtualEthernetManagedServer : public std::enable_shared_from_this<VirtualEthernetManagedServer> {
            public:
                typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
                typedef std::shared_ptr<VirtualEthernetInformation>                 VirtualEthernetInformationPtr;
                typedef ppp::function<void(bool, VirtualEthernetInformationPtr&)>   AuthenticationToManagedServerAsyncCallback;
                typedef ppp::coroutines::YieldContext                               YieldContext;
                typedef ppp::configurations::AppConfiguration                       AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                           AppConfigurationPtr;
                typedef ppp::function<void(bool)>                                   TryVerifyUriAsyncCallback;
                typedef ppp::threading::Timer                                       Timer;
                typedef std::shared_ptr<Timer>                                      TimerPtr;
                typedef std::mutex                                                  SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                         SynchronizedObjectScope;

            private:
                typedef struct {
                    uint64_t                                                        timeout;
                    AuthenticationToManagedServerAsyncCallback                      ac;
                }                                                                   AuthenticationWaitable;
                typedef ppp::unordered_map<Int128, AuthenticationWaitable>          AuthenticationWaitableTable;
                typedef ppp::unordered_map<void*, TimerPtr>                         TimerTable;
                struct UploadTrafficTask {
                    int64_t                                                         rx = 0;
                    int64_t                                                         tx = 0;
                };
                typedef ppp::unordered_map<Int128, UploadTrafficTask>               UploadTrafficTaskTable;
                typedef ppp::net::asio::websocket                                   WebSocket;
                typedef ppp::net::asio::sslwebsocket                                WebSocketSsl;
                struct IWebSocket { // Composite 
                public:
                    typedef WebSocket::AsynchronousWriteCallback                    AsynchronousWriteCallback;
                    typedef WebSocket::HandshakeType                                HandshakeType;

                public:
                    void                                                            Dispose() noexcept;
                    bool                                                            IsDisposed() noexcept;
                    bool                                                            Read(const void* buffer, int offset, int length, YieldContext& y) noexcept;
                    bool                                                            Run(HandshakeType type, const ppp::string& host, const ppp::string& path, YieldContext& y) noexcept;
                    bool                                                            Write(const void* buffer, int offset, int length, const AsynchronousWriteCallback& cb) noexcept;

                public:
                    std::shared_ptr<WebSocket>                                      ws;
                    std::shared_ptr<WebSocketSsl>                                   wss;  
                    AppConfigurationPtr                                             configuration;
                };
                typedef std::shared_ptr<IWebSocket>                                 IWebScoketPtr;

            public:
                VirtualEthernetManagedServer(const std::shared_ptr<VirtualEthernetSwitcher>& switcher) noexcept;

            public:
                std::shared_ptr<VirtualEthernetManagedServer>                       GetReference() noexcept;
                AppConfigurationPtr                                                 GetConfiguration() noexcept;
                std::shared_ptr<ppp::threading::BufferswapAllocator>                GetBufferswapAllocator() noexcept;
                SynchronizedObject&                                                 GetSynchronizedObject() noexcept;
                ppp::string                                                         GetUri() noexcept;
                bool                                                                LinkIsAvailable() noexcept;
                bool                                                                LinkIsReconnecting() noexcept;
                virtual void                                                        Dispose() noexcept;
                virtual bool                                                        TryVerifyUriAsync(const ppp::string& url, const TryVerifyUriAsyncCallback& ac) noexcept;
                virtual bool                                                        ConnectToManagedServer(const ppp::string& url) noexcept;
                virtual bool                                                        Update(UInt64 now) noexcept;
                virtual int                                                         NewId() noexcept;

            public:
                virtual bool                                                        AuthenticationToManagedServer(const ppp::Int128& session_id, const AuthenticationToManagedServerAsyncCallback& ac) noexcept;
                virtual void                                                        UploadTrafficToManagedServer(const ppp::Int128& session_id, int64_t rx, int64_t tx) noexcept;

            protected:
                bool                                                                SendToManagedServer(const ppp::Int128& session_id, int cmd, int id) noexcept;
                virtual bool                                                        SendToManagedServer(const ppp::Int128& session_id, int cmd, int id, const ppp::string& data) noexcept;
                virtual bool                                                        SendToManagedServer(const ppp::Int128& session_id, int cmd, int id, const Json::Value& data) noexcept;

            private:
                AuthenticationToManagedServerAsyncCallback                          DeleteAuthenticationToManagedServer(const ppp::Int128& session_id) noexcept;
                void                                                                TickAllAuthenticationToManagedServer(UInt64 now) noexcept;
                void                                                                TickEchoToManagedServer(UInt64 now) noexcept;
                void                                                                RunInner(const ppp::string& url, YieldContext& y) noexcept;
                ppp::string                                                         GetManagedServerEndPoint(const ppp::string& url, ppp::string& host, ppp::string& path, boost::asio::ip::tcp::endpoint& remoteEP, bool& ssl, YieldContext& y) noexcept;
                bool                                                                TickAllUploadTrafficToManagedServer(UInt64 now) noexcept;

            private:
                void                                                                Run(IWebScoketPtr& websocket, YieldContext& y) noexcept;
                bool                                                                AckAuthenticationToManagedServer(Json::Value& json, YieldContext& y) noexcept;
                bool                                                                AckAllUploadTrafficToManagedServer(Json::Value& json, YieldContext& y) noexcept;
                IWebScoketPtr                                                       NewWebSocketConnectToManagedServer2(const ppp::string& url, YieldContext& y) noexcept;
                IWebScoketPtr                                                       NewWebSocketConnectToManagedServer(const ppp::string& url, YieldContext& y) noexcept;

            private:
                SynchronizedObject                                                  syncobj_;
                struct {
                    bool                                                            disposed_      : 1;
                    bool                                                            reconnecting_  : 7;
                };
                std::atomic<int>                                                    aid_           = 0;
                UInt64                                                              echotest_next_ = 0;
                UInt64                                                              traffics_next_ = 0;
                ppp::string                                                         url_;
                std::shared_ptr<VirtualEthernetSwitcher>                            switcher_;
                std::shared_ptr<boost::asio::io_context>                            context_;
                IWebScoketPtr                                                       server_;
                std::shared_ptr<ppp::threading::BufferswapAllocator>                allocator_;
                AppConfigurationPtr                                                 configuration_;
                UploadTrafficTaskTable                                              traffics_;
                AuthenticationWaitableTable                                         authentications_;
            };
        }
    }
}