#pragma once

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
                typedef ppp::app::protocol::VirtualEthernetInformation          VirtualEthernetInformation;
                typedef ppp::function<void(bool, VirtualEthernetInformation*)>  AuthenticationToManagedServerAsyncCallback;
                typedef ppp::coroutines::YieldContext                           YieldContext;
                typedef ppp::configurations::AppConfiguration                   AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                       AppConfigurationPtr;
                typedef ppp::function<void(bool)>                               TryVerifyUriAsyncCallback;
                typedef ppp::threading::Timer                                   Timer;
                typedef std::shared_ptr<Timer>                                  TimerPtr;
                typedef std::mutex                                              SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                     SynchronizedObjectScope;

            private:
                typedef struct {
                    uint64_t                                                    timeout;
                    AuthenticationToManagedServerAsyncCallback                  ac;
                }                                                               AuthenticationWaitable;
                typedef ppp::unordered_map<Int128, AuthenticationWaitable>      AuthenticationWaitableTable;
                typedef ppp::net::asio::websocket                               WebSocket;
                typedef std::shared_ptr<WebSocket>                              WebSocketPtr;
                typedef ppp::unordered_map<void*, TimerPtr>                     TimerTable;

            public:
                VirtualEthernetManagedServer(const std::shared_ptr<VirtualEthernetSwitcher>& switcher) noexcept;

            public:
                std::shared_ptr<VirtualEthernetManagedServer>                   GetReference() noexcept;
                AppConfigurationPtr                                             GetConfiguration() noexcept;
                std::shared_ptr<ppp::threading::BufferswapAllocator>            GetBufferswapAllocator() noexcept;
                SynchronizedObject&                                             GetSynchronizedObject() noexcept;
                virtual bool                                                    TryVerifyUriAsync(const ppp::string& url, const TryVerifyUriAsyncCallback& ac) noexcept;
                virtual bool                                                    ConnectToManagedServer(const ppp::string& url) noexcept;
                virtual void                                                    Update() noexcept;
                virtual bool                                                    LinkIsAvailable() noexcept;

            public:
                virtual bool                                                    AuthenticationToManagedServer(const ppp::Int128& session_id, const AuthenticationToManagedServerAsyncCallback& ac) noexcept;

            protected:
                bool                                                            SendToManagedServer(const ppp::Int128& session_id, int cmd) noexcept;
                virtual bool                                                    SendToManagedServer(const ppp::Int128& session_id, int cmd, const ppp::string& data) noexcept;
                virtual bool                                                    SendToManagedServer(const ppp::Int128& session_id, int cmd, const Json::Value& data) noexcept;

            private:
                AuthenticationToManagedServerAsyncCallback                      DeleteAuthenticationToManagedServer(const ppp::Int128& session_id) noexcept;
                void                                                            TickAllAuthenticationToManagedServer() noexcept;
                void                                                            RunInner(const ppp::string& url, YieldContext& y) noexcept;
                bool                                                            TryGetManagedServerEndPoint(const ppp::string& url, ppp::string& host, ppp::string& path, boost::asio::ip::tcp::endpoint& remoteEP, YieldContext& y) noexcept;

            private:
                void                                                            Run(WebSocketPtr& websocket, YieldContext& y) noexcept;
                void                                                            AckAuthenticationToManagedServer(Json::Value& json) noexcept;
                WebSocketPtr                                                    NewWebSocketConnectToManagedServer2(const ppp::string& url, YieldContext& y) noexcept;
                WebSocketPtr                                                    NewWebSocketConnectToManagedServer(const ppp::string& url, YieldContext& y) noexcept;

            private:
                SynchronizedObject                                              syncobj_;
                bool                                                            disposed_;
                std::shared_ptr<VirtualEthernetSwitcher>                        switcher_;
                std::shared_ptr<boost::asio::io_context>                        context_;
                WebSocketPtr                                                    server_;
                std::shared_ptr<ppp::threading::BufferswapAllocator>            allocator_;
                AppConfigurationPtr                                             configuration_;
                AuthenticationWaitableTable                                     authentications_;
            };
        }
    }
}