#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/net/Firewall.h>
#include <ppp/net/native/rib.h>
#include <ppp/threading/Timer.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetManagedServer;
            class VirtualEthernetExchanger;
            class VirtualEthernetNetworkTcpipConnection;

            /* 虚拟以太网交换机 */
            class VirtualEthernetSwitcher : public std::enable_shared_from_this<VirtualEthernetSwitcher> { 
                friend class VirtualEthernetNetworkTcpipConnection;
                friend class VirtualEthernetExchanger;
                friend class VirtualEthernetManagedServer;
                typedef struct {
                    uint32_t                                            IPAddress;
                    uint32_t                                            SubmaskAddress;
                    std::shared_ptr<VirtualEthernetExchanger>           Exchanger;
                }                                                       NatInformation;
                typedef std::shared_ptr<NatInformation>                 NatInformationPtr;
                typedef std::unordered_map<uint32_t, NatInformationPtr> NatInformationTable;

            public:
                typedef ppp::app::protocol::VirtualEthernetInformation  VirtualEthernetInformation;
                typedef std::shared_ptr<VirtualEthernetInformation>     VirtualEthernetInformationPtr;
                typedef std::shared_ptr<VirtualEthernetExchanger>       VirtualEthernetExchangerPtr;
                typedef ppp::unordered_map<Int128,
                    VirtualEthernetExchangerPtr>                        VirtualEthernetExchangerTable;
                typedef std::shared_ptr<VirtualEthernetManagedServer>   VirtualEthernetManagedServerPtr;
                typedef ppp::app::protocol::VirtualEthernetLogger       VirtualEthernetLogger;
                typedef std::shared_ptr<VirtualEthernetLogger>          VirtualEthernetLoggerPtr;
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::transmissions::ITransmission               ITransmission;
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                typedef ppp::threading::Timer                           Timer;
                typedef std::shared_ptr<Timer>                          TimerPtr;
                typedef ppp::net::Firewall                              Firewall;
                typedef std::shared_ptr<ppp::net::Firewall>             FirewallPtr;
                typedef std::shared_ptr<boost::asio::io_context>        ContextPtr;
                typedef ppp::coroutines::YieldContext                   YieldContext;
                typedef std::mutex                                      SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
                typedef ppp::transmissions::ITransmissionStatistics     ITransmissionStatistics;
                typedef std::shared_ptr<ITransmissionStatistics>        ITransmissionStatisticsPtr;
                typedef std::shared_ptr<
                    VirtualEthernetNetworkTcpipConnection>              VirtualEthernetNetworkTcpipConnectionPtr;
                typedef ppp::unordered_map<void*,
                    VirtualEthernetNetworkTcpipConnectionPtr>           VirtualEthernetNetworkTcpipConnectionTable;

            public:
                VirtualEthernetSwitcher(const AppConfigurationPtr& configuration) noexcept;
                virtual ~VirtualEthernetSwitcher() noexcept;

            public:
                int                                                     GetNode() noexcept;
                std::shared_ptr<VirtualEthernetSwitcher>                GetReference() noexcept;
                FirewallPtr                                             GetFirewall() noexcept;
                ContextPtr                                              GetContext() noexcept;
                AppConfigurationPtr                                     GetConfiguration() noexcept;
                SynchronizedObject&                                     GetSynchronizedObject() noexcept;
                VirtualEthernetLoggerPtr                                GetLogger() noexcept { return logger_; }
                VirtualEthernetManagedServerPtr                         GetManagedServer() noexcept;

            public:
                virtual bool                                            Open(const ppp::string& firewall) noexcept;
                virtual bool                                            Run() noexcept;
                virtual void                                            Dispose() noexcept;
                virtual bool                                            IsDisposed() noexcept;

            public:
                ITransmissionStatisticsPtr&                             GetStatistics() noexcept;
                boost::asio::ip::address                                GetInterfaceIP() noexcept;
                boost::asio::ip::udp::endpoint                          GetDnsserverEndPoint() noexcept;
                std::shared_ptr<boost::asio::ip::tcp::resolver>&        GetTResolver() noexcept { return tresolver_; }
                std::shared_ptr<boost::asio::ip::udp::resolver>&        GetUResolver() noexcept { return uresolver_; }
                int                                                     GetAllExchangerNumber() noexcept;

            public:
                typedef enum {
                    NetworkAcceptorCategories_Min,
                    NetworkAcceptorCategories_Tcpip = NetworkAcceptorCategories_Min,
                    NetworkAcceptorCategories_WebSocket,
                    NetworkAcceptorCategories_WebSocketSSL,
                    NetworkAcceptorCategories_CDN1,
                    NetworkAcceptorCategories_CDN2,
                    NetworkAcceptorCategories_Max,
                }                                                       NetworkAcceptorCategories;
                boost::asio::ip::tcp::endpoint                          GetLocalEndPoint(NetworkAcceptorCategories categories) noexcept;

            protected:
                virtual ITransmissionPtr                                Accept(int categories, const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
                virtual bool                                            Establish(const ITransmissionPtr& transmission, const Int128& session_id, const VirtualEthernetInformationPtr& i, YieldContext& y) noexcept;
                virtual bool                                            Connect(const ITransmissionPtr& transmission, const Int128& session_id, YieldContext& y) noexcept;
                virtual bool                                            OnTick(UInt64 now) noexcept;
                virtual bool                                            OnInformation(const Int128& session_id, const std::shared_ptr<VirtualEthernetInformation>& info, YieldContext& y) noexcept;

            protected:
                virtual VirtualEthernetLoggerPtr                        NewLogger() noexcept;
                virtual VirtualEthernetManagedServerPtr                 NewManagedServer() noexcept;
                virtual FirewallPtr                                     NewFirewall() noexcept;
                virtual ITransmissionStatisticsPtr                      NewStatistics() noexcept;
                virtual VirtualEthernetExchangerPtr                     NewExchanger(const ITransmissionPtr& transmission, const Int128& session_id) noexcept;
                virtual VirtualEthernetNetworkTcpipConnectionPtr        NewConnection(const ITransmissionPtr& transmission, const Int128& session_id) noexcept;

            private:
                void                                                    Finalize() noexcept;
                bool                                                    Accept(const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, int categories) noexcept;
                int                                                     Run(const ContextPtr& context, const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                VirtualEthernetExchangerPtr                             DeleteExchanger(VirtualEthernetExchanger* exchanger) noexcept;
                VirtualEthernetExchangerPtr                             GetExchanger(const Int128& session_id) noexcept;
                VirtualEthernetExchangerPtr                             AddNewExchanger(const ITransmissionPtr& transmission, const Int128& session_id) noexcept;
                VirtualEthernetNetworkTcpipConnectionPtr                AddNewConnection(const ITransmissionPtr& transmission, const Int128& session_id) noexcept;
                bool                                                    DeleteConnection(const VirtualEthernetNetworkTcpipConnection* connection) noexcept;

            private:
                boost::asio::ip::udp::endpoint                          ParseDNSEndPoint(const ppp::string& dnserver_endpoint) noexcept;
                void                                                    TickAllExchangers(UInt64 now) noexcept;
                void                                                    TickAllConnections(UInt64 now) noexcept;
                bool                                                    OpenManagedServerIfNeed() noexcept;

            private:
                bool                                                    CreateFirewall(const ppp::string& path) noexcept;
                void                                                    CloseAllAcceptors() noexcept;
                bool                                                    CreateAllAcceptors() noexcept;
                bool                                                    CloseAlwaysTimeout() noexcept;
                bool                                                    CreateAlwaysTimeout() noexcept;
                bool                                                    OpenLogger() noexcept;
                bool                                                    DeleteNatInformation(VirtualEthernetExchanger* key, uint32_t ip) noexcept;
                NatInformationPtr                                       FindNatInformation(uint32_t ip) noexcept;
                NatInformationPtr                                       AddNatInformation(const std::shared_ptr<VirtualEthernetExchanger>& exchanger, uint32_t ip, uint32_t mask) noexcept;
                
            private:
                template <typename TTransmission>
                typename std::enable_if<std::is_base_of<ITransmission, TTransmission>::value, std::shared_ptr<TTransmission>/**/>::type
                NewWebsocketTransmission(const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
                    const ppp::string& host = configuration_->websocket.host;
                    const ppp::string& path = configuration_->websocket.path;
                    auto transmission = make_shared_object<TTransmission>(context, socket, configuration_);
                    if (NULL == transmission) {
                        return NULL;
                    }
                    
                    if (host.size() > 0 && path.size() > 0) {
                        transmission->Host = host;
                        transmission->Path = path;
                    }
                    return transmission;
                }

            private:
                bool                                                    disposed_;
                std::shared_ptr<boost::asio::ip::tcp::resolver>         tresolver_;
                std::shared_ptr<boost::asio::ip::udp::resolver>         uresolver_;
                VirtualEthernetLoggerPtr                                logger_;
                NatInformationTable                                     nats_;
                FirewallPtr                                             firewall_;
                VirtualEthernetExchangerTable                           exchangers_;
                SynchronizedObject                                      syncobj_;
                TimerPtr                                                timeout_;
                AppConfigurationPtr                                     configuration_;
                ContextPtr                                              context_;
                boost::asio::ip::udp::endpoint                          dnsserverEP_;
                boost::asio::ip::address                                interfaceIP_;
                VirtualEthernetNetworkTcpipConnectionTable              connections_;
                ITransmissionStatisticsPtr                              statistics_;
                VirtualEthernetManagedServerPtr                         managed_server_;
                std::shared_ptr<boost::asio::ip::tcp::acceptor>         acceptors_[NetworkAcceptorCategories_Max];
            };
        }
    }
}