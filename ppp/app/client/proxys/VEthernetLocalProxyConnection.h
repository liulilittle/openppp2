#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/io/Stream.h>
#include <ppp/io/MemoryStream.h>

#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/net/rinetd/RinetdConnection.h>

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

#include <ppp/app/mux/vmux_net.h>
#include <ppp/app/mux/vmux_skt.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace proxys {
                class VEthernetLocalProxySwitcher;

                class VEthernetLocalProxyConnection : public std::enable_shared_from_this<VEthernetLocalProxyConnection> {
                public:
                    typedef ppp::net::rinetd::RinetdConnection                          RinetdConnection;
                    typedef ppp::configurations::AppConfiguration                       AppConfiguration;
                    typedef std::shared_ptr<AppConfiguration>                           AppConfigurationPtr;
                    typedef ppp::threading::Executors                                   Executors;
                    typedef std::shared_ptr<boost::asio::io_context>                    ContextPtr;
                    typedef ppp::transmissions::ITransmission                           ITransmission;
                    typedef std::shared_ptr<ITransmission>                              ITransmissionPtr;
                    typedef ITransmission::AsynchronousWriteCallback                    AsynchronousWriteCallback;
                    typedef ppp::coroutines::YieldContext                               YieldContext;
                    typedef std::shared_ptr<VEthernetExchanger>                         VEthernetExchangerPtr;
                    typedef std::shared_ptr<VEthernetLocalProxySwitcher>                VEthernetLocalProxySwitcherPtr;
                    typedef ppp::app::protocol::VirtualEthernetTcpipConnection          VirtualEthernetTcpipConnection;
                    typedef std::shared_ptr<VirtualEthernetTcpipConnection>             VirtualEthernetTcpipConnectionPtr;

                public:
                    VEthernetLocalProxyConnection(const VEthernetLocalProxySwitcherPtr& proxy,
                        const VEthernetExchangerPtr&                                    exchanger, 
                        const std::shared_ptr<boost::asio::io_context>&                 context,
                        const ppp::threading::Executors::StrandPtr&                     strand,
                        const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept;
                    virtual ~VEthernetLocalProxyConnection() noexcept;

                public:
                    bool                                                                IsDisposed()         noexcept { return disposed_; }
                    VEthernetExchangerPtr&                                              GetExchanger()       noexcept { return exchanger_; }
                    ContextPtr&                                                         GetContext()         noexcept { return context_; }
                    ppp::threading::Executors::StrandPtr&                               GetStrand()          noexcept { return strand_; }
                    AppConfigurationPtr&                                                GetConfiguration()   noexcept { return configuration_; }
                    VEthernetLocalProxySwitcherPtr&                                     GetProxy()           noexcept { return proxy_; }
                    std::shared_ptr<boost::asio::ip::tcp::socket>&                      GetSocket()          noexcept { return socket_; }
                    std::shared_ptr<ppp::threading::BufferswapAllocator>&               GetBufferAllocator() noexcept { return allocator_; }
                    std::shared_ptr<VEthernetLocalProxyConnection>                      GetReference()       noexcept { return shared_from_this(); }

                public:
                    virtual bool                                                        Run(YieldContext& y) noexcept;
                    virtual void                                                        Update() noexcept;
                    virtual void                                                        Dispose() noexcept;
                    bool                                                                IsPortAging(uint64_t now) noexcept { return disposed_ || now >= timeout_; }
                    static std::shared_ptr<ppp::app::protocol::AddressEndPoint>         GetAddressEndPointByProtocol(const ppp::string& host, int port) noexcept;

                private:
                    void                                                                Finalize() noexcept;

                protected:
                    virtual bool                                                        Handshake(YieldContext& y) noexcept = 0;
                    bool                                                                ConnectBridgeToPeer(const std::shared_ptr<ppp::app::protocol::AddressEndPoint>& destinationEP, YieldContext& y) noexcept;
                    bool                                                                SendBufferToPeer(YieldContext& y, const void* messages, int messages_size) noexcept;

                private:
                    bool                                                                disposed_ = false;
                    std::shared_ptr<boost::asio::io_context>                            context_;
                    ppp::threading::Executors::StrandPtr                                strand_;
                    UInt64                                                              timeout_  = 0;
                    VEthernetExchangerPtr                                               exchanger_;
                    std::shared_ptr<boost::asio::ip::tcp::socket>                       socket_;
                    VirtualEthernetTcpipConnectionPtr                                   connection_;
                    AppConfigurationPtr                                                 configuration_;
                    VEthernetLocalProxySwitcherPtr                                      proxy_;
                    std::shared_ptr<ppp::threading::BufferswapAllocator>                allocator_;
                    std::shared_ptr<RinetdConnection>                                   connection_rinetd_;
                    std::shared_ptr<vmux::vmux_skt>                                     connection_mux_;
                };
            }
        }
    }
}