#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/io/Stream.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace http {
                class VEthernetHttpProxySwitcher;

                class VEthernetHttpProxyConnection : public std::enable_shared_from_this<VEthernetHttpProxyConnection> {
                public:
                    class ProtocolRoot final {
                    public:
                        typedef ppp::unordered_map<ppp::string, ppp::string>            HeaderCollection;

                    public:
                        ppp::string                                                     RawRotocol;
                        ppp::string                                                     Protocol;
                        ppp::string                                                     Method;
                        ppp::string                                                     RawUri;
                        bool                                                            TunnelMode;
                        ppp::string                                                     Host;
                        ppp::string                                                     Version;
                        HeaderCollection                                                Headers;

                    public:
                        ProtocolRoot() noexcept : TunnelMode(false) {}

                    public:
                        ppp::string                                                     ToString() noexcept;
                    };
                    typedef ppp::configurations::AppConfiguration                       AppConfiguration;
                    typedef std::shared_ptr<AppConfiguration>                           AppConfigurationPtr;
                    typedef ppp::threading::Executors                                   Executors;
                    typedef std::shared_ptr<boost::asio::io_context>                    ContextPtr;
                    typedef ppp::transmissions::ITransmission                           ITransmission;
                    typedef std::shared_ptr<ITransmission>                              ITransmissionPtr;
                    typedef ITransmission::AsynchronousWriteCallback                    AsynchronousWriteCallback;
                    typedef ppp::coroutines::YieldContext                               YieldContext;
                    typedef std::shared_ptr<VEthernetExchanger>                         VEthernetExchangerPtr;
                    typedef std::shared_ptr<VEthernetHttpProxySwitcher>                 VEthernetHttpProxySwitcherPtr;
                    typedef ppp::app::protocol::VirtualEthernetTcpipConnection          VirtualEthernetTcpipConnection;
                    typedef std::shared_ptr<VirtualEthernetTcpipConnection>             VirtualEthernetTcpipConnectionPtr;

                public:
                    VEthernetHttpProxyConnection(const VEthernetHttpProxySwitcherPtr&   proxy,
                        const VEthernetExchangerPtr&                                    exchanger, 
                        const std::shared_ptr<boost::asio::io_context>&                 context,
                        const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept;
                    virtual ~VEthernetHttpProxyConnection() noexcept;

                public:
                    VEthernetExchangerPtr                                               GetExchanger() noexcept;
                    ContextPtr                                                          GetContext() noexcept;
                    AppConfigurationPtr                                                 GetConfiguration() noexcept;
                    VEthernetHttpProxySwitcherPtr                                       GetProxy() noexcept;
                    std::shared_ptr<boost::asio::ip::tcp::socket>                       GetSocket() noexcept;
                    std::shared_ptr<ppp::threading::BufferswapAllocator>                GetBufferAllocator() noexcept;

                public:
                    virtual bool                                                        Run(YieldContext& y) noexcept;
                    virtual void                                                        Update() noexcept;
                    virtual void                                                        Dispose() noexcept;
                    bool                                                                IsPortAging(uint64_t now) noexcept { return disposed_ || now >= timeout_; }

                private:
                    void                                                                Finalize() noexcept;
                    bool                                                                WriteToLocal(YieldContext& y, ppp::io::MemoryStream& stream) noexcept;
                    bool                                                                WriteToLocal(YieldContext& y, const void* messages, int messages_size) noexcept;
                    bool                                                                ConnectBridgeToPeer(const std::shared_ptr<ProtocolRoot>& protocolRoot, YieldContext& y) noexcept;
                    bool                                                                ProtocolReadFirstRoot(const ppp::vector<ppp::string>& headers, const std::shared_ptr<ProtocolRoot>& protocolRoot) noexcept;
                    bool                                                                ProtocolReadAllHeaders(const ppp::vector<ppp::string>& headers, ProtocolRoot::HeaderCollection& s) noexcept;
                    std::shared_ptr<ProtocolRoot>                                       GetProtocolRootFromSocket(ppp::io::MemoryStream& ms) noexcept;
                    bool                                                                ProtocolReadHeaders(ppp::io::MemoryStream& ms, ppp::vector<ppp::string>& headers, ppp::string* out_) noexcept;
                    std::shared_ptr<ppp::app::protocol::AddressEndPoint>                GetAddressEndPointByProtocol(const std::shared_ptr<ProtocolRoot>& protocolRoot) noexcept;
                    bool                                                                ProcessHandshaked(const std::shared_ptr<ProtocolRoot>& protocolRoot, const void* messages, int messages_size, YieldContext& y) noexcept;
                    bool                                                                ProcessHandshaking(YieldContext& y) noexcept;

                protected:
                    virtual VirtualEthernetTcpipConnectionPtr                           OnConnect(const std::shared_ptr<ProtocolRoot>& protocolRoot, const std::shared_ptr<ppp::app::protocol::AddressEndPoint>& destinationEP, YieldContext& y) noexcept;
                    virtual bool                                                        OnEstablish(YieldContext& y) noexcept;

                private:
                    bool                                                                disposed_;
                    std::shared_ptr<boost::asio::io_context>                            context_;
                    UInt64                                                              timeout_;
                    VEthernetExchangerPtr                                               exchanger_;
                    std::shared_ptr<boost::asio::ip::tcp::socket>                       socket_;
                    VirtualEthernetTcpipConnectionPtr                                   connection_;
                    AppConfigurationPtr                                                 configuration_;
                    VEthernetHttpProxySwitcherPtr                                       proxy_;
                    boost::asio::ip::tcp::resolver                                      resolver_;
                    std::shared_ptr<ppp::threading::BufferswapAllocator>                allocator_;
                };
            }
        }
    }
}