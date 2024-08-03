#pragma once

#include <ppp/app/client/proxys/VEthernetLocalProxyConnection.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace proxys {
                class VEthernetHttpProxySwitcher;

                class VEthernetHttpProxyConnection : public VEthernetLocalProxyConnection {
                public:
                    class ProtocolRoot final {
                    public:
                        typedef ppp::unordered_map<ppp::string, ppp::string>            HeaderCollection;

                    public:
                        ppp::string                                                     RawRotocol;
                        ppp::string                                                     Protocol;
                        ppp::string                                                     Method;
                        ppp::string                                                     RawUri;
                        bool                                                            TunnelMode = false;
                        ppp::string                                                     Host;
                        ppp::string                                                     Version;
                        HeaderCollection                                                Headers;

                    public:
                        ProtocolRoot() noexcept : TunnelMode(false) {}

                    public:
                        ppp::string                                                     ToString() noexcept;
                    };
                    typedef std::shared_ptr<VEthernetHttpProxySwitcher>                 VEthernetHttpProxySwitcherPtr;

                public:
                    VEthernetHttpProxyConnection(const VEthernetHttpProxySwitcherPtr&   proxy,
                        const VEthernetExchangerPtr&                                    exchanger, 
                        const std::shared_ptr<boost::asio::io_context>&                 context,
                        const ppp::threading::Executors::StrandPtr&                     strand,
                        const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept;
                        
                public:
                    static bool                                                         ProtocolReadAllHeaders(ppp::io::MemoryStream& headers, VEthernetHttpProxyConnection::YieldContext& y, boost::asio::ip::tcp::socket& socket) noexcept;
                    static bool                                                         ProtocolReadAllHeaders(const ppp::vector<ppp::string>& headers, ProtocolRoot::HeaderCollection& s) noexcept;
                    static bool                                                         ProtocolReadFirstRoot(const ppp::vector<ppp::string>& headers, const std::shared_ptr<ProtocolRoot>& protocolRoot) noexcept;
                    static std::shared_ptr<ProtocolRoot>                                GetProtocolRootFromSocket(ppp::io::MemoryStream& ms) noexcept;
                    static bool                                                         ProtocolReadHeaders(ppp::io::MemoryStream& ms, ppp::vector<ppp::string>& headers, ppp::string* out_) noexcept;
                    static std::shared_ptr<ppp::app::protocol::AddressEndPoint>         GetAddressEndPointByProtocol(const std::shared_ptr<ProtocolRoot>& protocolRoot) noexcept;
    
                private:
                    bool                                                                ProcessHandshaked(const std::shared_ptr<ProtocolRoot>& protocolRoot, const void* messages, int messages_size, YieldContext& y) noexcept;
                    bool                                                                ConnectBridgeToPeer(const std::shared_ptr<ProtocolRoot>& protocolRoot, YieldContext& y) noexcept;

                protected:
                    virtual bool                                                        Handshake(YieldContext& y) noexcept override;
                };
            }
        }
    }
}