#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetSwitcher;

            class VirtualEthernetNetworkTcpipConnection : public std::enable_shared_from_this<VirtualEthernetNetworkTcpipConnection> {
            public:
                typedef ppp::app::protocol::VirtualEthernetTcpipConnection  VirtualEthernetTcpipConnection;
                typedef ppp::configurations::AppConfiguration               AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                   AppConfigurationPtr;
                typedef ppp::transmissions::ITransmission                   ITransmission;
                typedef std::shared_ptr<ITransmission>                      ITransmissionPtr;

            public:
                VirtualEthernetNetworkTcpipConnection(
                    const std::shared_ptr<VirtualEthernetSwitcher>&         switcher,
                    const Int128&                                           id,
                    const ITransmissionPtr&                                 transmission) noexcept;
                virtual ~VirtualEthernetNetworkTcpipConnection() noexcept;

            public:
                std::shared_ptr<boost::asio::io_context>                    GetContext()       noexcept { return context_; }
                ppp::threading::Executors::StrandPtr                        GetStrand()        noexcept { return strand_; }
                Int128                                                      GetId()            noexcept { return id_; }
                ITransmissionPtr                                            GetTransmission()  noexcept { return transmission_; }
                AppConfigurationPtr                                         GetConfiguration() noexcept { return configuration_; }
                std::shared_ptr<VirtualEthernetSwitcher>                    GetSwitcher()      noexcept { return switcher_; }
                bool                                                        IsMux()            noexcept { return mux_; }

            public:
                virtual bool                                                Run(ppp::coroutines::YieldContext& y) noexcept;
                virtual void                                                Update() noexcept;
                virtual void                                                Dispose() noexcept;
                bool                                                        IsPortAging(uint64_t now) noexcept { return disposed_ || (!mux_ && now >= timeout_); }

            private:
                void                                                        Finalize() noexcept;
                std::shared_ptr<VirtualEthernetTcpipConnection>             AcceptConnection(ppp::coroutines::YieldContext& y) noexcept;
                bool                                                        AcceptMuxLinklayer(const std::shared_ptr<VirtualEthernetTcpipConnection>& connection, uint32_t vlan, uint32_t seq, uint32_t ack, ppp::coroutines::YieldContext& y) noexcept;

            private:
                struct {
                    bool                                                    disposed_ : 1;
                    bool                                                    mux_      : 7;
                };
                Int128                                                      id_       = 0;
                UInt64                                                      timeout_  = 0;
                ppp::threading::Executors::ContextPtr                       context_;
                ppp::threading::Executors::StrandPtr                        strand_;
                std::shared_ptr<VirtualEthernetSwitcher>                    switcher_;
                ITransmissionPtr                                            transmission_;
                std::shared_ptr<VirtualEthernetTcpipConnection>             connection_;
                AppConfigurationPtr                                         configuration_;
            };
        }
    }
}