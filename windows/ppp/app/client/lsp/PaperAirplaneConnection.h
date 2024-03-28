#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

namespace ppp
{
    namespace app
    {
        namespace client
        {
            class VEthernetExchanger;

            namespace lsp
            {
                class PaperAirplaneController;

                class PaperAirplaneConnection : public std::enable_shared_from_this<PaperAirplaneConnection>
                {
                public:
                    typedef ppp::configurations::AppConfiguration                       AppConfiguration;
                    typedef std::shared_ptr<AppConfiguration>                           AppConfigurationPtr;
                    typedef ppp::threading::Executors                                   Executors;
                    typedef std::shared_ptr<boost::asio::io_context>                    ContextPtr;
                    typedef ppp::transmissions::ITransmission                           ITransmission;
                    typedef std::shared_ptr<ITransmission>                              ITransmissionPtr;
                    typedef ppp::coroutines::YieldContext                               YieldContext;
                    typedef std::shared_ptr<VEthernetExchanger>                         VEthernetExchangerPtr;
                    typedef std::shared_ptr<PaperAirplaneController>                    PaperAirplaneControllerPtr;
                    typedef ppp::app::protocol::VirtualEthernetTcpipConnection          VirtualEthernetTcpipConnection;
                    typedef std::shared_ptr<VirtualEthernetTcpipConnection>             VirtualEthernetTcpipConnectionPtr;

                public:
                    PaperAirplaneConnection(const std::shared_ptr<PaperAirplaneController>& controller, const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
                    virtual ~PaperAirplaneConnection() noexcept;

                public:
                    VEthernetExchangerPtr                                               GetExchanger() noexcept;
                    ContextPtr                                                          GetContext() noexcept;
                    AppConfigurationPtr                                                 GetConfiguration() noexcept;
                    PaperAirplaneControllerPtr                                          GetController() noexcept;
                    std::shared_ptr<boost::asio::ip::tcp::socket>                       GetSocket() noexcept;
                    std::shared_ptr<ppp::threading::BufferswapAllocator>                GetBufferAllocator() noexcept;

                public:
                    virtual void                                                        Dispose() noexcept;
                    virtual void                                                        Update() noexcept;
                    virtual bool                                                        Run(const boost::asio::ip::address& host, int port, YieldContext& y) noexcept;
                    bool                                                                IsPortAging(uint64_t now) noexcept { return disposed_ || now >= timeout_; }

                private:
                    void                                                                Finalize() noexcept;
                    bool                                                                OnConnect(const boost::asio::ip::address& host, int port, YieldContext& y) noexcept;

                private:
                    bool                                                                disposed_ = false;
                    UInt64                                                              timeout_  = 0;
                    PaperAirplaneControllerPtr                                          controller_;
                    ContextPtr                                                          context_;
                    std::shared_ptr<boost::asio::ip::tcp::socket>                       socket_;
                    VirtualEthernetTcpipConnectionPtr                                   connection_;
                    AppConfigurationPtr                                                 configuration_;
                };
            }
        }
    }
}