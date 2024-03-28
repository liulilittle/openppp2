#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITransmission.h>
#include <windows/ppp/app/client/lsp/PaperAirplaneRoot.h>

namespace ppp
{
    namespace app
    {
        namespace client
        {
            class VEthernetExchanger;

            namespace lsp
            {
                class PaperAirplaneConnection;

                // [PaperAirplane] is based on Windows/SPI, LSP/NSP network session layer layering technology to implement a 
                // VPN/RING-3 layer application tunnel agent technology, which is often used in online game accelerators, 
                // Such as Web UU, Adventure accelerator, 360 Game accelerator, mobile game accelerator, etc. 
                // Lenovo Game Accelerator, fast game accelerator and so on.
                // 
                // In the VPN/SD-WAN and Global-proxy industry, PPP PRIVATE NETWORK™ 1 and Proxifier 
                // Are implemented based on the NSP/LSP layering technology.
                class PaperAirplaneController : public std::enable_shared_from_this<PaperAirplaneController>
                {
                    friend class PaperAirplaneConnection;

                public:
                    typedef ppp::configurations::AppConfiguration                   AppConfiguration;
                    typedef std::shared_ptr<AppConfiguration>                       AppConfigurationPtr;
                    typedef ppp::transmissions::ITransmission                       ITransmission;
                    typedef std::shared_ptr<ITransmission>                          ITransmissionPtr;
                    typedef ppp::threading::Timer                                   Timer;
                    typedef std::shared_ptr<Timer>                                  TimerPtr;
                    typedef std::shared_ptr<boost::asio::io_context>                ContextPtr;
                    typedef ppp::coroutines::YieldContext                           YieldContext;
                    typedef std::shared_ptr<PaperAirplaneConnection>                PaperAirplaneConnectionPtr;

                private:
                    typedef paper_airplane::PaperAirplaneControlBlockPort           PaperAirplaneControlBlockPort;
                    typedef std::shared_ptr<PaperAirplaneControlBlockPort>          PaperAirplaneControlBlockPortPtr;
                    typedef struct
                    {
                        boost::asio::ip::tcp::endpoint                              natEP;
                        boost::asio::ip::tcp::endpoint                              destinationEP;
                        uint64_t                                                    last;
                    }                                                               PortForwardMappingEntry;
                    typedef std::unordered_map<boost::asio::ip::tcp::endpoint,
                        PortForwardMappingEntry>                                    PortForwardMappingEntriesTable;         
                    typedef std::unordered_map<void*, PaperAirplaneConnectionPtr>   PaperAirplaneConnectionTable;

                public:
                    PaperAirplaneController(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;
                    virtual ~PaperAirplaneController() noexcept;

                public:
                    std::shared_ptr<PaperAirplaneController>                        GetReference() noexcept;
                    std::shared_ptr<VEthernetExchanger>                             GetExchanger() noexcept;
                    AppConfigurationPtr                                             GetConfiguration() noexcept;
                    ContextPtr                                                      GetContext() noexcept;

                public:
                    virtual bool                                                    Open(int interface_index, uint32_t ip, uint32_t mask) noexcept;
                    virtual void                                                    Dispose() noexcept;

                public:
                    static int                                                      Install() noexcept;
                    static bool                                                     NoLsp() noexcept;
                    static bool                                                     NoLsp(const ppp::string& path) noexcept;
                    static bool                                                     Reset() noexcept;

                private:
                    static int                                                      Upgrade() noexcept;
                    static int                                                      Uninstall(bool reboot) noexcept;

                protected:
                    virtual void                                                    Update(UInt64 now) noexcept;
                    virtual PaperAirplaneConnectionPtr                              NewConnection(const std::shared_ptr<boost::asio::io_context>& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;

                private:
                    static bool                                                     CopyToSystemFolder() noexcept;

                private:
                    void                                                            Finalize() noexcept;
                    bool                                                            OpenAllAcceptors() noexcept;
                    bool                                                            OpenControlBlockPort(int interface_index, uint32_t ip, uint32_t mask) noexcept;
                    bool                                                            NextAlwaysTickTimer() noexcept;

                private:
                    bool                                                            AcceptMasterAcceptor() noexcept;
                    bool                                                            AcceptForwardAcceptor() noexcept;
                    bool                                                            AcceptForwardClient(const ppp::net::Socket::AsioContext& context, const ppp::net::Socket::AsioTcpSocket& socket, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept;

                private:
                    bool                                                            UpdateAllForwardEntries(UInt64 now) noexcept;
                    bool                                                            ReleaseConnection(PaperAirplaneConnection* connection) noexcept;
                    bool                                                            Timeout(int milliseconds, const Timer::TimeoutEventHandler& handler) noexcept;

                private:
                    bool                                                            disposed_     = false;
                    int                                                             forward_port_ = 0;
                    std::shared_ptr<VEthernetExchanger>                             exchanger_;
                    AppConfigurationPtr                                             configuration_;
                    ContextPtr                                                      context_;
                    std::unordered_map<Timer*, TimerPtr>                            timeouts_;
                    PaperAirplaneControlBlockPortPtr                                block_port_;
                    PortForwardMappingEntriesTable                                  entries_;
                    PaperAirplaneConnectionTable                                    connections_;
                    boost::asio::ip::tcp::acceptor                                  acceptors_[2];
                };
            }
        }
    }
}