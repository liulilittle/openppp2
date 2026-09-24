#include <windows/ppp/app/client/lsp/PaperAirplaneConnection.h>
#include <windows/ppp/app/client/lsp/PaperAirplaneController.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>

#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/VEthernetNetworkTcpipForwarding.inl>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/protocol/templates/TVEthernetTcpipConnection.h>
#include <ppp/diagnostics/Error.h>

namespace ppp
{
    namespace app
    {
        namespace client
        {
            namespace lsp
            {
                PaperAirplaneConnection::PaperAirplaneConnection(const std::shared_ptr<PaperAirplaneController>& controller, const ContextPtr& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept
                    : disposed_(false)
                    , timeout_(0)
                    , controller_(controller)
                    , context_(context)
                    , strand_(strand)
                    , socket_(socket)
                    , configuration_(controller->GetConfiguration())
                {
                    Update();
                }

                PaperAirplaneConnection::~PaperAirplaneConnection() noexcept
                {
                    Finalize();
                }

                PaperAirplaneConnection::PaperAirplaneControllerPtr PaperAirplaneConnection::GetController() noexcept
                {
                    std::lock_guard<std::mutex> lock(state_mutex_);
                    return controller_;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> PaperAirplaneConnection::GetSocket() noexcept
                {
                    std::lock_guard<std::mutex> lock(state_mutex_);
                    return socket_;
                }

                bool PaperAirplaneConnection::IsPortAging(uint64_t now) noexcept
                {
                    std::lock_guard<std::mutex> lock(state_mutex_);
                    return disposed_ || now >= timeout_;
                }

                void PaperAirplaneConnection::Finalize() noexcept
                {
                    exchangeof(disposed_, true);
                    for (;;)
                    {
                        std::shared_ptr<VirtualEthernetTcpipConnection> connection = std::move(connection_);
                        std::shared_ptr<vmux::vmux_skt> connection_mux = std::move(connection_mux_);

                        if (NULLPTR != connection)
                        {
                            connection->Dispose();
                        }

                        if (NULLPTR != connection_mux) 
                        {
                            connection_mux->close();
                        }

                        ppp::net::Socket::Closesocket(socket_);
                        break;
                    }

                    controller_->ReleaseConnection(this);
                }

                void PaperAirplaneConnection::Update() noexcept
                {
                    bool linked = false;
                    if (VirtualEthernetTcpipConnectionPtr connection = connection_; NULLPTR != connection)
                    {
                        linked = connection->IsLinked();
                    }
                    elif(std::shared_ptr<vmux::vmux_skt> connection_mux = connection_mux_; NULLPTR != connection_mux)
                    {
                        linked = connection_mux->is_connected();
                    }

                    uint64_t now = Executors::GetTickCount();
                    if (linked)
                    {
                        timeout_ = now + (UInt64)configuration_->tcp.inactive.timeout * 1000ULL;
                    }
                    else
                    {
                        timeout_ = now + (UInt64)configuration_->tcp.connect.timeout * 1000ULL;
                    }
                }

                void PaperAirplaneConnection::Dispose() noexcept
                {
                    auto self = shared_from_this();
                    ppp::threading::Executors::ContextPtr context = context_;
                    ppp::threading::Executors::StrandPtr strand = strand_;

                    ppp::threading::Executors::Post(context, strand,
                        [self, this, context, strand]() noexcept
                        {
                            Finalize();
                        });
                }

                PaperAirplaneConnection::VEthernetExchangerPtr PaperAirplaneConnection::GetExchanger() noexcept
                {
                    PaperAirplaneControllerPtr controller = GetController();
                    if (NULLPTR == controller)
                    {
                        return NULLPTR;
                    }
                    else
                    {
                        return controller->GetExchanger();
                    }
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> PaperAirplaneConnection::GetBufferAllocator() noexcept
                {
                    AppConfigurationPtr configuration = GetConfiguration();
                    if (NULLPTR == configuration)
                    {
                        return NULLPTR;
                    }
                    else
                    {
                        return configuration->GetBufferAllocator();
                    }
                }

                bool PaperAirplaneConnection::Run(const boost::asio::ip::address& host, int port, YieldContext& y) noexcept
                {
                    bool ok = this->OnConnect(host, port, y);
                    if (!ok)
                    {
                        return false;
                    }

                    if (disposed_) 
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return false;
                    }

                    VirtualEthernetTcpipConnectionPtr connection = this->connection_;
                    if (NULLPTR != connection) 
                    {
                        this->Update();
                        return connection->Run(y);
                    }

                    std::shared_ptr<vmux::vmux_skt> connection_mux = this->connection_mux_;
                    if (NULLPTR != connection_mux)
                    {
                        this->Update();
                        return connection_mux->run();
                    }

                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                bool PaperAirplaneConnection::OnConnect(const boost::asio::ip::address& host, int port, YieldContext& y) noexcept
                {
                    using VEthernetTcpipConnection = ppp::app::protocol::templates::TVEthernetTcpipConnection<PaperAirplaneConnection>;

                    if (disposed_)
                    {
                        return false;
                    }

                    if (!y)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
                        return false;
                    }

                    if (host.is_unspecified())
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                        return false;
                    }

                    if (port <= 0 || port > 0xFFFF)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                        return false;
                    }

                    std::shared_ptr<boost::asio::io_context> context = GetContext();
                    if (NULLPTR == context)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                        return false;
                    }

                    AppConfigurationPtr configuration = GetConfiguration();
                    if (NULLPTR == configuration)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                        return false;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = GetSocket();
                    if (NULLPTR == socket)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                        return false;
                    }

                    VEthernetExchangerPtr exchanger = GetExchanger();
                    if (NULLPTR == exchanger)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                        return false;
                    }

                    auto self = shared_from_this();
                    int mux_status = VEthernetNetworkTcpipConnection::Mux(self, exchanger, boost::asio::ip::tcp::endpoint(host, port), socket, connection_mux_, y);
                    if (mux_status < 1) 
                    {
                        if (mux_status < 0)
                        {
                            if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode())
                            {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketConnectFailed);
                            }
                        }
                        return mux_status == 0;
                    }

                    std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger->ConnectTransmission(context, strand_, y);
                    if (NULLPTR == transmission)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                        return false;
                    }

                    std::shared_ptr<VEthernetTcpipConnection> connection = 
                        make_shared_object<VEthernetTcpipConnection>(self, configuration, context, strand_, exchanger->GetId(), socket);
                    if (NULLPTR == connection)
                    {
                        IDisposable::DisposeReferences(transmission);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        return false;
                    }

                    bool ok = connection->Connect(y, transmission, stl::transform<ppp::string>(host.to_string()), port);
                    if (!ok)
                    {
                        IDisposable::DisposeReferences(connection, transmission);
                        if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode())
                        {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketConnectFailed);
                        }
                        return false;
                    }

                    this->connection_ = std::move(connection);
                    return true;
                }
            }
        }
    }
}
