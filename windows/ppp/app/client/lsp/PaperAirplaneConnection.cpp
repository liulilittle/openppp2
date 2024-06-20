#include <windows/ppp/app/client/lsp/PaperAirplaneConnection.h>
#include <windows/ppp/app/client/lsp/PaperAirplaneController.h>
#include <ppp/IDisposable.h>
#include <ppp/app/client/VEthernetExchanger.h>

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

                void PaperAirplaneConnection::Finalize() noexcept
                {
                    exchangeof(disposed_, true);
                    for (;;)
                    {
                        std::shared_ptr<VirtualEthernetTcpipConnection> connection = std::move(connection_);
                        if (NULL != connection)
                        {
                            connection_.reset();
                            connection->Dispose();
                        }

                        ppp::net::Socket::Closesocket(socket_);
                        break;
                    }

                    controller_->ReleaseConnection(this);
                }

                void PaperAirplaneConnection::Update() noexcept
                {
                    VirtualEthernetTcpipConnectionPtr connection = connection_;
                    if (NULL != connection && connection->IsLinked()) 
                    {
                        timeout_ = Executors::GetTickCount() + (UInt64)configuration_->tcp.inactive.timeout * 1000;
                    }
                    else 
                    {
                        timeout_ = Executors::GetTickCount() + (UInt64)configuration_->tcp.connect.timeout * 1000;;
                    }
                }

                void PaperAirplaneConnection::Dispose() noexcept
                {
                    auto self = shared_from_this();
                    ppp::threading::Executors::Post(context_, strand_,
                        [self, this]() noexcept
                        {
                            Finalize();
                        });
                }

                PaperAirplaneConnection::VEthernetExchangerPtr PaperAirplaneConnection::GetExchanger() noexcept
                {
                    PaperAirplaneControllerPtr controller = GetController();
                    if (NULL == controller)
                    {
                        return NULL;
                    }
                    else
                    {
                        return controller->GetExchanger();
                    }
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> PaperAirplaneConnection::GetBufferAllocator() noexcept
                {
                    AppConfigurationPtr configuration = GetConfiguration();
                    if (NULL == configuration)
                    {
                        return NULL;
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
                        return false;
                    }

                    VirtualEthernetTcpipConnectionPtr connection = this->connection_;
                    if (NULL == connection) 
                    {
                        return false;
                    }

                    this->Update();
                    return connection->Run(y);
                }

                bool PaperAirplaneConnection::OnConnect(const boost::asio::ip::address& host, int port, YieldContext& y) noexcept
                {
                    using VEthernetTcpipConnection = ppp::app::protocol::templates::VEthernetTcpipConnection<PaperAirplaneConnection>;

                    if (disposed_)
                    {
                        return false;
                    }

                    if (!y)
                    {
                        return false;
                    }

                    std::shared_ptr<boost::asio::io_context> context = GetContext();
                    if (NULL == context)
                    {
                        return false;
                    }

                    AppConfigurationPtr configuration = GetConfiguration();
                    if (NULL == configuration)
                    {
                        return false;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = GetSocket();
                    if (NULL == socket)
                    {
                        return false;
                    }

                    VEthernetExchangerPtr exchanger = GetExchanger();
                    if (NULL == exchanger)
                    {
                        return false;
                    }

                    std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger->ConnectTransmission(context, strand_, y);
                    if (NULL == transmission)
                    {
                        return NULL;
                    }

                    auto self = shared_from_this();
                    std::shared_ptr<VEthernetTcpipConnection> connection = 
                        make_shared_object<VEthernetTcpipConnection>(self, configuration, context, strand_, exchanger->GetId(), socket);
                    if (NULL == connection)
                    {
                        IDisposable::DisposeReferences(transmission);
                        return NULL;
                    }

                    bool ok = connection->Connect(y, transmission, stl::transform<ppp::string>(host.to_string()), port);
                    if (!ok)
                    {
                        IDisposable::DisposeReferences(connection, transmission);
                        return NULL;
                    }

                    this->connection_ = std::move(connection);
                    return true;
                }
            }
        }
    }
}