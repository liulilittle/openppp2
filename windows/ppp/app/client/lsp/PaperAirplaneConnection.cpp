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
                PaperAirplaneConnection::PaperAirplaneConnection(const std::shared_ptr<PaperAirplaneController>& controller, const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept
                    : disposed_(false)
                    , timeout_(0)
                    , controller_(controller)
                    , context_(context)
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
                    exchangeof(disposed_, true); {
                        std::shared_ptr<VirtualEthernetTcpipConnection> connection = std::move(connection_);
                        if (NULL != connection) 
                        {
                            connection_.reset();
                            connection->Dispose();
                        }

                        ppp::net::Socket::Closesocket(socket_);
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
                    std::shared_ptr<boost::asio::io_context> context = GetContext();
                    context->post(
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

                PaperAirplaneConnection::ContextPtr PaperAirplaneConnection::GetContext() noexcept
                {
                    return context_;
                }

                PaperAirplaneConnection::AppConfigurationPtr PaperAirplaneConnection::GetConfiguration() noexcept
                {
                    return configuration_;
                }

                PaperAirplaneConnection::PaperAirplaneControllerPtr PaperAirplaneConnection::GetController() noexcept
                {
                    return controller_;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> PaperAirplaneConnection::GetSocket() noexcept
                {
                    return socket_;
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

                    std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger->ConnectTransmission(context, y);
                    if (NULL == transmission)
                    {
                        return NULL;
                    }

                    ppp::string address;
                    std::shared_ptr<VEthernetTcpipConnection> connection = make_shared_object<VEthernetTcpipConnection>(shared_from_this(), configuration, context, exchanger->GetId(), socket);
                    if (NULL == connection)
                    {
                        IDisposable::DisposeReferences(transmission);
                        return NULL;
                    }
                    else
                    {
                        std::string tmp = host.to_string();
                        address = ppp::string(tmp.data(), tmp.size());
                    }

                    bool ok = connection->Connect(y, transmission, address, port);
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