#include <windows/ppp/app/client/lsp/PaperAirplaneConnection.h>
#include <windows/ppp/app/client/lsp/PaperAirplaneController.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>

#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/protocol/templates/TVEthernetTcpipConnection.h>

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
                        connection_.reset();
                        
                        std::shared_ptr<vmux::vmux_skt> connection_mux = std::move(connection_mux_);
                        connection_mux_.reset();

                        if (NULL != connection)
                        {
                            connection->Dispose();
                        }

                        if (NULL != connection_mux) 
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
                    if (VirtualEthernetTcpipConnectionPtr connection = connection_; NULL != connection)
                    {
                        linked = connection->IsLinked();
                    }
                    elif(std::shared_ptr<vmux::vmux_skt> connection_mux = connection_mux_; NULL != connection_mux)
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
                    if (NULL != connection) 
                    {
                        this->Update();
                        return connection->Run(y);
                    }

                    std::shared_ptr<vmux::vmux_skt> connection_mux = this->connection_mux_;
                    if (NULL != connection_mux)
                    {
                        this->Update();
                        return connection_mux->run();
                    }

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

                    auto self = shared_from_this();
                    int mux_status = VEthernetNetworkTcpipConnection::Mux(self, exchanger, boost::asio::ip::tcp::endpoint(host, port), socket, connection_mux_, y);
                    if (mux_status < 1) 
                    {
                        return mux_status == 0;
                    }

                    std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger->ConnectTransmission(context, strand_, y);
                    if (NULL == transmission)
                    {
                        return false;
                    }

                    std::shared_ptr<VEthernetTcpipConnection> connection = 
                        make_shared_object<VEthernetTcpipConnection>(self, configuration, context, strand_, exchanger->GetId(), socket);
                    if (NULL == connection)
                    {
                        IDisposable::DisposeReferences(transmission);
                        return false;
                    }

                    bool ok = connection->Connect(y, transmission, stl::transform<ppp::string>(host.to_string()), port);
                    if (!ok)
                    {
                        IDisposable::DisposeReferences(connection, transmission);
                        return false;
                    }

                    this->connection_ = std::move(connection);
                    return true;
                }
            }
        }
    }
}