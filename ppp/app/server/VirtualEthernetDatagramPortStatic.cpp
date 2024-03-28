#include <ppp/app/server/VirtualEthernetDatagramPortStatic.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

typedef ppp::coroutines::YieldContext                   YieldContext;
typedef ppp::net::IPEndPoint                            IPEndPoint;
typedef ppp::net::Socket                                Socket;
typedef ppp::net::Ipep                                  Ipep;
typedef ppp::app::protocol::VirtualEthernetPacket       VirtualEthernetPacket;

namespace ppp {
    namespace app {
        namespace server {
            VirtualEthernetDatagramPortStatic::VirtualEthernetDatagramPortStatic(const VirtualEthernetExchangerPtr& exchanger, const std::shared_ptr<boost::asio::io_context>& context, uint32_t source_ip, int source_port) noexcept
                : disposed_(false)
                , in_(false)
                , onlydns_(true)
                , timeout_(0)
                , socket_(*context)
                , exchanger_(exchanger)
                , configuration_(exchanger->GetConfiguration())
                , source_ip_(source_ip)
                , source_port_(source_port)
                , context_(context) {
                switcher_ = exchanger->GetSwitcher();
                buffer_ = Executors::GetCachedBuffer(context);
                Update();
            }

            VirtualEthernetDatagramPortStatic::~VirtualEthernetDatagramPortStatic() noexcept {
                Finalize();
            }

            std::shared_ptr<VirtualEthernetDatagramPortStatic> VirtualEthernetDatagramPortStatic::GetReference() noexcept {
                return shared_from_this();
            }

            VirtualEthernetDatagramPortStatic::VirtualEthernetExchangerPtr VirtualEthernetDatagramPortStatic::GetExchanger() noexcept {
                return exchanger_;
            }

            VirtualEthernetDatagramPortStatic::ContextPtr VirtualEthernetDatagramPortStatic::GetContext() noexcept {
                return context_;
            }

            VirtualEthernetDatagramPortStatic::AppConfigurationPtr VirtualEthernetDatagramPortStatic::GetConfiguration() noexcept {
                return configuration_;
            }

            void VirtualEthernetDatagramPortStatic::Finalize() noexcept {
                Socket::Closesocket(socket_);
                disposed_ = true; 

                exchanger_->StaticEchoReleasePort(source_ip_, source_port_);
            }

            void VirtualEthernetDatagramPortStatic::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                context->post(std::bind(&VirtualEthernetDatagramPortStatic::Finalize, self));
            }

            bool VirtualEthernetDatagramPortStatic::Open() noexcept {
                if (disposed_) {
                    return false;
                }

                bool opened = socket_.is_open();
                if (opened) {
                    return false;
                }

                std::shared_ptr<VirtualEthernetSwitcher> switcher = exchanger_->GetSwitcher();
                boost::asio::ip::address address = switcher->GetInterfaceIP();

                bool success = VirtualEthernetPacket::OpenDatagramSocket(socket_, address, IPEndPoint::MinPort, sourceEP_) && Loopback();
                if (success) {
                    boost::system::error_code ec;
                    boost::asio::ip::udp::endpoint localEP = socket_.local_endpoint(ec);
                    if (ec) {
                        return false;
                    }

                    boost::asio::ip::address localIP = localEP.address();
                    in_ = localIP.is_v4();

                    int handle = socket_.native_handle();
                    ppp::net::Socket::AdjustDefaultSocketOptional(handle, in_);
                    ppp::net::Socket::SetTypeOfService(handle);
                    ppp::net::Socket::SetSignalPipeline(handle, false);
                    ppp::net::Socket::ReuseSocketAddress(handle, true);
                }

                return success;
            }

            bool VirtualEthernetDatagramPortStatic::Loopback() noexcept {
                if (disposed_) {
                    return false;
                }

                bool openped = socket_.is_open();
                if (!openped) {
                    return false;
                }

                auto self = shared_from_this();
                socket_.async_receive_from(boost::asio::buffer(buffer_.get(), PPP_BUFFER_SIZE), sourceEP_,
                    [self, this](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        if (ec == boost::system::errc::operation_canceled) {
                            return false;
                        }

                        if (ec == boost::system::errc::success) {
                            if (sz > 0) {
                                boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(sourceEP_);
                                Output(buffer_.get(), sz, remoteEP);
                            }
                        }

                        return Loopback();
                    });
                return true;
            }

            bool VirtualEthernetDatagramPortStatic::Output(const void* messages, int message_length, const boost::asio::ip::udp::endpoint& remoteEP) noexcept {
                if (NULL == messages || message_length < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }
                
                boost::asio::ip::udp::socket& socket = switcher_->static_echo_socket_;
                if (!socket.is_open()) {
                    return false;
                }

                boost::asio::ip::address remoteIP = remoteEP.address();
                if (!remoteIP.is_v4()) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = configuration_->GetBufferAllocator();
                uint32_t destinationIP = htonl(remoteIP.to_v4().to_uint());

                int packet_length = -1;
                std::shared_ptr<Byte> packet = VirtualEthernetPacket::Pack(configuration_,
                    allocator,
                    switcher_->static_echo_protocol_,
                    switcher_->static_echo_transport_,
                    exchanger_->static_echo_session_id_,
                    destinationIP,
                    remoteEP.port(),
                    source_ip_,
                    source_port_,
                    messages,
                    message_length,
                    packet_length);
                if (NULL == packet) {
                    return false;
                }

                boost::system::error_code ec;
                socket.send_to(boost::asio::buffer(packet.get(), packet_length), 
                    exchanger_->static_echo_source_ep_, boost::asio::socket_base::message_end_of_record, ec);
                
                if (ec) {
                    return false;
                }

                Update();
                if (auto statistics = exchanger_->GetStatistics(); NULL != statistics) {
                    statistics->AddOutgoingTraffic(packet_length);
                }

                return true;
            }

            bool VirtualEthernetDatagramPortStatic::SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                if (!socket_.is_open()) {
                    return false;
                }

                int destinationPort = destinationEP.port();
                if (destinationPort <= IPEndPoint::MinPort || destinationPort > IPEndPoint::MaxPort) {
                    return false;
                }

                boost::system::error_code ec;
                if (in_) {
                    socket_.send_to(boost::asio::buffer(packet, packet_length), 
                        Ipep::V6ToV4(destinationEP), boost::asio::socket_base::message_end_of_record, ec);
                }
                else {
                    socket_.send_to(boost::asio::buffer(packet, packet_length), 
                        Ipep::V4ToV6(destinationEP), boost::asio::socket_base::message_end_of_record, ec);
                }

                if (ec) {
                    return false; // Failed to sendto the datagram packet. 
                }
                else {
                    // Succeeded in sending the datagram packet to the external network. 
                    if (destinationPort != PPP_DNS_SYS_PORT) {
                        onlydns_ = false;
                    }

                    Update();
                    return true;
                }
            }
        }
    }
}