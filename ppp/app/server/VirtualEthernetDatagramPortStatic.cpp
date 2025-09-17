#include <ppp/app/server/VirtualEthernetDatagramPortStatic.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetDatagramPort.h>
#include <ppp/app/server/VirtualEthernetNamespaceCache.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/net/native/checksum.h>
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

            boost::asio::ip::udp::endpoint VirtualEthernetDatagramPortStatic::GetSourceEndPoint() noexcept {
                IPEndPoint ep(source_ip_, source_port_);
                return IPEndPoint::ToEndPoint<boost::asio::ip::udp>(ep);
            }

            void VirtualEthernetDatagramPortStatic::Finalize() noexcept {
                Socket::Closesocket(socket_);
                disposed_ = true; 

                exchanger_->StaticEchoReleasePort(source_ip_, source_port_);
            }

            void VirtualEthernetDatagramPortStatic::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context, 
                    [self, this]() noexcept {
                        Finalize();
                    });
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
                    localEP_ = socket_.local_endpoint(ec);
                    if (ec) {
                        return false;
                    }

                    boost::asio::ip::address localIP = localEP_.address();
                    in_ = localIP.is_v4();

                    int handle = socket_.native_handle();
                    ppp::net::Socket::AdjustDefaultSocketOptional(handle, in_);
                    ppp::net::Socket::SetTypeOfService(handle);
                    ppp::net::Socket::SetSignalPipeline(handle, false);
                    ppp::net::Socket::ReuseSocketAddress(handle, true);
                    ppp::net::Socket::SetWindowSizeIfNotZero(handle, configuration_->udp.cwnd, configuration_->udp.rwnd);
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
                        elif(ec == boost::system::errc::success) {
                            int bytes_transferred = static_cast<int>(sz);
                            if (bytes_transferred > 0) {
                                boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(sourceEP_);
                                Output(buffer_.get(), bytes_transferred, remoteEP);

                                if (configuration_->udp.dns.cache) {
                                    int remotePort = remoteEP.port();
                                    if (remotePort == PPP_DNS_SYS_PORT) {
                                        VirtualEthernetDatagramPort::NamespaceQuery(switcher_, buffer_.get(), bytes_transferred);
                                    }
                                }
                            }
                        }

                        return Loopback();
                    });
                return true;
            }

            bool VirtualEthernetDatagramPortStatic::Output(
                VirtualEthernetSwitcher*                            switcher, 
                VirtualEthernetExchanger*                           exchanger, 
                const void*                                         messages, 
                int                                                 message_length, 
                const boost::asio::ip::udp::endpoint&               sourceEP,
                const boost::asio::ip::udp::endpoint&               remoteEP) noexcept {
                
                boost::asio::ip::address sourceIP = sourceEP.address();
                if (sourceIP.is_v4()) {
                    boost::asio::ip::address_v4 in = sourceIP.to_v4();
                    return Output(switcher, exchanger, htonl(in.to_uint()), sourceEP.port(), messages, message_length, remoteEP);
                }
                else {
                    boost::asio::ip::udp::endpoint inEP = Ipep::V6ToV4(sourceEP);
                    sourceIP = inEP.address();

                    if (sourceIP.is_v4()) {
                        return Output(switcher, exchanger, messages, message_length, inEP, remoteEP);
                    }
                    else {
                        return false;
                    }
                }
            }

            bool VirtualEthernetDatagramPortStatic::Output(
                VirtualEthernetSwitcher*                            switcher, 
                VirtualEthernetExchanger*                           exchanger, 
                uint32_t                                            source_ip,
                int                                                 source_port,
                const void*                                         messages, 
                int                                                 message_length, 
                const boost::asio::ip::udp::endpoint&               remoteEP) noexcept {

                if (NULL == switcher || NULL == exchanger) {
                    return false;
                }

                if (NULL == messages || message_length < 1) {
                    return false;
                }

                boost::asio::ip::udp::socket& socket = switcher->static_echo_socket_;
                if (!socket.is_open()) {
                    return false;
                }

                boost::asio::ip::address remoteIP = remoteEP.address();
                if (!remoteIP.is_v4()) {
                    return false;
                }

                std::shared_ptr<AppConfiguration> configuration = switcher->configuration_;
                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = configuration->GetBufferAllocator();
                uint32_t destinationIP = htonl(remoteIP.to_v4().to_uint());

                int packet_length = -1;
                std::shared_ptr<Byte> packet = VirtualEthernetPacket::Pack(configuration,
                    allocator,
                    switcher->static_echo_protocol_,
                    switcher->static_echo_transport_,
                    exchanger->static_echo_session_id_,
                    destinationIP,
                    remoteEP.port(),
                    source_ip,
                    source_port,
                    messages,
                    message_length,
                    packet_length);
                if (NULL == packet) {
                    return false;
                }

                boost::system::error_code ec;
                socket.send_to(boost::asio::buffer(packet.get(), packet_length), 
                    exchanger->static_echo_source_ep_, boost::asio::socket_base::message_end_of_record, ec);
                
                if (ec) {
                    return false;
                }

                auto statistics = exchanger->GetStatistics(); 
                if (NULL != statistics) {
                    statistics->AddOutgoingTraffic(packet_length);
                }

                return true;
            }

            bool VirtualEthernetDatagramPortStatic::Output(const void* messages, int message_length, const boost::asio::ip::udp::endpoint& remoteEP) noexcept {
                if (disposed_) {
                    return false;
                }

                bool ok = Output(switcher_.get(), exchanger_.get(), source_ip_, source_port_, messages, message_length, remoteEP);
                if (ok) {
                    Update();
                }

                return ok;
            }

            int VirtualEthernetDatagramPortStatic::NamespaceQuery(
                const boost::asio::ip::udp::endpoint&               destinationEP,
                const void*                                         packet,
                int                                                 packet_length) noexcept {

                using dns_hdr = ppp::net::native::dns::dns_hdr;

                if (NULL != packet && packet_length >= sizeof(dns_hdr)) {
                    auto cache = switcher_->GetNamespaceCache();
                    if (NULL != cache) {
                        std::shared_ptr<Byte> response;
                        int response_length;

                        ppp::string domain = ppp::net::native::dns::ExtractHost((Byte*)packet, packet_length);
                        if (domain.size() > 0) {
                            if (cache->Get(domain, response, response_length, ((dns_hdr*)packet)->usTransID)) {
                                boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(destinationEP);
                                return Output(response.get(), response_length, remoteEP);
                            }
                        }
                    }
                }

                return -1;
            }

            bool VirtualEthernetDatagramPortStatic::SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept {
                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                bool opened = socket_.is_open();
                if (!opened) {
                    return false;
                }

                int destinationPort = destinationEP.port();
                if (destinationPort <= IPEndPoint::MinPort || destinationPort > IPEndPoint::MaxPort) {
                    return false;
                }

                boost::system::error_code ec;
                if (configuration_->udp.dns.cache) {
                    if (destinationPort == PPP_DNS_SYS_PORT) {
                        int status = NamespaceQuery(destinationEP, packet, packet_length);
                        if (status > 0) {
                            goto LABEL_OK;
                        }
                        elif(status == 0) {
                            return false;
                        }
                    }
                }

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
                LABEL_OK:
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