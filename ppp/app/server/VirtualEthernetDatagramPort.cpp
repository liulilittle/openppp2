#include <ppp/app/server/VirtualEthernetDatagramPortStatic.h>
#include <ppp/app/server/VirtualEthernetDatagramPort.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
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
            VirtualEthernetDatagramPort::VirtualEthernetDatagramPort(const VirtualEthernetExchangerPtr& exchanger, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept
                : disposed_(false)
                , onlydns_(true)
                , sendto_(false)
                , in_(false)
                , finalize_(false)
                , timeout_(0)
                , context_(transmission->GetContext())
                , socket_(*context_)
                , exchanger_(exchanger)
                , transmission_(transmission)
                , configuration_(exchanger->GetConfiguration())
                , sourceEP_(sourceEP) {
                buffer_ = Executors::GetCachedBuffer(context_);
                Update();
            }

            VirtualEthernetDatagramPort::~VirtualEthernetDatagramPort() noexcept {
                Finalize();
            }

            void VirtualEthernetDatagramPort::Finalize() noexcept {
                std::shared_ptr<ITransmission> transmission = std::move(transmission_); 
                transmission_.reset();
                
                if (sendto_ && !finalize_) {
                    if (NULL != transmission) {
                        if (!exchanger_->DoSendTo(transmission, sourceEP_, sourceEP_, NULL, 0, nullof<YieldContext>())) {
                            transmission->Dispose();
                        }
                    }
                }

                disposed_ = true;
                sendto_ = false;
                finalize_ = true;
                Socket::Closesocket(socket_);

                exchanger_->ReleaseDatagramPort(sourceEP_);
            }

            void VirtualEthernetDatagramPort::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context, 
                    [self, this]() noexcept {
                        Finalize();
                    });
            }

            bool VirtualEthernetDatagramPort::Open() noexcept {
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

            bool VirtualEthernetDatagramPort::Loopback() noexcept {
                if (disposed_) {
                    return false;
                }

                bool opened = socket_.is_open();
                if (!opened) {
                    return false;
                }

                auto self = shared_from_this();
                socket_.async_receive_from(boost::asio::buffer(buffer_.get(), PPP_BUFFER_SIZE), remoteEP_,
                    [self, this](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        bool disposing = true;
                        while (ec == boost::system::errc::success) {
                            int bytes_transferred = static_cast<int>(sz);
                            if (bytes_transferred < 1) {
                                disposing = false;
                                break;
                            }

                            if (configuration_->udp.dns.cache) {
                                int remotePort = remoteEP_.port();
                                if (remotePort == PPP_DNS_SYS_PORT) {
                                    NamespaceQuery(exchanger_->GetSwitcher(), buffer_.get(), bytes_transferred);
                                }
                            }

                            std::shared_ptr<ITransmission> transmission = transmission_;
                            if (NULL == transmission) {
                                break;
                            }

                            boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(remoteEP_);
                            if (exchanger_->DoSendTo(transmission, sourceEP_, remoteEP, buffer_.get(), bytes_transferred, nullof<YieldContext>())) {
                                Update();
                                disposing = false;
                            }
                            else {
                                transmission_.reset();
                                transmission->Dispose();
                            }

                            break;
                        }

                        if (disposing) {
                            Dispose();
                        }
                        else {
                            Loopback();
                        }
                    });
                return true;
            }

            bool VirtualEthernetDatagramPort::NamespaceQuery(
                const std::shared_ptr<VirtualEthernetSwitcher>&     switcher,
                const void*                                         packet,
                int                                                 packet_length) noexcept {

                auto cache = switcher->GetNamespaceCache();
                if (NULL == cache) {
                    return false;
                }

                uint16_t queries_type = 0;
                uint16_t queries_clazz = 0;
                ppp::string domain = ppp::net::native::dns::ExtractHostY((Byte*)packet, packet_length,
                    [&queries_type, &queries_clazz](ppp::net::native::dns::dns_hdr* h, ppp::string& domain, uint16_t type, uint16_t clazz) noexcept -> bool {
                        queries_type = type;
                        queries_clazz = clazz;
                        return true;
                    });

                if (domain.empty()) {
                    return false;
                }

                std::shared_ptr<Byte> response = make_shared_alloc<Byte>(packet_length);
                if (NULL == response) {
                    return false;
                }

                ppp::string queries_key = VirtualEthernetNamespaceCache::QueriesKey(queries_type, queries_clazz, domain);
                memcpy(response.get(), packet, packet_length);

                return cache->Add(queries_key, response, packet_length);
            }

            int VirtualEthernetDatagramPort::NamespaceQuery(
                const std::shared_ptr<VirtualEthernetSwitcher>&     switcher,
                VirtualEthernetExchanger*                           exchanger, 
                const boost::asio::ip::udp::endpoint&               sourceEP,
                const boost::asio::ip::udp::endpoint&               destinationEP,
                const ppp::string&                                  domain,
                const void*                                         packet,
                int                                                 packet_length,
                uint16_t                                            queries_type,
                uint16_t                                            queries_clazz,
                bool                                                static_transit) noexcept { 
                
                using dns_hdr = ppp::net::native::dns::dns_hdr;

                if (NULL != packet && packet_length >= sizeof(dns_hdr)) {
                    if (domain.size() > 0) {
                        auto cache = switcher->GetNamespaceCache();
                        if (NULL != cache) {
                            std::shared_ptr<Byte> response;
                            int response_length;

                            ppp::string queries_key = VirtualEthernetNamespaceCache::QueriesKey(queries_type, queries_clazz, domain);
                            if (cache->Get(queries_key, response, response_length, ((dns_hdr*)packet)->usTransID)) {
                                std::shared_ptr<ITransmission> transmission = exchanger->GetTransmission();
                                if (NULL != transmission) {
                                    boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(destinationEP);
                                    if (static_transit) {
                                        bool outputed = VirtualEthernetDatagramPortStatic::Output(switcher.get(), 
                                            exchanger, response.get(), response_length, sourceEP, remoteEP);
                                        if (outputed) {
                                            return 1;
                                        }
                                        else {
                                            return -1;
                                        }
                                    }
                                    elif(exchanger->DoSendTo(transmission, sourceEP, remoteEP, response.get(), response_length, nullof<YieldContext>())) {
                                        return 1;
                                    }
                                    else {
                                        transmission->Dispose();
                                        return -1;
                                    }
                                }
                            }
                        }
                    }
                }

                return 0;
            }

            bool VirtualEthernetDatagramPort::SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept {
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
                    sendto_ = true;
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