#include <ppp/app/server/VirtualEthernetDatagramPort.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

typedef ppp::coroutines::YieldContext                   YieldContext;
typedef ppp::net::IPEndPoint                            IPEndPoint;
typedef ppp::net::Socket                                Socket;
typedef ppp::net::Ipep                                  Ipep;

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
                , socket_(*transmission->GetContext())
                , exchanger_(exchanger)
                , transmission_(transmission)
                , configuration_(exchanger->GetConfiguration())
                , sourceEP_(sourceEP) {
                auto context = transmission->GetContext();
                buffer_ = Executors::GetCachedBuffer(context.get());
                Update();
            }

            VirtualEthernetDatagramPort::~VirtualEthernetDatagramPort() noexcept {
                Finalize();
            }

            std::shared_ptr<VirtualEthernetDatagramPort> VirtualEthernetDatagramPort::GetReference() noexcept {
                return shared_from_this();
            }

            VirtualEthernetDatagramPort::VirtualEthernetExchangerPtr VirtualEthernetDatagramPort::GetExchanger() noexcept {
                return exchanger_;
            }

            VirtualEthernetDatagramPort::ContextPtr VirtualEthernetDatagramPort::GetContext() noexcept {
                return transmission_->GetContext();
            }

            VirtualEthernetDatagramPort::AppConfigurationPtr VirtualEthernetDatagramPort::GetConfiguration() noexcept {
                return configuration_;
            }

            boost::asio::ip::udp::endpoint& VirtualEthernetDatagramPort::GetLocalEndPoint() noexcept {
                return localEP_;
            }

            boost::asio::ip::udp::endpoint& VirtualEthernetDatagramPort::GetSourceEndPoint() noexcept {
                return sourceEP_;
            }

            void VirtualEthernetDatagramPort::Finalize() noexcept {
                if (sendto_ && !finalize_) {
                    if (!exchanger_->DoSendTo(transmission_, sourceEP_, sourceEP_, NULL, 0, nullof<YieldContext>())) {
                        transmission_->Dispose();
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
                context->post(std::bind(&VirtualEthernetDatagramPort::Finalize, self));
            }

            bool VirtualEthernetDatagramPort::Open() noexcept {
                if (disposed_) {
                    return false;
                }

                if (socket_.is_open()) {
                    return false;
                }

                auto opensocket = [this]() noexcept {
                    std::shared_ptr<VirtualEthernetSwitcher> switcher = exchanger_->GetSwitcher();
                    boost::asio::ip::address address = switcher->GetInterfaceIP();

                    bool ok = false;
                    if (address.is_v4() || address.is_v6()) {
                        ok = Socket::OpenSocket(socket_, address, IPEndPoint::MinPort);
                        if (ok) {
                            return Loopback();
                        }

                        boost::system::error_code ec;
                        socket_.close(ec);
                        if (ec) {
                            return false;
                        }

                        goto opensocket_by_protocol;
                    }

                opensocket_by_protocol: /* Label.s */
                    if (sourceEP_.protocol() == boost::asio::ip::udp::v4()) {
                        ok = Socket::OpenSocket(socket_, boost::asio::ip::address_v4::any(), IPEndPoint::MinPort);
                    }
                    else {
                        ok = Socket::OpenSocket(socket_, boost::asio::ip::address_v6::any(), IPEndPoint::MinPort);
                    }

                    return ok && Loopback();
                };

                bool success = opensocket();
                if (success) {
                    boost::system::error_code ec;
                    localEP_ = socket_.local_endpoint(ec);

                    boost::asio::ip::address localIP = localEP_.address();
                    in_ = localIP.is_v4();
                }

                return success;
            }

            bool VirtualEthernetDatagramPort::Loopback() noexcept {
                if (disposed_) {
                    return false;
                }

                if (!socket_.is_open()) {
                    return false;
                }

                auto self = shared_from_this();
                socket_.async_receive_from(boost::asio::buffer(buffer_.get(), PPP_BUFFER_SIZE), remoteEP_,
                    [self, this](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        bool disposing = false;
                        if (ec == boost::system::errc::success) {
                            if (sz > 0) {
                                boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(remoteEP_);
                                if (!exchanger_->DoSendTo(transmission_, sourceEP_, remoteEP, buffer_.get(), sz, nullof<YieldContext>())) {
                                    disposing = true;
                                    transmission_->Dispose();
                                }
                            }
                        }
                        elif(ec == boost::system::errc::operation_canceled) {
                            disposing = true;
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

            bool VirtualEthernetDatagramPort::SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept {
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
                    socket_.send_to(boost::asio::buffer(packet, packet_length), Ipep::V6ToV4(destinationEP), boost::asio::socket_base::message_end_of_record, ec);
                }
                else {
                    socket_.send_to(boost::asio::buffer(packet, packet_length), Ipep::V4ToV6(destinationEP), boost::asio::socket_base::message_end_of_record, ec);
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