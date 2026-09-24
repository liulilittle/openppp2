#include <ppp/app/server/VirtualEthernetDatagramPort.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/net/native/checksum.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file VirtualEthernetDatagramPort.cpp
 * @brief Implements dynamic UDP relay port behavior for virtual ethernet traffic.
 */

typedef ppp::coroutines::YieldContext                   YieldContext;
typedef ppp::net::IPEndPoint                            IPEndPoint;
typedef ppp::net::Socket                                Socket;
typedef ppp::net::Ipep                                  Ipep;
typedef ppp::app::protocol::VirtualEthernetPacket       VirtualEthernetPacket;

namespace ppp {
    namespace app {
        namespace server {
            /**
             * @brief Initializes relay state and acquires a reusable receive buffer.
             */
            VirtualEthernetDatagramPort::VirtualEthernetDatagramPort(const VirtualEthernetExchangerPtr& exchanger, udp::ServerUdpRelayHostPorts ports, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept
                : disposed_(false)
                , onlydns_(true)
                , sendto_(false)
                , in_(false)
                , finalize_(false)
                , timeout_(0)
                , context_(transmission->GetContext())
                , socket_(*context_)
                , ports_(std::move(ports))
                , exchanger_(exchanger)
                , transmission_(transmission)
                , configuration_(ports_.get_configuration())
                , sourceEP_(sourceEP) {
                buffer_ = Executors::GetCachedBuffer(context_);
                Update();
            }

            /**
             * @brief Ensures asynchronous resources are finalized.
             */
            VirtualEthernetDatagramPort::~VirtualEthernetDatagramPort() noexcept {
                Finalize();
            }

            void VirtualEthernetDatagramPort::Update() noexcept {
                UInt64 now = Executors::GetTickCount();
                if (onlydns_) {
                    timeout_ = now + (UInt64)configuration_->udp.dns.timeout * 1000;
                }
                else {
                    timeout_ = now + (UInt64)configuration_->udp.inactive.timeout * 1000;
                }
            }

            bool VirtualEthernetDatagramPort::SendToClient(
                const ITransmissionPtr& transmission,
                const boost::asio::ip::udp::endpoint& destinationEP,
                const Byte* packet, int packet_length) noexcept {
                if (NULLPTR == transmission || packet_length < 0 ||
                    (NULLPTR == packet && packet_length != 0)) {
                    return false;
                }

                std::shared_ptr<boost::asio::io_context> context = transmission->GetContext();
                ITransmission::StrandPtr strand = transmission->GetStrand();
                if (NULLPTR == context || NULLPTR == strand) {
                    return false;
                }

                auto payload = std::make_shared<std::vector<Byte>>();
                if (packet_length > 0) {
                    payload->assign(packet, packet + packet_length);
                }

                udp::ServerUdpRelayHostPorts ports = ports_;
                VirtualEthernetExchangerPtr exchanger = exchanger_;
                boost::asio::ip::udp::endpoint sourceEP = sourceEP_;
                return YieldContext::Spawn(NULLPTR, *context, strand.get(),
                    [ports = std::move(ports), exchanger = std::move(exchanger),
                     transmission, sourceEP, destinationEP, payload, packet_length](
                        YieldContext& y) noexcept {
                        (void)exchanger;
                        Byte* data = packet_length > 0 ? payload->data() : NULLPTR;
                        if (!ports.do_send_to(transmission, sourceEP, destinationEP,
                                data, packet_length, y)) {
                            transmission->Dispose();
                        }
                    });
            }

            /**
             * @brief Closes socket, sends a close signal when needed, and unregisters this port.
             */
            void VirtualEthernetDatagramPort::Finalize() noexcept {
                std::shared_ptr<ITransmission> transmission = std::move(transmission_); 
                if (sendto_ && !finalize_) {
                    if (NULLPTR != transmission &&
                        !SendToClient(transmission, sourceEP_, NULLPTR, 0)) {
                        transmission->Dispose();
                    }
                }

                disposed_ = true;
                sendto_ = false;
                finalize_ = true;
                Socket::Closesocket(socket_);

                ports_.release_port(sourceEP_);
            }

            /**
             * @brief Dispatches finalization to the owning io_context thread.
             */
            void VirtualEthernetDatagramPort::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context, 
                    [self, this]() noexcept {
                        Finalize();
                    });
            }

            /**
             * @brief Opens and configures the UDP socket, then starts async receive loop.
             * @return True if opening and initialization succeed.
             */
            bool VirtualEthernetDatagramPort::Open() noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                bool opened = socket_.is_open();
                if (opened) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VEthernetDatagramPortOpenSocketAlreadyOpen);
                    return false;
                }

                boost::asio::ip::address address = ports_.get_interface_ip();

                bool success = VirtualEthernetPacket::OpenDatagramSocket(socket_, address, IPEndPoint::MinPort, sourceEP_) && Loopback();
                if (success) {
                    boost::system::error_code ec;
                    localEP_ = socket_.local_endpoint(ec);
                    if (ec) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpOpenFailed);
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

            bool VirtualEthernetDatagramPort::RebindTransmission(const ITransmissionPtr& transmission) noexcept {
                if (disposed_) {
                    return false;
                }
                if (NULLPTR != transmission && transmission->GetContext() != context_) {
                    return false;
                }

                transmission_ = transmission;
                return true;
            }

            /**
             * @brief Starts one asynchronous receive cycle for relay traffic.
             * @return True if receive operation is scheduled.
             */
            bool VirtualEthernetDatagramPort::Loopback() noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                bool opened = socket_.is_open();
                if (!opened) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                    return false;
                }

                auto self = shared_from_this();
                socket_.async_receive_from(boost::asio::buffer(buffer_.get(), PPP_BUFFER_SIZE), remoteEP_,
                    [self, this](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        bool disposing = ec != boost::system::errc::success;
                        while (!disposing) {
                            int bytes_transferred = static_cast<int>(sz);
                            if (bytes_transferred < 1) {
                                break;
                            }

                            if (configuration_->udp.dns.cache) {
                                int remotePort = remoteEP_.port();
                                if (remotePort == PPP_DNS_SYS_PORT) {
                                    ports_.namespace_query(buffer_.get(), bytes_transferred);
                                }
                            }

                            std::shared_ptr<ITransmission> transmission = transmission_;
                            if (NULLPTR == transmission) {
                                break;
                            }

                            boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(remoteEP_);
                            if (SendToClient(transmission, remoteEP,
                                    buffer_.get(), bytes_transferred)) {
                                Update();
                            }
                            else {
                                if (transmission_ == transmission) {
                                    transmission_.reset();
                                }
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

            /**
             * @brief Sends outbound UDP payload and refreshes aging timeout.
             * @return True on successful send.
             */
            bool VirtualEthernetDatagramPort::SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                bool opened = socket_.is_open();
                if (!opened) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                    return false;
                }

                int destinationPort = destinationEP.port();
                if (destinationPort <= IPEndPoint::MinPort || destinationPort > IPEndPoint::MaxPort) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
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
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpSendFailed);
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
