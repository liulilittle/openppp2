#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetDatagramPort.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>

/**
 * @file VEthernetDatagramPort.cpp
 * @brief Implements UDP datagram port lifecycle and forwarding behavior.
 */

typedef ppp::coroutines::YieldContext                   YieldContext;
typedef ppp::net::IPEndPoint                            IPEndPoint;
typedef ppp::net::Socket                                Socket;
typedef ppp::net::Ipep                                  Ipep;

namespace ppp {
    namespace app {
        namespace client {
            /**
             * @brief Constructs a UDP datagram port mapped from a source endpoint.
             * @param exchanger Shared exchanger that routes packets between local and remote paths.
             * @param transmission Underlying transmission channel for tunneled sends.
             * @param sourceEP Source UDP endpoint represented by this port mapping.
             */
            VEthernetDatagramPort::VEthernetDatagramPort(const VEthernetExchangerPtr& exchanger, udp::UdpRelayHostPorts ports, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept
                : disposed_(false)
                , onlydns_(true)
                , sendto_(false)
                , finalize_(false)
                , timeout_(0)
                , context_(transmission->GetContext())
                , ports_(std::move(ports))
                , exchanger_(exchanger)
                , transmission_(transmission)
                , configuration_(ports_.get_configuration())
                , sourceEP_(sourceEP)
#if defined(_ANDROID)
                , opened_(0)
                , socket_(*context_)
#endif
            {
                Update();

#if defined(_ANDROID)
                buffer_ = Executors::GetCachedBuffer(context_);
                ProtectorNetwork = ports_.get_protector_network();
#endif
            }

            /**
             * @brief Destroys the datagram port and finalizes resources.
             */
            VEthernetDatagramPort::~VEthernetDatagramPort() noexcept {
                Finalize();
            }

            /**
             * @brief Finalizes this port mapping and releases associated transport resources.
             * @note If packets were sent before finalization, a terminal notification send is attempted.
             */
            void VEthernetDatagramPort::Finalize() noexcept {
                std::shared_ptr<ITransmission> transmission;
                bool fin = false;

                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    transmission = std::move(transmission_);
                    if (sendto_ && !finalize_) {
                        fin = true;
                    }

                    disposed_ = true;
                    sendto_ = false;
                    finalize_ = true;

#if defined(_ANDROID)
                    messages_.clear();
                    Socket::Closesocket(socket_);
#endif
                    break;
                }

                ports_.release_port(sourceEP_, this);
                /**
                 * @brief Notify upstream path about closure when this mapping already transmitted data.
                 */
                if (fin && transmission) {
                    if (!ports_.do_send_to(transmission, sourceEP_, sourceEP_, NULLPTR, 0, nullof<YieldContext>())) {
                        transmission->Dispose();
                    }
                }
            }

            /**
             * @brief Schedules asynchronous disposal on the owning I/O context.
             */
            void VEthernetDatagramPort::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context, 
                    [self, this, context]() noexcept {
                        Finalize();
                    });
            }

            /**
             * @brief Sends one UDP payload through bypass socket or tunnel transmission.
             * @param packet Pointer to payload bytes.
             * @param packet_length Payload length in bytes.
             * @param destinationEP Destination UDP endpoint.
             * @return true if the payload is accepted for sending; otherwise false.
             * @note Android bypass mode may queue packets until local UDP socket opening completes.
             */
            bool VEthernetDatagramPort::RebindTransmission(
                const ITransmissionPtr& transmission) noexcept {
                if (NULLPTR != transmission && transmission->GetContext() != context_) {
                    return false;
                }

                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return false;
                }
                transmission_ = transmission;
                return true;
            }

            bool VEthernetDatagramPort::SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept {
                return SendTo(packet, packet_length, destinationEP, routing::RoutingAction::Auto);
            }

            bool VEthernetDatagramPort::SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP, routing::RoutingAction action) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                }

                std::shared_ptr<ITransmission> transmission;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                    }
                    transmission = transmission_;
                }

                int destinationPort = destinationEP.port();
                if (destinationPort <= IPEndPoint::MinPort || destinationPort > IPEndPoint::MaxPort) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                }

                boost::asio::ip::address address = destinationEP.address();
                if (address.is_unspecified()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                routing::UdpRoutingSelectorInput routing_input;
                routing_input.action = action;
#if defined(_ANDROID)
                if (address.is_v4()) {
                    routing_input.platform = routing::UdpRoutingPlatform::Android;
                    routing_input.legacy_bypass = ports_.is_bypass_ip(address);
                }
#endif
                routing::UdpRoutingMode routing_mode = routing::UdpRoutingSelector::Select(routing_input);
                if (routing_mode == routing::UdpRoutingMode::Reject) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpSendFailed);
                }

                bool ok = false;
                bool fin = false;

                /**
                 * @brief Select direct physical-network bypass or VPN tunnel forwarding.
                 */
                do {
                    if (NULLPTR == transmission) {
                        // Suspension intentionally detaches the carrier without deleting
                        // the logical UDP flow; a committed resume will rebind it.
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                        break;
                    }

#if defined(_ANDROID)
                    // It is sent out through the local physical NIC.
                    if (routing_mode == routing::UdpRoutingMode::DirectSocket) {
                        // If the socket is currently open, send data directly.
                        SynchronizedObjectScope scope(syncobj_);
                        if (opened_ > 1) {
                            boost::system::error_code ec;
                            socket_.send_to(boost::asio::buffer(packet, packet_length), 
                                destinationEP, boost::asio::socket_base::message_end_of_record, ec);

                            if (ec == boost::system::errc::success) {
                                ok = true;
                            }
                            else {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpSendFailed);
                                fin = true;
                            }
                        }
                        else {
                            // If you are not currently opening a physical network socket, try to open the socket.
                            auto allocator = transmission->BufferAllocator;
                            if (opened_ < 1) {
                                auto self = shared_from_this();
                                auto context = context_;

                                bool opening = YieldContext::Spawn(allocator.get(), *context,
                                    [self, this, context](YieldContext& y) noexcept {
                                        bool opened = Open(y);
                                        if (!opened) {
                                            Dispose();
                                        }
                                    });

                                if (opening) {
                                    opened_ = 1;
                                }
                                else {
                                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineSpawnFailed);
                                    fin = true;
                                    break;
                                }
                            }

                            // If you are currently trying to open the socket, cache the data and do not send it until it is opened.
                            std::shared_ptr<Byte> packet_managed = ppp::net::asio::IAsynchronousWriteIoQueue::Copy(allocator, packet, packet_length);
                            if (NULLPTR == packet_managed) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                                break;
                            }

                            Message message;
                            message.packet        = packet_managed;
                            message.packet_length = packet_length;
                            message.destinationEP = destinationEP;
                            message.action        = action;

                            ok = true;
                            messages_.emplace_back(message);
                        }

                        break;
                    }
#endif
                    // Send it to the VPN server for outgoing.
                    ok = ports_.do_send_to(transmission, sourceEP_, destinationEP, (Byte*)packet, packet_length, nullof<YieldContext>());
                    if (destinationPort == PPP_DNS_SYS_PORT || !ok) {
                        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "udp_port", "DoSendTo source=%s:%u destination=%s:%u bytes=%d ok=%d",
                            sourceEP_.address().to_string().c_str(),
                            sourceEP_.port(),
                            destinationEP.address().to_string().c_str(),
                            destinationEP.port(),
                            packet_length,
                            ok ? 1 : 0);
                    }
                    if (!ok) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpSendFailed);
                        fin = true;
                        transmission->Dispose();
                    }
                } while (false);

                // Successfully sent a UDP data packet, so need to update the last activity time.
                if (ok) {
                    sendto_ = true;
                    if (destinationPort != PPP_DNS_SYS_PORT) {
                        onlydns_ = false;
                    }

                    Update();
                }

                // UDP port mapping has failed and needs to be shut down.
                if (fin) {
                    Dispose();
                }

                return ok;
            }

            /**
             * @brief Forwards a received UDP payload to switcher output processing.
             * @param packet Payload buffer.
             * @param packet_length Payload length in bytes.
             * @param destinationEP Destination endpoint associated with the payload.
             */
            void VEthernetDatagramPort::OnMessage(const std::shared_ptr<Byte>& owner, void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept {
                ports_.datagram_output(sourceEP_, destinationEP, owner, packet, packet_length, true);
            }

#if defined(_ANDROID)
            /**
             * @brief Opens bypass UDP socket, protects it, and replays buffered payloads.
             * @param y Coroutine yield context for coordinated async operations.
             * @return true when socket setup and receive loop start succeed.
             */
            bool VEthernetDatagramPort::Open(ppp::coroutines::YieldContext& y) noexcept {
                if (disposed_) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                bool opened = false;
                boost::asio::io_context& context = y.GetContext();

                boost::asio::post(context, 
                    [this, &y, &opened]() noexcept {
                        // Open the udp port and listen on any address 0.0.0.0.
                        for (;;) {
                            SynchronizedObjectScope scope(syncobj_);
                            opened = Socket::OpenSocket(socket_,
                                boost::asio::ip::address_v4::any(), IPEndPoint::MinPort);
                            break;
                        }

                        // Wake up the coroutine currently waiting to open the udp socket.
                        y.R();
                    });

                // Suspend and wait for the udp socket to open.
                y.Suspend();
                if (!opened) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                    return false;
                }
                else {
                    ppp::net::Socket::SetWindowSizeIfNotZero(socket_.native_handle(), configuration_->udp.cwnd, configuration_->udp.rwnd);
                }

                // Protect udp sockets to prevent udp data from being sent to the VPN loop.
                auto protector_network = ProtectorNetwork;
                if (NULLPTR == protector_network ||
                    !protector_network->Protect(socket_.native_handle(), y)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                    return false;
                }

                /**
                 * @brief Move queued payloads out of shared state, then flush them after socket readiness.
                 */
                // Send all unsent message data to the public network.
                Messages messages; {
                    SynchronizedObjectScope scope(syncobj_);
                    opened_ = 2;

                    messages = std::move(messages_);
                    messages_.clear();
                }

                for (Message& message : messages) {
                    SendTo(message.packet.get(), message.packet_length, message.destinationEP, message.action);
                }

                bool ok = Loopback();
                if (!ok && !disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpRelayFailed);
                }

                return ok;
            }

            /**
             * @brief Runs asynchronous receive loop on the bypass UDP socket.
             * @return true if a receive operation is scheduled; otherwise false.
             * @note The mutex is released before registering the async receive to avoid Pattern-D
             *       deadlock: the completion callback calls Loopback() which re-acquires syncobj_.
             *       Holding syncobj_ across async_receive_from is therefore illegal.
             */
            bool VEthernetDatagramPort::Loopback() noexcept {
                // Validate invariants under lock, then release before scheduling async I/O.
                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                    }

                    if (!socket_.is_open()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
                        return false;
                    }

                    break;
                }

                // IMPORTANT: async_receive_from is intentionally called outside the syncobj_ scope.
                // The completion callback re-enters Loopback() which re-acquires syncobj_; holding
                // the mutex here would create a Pattern-D deadlock on the first callback dispatch.
                auto self = shared_from_this();
                socket_.async_receive_from(boost::asio::buffer(buffer_.get(), PPP_BUFFER_SIZE), remoteEP_,
                    [self, this](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        bool disposing = false;
                        if (ec == boost::system::errc::success) {
                            if (sz > 0) {
                                OnMessage(buffer_, buffer_.get(), sz, remoteEP_);
                            }
                        }
                        elif(ec == boost::system::errc::operation_canceled) {
                            disposing = true;
                        }
                        else {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpRelayFailed);
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
#endif
        }
    }
}
