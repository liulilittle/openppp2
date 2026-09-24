#include <ppp/app/client/ExchangerStaticEchoChannel.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/asio/vdns.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/Timer.h>

#include <common/aggligator/aggligator.h>

#include <algorithm>

namespace ppp {
    namespace app {
        namespace client {

            typedef ppp::app::protocol::VirtualEthernetPacket                   VirtualEthernetPacket;
            typedef ppp::net::AddressFamily                                     AddressFamily;
            typedef ppp::net::Socket                                            Socket;
            typedef ppp::net::IPEndPoint                                        IPEndPoint;
            typedef ppp::net::Ipep                                              Ipep;
            typedef ppp::threading::Timer                                       Timer;
            typedef ppp::threading::Executors                                   Executors;
            typedef VEthernetExchanger::ITransmissionPtr                        ITransmissionPtr;
            typedef VEthernetExchanger::AppConfigurationPtr                    AppConfigurationPtr;
            typedef VEthernetExchanger::YieldContext                            YieldContext;

            static constexpr int STATIC_ECHO_KEEP_ALIVED_ID = IPEndPoint::NoneAddress - 1;

            struct ExchangerStaticEchoDetail {
                typedef ExchangerStaticEchoChannel::StaticEchoDatagarmSocket            StaticEchoDatagarmSocket;
                static bool StaticEchoNextTimeout(VEthernetExchanger& owner) noexcept;
                static bool StaticEchoOpenAsynchronousSocket(VEthernetExchanger& owner, ExchangerStaticEchoChannel& channel, StaticEchoDatagarmSocket& socket, ppp::coroutines::YieldContext& y) noexcept;
                static bool StaticEchoLoopbackSocket(VEthernetExchanger& owner, ExchangerStaticEchoChannel& channel, const std::shared_ptr<StaticEchoDatagarmSocket>& socket) noexcept;
                static boost::asio::ip::udp::endpoint StaticEchoGetRemoteEndPoint(VEthernetExchanger& owner) noexcept;
                static bool StaticEchoPacketToRemoteExchanger(VEthernetExchanger& owner, ExchangerStaticEchoChannel& channel, const std::shared_ptr<Byte>& packet, int packet_length) noexcept;
                static std::shared_ptr<VirtualEthernetPacket> StaticEchoReadPacket(VEthernetExchanger& owner, const void* packet, int packet_length) noexcept;
                static bool StaticEchoPacketInput(VEthernetExchanger& owner, const std::shared_ptr<VirtualEthernetPacket>& packet) noexcept;
                static int StaticEchoYieldReceiveForm(VEthernetExchanger& owner, ExchangerStaticEchoChannel& channel, Byte* incoming_packet, int incoming_traffic) noexcept;
            };

            void ExchangerStaticEchoChannel::Bind(VEthernetExchanger* owner) noexcept {
                owner_ = owner;
            }

            void ExchangerStaticEchoChannel::InitializeCiphers(
                const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept {
                if (configuration->key.protocol.size() > 0 && configuration->key.protocol_key.size() > 0 &&
                    configuration->key.transport.size() > 0 && configuration->key.transport_key.size() > 0) {
                    if (ppp::cryptography::Ciphertext::Support(configuration->key.protocol) &&
                        ppp::cryptography::Ciphertext::Support(configuration->key.transport)) {
                        static_echo_protocol_ = make_shared_object<ppp::cryptography::Ciphertext>(
                            configuration->key.protocol, configuration->key.protocol_key);
                        static_echo_transport_ = make_shared_object<ppp::cryptography::Ciphertext>(
                            configuration->key.transport, configuration->key.transport_key);
                    }
                }
            }

            void ExchangerStaticEchoChannel::ConfigureSession(
                const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                const ppp::Int128& id,
                const ppp::Int128& fsid,
                int session_id,
                int remote_port) noexcept {
                static_echo_session_id_ = session_id;
                static_echo_remote_port_ = remote_port;
                VirtualEthernetPacket::Ciphertext(
                    configuration, id, fsid, session_id, static_echo_protocol_, static_echo_transport_);
            }

            /** @brief Closes static-echo sockets and resets static-session state. */
            void ExchangerStaticEchoChannel::StaticEchoClean() noexcept {
                VEthernetExchanger& owner = *owner_;
                for (int i = 0; i < arraysizeof(owner.static_echo_.static_echo_sockets_); i++) {
                    std::shared_ptr<ExchangerStaticEchoDetail::StaticEchoDatagarmSocket>& r = owner.static_echo_.static_echo_sockets_[i];
                    std::shared_ptr<ExchangerStaticEchoDetail::StaticEchoDatagarmSocket> socket = std::move(r);

                    Socket::Closesocket(socket);
                }

                owner.static_echo_.static_echo_input_       = false;
                owner.static_echo_.static_echo_timeout_     = UINT64_MAX;
                owner.static_echo_.static_echo_session_id_  = 0;
                owner.static_echo_.static_echo_remote_port_ = IPEndPoint::MinPort;

                owner.static_echo_.static_echo_protocol_    = NULLPTR;
                owner.static_echo_.static_echo_transport_   = NULLPTR;
            }

            /** @brief Returns whether static-echo data path is currently usable. */
            bool ExchangerStaticEchoChannel::StaticEchoAllocated() noexcept {
                VEthernetExchanger& owner = *owner_;
                if (owner.disposed_.load(std::memory_order_acquire)) {
                    return false;
                }

                std::shared_ptr<ExchangerStaticEchoDetail::StaticEchoDatagarmSocket> socket = owner.static_echo_.static_echo_sockets_[0];
                if (NULLPTR == socket) {
                    return false;
                }

                return socket->is_open() && owner.static_echo_.static_echo_timeout_ != 0 && owner.static_echo_.static_echo_session_id_ != 0 && owner.static_echo_.static_echo_remote_port_ != 0;
            }

            /** @brief Rotates static-echo active socket when keepalive window expires. */
            bool ExchangerStaticEchoChannel::StaticEchoSwapAsynchronousSocket() noexcept {
                VEthernetExchanger& owner = *owner_;
                if (owner.disposed_.load(std::memory_order_acquire)) {
                    return false;
                }

                if (owner.static_echo_.static_echo_timeout_ != UINT64_MAX && owner.switcher_->StaticMode(NULLPTR)) {
                    UInt64 now = ppp::threading::Executors::GetTickCount();
                    if (now >= owner.static_echo_.static_echo_timeout_) {
                        std::shared_ptr<ExchangerStaticEchoDetail::StaticEchoDatagarmSocket> socket = std::move(owner.static_echo_.static_echo_sockets_[0]);
                        owner.static_echo_.static_echo_sockets_[0] = std::move(owner.static_echo_.static_echo_sockets_[1]);
                        owner.static_echo_.static_echo_sockets_[1] = NULLPTR;

                        owner.static_echo_.static_echo_input_ = false;
                        if (!ExchangerStaticEchoDetail::StaticEchoNextTimeout(owner)) {
                            return false;
                        }

                        auto self = owner.shared_from_this();
                        auto notifiy_if_need =
                            [self, &owner, this]() noexcept {
                                // Notifies the VPN server of domestic port changes for smoother dynamic switchover of virtual links.
                                if (!owner.static_echo_.static_echo_input_ && owner.static_echo_.static_echo_sockets_[0]) {
                                    StaticEchoGatewayServer(STATIC_ECHO_KEEP_ALIVED_ID);
                                }
                            };

                        // Here do not close the socket immediately, delay one second, because the data sent by the VPN server may not reach the network card,
                        // Reduce the packet loss rate during switching and improve the smoothness of the cross.
                        bool closesocket = true;
                        std::shared_ptr<boost::asio::io_context> context = owner.GetContext();
                        if (NULLPTR != context) {
                            int milliseconds = RandomNext(500, 1000);
                            std::shared_ptr<Timer> timeout = Timer::Timeout(context, milliseconds,
                                [socket, notifiy_if_need](Timer*) noexcept {
                                    notifiy_if_need();
                                    Socket::Closesocket(socket);
                                });
                            if (NULLPTR != timeout) {
                                closesocket = false;
                            }
                        }

                        // Handles whether you can delay closing the socket. If not, close the socket immediately.
                        if (closesocket) {
                            Socket::Closesocket(socket);
                        }

                        notifiy_if_need();
                        if (NULLPTR == context) {
                            return false;
                        }

                        // Re-instance and try to open the Datagram Port.
                        socket = make_shared_object<ExchangerStaticEchoDetail::StaticEchoDatagarmSocket>(*context);
                        if (NULLPTR == socket) {
                            return false;
                        }

                        auto configuration = owner.GetConfiguration();
                        auto allocator = configuration->GetBufferAllocator();
                        owner.static_echo_.static_echo_sockets_[1] = socket;

                        return YieldContext::Spawn(allocator.get(), *context,
                            [self, &owner, this, socket, context](YieldContext& y) noexcept {
                                bool opened = ExchangerStaticEchoDetail::StaticEchoOpenAsynchronousSocket(owner, *this, *socket, y);
                                if (opened) {
                                    ExchangerStaticEchoDetail::StaticEchoLoopbackSocket(owner, *this, socket);
                                }
                            });
                    }
                }

                return true;
            }

            /** @brief Sends static-echo gateway keepalive marker packet. */
            bool ExchangerStaticEchoChannel::StaticEchoGatewayServer(int ack_id) noexcept {
                VEthernetExchanger& owner = *owner_;
                if (owner.disposed_.load(std::memory_order_acquire)) {
                    return false;
                }

                std::shared_ptr<ppp::net::packet::IPFrame> packet = make_shared_object<ppp::net::packet::IPFrame>();
                if (NULLPTR == packet) {
                    return false;
                }

                packet->AddressesFamily = AddressFamily::InterNetwork;
                packet->Destination     = htonl(ack_id);
                packet->Id              = ppp::net::packet::IPFrame::NewId();
                packet->Source          = IPEndPoint::LoopbackAddress;
                packet->ProtocolType    = ppp::net::native::ip_hdr::IP_PROTO_ICMP;
                ppp::app::protocol::VirtualEthernetPacket::FillBytesToPayload(packet.get());

                return StaticEchoPacketToRemoteExchanger(packet.get());
            }

            /** @brief Allocates static-echo sockets and negotiates static mode remotely. */
            bool ExchangerStaticEchoChannel::StaticEchoAllocatedToRemoteExchanger(YieldContext& y) noexcept {
                StaticEchoClean();
                VEthernetExchanger& owner = *owner_;
                if (owner.disposed_.load(std::memory_order_acquire)) {
                    return false;
                }

                if (StaticEchoAllocated()) {
                    return true;
                }

                std::shared_ptr<boost::asio::io_context> context = owner.GetContext();
                if (NULLPTR == context) {
                    return false;
                }

                bool static_mode = owner.switcher_->StaticMode(NULLPTR);
                if (!static_mode) {
                    return true;
                }

                for (int i = 0; i < arraysizeof(owner.static_echo_.static_echo_sockets_); i++) {
                    std::shared_ptr<ExchangerStaticEchoDetail::StaticEchoDatagarmSocket>& socket = owner.static_echo_.static_echo_sockets_[i];
                    if (NULLPTR == socket) {
                        socket = make_shared_object<ExchangerStaticEchoDetail::StaticEchoDatagarmSocket>(*context);
                        if (NULLPTR == socket) {
                            return false;
                        }
                    }

                    if (socket->is_open(true)) {
                        continue;
                    }

                    bool opened = ExchangerStaticEchoDetail::StaticEchoOpenAsynchronousSocket(owner, *this, *socket, y) && ExchangerStaticEchoDetail::StaticEchoLoopbackSocket(owner, *this, socket);
                    if (!opened) {
                        socket.reset();
                        return false;
                    }
                }

                ITransmissionPtr transmission = owner.GetTransmission();
                if (NULLPTR == transmission) {
                    return false;
                }

                return owner.DoStatic(transmission, y);
            }

            /** @brief Packs and sends an IP frame over static-echo transport. */
            bool ExchangerStaticEchoChannel::StaticEchoPacketToRemoteExchanger(const ppp::net::packet::IPFrame* packet) noexcept {
                if (NULLPTR == packet || packet->AddressesFamily != AddressFamily::InterNetwork) {
                    return false;
                }

                VEthernetExchanger& owner = *owner_;
                if (owner.disposed_.load(std::memory_order_acquire)) {
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = owner.GetConfiguration();
                if (NULLPTR == configuration) {
                    return false;
                }

                int session_id = owner.static_echo_.static_echo_session_id_;
                if (session_id < 1) {
                    return false;
                }

                int message_length = -1;
                std::shared_ptr<Byte> messages = VirtualEthernetPacket::Pack(configuration,
                    configuration->GetBufferAllocator(),
                    VirtualEthernetPacket::SessionCiphertext([&owner](int) noexcept { return owner.static_echo_.static_echo_protocol_; }),
                    VirtualEthernetPacket::SessionCiphertext([&owner](int) noexcept { return owner.static_echo_.static_echo_transport_; }),
                    session_id,
                    packet,
                    message_length);
                return ExchangerStaticEchoDetail::StaticEchoPacketToRemoteExchanger(owner, *this, messages, message_length);
            }

            /** @brief Packs and sends a UDP frame over static-echo transport. */
            bool ExchangerStaticEchoChannel::StaticEchoPacketToRemoteExchanger(const std::shared_ptr<ppp::net::packet::UdpFrame>& frame) noexcept {
                if (NULLPTR == frame || frame->AddressesFamily != AddressFamily::InterNetwork) {
                    return false;
                }

                VEthernetExchanger& owner = *owner_;
                if (owner.disposed_.load(std::memory_order_acquire)) {
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = owner.GetConfiguration();
                if (NULLPTR == configuration) {
                    return false;
                }

                int session_id = owner.static_echo_.static_echo_session_id_;
                if (session_id < 1) {
                    return false;
                }

                std::shared_ptr<ppp::net::packet::BufferSegment> payload_buffers = frame->Payload;
                if (NULLPTR == payload_buffers) {
                    return false;
                }

                int packet_length = -1;
                uint32_t source_ip = frame->Source.GetAddress();
                uint32_t destination_ip = frame->Destination.GetAddress();
                std::shared_ptr<Byte> packet = VirtualEthernetPacket::Pack(configuration,
                    configuration->GetBufferAllocator(),
                    VirtualEthernetPacket::SessionCiphertext([&owner](int) noexcept { return owner.static_echo_.static_echo_protocol_; }),
                    VirtualEthernetPacket::SessionCiphertext([&owner](int) noexcept { return owner.static_echo_.static_echo_transport_; }),
                    session_id,
                    source_ip,
                    frame->Source.Port,
                    destination_ip,
                    frame->Destination.Port,
                    payload_buffers->Buffer.get(),
                    payload_buffers->Length,
                    packet_length);
                return ExchangerStaticEchoDetail::StaticEchoPacketToRemoteExchanger(owner, *this, packet, packet_length);
            }

            /** @brief Sends a pre-packed static-echo packet to selected remote endpoint. */
            bool ExchangerStaticEchoChannel::StaticEchoPacketToRemoteExchanger(const std::shared_ptr<Byte>& packet, int packet_length) noexcept {
                return ExchangerStaticEchoDetail::StaticEchoPacketToRemoteExchanger(*owner_, *this, packet, packet_length);
            }

            /** @brief Adds static-echo remote endpoint into balance set/list. */
            bool ExchangerStaticEchoChannel::StaticEchoAddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept {
                boost::asio::ip::udp::endpoint destinationEP = Ipep::V4ToV6(remoteEP);
                boost::asio::ip::address destinationIP = destinationEP.address();
                if (!AcceptsBalancePoolEndpoint(destinationIP)) {
                    return false;
                }

                VEthernetExchanger& owner = *owner_;
                VEthernetExchanger::SynchronizedObjectScope scope(owner.static_echo_.syncobj_);
                auto r = owner.static_echo_.static_echo_server_ep_set_.emplace(destinationEP);
                if (!r.second) {
                    return false;
                }

                owner.static_echo_.static_echo_server_ep_balances_.emplace_back(destinationEP);
                return true;
            }

            /** @brief Computes next timeout used for static-echo socket rotation. */
            bool ExchangerStaticEchoDetail::StaticEchoNextTimeout(VEthernetExchanger& owner) noexcept {
                    if (owner.disposed_.load(std::memory_order_acquire)) {
                        return false;
                    }

                    std::shared_ptr<ExchangerStaticEchoDetail::StaticEchoDatagarmSocket> socket = owner.static_echo_.static_echo_sockets_[0];
                    if (NULLPTR == socket) {
                        return false;
                    }

                    bool opened = socket->is_open(true);
                    if (!opened) {
                        return false;
                    }

                    AppConfigurationPtr configuration = owner.GetConfiguration();
                    int min = std::max<int>(0, configuration->udp.static_.keep_alived[0]);
                    int max = std::max<int>(0, configuration->udp.static_.keep_alived[1]);
                    if (min == 0) {
                        min = PPP_UDP_KEEP_ALIVED_MIN_TIMEOUT;
                    }

                    if (max == 0) {
                        max = PPP_UDP_KEEP_ALIVED_MAX_TIMEOUT;
                    }

                    if (min > max) {
                        std::swap(min, max);
                    }

                    uint64_t tick = ppp::threading::Executors::GetTickCount();
                    min = std::max<int>(1, min) * 1000;
                    max = std::max<int>(1, max) * 1000;

                    if (min == max) {
                        owner.static_echo_.static_echo_timeout_ = tick + min;
                    }
                    else {
                        uint64_t next = RandomNext(min, max + 1);
                        owner.static_echo_.static_echo_timeout_ = tick + next;
                    }

                    return true;
                }

                /** @brief Sends a pre-packed static-echo packet to selected remote endpoint. */
                bool ExchangerStaticEchoDetail::StaticEchoPacketToRemoteExchanger(VEthernetExchanger& owner, ExchangerStaticEchoChannel& channel, const std::shared_ptr<Byte>& packet, int packet_length) noexcept {
                    if (NULLPTR == packet || packet_length < 1) {
                        return false;
                    }

                    if (owner.disposed_.load(std::memory_order_acquire)) {
                        return false;
                    }

                    std::shared_ptr<ExchangerStaticEchoDetail::StaticEchoDatagarmSocket> socket = owner.static_echo_.static_echo_sockets_[0];
                    if (NULLPTR == socket) {
                        return false;
                    }

                    bool opened = socket->is_open();
                    if (!opened) {
                        return false;
                    }

                    boost::asio::ip::udp::endpoint serverEP = ExchangerStaticEchoDetail::StaticEchoGetRemoteEndPoint(owner);
                    if (ExchangerStaticEchoChannel::IsValidServerPort(serverEP.port())) {
                        std::shared_ptr<ppp::transmissions::ITransmissionStatistics> statistics = owner.switcher_->GetStatistics();
                        boost::asio::post(socket->get_executor(),
                            [statistics, socket, packet, packet_length, serverEP]() noexcept {
                                boost::system::error_code ec;
                                socket->send_to(boost::asio::buffer(packet.get(), packet_length), serverEP,
                                    boost::asio::socket_base::message_end_of_record, ec);

                                if (ec == boost::system::errc::success) {
                                    if (NULLPTR != statistics) {
                                        statistics->AddOutgoingTraffic(packet_length);
                                    }
                                }
                            });
                        return true;
                    }

                    return false;
                }

                /** @brief Decodes and decrypts incoming static-echo packet. */
                std::shared_ptr<VirtualEthernetPacket> ExchangerStaticEchoDetail::StaticEchoReadPacket(VEthernetExchanger& owner, const void* packet, int packet_length) noexcept {
                    if (NULLPTR == packet || packet_length < 1) {
                        return NULLPTR;
                    }

                    if (owner.disposed_.load(std::memory_order_acquire)) {
                        return NULLPTR;
                    }

                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = owner.GetConfiguration();
                    if (NULLPTR == configuration) {
                        return NULLPTR;
                    }

                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = configuration->GetBufferAllocator();
                    return VirtualEthernetPacket::Unpack(configuration,
                        allocator,
                        VirtualEthernetPacket::SessionCiphertext([&owner](int) noexcept { return owner.static_echo_.static_echo_protocol_; }),
                        VirtualEthernetPacket::SessionCiphertext([&owner](int) noexcept { return owner.static_echo_.static_echo_transport_; }),
                        packet,
                        packet_length);
                }

                /** @brief Injects decoded static-echo packet into local output path. */
                bool ExchangerStaticEchoDetail::StaticEchoPacketInput(VEthernetExchanger& owner, const std::shared_ptr<VirtualEthernetPacket>& packet) noexcept {
                    if (NULLPTR == packet || owner.disposed_.load(std::memory_order_acquire)) {
                        return false;
                    }

                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = owner.GetConfiguration();
                    if (NULLPTR == configuration) {
                        return false;
                    }

                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = configuration->GetBufferAllocator();
                    owner.static_echo_.static_echo_input_ = true;

                    if (packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_UDP) {
                        auto tap = owner.switcher_->GetTap();
                        if (NULLPTR == tap) {
                            return false;
                        }

                        std::shared_ptr<ppp::net::packet::UdpFrame> frame = packet->GetUdpPacket();
                        if (NULLPTR == frame) {
                            return false;
                        }

                        std::shared_ptr<ppp::net::packet::IPFrame> ip = frame->ToIp(allocator);
                        if (NULLPTR == ip) {
                            return false;
                        }

                        if (configuration->udp.dns.cache && frame->Source.Port == PPP_DNS_SYS_PORT) {
                            auto payload = frame->Payload;
                            if (NULLPTR != payload) {
                                ppp::net::asio::vdns::AddCache(payload->Buffer.get(), payload->Length);
                            }
                        }

                        return owner.switcher_->Output(ip.get());
                    }
                    elif(packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_IP) {
                        std::shared_ptr<ppp::net::packet::IPFrame> frame = packet->GetIPPacket(allocator);
                        if (NULLPTR == frame) {
                            return false;
                        }

                        if (frame->ProtocolType == ppp::net::native::ip_hdr::IP_PROTO_ICMP) {
                            if (frame->Source == IPEndPoint::LoopbackAddress) {
                                int ack_id = ntohl(frame->Destination);
                                if (ack_id == 0 || ack_id == STATIC_ECHO_KEEP_ALIVED_ID) {
                                    return false;
                                }

                                return owner.switcher_->ERORTE(ack_id);
                            }
                        }

                        return owner.switcher_->Output(frame.get());
                    }
                    else {
                        return false;
                    }
                }

                /** @brief Handles one static-echo receive completion and updates statistics. */
                int ExchangerStaticEchoDetail::StaticEchoYieldReceiveForm(VEthernetExchanger& owner, ExchangerStaticEchoChannel& channel, Byte* incoming_packet, int incoming_traffic) noexcept {
                    std::shared_ptr<VirtualEthernetPacket> packet = ExchangerStaticEchoDetail::StaticEchoReadPacket(owner, incoming_packet, incoming_traffic);
                    if (NULLPTR != packet) {
                        ExchangerStaticEchoDetail::StaticEchoPacketInput(owner, packet);
                    }

                    auto statistics = owner.switcher_->GetStatistics();
                    if (NULLPTR != statistics) {
                        statistics->AddIncomingTraffic(incoming_traffic);
                    }

                    return incoming_traffic;
                }

                /** @brief Starts or continues async receive loop for static-echo socket. */
            bool ExchangerStaticEchoDetail::StaticEchoLoopbackSocket(VEthernetExchanger& owner, ExchangerStaticEchoChannel& channel, const std::shared_ptr<StaticEchoDatagarmSocket>& socket) noexcept {
                    if (owner.disposed_.load(std::memory_order_acquire)) {
                        return false;
                    }

                    bool openped = socket->is_open();
                    if (!openped) {
                        return false;
                    }

                    if (NULLPTR == socket->receive_buffer_) {
                        socket->receive_buffer_ = ppp::make_shared_alloc<Byte>(PPP_BUFFER_SIZE);
                        if (NULLPTR == socket->receive_buffer_) {
                            return false;
                        }
                    }

                    auto self = owner.shared_from_this();
                    if (std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = owner.switcher_->GetQoS(); NULLPTR != qos) {
                        return qos->BeginRead(
                            [self, &owner, &channel, socket, qos]() noexcept {
                                socket->async_receive_from(boost::asio::buffer(socket->receive_buffer_.get(), PPP_BUFFER_SIZE), socket->receive_source_ep_,
                                    [self, &owner, &channel, qos, socket](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                        int bytes_transferred = std::max<int>(-1, ec ? -1 : (int)sz);
                                        if (bytes_transferred > 0) {
                                            qos->EndRead(ExchangerStaticEchoDetail::StaticEchoYieldReceiveForm(owner, channel, socket->receive_buffer_.get(), bytes_transferred));
                                        }

                                        ExchangerStaticEchoDetail::StaticEchoLoopbackSocket(owner, channel, socket);
                                    });
                            });
                    }
                    else {
                        socket->async_receive_from(boost::asio::buffer(socket->receive_buffer_.get(), PPP_BUFFER_SIZE), socket->receive_source_ep_,
                            [self, &owner, &channel, qos, socket](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                int bytes_transferred = std::max<int>(-1, ec ? -1 : (int)sz);
                                if (bytes_transferred > 0) {
                                    ExchangerStaticEchoDetail::StaticEchoYieldReceiveForm(owner, channel, socket->receive_buffer_.get(), bytes_transferred);
                                }

                                ExchangerStaticEchoDetail::StaticEchoLoopbackSocket(owner, channel, socket);
                            });
                        return true;
                    }
                }

                /** @brief Chooses remote endpoint for next static-echo transmission. */
                boost::asio::ip::udp::endpoint ExchangerStaticEchoDetail::StaticEchoGetRemoteEndPoint(VEthernetExchanger& owner) noexcept {
                    std::shared_ptr<aggligator::aggligator> aggligator = owner.switcher_->GetAggligator();
                    if (NULLPTR != aggligator) {
#if !defined(_ANDROID) && !defined(_IPHONE)
                        auto ni = owner.switcher_->GetUnderlyingNetworkInterface();
                        if (NULLPTR != ni) {
                            boost::asio::ip::udp::endpoint ep = aggligator->client_endpoint(ni->IPAddress);
                            return Ipep::V4ToV6(ep);
                        }
#endif
                        return aggligator->client_endpoint(boost::asio::ip::address_v6::loopback());
                    }

                    boost::asio::ip::udp::endpoint destinationEP;
                    for (VEthernetExchanger::SynchronizedObjectScope scope(owner.static_echo_.syncobj_);;) {
                        auto tail = owner.static_echo_.static_echo_server_ep_balances_.begin();
                        auto endl = owner.static_echo_.static_echo_server_ep_balances_.end();
                        if (tail == endl) {
                            destinationEP = boost::asio::ip::udp::endpoint(owner.server_url_.remoteEP.address(), owner.static_echo_.static_echo_remote_port_);
                            break;
                        }

                        std::size_t server_addrsss_num = owner.static_echo_.static_echo_server_ep_set_.size();
                        if (server_addrsss_num == 1) {
                            destinationEP = *owner.static_echo_.static_echo_server_ep_balances_.begin();
                        }
                        else {
                            destinationEP = *tail;
                            owner.static_echo_.static_echo_server_ep_balances_.erase(tail);
                            owner.static_echo_.static_echo_server_ep_balances_.emplace_back(destinationEP);
                        }

                        break;
                    }

                    return Ipep::V4ToV6(destinationEP);
                }

                /** @brief Opens and configures static-echo UDP socket for use. */
            bool ExchangerStaticEchoDetail::StaticEchoOpenAsynchronousSocket(VEthernetExchanger& owner, ExchangerStaticEchoChannel& channel, StaticEchoDatagarmSocket& socket, YieldContext& y) noexcept {
                    if (owner.disposed_.load(std::memory_order_acquire)) {
                        return false;
                    }

                    bool opened = socket.is_open(true);
                    if (opened) {
                        return true;
                    }

                    if (!ExchangerStaticEchoChannel::IsValidServerPort(owner.server_url_.port)) {
                        return false;
                    }

                    AppConfigurationPtr configuration = owner.GetConfiguration();
                    if (NULLPTR == configuration) {
                        return false;
                    }

                    opened = ppp::coroutines::asio::async_open<boost::asio::ip::udp::socket>(y, socket, boost::asio::ip::udp::v6()) && !owner.disposed_.load(std::memory_order_acquire);
                    if (!opened) {
                        return false;
                    }

                    bool ok = false;
                    for (;;) {
                        opened = Socket::OpenSocket(socket, boost::asio::ip::address_v6::any(), IPEndPoint::MinPort, opened);
                        if (!opened) {
                            break;
                        }
                        else {
                            Socket::SetWindowSizeIfNotZero(socket.native_handle(), configuration->udp.cwnd, configuration->udp.rwnd);
                        }

#if defined(_ANDROID)
                        std::shared_ptr<aggligator::aggligator> aggligator = owner.switcher_->GetAggligator();
                        if (NULLPTR == aggligator) {
                            auto protector_network = owner.switcher_->GetProtectorNetwork();
                            if (NULLPTR != protector_network) {
                                opened = protector_network->Protect(socket.native_handle(), y);
                                if (!opened) {
                                    break;
                                }
                            }
                        }
#endif
                        // Mark that the socket has been opened.
                        socket.opened = opened;

                        // Set the timeout period for closing and re-opening the socket next-timed.
                        ok = ExchangerStaticEchoDetail::StaticEchoNextTimeout(owner);
                        break;
                    }

                    if (!ok) {
                        Socket::Closesocket(socket);
                    }

                    return ok;
                }

        }
    }
}
