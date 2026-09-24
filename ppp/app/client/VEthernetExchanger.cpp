#include <ppp/configurations/AppConfiguration.h>
#include <ppp/transmissions/proxys/IForwarding.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetDatagramPort.h>
#include <ppp/app/client/udp/ClientDatagramPortManager.h>
#include <ppp/app/client/ClientFrpRegistry.h>
#include <ppp/app/client/ClientSessionResumeHandshakePolicy.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/app/protocol/VirtualEthernetPathMtu.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/protocol/TransportAuthNegotiation.h>
#include <ppp/app/mux/MuxTransportAdapter.h>
#include <ppp/app/mux/MuxCoordinator.h>
#include <ppp/app/P2PCandidateAdapter.h>
#include <ppp/diagnostics/LinkTelemetry.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/auxiliary/UriAuxiliary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/IDisposable.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/diagnostics/DatapathPerfJson.h>
#include <ppp/p2p/P2PCapabilityGate.h>
#include <ppp/p2p/P2PControlDatagram.h>
#include <ppp/p2p/P2PRelayOfferCoordinator.h>
#include <ppp/p2p/P2PSocketProtector.h>
#include <ppp/p2p/P2PStunClient.h>
#include <ppp/p2p/P2PZeroRTTCache.h>

#if defined(_IPHONE)
#include <ios/ppp/tap/TapIos.h>
#endif

#include <algorithm>
#include <chrono>
#include <limits>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/transmissions/IWebsocketTransmission.h>

/**
 * @file VEthernetExchanger.cpp
 * @brief Client-side virtual Ethernet exchanger implementation.
 * @details Licensed under GPL-3.0.
 */

typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
typedef ppp::app::protocol::VirtualEthernetPacket                   VirtualEthernetPacket;
typedef ppp::collections::Dictionary                                Dictionary;
typedef ppp::auxiliary::StringAuxiliary                             StringAuxiliary;
typedef ppp::net::AddressFamily                                     AddressFamily;
typedef ppp::net::Socket                                            Socket;
typedef ppp::net::IPEndPoint                                        IPEndPoint;
typedef ppp::net::Ipep                                              Ipep;
typedef ppp::threading::Timer                                       Timer;
typedef ppp::threading::Executors                                   Executors;
typedef ppp::transmissions::ITransmission                           ITransmission;
typedef ppp::transmissions::ITcpipTransmission                      ITcpipTransmission;
typedef ppp::transmissions::IWebsocketTransmission                  IWebsocketTransmission;
typedef ppp::transmissions::ISslWebsocketTransmission               ISslWebsocketTransmission;

namespace ppp {
    namespace app {
        namespace client {
            using ppp::telemetry::Level;
            using ppp::app::protocol::SessionResumeAction;
            using ppp::app::protocol::SessionResumeCandidateBinding;
            using ppp::app::protocol::SessionResumeControl;
            using ppp::app::protocol::SessionResumeExporter;
            using ppp::app::protocol::SessionResumeId;
            using ppp::app::protocol::SessionResumeNonce;
            using ppp::app::protocol::SessionResumePendingAttempt;
            using ppp::app::protocol::SessionResumeProof;
            using ppp::app::protocol::SessionResumeSecret;
            using ppp::app::protocol::SessionResumeTranscriptFields;

            template <std::size_t N>
            class SessionResumeArrayCleanser final {
            public:
                explicit SessionResumeArrayCleanser(
                    std::array<std::uint8_t, N>& value) noexcept
                    : value_(value) {
                }

                ~SessionResumeArrayCleanser() noexcept {
                    OPENSSL_cleanse(value_.data(), value_.size());
                }

            private:
                std::array<std::uint8_t, N>& value_;
            };

            template <std::size_t N>
            static bool DecodeSessionResumeHex(
                const ppp::string& text,
                std::array<std::uint8_t, N>& output) noexcept {
                if (text.size() != N * 2) {
                    output.fill(0);
                    return false;
                }

                std::array<std::uint8_t, N> decoded{};
                SessionResumeArrayCleanser decoded_cleanser(decoded);
                for (std::size_t i = 0; i < N; ++i) {
                    const auto nibble = [](char c, std::uint8_t& value) noexcept -> bool {
                        if (c >= '0' && c <= '9') {
                            value = static_cast<std::uint8_t>(c - '0');
                            return true;
                        }
                        if (c >= 'a' && c <= 'f') {
                            value = static_cast<std::uint8_t>(c - 'a' + 10);
                            return true;
                        }
                        return false;
                    };
                    std::uint8_t high = 0;
                    std::uint8_t low = 0;
                    if (!nibble(text[i * 2], high) || !nibble(text[i * 2 + 1], low)) {
                        output.fill(0);
                        return false;
                    }
                    decoded[i] = static_cast<std::uint8_t>((high << 4) | low);
                }
                output = decoded;
                return true;
            }

            template <std::size_t N>
            static ppp::string EncodeSessionResumeHex(
                const std::array<std::uint8_t, N>& value) {
                static constexpr char LowerHex[] = "0123456789abcdef";
                ppp::string encoded;
                encoded.resize(N * 2);
                for (std::size_t i = 0; i < N; ++i) {
                    encoded[i * 2] = LowerHex[value[i] >> 4];
                    encoded[i * 2 + 1] = LowerHex[value[i] & 0x0f];
                }
                return encoded;
            }

            static bool DecodeAuthenticatedSessionResumeControl(
                const SessionResumeControl& control,
                SessionResumePendingAttempt& output) noexcept {
                output.Clear();
                SessionResumeTranscriptFields& fields = output.fields;
                SessionResumeProof& proof = output.proof;
                fields.action = control.action;
                fields.capabilities = control.capabilities;
                fields.generation = control.generation;
                if (control.version != SessionResumeControl::ProtocolVersion ||
                    control.capabilities != SessionResumeControl::CapabilityV1 ||
                    !DecodeSessionResumeHex(control.session_id, fields.session_id) ||
                    !DecodeSessionResumeHex(control.client_nonce, fields.client_nonce) ||
                    (!control.server_nonce.empty() &&
                        !DecodeSessionResumeHex(control.server_nonce, fields.server_nonce)) ||
                    !DecodeSessionResumeHex(control.candidate_binding, fields.candidate_binding) ||
                    !DecodeSessionResumeHex(control.proof, proof)) {
                    output.Clear();
                    return false;
                }
                output.active = true;
                return true;
            }

            static bool DecodeFreshSessionResumeOffer(
                const SessionResumeControl& control,
                SessionResumeId& session_id,
                SessionResumeNonce& server_nonce) noexcept {
                session_id.fill(0);
                server_nonce.fill(0);
                return control.version == SessionResumeControl::ProtocolVersion &&
                    control.action == SessionResumeAction::Offer &&
                    control.capabilities == SessionResumeControl::CapabilityV1 &&
                    control.generation == 0 && control.client_nonce.empty() &&
                    control.candidate_binding.empty() && control.proof.empty() &&
                    control.reason.empty() &&
                    DecodeSessionResumeHex(control.session_id, session_id) &&
                    DecodeSessionResumeHex(control.server_nonce, server_nonce);
            }

            static bool IsBareSessionResumeReject(
                const SessionResumeControl& control) noexcept {
                return control.version == SessionResumeControl::ProtocolVersion &&
                    control.action == SessionResumeAction::Reject &&
                    control.capabilities == 0 && control.session_id.empty() &&
                    control.generation == 0 && control.client_nonce.empty() &&
                    control.server_nonce.empty() && control.candidate_binding.empty() &&
                    control.proof.empty() && !control.reason.empty();
            }

            static bool IsTerminalSessionResumeError(
                ppp::diagnostics::ErrorCode error) noexcept {
                return error == ppp::diagnostics::ErrorCode::ProtocolFrameInvalid ||
                    error == ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid ||
                    error == ppp::diagnostics::ErrorCode::ProtocolDecodeFailed ||
                    error == ppp::diagnostics::ErrorCode::SessionAuthFailed;
            }

            static bool P2PControlCandidateFromEndpoint(
                const boost::asio::ip::udp::endpoint& endpoint,
                ppp::p2p::P2PCandidateEndpoint& output) noexcept {
                ppp::p2p::P2PCandidateV1 candidate;
                if (!ppp::app::P2PCandidateFromEndpoint(endpoint, candidate)) {
                    return false;
                }
                output.address_family = candidate.address_family;
                output.address = candidate.address;
                output.port = candidate.port;
                return true;
            }
            /** @brief Minimum keepalive echo interval in milliseconds. */
            static constexpr int SEND_ECHO_KEEP_ALIVE_PACKET_MIN_TIMEOUT = 1000;
            /** @brief Maximum keepalive echo interval in milliseconds. */
            static constexpr int SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT = 5000;
            /** @brief Hard timeout threshold before keepalive is considered stale. */
#if defined(_IPHONE) || defined(_ANDROID)
            // Mobile OS may freeze the VPN process in background; use a longer
            // stale threshold so a Doze wake does not immediately dispose the
            // main transmission (iOS Packet Tunnel already relied on 120s).
            static constexpr int SEND_ECHO_KEEP_ALIVE_PACKET_MMX_TIMEOUT = 120000;
#else
            static constexpr int SEND_ECHO_KEEP_ALIVE_PACKET_MMX_TIMEOUT = SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT << 2;
#endif
#if defined(_IPHONE)
            // Under ctcp load the io_context may not service the main transmission read
            // loop for tens of seconds while hundreds of per-flow handshakes run.
            // mux=0 opens one server TCP+handshake per TUN flow; cap to stay inside NE memory.
            static constexpr int IOS_CHILD_TRANSMISSION_LIMIT = 96;
            // Soft mark for telemetry only; uploads can legitimately queue above this.
            static constexpr int IOS_CHILD_CONNECT_WAITER_SOFT_LIMIT = 96;
            // Absolute emergency cap for callers that bypass BeginAcceptClient() backpressure.
            static constexpr int IOS_CHILD_CONNECT_WAITER_BURST_LIMIT = 192;
            static constexpr int IOS_CHILD_SLOT_WAIT_INTERVAL_MS = 25;
            static constexpr int IOS_CHILD_SLOT_WAIT_MAX_MS = 15000;
#endif
            const char* TransmissionRoleName(ppp::transmissions::TcpTransmissionRole role) noexcept {
                switch (role) {
                case ppp::transmissions::TcpTransmissionRole::Main:
                    return "main";
                case ppp::transmissions::TcpTransmissionRole::Server:
                    return "server";
                case ppp::transmissions::TcpTransmissionRole::Child:
                default:
                    return "child";
                }
            }

            /** @brief Reserved ACK identifier used for static-echo keepalive signaling. */
            static constexpr int STATIC_ECHO_KEEP_ALIVED_ID              = IPEndPoint::NoneAddress - 1;

            static ppp::p2p::P2PState ConfiguredP2PState(
                const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept {
                if (!configuration) {
                    return ppp::p2p::P2PState::Unavailable;
                }
                return ppp::p2p::P2PCapabilityGate::Evaluate(
                    configuration->p2p.enabled,
                    configuration->p2p.mode.c_str(),
                    false,
                    false,
                    ppp::p2p::ProductionAuthenticatedControlV1Ready).state;
            }

            /** @brief Constructs exchanger and initializes optional static-echo ciphers. */
            VEthernetExchanger::VEthernetExchanger(
                const VEthernetNetworkSwitcherPtr&      switcher,
                const AppConfigurationPtr&              configuration,
                const ContextPtr&                       context,
                const Int128&                           id) noexcept
                : VirtualEthernetLinklayer(configuration, context, id)
                , disposed_(false)
                , switcher_(switcher)
                , network_state_(NetworkState_Connecting)
                , configured_p2p_state_(ConfiguredP2PState(configuration))
                , p2p_state_(ConfiguredP2PState(configuration)) {

                buffer_                   = Executors::GetCachedBuffer(context);
                mux_coordinator_          = std::make_unique<ppp::app::mux::MuxCoordinator>();
                server_url_.port          = 0;
                server_url_.protocol_type = ProtocolType::ProtocolType_PPP;
                static_echo_.Bind(this);
                static_echo_.InitializeCiphers(configuration);
                datagram_manager_ = std::make_unique<udp::ClientDatagramPortManager>(BuildUdpRelayHostPorts());
                frp_registry_ = std::make_unique<ClientFrpRegistry>();
            }

            udp::UdpRelayHostPorts VEthernetExchanger::BuildUdpRelayHostPorts() noexcept {
                // The manager is a member owned by this exchanger, so its callbacks may capture the
                // raw exchanger pointer: they never outlive the exchanger, and this is invoked from the
                // constructor where shared_from_this() is not yet available.
                VEthernetExchanger* self = this;

                udp::UdpRelayHostPorts host;
                host.datagram_output =
                    [self](const boost::asio::ip::udp::endpoint& source, const boost::asio::ip::udp::endpoint& destination,
                           const std::shared_ptr<Byte>& owner, void* packet, int packet_size, bool caching) noexcept {
                        return self->switcher_->DatagramOutput(source, destination, owner, packet, packet_size, caching);
                    };
                host.get_transmission = [self]() noexcept { return self->transmission_; };
                host.create_port =
                    [self](const udp::ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& source) noexcept {
                        return self->NewDatagramPort(transmission, source);
                    };
                host.is_disposed = [self]() noexcept { return self->disposed_.load(std::memory_order_acquire); };
                host.get_tap = [self]() noexcept { return self->switcher_->GetTap(); };
                host.get_configuration = [self]() noexcept { return self->switcher_->GetConfiguration(); };
                host.rewrite_fakeip =
                    [self](const boost::asio::ip::address& address) noexcept { return self->switcher_->RewriteFakeIpAddress(address); };
                // do_send_to mirrors the link-layer SENDTO; the port supplies its own transmission and
                // coroutine yield context. release_port lets a port deregister itself on finalize (P2-d).
                host.do_send_to =
                    [self](const udp::ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& source,
                           const boost::asio::ip::udp::endpoint& destination, ppp::Byte* packet, int packet_length,
                           ppp::coroutines::YieldContext& y) noexcept {
                        return self->DoSendTo(transmission, source, destination, packet, packet_length, y);
                    };
                host.release_port =
                    [self](const boost::asio::ip::udp::endpoint& source,
                           const VEthernetDatagramPort* expected) noexcept {
                        self->ReleaseDatagramPortIf(source, expected);
                    };
                host.emplace_timeout = [](int64_t, ppp::function<void()>) noexcept {};
#if defined(_ANDROID)
                host.is_bypass_ip =
                    [self](const boost::asio::ip::address& address) noexcept { return self->switcher_->IsBypassIpAddress(address); };
                host.get_protector_network =
                    [self]() noexcept { return self->switcher_->GetProtectorNetwork(); };
#endif
                return host;
            }

            /** @brief Finalizes exchanger on destruction. */
            VEthernetExchanger::~VEthernetExchanger() noexcept {
                Finalize();
            }

            /** @brief Sends requested IPv6/IPv4 information extensions to the remote endpoint. */
            bool VEthernetExchanger::SendRequestedIPv6Configuration(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (NULLPTR == transmission || NULLPTR == configuration) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                VirtualEthernetInformationExtensions request;
                std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_;
                boost::system::error_code ec;
                if (switcher && !switcher->RequestedIPv6().empty()) {
                    boost::asio::ip::address address = StringToAddress(switcher->RequestedIPv6(), ec);
                    if (!ec && address.is_v6()) {
                        request.RequestedIPv6Address = address;
                    }
                }

                // Hint fallback: if no explicit RequestedIPv6() preference was configured,
                // but a previous session successfully applied an IPv6 address, re-request that
                // same address so the server can honour address continuity on reconnect.
                if (!request.HasAny() && switcher) {
                    boost::asio::ip::address hint = switcher->LastAssignedIPv6();
                    if (hint.is_v6()) {
                        request.RequestedIPv6Address = hint;
                    }
                }

                // Only send the newer INFO extension request when the local profile explicitly
                // opts into server-side IPv4 allocation. Older servers treat any client-originated
                // extended INFO packet as invalid, so the default mobile/static-TUN path stays
                // on the legacy handshake.
                if (configuration->server.ipv4_pool.configured) {
                    ppp::app::protocol::ClientIPv4Request ipv4_req;
                    ipv4_req.enabled = true;

                    bool is_static = switcher && switcher->StaticMode(NULLPTR);
                    if (is_static && switcher) {
                        std::shared_ptr<ppp::tap::ITap> tap = switcher->GetTap();
                        if (NULLPTR != tap && tap->IPAddress != IPEndPoint::AnyAddress && tap->IPAddress != IPEndPoint::NoneAddress) {
                            ipv4_req.mode = "manual";
                            ipv4_req.address = Ipep::ToAddress(tap->IPAddress).to_string();
                            ipv4_req.gateway = Ipep::ToAddress(tap->GatewayServer).to_string();
                            ipv4_req.mask = Ipep::ToAddress(tap->SubmaskAddress).to_string();
                        }
                        else {
                            ipv4_req.mode = "auto";
                        }
                    }
                    else {
                        ipv4_req.mode = "auto";
                    }

                    request.ClientIPv4Req = ipv4_req;
                }

                const auto protector = ppp::p2p::CreateSocketProtector();
                const auto p2p_capability = ppp::p2p::P2PCapabilityGate::Evaluate(
                    configuration->p2p.enabled,
                    configuration->p2p.mode.c_str(),
                    transmission->HasAuthenticatedSessionExporter(),
                    protector && protector->IsReady(),
                    ppp::p2p::ProductionAuthenticatedControlV1Ready);
                {
                    std::lock_guard<std::mutex> scope(runtime_state_mutex_);
                    if (!disposed_.load(std::memory_order_acquire)) {
                        p2p_state_.store(p2p_capability.state, std::memory_order_relaxed);
                    }
                }
                if (p2p_capability.allowed) {
                    const uint64_t candidate_generation =
                        p2p_offer_generation_.load(std::memory_order_acquire);
                    auto context = transmission->GetContext();
#if defined(_IPHONE)
                    auto ios_tap = std::dynamic_pointer_cast<ppp::tap::TapIos>(
                        switcher ? switcher->GetTap() : nullptr);
                    auto candidate_factory = ios_tap
                        ? ios_tap->GetP2PDatagramTransportFactory()
                        : nullptr;
#else
                    auto candidate_factory =
                        ppp::p2p::CreateNativeSocketP2PDatagramTransportFactory(protector);
#endif
                    auto candidate_transport = context && candidate_factory
                        ? candidate_factory->Create(*context)
                        : nullptr;
                    std::weak_ptr<ppp::app::protocol::VirtualEthernetLinklayer> weak_self =
                        shared_from_this();
                    std::weak_ptr<ppp::transmissions::ITransmission> weak_transmission =
                        transmission;
                    const uint64_t transport_registration =
                        ++p2p_transport_registration_sequence_;
                    const bool started = candidate_transport &&
                        candidate_transport->Start(
                            [weak_self, weak_transmission, candidate_generation,
                             transport_registration](
                                ppp::p2p::P2PDatagramReceiveStatus status,
                                const boost::asio::ip::udp::endpoint& sender,
                                const std::uint8_t* packet, int packet_size) noexcept {
                                auto base = weak_self.lock();
                                auto self = std::dynamic_pointer_cast<VEthernetExchanger>(base);
                                auto transmission = weak_transmission.lock();
                                if (self && transmission) {
                                    self->HandleP2PDatagram(
                                        transmission, candidate_generation,
                                        transport_registration,
                                        status, sender, packet, packet_size);
                                }
                            });
                    const auto bound = started
                        ? candidate_transport->LocalEndpoint()
                        : boost::asio::ip::udp::endpoint();
                    boost::asio::ip::address candidate_address;
#if defined(_IPHONE)
                    candidate_address = bound.address();
#elif defined(_ANDROID)
                    const auto remote_endpoint = transmission->GetRemoteEndPoint();
                    if (remote_endpoint.address().is_v4()) {
                        const uint32_t destination =
                            IPEndPoint::ToEndPoint(remote_endpoint).GetAddress();
                        candidate_address = Ipep::ToAddress(
                            Socket::GetBestInterfaceIP(destination));
                    }
#else
                    auto underlying = switcher
                        ? switcher->GetUnderlyingNetworkInterface()
                        : nullptr;
                    if (underlying) {
                        candidate_address = underlying->IPAddress;
                    }
#endif
                    const boost::asio::ip::udp::endpoint host_candidate(
                        candidate_address, bound.port());
                    uint32_t local_virtual_ip = 0;
                    if (switcher) {
                        std::shared_ptr<ppp::tap::ITap> tap = switcher->GetTap();
                        if (NULLPTR != tap) {
                            local_virtual_ip = tap->IPAddress;
                        }
                    }
                    ppp::app::protocol::P2PEndpointCandidate candidate;
                    const std::string candidate_endpoint =
                        ppp::app::P2PEndpointToString(host_candidate);
                    candidate.endpoint.assign(
                        candidate_endpoint.data(), candidate_endpoint.size());
                    candidate.source = "host";

                    // Host-only first; STUN is async so register never blocks.
                    ppp::vector<ppp::app::protocol::P2PEndpointCandidate> gathered;
                    if (!candidate.endpoint.empty()) {
                        gathered.emplace_back(candidate);
                    }

                    std::shared_ptr<ppp::p2p::IP2PDatagramTransport> previous_transport;
                    bool registered = false;
                    if (!gathered.empty() && local_virtual_ip != 0) {
                        request.P2P.enabled = true;
                        request.P2P.mode = configuration->p2p.mode;
                        request.P2P.action = "register";
                        request.P2P.virtual_ip = local_virtual_ip;
                        request.P2P.candidates = gathered;
                        {
                            std::lock_guard<std::mutex> scope(p2p_offer_mutex_);
                            if (!disposed_.load(std::memory_order_acquire) &&
                                candidate_generation ==
                                    p2p_offer_generation_.load(std::memory_order_acquire)) {
                                previous_transport = std::move(p2p_candidate_transport_);
                                p2p_registered_candidates_ = request.P2P.candidates;
                                p2p_registered_transmission_ = transmission;
                                p2p_candidate_transport_ = candidate_transport;
                                p2p_local_candidate_ = host_candidate;
                                p2p_peer_candidate_ = {};
                                p2p_peer_virtual_ip_ = 0;
                                p2p_last_heartbeat_tx_ms_ = 0;
                                p2p_heartbeat_misses_ = 0;
                                p2p_suspect_since_ms_ = 0;
                                p2p_migrate_started_ms_ = 0;
                                p2p_direct_data_path_.Reset(candidate_generation);
                                p2p_transport_registration_id_ = transport_registration;
                                p2p_registered_virtual_ip_ = request.P2P.virtual_ip;
                                const auto cached = p2p_zero_rtt_cache_.Lookup(local_virtual_ip);
                                if (cached.valid && !cached.peer_endpoint.address().is_unspecified()) {
                                    p2p_peer_candidate_ = cached.peer_endpoint;
                                    ppp::telemetry::Count("p2p.zero_rtt.hit", 1);
                                }
                                registered = true;
                            }
                        }
                    }
                    if (previous_transport) {
                        previous_transport->Close();
                    }
                    if (!registered) {
                        request.P2P.Clear();
                        if (candidate_transport) {
                            candidate_transport->Close();
                        }
                        std::lock_guard<std::mutex> scope(runtime_state_mutex_);
                        if (!disposed_.load(std::memory_order_acquire) &&
                            candidate_generation ==
                                p2p_offer_generation_.load(std::memory_order_acquire)) {
                            p2p_state_.store(ppp::p2p::P2PState::Unavailable, std::memory_order_relaxed);
                        }
                        ppp::telemetry::Count("p2p.candidate_gather.fail", 1);
                    }
                    else if (!configuration->p2p.stun_servers.empty() && bound.port() != 0) {
                        StartP2PStunGatherAsync(
                            transmission, candidate_generation, transport_registration,
                            local_virtual_ip, configuration->p2p.stun_servers);
                    }
                }
                else if (configuration->p2p.enabled) {
                    ppp::telemetry::Log(Level::kInfo, "p2p", "direct registration suppressed reason=%s", p2p_capability.reason);
                }

                if (!configuration->client.peer_route_announce.empty()) {
                    request.PeerRouteAnnounce.enabled = true;
                    request.PeerRouteAnnounce.action = "register";
                    for (const auto& item : configuration->client.peer_route_announce) {
                        ppp::app::protocol::PeerPrefixRouteEntry entry;
                        entry.network = item.network;
                        entry.prefix = item.prefix;
                        request.PeerRouteAnnounce.prefixes.emplace_back(std::move(entry));
                    }
                }

                if (!request.HasAny()) {
                    return true;
                }

                InformationEnvelope envelope;
                envelope.Base.Clear();
                envelope.Extensions = request;
                envelope.ExtendedJson = request.ToJson();
                return DoInformation(transmission, envelope, y);
            }

            bool VEthernetExchanger::AuthenticatePlainTransport(
                const ITransmissionPtr& transmission,
                YieldContext& y) noexcept {
                using ppp::app::protocol::TransportAuthCarrier;
                using ppp::app::protocol::TransportAuthControl;
                using ppp::app::protocol::TransportAuthInitiator;
                using ppp::app::protocol::TransportAuthNegotiationContext;

                const auto fail = [&transmission](
                    ppp::diagnostics::ErrorCode error) noexcept -> bool {
                    ppp::diagnostics::SetLastErrorCode(error);
                    if (transmission) {
                        transmission->Dispose();
                    }
                    return false;
                };
                if (!transmission) {
                    return fail(ppp::diagnostics::ErrorCode::SessionAuthFailed);
                }

                TransportAuthNegotiationContext context;
                const auto kind = transmission->GetAuthenticatedCarrierKind();
                if (kind == ppp::transmissions::AuthenticatedCarrierKind::Tcp) {
                    context.carrier = TransportAuthCarrier::Tcp;
                }
                elif(kind == ppp::transmissions::AuthenticatedCarrierKind::WebSocket) {
                    context.carrier = TransportAuthCarrier::WebSocket;
                }
                else {
                    return fail(ppp::diagnostics::ErrorCode::SessionAuthFailed);
                }
                ppp::p2p::Int128ToBytes(GetId(), context.session_id.data());

                std::array<std::uint8_t, 16> random_token{};
                SessionResumeArrayCleanser random_token_cleanser(random_token);
                if (RAND_bytes(random_token.data(), static_cast<int>(random_token.size())) != 1) {
                    return fail(ppp::diagnostics::ErrorCode::SessionAuthFailed);
                }
                const ppp::string encoded_token = EncodeSessionResumeHex(random_token);
                context.token.assign(encoded_token.data(), encoded_token.size());

                AppConfigurationPtr configuration = GetConfiguration();
                TransportAuthInitiator initiator(
                    configuration ? configuration->transport_auth_keyring : nullptr,
                    context);
                const auto send_control = [this, &transmission, &y](
                    const TransportAuthControl& control) noexcept -> bool {
                    InformationEnvelope envelope;
                    envelope.Base.Clear();
                    envelope.Extensions.TransportAuth = control;
                    envelope.ExtendedJson = envelope.Extensions.ToJson();
                    return DoInformation(transmission, envelope, y);
                };
                const auto read_control = [&transmission, &y](
                    TransportAuthControl& control) noexcept -> bool {
                    InformationEnvelope envelope;
                    if (!ReadInformation(transmission, envelope, y)) {
                        return false;
                    }
                    control = envelope.Extensions.TransportAuth;
                    envelope.Extensions.TransportAuth.Clear();
                    if (!control.HasAny() || envelope.Extensions.HasAny()) {
                        ppp::diagnostics::SetLastErrorCode(
                            ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                        return false;
                    }
                    return true;
                };

                TransportAuthControl advertisement;
                if (!initiator.CreateAdvertisement(advertisement) ||
                    !send_control(advertisement)) {
                    return fail(ppp::diagnostics::ErrorCode::SessionAuthFailed);
                }

                TransportAuthControl selection;
                TransportAuthControl proof;
                if (!read_control(selection)) {
                    const auto error = ppp::diagnostics::GetLastErrorCode() ==
                        ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid
                        ? ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid
                        : ppp::diagnostics::ErrorCode::SessionAuthFailed;
                    return fail(error);
                }
                if (!initiator.ConsumeSelection(selection, proof) ||
                    !send_control(proof)) {
                    return fail(ppp::diagnostics::ErrorCode::SessionAuthFailed);
                }

                TransportAuthControl acknowledgement;
                if (!read_control(acknowledgement)) {
                    const auto error = ppp::diagnostics::GetLastErrorCode() ==
                        ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid
                        ? ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid
                        : ppp::diagnostics::ErrorCode::SessionAuthFailed;
                    return fail(error);
                }
                ppp::cryptography::noise::NoisePskHandshakeResult result;
                if (!initiator.ConsumeAcknowledgement(acknowledgement) ||
                    !initiator.TakeNoiseResult(result) ||
                    !transmission->InstallNoiseAuthenticatedCarrierBinding(
                        std::move(result))) {
                    return fail(ppp::diagnostics::ErrorCode::SessionAuthFailed);
                }
                return true;
            }

            void VEthernetExchanger::ClearSessionResumeState() noexcept {
                session_resume_pending_.Clear();
                session_resume_root_.Clear();
                session_resume_id_.fill(0);
                session_resume_generation_ = 0;
                session_resume_armed_ = false;
            }

            bool VEthernetExchanger::SendSessionResumeControl(
                const ITransmissionPtr& transmission,
                const SessionResumeTranscriptFields& fields,
                const SessionResumeProof& proof,
                YieldContext& y) noexcept {
                SessionResumeControl control;
                control.action = fields.action;
                control.capabilities = fields.capabilities;
                control.session_id = EncodeSessionResumeHex(fields.session_id);
                control.generation = fields.generation;
                control.client_nonce = EncodeSessionResumeHex(fields.client_nonce);
                if (fields.action != SessionResumeAction::ResumeRequest &&
                    fields.action != SessionResumeAction::GenerationSync) {
                    control.server_nonce = EncodeSessionResumeHex(fields.server_nonce);
                }
                if (fields.action != SessionResumeAction::Accepted) {
                    control.candidate_binding = EncodeSessionResumeHex(fields.candidate_binding);
                }
                control.proof = EncodeSessionResumeHex(proof);
                if (!control.Valid()) {
                    return ppp::diagnostics::SetLastError(
                        ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                }

                InformationEnvelope envelope;
                envelope.Base.Clear();
                envelope.Extensions.SessionResume = control;
                envelope.ExtendedJson = envelope.Extensions.ToJson();
                return DoInformation(transmission, envelope, y);
            }

            bool VEthernetExchanger::AcceptFreshSessionResumeOffer(
                const ITransmissionPtr& transmission,
                const InformationEnvelope& offer,
                YieldContext& y) noexcept {
                SessionResumeId offered_id{};
                SessionResumeArrayCleanser offered_id_cleanser(offered_id);
                SessionResumeNonce server_nonce{};
                SessionResumeArrayCleanser server_nonce_cleanser(server_nonce);
                SessionResumeId expected_id{};
                ppp::p2p::Int128ToBytes(GetId(), expected_id.data());
                if (!transmission || !IsClientSessionRecoveryCarrierEligible(
                        transmission->GetAuthenticatedCarrierKind(),
                        transmission->GetAuthenticatedCarrierMethod(),
                        transmission->IsAuthenticatedCarrierBindingActive(),
                        transmission->HasAuthenticatedSessionExporter()) ||
                    !DecodeFreshSessionResumeOffer(
                        offer.Extensions.SessionResume, offered_id, server_nonce) ||
                    offered_id != expected_id) {
                    ClearSessionResumeState();
                    return ppp::diagnostics::SetLastError(
                        ppp::diagnostics::ErrorCode::SessionAuthFailed);
                }

                SessionResumeExporter exporter =
                    [transmission](const char* label, const std::uint8_t* context,
                        std::size_t context_length, std::uint8_t* output,
                        std::size_t output_length) noexcept -> bool {
                        return transmission->ExportAuthenticatedSessionKey(
                            label, context, context_length, output, output_length);
                    };
                SessionResumeSecret candidate_root;
                if (!ppp::app::protocol::DeriveSessionResumeRetainedRoot(
                        exporter, expected_id, candidate_root)) {
                    ClearSessionResumeState();
                    return ppp::diagnostics::SetLastError(
                        ppp::diagnostics::ErrorCode::SessionAuthFailed);
                }

                session_resume_pending_.Clear();
                session_resume_pending_.active = true;
                session_resume_pending_.fields.action = SessionResumeAction::Accepted;
                session_resume_pending_.fields.capabilities =
                    SessionResumeControl::CapabilityV1;
                session_resume_pending_.fields.session_id = expected_id;
                session_resume_pending_.fields.server_nonce = server_nonce;
                if (!ppp::app::protocol::GenerateSessionResumeNonce(
                        session_resume_pending_.fields.client_nonce) ||
                    !ppp::app::protocol::ComputeSessionResumeProof(
                        candidate_root, session_resume_pending_.fields,
                        session_resume_pending_.proof)) {
                    ClearSessionResumeState();
                    return ppp::diagnostics::SetLastError(
                        ppp::diagnostics::ErrorCode::SessionAuthFailed);
                }

                const bool sent = SendSessionResumeControl(
                    transmission, session_resume_pending_.fields,
                    session_resume_pending_.proof, y);
                session_resume_pending_.Clear();
                if (!sent) {
                    ClearSessionResumeState();
                    return false;
                }

                session_resume_root_ = std::move(candidate_root);
                session_resume_id_ = expected_id;
                session_resume_generation_ = 1;
                session_resume_armed_ = true;
                return true;
            }

            VEthernetExchanger::SessionResumeNegotiationResult
            VEthernetExchanger::NegotiateSessionResume(
                const ITransmissionPtr& transmission,
                InformationEnvelope& initial_information,
                bool& has_initial_information,
                YieldContext& y) noexcept {
                has_initial_information = false;
                AppConfigurationPtr configuration = GetConfiguration();
                const bool recovery_carrier_eligible = transmission &&
                    IsClientSessionRecoveryCarrierEligible(
                        transmission->GetAuthenticatedCarrierKind(),
                        transmission->GetAuthenticatedCarrierMethod(),
                        transmission->IsAuthenticatedCarrierBindingActive(),
                        transmission->HasAuthenticatedSessionExporter());
                const ClientSessionResumePreamble preamble =
                    SelectClientSessionResumePreamble(configuration &&
                        configuration->client.session_resume.enabled,
                        switcher_ && switcher_->IsVNet(),
                        recovery_carrier_eligible,
                        session_resume_armed_, session_resume_root_.IsSet());
                if (preamble == ClientSessionResumePreamble::Legacy) {
                    ClearSessionResumeState();
                    return SessionResumeNegotiationResult::Fresh;
                }

                SessionResumeId expected_id{};
                ppp::p2p::Int128ToBytes(GetId(), expected_id.data());
                if (!session_resume_armed_ || !session_resume_root_.IsSet()) {
                    ClearSessionResumeState();
                    if (!ReadInformation(transmission, initial_information, y)) {
                        ClearSessionResumeState();
                        return SessionResumeNegotiationResult::Failed;
                    }
                    has_initial_information = true;

                    SessionResumeId offered_id{};
                    SessionResumeArrayCleanser offered_id_cleanser(offered_id);
                    SessionResumeNonce server_nonce{};
                    SessionResumeArrayCleanser server_nonce_cleanser(server_nonce);
                    if (!initial_information.Extensions.SessionResume.HasAny() ||
                        !DecodeFreshSessionResumeOffer(
                            initial_information.Extensions.SessionResume,
                            offered_id, server_nonce) || offered_id != expected_id) {
                        ClearSessionResumeState();
                        return SessionResumeNegotiationResult::Fresh;
                    }
                    if (!AcceptFreshSessionResumeOffer(
                            transmission, initial_information, y)) {
                        return SessionResumeNegotiationResult::Failed;
                    }
                    return SessionResumeNegotiationResult::Fresh;
                }

                if (session_resume_id_ != expected_id) {
                    ClearSessionResumeState();
                    return SessionResumeNegotiationResult::Fresh;
                }

                SessionResumeExporter exporter =
                    [transmission](const char* label, const std::uint8_t* context,
                        std::size_t context_length, std::uint8_t* output,
                        std::size_t output_length) noexcept -> bool {
                        return transmission->ExportAuthenticatedSessionKey(
                            label, context, context_length, output, output_length);
                    };
                SessionResumeCandidateBinding candidate_binding{};
                SessionResumeArrayCleanser candidate_binding_cleanser(candidate_binding);
                if (!ppp::app::protocol::DeriveSessionResumeCandidateBinding(
                        exporter, expected_id, candidate_binding)) {
                    ClearSessionResumeState();
                    return ppp::diagnostics::SetLastError(
                        ppp::diagnostics::ErrorCode::SessionAuthFailed,
                        SessionResumeNegotiationResult::Failed);
                }

                const auto terminal_failure = [this](
                    ppp::diagnostics::ErrorCode error) noexcept {
                    ClearSessionResumeState();
                    ppp::diagnostics::SetLastErrorCode(error);
                    return SessionResumeNegotiationResult::Failed;
                };
                unsigned int generation_sync_count = 0;
                for (;;) {
                    session_resume_pending_.Clear();
                    session_resume_pending_.active = true;
                    session_resume_pending_.fields.action =
                        SessionResumeAction::ResumeRequest;
                    session_resume_pending_.fields.capabilities =
                        SessionResumeControl::CapabilityV1;
                    session_resume_pending_.fields.session_id = expected_id;
                    session_resume_pending_.fields.generation =
                        session_resume_generation_;
                    session_resume_pending_.fields.candidate_binding =
                        candidate_binding;
                    if (!ppp::app::protocol::GenerateSessionResumeNonce(
                            session_resume_pending_.fields.client_nonce) ||
                        !ppp::app::protocol::ComputeSessionResumeProof(
                            session_resume_root_, session_resume_pending_.fields,
                            session_resume_pending_.proof)) {
                        return terminal_failure(
                            ppp::diagnostics::ErrorCode::SessionAuthFailed);
                    }
                    if (!SendSessionResumeControl(
                            transmission, session_resume_pending_.fields,
                            session_resume_pending_.proof, y)) {
                        session_resume_pending_.Clear();
                        return SessionResumeNegotiationResult::Failed;
                    }

                    InformationEnvelope response;
                    if (!ReadInformation(transmission, response, y)) {
                        session_resume_pending_.Clear();
                        if (IsTerminalSessionResumeError(
                                ppp::diagnostics::GetLastErrorCode())) {
                            ClearSessionResumeState();
                        }
                        return SessionResumeNegotiationResult::Failed;
                    }
                    const SessionResumeControl& control =
                        response.Extensions.SessionResume;
                    if (!control.HasAny()) {
                        session_resume_pending_.Clear();
                        ClearSessionResumeState();
                        initial_information = response;
                        has_initial_information = true;
                        return SessionResumeNegotiationResult::Fresh;
                    }

                    if (control.action == SessionResumeAction::Offer ||
                        IsBareSessionResumeReject(control)) {
                        const bool rejected = IsBareSessionResumeReject(control);
                        session_resume_pending_.Clear();
                        ClearSessionResumeState();
                        if (rejected) {
                            if (!ReadInformation(
                                    transmission, response, y)) {
                                return SessionResumeNegotiationResult::Failed;
                            }
                            if (!response.Extensions.SessionResume.HasAny()) {
                                initial_information = response;
                                has_initial_information = true;
                                return SessionResumeNegotiationResult::Fresh;
                            }
                        }

                        SessionResumeId offered_id{};
                        SessionResumeArrayCleanser offered_id_cleanser(offered_id);
                        SessionResumeNonce server_nonce{};
                        SessionResumeArrayCleanser server_nonce_cleanser(server_nonce);
                        if (!DecodeFreshSessionResumeOffer(
                                response.Extensions.SessionResume,
                                offered_id, server_nonce) ||
                            offered_id != expected_id) {
                            return terminal_failure(
                                ppp::diagnostics::ErrorCode::SessionAuthFailed);
                        }
                        initial_information = response;
                        has_initial_information = true;
                        if (!AcceptFreshSessionResumeOffer(
                                transmission, response, y)) {
                            return SessionResumeNegotiationResult::Failed;
                        }
                        return SessionResumeNegotiationResult::Fresh;
                    }

                    SessionResumePendingAttempt authenticated_response;
                    if (!DecodeAuthenticatedSessionResumeControl(
                            control, authenticated_response)) {
                        return terminal_failure(
                            ppp::diagnostics::ErrorCode::SessionAuthFailed);
                    }
                    const SessionResumeTranscriptFields& request =
                        session_resume_pending_.fields;
                    const SessionResumeTranscriptFields& received =
                        authenticated_response.fields;
                    const bool same_request =
                        received.session_id == request.session_id &&
                        received.client_nonce == request.client_nonce &&
                        received.candidate_binding == request.candidate_binding;

                    if (received.action == SessionResumeAction::GenerationSync) {
                        if (!same_request || generation_sync_count != 0 ||
                            !ppp::app::protocol::VerifySessionResumeProof(
                                session_resume_root_, received,
                                authenticated_response.proof)) {
                            return terminal_failure(
                                ppp::diagnostics::ErrorCode::SessionAuthFailed);
                        }
                        ++generation_sync_count;
                        session_resume_generation_ = received.generation;
                        session_resume_pending_.Clear();
                        continue;
                    }

                    if (received.action == SessionResumeAction::Reject) {
                        const bool authenticated = same_request &&
                            received.generation == request.generation &&
                            ppp::app::protocol::VerifySessionResumeProof(
                                session_resume_root_, received,
                                authenticated_response.proof);
                        (void)authenticated;
                        return terminal_failure(
                            ppp::diagnostics::ErrorCode::SessionAuthFailed);
                    }

                    if (received.action != SessionResumeAction::ResumeAccept ||
                        !same_request || received.generation != request.generation ||
                        !ppp::app::protocol::VerifySessionResumeProof(
                            session_resume_root_, received,
                            authenticated_response.proof) ||
                        request.generation ==
                            std::numeric_limits<std::uint64_t>::max()) {
                        return terminal_failure(
                            ppp::diagnostics::ErrorCode::SessionAuthFailed);
                    }

                    const std::uint64_t request_generation = request.generation;
                    session_resume_pending_.Clear();
                    session_resume_pending_.active = true;
                    session_resume_pending_.fields = received;
                    session_resume_pending_.fields.action =
                        SessionResumeAction::ResumeConfirm;
                    if (!ppp::app::protocol::ComputeSessionResumeProof(
                            session_resume_root_, session_resume_pending_.fields,
                            session_resume_pending_.proof)) {
                        return terminal_failure(
                            ppp::diagnostics::ErrorCode::SessionAuthFailed);
                    }
                    if (!SendSessionResumeControl(
                            transmission, session_resume_pending_.fields,
                            session_resume_pending_.proof, y)) {
                        session_resume_pending_.Clear();
                        return SessionResumeNegotiationResult::Failed;
                    }

                    InformationEnvelope committed_envelope;
                    if (!ReadInformation(
                            transmission, committed_envelope, y)) {
                        session_resume_pending_.Clear();
                        if (IsTerminalSessionResumeError(
                                ppp::diagnostics::GetLastErrorCode())) {
                            ClearSessionResumeState();
                        }
                        return SessionResumeNegotiationResult::Failed;
                    }
                    SessionResumePendingAttempt committed;
                    if (!DecodeAuthenticatedSessionResumeControl(
                            committed_envelope.Extensions.SessionResume,
                            committed) ||
                        committed.fields.action !=
                            SessionResumeAction::ResumeCommitted ||
                        committed.fields.session_id !=
                            session_resume_pending_.fields.session_id ||
                        committed.fields.client_nonce !=
                            session_resume_pending_.fields.client_nonce ||
                        committed.fields.server_nonce !=
                            session_resume_pending_.fields.server_nonce ||
                        committed.fields.candidate_binding !=
                            session_resume_pending_.fields.candidate_binding ||
                        committed.fields.generation != request_generation + 1 ||
                        !ppp::app::protocol::VerifySessionResumeProof(
                            session_resume_root_, committed.fields,
                            committed.proof)) {
                        return terminal_failure(
                            ppp::diagnostics::ErrorCode::SessionAuthFailed);
                    }

                    session_resume_generation_ = committed.fields.generation;
                    session_resume_armed_ = true;
                    session_resume_pending_.Clear();
                    return SessionResumeNegotiationResult::Resumed;
                }
            }

            bool VEthernetExchanger::ApplyPreDataInformation(
                const ITransmissionPtr& transmission,
                const InformationEnvelope& information,
                YieldContext& y) noexcept {
                InformationEnvelope ordinary = information;
                ordinary.Extensions.SessionResume.Clear();
                ordinary.ExtendedJson = ordinary.Extensions.HasAny()
                    ? ordinary.Extensions.ToJson() : ppp::string();
                return OnInformation(transmission, ordinary, y);
            }

            /** @brief Disposes and releases all owned runtime objects. */
            void VEthernetExchanger::Finalize() noexcept {
                /** @brief One-shot guard: only the first caller proceeds with cleanup. */
                if (disposed_.exchange(true, std::memory_order_acq_rel)) {
                    return;
                }
                ClearSessionResumeState();
                {
                    std::lock_guard<std::mutex> scope(runtime_state_mutex_);
                    p2p_state_.store(ppp::p2p::P2PState::Disabled, std::memory_order_relaxed);
                }
                const uint64_t p2p_generation = ++p2p_offer_generation_;
                p2p_offer_session_.AdvanceGeneration(p2p_generation);
                ResetP2PCandidateTransport();

                ITransmissionPtr transmission;
                DeadlineTimerTable deadline_timers;
                std::shared_ptr<vmux::vmux_net> mux;

                /** @brief Atomically swaps internal tables/resources before releasing outside lock. */
                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);

                    deadline_timers = std::move(deadline_timers_);
                    deadline_timers_.clear();

                    mux_vlan_ = 0;
                    mux = mux_coordinator_->Take();
                    transmission = std::move(transmission_);
                    break;
                }

                static_echo_.StaticEchoClean();
                if (NULLPTR != transmission) {
                    transmission->Dispose();
                }

                for (auto&& [_, deadline_timer] : deadline_timers) {
                    ppp::net::Socket::Cancel(*deadline_timer);
                }

                frp_registry_->ReleaseAll();
                datagram_manager_->Release();

                ppp::telemetry::Log(Level::kInfo, "client_exchanger", "exchanger finalized");

                if (NULLPTR != mux) {
                    mux->close_exec();
                }
            }

            /** @brief Posts exchanger finalization to execution context. */
            void VEthernetExchanger::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                StrandPtr strand = owner_strand_;
                auto finalize = [self, this, context, strand]() noexcept {
                    Finalize();
                };
                if (strand) {
                    boost::asio::dispatch(*strand, std::move(finalize));
                }
                else {
                    boost::asio::dispatch(*context, std::move(finalize));
                }
            }

            template <typename TTransmission>
            typename std::enable_if<std::is_base_of<ITransmission, TTransmission>::value, std::shared_ptr<TTransmission>>::type
            VEthernetExchanger::NewWebsocketTransmission(
                const ContextPtr& context,
                const StrandPtr& strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                const ppp::string& host,
                const ppp::string& path) noexcept {

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (NULLPTR == configuration) {
                    return NULLPTR;
                }

                auto transmission = make_shared_object<TTransmission>(context, strand, socket, configuration);
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                if (host.size() > 0 && path.size() > 0) {
                    transmission->Host = host;
                    transmission->Path = path;
                }

                return transmission;
            }

            template std::shared_ptr<IWebsocketTransmission> VEthernetExchanger::NewWebsocketTransmission<IWebsocketTransmission>(
                const ContextPtr& context,
                const StrandPtr& strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                const ppp::string& host,
                const ppp::string& path) noexcept;

            template std::shared_ptr<ISslWebsocketTransmission> VEthernetExchanger::NewWebsocketTransmission<ISslWebsocketTransmission>(
                const ContextPtr& context,
                const StrandPtr& strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                const ppp::string& host,
                const ppp::string& path) noexcept;

            /** @brief Creates a transport object based on selected protocol type. */
            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::NewTransmission(
                const ContextPtr&                                                   context,
                const StrandPtr&                                                    strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&                socket,
                ProtocolType                                                        protocol_type,
                const ppp::string&                                                  host,
                const ppp::string&                                                  path,
                ppp::transmissions::TcpTransmissionRole                             role) noexcept {

                ITransmissionPtr transmission;
                if (protocol_type == ProtocolType::ProtocolType_Http ||
                    protocol_type == ProtocolType::ProtocolType_WebSocket) {
                    transmission = NewWebsocketTransmission<IWebsocketTransmission>(context, strand, socket, host, path);
                }
                elif(protocol_type == ProtocolType::ProtocolType_HttpSSL ||
                    protocol_type == ProtocolType::ProtocolType_WebSocketSSL) {
                    transmission = NewWebsocketTransmission<ISslWebsocketTransmission>(context, strand, socket, host, path);
                }
                else {
                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                    transmission = make_shared_object<ITcpipTransmission>(context, strand, socket, configuration, role);
                }

                if (NULLPTR != transmission) {
                    transmission->QoS = switcher_->GetQoS();
                    transmission->Statistics = switcher_->GetStatistics();
                    ppp::telemetry::Log(Level::kDebug, "client_exchanger", "transmission created: protocol=%d role=%s",
                        (int)protocol_type,
                        TransmissionRoleName(role));
                }

                return transmission;
            }

            /** @brief Creates and configures an asynchronous TCP socket. */
            std::shared_ptr<boost::asio::ip::tcp::socket> VEthernetExchanger::NewAsynchronousSocket(const ContextPtr& context, const StrandPtr& strand, const boost::asio::ip::tcp& protocol, ppp::coroutines::YieldContext& y) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed, std::shared_ptr<boost::asio::ip::tcp::socket>(NULLPTR));
                }

                if (!context) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing, std::shared_ptr<boost::asio::ip::tcp::socket>(NULLPTR));
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = strand ?
                    make_shared_object<boost::asio::ip::tcp::socket>(*strand) : make_shared_object<boost::asio::ip::tcp::socket>(*context);
                if (!socket) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed, std::shared_ptr<boost::asio::ip::tcp::socket>(NULLPTR));
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (!configuration) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::AppConfigurationMissing, std::shared_ptr<boost::asio::ip::tcp::socket>(NULLPTR));
                }

                if (!ppp::coroutines::asio::async_open(y, *socket, protocol)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketOpenFailed, std::shared_ptr<boost::asio::ip::tcp::socket>(NULLPTR));
                }

                Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);
                Socket::AdjustSocketOptional(*socket, protocol == boost::asio::ip::tcp::v4(), configuration->tcp.fast_open, configuration->tcp.turbo);
                return socket;
            }

            /** @brief Resolves, validates, and caches the remote server endpoint. */
            bool VEthernetExchanger::GetRemoteEndPoint(YieldContext* y, ppp::string& hostname, ppp::string& address, ppp::string& path, int& port, ProtocolType& protocol_type, ppp::string& server, boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                if (server_url_.port > IPEndPoint::MinPort && server_url_.port <= IPEndPoint::MaxPort) {
                    remoteEP      = server_url_.remoteEP;
                    hostname      = server_url_.hostname;
                    address       = server_url_.address;
                    path          = server_url_.path;
                    server        = server_url_.server;
                    port          = server_url_.port;
                    protocol_type = server_url_.protocol_type;
                    return true;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (!configuration) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                }

                ppp::string& client_server_string = configuration->client.server;
                if (client_server_string.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                std::shared_ptr<ppp::transmissions::proxys::IForwarding> forwarding = switcher_->GetForwarding(); ;
                if (NULLPTR != forwarding) {
                    ppp::string abs_url;
                    server = UriAuxiliary::Parse(client_server_string, hostname, address, path, port, protocol_type, &abs_url, *y, false);
                }
                else {
                    server = UriAuxiliary::Parse(client_server_string, hostname, address, path, port, protocol_type, *y);
                }

                if (server.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                if (hostname.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                ppp::telemetry::Count("client_exchanger.dns.resolve", 1);
                ppp::telemetry::Log(Level::kDebug, "client_exchanger", "dns resolved: %s", hostname.c_str());

                if (NULLPTR != forwarding) {
                    ppp::string session_guid = StringAuxiliary::Int128ToGuidString(GetId());
                    ppp::telemetry::SpanScope span("client.proxy.setup", session_guid.c_str());
                    struct ScopedProxySetupHistogram final {
                        std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

                        ~ScopedProxySetupHistogram() noexcept {
                            int64_t elapsed = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
                            ppp::telemetry::Histogram("client.proxy.setup.us", elapsed);
                        }
                    } proxy_setup_histogram;

                    boost::asio::ip::tcp::endpoint forwarding_to_endpoint = forwarding->GetLocalEndPoint();
                    if (int forwarding_to_port = forwarding_to_endpoint.port(); forwarding_to_port > IPEndPoint::MinPort && forwarding_to_port <= IPEndPoint::MaxPort) {
                        forwarding->SetRemoteEndPoint(hostname, port);
                        port = forwarding_to_port;
                        address = forwarding_to_endpoint.address().to_string();
                        ppp::telemetry::Count("client_exchanger.proxy.setup", 1);
                        ppp::telemetry::Log(Level::kInfo, "client_exchanger", "proxy forwarding setup: %s:%d", hostname.c_str(), port);
                    }
                }

                if (address.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    ppp::telemetry::Log(Level::kInfo, "client_exchanger", "network port invalid in GetRemoteEndPoint port=%d server=%s hostname=%s address=%s", port, client_server_string.c_str(), hostname.c_str(), address.c_str());
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                }

                IPEndPoint ipep(address.data(), port);
                if (IPEndPoint::IsInvalid(ipep)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                remoteEP                  = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(ipep);
                server_url_.remoteEP      = remoteEP;
                server_url_.hostname      = hostname;
                server_url_.address       = address;
                server_url_.path          = path;
                server_url_.server        = server;
                server_url_.port          = port;
                server_url_.protocol_type = protocol_type;
                return true;
            }

            /** @brief Opens a transport connection to current remote endpoint. */
            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::OpenTransmission(const ContextPtr& context, const StrandPtr& strand, YieldContext& y, ppp::transmissions::TcpTransmissionRole role) noexcept {
                boost::asio::ip::tcp::endpoint remoteEP;
                ppp::string hostname;
                ppp::string address;
                ppp::string path;
                ppp::string server;
                int port = IPEndPoint::MinPort;
                ProtocolType protocol_type = ProtocolType::ProtocolType_PPP;

                if (!GetRemoteEndPoint(y.GetPtr(), hostname, address, path, port, protocol_type, server, remoteEP)) {
                    return NULLPTR;
                }

                boost::asio::ip::address remoteIP = remoteEP.address();
                if (IPEndPoint::IsInvalid(remoteIP)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                }

                int remotePort = remoteEP.port();
                if (remotePort <= IPEndPoint::MinPort || remotePort > IPEndPoint::MaxPort) {
                    ppp::telemetry::Log(Level::kInfo, "client_exchanger", "network port invalid in OpenTransmission remote_port=%d server=%s hostname=%s address=%s", remotePort, server.c_str(), hostname.c_str(), address.c_str());
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                }

#if defined(_WIN32)
                bool windows_ipv6_route_staged = false;
                if (role == ppp::transmissions::TcpTransmissionRole::Main) {
                    const bool had_takeover = switcher_->HasActiveWindowsIPv6Takeover();
                    boost::asio::ip::tcp::endpoint egress_endpoint = remoteEP;
                    if (const auto forwarding = switcher_->GetForwarding(); forwarding) {
                        egress_endpoint = forwarding->GetProxyEndPoint();
                    }
                    const boost::asio::ip::address egress_address = egress_endpoint.address();
                    const bool proven_external =
                        !IPEndPoint::IsInvalid(egress_address) &&
                        !egress_address.is_unspecified() &&
                        !egress_address.is_multicast() &&
                        !egress_address.is_loopback();
                    const bool staged = switcher_->StageWindowsIPv6Egress(
                        egress_endpoint, proven_external);
                    const bool protected_route = staged && switcher_->EnsureWindowsIPv6Sink();
                    if (protected_route) {
                        windows_ipv6_route_staged = true;
                    }
                    else {
                        switcher_->RollbackWindowsIPv6Egress();
                        // Initial protection is best-effort. Once takeover exists, or an exact
                        // rollback is pending, never connect a candidate without a safe egress.
                        if (had_takeover || switcher_->HasPendingWindowsIPv6Cleanup()) {
                            return ppp::diagnostics::SetLastError(
                                ppp::diagnostics::ErrorCode::RouteAddFailed,
                                VEthernetExchanger::ITransmissionPtr(NULLPTR));
                        }
                    }
                }
#endif
                auto rollback_windows_ipv6_route = [&]() noexcept {
#if defined(_WIN32)
                    if (windows_ipv6_route_staged) {
                        switcher_->RollbackWindowsIPv6Egress();
                        windows_ipv6_route_staged = false;
                    }
#endif
                };

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = NewAsynchronousSocket(context, strand, remoteEP.protocol(), y);
                if (!socket) {
                    rollback_windows_ipv6_route();
                    return NULLPTR;
                }

#if defined(_LINUX)
                // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter.
                // IPV6 does not need to be linked, because VPN is IPV4,
                // And IPV6 does not affect the physical layer network communication of the VPN.
                if (!remoteIP.is_loopback()) {
                    auto protector_network = switcher_->GetProtectorNetwork();
                    if (NULLPTR != protector_network) {
                        if (!protector_network->Protect(socket->native_handle(), y)) {
                            rollback_windows_ipv6_route();
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                        }
                    }
                }
#endif

                ppp::telemetry::Count("client_exchanger.connect.attempt", 1);
                ppp::telemetry::Log(Level::kInfo, "client_exchanger", "tcp connecting: %s:%d address=%s", hostname.c_str(), remotePort, remoteIP.to_string().c_str());

                AppConfigurationPtr configuration = GetConfiguration();
                if (NULLPTR == configuration) {
                    rollback_windows_ipv6_route();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::AppConfigurationMissing, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                }

                static constexpr int ConnectPending = 0;
                static constexpr int ConnectCompleted = 1;
                static constexpr int ConnectTimedOut = 2;
                std::shared_ptr<std::atomic_int> connect_state = make_shared_object<std::atomic_int>(ConnectPending);
                std::shared_ptr<boost::asio::steady_timer> connect_timer = strand
                    ? make_shared_object<boost::asio::steady_timer>(*strand)
                    : make_shared_object<boost::asio::steady_timer>(*context);
                if (NULLPTR == connect_state || NULLPTR == connect_timer) {
                    rollback_windows_ipv6_route();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                }

                const int64_t timeout_ms = std::max<int64_t>(1,
                    static_cast<int64_t>(configuration->tcp.connect.timeout) * 1000);
                connect_timer->expires_after(std::chrono::milliseconds(timeout_ms));
                connect_timer->async_wait(
                    [socket, connect_state](const boost::system::error_code& ec) noexcept {
                        int expected = ConnectPending;
                        if (ec == boost::system::errc::success &&
                            connect_state->compare_exchange_strong(expected, ConnectTimedOut, std::memory_order_acq_rel)) {
                            Socket::Closesocket(socket);
                        }
                    });

                bool ok = ppp::coroutines::asio::async_connect(*socket, remoteEP, y);
                int expected = ConnectPending;
                const bool timed_out = !connect_state->compare_exchange_strong(
                    expected, ConnectCompleted, std::memory_order_acq_rel) && expected == ConnectTimedOut;
                connect_timer->cancel();
                if (!ok || timed_out) {
                    const ppp::diagnostics::ErrorCode error = timed_out
                        ? ppp::diagnostics::ErrorCode::TcpConnectTimeout
                        : ppp::diagnostics::ErrorCode::TcpConnectFailed;
                    ppp::telemetry::Count("client_exchanger.connect.fail.tcp", 1);
                    ppp::telemetry::Log(Level::kInfo, "client_exchanger", "tcp connect failed: %s:%d address=%s error=%d", hostname.c_str(), remotePort, remoteIP.to_string().c_str(), (int)error);
                    rollback_windows_ipv6_route();
                    return ppp::diagnostics::SetLastError(error, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                }

                ppp::telemetry::Log(Level::kInfo, "client_exchanger", "tcp connected: %s:%d role=%s", hostname.c_str(), remotePort, TransmissionRoleName(role));
                ITransmissionPtr transmission = NewTransmission(
                    context, strand, socket, protocol_type, hostname, path, role);
                if (!transmission) {
                    rollback_windows_ipv6_route();
                }
                return transmission;
            }

            /** @brief Starts main asynchronous exchanger loop. */
            bool VEthernetExchanger::Open() noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                AppConfigurationPtr configuration = GetConfiguration();
                if (!configuration) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                }

                ContextPtr context = GetContext();
                if (!context) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                }

                auto self = shared_from_this();
                auto allocator = configuration->GetBufferAllocator();
                StrandPtr strand = make_shared_object<Executors::Strand>(
                    boost::asio::make_strand(*context));
                if (!strand) {
                    return ppp::diagnostics::SetLastError(
                        ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                }
                owner_strand_ = strand;

                return YieldContext::Spawn(allocator.get(), *context, strand.get(),
                    [self, this, context, strand](YieldContext& y) noexcept {
                        Loopback(context, strand, y);
                    });
            }

            /** @brief Schedules periodic maintenance tasks on exchanger context. */
            bool VEthernetExchanger::Update() noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return false;
                }

                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context,
                    [self, this, context]() noexcept {
                        static thread_local VEthernetExchanger* in_update_owner = NULLPTR;
                        if (NULLPTR != in_update_owner) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TCPLinkDeadlockDetected);
                            return;
                        }

                        in_update_owner = this;
                        struct UpdateScope final {
                            VEthernetExchanger*& owner;

                            ~UpdateScope() noexcept {
                                owner = NULLPTR;
                            }
                        } update_scope{ in_update_owner };

                        uint64_t now = ppp::threading::Executors::GetTickCount();
                        SendEchoKeepAlivePacket(now, false);
                        DoMuxEvents();
                        DoKeepAlived(GetTransmission(), now);

                        // UDP datagram ports: the manager owns the session table and its own two-phase GC.
                        datagram_manager_->Tick(now);

                        uint64_t expired_generation = 0;
                        std::shared_ptr<ppp::p2p::IP2PDatagramTransport> expired_transport;
                        bool offer_expired = false;
                        bool path_fallback = false;
                        {
                            std::lock_guard<std::mutex> offer_scope(p2p_offer_mutex_);
                            const uint64_t generation =
                                p2p_offer_generation_.load(std::memory_order_acquire);
                            offer_expired = p2p_offer_session_.Expire(
                                now, &expired_generation);
                            if (offer_expired && expired_generation == generation) {
                                p2p_direct_data_path_.Fallback(
                                    ppp::p2p::P2PFallbackReason::Timeout,
                                    true, expired_generation);
                                expired_transport = std::move(p2p_candidate_transport_);
                                p2p_registered_candidates_.clear();
                                p2p_registered_transmission_.reset();
                                p2p_local_candidate_ = {};
                                p2p_peer_candidate_ = {};
                                p2p_transport_registration_id_ = 0;
                                p2p_registered_virtual_ip_ = 0;
                                p2p_peer_virtual_ip_ = 0;
                                p2p_last_heartbeat_tx_ms_ = 0;
                                p2p_heartbeat_misses_ = 0;
                                p2p_suspect_since_ms_ = 0;
                                p2p_migrate_started_ms_ = 0;
                            }
                            else if (p2p_candidate_transport_ &&
                                p2p_direct_data_path_.State() == ppp::p2p::P2PState::Direct) {
                                const auto configuration = GetConfiguration();
                                const int interval_ms = configuration
                                    ? configuration->p2p.heartbeat_interval_ms : 1000;
                                const int miss_max = configuration
                                    ? configuration->p2p.heartbeat_miss_max : 2;
                                const int suspect_timeout_ms = configuration
                                    ? configuration->p2p.suspect_timeout_ms : 2000;
                                const uint64_t last_rx =
                                    p2p_offer_session_.LastReceiveActivityMs();
                                if (last_rx != 0 &&
                                    now - last_rx >= static_cast<uint64_t>(interval_ms)) {
                                    if (p2p_last_heartbeat_tx_ms_ == 0 ||
                                        now - p2p_last_heartbeat_tx_ms_ >=
                                            static_cast<uint64_t>(interval_ms)) {
                                        std::vector<std::uint8_t> heartbeat;
                                        if (p2p_offer_session_.SealHeartbeat(
                                                now, generation, heartbeat) &&
                                            p2p_candidate_transport_->SendTo(
                                                heartbeat.data(),
                                                static_cast<int>(heartbeat.size()),
                                                p2p_peer_candidate_)) {
                                            p2p_last_heartbeat_tx_ms_ = now;
                                            ++p2p_heartbeat_misses_;
                                            ppp::telemetry::Count("p2p.heartbeat.sent", 1);
                                        }
                                    }
                                }
                                if (p2p_heartbeat_misses_ >= miss_max) {
                                    if (p2p_direct_data_path_.MarkSuspect(generation)) {
                                        p2p_suspect_since_ms_ = now;
                                        p2p_state_.store(
                                            ppp::p2p::P2PState::Suspect,
                                            std::memory_order_relaxed);
                                        ppp::telemetry::Count("p2p.heartbeat.suspect", 1);
                                    }
                                }
                                if (p2p_direct_data_path_.State() ==
                                        ppp::p2p::P2PState::Suspect &&
                                    p2p_suspect_since_ms_ != 0 &&
                                    now - p2p_suspect_since_ms_ >=
                                        static_cast<uint64_t>(suspect_timeout_ms)) {
                                    p2p_direct_data_path_.Fallback(
                                        ppp::p2p::P2PFallbackReason::Timeout,
                                        true, generation);
                                    path_fallback = true;
                                    p2p_last_heartbeat_tx_ms_ = 0;
                                    p2p_heartbeat_misses_ = 0;
                                    p2p_suspect_since_ms_ = 0;
                                    p2p_migrate_started_ms_ = 0;
                                }
                                if (p2p_migrate_started_ms_ != 0) {
                                    const int grace_ms = configuration
                                        ? configuration->p2p.migration_grace_ms : 5000;
                                    if (now - p2p_migrate_started_ms_ >=
                                        static_cast<uint64_t>(grace_ms)) {
                                        p2p_direct_data_path_.Fallback(
                                            ppp::p2p::P2PFallbackReason::MigrationFailure,
                                            true, generation);
                                        path_fallback = true;
                                        p2p_migrate_started_ms_ = 0;
                                        p2p_last_heartbeat_tx_ms_ = 0;
                                        p2p_heartbeat_misses_ = 0;
                                        p2p_suspect_since_ms_ = 0;
                                    }
                                }
                            }
                            else if (p2p_candidate_transport_ &&
                                p2p_direct_data_path_.State() == ppp::p2p::P2PState::Suspect) {
                                const auto configuration = GetConfiguration();
                                const int suspect_timeout_ms = configuration
                                    ? configuration->p2p.suspect_timeout_ms : 2000;
                                if (p2p_suspect_since_ms_ != 0 &&
                                    now - p2p_suspect_since_ms_ >=
                                        static_cast<uint64_t>(suspect_timeout_ms)) {
                                    p2p_direct_data_path_.Fallback(
                                        ppp::p2p::P2PFallbackReason::Timeout,
                                        true, generation);
                                    path_fallback = true;
                                    p2p_last_heartbeat_tx_ms_ = 0;
                                    p2p_heartbeat_misses_ = 0;
                                    p2p_suspect_since_ms_ = 0;
                                    p2p_migrate_started_ms_ = 0;
                                }
                            }
                        }
                        if (expired_transport) expired_transport->Close();
                        if (offer_expired || path_fallback) {
                            std::lock_guard<std::mutex> state_scope(runtime_state_mutex_);
                            if (!disposed_.load(std::memory_order_acquire) &&
                                network_state_.load(std::memory_order_relaxed) == NetworkState_Established &&
                                (offer_expired
                                    ? expired_generation
                                    : p2p_offer_generation_.load(std::memory_order_acquire)) ==
                                    p2p_offer_generation_.load(std::memory_order_acquire)) {
                                p2p_state_.store(
                                    ppp::p2p::P2PState::Relay,
                                    std::memory_order_relaxed);
                            }
                        }

                        frp_registry_->Tick(now);
                    });
                return true;
            }

            /** @brief Executes keepalive timeout logic for established state. */
            bool VEthernetExchanger::DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return false;
                }

                NetworkState network_state = GetNetworkState();
                if (network_state != NetworkState_Established) {
                    return true;
                }

                if (VirtualEthernetLinklayer::DoKeepAlived(transmission, now)) {
                    return true;
                }

                IDisposable::Dispose(transmission);
                return false;
            }

            /** @brief Connects and handshakes a child transmission for mux use. */
            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::ConnectTransmission(const ContextPtr& context, const StrandPtr& strand, YieldContext& y, uint64_t* ios_child_slot_generation) noexcept {
                if (NULLPTR == context) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                }

                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                }

                // VPN client A link can be created only after a link is established between the local switch and the remote VPN server.
                ITransmissionPtr owner_link = transmission_;
                if (NULLPTR == owner_link) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                }

#if defined(_IPHONE)
                const bool ios_child_slot = (NULLPTR != ios_child_slot_generation);
                uint64_t ios_reserved_generation = 0;
                if (NULLPTR != ios_child_slot_generation) {
                    *ios_child_slot_generation = 0;
                }
                if (ios_child_slot) {
                    if (!TryReserveIosChildTransmissionSlot(context, y, ios_reserved_generation)) {
                        if (disposed_.load(std::memory_order_acquire)) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                        }

                        ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCode();
                        if (code == ppp::diagnostics::ErrorCode::Success) {
                            code = ppp::diagnostics::ErrorCode::SessionQuotaExceeded;
                        }

                        return ppp::diagnostics::SetLastError(code, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                    }
                }
#endif

                ITransmissionPtr transmission = OpenTransmission(context, strand, y, ppp::transmissions::TcpTransmissionRole::Child);
                if (NULLPTR == transmission) {
#if defined(_IPHONE)
                    if (ios_child_slot) {
                        ReleaseIosChildTransmissionSlot(ios_reserved_generation);
                    }
#endif
                    return NULLPTR;
                }

                bool noerror = transmission->HandshakeServer(y, GetId(), false);
                if (noerror) {
#if defined(_IPHONE)
                    if (ios_child_slot && NULLPTR != ios_child_slot_generation) {
                        *ios_child_slot_generation = ios_reserved_generation;
                    }
#endif
                    return transmission;
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                    transmission->Dispose();
#if defined(_IPHONE)
                    if (ios_child_slot) {
                        ReleaseIosChildTransmissionSlot(ios_reserved_generation);
                    }
#endif
                    return NULLPTR;
                }
            }

#if defined(_IPHONE)
            bool VEthernetExchanger::IosPeerConnectBackpressured() const noexcept {
                std::shared_ptr<vmux::vmux_net> mux = mux_coordinator_->Session();
                if (NULLPTR != mux && mux->is_established()) {
                    return false;
                }

                return ios_child_connect_waiters_.load(std::memory_order_relaxed) >= IOS_CHILD_CONNECT_WAITER_BURST_LIMIT;
            }

            void VEthernetExchanger::ResetIosChildTransmissionSlots(const char* reason) noexcept {
                int stale_active = 0;
                uint64_t generation = 0;
                {
                    std::lock_guard<std::mutex> lock(ios_child_slots_mutex_);
                    stale_active = ios_child_transmission_active_.exchange(0, std::memory_order_acq_rel);
                    generation = ios_child_slot_generation_.fetch_add(1, std::memory_order_acq_rel) + 1;
                }
                if (stale_active > 0) {
                    ppp::telemetry::Log(Level::kInfo, "client_exchanger",
                        "ios child slots reset reason=%s stale_active=%d generation=%llu",
                        (NULLPTR != reason && reason[0] != '\0') ? reason : "unknown",
                        stale_active,
                        (unsigned long long)generation);
                }
            }

            void VEthernetExchanger::ReleaseIosChildTransmissionSlot(uint64_t generation) noexcept {
                if (generation == 0) {
                    return;
                }

                std::lock_guard<std::mutex> lock(ios_child_slots_mutex_);
                uint64_t current_generation = ios_child_slot_generation_.load(std::memory_order_acquire);
                if (generation != current_generation) {
                    ppp::telemetry::Log(Level::kDebug, "client_exchanger",
                        "ios child slot stale release ignored generation=%llu current=%llu active=%d",
                        (unsigned long long)generation,
                        (unsigned long long)current_generation,
                        ios_child_transmission_active_.load(std::memory_order_acquire));
                    return;
                }

                int active = ios_child_transmission_active_.load(std::memory_order_acquire);
                if (active <= 0) {
                    ios_child_transmission_active_.store(0, std::memory_order_release);
                    return;
                }
                ios_child_transmission_active_.store(active - 1, std::memory_order_release);
            }

            bool VEthernetExchanger::TryReserveIosChildTransmissionSlot(const ContextPtr& context, YieldContext& y, uint64_t& generation) noexcept {
                generation = 0;
                ios_child_connect_waiters_.fetch_add(1, std::memory_order_relaxed);
                struct WaiterGuard final {
                    std::atomic<int>& counter;
                    bool released = false;
                    ~WaiterGuard() noexcept {
                        if (!released) {
                            counter.fetch_sub(1, std::memory_order_relaxed);
                        }
                    }
                } waiter_guard{ios_child_connect_waiters_};

                int waited_ms = 0;
                for (;;) {
                    if (disposed_.load(std::memory_order_acquire)) {
                        return false;
                    }

                    if (GetNetworkState() != NetworkState_Established) {
                        return false;
                    }

                    if (NULLPTR == transmission_) {
                        return false;
                    }

                    const int waiters = ios_child_connect_waiters_.load(std::memory_order_relaxed);
                    int active = 0;
                    {
                        std::lock_guard<std::mutex> lock(ios_child_slots_mutex_);
                        active = ios_child_transmission_active_.load(std::memory_order_acquire);
                        if (active < IOS_CHILD_TRANSMISSION_LIMIT) {
                            ios_child_transmission_active_.store(active + 1, std::memory_order_release);
                            generation = ios_child_slot_generation_.load(std::memory_order_acquire);
                            waiter_guard.released = true;
                            ios_child_connect_waiters_.fetch_sub(1, std::memory_order_relaxed);
                            ppp::telemetry::Histogram("client_exchanger.ios_child_slot.active", active + 1);
                            if (waited_ms > 0) {
                                ppp::telemetry::Histogram("client_exchanger.ios_child_slot.wait_ms", waited_ms);
                            }
                            return true;
                        }
                    }

                    if (waiters > IOS_CHILD_CONNECT_WAITER_BURST_LIMIT) {
                        ppp::telemetry::Count("client_exchanger.ios_child_slot.waiter_rejected", 1);
                        ppp::telemetry::Log(Level::kInfo, "client_exchanger",
                            "ios child slot waiter burst rejected waiters=%d active=%d active_limit=%d burst_limit=%d",
                            waiters,
                            active,
                            IOS_CHILD_TRANSMISSION_LIMIT,
                            IOS_CHILD_CONNECT_WAITER_BURST_LIMIT);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);
                        return false;
                    }

                    if (waiters > IOS_CHILD_CONNECT_WAITER_SOFT_LIMIT) {
                        ppp::telemetry::Count("client_exchanger.ios_child_slot.wait.backpressure", 1);
                    }
                    else {
                        ppp::telemetry::Count("client_exchanger.ios_child_slot.wait", 1);
                    }

                    if (!Sleep(IOS_CHILD_SLOT_WAIT_INTERVAL_MS, context, y)) {
                        if (!disposed_.load(std::memory_order_acquire)
                            && GetNetworkState() == NetworkState_Established
                            && NULLPTR != transmission_
                            && ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);
                        }
                        return false;
                    }

                    waited_ms += IOS_CHILD_SLOT_WAIT_INTERVAL_MS;
                    if (waited_ms >= IOS_CHILD_SLOT_WAIT_MAX_MS) {
                        ppp::telemetry::Count("client_exchanger.ios_child_slot.wait_timeout", 1);
                        ppp::telemetry::Log(Level::kInfo, "client_exchanger",
                            "ios child slot wait timeout waiters=%d active=%d active_limit=%d waited_ms=%d",
                            waiters,
                            active,
                            IOS_CHILD_TRANSMISSION_LIMIT,
                            waited_ms);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);
                        return false;
                    }
                }
            }
#endif

#if defined(_ANDROID)
            /** @brief Waits until Android protector JNI context becomes available. */
            bool VEthernetExchanger::AwaitJniAttachThread(const ContextPtr& context, YieldContext& y) noexcept {
                // On the Android platform, when the VPN tunnel transport layer is enabled,
                // Ensure that the JVM thread has been attached to the PPP. Otherwise, the link cannot be protected,
                // Resulting in loop problems and VPN loopback crashes.
                bool attach_ok = false;
                while (!disposed_.load(std::memory_order_acquire)) {
                    if (std::shared_ptr<ppp::net::ProtectorNetwork> protector = switcher_->GetProtectorNetwork(); NULLPTR != protector) {
                        if (NULLPTR != protector->GetContext() && NULLPTR != protector->GetEnvironment()) {
                            attach_ok = true;
                            break;
                        }
                    }

                    bool sleep_ok = Sleep(10, context, y); // Poll.
                    if (!sleep_ok) {
                        break;
                    }
                }

                return attach_ok;
            }
#endif

            /** @brief Runs connect-handshake-run-reconnect loop until disposed. */
            bool VEthernetExchanger::Loopback(const ContextPtr& context, const StrandPtr& strand, YieldContext& y) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (!configuration) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                }
#if defined(_ANDROID)
                elif(!AwaitJniAttachThread(context, y)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed);
                }
#endif
                const uint64_t base_delay_ms = static_cast<uint64_t>(configuration->client.reconnections.timeout) * 1000;
                const uint64_t max_delay_ms = static_cast<uint64_t>(configuration->client.reconnections.max_delay) * 1000;
                ClientReconnectionPolicy reconnection_policy(
                    base_delay_ms, max_delay_ms,
                    static_cast<uint32_t>(configuration->client.reconnections.jitter_percent));

                bool run_once = false;
                while (!disposed_.load(std::memory_order_acquire)) {
                    ExchangeToConnectingState();
#if defined(_IPHONE)
                    bool session_established = false;
#endif
                    bool mappings_registered = false;
                    ITransmissionPtr transmission = OpenTransmission(
                        context, strand, y, ppp::transmissions::TcpTransmissionRole::Main);
                    if (NULLPTR == transmission) {
                        server_url_.port = 0;
                        ppp::telemetry::Count("client_exchanger.connect.fail.open_transmission", 1);
                        ppp::telemetry::Log(Level::kInfo, "client_exchanger", "open transmission failed error=%d", (int)ppp::diagnostics::GetLastErrorCode());
                    }
                    else {
                        static constexpr int HandshakePending = 0;
                        static constexpr int HandshakeCompleted = 1;
                        static constexpr int HandshakeTimedOut = 2;
                        std::shared_ptr<std::atomic_int> handshake_state =
                            make_shared_object<std::atomic_int>(HandshakePending);
                        std::shared_ptr<boost::asio::steady_timer> handshake_timer =
                            make_shared_object<boost::asio::steady_timer>(*strand);
                        bool established = false;
                        bool transport_auth_failed = false;
                        if (NULLPTR == handshake_state || NULLPTR == handshake_timer) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        }
                        else {
                            const auto arm_handshake_timer =
                                [transmission, handshake_state, handshake_timer](
                                    int64_t timeout_ms) noexcept {
                                    handshake_timer->expires_after(
                                        std::chrono::milliseconds(std::max<int64_t>(1, timeout_ms)));
                                    handshake_timer->async_wait(
                                        [transmission, handshake_state](
                                            const boost::system::error_code& ec) noexcept {
                                            int expected = HandshakePending;
                                            if (ec == boost::system::errc::success &&
                                                handshake_state->compare_exchange_strong(
                                                    expected, HandshakeTimedOut,
                                                    std::memory_order_acq_rel)) {
                                                transmission->Dispose();
                                            }
                                        });
                                };
                            arm_handshake_timer(
                                static_cast<int64_t>(configuration->tcp.connect.timeout) * 1000);

                            InformationEnvelope initial_information;
                            bool has_initial_information = false;
                            bool sent_fresh_probe = false;
                            SessionResumeNegotiationResult negotiation =
                                SessionResumeNegotiationResult::Fresh;
                            established = transmission->HandshakeServer(y, GetId(), true);
                            if (established && ShouldRunClientTransportAuth(
                                    transmission->GetAuthenticatedCarrierKind(),
                                    configuration->client.transport_auth.enabled,
                                    transmission->PeerSupportsTransportAuthV1(),
                                    transmission->PeerEnablesTransportAuthV1())) {
                                arm_handshake_timer(
                                    configuration->transport_auth.handshake_timeout_ms);
                                established = AuthenticatePlainTransport(transmission, y);
                                transport_auth_failed = !established;
                            }
                            if (established) {
                                const bool recovery_carrier_eligible =
                                    IsClientSessionRecoveryCarrierEligible(
                                        transmission->GetAuthenticatedCarrierKind(),
                                        transmission->GetAuthenticatedCarrierMethod(),
                                        transmission->IsAuthenticatedCarrierBindingActive(),
                                        transmission->HasAuthenticatedSessionExporter());
                                const ClientSessionResumePreamble preamble =
                                    SelectClientSessionResumePreamble(
                                        configuration->client.session_resume.enabled,
                                        switcher_->IsVNet(),
                                        recovery_carrier_eligible,
                                        session_resume_armed_, session_resume_root_.IsSet());
                                if (preamble == ClientSessionResumePreamble::FreshProbe) {
                                    established = EchoLanToRemoteExchanger(
                                        transmission, y) > -1;
                                    sent_fresh_probe = established;
                                }
                            }
                            if (established) {
                                negotiation = NegotiateSessionResume(transmission,
                                    initial_information,
                                    has_initial_information, y);
                                established = negotiation !=
                                    SessionResumeNegotiationResult::Failed;
                            }
                            if (established) {
                                if (negotiation == SessionResumeNegotiationResult::Resumed) {
                                    established = datagram_manager_->RebindTransmission(transmission);
                                    if (!established) {
                                        ppp::diagnostics::SetLastErrorCode(
                                            ppp::diagnostics::ErrorCode::SessionTransportMissing);
                                    }
                                }
                                else {
                                    // A fresh session cannot inherit server-side UDP flow state.
                                    // Keep local handlers registered, but discard retained ports.
                                    datagram_manager_->ResetPorts();
                                }
                            }
                            if (established && has_initial_information) {
                                established = ApplyPreDataInformation(
                                    transmission, initial_information, y);
                            }
                            if (established && !sent_fresh_probe) {
                                established = EchoLanToRemoteExchanger(transmission, y) > -1;
                            }

                            int expected = HandshakePending;
                            const bool handshake_timed_out = !handshake_state->compare_exchange_strong(
                                expected, HandshakeCompleted, std::memory_order_acq_rel) && expected == HandshakeTimedOut;
                            handshake_timer->cancel();
                            if (handshake_timed_out) {
                                established = false;
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketTimeout);
                            }
                        }

#if defined(_WIN32)
                        if (established && !switcher_->CommitWindowsIPv6Egress()) {
                            switcher_->RollbackWindowsIPv6Egress();
                            established = false;
                            ppp::diagnostics::SetLastErrorCode(
                                ppp::diagnostics::ErrorCode::RouteAddFailed);
                        }
                        if (!established) {
                            switcher_->RollbackWindowsIPv6Egress();
                        }
#endif
                        if (!established) {
                            if (!transport_auth_failed && IsTerminalSessionResumeError(
                                    ppp::diagnostics::GetLastErrorCode())) {
                                ClearSessionResumeState();
                            }
                            server_url_.port = 0;
                            ppp::telemetry::Count("client_exchanger.connect.fail.handshake", 1);
                            ppp::telemetry::Log(Level::kInfo, "client_exchanger", "exchanger handshake failed error=%d", (int)ppp::diagnostics::GetLastErrorCode());
                        }
                        else {
#if defined(_IPHONE)
                            session_established = true;
#endif
                            transmission_ = transmission;
                            ExchangeToEstablishState();
                            ppp::telemetry::Count("client_exchanger.connect", 1);
                            ppp::telemetry::Log(Level::kInfo, "client_exchanger", "exchanger connected");
#if !defined(_ANDROID) && !defined(_IPHONE)
                            if (std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_; NULLPTR != switcher) {
                                if (!switcher->TryApplyHostedNetworkRoutes()) {
                                    ppp::telemetry::Log(Level::kInfo, "client_exchanger", "route setup failed after exchanger connected");
                                    ppp::telemetry::Count("client_exchanger.route_setup.fail", 1);
                                }
                            }
#endif
                            bool main_run_ok = false;
                            if (SendRequestedIPv6Configuration(transmission, y)) {
                                RegisterAllMappingPorts();
                                mappings_registered = true;
                                ppp::telemetry::Log(Level::kInfo, "protocol", "session established role=main");
                                if (static_echo_.StaticEchoAllocatedToRemoteExchanger(y)) {
                                    reconnection_policy.Reset();
                                    if (Run(transmission, y)) {
                                        main_run_ok = true;
                                        run_once = true;
                                    }
                                }
                            }
                            if (IsTerminalSessionResumeError(
                                    ppp::diagnostics::GetLastErrorCode())) {
                                ClearSessionResumeState();
                            }
                            ppp::telemetry::Log(Level::kInfo, "protocol",
                                "session disposed role=main reason=loop_end ok=%d error=%d",
                                main_run_ok ? 1 : 0,
                                (int)ppp::diagnostics::GetLastErrorCode());

                            link_telemetry_.RecordFault();
                            ppp::diagnostics::LinkTelemetryGlobal::GetInstance().GetTotal().RecordFault();
                            ppp::telemetry::Count("client_exchanger.disconnect", 1);
                            ppp::telemetry::Log(Level::kInfo, "client_exchanger", "exchanger disconnecting");
                        }
                    }

                    if (!disposed_.load(std::memory_order_acquire)) {
                        ExchangeToReconnectingState();
                    }

                    // L3 roaming retains UDP flow state only. VMUX and all other
                    // carrier-bound state must be closed before reconnect can publish.
                    std::shared_ptr<vmux::vmux_net> mux = mux_coordinator_->Take();
                    mux_vlan_ = 0;
                    if (NULLPTR != mux) {
                        mux->close_exec();
                    }
                    datagram_manager_->RebindTransmission(NULLPTR);
                    static_echo_.StaticEchoClean();
                    if (mappings_registered) {
                        UnregisterAllMappingPorts();
                    }
                    if (transmission_ == transmission) {
                        transmission_.reset();
                    }
#if defined(_IPHONE)
                    if (session_established) {
                        ResetIosChildTransmissionSlots("main_transmission_end");
                    }
#endif
                    if (NULLPTR != transmission) {
                        transmission->Dispose();
                    }

                    if (disposed_.load(std::memory_order_acquire)) {
                        break;
                    }
                    const uint64_t entropy =
                        (static_cast<uint64_t>(static_cast<uint32_t>(RandomNext())) << 32) |
                        static_cast<uint32_t>(RandomNext());
                    const uint64_t delay_ms = reconnection_policy.OnFailure(entropy);
                    if (!Sleep(static_cast<int64_t>(delay_ms), context, y)) {
                        break;
                    }
                }
                return run_once;
            }

            /** @brief Maintains vmux session and negotiates mux when required. */
            bool VEthernetExchanger::DoMuxEvents() noexcept {
                bool successes = false;
                while (!disposed_.load(std::memory_order_acquire)) {
                    uint16_t max_connections = switcher_->mux_;
                    if (max_connections == 0) {
                        break;
                    }

                    if (network_state_.load() != NetworkState_Established) {
                        break;
                    }

                    AppConfigurationPtr configuration = GetConfiguration();
                    if (NULLPTR == configuration) {
                        break;
                    }

                    std::shared_ptr<vmux::vmux_net> mux = mux_coordinator_->Session();
                    if (NULLPTR != mux) {
                        bool breaking = true;
                        successes = true;

                        if (mux->Vlan != mux_vlan_) {
                            mux->close_exec();
                        }
                        elif(!mux->update()) {
                            int64_t reconnection_timeout = static_cast<int64_t>(configuration->client.reconnections.timeout) * 1000;
                            uint64_t mux_last = mux->get_last();

                            uint64_t now = mux->now_tick();
                            if (now >= (mux_last + (uint64_t)reconnection_timeout)) {
                                mux_coordinator_->ResetIfCurrent(mux);
                                breaking = false;
                            }

                            mux->close_exec();
                        }

                        if (breaking) {
                            // turbo dynamic pool: if the quality controller asked to
                            // grow, connect that many extra carrier links at runtime
                            // and attach each through add_linklayer's established-
                            // session path (single-link, single forwarding coroutine).
                            if (mux->is_established()) {
                                int grow = mux->take_turbo_pending_grow();
                                if (grow > 0) {
                                    MuxGrowLinklayers(switcher_->GetBufferAllocator(), mux, grow);
                                }
                            }
                            break;
                        }
                    }

                    ppp::threading::Executors::StrandPtr vmux_strand;
                    ppp::threading::Executors::ContextPtr vmux_context = ppp::threading::Executors::SelectScheduler(vmux_strand);
                    if (NULLPTR == vmux_context) {
                        break;
                    }
                    if (NULLPTR == vmux_strand) {
                        vmux_strand = make_shared_object<ppp::threading::Executors::Strand>(vmux_context->get_executor());
                        if (NULLPTR == vmux_strand) {
                            break;
                        }
                    }
                    {
                        vmux::vmux_net::mux_mode mux_mode = vmux::vmux_net::parse_mode(configuration->GetEffectiveMuxMode());
                        mux = make_shared_object<vmux::vmux_net>(vmux_context, vmux_strand, max_connections, false, (switcher_->mux_acceleration_ & PPP_MUX_ACCELERATION_LOCAL) != 0, mux_mode);
                        if (NULLPTR == mux) {
                            break;
                        }

                        // turbo dynamic pool: raise the carrier-link ceiling to
                        // base * PPP_MUX_TURBO_FACTOR_MAX so the quality controller
                        // can grow the pool past --tun-mux under poor quality. The
                        // base (max_connections) is still what is established and
                        // negotiated on the wire; growth happens at runtime.
                        if (mux_mode == vmux::vmux_net::mux_mode_flow &&
                            NULLPTR != configuration && configuration->mux.turbo) {
                            uint32_t hard = (uint32_t)max_connections * (uint32_t)PPP_MUX_TURBO_FACTOR_MAX;
                            if (hard > UINT16_MAX) {
                                hard = UINT16_MAX;
                            }
                            mux->set_pool_hard_max((uint16_t)hard);
                        }
                    }

                    ITransmissionPtr vnet_transmission = GetTransmission();
                    if (NULLPTR == vnet_transmission) {
                        break;
                    }

                    ppp::threading::Executors::ContextPtr vnet_context = GetContext();
                    if (NULLPTR == vnet_context) {
                        break;
                    }

                    std::shared_ptr<ppp::threading::BufferswapAllocator> buffer_allocator = switcher_->GetBufferAllocator();
                    mux->AppConfiguration = configuration;
                    mux->BufferAllocator  = buffer_allocator;
#if defined(_LINUX)
                    mux->ProtectorNetwork = switcher_->GetProtectorNetwork();
#endif

                    for (;;) {
                        uint16_t vlan = (uint16_t)vmux::vmux_net::ftt_random_aid(1, UINT16_MAX);
                        if (vlan != 0 && vlan != mux_vlan_) {
                            mux_vlan_ = vlan;
                            mux->Vlan = vlan;
                            break;
                        }
                    }

                    std::shared_ptr<VirtualEthernetLinklayer> self = shared_from_this();
                    mux_coordinator_->Replace(mux);

                    successes = YieldContext::Spawn(buffer_allocator.get(), *vnet_context,
                        [self, this, vnet_transmission, mux, vnet_context, configuration](YieldContext& y) noexcept {
                            bool ok = false;
                            if (!disposed_.load(std::memory_order_acquire)) {
                                uint16_t max_connections = mux->get_max_connections();
                                // Advertise FLOW_V2 as an implementation capability, independent
                                // of the current scheduler preset. Whether it is *used* is decided
                                // later by mode_requires_flow_v2 + peer intersection.
                                Byte ordering_caps = (Byte)vmux::vmux_net::ordering_caps_flow_v2;
                                // Advertise reliability / FEC when enabled locally; the server
                                // intersects both ends and echoes the authoritative result.
                                if (NULLPTR != configuration && configuration->mux.reliability.enabled) {
                                    ordering_caps |= (Byte)vmux::vmux_net::ordering_caps_reliability;
                                    if (configuration->mux.fec.enabled) {
                                        ordering_caps |= (Byte)vmux::vmux_net::ordering_caps_fec;
                                    }
                                }
                                ok = DoMux(vnet_transmission, mux->Vlan, max_connections, (switcher_->mux_acceleration_ & PPP_MUX_ACCELERATION_REMOTE) != 0, ordering_caps, y);
                            }

                            if (!ok) {
                                mux->close_exec();
                            }
                        });
                    break;
                }

                if (!successes) {
                    std::shared_ptr<vmux::vmux_net> mux = mux_coordinator_->Take();
                    if (NULLPTR != mux) {
                        mux->close_exec();
                    }
                }

                return successes;
            }

            /** @brief Derives mux state from current vmux runtime object. */
            VEthernetExchanger::NetworkState VEthernetExchanger::GetMuxNetworkState() noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return NetworkState_Reconnecting;
                }

                std::shared_ptr<vmux::vmux_net> mux = mux_coordinator_->Session();
                if (NULLPTR == mux) {
                    return NetworkState_Connecting;
                }

                if (mux->is_disposed()) {
                    return NetworkState_Reconnecting;
                }

                if (mux->is_established()) {
                    return NetworkState_Established;
                }

                return NetworkState_Connecting;
            }

            ppp::app::mux::MuxRuntimeState VEthernetExchanger::GetMuxRuntimeState() noexcept {
                if (std::shared_ptr<vmux::vmux_net> mux = mux_coordinator_->Session(); NULLPTR != mux) {
                    return mux_coordinator_->RuntimeState();
                }

                ppp::app::mux::MuxRuntimeState state;
                if (auto configuration = GetConfiguration(); NULLPTR != configuration) {
                    const ppp::string requested = configuration->GetEffectiveMuxMode();
                    state.requested_mode.assign(requested.data(), requested.size());
                }
                if (state.requested_mode.empty()) {
                    state.requested_mode = "compat";
                }
                state.effective_mode = "compat";
                state.receiver_ordering = "compat";
                if (state.requested_mode != "compat") {
                    state.fallback_reason = "mux_inactive";
                }
                ppp::app::mux::FillMuxPresentation(state);
                return state;
            }

            /** @brief Establishes all required vmux child linklayers. */
            bool VEthernetExchanger::MuxConnectAllLinklayers(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<void>& session) noexcept {
                using ppp::app::protocol::VirtualEthernetTcpipConnection;
                const std::shared_ptr<vmux::vmux_net> mux =
                    std::static_pointer_cast<vmux::vmux_net>(session);

                std::shared_ptr<boost::asio::io_context> context = mux->get_context();
                if (NULLPTR == context) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                }

                auto self = shared_from_this();
                auto strand = mux->get_strand();

                return YieldContext::Spawn(allocator.get(), *context, strand.get(),
                    [self, this, mux, context, strand](YieldContext& y) noexcept -> bool {
                        if (disposed_.load(std::memory_order_acquire) || !mux_coordinator_->IsCurrent(mux)) {
                            mux->close_exec();
                            return false;
                        }

                        int max_connections = mux->get_max_connections();
                        int bok_connections = 0;

                        const uint32_t& tx_seq = mux->get_tx_seq();
                        const uint32_t& rx_ack = mux->get_rx_ack();
                        if (!mux->ftt(vmux::vmux_net::ftt_random_aid(1, INT32_MAX), vmux::vmux_net::ftt_random_aid(1, INT32_MAX))) {
                            mux->close_exec();
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                        }

                        auto context = mux->get_context();
                        auto strand = mux->get_strand();

                        for (int i = 0; i < max_connections; i++) {
                            if (disposed_.load(std::memory_order_acquire) || !mux_coordinator_->IsCurrent(mux)) {
                                bok_connections = -1;
                                break;
                            }

                            if (mux->is_established()) {
                                return true;
                            }

                            ITransmissionPtr transmission = ConnectTransmission(context, strand, y);
                            if (NULLPTR == transmission) {
                                break;
                            }

                            std::shared_ptr<boost::asio::ip::tcp::socket> default_socket;
                            std::shared_ptr<VirtualEthernetTcpipConnection> connection =
                                make_shared_object<VirtualEthernetTcpipConnection>(
                                    mux->AppConfiguration, context, strand, GetId(), default_socket);
                            if (NULLPTR == connection) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                                break;
                            }

                            // In this lightweight and simple vmux circuit switch, seq and ack are delivered by the client, and the server and client are opposite.
                            if (!connection->ConnectMux(y, transmission, mux->Vlan, rx_ack, tx_seq)) {
                                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                                }
                                break;
                            }

                            bool bok = mux->do_yield(y,
                                [self, mux, connection]() noexcept -> bool {
                                    vmux::vmux_net::vmux_linklayer_ptr linklayer;
                                    vmux::vmux_net::vmux_native_add_linklayer_after_success_before_callback handling;
                                    auto transport = ppp::app::mux::MakeMuxTransport(connection);
                                    return mux->add_linklayer(transport, linklayer, handling);
                                });

                            if (!bok) {
                                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                                }
                                break;
                            }

                            bok_connections++;
                        }

                        if (bok_connections >= max_connections) {
                            return true;
                        }

                        mux->close_exec();
                        if (!disposed_.load(std::memory_order_acquire) && ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                        }
                        return false;
                    });
            }

            /** @brief Connects `count` extra carrier links at runtime (turbo grow, C-B3 caller). */
            bool VEthernetExchanger::MuxGrowLinklayers(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<void>& session, int count) noexcept {
                using ppp::app::protocol::VirtualEthernetTcpipConnection;
                const std::shared_ptr<vmux::vmux_net> mux =
                    std::static_pointer_cast<vmux::vmux_net>(session);

                if (NULLPTR == mux || count <= 0) {
                    return false;
                }

                std::shared_ptr<boost::asio::io_context> context = mux->get_context();
                if (NULLPTR == context) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                }

                auto self = shared_from_this();
                auto strand = mux->get_strand();

                return YieldContext::Spawn(allocator.get(), *context, strand.get(),
                    [self, this, mux, count, context, strand](YieldContext& y) noexcept -> bool {
                        // Grow is best-effort and non-fatal: a failed extra link must
                        // never tear down the established base pool. Stop on the first
                        // failure and leave the existing links untouched.
                        const uint32_t& tx_seq = mux->get_tx_seq();
                        const uint32_t& rx_ack = mux->get_rx_ack();

                        for (int i = 0; i < count; i++) {
                            if (disposed_.load(std::memory_order_acquire) || !mux_coordinator_->IsCurrent(mux) || mux->is_disposed()) {
                                break;
                            }

                            ITransmissionPtr transmission = ConnectTransmission(context, strand, y);
                            if (NULLPTR == transmission) {
                                break;
                            }

                            std::shared_ptr<boost::asio::ip::tcp::socket> default_socket;
                            std::shared_ptr<VirtualEthernetTcpipConnection> connection =
                                make_shared_object<VirtualEthernetTcpipConnection>(
                                    mux->AppConfiguration, context, strand, GetId(), default_socket);
                            if (NULLPTR == connection) {
                                break;
                            }

                            if (!connection->ConnectMux(y, transmission, mux->Vlan, rx_ack, tx_seq)) {
                                break;
                            }

                            bool bok = mux->do_yield(y,
                                [self, mux, connection]() noexcept -> bool {
                                    vmux::vmux_net::vmux_linklayer_ptr linklayer;
                                    vmux::vmux_net::vmux_native_add_linklayer_after_success_before_callback handling;
                                    // The mux strand enforces the runtime hard ceiling.
                                    // add_linklayer detects the established session and
                                    // attaches this as a single runtime link (one
                                    // forwarding coroutine; no batch re-spawn).
                                    auto transport = ppp::app::mux::MakeMuxTransport(connection);
                                    return mux->add_linklayer(transport, linklayer, handling);
                                });

                            if (!bok) {
                                break;
                            }
                        }

                        return true;
                    });
            }

            /** @brief Removes a deadline timer from tracking table and cancels it. */
            bool VEthernetExchanger::ReleaseDeadlineTimer(const boost::asio::steady_timer* deadline_timer) noexcept {
                if (NULLPTR == deadline_timer) {
                    return false;
                }

                DeadlineTimerPtr reference;
                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    Dictionary::TryRemove(deadline_timers_, (void*)deadline_timer, reference);
                    break;
                }

                if (NULLPTR == reference) {
                    return false;
                }

                Socket::Cancel(*reference);
                return true;
            }

            /** @brief Creates and tracks one asynchronous deadline timer. */
            bool VEthernetExchanger::NewDeadlineTimer(const ContextPtr& context, int64_t timeout, const ppp::function<void(bool)>& event) noexcept {
                std::shared_ptr<boost::asio::steady_timer> t = make_shared_object<boost::asio::steady_timer>(*context);
                if (NULLPTR == t) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                }

                SynchronizedObjectScope scope(syncobj_);
                if (disposed_.load(std::memory_order_acquire)) {
                    return false;
                }
                else {
                    timeout = std::max<int64_t>(1, timeout);
                }

                auto self = shared_from_this();
                boost::asio::steady_timer* deadline_timer = t.get();

                t->expires_after(Timer::DurationTime(timeout));
                t->async_wait(
                    [self, this, deadline_timer, event](const boost::system::error_code& ec) noexcept {
                        ReleaseDeadlineTimer(deadline_timer);
                        event(ec == boost::system::errc::success);
                    });

                auto r = deadline_timers_.emplace(deadline_timer, std::move(t));
                if (r.second) {
                    return true;
                }

                Socket::Cancel(*t);
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
            }

            /** @brief Transitions state to established and initializes keepalive schedule. */
            void VEthernetExchanger::ExchangeToEstablishState() noexcept {
                uint64_t now = Executors::GetTickCount();
                keepalive_policy_.OnConnected(
                    now,
                    RandomNext(SEND_ECHO_KEEP_ALIVE_PACKET_MIN_TIMEOUT,
                        SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT));
                {
                    std::lock_guard<std::mutex> scope(runtime_state_mutex_);
                    network_state_.store(NetworkState_Established, std::memory_order_relaxed);
                }
                reconnection_count_ = 0;
            }

            /** @brief Transitions state to connecting. */
            void VEthernetExchanger::ExchangeToConnectingState() noexcept {
                keepalive_policy_.Reset();
                const uint64_t p2p_generation = ++p2p_offer_generation_;
                p2p_offer_session_.AdvanceGeneration(p2p_generation);
                {
                    std::lock_guard<std::mutex> scope(runtime_state_mutex_);
                    network_state_.store(NetworkState_Connecting, std::memory_order_relaxed);
                    p2p_state_.store(configured_p2p_state_, std::memory_order_relaxed);
                }
                ResetP2PCandidateTransport();
            }

            /** @brief Transitions state to reconnecting and increments retry count. */
            void VEthernetExchanger::ExchangeToReconnectingState() noexcept {
                keepalive_policy_.Reset();
                const uint64_t p2p_generation = ++p2p_offer_generation_;
                p2p_offer_session_.AdvanceGeneration(p2p_generation);
                {
                    std::lock_guard<std::mutex> scope(runtime_state_mutex_);
                    network_state_.store(NetworkState_Reconnecting, std::memory_order_relaxed);
                    p2p_state_.store(configured_p2p_state_, std::memory_order_relaxed);
                }
                ResetP2PCandidateTransport();
                if (reconnection_count_ < std::numeric_limits<int>::max()) {
                    ++reconnection_count_;
                }
#if defined(_IPHONE)
                ResetIosChildTransmissionSlots("reconnecting");
#endif
            }

            VEthernetExchanger::RuntimeStateSnapshot VEthernetExchanger::GetRuntimeState() const noexcept {
                std::lock_guard<std::mutex> scope(runtime_state_mutex_);
                RuntimeStateSnapshot snapshot;
                snapshot.network_state = network_state_.load(std::memory_order_relaxed);
                if (disposed_.load(std::memory_order_acquire)) {
                    snapshot.p2p_state = ppp::p2p::P2PState::Disabled;
                }
                else if (snapshot.network_state != NetworkState_Established) {
                    snapshot.p2p_state = configured_p2p_state_;
                }
                else {
                    snapshot.p2p_state = p2p_state_.load(std::memory_order_relaxed);
                }
                return snapshot;
            }

            /** @brief Registers all configured FRP mapping ports. */
            bool VEthernetExchanger::RegisterAllMappingPorts() noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                AppConfigurationPtr configuration = GetConfiguration();
                for (ppp::configurations::MappingConfiguration& mapping : configuration->client.mappings) {
                    RegisterMappingPort(mapping);
                }

                return true;
            }

            /** @brief Unregisters and disposes all FRP mapping ports. */
            void VEthernetExchanger::UnregisterAllMappingPorts() noexcept {
                frp_registry_->ReleaseAll();
            }

            /** @brief Rejects unsolicited LAN messages for security hardening. */
            bool VEthernetExchanger::OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid); // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            /** @brief Forwards NAT payload from remote side to local switcher output. */
            bool VEthernetExchanger::OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                if (NULLPTR == switcher_ || NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                std::shared_ptr<ppp::tap::ITap> tap = switcher_->GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                const Byte version = packet[0] >> 4;
                app::protocol::VirtualEthernetIPv6PathMtuAddress assigned_ipv6;
                bool has_assigned_ipv6 = false;
                if (version == ppp::ipv6::IPv6_VERSION) {
                    const auto information_extensions = switcher_->GetInformationExtensions();
                    if (information_extensions.AssignedIPv6Address.is_v6()) {
                        assigned_ipv6 = app::protocol::VirtualEthernetIPv6PathMtuAddress::Create(
                            information_extensions.AssignedIPv6Address.to_v6());
                        has_assigned_ipv6 = true;
                    }
                }

                AppConfigurationPtr configuration = GetConfiguration();
                if (NULLPTR != configuration && !configuration->client.peer_gateway_forward) {
                    bool destination_matches = false;
                    if (version == ppp::net::native::ip_hdr::IP_VER) {
                        int ip_length = packet_length;
                        ppp::net::native::ip_hdr* ip = ppp::net::native::ip_hdr::Parse(packet, ip_length);
                        destination_matches = NULLPTR != ip && ip->dest == tap->IPAddress;
                    }
                    elif(version == ppp::ipv6::IPv6_VERSION) {
                        boost::asio::ip::address_v6 source;
                        boost::asio::ip::address_v6 destination;
                        destination_matches = has_assigned_ipv6 &&
                            ppp::ipv6::TryParsePacket(packet, packet_length, source, destination) &&
                            app::protocol::VirtualEthernetIPv6PathMtuAddress::Create(destination) == assigned_ipv6;
                    }

                    if (!destination_matches) {
                        ppp::telemetry::Log(Level::kInfo, "client_exchanger", "peer gateway forward rejected");
                        ppp::telemetry::Count("client.peer_gateway_forward.rejected", 1);
                        return false;
                    }
                }

                app::protocol::IcmpPathMtuError error;
                if (app::protocol::TryParseIcmpPathMtuError(packet, packet_length, error) &&
                    error.IsPathMtuUpdate && error.OuterDestination == tap->IPAddress &&
                    error.QuotedSource == tap->IPAddress) {
                    if (app::protocol::GetVirtualEthernetPathMtuCache().Observe(
                            error.QuotedDestination, error.NextHopMtu, Executors::GetTickCount())) {
                        ppp::telemetry::Count("pmtu.cache_update", 1);
                    }
                }

                app::protocol::IcmpIPv6PathMtuError ipv6_error;
                if (has_assigned_ipv6 && app::protocol::TryParseIcmpIPv6PathMtuError(packet, packet_length, ipv6_error) &&
                    ipv6_error.OuterDestination == assigned_ipv6 && ipv6_error.QuotedSource == assigned_ipv6) {
                    if (app::protocol::GetVirtualEthernetIPv6PathMtuCache().Observe(
                            ipv6_error.QuotedDestination, ipv6_error.NextHopMtu, Executors::GetTickCount())) {
                        ppp::telemetry::Count("pmtu.ipv6_cache_update", 1);
                    }
                }

                const bool output = switcher_->Output(packet, packet_length);
                if (output) {
                    ppp::diagnostics::datapath_perf::RecordNatToTun(packet_length);
                }
                return output;
            }

            /** @brief Handles mux negotiation callback and starts vmux linking. */
            bool VEthernetExchanger::OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, Byte ordering_caps, YieldContext& y) noexcept {
                std::shared_ptr<vmux::vmux_net> mux = mux_coordinator_->Session();
                if (NULLPTR != mux) {
                    bool successed = false;
                    if (vlan != 0 && max_connections > 0 && mux->Vlan == vlan && max_connections == mux->get_max_connections() && !mux->is_disposed()) {
                        bool established = mux->is_established();
                        successed = true;

                        if (!established) {
                            auto configuration = GetConfiguration();
                            auto allocator = configuration->GetBufferAllocator();

                            // Apply the negotiated receiver ordering mode (flow v2) before linking.
                            // The server echoes the agreed capability in its MUX reply; agreed
                            // FLOW_V2 requires this end to also need it — i.e. an active scheduler
                            // configuration that uses per-flow ordering. Fail-safe: any mismatch
                            // or older peer falls back to
                            // compat global ordering.
                            // Capability is always true on this build; usage depends on mode+turbo.
                            const bool agreed_flow_v2 =
                                (ordering_caps & vmux::vmux_net::ordering_caps_flow_v2) != 0;
                            const bool agreed_reliability =
                                (ordering_caps & vmux::vmux_net::ordering_caps_reliability) != 0;
                            const bool agreed_fec =
                                (ordering_caps & vmux::vmux_net::ordering_caps_fec) != 0;
                            mux->apply_agreed_ordering(agreed_flow_v2, agreed_reliability, agreed_fec);

                            successed = MuxConnectAllLinklayers(allocator, mux);
                        }
                    }

                    if (!successed) {
                        mux->close_exec();
                    }
                }

                return true;
            }

            /** @brief Adapts base information payload to extended envelope handler. */
            void VEthernetExchanger::ResetP2PCandidateTransport() noexcept {
                std::shared_ptr<ppp::p2p::IP2PDatagramTransport> transport;
                {
                    std::lock_guard<std::mutex> scope(p2p_offer_mutex_);
                    transport = std::move(p2p_candidate_transport_);
                    p2p_registered_candidates_.clear();
                    p2p_registered_transmission_.reset();
                    p2p_local_candidate_ = {};
                    p2p_peer_candidate_ = {};
                    p2p_direct_data_path_.Reset(
                        p2p_offer_generation_.load(std::memory_order_acquire));
                    p2p_transport_registration_id_ = 0;
                    p2p_registered_virtual_ip_ = 0;
                    p2p_peer_virtual_ip_ = 0;
                }
                if (transport) {
                    transport->Close();
                }
            }

            void VEthernetExchanger::StartP2PStunGatherAsync(
                const ITransmissionPtr& transmission,
                uint64_t generation,
                uint64_t transport_registration,
                uint32_t local_virtual_ip,
                ppp::vector<ppp::string> stun_servers) noexcept {
                if (!transmission || stun_servers.empty() || local_virtual_ip == 0) {
                    return;
                }
                auto self = shared_from_this();
                std::thread([self, this, transmission, generation,
                             transport_registration, local_virtual_ip,
                             stun_servers = std::move(stun_servers)]() mutable noexcept {
                    ppp::SetThreadName("p2p-stun");
                    boost::asio::io_context io;
                    boost::asio::ip::udp::endpoint mapped;
                    bool ok = false;
                    for (const auto& stun_server : stun_servers) {
                        if (disposed_.load(std::memory_order_acquire) ||
                            generation != p2p_offer_generation_.load(std::memory_order_acquire)) {
                            return;
                        }
                        const auto server_ep = Ipep::ParseEndPoint(stun_server);
                        if (server_ep.address().is_unspecified() || server_ep.port() == 0) {
                            continue;
                        }
                        const auto stun = ppp::p2p::P2PStunClient::Query(
                            io, server_ep, 300);
                        if (!stun.success) {
                            continue;
                        }
                        mapped = stun.mapped_endpoint;
                        ok = true;
                        break; // ponytail: one mapped candidate is enough
                    }
                    if (!ok) {
                        ppp::telemetry::Count("p2p.stun.async.fail", 1);
                        return;
                    }

                    auto context = transmission->GetContext();
                    auto strand = transmission->GetStrand();
                    if (!context || !strand) {
                        return;
                    }
                    Executors::Post(context, strand,
                        [self, this, transmission, generation,
                         transport_registration, local_virtual_ip, mapped]() noexcept {
                            ApplyP2PStunMappedCandidate(
                                transmission, generation, transport_registration,
                                local_virtual_ip, mapped);
                        });
                }).detach();
            }

            void VEthernetExchanger::ApplyP2PStunMappedCandidate(
                const ITransmissionPtr& transmission,
                uint64_t generation,
                uint64_t transport_registration,
                uint32_t local_virtual_ip,
                const boost::asio::ip::udp::endpoint& mapped) noexcept {
                if (!transmission || disposed_.load(std::memory_order_acquire) ||
                    generation != p2p_offer_generation_.load(std::memory_order_acquire)) {
                    return;
                }

                ppp::app::protocol::P2PEndpointCandidate stun_candidate;
                const std::string stun_endpoint =
                    ppp::app::P2PEndpointToString(mapped);
                stun_candidate.endpoint.assign(
                    stun_endpoint.data(), stun_endpoint.size());
                stun_candidate.source = "stun";
                if (stun_candidate.endpoint.empty()) {
                    return;
                }

                ppp::vector<ppp::app::protocol::P2PEndpointCandidate> candidates;
                ppp::string mode = "direct-preferred";
                {
                    std::lock_guard<std::mutex> scope(p2p_offer_mutex_);
                    if (disposed_.load(std::memory_order_acquire) ||
                        generation != p2p_offer_generation_.load(std::memory_order_acquire) ||
                        p2p_registered_transmission_.lock() != transmission ||
                        p2p_transport_registration_id_ != transport_registration ||
                        p2p_registered_virtual_ip_ != local_virtual_ip) {
                        return;
                    }
                    candidates = p2p_registered_candidates_;
                    bool already = false;
                    for (const auto& item : candidates) {
                        if (item.source == "stun" &&
                            item.endpoint == stun_candidate.endpoint) {
                            already = true;
                            break;
                        }
                    }
                    if (!already) {
                        candidates.emplace_back(stun_candidate);
                        p2p_registered_candidates_ = candidates;
                    }
                    auto configuration = GetConfiguration();
                    if (configuration) {
                        mode = configuration->p2p.mode;
                    }
                }

                InformationEnvelope envelope;
                envelope.Base.Clear();
                envelope.Extensions.P2P.enabled = true;
                envelope.Extensions.P2P.mode = mode;
                envelope.Extensions.P2P.action = "register";
                envelope.Extensions.P2P.virtual_ip = local_virtual_ip;
                envelope.Extensions.P2P.candidates = std::move(candidates);
                envelope.ExtendedJson = envelope.Extensions.ToJson();
                if (DoInformation(transmission, envelope, nullof<YieldContext>())) {
                    ppp::telemetry::Count("p2p.stun.mapped", 1);
                    ppp::telemetry::Count("p2p.stun.async.ok", 1);
                }
                else {
                    ppp::telemetry::Count("p2p.stun.reregister.fail", 1);
                }
            }

            void VEthernetExchanger::HandleP2PDatagram(
                const ITransmissionPtr& transmission,
                uint64_t generation,
                uint64_t transport_registration,
                ppp::p2p::P2PDatagramReceiveStatus status,
                const boost::asio::ip::udp::endpoint& sender,
                const std::uint8_t* packet,
                int packet_size) noexcept {
                if (!transmission) {
                    return;
                }
                auto context = transmission->GetContext();
                auto strand = transmission->GetStrand();
                if (!context || !strand) {
                    return;
                }
                if (status == ppp::p2p::P2PDatagramReceiveStatus::Error) {
                    auto self = shared_from_this();
                    Executors::Post(context, strand,
                        [self, this, transmission, generation,
                         transport_registration]() noexcept {
                            std::shared_ptr<ppp::p2p::IP2PDatagramTransport> transport;
                            {
                                std::lock_guard<std::mutex> scope(p2p_offer_mutex_);
                                if (disposed_.load(std::memory_order_acquire) ||
                                    generation != p2p_offer_generation_.load(std::memory_order_acquire) ||
                                    p2p_registered_transmission_.lock() != transmission ||
                                    !p2p_candidate_transport_ ||
                                    p2p_transport_registration_id_ != transport_registration) {
                                    return;
                                }
                                transport = std::move(p2p_candidate_transport_);
                                p2p_registered_candidates_.clear();
                                p2p_registered_transmission_.reset();
                                p2p_local_candidate_ = {};
                                p2p_peer_candidate_ = {};
                                p2p_transport_registration_id_ = 0;
                                p2p_registered_virtual_ip_ = 0;
                                p2p_peer_virtual_ip_ = 0;
                            }
                            p2p_offer_session_.ResetGeneration(generation);
                            p2p_direct_data_path_.Fallback(
                                ppp::p2p::P2PFallbackReason::SocketError, true, generation);
                            {
                                std::lock_guard<std::mutex> state_scope(runtime_state_mutex_);
                                if (!disposed_.load(std::memory_order_acquire) &&
                                    generation == p2p_offer_generation_.load(std::memory_order_acquire)) {
                                    p2p_state_.store(ppp::p2p::P2PState::Relay, std::memory_order_relaxed);
                                }
                            }
                            transport->Close();
                            ppp::telemetry::Count("p2p.control.transport.error", 1);
                        });
                    return;
                }
                if (status != ppp::p2p::P2PDatagramReceiveStatus::Packet ||
                    !packet || packet_size < 2) {
                    return;
                }
                const bool control_datagram = packet[0] == 1 &&
                    packet[1] >= static_cast<std::uint8_t>(ppp::p2p::P2PControlType::Probe) &&
                    packet[1] <= static_cast<std::uint8_t>(ppp::p2p::P2PControlType::MigrateAck) &&
                    (packet_size == static_cast<int>(ppp::p2p::P2PControlPacket::WireSize) ||
                     packet_size == static_cast<int>(ppp::p2p::P2PControlPacket::ProbeAckWireSize));
                const bool data_datagram = packet[0] == 1 && packet[1] == 5 &&
                    packet_size >= static_cast<int>(
                        ppp::p2p::P2PDataPacketHeader::HeaderSize +
                        ppp::p2p::P2PDataPacketHeader::TagSize + 1) &&
                    packet_size <= static_cast<int>(
                        ppp::p2p::P2PDataPacketHeader::HeaderSize +
                        ppp::p2p::P2PDataPacketHeader::TagSize +
                        ppp::p2p::P2PDataPacketHeader::MaxPayloadSize);
                if (!control_datagram && !data_datagram) {
                    return;
                }

                std::vector<std::uint8_t> datagram;
                try {
                    datagram.assign(packet, packet + packet_size);
                }
                catch (...) {
                    return;
                }

                auto self = shared_from_this();
                Executors::Post(context, strand,
                    [self, this, transmission, generation,
                     transport_registration, sender,
                     datagram = std::move(datagram)]() noexcept {
                        if (disposed_.load(std::memory_order_acquire) ||
                            generation != p2p_offer_generation_.load(std::memory_order_acquire)) {
                            return;
                        }

                        std::shared_ptr<ppp::p2p::IP2PDatagramTransport> transport;
                        boost::asio::ip::udp::endpoint local_candidate;
                        {
                            std::lock_guard<std::mutex> scope(p2p_offer_mutex_);
                            if (p2p_registered_transmission_.lock() != transmission ||
                                !p2p_candidate_transport_ ||
                                p2p_transport_registration_id_ != transport_registration) {
                                return;
                            }
                            transport = p2p_candidate_transport_;
                            local_candidate = p2p_local_candidate_;
                        }

                        if (datagram[1] == 5) {
                            std::vector<std::uint8_t> plaintext;
                            bool from_new_endpoint = false;
                            {
                                std::lock_guard<std::mutex> scope(p2p_offer_mutex_);
                                if (disposed_.load(std::memory_order_acquire) ||
                                    generation != p2p_offer_generation_.load(std::memory_order_acquire) ||
                                    p2p_registered_transmission_.lock() != transmission ||
                                    p2p_candidate_transport_ != transport ||
                                    p2p_transport_registration_id_ != transport_registration) {
                                    return;
                                }
                                from_new_endpoint = !p2p_peer_candidate_.address().is_unspecified() &&
                                    sender != p2p_peer_candidate_ &&
                                    (p2p_direct_data_path_.State() == ppp::p2p::P2PState::Direct ||
                                     p2p_direct_data_path_.State() == ppp::p2p::P2PState::Suspect);
                                if (from_new_endpoint) {
                                    ppp::p2p::P2PCandidateEndpoint source;
                                    ppp::p2p::P2PCandidateEndpoint destination;
                                    std::vector<std::uint8_t> challenge;
                                    if (p2p_migrate_started_ms_ == 0 &&
                                        P2PControlCandidateFromEndpoint(
                                            local_candidate, source) &&
                                        P2PControlCandidateFromEndpoint(
                                            sender, destination) &&
                                        ppp::p2p::CreateAuthenticatedMigrateChallengeDatagram(
                                            p2p_offer_session_, source, destination,
                                            Executors::GetTickCount(), generation, challenge) &&
                                        transport->SendTo(
                                            challenge.data(),
                                            static_cast<int>(challenge.size()), sender)) {
                                        p2p_migrate_started_ms_ = Executors::GetTickCount();
                                        p2p_direct_data_path_.MarkSuspect(generation);
                                        p2p_suspect_since_ms_ = p2p_migrate_started_ms_;
                                        p2p_state_.store(
                                            ppp::p2p::P2PState::Suspect,
                                            std::memory_order_relaxed);
                                        ppp::telemetry::Count("p2p.migrate.challenge", 1);
                                    }
                                    return;
                                }
                                if (sender != p2p_peer_candidate_ ||
                                    !p2p_direct_data_path_.Open(
                                        p2p_offer_session_, datagram,
                                        Executors::GetTickCount(), generation, plaintext)) {
                                    return;
                                }
                                p2p_heartbeat_misses_ = 0;
                                p2p_last_heartbeat_tx_ms_ = 0;
                            }
                            if (disposed_.load(std::memory_order_acquire) ||
                                generation != p2p_offer_generation_.load(std::memory_order_acquire)) {
                                return;
                            }
                            if (plaintext.size() == 1 && plaintext[0] == 0) {
                                ppp::telemetry::Count("p2p.heartbeat.rx", 1);
                                return;
                            }
                            if (!ppp::p2p::P2PDirectDataPath::AllowsInboundPacket(
                                    plaintext.data(), static_cast<int>(plaintext.size()),
                                    p2p_registered_virtual_ip_, p2p_peer_virtual_ip_)) {
                                return;
                            }
                            if (!plaintext.empty() && OnNat(transmission,
                                    plaintext.data(), static_cast<int>(plaintext.size()),
                                    nullof<YieldContext>())) {
                                ppp::telemetry::Count("p2p.data.receive", 1);
                            }
                            return;
                        }

                        ppp::p2p::P2PCandidateEndpoint observed_source;
                        ppp::p2p::P2PCandidateEndpoint observed_destination;
                        if (!P2PControlCandidateFromEndpoint(sender, observed_source) ||
                            !P2PControlCandidateFromEndpoint(
                                local_candidate, observed_destination)) {
                            return;
                        }

                        ppp::p2p::P2PControlDatagramResult result;
                        if (!ppp::p2p::HandleAuthenticatedControlDatagram(
                                p2p_offer_session_, datagram,
                                observed_source, observed_destination,
                                Executors::GetTickCount(), generation, result)) {
                            return;
                        }
                        if (result.action == ppp::p2p::P2PControlDatagramAction::Reply) {
                            bool sent = false;
                            {
                                std::lock_guard<std::mutex> scope(p2p_offer_mutex_);
                                if (!disposed_.load(std::memory_order_acquire) &&
                                    generation == p2p_offer_generation_.load(std::memory_order_acquire) &&
                                    p2p_registered_transmission_.lock() == transmission &&
                                    p2p_candidate_transport_ == transport &&
                                    p2p_transport_registration_id_ == transport_registration &&
                                    !result.reply.empty()) {
                                    sent = transport->SendTo(
                                        result.reply.data(),
                                        static_cast<int>(result.reply.size()), sender);
                                }
                            }
                            if (!sent) {
                                ppp::telemetry::Count("p2p.control.reply.fail", 1);
                            }
                            return;
                        }
                        if (result.action ==
                                ppp::p2p::P2PControlDatagramAction::AuthenticatedAck &&
                            result.authenticated_ack) {
                            bool activated = false;
                            {
                                std::lock_guard<std::mutex> scope(p2p_offer_mutex_);
                                if (!disposed_.load(std::memory_order_acquire) &&
                                    generation == p2p_offer_generation_.load(std::memory_order_acquire) &&
                                    p2p_registered_transmission_.lock() == transmission &&
                                    p2p_candidate_transport_ == transport &&
                                    p2p_transport_registration_id_ == transport_registration &&
                                    sender == p2p_peer_candidate_ &&
                                    p2p_direct_data_path_.StageAuthenticatedAck(
                                        std::move(*result.authenticated_ack), generation)) {
                                    ppp::telemetry::Count("p2p.control.ack.authenticated", 1);
                                    activated = p2p_direct_data_path_.Activate(transport->IsReady(), generation);
                                    if (activated) {
                                        p2p_heartbeat_misses_ = 0;
                                        p2p_last_heartbeat_tx_ms_ = 0;
                                        p2p_suspect_since_ms_ = 0;
                                        p2p_migrate_started_ms_ = 0;
                                        ppp::p2p::P2PSessionCache cache;
                                        cache.session_id = GetId();
                                        cache.peer_endpoint = p2p_peer_candidate_;
                                        cache.cipher = ppp::p2p::P2PCipher::ChaCha20Poly1305;
                                        cache.valid = true;
                                        p2p_zero_rtt_cache_.Store(
                                            p2p_registered_virtual_ip_, cache);
                                        std::lock_guard<std::mutex> state_scope(runtime_state_mutex_);
                                        if (!disposed_.load(std::memory_order_acquire) &&
                                            generation == p2p_offer_generation_.load(std::memory_order_acquire)) {
                                            p2p_state_.store(
                                                ppp::p2p::P2PState::Direct,
                                                std::memory_order_relaxed);
                                        }
                                    }
                                }
                            }
                            if (activated) {
                                ppp::telemetry::Count("p2p.data.direct", 1);
                            }
                            return;
                        }
                        if (result.action ==
                                ppp::p2p::P2PControlDatagramAction::AuthenticatedMigrateAck &&
                            result.authenticated_ack) {
                            bool recovered = false;
                            {
                                std::lock_guard<std::mutex> scope(p2p_offer_mutex_);
                                if (!disposed_.load(std::memory_order_acquire) &&
                                    generation == p2p_offer_generation_.load(std::memory_order_acquire) &&
                                    p2p_registered_transmission_.lock() == transmission &&
                                    p2p_candidate_transport_ == transport &&
                                    p2p_transport_registration_id_ == transport_registration &&
                                    p2p_direct_data_path_.AcceptRecoveryAck(
                                        std::move(*result.authenticated_ack), generation)) {
                                    p2p_peer_candidate_ = sender;
                                    p2p_heartbeat_misses_ = 0;
                                    p2p_last_heartbeat_tx_ms_ = 0;
                                    p2p_suspect_since_ms_ = 0;
                                    p2p_migrate_started_ms_ = 0;
                                    ppp::p2p::P2PSessionCache cache;
                                    cache.session_id = GetId();
                                    cache.peer_endpoint = p2p_peer_candidate_;
                                    cache.cipher = ppp::p2p::P2PCipher::ChaCha20Poly1305;
                                    cache.valid = true;
                                    p2p_zero_rtt_cache_.Store(
                                        p2p_registered_virtual_ip_, cache);
                                    recovered = true;
                                    std::lock_guard<std::mutex> state_scope(runtime_state_mutex_);
                                    if (!disposed_.load(std::memory_order_acquire) &&
                                        generation == p2p_offer_generation_.load(std::memory_order_acquire)) {
                                        p2p_state_.store(
                                            ppp::p2p::P2PState::Direct,
                                            std::memory_order_relaxed);
                                    }
                                }
                            }
                            if (recovered) {
                                ppp::telemetry::Count("p2p.migrate.recovered", 1);
                            }
                        }
                    });
            }

            void VEthernetExchanger::HandleP2PRelayOffer(
                const ITransmissionPtr& transmission,
                const ppp::app::protocol::P2PControlMessage& message) noexcept {
                if (!transmission || !message.enabled || message.action != "offer-v1" ||
                    message.authenticated_offer_v1.empty()) {
                    return;
                }

                auto context = transmission->GetContext();
                auto strand = transmission->GetStrand();
                if (!context || !strand) {
                    return;
                }

                const uint64_t generation = p2p_offer_generation_.load(std::memory_order_acquire);
                auto self = shared_from_this();
                Executors::Post(context, strand,
                    [self, this, transmission, message, generation]() noexcept {
                        if (disposed_.load(std::memory_order_acquire) ||
                            generation != p2p_offer_generation_.load(std::memory_order_acquire)) {
                            return;
                        }

                        ppp::vector<ppp::app::protocol::P2PEndpointCandidate> local_candidates;
                        uint32_t local_virtual_ip = 0;
                        {
                            std::lock_guard<std::mutex> scope(p2p_offer_mutex_);
                            if (p2p_registered_transmission_.lock() != transmission) {
                                return;
                            }
                            local_candidates = p2p_registered_candidates_;
                            local_virtual_ip = p2p_registered_virtual_ip_;
                        }
                        if (local_virtual_ip == 0 || message.virtual_ip != local_virtual_ip ||
                            message.peer_virtual_ip == 0) {
                            return;
                        }

                        std::vector<ppp::p2p::P2PCandidateV1> candidates;
                        boost::asio::ip::udp::endpoint peer_candidate;
                        try {
                            candidates.reserve(local_candidates.size() + message.candidates.size());
                            const auto append = [&candidates](const auto& values) noexcept {
                                try {
                                    for (const auto& value : values) {
                                        const auto endpoint = Ipep::ParseEndPoint(value.endpoint);
                                        ppp::p2p::P2PCandidateV1 candidate;
                                        if (!ppp::app::P2PCandidateFromEndpoint(endpoint, candidate)) {
                                            return false;
                                        }
                                        candidates.emplace_back(candidate);
                                    }
                                    return true;
                                }
                                catch (...) {
                                    return false;
                                }
                            };
                            if (!append(local_candidates) || !append(message.candidates) || candidates.empty()) {
                                return;
                            }
                            if (!message.candidates.empty()) {
                                peer_candidate = Ipep::ParseEndPoint(
                                    message.candidates.front().endpoint);
                            }
                        }
                        catch (...) {
                            return;
                        }

                        ppp::p2p::P2PRelayOfferRecipientContext recipient;
                        ppp::p2p::Int128ToBytes(GetId(), recipient.local_session_id.data());
                        std::memcpy(recipient.local_peer_id.data() + 12,
                            &local_virtual_ip, sizeof(local_virtual_ip));
                        if (!ppp::p2p::HashP2PCandidateSet(candidates, recipient.candidate_set_hash)) {
                            return;
                        }

                        const auto exporter = [transmission](const char* label,
                            const std::uint8_t* exporter_context, std::size_t context_length,
                            std::uint8_t* output, std::size_t output_length) noexcept {
                            return transmission->ExportAuthenticatedSessionKey(
                                label, exporter_context, context_length, output, output_length);
                        };
                        std::string encoded;
                        try {
                            encoded.assign(message.authenticated_offer_v1.data(),
                                message.authenticated_offer_v1.size());
                        }
                        catch (...) {
                            return;
                        }
                        const uint64_t now = Executors::GetTickCount();
                        if (!p2p_offer_session_.Accept(
                                encoded, recipient, exporter, now, generation)) {
                            return;
                        }
                        if (disposed_.load(std::memory_order_acquire) ||
                            generation != p2p_offer_generation_.load(std::memory_order_acquire)) {
                            p2p_offer_session_.ResetGeneration(generation);
                            return;
                        }

                        {
                            std::lock_guard<std::mutex> offer_scope(p2p_offer_mutex_);
                            if (disposed_.load(std::memory_order_acquire) ||
                                generation != p2p_offer_generation_.load(std::memory_order_acquire) ||
                                !p2p_offer_session_.IsActiveGeneration(generation)) {
                                p2p_offer_session_.ResetGeneration(generation);
                                return;
                            }
                            p2p_peer_candidate_ = {};
                            p2p_peer_virtual_ip_ = 0;
                            p2p_direct_data_path_.Reset(generation);
                            bool stale = false;
                            {
                                std::lock_guard<std::mutex> state_scope(runtime_state_mutex_);
                                stale = disposed_.load(std::memory_order_acquire) ||
                                    generation != p2p_offer_generation_.load(std::memory_order_acquire);
                                if (!stale) {
                                    p2p_state_.store(ppp::p2p::P2PState::Eligible, std::memory_order_relaxed);
                                }
                            }
                            if (stale) {
                                p2p_offer_session_.ResetGeneration(generation);
                                return;
                            }
                        }
                        ppp::telemetry::Count("p2p.offer_v1.accepted", 1);

                        std::shared_ptr<ppp::p2p::IP2PDatagramTransport> candidate_transport;
                        boost::asio::ip::udp::endpoint local_candidate;
                        {
                            std::lock_guard<std::mutex> scope(p2p_offer_mutex_);
                            if (p2p_registered_transmission_.lock() != transmission) {
                                return;
                            }
                            candidate_transport = p2p_candidate_transport_;
                            local_candidate = p2p_local_candidate_;
                        }
                        ppp::p2p::P2PCandidateEndpoint source;
                        ppp::p2p::P2PCandidateEndpoint destination;
                        std::vector<std::uint8_t> probe;
                        const bool sent = candidate_transport &&
                            P2PControlCandidateFromEndpoint(local_candidate, source) &&
                            P2PControlCandidateFromEndpoint(peer_candidate, destination) &&
                            ppp::p2p::CreateAuthenticatedProbeDatagram(
                                p2p_offer_session_, source, destination,
                                Executors::GetTickCount(), generation, probe) &&
                            candidate_transport->SendTo(
                                probe.data(), static_cast<int>(probe.size()), peer_candidate);
                        bool began = false;
                        if (sent) {
                            std::lock_guard<std::mutex> scope(p2p_offer_mutex_);
                            if (!disposed_.load(std::memory_order_acquire) &&
                                generation == p2p_offer_generation_.load(std::memory_order_acquire) &&
                                p2p_registered_transmission_.lock() == transmission &&
                                p2p_candidate_transport_ == candidate_transport) {
                                p2p_peer_candidate_ = peer_candidate;
                                p2p_peer_virtual_ip_ = message.peer_virtual_ip;
                                began = p2p_direct_data_path_.Begin(generation);
                            }
                        }
                        if (!began) {
                            p2p_offer_session_.ResetGeneration(generation);
                            {
                                std::lock_guard<std::mutex> scope(p2p_offer_mutex_);
                                if (generation ==
                                        p2p_offer_generation_.load(std::memory_order_acquire)) {
                                    p2p_peer_candidate_ = {};
                                    p2p_peer_virtual_ip_ = 0;
                                    p2p_direct_data_path_.Reset(generation);
                                }
                            }
                            {
                                std::lock_guard<std::mutex> state_scope(runtime_state_mutex_);
                                if (!disposed_.load(std::memory_order_acquire) &&
                                    generation == p2p_offer_generation_.load(std::memory_order_acquire)) {
                                    p2p_state_.store(ppp::p2p::P2PState::Relay, std::memory_order_relaxed);
                                }
                            }
                            ppp::telemetry::Count("p2p.control.probe.fail", 1);
                            return;
                        }
                        {
                            std::lock_guard<std::mutex> state_scope(runtime_state_mutex_);
                            if (!disposed_.load(std::memory_order_acquire) &&
                                generation == p2p_offer_generation_.load(std::memory_order_acquire)) {
                                p2p_state_.store(ppp::p2p::P2PState::Probing, std::memory_order_relaxed);
                            }
                        }
                        ppp::telemetry::Count("p2p.control.probe.sent", 1);
                    });
            }

            bool VEthernetExchanger::OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept {
                InformationEnvelope envelope;
                envelope.Base = information;
                return OnInformation(transmission, envelope, y);
            }

            /** @brief Updates cached information and notifies network switcher. */
            bool VEthernetExchanger::OnInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept {
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                if (NULLPTR == context) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                }

                auto ei = make_shared_object<VirtualEthernetInformation>(information.Base);
                if (NULLPTR == ei) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                }

                if (information.Extensions.P2P.HasAny()) {
                    HandleP2PRelayOffer(transmission, information.Extensions.P2P);
                }

                auto self = shared_from_this();
                boost::asio::post(*context,
                    [self, this, context, ei, information]() noexcept {
                        information_ = ei;
                        if (!disposed_.load(std::memory_order_acquire)) {
                            switcher_->OnInformation(ei, information.Extensions);
                        }
                    });
                return true;
            }

            /** @brief Rejects unsolicited push events for security hardening. */
            bool VEthernetExchanger::OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid); // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            /** @brief Rejects unsolicited connect events for security hardening. */
            bool VEthernetExchanger::OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid); // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            /** @brief Rejects unsolicited connect-ack events for security hardening. */
            bool VEthernetExchanger::OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid); // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            /** @brief Rejects unsolicited disconnect events for security hardening. */
            bool VEthernetExchanger::OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid); // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            /** @brief Rejects unsupported static callback variant. */
            bool VEthernetExchanger::OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid); // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            /** @brief Applies static session parameters received from server. */
            bool VEthernetExchanger::OnStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept {
                if (remote_port < IPEndPoint::MinPort || remote_port > IPEndPoint::MaxPort) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                }

                if (session_id < 0) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionIdInvalid);
                }

                // If the server does not support static tunneling, clean up the pre-prepared resources.
                if (remote_port == IPEndPoint::MinPort || session_id == 0) {
                    static_echo_.StaticEchoClean();
                }
                else {
                    AppConfigurationPtr configuration = GetConfiguration();
                    static_echo_.ConfigureSession(configuration, GetId(), fsid, session_id, remote_port);
                }

                StaticEchoGatewayServer(STATIC_ECHO_KEEP_ALIVED_ID);
                return true;
            }

            /** @brief Handles ACK echo callback from server. */
            bool VEthernetExchanger::OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept {
                if (ack_id != 0) {
                    switcher_->ERORTE(ack_id);
                }

                return true;
            }

            /** @brief Handles packet echo callback from server. */
            bool VEthernetExchanger::OnEcho(const ITransmissionPtr& transmission, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept {
                switcher_->Output(packet, packet_length);
                return true;
            }

            /** @brief Handles UDP callback packet delivered by remote exchanger. */
            bool VEthernetExchanger::OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept {
                return datagram_manager_->OnSendTo(transmission, sourceEP, destinationEP, packet, packet_length, y);
            }

            /** @brief Routes inbound UDP payload to matching datagram port or switcher. */
            bool VEthernetExchanger::ReceiveFromDestination(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length) noexcept {
                return datagram_manager_->ReceiveFromDestination(sourceEP, destinationEP, packet, packet_length);
            }

            /** @brief Sends UDP packet using source-bound datagram relay port. */
            bool VEthernetExchanger::SendTo(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const void* packet, int packet_size) noexcept {
                return SendTo(sourceEP, destinationEP, packet, packet_size, routing::RoutingAction::Auto);
            }

            bool VEthernetExchanger::SendTo(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const void* packet, int packet_size, routing::RoutingAction action) noexcept {
                if (NULLPTR == packet || packet_size < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                }

                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                return datagram_manager_->SendTo(sourceEP, destinationEP, packet, packet_size, action);
            }

            bool VEthernetExchanger::SendDnsDatagram(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const void* packet, int packet_size) noexcept {
                return SendTo(sourceEP, destinationEP, packet, packet_size);
            }

            /** @brief Registers a local datagram reply handler for a specific source endpoint. */
            bool VEthernetExchanger::RegisterDatagramHandler(const boost::asio::ip::udp::endpoint& sourceEP, const DatagramPacketHandler& handler) noexcept {
                if (!handler) {
                    return false;
                }

                return datagram_manager_->RegisterDatagramHandler(sourceEP, handler);
            }

            /** @brief Removes a local datagram reply handler. */
            bool VEthernetExchanger::ReleaseDatagramHandler(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                return datagram_manager_->ReleaseDatagramHandler(sourceEP);
            }

            /** @brief Dispatches a datagram reply to a registered local handler before TAP injection. */
            bool VEthernetExchanger::TryHandleDatagram(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_size) noexcept {
                return datagram_manager_->TryHandleDatagram(sourceEP, destinationEP, packet, packet_size);
            }

            /** @brief Sends ACK-based keepalive/echo packet through active transport. */
            bool VEthernetExchanger::Echo(int ack_id) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                bool ok = DoEcho(transmission, ack_id, nullof<YieldContext>());
                if (!ok) {
                    transmission->Dispose();
                }

                return ok;
            }

            /** @brief Sends packet-based echo payload through active transport. */
            bool VEthernetExchanger::Echo(const void* packet, int packet_size) noexcept {
                if (NULLPTR == packet || packet_size < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                }

                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                bool ok = DoEcho(transmission, (Byte*)packet, packet_size, nullof<YieldContext>());
                if (!ok) {
                    transmission->Dispose();
                }

                return ok;
            }

            /** @brief Sends NAT payload packet through active transport. */
            bool VEthernetExchanger::Nat(const void* packet, int packet_size) noexcept {
                if (NULLPTR == packet || packet_size < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                }

                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                std::shared_ptr<ppp::p2p::IP2PDatagramTransport> failed_p2p_transport;
                const uint64_t generation =
                    p2p_offer_generation_.load(std::memory_order_acquire);
                bool direct_send_failed = false;
                {
                    std::lock_guard<std::mutex> scope(p2p_offer_mutex_);
                    if (!disposed_.load(std::memory_order_acquire) &&
                        generation == p2p_offer_generation_.load(std::memory_order_acquire) &&
                        p2p_registered_transmission_.lock() == transmission &&
                        p2p_candidate_transport_ &&
                        p2p_direct_data_path_.State() == ppp::p2p::P2PState::Direct &&
                        ppp::p2p::P2PDirectDataPath::AllowsOutboundPacket(
                            packet, packet_size, p2p_registered_virtual_ip_,
                            p2p_peer_virtual_ip_)) {
                        if (packet_size <= static_cast<int>(
                                ppp::p2p::P2PDataPacketHeader::MaxPayloadSize) &&
                            p2p_direct_data_path_.Send(
                                p2p_offer_session_, *p2p_candidate_transport_,
                                p2p_peer_candidate_,
                                static_cast<const std::uint8_t*>(packet),
                                static_cast<std::size_t>(packet_size),
                                Executors::GetTickCount(), generation)) {
                            ppp::telemetry::Count("p2p.data.send", 1);
                            return true;
                        }
                        direct_send_failed = true;
                        p2p_direct_data_path_.Fallback(
                            ppp::p2p::P2PFallbackReason::SocketError,
                            true, generation);
                        p2p_offer_session_.ResetGeneration(generation);
                        failed_p2p_transport = std::move(p2p_candidate_transport_);
                        p2p_registered_candidates_.clear();
                        p2p_registered_transmission_.reset();
                        p2p_local_candidate_ = {};
                        p2p_peer_candidate_ = {};
                        p2p_transport_registration_id_ = 0;
                        p2p_registered_virtual_ip_ = 0;
                        p2p_peer_virtual_ip_ = 0;
                    }
                }
                if (direct_send_failed) {
                    {
                        std::lock_guard<std::mutex> state_scope(runtime_state_mutex_);
                        if (!disposed_.load(std::memory_order_acquire) &&
                            generation == p2p_offer_generation_.load(std::memory_order_acquire)) {
                            p2p_state_.store(
                                ppp::p2p::P2PState::Relay,
                                std::memory_order_relaxed);
                        }
                    }
                    if (failed_p2p_transport) failed_p2p_transport->Close();
                    ppp::telemetry::Count("p2p.data.send.fallback", 1);
                }

                bool ok = DoNat(transmission, (Byte*)packet, packet_size, nullof<YieldContext>());
                if (!ok) {
                    transmission->Dispose();
                }

                return ok;
            }

            /** @brief Announces local LAN information to remote exchanger when needed. */
            int VEthernetExchanger::EchoLanToRemoteExchanger(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError<int>(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                bool vnet = switcher_->IsVNet();
                if (!vnet) {
                    return 0;
                }

                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError<int>(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                std::shared_ptr<ppp::tap::ITap> tap = switcher_->GetTap();
                if (NULLPTR == tap) {
                    return ppp::diagnostics::SetLastError<int>(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }

                bool ok = DoLan(transmission, tap->IPAddress, tap->SubmaskAddress, y);
                if (ok) {
                    return 1;
                }

                transmission->Dispose();
                return ppp::diagnostics::SetLastError<int>(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
            }

            /** @brief Creates and registers datagram relay port for source endpoint. */
            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::AddNewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                return datagram_manager_->AddNewDatagramPort(transmission, sourceEP);
            }

            /** @brief Allocates a new datagram relay port object. */
            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, VEthernetExchanger::VEthernetDatagramPortPtr(NULLPTR));
                }

                auto my = shared_from_this();
                std::shared_ptr<VEthernetExchanger> exchanger
                    = std::dynamic_pointer_cast<VEthernetExchanger>(my);

                return make_shared_object<VEthernetDatagramPort>(exchanger, BuildUdpRelayHostPorts(), transmission, sourceEP);
            }

            /** @brief Returns datagram relay port by source endpoint key. */
            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                return datagram_manager_->GetDatagramPort(sourceEP);
            }

            /** @brief Removes and returns datagram relay port by source endpoint key. */
            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                return datagram_manager_->ReleaseDatagramPort(sourceEP);
            }

            /** @brief Removes source only when it still maps to the self-finalizing port. */
            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::ReleaseDatagramPortIf(
                const boost::asio::ip::udp::endpoint& sourceEP,
                const VEthernetDatagramPort* expected) noexcept {
                return datagram_manager_->ReleaseDatagramPortIf(sourceEP, expected);
            }

            /** @brief Sends scheduled keepalive echo and handles stale-link timeout. */
            bool VEthernetExchanger::SendEchoKeepAlivePacket(UInt64 now, bool immediately) noexcept {
                if (network_state_ != NetworkState_Established) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                bool defer_for_child_links = false;
#if defined(_IPHONE)
                defer_for_child_links = NULLPTR == mux_coordinator_->Session() &&
                    ios_child_transmission_active_.load(std::memory_order_acquire) > 0;
#endif
                const ClientKeepAliveAction action = keepalive_policy_.Evaluate(
                    now,
                    immediately,
                    NULLPTR != transmission,
                    defer_for_child_links,
                    SEND_ECHO_KEEP_ALIVE_PACKET_MMX_TIMEOUT);
                if (action == ClientKeepAliveAction::DeferForChildLinks) {
                    ppp::telemetry::Count("client_exchanger.keepalive.defer_children", 1);
                    return false;
                }
                if (action == ClientKeepAliveAction::CloseTransport) {
                    ppp::telemetry::Count("client_exchanger.keepalive.timeout", 1);
                    ppp::telemetry::Log(Level::kInfo, "client_exchanger",
                        "echo keepalive stale disposing transmission silence_ms=%llu threshold_ms=%d",
                        (unsigned long long)(now - keepalive_policy_.LastPacketAt()),
                        SEND_ECHO_KEEP_ALIVE_PACKET_MMX_TIMEOUT);
                    transmission->Dispose();
#if defined(_IPHONE)
                    ResetIosChildTransmissionSlots("keepalive_stale");
#endif
                    return false;
                }
                if (action != ClientKeepAliveAction::SendEcho) {
                    return false;
                }
                keepalive_policy_.OnEchoSent(
                    now,
                    RandomNext(SEND_ECHO_KEEP_ALIVE_PACKET_MIN_TIMEOUT,
                        SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT));
                return Echo(0);
            }

            /** @brief Processes incoming linklayer packet and refreshes keepalive timer. */
            bool VEthernetExchanger::PacketInput(const ITransmissionPtr& transmission, const std::shared_ptr<Byte>& owner, Byte* p, int packet_length, YieldContext& y) noexcept {
                bool successed = VirtualEthernetLinklayer::PacketInput(transmission, owner, p, packet_length, y);
                if (successed) {
                    if (network_state_ == NetworkState_Established) {
                        keepalive_policy_.OnPacket(Executors::GetTickCount());
                    }
                }

                return successed;
            }

            /** @brief Registers one configured FRP mapping endpoint. */
            bool VEthernetExchanger::RegisterMappingPort(ppp::configurations::MappingConfiguration& mapping) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                boost::system::error_code ec;
                boost::asio::ip::address local_ip = StringToAddress(mapping.local_ip.data(), ec);
                if (ec) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                boost::asio::ip::address remote_ip = StringToAddress(mapping.remote_ip.data(), ec);
                if (ec) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                bool in = remote_ip.is_v4();
                bool protocol_tcp_or_udp = mapping.protocol_tcp_or_udp;

                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, protocol_tcp_or_udp, mapping.remote_port);
                if (NULLPTR != mapping_port) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingEntryConflict);
                }

                mapping_port = NewMappingPort(in, protocol_tcp_or_udp, mapping.remote_port);
                if (NULLPTR == mapping_port) {
                    ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCode();
                    if (ppp::diagnostics::ErrorCode::Success == code) {
                        code = ppp::diagnostics::ErrorCode::MemoryAllocationFailed;
                    }

                    return ppp::diagnostics::SetLastError(code);
                }

                bool ok = mapping_port->OpenFrpClient(local_ip, mapping.local_port);
                if (ok) {
                    ok = frp_registry_->Add(
                        in, protocol_tcp_or_udp, mapping.remote_port, mapping_port);
                }

                if (!ok) {
                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MappingOpenFailed);
                    }
                    mapping_port->Dispose();
                }

                return ok;
            }

            /** @brief Creates one FRP mapping port object bound to this exchanger. */
            VEthernetExchanger::VirtualEthernetMappingPortPtr VEthernetExchanger::NewMappingPort(bool in, bool tcp, int remote_port) noexcept {
                class VIRTUAL_ETHERNET_MAPPING_PORT final : public VirtualEthernetMappingPort {
                public:
                    /** @brief Constructs mapping port implementation bound to exchanger linklayer. */
                    VIRTUAL_ETHERNET_MAPPING_PORT(const std::shared_ptr<VirtualEthernetLinklayer>& linklayer, const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port) noexcept
                        : VirtualEthernetMappingPort(linklayer, transmission, tcp, in, remote_port) {

                    }

                public:
                    /** @brief Defers parent-table removal and then disposes base resources. */
                    virtual void Dispose() noexcept override {
                        // Defer parent-table removal so Dispose() never runs child finalization
                        // while the exchanger lock is held.
                        if (std::shared_ptr<VirtualEthernetLinklayer> linklayer = GetLinklayer(); NULLPTR != linklayer) {
                            if (std::shared_ptr<VEthernetExchanger> exchanger = std::dynamic_pointer_cast<VEthernetExchanger>(linklayer); NULLPTR != exchanger) {
                                auto self = shared_from_this();
                                std::shared_ptr<boost::asio::io_context> context = exchanger->GetContext();
                                auto remove_mapping = [exchanger, self]() noexcept {
                                    exchanger->frp_registry_->Remove(
                                        self->ProtocolIsNetworkV4(),
                                        self->ProtocolIsTcpNetwork(),
                                        self->GetRemotePort());
                                };

                                if (NULLPTR != context) {
                                    boost::asio::post(*context, std::move(remove_mapping));
                                }
                                else {
                                    remove_mapping();
                                }
                            }
                        }

                        VirtualEthernetMappingPort::Dispose();
                    }
                };

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, VEthernetExchanger::VirtualEthernetMappingPortPtr(NULLPTR));
                }

                auto self = shared_from_this();
                return make_shared_object<VIRTUAL_ETHERNET_MAPPING_PORT>(self, transmission, tcp, in, remote_port);
            }

            /** @brief Returns FRP mapping port by direction/protocol/port key. */
            VEthernetExchanger::VirtualEthernetMappingPortPtr VEthernetExchanger::GetMappingPort(bool in, bool tcp, int remote_port) noexcept {
                return frp_registry_->Get(in, tcp, remote_port);
            }

            /** @brief Dispatches FRP UDP payload callback to mapped client port. */
            bool VEthernetExchanger::OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept {
#if defined(_ANDROID)
                auto self = shared_from_this();
                Post(
                    [self, this, owner, packet, packet_length, sourceEP, in, remote_port]() noexcept {
                        VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, false, remote_port);
                        if (NULLPTR != mapping_port) {
                            mapping_port->Client_OnFrpSendTo(packet, packet_length, sourceEP);
                        }
                    });
#else
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, false, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Client_OnFrpSendTo(packet, packet_length, sourceEP);
                }
#endif
                return true;
            }

            /** @brief Dispatches FRP TCP connect callback to mapped client port. */
            bool VEthernetExchanger::OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept {
#if defined(_ANDROID)
                auto self = shared_from_this();
                Post(
                    [self, this, in, remote_port, connection_id]() noexcept {
                        VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                        if (NULLPTR != mapping_port) {
                            mapping_port->Client_OnFrpConnect(connection_id);
                        }
                    });
#else
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Client_OnFrpConnect(connection_id);
                }
#endif
                return true;
            }

            /** @brief Dispatches FRP TCP disconnect callback to mapped client port. */
            bool VEthernetExchanger::OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Client_OnFrpDisconnect(connection_id);
                }

                return true;
            }

            /** @brief Dispatches FRP TCP payload callback to mapped client port. */
            bool VEthernetExchanger::OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const std::shared_ptr<Byte>& owner, const void* packet, int packet_length) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Client_OnFrpPush(connection_id, owner, packet, packet_length);
                }

                return true;
            }

            bool VEthernetExchanger::StaticEchoAllocated() noexcept {
                return static_echo_.StaticEchoAllocated();
            }

            bool VEthernetExchanger::StaticEchoAddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept {
                return static_echo_.StaticEchoAddRemoteEndPoint(remoteEP);
            }

            void VEthernetExchanger::StaticEchoClean() noexcept {
                static_echo_.StaticEchoClean();
            }

            bool VEthernetExchanger::StaticEchoSwapAsynchronousSocket() noexcept {
                return static_echo_.StaticEchoSwapAsynchronousSocket();
            }

            bool VEthernetExchanger::StaticEchoGatewayServer(int ack_id) noexcept {
                return static_echo_.StaticEchoGatewayServer(ack_id);
            }

            bool VEthernetExchanger::StaticEchoPacketToRemoteExchanger(const ppp::net::packet::IPFrame* packet) noexcept {
                return static_echo_.StaticEchoPacketToRemoteExchanger(packet);
            }

            bool VEthernetExchanger::StaticEchoPacketToRemoteExchanger(const std::shared_ptr<ppp::net::packet::UdpFrame>& frame) noexcept {
                return static_echo_.StaticEchoPacketToRemoteExchanger(frame);
            }

            bool VEthernetExchanger::StaticEchoPacketToRemoteExchanger(const std::shared_ptr<Byte>& packet, int packet_length) noexcept {
                return static_echo_.StaticEchoPacketToRemoteExchanger(packet, packet_length);
            }

            bool VEthernetExchanger::Sleep(int64_t timeout, const ContextPtr& context, YieldContext& y) noexcept {
                using atomic_int = std::atomic<int>;

                std::shared_ptr<atomic_int> status = ppp::make_shared_object<atomic_int>(-1);
                if (NULLPTR == status) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                }

                auto self = shared_from_this();
                boost::asio::post(*context,
                    [self, this, context, timeout, status, &y]() noexcept {
                        bool ok = NewDeadlineTimer(context, timeout,
                            [status, &y](bool b) noexcept {
                                ppp::coroutines::asio::R(y, *status, b);
                            });

                        if (!ok) {
                            ppp::coroutines::asio::R(y, *status, false);
                        }
                    });

                y.Suspend();
                return status->load() > 0;
            }

        }
    }
}
