#pragma once

/**
 * @file VEthernetExchanger.h
 * @brief Client-side virtual Ethernet exchanger declarations.
 *
 * @details
 * VEthernetExchanger is the **core client component** responsible for all
 * communication with the remote VPN server. It derives from
 * VirtualEthernetLinklayer and adds:
 *
 *  - Connection lifecycle management (Connecting → Established → Reconnecting)
 *  - Automatic reconnection with configurable back-off
 *  - Outbound NAT packet injection via Nat()
 *  - UDP relay table management through VEthernetDatagramPort instances
 *  - Static-echo UDP channel for reduced-latency data delivery
 *  - FRP (Fast Reverse Proxy) port mapping registration and dispatch
 *  - VMUX multiplexed sub-link management
 *  - Mapping port registration for inbound/outbound port-forwarding rules
 *
 * ### Threading model
 * All state transitions and protocol callbacks are executed on the
 * Boost.Asio `io_context` owned by the parent VEthernetNetworkSwitcher.
 * The internal `syncobj_` mutex guards only the datagram port table and
 * the deadline-timer table. `runtime_state_mutex_` commits the network/P2P
 * projection consumed outside the exchanger strand; remaining mutable state
 * is accessed exclusively from the IO thread.
 *
 * ### Lifecycle
 * 1. Construct with switcher, configuration, context, and session id.
 * 2. Call Open() to start the connect-handshake-reconnect coroutine.
 * 3. The exchanger drives itself through NetworkState transitions.
 * 4. Call Dispose() to schedule asynchronous teardown.
 *
 * Licensed under GPL-3.0.
 */

#include <atomic>
#include <mutex>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/SessionResumeAuthenticator.h>
#include <ppp/app/client/routing/HumanRoutingRules.h>
#include <ppp/configurations/AppConfigurationFwd.h>
#include <ppp/configurations/MappingConfiguration.h>
#include <ppp/app/protocol/VirtualEthernetMappingPort.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/app/mux/MuxRuntimeState.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/diagnostics/LinkTelemetry.h>
#include <ppp/Int128.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/p2p/P2PClientOfferSession.h>
#include <ppp/p2p/P2PDatagramTransport.h>
#include <ppp/p2p/P2PDirectDataPath.h>
#include <ppp/p2p/P2PState.h>
#include <ppp/p2p/P2PZeroRTTCache.h>
#include <ppp/threading/Timer.h>
#include <ppp/auxiliary/UriAuxiliary.h>
#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/app/client/ExchangerStaticEchoChannel.h>
#include <ppp/app/client/ClientKeepAlivePolicy.h>
#include <ppp/app/client/ClientReconnectionPolicy.h>
#include <ppp/app/client/udp/UdpRelayHost.h>
#include <ppp/app/client/dns/IDnsTunnelTransport.h>

namespace ppp::app::mux { class MuxCoordinator; }

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;
            class VEthernetDatagramPort;
            class ClientFrpRegistry;

            inline bool ShouldRunClientTransportAuth(
                ppp::transmissions::AuthenticatedCarrierKind kind,
                bool policy_enabled,
                bool peer_supports_v1,
                bool peer_enables_v1) noexcept {
                return policy_enabled && peer_supports_v1 && peer_enables_v1 &&
                    (kind == ppp::transmissions::AuthenticatedCarrierKind::Tcp ||
                     kind == ppp::transmissions::AuthenticatedCarrierKind::WebSocket);
            }

            inline bool IsClientSessionRecoveryCarrierEligible(
                ppp::transmissions::AuthenticatedCarrierKind kind,
                ppp::transmissions::AuthenticatedCarrierMethod method,
                bool binding_active,
                bool has_exporter) noexcept {
                if (!binding_active || !has_exporter) {
                    return false;
                }
                if (kind == ppp::transmissions::AuthenticatedCarrierKind::TlsWebSocket) {
                    return method == ppp::transmissions::AuthenticatedCarrierMethod::TlsExporterV1;
                }
                if (kind == ppp::transmissions::AuthenticatedCarrierKind::Tcp ||
                    kind == ppp::transmissions::AuthenticatedCarrierKind::WebSocket) {
                    return method == ppp::transmissions::AuthenticatedCarrierMethod::NoisePskV1;
                }
                return false;
            }

            namespace udp {
                class ClientDatagramPortManager;
            }

            /**
             * @brief Core client exchanger that manages the transport session with the remote server.
             *
             * @details
             * VEthernetExchanger extends VirtualEthernetLinklayer and implements the full
             * client-side protocol state machine:
             *
             *  - **Connecting**: Resolving the remote endpoint and establishing a TCP connection.
             *  - **Established**: Active data-plane forwarding; keepalive packets sent periodically.
             *  - **Reconnecting**: Connection lost; back-off delay before next attempt.
             *
             * The exchanger owns:
             *  - One primary ITransmission channel (TCP / WebSocket / WebSocket-SSL / PPP).
             *  - A table of VEthernetDatagramPort objects for UDP relay.
             *  - Optional coordinated VMUX session for multiplexed sub-links.
             *  - A static-echo UDP channel for low-latency bypass.
             *  - FRP port-mapping registrations from AppConfiguration.
             *
             * @note
             * Only one exchanger instance exists per VEthernetNetworkSwitcher. It is
             * created by VEthernetNetworkSwitcher::NewExchanger() and held via shared_ptr.
             *
             * @warning
             * Dispose() must be called from the owning IO thread or via Post().
             * Accessing any mutable member from a different thread without the mutex
             * is undefined behavior.
             */
            class VEthernetExchanger : public ppp::app::protocol::VirtualEthernetLinklayer, public udp::IUdpRelayHost, public dns::IDnsTunnelTransport {
                friend class                                                            VEthernetNetworkSwitcher;
                friend class                                                            ExchangerStaticEchoChannel;
                friend struct                                                           ExchangerStaticEchoDetail;
                friend class                                                            ClientPacketDispatchHandler;

            public:
                /** @brief Shared pointer alias for the parent network switcher. */
                typedef std::shared_ptr<VEthernetNetworkSwitcher>                       VEthernetNetworkSwitcherPtr;
                /** @brief Base information packet alias. */
                typedef ppp::app::protocol::VirtualEthernetInformation                  VirtualEthernetInformation;
                /** @brief Extended information packet alias. */
                typedef ppp::app::protocol::VirtualEthernetInformationExtensions        VirtualEthernetInformationExtensions;
                /** @brief URI utility alias. */
                typedef ppp::auxiliary::UriAuxiliary                                    UriAuxiliary;
                /** @brief Transport protocol type alias. */
                typedef UriAuxiliary::ProtocolType                                      ProtocolType;
                /** @brief Timer type alias. */
                typedef ppp::threading::Timer                                           Timer;
                /** @brief Shared pointer alias for timers. */
                typedef std::shared_ptr<Timer>                                          TimerPtr;
                /** @brief Map of opaque-key to timer used for deadline tracking. */
                typedef ppp::unordered_map<void*, TimerPtr>                             TimerTable;
                /** @brief Shared pointer alias for a UDP datagram relay port. */
                typedef std::shared_ptr<VEthernetDatagramPort>                          VEthernetDatagramPortPtr;
                /** @brief Callback used by local proxy UDP handlers before TAP injection. */
                typedef ppp::function<bool(const boost::asio::ip::udp::endpoint&, const boost::asio::ip::udp::endpoint&, void*, int)> DatagramPacketHandler;
                /** @brief Strand pointer alias used for serialized IO operations. */
                typedef ppp::threading::Executors::StrandPtr                            StrandPtr;
                /** @brief Internal mutex type. */
                typedef std::mutex                                                      SynchronizedObject;
                /** @brief RAII lock guard for the internal mutex. */
                typedef std::lock_guard<SynchronizedObject>                             SynchronizedObjectScope;

            private:
                /** @brief Map from source UDP endpoint to datagram relay port. */
                typedef ppp::unordered_map<boost::asio::ip::udp::endpoint,
                    VEthernetDatagramPortPtr>                                           VEthernetDatagramPortTable;
                /** @brief Map from local UDP source endpoint to optional proxy response handler. */
                typedef ppp::unordered_map<boost::asio::ip::udp::endpoint,
                    DatagramPacketHandler>                                              DatagramPacketHandlerTable;
                /** @brief Mapping port alias (FRP port-forwarding). */
                typedef ppp::app::protocol::VirtualEthernetMappingPort                  VirtualEthernetMappingPort;
                /** @brief Shared pointer alias for mapping port. */
                typedef std::shared_ptr<VirtualEthernetMappingPort>                     VirtualEthernetMappingPortPtr;
                /** @brief Ciphertext algorithm alias. */
                typedef ppp::cryptography::Ciphertext                                   Ciphertext;
                /** @brief Shared pointer alias for ciphertext objects. */
                typedef std::shared_ptr<Ciphertext>                                     CiphertextPtr;
                /** @brief Shared pointer alias for Boost steady (monotonic) timers. */
                typedef std::shared_ptr<boost::asio::steady_timer>                      DeadlineTimerPtr;
                /** @brief Map from opaque key to Boost steady timer. */
                typedef ppp::unordered_map<void*, DeadlineTimerPtr>                     DeadlineTimerTable;

            public:
                /**
                 * @brief Constructs a new exchanger instance.
                 *
                 * @param switcher  Owning network switcher providing TAP and route context.
                 * @param configuration  Runtime application configuration snapshot.
                 * @param context  Boost.Asio io_context for all async operations.
                 * @param id  128-bit session identifier assigned by the server.
                 */
                VEthernetExchanger(
                    const VEthernetNetworkSwitcherPtr&                                  switcher,
                    const AppConfigurationPtr&                                          configuration,
                    const ContextPtr&                                                   context,
                    const Int128&                                                       id) noexcept;

                /**
                 * @brief Destroys the exchanger and frees all managed resources.
                 *
                 * @note The destructor calls Finalize() to ensure datagram ports, timers,
                 *       and mapping ports are released even if Dispose() was not called.
                 */
                virtual ~VEthernetExchanger() noexcept;

            public:
                /**
                 * @brief Logical network state of the exchanger session.
                 *
                 * @details
                 * State transitions:
                 *  - Initial state: NetworkState_Connecting
                 *  - On successful handshake: → NetworkState_Established
                 *  - On link loss: → NetworkState_Reconnecting → NetworkState_Connecting
                 */
                typedef enum {
                    NetworkState_Connecting,    ///< Resolving and connecting to the remote server.
                    NetworkState_Established,   ///< Session fully established; data plane active.
                    NetworkState_Reconnecting,  ///< Link lost; waiting before next reconnect attempt.
                }                                                                       NetworkState;

                struct RuntimeStateSnapshot final {
                    NetworkState network_state = NetworkState_Connecting;
                    ppp::p2p::P2PState p2p_state = ppp::p2p::P2PState::Disabled;
                };

            public:
                /**
                 * @brief Gets the current logical network state.
                 * @return Atomic snapshot of the current NetworkState.
                 * @note Thread-safe due to std::atomic<NetworkState>.
                 */
                NetworkState                                                            GetNetworkState()       noexcept { return network_state_.load(); }
                RuntimeStateSnapshot                                                    GetRuntimeState() const noexcept;

                /**
                 * @brief Gets the shared receive buffer used by async IO paths.
                 * @return Shared byte buffer allocated at construction time.
                 */
                std::shared_ptr<Byte>                                                   GetBuffer()             noexcept { return buffer_; }

                ppp::app::mux::MuxCoordinator*                                          GetMuxCoordinator()     noexcept { return mux_coordinator_.get(); }

                /**
                 * @brief Gets the owning network switcher.
                 * @return Shared pointer to VEthernetNetworkSwitcher.
                 */
                VEthernetNetworkSwitcherPtr                                             GetSwitcher()           noexcept { return switcher_; }

                /**
                 * @brief Gets the latest server information snapshot received from the server.
                 * @return Shared VirtualEthernetInformation; null until first OnInformation callback.
                 */
                std::shared_ptr<VirtualEthernetInformation>                             GetInformation()        noexcept { return information_; }

                /**
                 * @brief Gets the active transmission channel.
                 * @return Shared ITransmission; null when not in Established state.
                 */
                ITransmissionPtr                                                        GetTransmission()       noexcept { return transmission_; }

                /**
                 * @brief Gets the total number of reconnect attempts since the last established state.
                 * @return Non-negative reconnection counter; reset on successful establishment.
                 */
                int                                                                     GetReconnectionCount()  noexcept { return reconnection_count_; }

                /**
                 * @brief Gets the link telemetry object for this session.
                 *
                 * Tracks unexpected RST faults, clean closes, and tunnel quality.
                 * @return Reference to the session-level LinkTelemetry instance.
                 */
                ppp::diagnostics::LinkTelemetry&                                           GetLinkTelemetry()      noexcept { return link_telemetry_; }

                /**
                 * @brief Gets the VMUX network state derived from the coordinated session lifecycle.
                 * @return NetworkState based on vmux connectivity; NetworkState_Connecting if mux is null.
                 */
                NetworkState                                                            GetMuxNetworkState()    noexcept;
                ppp::app::mux::MuxRuntimeState                                           GetMuxRuntimeState()    noexcept;

                /**
                 * @brief Starts the asynchronous connect-handshake-reconnect coroutine loop.
                 * @return true if the coroutine was successfully spawned; false otherwise.
                 * @note Must be called once after construction and before any data is sent.
                 */
                virtual bool                                                            Open()                  noexcept;

                /**
                 * @brief Schedules asynchronous disposal of the exchanger.
                 *
                 * @details
                 * Posts a Finalize() task to the io_context. Safe to call from any thread;
                 * subsequent calls after the first are no-ops.
                 */
                virtual void                                                            Dispose()               noexcept;

                /**
                 * @brief Opens an additional transmission for a vmux sub-link.
                 *
                 * @param context  IO context for the new transmission.
                 * @param strand   Optional strand for serialized operation.
                 * @param y        Coroutine yield context.
                 * @return Shared ITransmission on success; null on failure.
                 * @note Called from vmux internal machinery to establish multiplexed sub-connections.
                 */
                virtual ITransmissionPtr                                                ConnectTransmission(const ContextPtr& context, const StrandPtr& strand, YieldContext& y, uint64_t* ios_child_slot_generation = NULLPTR) noexcept;

#if defined(_IPHONE)
                /** @brief True when ctcp peer-connect backlog is above the soft backpressure threshold. */
                bool                                                                    IosPeerConnectBackpressured() const noexcept;

                /** @brief Releases one iOS child-transmission slot (mux=0 per-flow server TCP). */
                void                                                                    ReleaseIosChildTransmissionSlot(uint64_t generation) noexcept;
#endif

            public:
                /**
                 * @brief Executes a callable in the exchanger's IO context.
                 *
                 * @tparam F Callable type with signature `void()`.
                 * @param f  Callable to invoke.
                 *
                 * @details
                 * On Android, the callable is posted to the io_context to ensure execution
                 * on the correct thread. On all other platforms the callable is invoked inline
                 * because this method is already called from within the IO thread.
                 *
                 * @note Not intended for cross-thread dispatch outside of Android VPN service.
                 */
                template <typename F>
                void                                                                    Post(F&& f) noexcept {
#if defined(_ANDROID)
                    auto context = GetContext();
                    if (context) {
                        auto self = shared_from_this();
                        boost::asio::post(*context,
                            [self, f]() noexcept {
                                f();
                            });
                    }
#else
                    if (disposed_.load(std::memory_order_acquire)) {
                        return;
                    }

                    f();
#endif
                }

            public:
                /**
                 * @brief Sends a raw IPv4 packet into the remote NAT channel.
                 *
                 * @param packet       Pointer to raw IPv4 packet bytes.
                 * @param packet_size  Length of the packet in bytes.
                 * @return true if the packet was enqueued for transmission; false on error.
                 * @note Must be called from the IO thread. Calls SetLastError on failure.
                 */
                virtual bool                                                            Nat(const void* packet, int packet_size) noexcept;

                /**
                 * @brief Sends the requested IPv6 configuration envelope to the remote server.
                 *
                 * @param transmission  Transport channel to send on.
                 * @param y             Coroutine yield context.
                 * @return true if the message was sent successfully.
                 * @note Used during session establishment when an IPv6 address is requested.
                 */
                bool                                                                    SendRequestedIPv6Configuration(const ITransmissionPtr& transmission, YieldContext& y) noexcept;

                /**
                 * @brief Sends an ACK-based ICMP echo request using the given ack identifier.
                 *
                 * @param ack_id  Echo acknowledgment identifier to echo back.
                 * @return true if the echo was enqueued; false on error.
                 */
                virtual bool                                                            Echo(int ack_id) noexcept;

                /**
                 * @brief Sends a packet-based ICMP echo request.
                 *
                 * @param packet       Pointer to the ICMP packet payload.
                 * @param packet_size  Length of the payload in bytes.
                 * @return true if the echo was enqueued; false on error.
                 */
                virtual bool                                                            Echo(const void* packet, int packet_size) noexcept;

                /**
                 * @brief Sends a UDP payload from a local source endpoint to a remote destination.
                 *
                 * @param sourceEP       Source UDP endpoint on the local TAP interface.
                 * @param destinationEP  Destination UDP endpoint on the remote network.
                 * @param packet         Payload buffer.
                 * @param packet_size    Payload length in bytes.
                 * @return true if the datagram was forwarded; false on error.
                 */
                /** @brief IUdpRelayHost: hands the datagram manager the exchanger capabilities it needs. */
                udp::UdpRelayHostPorts                                                   BuildUdpRelayHostPorts() noexcept override;

                virtual bool                                                            SendTo(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const void* packet, int packet_size) noexcept;
                virtual bool                                                            SendTo(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const void* packet, int packet_size, routing::RoutingAction action) noexcept;
                bool                                                                    SendDnsDatagram(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const void* packet, int packet_size) noexcept override;

                /**
                 * @brief Registers an optional local handler for inbound UDP replies keyed by source endpoint.
                 * @param sourceEP Local UDP source endpoint used as the datagram relay key.
                 * @param handler Callback invoked before default TAP injection.
                 * @return true if the handler is stored.
                 */
                bool                                                                    RegisterDatagramHandler(const boost::asio::ip::udp::endpoint& sourceEP, const DatagramPacketHandler& handler) noexcept;

                /**
                 * @brief Removes a previously registered local UDP reply handler.
                 * @param sourceEP Local UDP source endpoint key.
                 * @return true if a handler was removed.
                 */
                bool                                                                    ReleaseDatagramHandler(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

                /**
                 * @brief Dispatches an inbound UDP reply to a registered local handler, if any.
                 * @return true when a handler consumed the packet.
                 */
                bool                                                                    TryHandleDatagram(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_size) noexcept;

                /**
                 * @brief Performs periodic maintenance: keepalive, static-echo rotation, mux events.
                 *
                 * @return true to continue the timer loop; false to stop.
                 * @note Called by the VEthernetNetworkSwitcher tick timer at regular intervals.
                 */
                virtual bool                                                            Update() noexcept;

                /**
                 * @brief Checks whether the static-echo transport is fully allocated and ready.
                 * @return true if static-echo session id, remote port, and sockets are valid.
                 */
                bool                                                                    StaticEchoAllocated() noexcept;

                /**
                 * @brief Resolves, validates, and caches the remote server endpoint from configuration.
                 *
                 * @param[in]  y              Optional coroutine yield context for DNS resolution.
                 * @param[out] hostname       Resolved or configured hostname string.
                 * @param[out] address        Resolved IP address string.
                 * @param[out] path           WebSocket URL path component.
                 * @param[out] port           TCP port number.
                 * @param[out] protocol_type  Selected protocol type (PPP, WS, WSS, etc.).
                 * @param[out] server         Full server URI string.
                 * @param[out] remoteEP       Resolved TCP endpoint.
                 * @return true if resolution succeeded; false otherwise.
                 */
                virtual bool                                                            GetRemoteEndPoint(YieldContext* y, ppp::string& hostname, ppp::string& address, ppp::string& path, int& port, ProtocolType& protocol_type, ppp::string& server, boost::asio::ip::tcp::endpoint& remoteEP) noexcept;

            protected:
                /**
                 * @brief Handles an inbound LAN announcement event from the remote transport.
                 *
                 * @param transmission  Transport channel that delivered the event.
                 * @param ip            Announced IPv4 address (network byte order).
                 * @param mask          Announced subnet mask (network byte order).
                 * @param y             Coroutine yield context.
                 * @return true if handled successfully; false to close the session.
                 */
                virtual bool                                                            OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept override;

                /**
                 * @brief Handles an inbound NAT packet from the remote transport.
                 *
                 * @param transmission   Transport channel.
                 * @param packet         Raw packet bytes (owned by the linklayer buffer).
                 * @param packet_length  Packet length in bytes.
                 * @param y              Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept override;

                /**
                 * @brief Handles the base information envelope received from the remote server.
                 *
                 * @param transmission  Transport channel.
                 * @param information   Parsed VirtualEthernetInformation payload.
                 * @param y             Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept override;

                /**
                 * @brief Handles the extended information envelope (IPv6, QoS extensions) from the server.
                 *
                 * @param transmission  Transport channel.
                 * @param information   Extended information envelope.
                 * @param y             Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept override;

                /**
                 * @brief Handles a TCP push-data event from the remote transport.
                 *
                 * @param transmission    Transport channel.
                 * @param connection_id   Logical TCP connection identifier.
                 * @param packet          Payload buffer.
                 * @param packet_length   Payload length in bytes.
                 * @param y               Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept override;

                /**
                 * @brief Handles a TCP connect request event from the remote transport.
                 *
                 * @param transmission   Transport channel.
                 * @param connection_id  Logical connection identifier.
                 * @param destinationEP  Requested remote TCP endpoint.
                 * @param y              Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept override;

                /**
                 * @brief Handles a TCP connect-acknowledgment event from the remote transport.
                 *
                 * @param transmission   Transport channel.
                 * @param connection_id  Logical connection identifier.
                 * @param error_code     0 on success; non-zero on remote connect failure.
                 * @param y              Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept override;

                /**
                 * @brief Handles a TCP disconnect event from the remote transport.
                 *
                 * @param transmission   Transport channel.
                 * @param connection_id  Logical connection identifier.
                 * @param y              Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept override;

                /**
                 * @brief Handles an ACK echo callback from the remote transport.
                 *
                 * @param transmission  Transport channel.
                 * @param ack_id        Echo ACK identifier matching an earlier Echo() call.
                 * @param y             Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept override;

                /**
                 * @brief Handles a packet-based echo callback from the remote transport.
                 *
                 * @param transmission   Transport channel.
                 * @param packet         Echo payload bytes.
                 * @param packet_length  Payload length in bytes.
                 * @param y              Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnEcho(const ITransmissionPtr& transmission, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept override;

                /**
                 * @brief Handles a UDP send-to callback received through the remote transport.
                 *
                 * @param transmission   Transport channel.
                 * @param sourceEP       Original UDP source endpoint.
                 * @param destinationEP  Original UDP destination endpoint.
                 * @param packet         UDP payload buffer.
                 * @param packet_length  Payload length in bytes.
                 * @param y              Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept override;

                /**
                 * @brief Handles a static-echo negotiation callback with no session payload.
                 *
                 * @param transmission  Transport channel.
                 * @param y             Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept override;

                /**
                 * @brief Handles a static-echo negotiation callback carrying session parameters.
                 *
                 * @param transmission   Transport channel.
                 * @param fsid           File-system/flow identifier token from server.
                 * @param session_id     Assigned static-echo session identifier.
                 * @param remote_port    UDP port on the server side for static-echo traffic.
                 * @param y              Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept override;

                /**
                 * @brief Handles a VMUX configuration negotiation callback from the server.
                 *
                 * @param transmission      Transport channel.
                 * @param vlan             Assigned VLAN identifier for the mux session.
                 * @param max_connections  Maximum allowed mux sub-connections.
                 * @param acceleration     Whether hardware/software acceleration is requested.
                 * @param y                Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, Byte ordering_caps, YieldContext& y) noexcept override;

            protected:
                /**
                 * @brief Creates a new datagram relay port for the given source endpoint.
                 *
                 * @param transmission  Transmission to associate with the new port.
                 * @param sourceEP      UDP source endpoint to relay.
                 * @return New VEthernetDatagramPort instance; null on allocation failure.
                 * @note Subclasses may override to inject a specialized port type.
                 */
                virtual VEthernetDatagramPortPtr                                        NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

                /**
                 * @brief Retrieves an existing datagram relay port by source endpoint.
                 *
                 * @param sourceEP  UDP source endpoint key.
                 * @return Existing port shared_ptr; null if not found.
                 * @note Acquires syncobj_ internally.
                 */
                virtual VEthernetDatagramPortPtr                                        GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

                /**
                 * @brief Removes and returns a datagram relay port by source endpoint.
                 *
                 * @param sourceEP  UDP source endpoint key to remove.
                 * @return Removed port shared_ptr; null if not found.
                 * @note Acquires syncobj_ internally. Port disposal is the caller's responsibility.
                 */
                virtual VEthernetDatagramPortPtr                                        ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                virtual VEthernetDatagramPortPtr                                        ReleaseDatagramPortIf(const boost::asio::ip::udp::endpoint& sourceEP, const VEthernetDatagramPort* expected) noexcept;

            protected:
                /**
                 * @brief Creates a concrete ITransmission instance for the resolved protocol type.
                 *
                 * @param context        IO context.
                 * @param strand         Optional strand for serialized operation.
                 * @param socket         Connected TCP socket to wrap.
                 * @param protocol_type  Protocol type selected by GetRemoteEndPoint().
                 * @param host           WebSocket host header value.
                 * @param path           WebSocket request path.
                 * @return Newly constructed ITransmission; null on failure.
                 */
                virtual ITransmissionPtr                                                NewTransmission(
                    const ContextPtr&                                                   context,
                    const StrandPtr&                                                    strand,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&                socket,
                    ProtocolType                                                        protocol_type,
                    const ppp::string&                                                  host,
                    const ppp::string&                                                  path,
                    ppp::transmissions::TcpTransmissionRole                             role = ppp::transmissions::TcpTransmissionRole::Child) noexcept;

                /**
                 * @brief Opens a transport channel to the cached remote endpoint.
                 *
                 * @param context  IO context.
                 * @param strand   Optional strand.
                 * @param y        Coroutine yield context; blocks until connected or failed.
                 * @param role     Main VPN session or per-flow child transmission.
                 * @return Shared ITransmission on success; null on failure.
                 */
                virtual ITransmissionPtr                                                OpenTransmission(const ContextPtr& context, const StrandPtr& strand, YieldContext& y, ppp::transmissions::TcpTransmissionRole role = ppp::transmissions::TcpTransmissionRole::Child) noexcept;

            protected:
                /**
                 * @brief Allocates and configures an asynchronous TCP socket with platform options.
                 *
                 * @param context   IO context.
                 * @param strand    Optional strand.
                 * @param protocol  IP protocol version (v4 or v6).
                 * @param y         Coroutine yield context.
                 * @return Configured TCP socket; null on failure.
                 */
                virtual std::shared_ptr<boost::asio::ip::tcp::socket>                   NewAsynchronousSocket(const ContextPtr& context, const StrandPtr& strand, const boost::asio::ip::tcp& protocol, ppp::coroutines::YieldContext& y) noexcept;

                /**
                 * @brief Executes the main connect → handshake → data-loop → reconnect coroutine.
                 *
                 * @param context  IO context that drives the coroutine.
                 * @param strand   Serial executor shared by the main carrier and negotiation timer.
                 * @param y        Coroutine yield context.
                 * @return true if the loop ran to completion normally; false on unrecoverable error.
                 * @note This is the entry point spawned by Open(). It loops until disposed_.
                 */
                virtual bool                                                            Loopback(const ContextPtr& context, const StrandPtr& strand, YieldContext& y) noexcept;

                /**
                 * @brief Handles a fully decoded inbound packet from the base linklayer.
                 *
                 * @param transmission   Source transport channel.
                 * @param p              Decoded packet buffer (owned by linklayer).
                 * @param packet_length  Packet length in bytes.
                 * @param y              Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            PacketInput(const ITransmissionPtr& transmission, const std::shared_ptr<Byte>& owner, Byte* p, int packet_length, YieldContext& y) noexcept;

            private:
                /**
                 * @brief Opens a transmission using no dedicated strand (convenience overload).
                 *
                 * @param context  IO context.
                 * @param y        Coroutine yield context.
                 * @return Shared ITransmission on success; null on failure.
                 */
                ITransmissionPtr                                                        OpenTransmission(const ContextPtr& context, YieldContext& y, ppp::transmissions::TcpTransmissionRole role = ppp::transmissions::TcpTransmissionRole::Child) noexcept {
                    StrandPtr strand;
                    return OpenTransmission(context, strand, y, role);
                }

                enum class SessionResumeNegotiationResult : std::uint8_t {
                    Failed,
                    Fresh,
                    Resumed,
                };

                bool                                                                    AuthenticatePlainTransport(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                void                                                                    ClearSessionResumeState() noexcept;
                bool                                                                    SendSessionResumeControl(const ITransmissionPtr& transmission, const ppp::app::protocol::SessionResumeTranscriptFields& fields, const ppp::app::protocol::SessionResumeProof& proof, YieldContext& y) noexcept;
                bool                                                                    AcceptFreshSessionResumeOffer(const ITransmissionPtr& transmission, const InformationEnvelope& offer, YieldContext& y) noexcept;
                SessionResumeNegotiationResult                                          NegotiateSessionResume(const ITransmissionPtr& transmission, InformationEnvelope& initial_information, bool& has_initial_information, YieldContext& y) noexcept;
                bool                                                                    ApplyPreDataInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept;

                /** @brief Releases all owned resources and marks the exchanger disposed. */
                void                                                                    Finalize() noexcept;

                /** @brief Transitions the state machine to NetworkState_Established. */
                void                                                                    ExchangeToEstablishState() noexcept;

                /** @brief Transitions the state machine to NetworkState_Connecting. */
                void                                                                    ExchangeToConnectingState() noexcept;

                /** @brief Transitions the state machine to NetworkState_Reconnecting. */
                void                                                                    ExchangeToReconnectingState() noexcept;

                /**
                 * @brief Sends the local LAN address and mask to the remote exchanger.
                 *
                 * @param transmission  Transport channel.
                 * @param y             Coroutine yield context.
                 * @return 0 on success; negative on failure.
                 */
                int                                                                     EchoLanToRemoteExchanger(const ITransmissionPtr& transmission, YieldContext& y) noexcept;

                /**
                 * @brief Sends a keepalive echo or closes a stale link.
                 *
                 * @param now        Current tick count in milliseconds.
                 * @param immediately  If true, send regardless of interval check.
                 * @return true if the keepalive was sent; false if the link was closed.
                 */
                bool                                                                    SendEchoKeepAlivePacket(UInt64 now, bool immediately) noexcept;

                /**
                 * @brief Routes a UDP packet received from the remote destination back to the local TAP.
                 *
                 * @param sourceEP       Remote source UDP endpoint.
                 * @param destinationEP  Local destination UDP endpoint.
                 * @param packet         UDP payload buffer.
                 * @param packet_length  Payload length in bytes.
                 * @return true if the packet was injected into the TAP path; false on error.
                 */
                bool                                                                    ReceiveFromDestination(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length) noexcept;

                /**
                 * @brief Inserts a new datagram port for the source endpoint if not already present.
                 *
                 * @param transmission  Transport channel for the new port.
                 * @param sourceEP      Source UDP endpoint.
                 * @return Existing or newly created port; null on allocation failure.
                 */
                VEthernetDatagramPortPtr                                                AddNewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

            private:
                /**
                 * @brief Creates a WebSocket-family transmission and sets host/path if configured.
                 *
                 * @tparam TTransmission  Concrete WebSocket transmission type (must derive from ITransmission).
                 * @param context  IO context.
                 * @param strand   Optional strand.
                 * @param socket   Connected TCP socket.
                 * @param host     WebSocket Host header value.
                 * @param path     WebSocket request path.
                 * @return Constructed transmission; null on failure.
                 */
                template <typename TTransmission>
                typename std::enable_if<std::is_base_of<ITransmission, TTransmission>::value, std::shared_ptr<TTransmission>/**/>::type
                NewWebsocketTransmission(const ContextPtr& context, const StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const ppp::string& host, const ppp::string& path) noexcept;

            private:
                /**
                 * @brief Looks up a mapping port by direction, protocol, and remote port.
                 *
                 * @param in           true for inbound (server→client); false for outbound.
                 * @param tcp          true for TCP; false for UDP.
                 * @param remote_port  Remote port number.
                 * @return Existing mapping port; null if not registered.
                 */
                VirtualEthernetMappingPortPtr                                           GetMappingPort(bool in, bool tcp, int remote_port) noexcept;

                /**
                 * @brief Allocates a new mapping port object for the given key.
                 *
                 * @param in           Direction flag.
                 * @param tcp          Protocol flag.
                 * @param remote_port  Remote port number.
                 * @return New mapping port; null on allocation failure.
                 */
                VirtualEthernetMappingPortPtr                                           NewMappingPort(bool in, bool tcp, int remote_port) noexcept;

                /**
                 * @brief Registers one AppConfiguration::MappingConfiguration entry.
                 *
                 * @param mapping  Mapping configuration to register.
                 * @return true if registration succeeded; false otherwise.
                 */
                bool RegisterMappingPort(ppp::configurations::MappingConfiguration& mapping) noexcept;

                /** @brief Unregisters and disposes all active mapping ports. */
                void                                                                    UnregisterAllMappingPorts() noexcept;

                /**
                 * @brief Iterates AppConfiguration and registers all mapping entries.
                 * @return true if all entries were registered; false if any failed.
                 */
                bool                                                                    RegisterAllMappingPorts() noexcept;

                /**
                 * @brief Cancels and removes a tracked deadline timer by its raw pointer key.
                 *
                 * @param deadline_timer  Pointer used as the table key.
                 * @return true if the timer was found and cancelled; false otherwise.
                 */
                bool                                                                    ReleaseDeadlineTimer(const boost::asio::steady_timer* deadline_timer) noexcept;

                /**
                 * @brief Creates a one-shot deadline timer and tracks it internally.
                 *
                 * @param context  IO context to schedule the timer on.
                 * @param timeout  Delay in milliseconds before the event fires.
                 * @param event    Callback invoked with true on expiry, false on cancellation.
                 * @return true if the timer was created; false on failure.
                 */
                bool                                                                    NewDeadlineTimer(const ContextPtr& context, int64_t timeout, const ppp::function<void(bool)>& event) noexcept;

                /**
                 * @brief Suspends the current coroutine for the specified duration.
                 *
                 * @param timeout  Sleep duration in milliseconds.
                 * @param context  IO context for the internal timer.
                 * @param y        Coroutine yield context.
                 * @return true if sleep completed normally; false if disposed during wait.
                 */
                bool                                                                    Sleep(int64_t timeout, const ContextPtr& context, YieldContext& y) noexcept;

#if defined(_ANDROID)
                /**
                 * @brief Waits until the Android VPN JNI thread is attached and the protector is ready.
                 *
                 * @param context  IO context for the internal polling timer.
                 * @param y        Coroutine yield context.
                 * @return true when the JNI thread is attached; false if disposed.
                 * @note Android-only. Required before opening protected sockets.
                 */
                bool                                                                    AwaitJniAttachThread(const ContextPtr& context, YieldContext& y) noexcept;
#endif

                /**
                 * @brief Executes keepalive checks for an established link.
                 *
                 * @param transmission  Active transport channel.
                 * @param now           Current tick count in milliseconds.
                 * @return true to continue; false to close the session due to timeout.
                 */
                virtual bool                                                            DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept override;

                /**
                 * @brief Drives VMUX lifecycle: polls connection state, tears down failed instances.
                 * @return true if mux is healthy or not in use; false if mux failed and session must close.
                 */
                bool                                                                    DoMuxEvents() noexcept;

                /**
                 * @brief Connects all VMUX sub-linklayers required by the negotiated session.
                 *
                 * @param allocator  Buffer allocator for sub-link transmission buffers.
                 * @param mux        VMUX instance to populate with sub-links.
                 * @return true if all sub-links were connected; false if any failed.
                 */
                bool                                                                    MuxConnectAllLinklayers(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<void>& mux) noexcept;
                /**
                 * @brief Connect N extra carrier links at runtime and attach each via
                 *        add_linklayer's established-session path (turbo dynamic pool grow).
                 * @return true when the grow coroutine was spawned.
                 */
                bool                                                                    MuxGrowLinklayers(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<void>& mux, int count) noexcept;

            private:
                /**
                 * @brief Adds a server-side remote UDP endpoint to the static-echo load-balance pool.
                 *
                 * @param remoteEP  Remote endpoint to add.
                 * @return true if successfully added; false if already present.
                 */
                bool                                                                    StaticEchoAddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept;

                /** @brief Clears all static-echo sockets, endpoints, and session state. */
                void                                                                    StaticEchoClean() noexcept;

                /**
                 * @brief Swaps the active and standby static-echo sockets when the rotation timer fires.
                 * @return true if the swap completed successfully; false otherwise.
                 */
                bool                                                                    StaticEchoSwapAsynchronousSocket() noexcept;

                /**
                 * @brief Sends a gateway keepalive packet through the static-echo channel.
                 *
                 * @param ack_id  Acknowledgment identifier to include in the keepalive.
                 * @return true if sent; false on error.
                 */
                bool                                                                    StaticEchoGatewayServer(int ack_id) noexcept;

                /**
                 * @brief Sends a pre-packed static-echo packet buffer to the current remote endpoint.
                 *
                 * @param packet         Shared packet buffer.
                 * @param packet_length  Packet length in bytes.
                 * @return true if sent; false on error.
                 */
                bool                                                                    StaticEchoPacketToRemoteExchanger(const std::shared_ptr<Byte>& packet, int packet_length) noexcept;

                /**
                 * @brief Packs and sends a raw IPv4 frame through the static-echo channel.
                 *
                 * @param packet  IPv4 frame to serialize and transmit.
                 * @return true if sent; false on error.
                 */
                bool                                                                    StaticEchoPacketToRemoteExchanger(const ppp::net::packet::IPFrame* packet) noexcept;

                /**
                 * @brief Packs and sends a UDP frame through the static-echo channel.
                 *
                 * @param frame  Parsed UDP frame to serialize and transmit.
                 * @return true if sent; false on error.
                 */
                bool                                                                    StaticEchoPacketToRemoteExchanger(const std::shared_ptr<ppp::net::packet::UdpFrame>& frame) noexcept;

            private:
                /**
                 * @brief Handles an FRP UDP send-to packet from the remote server.
                 *
                 * @param transmission   Transport channel.
                 * @param in             true for inbound direction.
                 * @param remote_port    FRP mapped port number.
                 * @param sourceEP       Source UDP endpoint of the forwarded datagram.
                 * @param packet         UDP payload buffer.
                 * @param packet_length  Payload length in bytes.
                 * @param y              Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept override;

                /**
                 * @brief Handles an FRP TCP connect request from the remote server.
                 *
                 * @param transmission   Transport channel.
                 * @param connection_id  Logical FRP connection identifier.
                 * @param in             Direction flag.
                 * @param remote_port    FRP mapped port number.
                 * @param y              Coroutine yield context.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept override;

                /**
                 * @brief Handles an FRP TCP disconnect notification from the remote server.
                 *
                 * @param transmission   Transport channel.
                 * @param connection_id  Logical FRP connection identifier.
                 * @param in             Direction flag.
                 * @param remote_port    FRP mapped port number.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept override;

                /**
                 * @brief Handles an FRP TCP data push payload from the remote server.
                 *
                 * @param transmission   Transport channel.
                 * @param connection_id  Logical FRP connection identifier.
                 * @param in             Direction flag.
                 * @param remote_port    FRP mapped port number.
                 * @param packet         Data payload buffer.
                 * @param packet_length  Payload length in bytes.
                 * @return true if handled; false to close the session.
                 */
                virtual bool                                                            OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const std::shared_ptr<Byte>& owner, const void* packet, int packet_length) noexcept override;

            private:
                void                                                                    HandleP2PRelayOffer(const ITransmissionPtr& transmission, const ppp::app::protocol::P2PControlMessage& message) noexcept;
                void                                                                    HandleP2PDatagram(const ITransmissionPtr& transmission, uint64_t generation, uint64_t transport_registration, ppp::p2p::P2PDatagramReceiveStatus status, const boost::asio::ip::udp::endpoint& sender, const std::uint8_t* packet, int packet_size) noexcept;
                void                                                                    ResetP2PCandidateTransport() noexcept;
                void                                                                    StartP2PStunGatherAsync(
                                                                                            const ITransmissionPtr& transmission,
                                                                                            uint64_t generation,
                                                                                            uint64_t transport_registration,
                                                                                            uint32_t local_virtual_ip,
                                                                                            ppp::vector<ppp::string> stun_servers) noexcept;
                void                                                                    ApplyP2PStunMappedCandidate(
                                                                                            const ITransmissionPtr& transmission,
                                                                                            uint64_t generation,
                                                                                            uint64_t transport_registration,
                                                                                            uint32_t local_virtual_ip,
                                                                                            const boost::asio::ip::udp::endpoint& mapped) noexcept;
                /** @brief Guards datagrams_, datagram_handlers_, and deadline_timers_ tables. */
                SynchronizedObject                                                      syncobj_;
                /** @brief Commits network and P2P projection as one runtime snapshot. */
                mutable std::mutex                                                      runtime_state_mutex_;

                /** @brief Atomic one-shot disposed flag; safe for cross-strand reads. */
                std::atomic_bool                                                        disposed_{false};
                /** @brief Shared receive buffer allocated once and reused across async reads. */
                std::shared_ptr<Byte>                                                   buffer_;

                /** @brief Pure keepalive timing and stale-link decision state. */
                ClientKeepAlivePolicy                                                   keepalive_policy_;

                /** @brief Owning network switcher. */
                VEthernetNetworkSwitcherPtr                                             switcher_;
                /** @brief Cached server information received during session establishment. */
                std::shared_ptr<VirtualEthernetInformation>                             information_;
                /** @brief UDP datagram relay session manager (P2-c: owns the extracted session tables). */
                std::unique_ptr<udp::ClientDatagramPortManager>                         datagram_manager_;
                /** @brief Active transport channel; null when not established. */
                ITransmissionPtr                                                        transmission_;
                /** @brief Serial executor owning main carrier and resume state mutations. */
                StrandPtr                                                               owner_strand_;
                /** @brief Exporter-derived root retained across transient carrier loss. */
                ppp::app::protocol::SessionResumeSecret                                 session_resume_root_;
                ppp::app::protocol::SessionResumeId                                     session_resume_id_{};
                std::uint64_t                                                           session_resume_generation_ = 0;
                bool                                                                    session_resume_armed_ = false;
                ppp::app::protocol::SessionResumePendingAttempt                         session_resume_pending_;
                /** @brief Atomic network state for safe cross-thread reads. */
                std::atomic<NetworkState>                                               network_state_      = NetworkState_Connecting;
                /** @brief P2P state when no authenticated relay session is established. */
                const ppp::p2p::P2PState                                                configured_p2p_state_;
                /** @brief Fail-closed P2P capability state published to RuntimeSnapshot. */
                std::atomic<ppp::p2p::P2PState>                                         p2p_state_{ppp::p2p::P2PState::Disabled};
                /** @brief Authenticated offer and derived-key owner for the active relay generation. */
                ppp::p2p::P2PClientOfferSession                                         p2p_offer_session_;
                /** @brief Guards the exact candidate set sent in the current registration. */
                mutable std::mutex                                                      p2p_offer_mutex_;
                ppp::vector<ppp::app::protocol::P2PEndpointCandidate>                   p2p_registered_candidates_;
                std::weak_ptr<ppp::transmissions::ITransmission>                       p2p_registered_transmission_;
                std::shared_ptr<ppp::p2p::IP2PDatagramTransport>                       p2p_candidate_transport_;
                boost::asio::ip::udp::endpoint                                          p2p_local_candidate_;
                boost::asio::ip::udp::endpoint                                          p2p_peer_candidate_;
                ppp::p2p::P2PDirectDataPath                                             p2p_direct_data_path_;
                ppp::p2p::P2PZeroRTTCache                                               p2p_zero_rtt_cache_;
                uint64_t                                                                p2p_transport_registration_id_ = 0;
                uint32_t                                                                p2p_registered_virtual_ip_ = 0;
                uint32_t                                                                p2p_peer_virtual_ip_ = 0;
                uint64_t                                                                p2p_last_heartbeat_tx_ms_ = 0;
                int                                                                     p2p_heartbeat_misses_ = 0;
                uint64_t                                                                p2p_suspect_since_ms_ = 0;
                uint64_t                                                                p2p_migrate_started_ms_ = 0;
                /** @brief Invalidates queued offer work across reconnect and teardown. */
                std::atomic<uint64_t>                                                   p2p_offer_generation_{1};
                std::atomic<uint64_t>                                                   p2p_transport_registration_sequence_{1};
                /** @brief Owns FRP mapping storage, updates, and release ordering. */
                std::unique_ptr<ClientFrpRegistry>                                      frp_registry_;
                /** @brief Pending deadline timers (guarded by syncobj_). */
                DeadlineTimerTable                                                      deadline_timers_;

                /** @brief Owns the active VMUX session and its runtime projection. */
                std::unique_ptr<ppp::app::mux::MuxCoordinator>                          mux_coordinator_;
                /** @brief VLAN identifier assigned during VMUX negotiation. */
                uint16_t                                                                mux_vlan_           = 0;

                /** @brief Number of reconnect attempts since the last established state. */
                int                                                                     reconnection_count_ = 0;

                /** @brief Per-session link fault telemetry (unexpected RST, link drops, quality). */
                ppp::diagnostics::LinkTelemetry                                             link_telemetry_;

                /** @brief Cached remote server endpoint metadata resolved by GetRemoteEndPoint(). */
                struct {
                    boost::asio::ip::tcp::endpoint                                      remoteEP;
                    ppp::string                                                         hostname;
                    ppp::string                                                         address;
                    ppp::string                                                         path;
                    ppp::string                                                         server;
                    int                                                                 port                = 0;
                    ProtocolType                                                        protocol_type       = ProtocolType::ProtocolType_PPP;
                }                                                                       server_url_;

                /** @brief Static-echo UDP channel extracted from exchanger core. */
                ExchangerStaticEchoChannel                                              static_echo_;

#if defined(_IPHONE)
                /** @brief Active per-flow server transmissions when mux is disabled. */
                std::atomic<int>                                                        ios_child_transmission_active_{0};
                /** @brief Coroutines blocked waiting for a child-transmission slot. */
                std::atomic<int>                                                        ios_child_connect_waiters_{0};
                /** @brief Generation token invalidating stale child slot releases after reset. */
                std::atomic<uint64_t>                                                   ios_child_slot_generation_{1};
                /** @brief Serializes active/generation updates for iOS child slots. */
                mutable std::mutex                                                      ios_child_slots_mutex_;

                bool                                                                    TryReserveIosChildTransmissionSlot(const ContextPtr& context, YieldContext& y, uint64_t& generation) noexcept;
                void                                                                    ResetIosChildTransmissionSlots(const char* reason) noexcept;
#endif
            };
        }
    }
}
