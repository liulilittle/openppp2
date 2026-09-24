#pragma once

/**
 * @file VirtualEthernetExchanger.h
 * @brief Declares the per-session virtual ethernet exchanger on the server side.
 *
 * @details `VirtualEthernetExchanger` is the core per-client session object on the server.
 *          It derives from `VirtualEthernetLinklayer` and handles every packet type
 *          the client can send: LAN announcements, NAT packets, ICMP echo, UDP sendto,
 *          IPv6, FRP port mapping, VMUX (multiplexed sub-channel), and static-echo.
 *
 *          Key responsibilities:
 *          - Registers the client's LAN subnet in the switcher's NAT table (`OnLan()`).
 *          - Forwards IPv4 NAT packets between clients in the same managed subnet
 *            or to the internet via `OnNat()`.
 *          - Proxies UDP datagrams through per-source `VirtualEthernetDatagramPort` objects.
 *          - Manages ICMP echo forwarding via `VirtualInternetControlMessageProtocol`.
 *          - Provides FRP inbound/outbound port-mapping via `VirtualEthernetMappingPort`.
 *          - Negotiates VMUX sub-channel multiplexing through a coordinator.
 *          - Handles static-echo allocation requests and forwards static-echo datagrams.
 *          - Uploads per-session traffic deltas to the managed server on each tick.
 *
 *          Lifecycle:
 *          - Constructed by `VirtualEthernetSwitcher::NewExchanger()`.
 *          - `Open()` initializes the ICMP helper and static-echo state.
 *          - `Update(now)` is called on every global tick and handles keepalive, port GC,
 *            VMUX polling, traffic upload, and DNS timeout expiry.
 *          - `Dispose()` schedules asynchronous teardown on the owning io_context.
 *
 *          Thread safety:
 *          - `syncobj_` guards `datagrams_`, `timeouts_`, and `mappings_`.
 *          - `static_echo_syncobj_` guards the static-echo sub-state (`static_echo_`,
 *            `static_allocated_context_`, `static_echo_datagram_ports_`).
 *          - Do not acquire both locks in the same call frame to avoid deadlock.
 *
 * @author  OPENPPP2 Team
 * @license GPL-3.0
 */

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetMappingPort.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/app/protocol/SessionResumeAuthenticator.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/SessionRecoveryState.h>
#include <ppp/app/server/udp/ServerUdpRelayHost.h>
#include <ppp/app/server/udp/StaticUdpRelayHost.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/LinkTelemetry.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Firewall.h>
#include <ppp/threading/Timer.h>
#include <ppp/transmissions/ITransmissionStatistics.h>
#include <atomic>

namespace ppp::app::mux { class MuxCoordinator; }

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetManagedServer;
            class VirtualEthernetSwitcher;
            class VirtualEthernetDatagramPort;
            class VirtualEthernetDatagramPortStatic;
            class VirtualInternetControlMessageProtocol;
            class VirtualInternetControlMessageProtocolStatic;

            namespace udp {
                class ServerDatagramPortManager;
                class StaticDatagramPortManager;
            }

            /**
             * @brief Handles one client session's L2/L3 forwarding, NAT, and control operations.
             *
             * @details Each `VirtualEthernetExchanger` is bound to exactly one transmission
             *          channel (TCP/WebSocket/…) that represents a connected VPN client.
             *          It processes the full protocol command set defined by
             *          `VirtualEthernetLinklayer` and dispatches to specialized sub-systems
             *          (ICMP, UDP, FRP, VMUX, static-echo).
             *
             * @note Friendship with `VirtualEthernetSwitcher`, `VirtualEthernetDatagramPort`,
             *       and the static ICMP/datagram helper classes is required so that those
             *       classes can access internal state without exposing it via public API.
             */
            class VirtualEthernetExchanger : public ppp::app::protocol::VirtualEthernetLinklayer, public udp::IServerUdpRelayHost, public udp::IStaticUdpRelayHost {
                friend class                                                                VirtualEthernetSwitcher;

            public:
                /** @brief Base information packet type alias. */
                typedef ppp::app::protocol::VirtualEthernetInformation                      VirtualEthernetInformation;
                /** @brief Extended information packet type alias. */
                typedef ppp::app::protocol::VirtualEthernetInformationExtensions            VirtualEthernetInformationExtensions;
                /** @brief Shared pointer alias for the parent switcher. */
                typedef std::shared_ptr<VirtualEthernetSwitcher>                            VirtualEthernetSwitcherPtr;
                /** @brief Shared pointer alias for the UDP datagram relay port. */
                typedef std::shared_ptr<VirtualEthernetDatagramPort>                        VirtualEthernetDatagramPortPtr;
                /** @brief Shared pointer alias for the Go managed-server bridge. */
                typedef std::shared_ptr<VirtualEthernetManagedServer>                       VirtualEthernetManagedServerPtr;
                /** @brief Static-echo allocation context value alias. */
                typedef VirtualEthernetSwitcher::VirtualEthernetStaticEchoAllocatedContext  VirtualEthernetStaticEchoAllocatedContext;
                /** @brief Shared pointer alias for the static-echo allocation context. */
                typedef std::shared_ptr<VirtualEthernetStaticEchoAllocatedContext>          VirtualEthernetStaticEchoAllocatedContextPtr;

                enum class CarrierStopResult : std::uint8_t {
                    Suspended,
                    Stale,
                    Terminal,
                };

                enum class ResumeBeginStatus : std::uint8_t {
                    Reserved,
                    GenerationSync,
                    Rejected,
                };

            private:    
                typedef std::mutex                                                          SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                                 SynchronizedObjectScope;
                typedef ppp::threading::Timer                                               Timer;
                typedef std::shared_ptr<Timer>                                              TimerPtr;
                typedef ppp::net::Firewall                                                  Firewall;
                typedef std::shared_ptr<ppp::net::Firewall>                                 FirewallPtr;
                typedef Timer::TimeoutEventHandlerPtr                                       TimeoutEventHandlerPtr;
                typedef ppp::unordered_map<void*, TimeoutEventHandlerPtr>                   TimeoutEventHandlerTable;
                typedef ppp::transmissions::ITransmissionStatistics                         ITransmissionStatistics;
                typedef std::shared_ptr<ITransmissionStatistics>                            ITransmissionStatisticsPtr;
                typedef ppp::net::Ipep                                                      Ipep;
                typedef ppp::app::protocol::VirtualEthernetLogger                           VirtualEthernetLogger;
                typedef std::shared_ptr<VirtualEthernetLogger>                              VirtualEthernetLoggerPtr;
                typedef ppp::unordered_map<boost::asio::ip::udp::endpoint,  
                    VirtualEthernetDatagramPortPtr>                                         VirtualEthernetDatagramPortTable;
                typedef std::shared_ptr<VirtualInternetControlMessageProtocol>              VirtualInternetControlMessageProtocolPtr;
                typedef ppp::app::protocol::VirtualEthernetMappingPort                      VirtualEthernetMappingPort;
                typedef std::shared_ptr<VirtualEthernetMappingPort>                         VirtualEthernetMappingPortPtr;
                typedef ppp::unordered_map<uint32_t, VirtualEthernetMappingPortPtr>         VirtualEthernetMappingPortTable;
                typedef std::shared_ptr<VirtualEthernetDatagramPortStatic>                  VirtualEthernetDatagramPortStaticPtr;
                typedef ppp::unordered_map<uint64_t, VirtualEthernetDatagramPortStaticPtr>  VirtualEthernetDatagramPortStaticTable;

            public:
                /**
                 * @brief Constructs a virtual exchanger bound to one transmission session.
                 *
                 * @param switcher      Parent switcher that manages all active exchangers.
                 * @param configuration Immutable runtime configuration snapshot.
                 * @param transmission  Session transport channel (TCP/WebSocket/…).
                 * @param id            Unique 128-bit session identifier.
                 */
                VirtualEthernetExchanger(
                    const VirtualEthernetSwitcherPtr&                                       switcher,
                    const AppConfigurationPtr&                                              configuration, 
                    const ITransmissionPtr&                                                 transmission,
                    const Int128&                                                           id) noexcept;

                /**
                 * @brief Destroys the exchanger and releases all session-level resources.
                 *
                 * @details Calls `Finalize()` to ensure the NAT entry, datagram ports,
                 *          ICMP helper, and transmission are all released even if `Dispose()`
                 *          was never called.
                 */
                virtual ~VirtualEthernetExchanger() noexcept;   
    
            public:
                /**
                 * @brief Runs periodic maintenance: port GC, keepalive, VMUX, traffic upload.
                 *
                 * @param now Current monotonic tick count in milliseconds.
                 * @return True to continue; false if the exchanger should be disposed.
                 */
                virtual bool                                                                Update(UInt64 now) noexcept;

                /**
                 * @brief Initializes the ICMP echo helper and static-echo state for this session.
                 *
                 * @return True on success; false if initialization fails.
                 */
                virtual bool                                                                Open() noexcept;

                /**
                 * @brief Schedules asynchronous disposal of this exchanger on its io_context.
                 *
                 * @details Sets internal flags and posts a cleanup coroutine.  Safe to call
                 *          from any thread; the actual teardown happens on the IO thread.
                 */
                virtual void                                                                Dispose() noexcept;
                void                                                                        Dispose(ppp::function<void()> completion) noexcept;

                /** @brief Returns true if this exchanger has been disposed (atomic load). */
                bool                                                                        IsDisposed() noexcept       { return disposed_.load(std::memory_order_acquire); }
                /** @brief Returns the parent switcher. */
                VirtualEthernetSwitcherPtr                                                  GetSwitcher() noexcept      { return switcher_; }
                /** @brief Returns a locked snapshot of the active carrier. */
                ITransmissionPtr                                                            GetTransmission() noexcept;
                /** @brief Returns the generation that fences the current carrier. */
                std::uint64_t                                                               GetCarrierGeneration() noexcept;
                /** @brief Prepares an authenticated recovery offer for a fresh secure carrier. */
                bool                                                                        PrepareFreshResumeOffer(const ITransmissionPtr& transmission, ppp::app::protocol::SessionResumeControl& offer) noexcept;
                /** @brief Authenticates and reserves a suspended session for one candidate carrier. */
                ResumeBeginStatus                                                           BeginResume(const ITransmissionPtr& transmission, const ppp::app::protocol::SessionResumeControl& request, const ppp::app::protocol::SessionResumeCandidateBinding& candidate, UInt64 now, std::uint64_t& reservation_token, ppp::app::protocol::SessionResumeControl& response) noexcept;
                /** @brief Verifies confirmation and prepares the committed response without publishing data-plane state. */
                bool                                                                        CommitResume(const ITransmissionPtr& transmission, const ppp::app::protocol::SessionResumeControl& confirm, const ppp::app::protocol::SessionResumeCandidateBinding& candidate, std::uint64_t reservation_token, UInt64 now, ppp::app::protocol::SessionResumeControl& committed) noexcept;
                /** @brief Publishes the prepared replacement carrier after the committed response is sent. */
                bool                                                                        PublishCommittedResume(const ITransmissionPtr& transmission, std::uint64_t reservation_token, UInt64 now) noexcept;
                /** @brief Cancels only the matching candidate reservation without expiring the session. */
                void                                                                        CancelResume(const ITransmissionPtr& transmission, std::uint64_t reservation_token) noexcept;
                /** @brief Handles one carrier completion with pointer and generation fencing. */
                CarrierStopResult                                                           OnCarrierStopped(const ITransmissionPtr& transmission, std::uint64_t generation, ppp::diagnostics::ErrorCode error, UInt64 now) noexcept;
                /** @brief Returns true after a suspended recovery grace deadline expires. */
                bool                                                                        IsRecoveryExpired(UInt64 now) noexcept;
                /** @brief Returns true while this session is awaiting an eligible replacement carrier. */
                bool                                                                        IsSuspended(UInt64 now) noexcept;
                /** @brief Returns the Go managed-server bridge (may be null). */
                VirtualEthernetManagedServerPtr                                             GetManagedServer() noexcept { return managed_server_; }
                /** @brief Returns the traffic statistics object for this session. */
                ITransmissionStatisticsPtr                                                  GetStatistics() noexcept    { return statistics_; }
                /** @brief Static-echo allocation context shared with the static datagram/ICMP ports (P2-f). */
                VirtualEthernetStaticEchoAllocatedContextPtr                                GetStaticAllocatedContext() noexcept { return static_allocated_context_; }
                /** @brief Static-echo session slot index (P2-f). */
                int                                                                         GetStaticEchoSessionId() noexcept { return static_echo_session_id_.load(); }
                /** @brief Most-recent static-echo sender endpoint (P2-f). */
                boost::asio::ip::udp::endpoint                                              GetStaticEchoSourceEndPoint() noexcept { return static_echo_source_ep_; }
                /** @brief Releases a static-echo UDP source-port mapping when a port is freed (public since P2-f). */
                bool                                                                        StaticEchoReleasePort(uint32_t source_ip, int source_port) noexcept;
                /** @brief Returns the link telemetry object for this session. */
                ppp::diagnostics::LinkTelemetry&                                             GetLinkTelemetry() noexcept { return link_telemetry_; }
                ppp::app::mux::MuxCoordinator*                                              GetMuxCoordinator() noexcept { return mux_coordinator_.get(); }
                /**
                 * @brief Returns the preferred TUN file descriptor hint for the forwarding layer.
                 * @return TUN fd; -1 if none is set.
                 */
                int                                                                         GetPreferredTunFd() noexcept;
                /**
                 * @brief Sets the preferred TUN file descriptor hint for the forwarding layer.
                 * @param fd TUN fd value; -1 to clear.
                 */
                void                                                                        SetPreferredTunFd(int fd) noexcept;

            public:
                /** @brief IServerUdpRelayHost: hands the datagram manager the exchanger capabilities it needs (P2-e). */
                udp::ServerUdpRelayHostPorts                                                 BuildServerUdpRelayHostPorts() noexcept override;

                /** @brief IStaticUdpRelayHost: hands the static-echo manager the exchanger capabilities it needs (P2-f). */
                udp::StaticUdpRelayHostPorts                                                 BuildStaticUdpRelayHostPorts() noexcept override;

                /** @brief Parses a DNS response and stores it in the switcher namespace cache (moved off the port, P2-e-2). */
                static bool                                                                 NamespaceQueryCache(const std::shared_ptr<VirtualEthernetSwitcher>& switcher, const void* packet, int packet_length) noexcept;

            protected:  
                /**
                 * @brief Handles the client LAN announcement and registers the NAT binding.
                 *
                 * @param transmission Active transmission channel.
                 * @param ip           Client LAN IPv4 address (host-byte order).
                 * @param mask         Client LAN subnet mask (host-byte order).
                 * @param y            Coroutine yield context.
                 * @return True on success; false to tear down the session.
                 */
                virtual bool                                                                OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept override;

                /**
                 * @brief Handles a NAT packet from the client and forwards it to the correct peer or internet.
                 *
                 * @param transmission  Active transmission channel.
                 * @param packet        Raw IP packet buffer.
                 * @param packet_length Packet length in bytes.
                 * @param y             Coroutine yield context.
                 * @return True on success; false to tear down the session.
                 */
                virtual bool                                                                OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept override;

                /**
                 * @brief Rejects the legacy information message to prevent protocol abuse.
                 *
                 * @param transmission  Active transmission channel.
                 * @param information   Parsed information payload (ignored).
                 * @param y             Coroutine yield context.
                 * @return Always false; this command is not valid server-side.
                 */
                virtual bool                                                                OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept override;

                /**
                 * @brief Handles the extended information envelope (IPv6 address request exchange).
                 *
                 * @param transmission  Active transmission channel.
                 * @param information   Extended information envelope from the client.
                 * @param y             Coroutine yield context.
                 * @return True on success; false to tear down the session.
                 */
                virtual bool                                                                OnInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept override;

                /**
                 * @brief Rejects direct push commands for security hardening.
                 *
                 * @details The server never receives push commands directly; they are routed
                 *          through the TCP connection object.
                 * @return Always false.
                 */
                virtual bool                                                                OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept override;

                /**
                 * @brief Rejects direct connect commands for security hardening.
                 * @return Always false.
                 */
                virtual bool                                                                OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept override;

                /**
                 * @brief Rejects connect-ack commands for security hardening.
                 * @return Always false.
                 */
                virtual bool                                                                OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept override;

                /**
                 * @brief Rejects direct disconnect commands for security hardening.
                 * @return Always false.
                 */
                virtual bool                                                                OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept override;

                /**
                 * @brief Handles an echo acknowledgment (keepalive reply) from the client.
                 *
                 * @param transmission Active transmission channel.
                 * @param ack_id       Acknowledgment sequence identifier.
                 * @param y            Coroutine yield context.
                 * @return True on success.
                 */
                virtual bool                                                                OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept override;

                /**
                 * @brief Handles an ICMP echo packet from the client.
                 *
                 * @param transmission  Active transmission channel.
                 * @param packet        Raw ICMP packet buffer.
                 * @param packet_length Packet length in bytes.
                 * @param y             Coroutine yield context.
                 * @return True on success.
                 */
                virtual bool                                                                OnEcho(const ITransmissionPtr& transmission, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept override;

                /**
                 * @brief Handles a UDP sendto command from the client.
                 *
                 * @details Finds or creates a `VirtualEthernetDatagramPort` for `sourceEP`,
                 *          applies DNS redirect policy, and forwards the payload to `destinationEP`.
                 *
                 * @param transmission  Active transmission channel.
                 * @param sourceEP      Client-side UDP source endpoint.
                 * @param destinationEP UDP destination endpoint.
                 * @param packet        UDP payload buffer.
                 * @param packet_length Payload length in bytes.
                 * @param y             Coroutine yield context.
                 * @return True on success.
                 */
                virtual bool                                                                OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept override;

                /**
                 * @brief Handles a static-echo channel allocation request from the client.
                 *
                 * @param transmission Active transmission channel.
                 * @param y            Coroutine yield context.
                 * @return True if the allocation is sent to the client successfully.
                 */
                virtual bool                                                                OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept override;

                /**
                 * @brief Rejects the client-side static-echo control packet for security hardening.
                 * @return Always false; this direction is reserved for client-side only.
                 */
                virtual bool                                                                OnStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept override;

                /**
                 * @brief Handles a VMUX configuration request from the client.
                 *
                 * @param transmission     Active transmission channel.
                 * @param vlan             VLAN identifier for the VMUX session.
                 * @param max_connections  Maximum number of sub-connections.
                 * @param acceleration     True to enable hardware acceleration hints.
                 * @param y                Coroutine yield context.
                 * @return True if the VMUX instance is created and acknowledged.
                 */
                virtual bool                                                                OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, Byte ordering_caps, YieldContext& y) noexcept override;

            protected:  
                /**
                 * @brief Returns the firewall instance used for this session.
                 *
                 * @details Falls back to the switcher-level firewall if no session-level one
                 *          is set.
                 * @return Active firewall for packet filtering.
                 */
                virtual FirewallPtr                                                         GetFirewall() noexcept override;

                /**
                 * @brief Factory: creates the ICMP echo forwarding helper for this session.
                 *
                 * @param transmission Active transmission channel.
                 * @return Newly constructed ICMP helper; null on failure.
                 */
                virtual VirtualInternetControlMessageProtocolPtr                            NewEchoTransmissions(const ITransmissionPtr& transmission) noexcept;

                /**
                 * @brief Factory: creates a UDP datagram relay port for a source endpoint.
                 *
                 * @param transmission Active transmission channel.
                 * @param sourceEP     Source endpoint for which the port is created.
                 * @return Newly constructed datagram port; null on failure.
                 */
                virtual VirtualEthernetDatagramPortPtr                                      NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

                /**
                 * @brief Finds the existing datagram relay port for a source endpoint.
                 *
                 * @param sourceEP Source endpoint to look up.
                 * @return Existing port; null if not found.
                 */
                virtual VirtualEthernetDatagramPortPtr                                      GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

                /**
                 * @brief Removes and returns ownership of a datagram relay port.
                 *
                 * @param sourceEP Source endpoint whose port should be released.
                 * @return Released port; null if not found.
                 */
                virtual VirtualEthernetDatagramPortPtr                                      ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
    
            private:    
                /** @brief Synchronously finalizes all session resources and deregisters from switcher. */
                void                                                                        Finalize() noexcept;

                /**
                 * @brief Removes a DNS redirect timeout handler by its native key.
                 * @param k Raw pointer key of the timeout entry to remove.
                 * @return True if the entry was found and removed.
                 */
                bool                                                                        DeleteTimeout(void* k) noexcept;

                /**
                 * @brief Resolves the configured DNS redirect host and dispatches the redirect task.
                 *
                 * @param transmission   Active transmission channel.
                 * @param sourceEP       UDP source endpoint of the original query.
                 * @param destinationEP  Original DNS destination endpoint.
                 * @param packet         Original DNS query buffer.
                 * @param packet_length  Query buffer length in bytes.
                 * @param static_transit True to use the static-echo transit path.
                 * @return True if the redirect task is dispatched.
                 */
                bool                                                                        INTERNAL_RedirectDnsQuery(
                    const ITransmissionPtr&                                                 transmission, 
                    const boost::asio::ip::udp::endpoint&                                   sourceEP,
                    const boost::asio::ip::udp::endpoint&                                   destinationEP,
                    const std::shared_ptr<Byte>&                                            owner,
                    Byte*                                                                   packet, 
                    int                                                                     packet_length,
                    bool                                                                    static_transit) noexcept;

                /**
                 * @brief Sends the DNS query to the redirect endpoint and relays the async response.
                 *
                 * @param transmission   Active transmission channel (by value for coroutine capture).
                 * @param redirectEP     Redirect destination UDP endpoint.
                 * @param sourceEP       Original client-side source endpoint.
                 * @param destinationEP  Original DNS destination endpoint.
                 * @param packet         Shared DNS query buffer.
                 * @param packet_length  Query buffer length in bytes.
                 * @param static_transit True to use the static-echo transit path for the reply.
                 * @return True if the query is sent and the response is relayed.
                 */
                bool                                                                        INTERNAL_RedirectDnsQuery(
                    ITransmissionPtr                                                        transmission,
                    boost::asio::ip::udp::endpoint                                          redirectEP,
                    boost::asio::ip::udp::endpoint                                          sourceEP,
                    boost::asio::ip::udp::endpoint                                          destinationEP,
                    std::shared_ptr<Byte>                                                   packet,
                    int                                                                     packet_length,
                    bool                                                                    static_transit) noexcept;

                /**
                 * @brief Applies the DNS redirect policy and returns a redirect status code.
                 *
                 * @param transmission   Active transmission channel.
                 * @param sourceEP       UDP source endpoint of the query.
                 * @param destinationEP  Original DNS destination endpoint.
                 * @param packet         DNS query buffer.
                 * @param packet_length  Query buffer length in bytes.
                 * @param static_transit True to use the static-echo transit path.
                 * @return 1 if redirected; 0 if no redirect applies; -1 on error.
                 */
                int                                                                         RedirectDnsQuery(
                    const ITransmissionPtr&                                                 transmission, 
                    const boost::asio::ip::udp::endpoint&                                   sourceEP, 
                    const boost::asio::ip::udp::endpoint&                                   destinationEP, 
                    const std::shared_ptr<Byte>&                                            owner,
                    Byte*                                                                   packet, 
                    int                                                                     packet_length,
                    bool                                                                    static_transit) noexcept;
    
            private:    
                /**
                 * @brief Uploads per-session rx/tx traffic deltas to the managed server.
                 * @return True if the upload is queued or sent successfully.
                 */
                int                                                                         NamespaceQueryReply(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const ppp::string& domain, const void* packet, int packet_length, uint16_t queries_type, uint16_t queries_clazz, bool static_transit) noexcept;

                bool                                                                        UploadTrafficToManagedServer() noexcept;

                /**
                 * @brief Runs VMUX polling and tears down the VMUX instance on failure.
                 * @return True if the VMUX instance is healthy; false if it was torn down.
                 */
                bool                                                                        DoMuxEvents() noexcept;

                /**
                 * @brief Registers a NAT entry based on the LAN announcement IP and mask.
                 *
                 * @param transmission Active transmission channel.
                 * @param ip           Client LAN IPv4 address (host-byte order).
                 * @param mask         Client LAN subnet mask (host-byte order).
                 * @return True if the NAT entry is registered.
                 */
                bool                                                                        Arp(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask) noexcept;

                /**
                 * @brief Forwards an IPv4 NAT packet to the peer exchanger inside the managed subnet.
                 *
                 * @param packet        Raw IP packet buffer.
                 * @param packet_length Packet length in bytes.
                 * @param y             Coroutine yield context.
                 * @return True if the packet is forwarded successfully.
                 */
                bool                                                                        ForwardNatPacketToDestination(Byte* packet, int packet_length, YieldContext& y) noexcept;

                /**
                 * @brief Forwards an IPv6 packet to the local peer exchanger or transit gateway.
                 *
                 * @param packet        Raw IPv6 packet buffer.
                 * @param packet_length Packet length in bytes.
                 * @param y             Coroutine yield context.
                 * @return True if the packet is forwarded successfully.
                 */
                bool                                                                        ForwardIPv6PacketToDestination(Byte* packet, int packet_length, YieldContext& y) noexcept;

                /**
                 * @brief Parses and dispatches an ICMP echo packet to the ICMP echo subsystem.
                 *
                 * @param transmission  Active transmission channel.
                 * @param packet        Raw ICMP packet buffer.
                 * @param packet_length Packet length in bytes.
                 * @return True if the packet is dispatched.
                 */
                bool                                                                        SendEchoToDestination(const ITransmissionPtr& transmission, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length) noexcept;

                /**
                 * @brief Forwards a UDP payload to its destination via the per-source datagram port.
                 *
                 * @param transmission  Active transmission channel.
                 * @param sourceEP      Client-side UDP source endpoint.
                 * @param destinationEP UDP destination endpoint.
                 * @param packet        UDP payload buffer.
                 * @param packet_length Payload length in bytes.
                 * @param y             Coroutine yield context.
                 * @return True on successful forwarding.
                 */
                bool                                                                        SendPacketToDestination(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept;
    
            private:    
                /**
                 * @brief Allocates a static-echo relay session and returns the assignment to the client.
                 *
                 * @param transmission Active transmission channel.
                 * @param y            Coroutine yield context.
                 * @return True if the allocation message is sent to the client.
                 */
                bool                                                                        StaticEcho(const ITransmissionPtr& transmission, YieldContext& y) noexcept;


                /**
                 * @brief Forwards a static-echo UDP packet to its network destination.
                 *
                 * @param packet Parsed virtual ethernet packet to forward.
                 * @return True if the packet is sent.
                 */
                bool                                                                        StaticEchoSendToDestination(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet) noexcept;

                /**
                 * @brief Handles an ICMP packet received via the static-echo channel.
                 *
                 * @param packet   Parsed virtual ethernet packet carrying the ICMP payload.
                 * @param sourceEP UDP source endpoint of the static-echo sender.
                 * @return True if the packet is forwarded.
                 */
                bool                                                                        StaticEchoEchoToDestination(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
    
            private:    
                /**
                 * @brief Finds an existing FRP mapping port by direction, protocol, and remote port.
                 *
                 * @param in          True for inbound; false for outbound.
                 * @param tcp         True for TCP; false for UDP.
                 * @param remote_port Remote port number.
                 * @return Existing port; null if not found.
                 */
                VirtualEthernetMappingPortPtr                                               GetMappingPort(bool in, bool tcp, int remote_port) noexcept;

                /**
                 * @brief Creates a new FRP mapping port object for the given key.
                 *
                 * @param in          True for inbound; false for outbound.
                 * @param tcp         True for TCP; false for UDP.
                 * @param remote_port Remote port number.
                 * @return Newly created port; null on failure.
                 */
                VirtualEthernetMappingPortPtr                                               NewMappingPort(bool in, bool tcp, int remote_port) noexcept;

                /**
                 * @brief Opens and registers an FRP mapping port in the mapping table.
                 *
                 * @param in          True for inbound; false for outbound.
                 * @param tcp         True for TCP; false for UDP.
                 * @param remote_port Remote port number.
                 * @return True if the port is opened and registered.
                 */
                bool                                                                        RegisterMappingPort(bool in, bool tcp, int remote_port) noexcept;
    
            private:    
                /**
                 * @brief Runs the base keepalive logic without deciding session recovery lifecycle.
                 *
                 * @param transmission Active transmission channel.
                 * @param now          Current tick count in milliseconds.
                 * @return True if keepalive sent; false when the carrier should stop.
                 */
                virtual bool                                                                DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept override;

                /**
                 * @brief Handles an FRP port-mapping entry notification from the client.
                 *
                 * @param transmission  Active transmission channel.
                 * @param tcp           True for TCP; false for UDP.
                 * @param in            True for inbound mapping; false for outbound.
                 * @param remote_port   Remote port number to expose.
                 * @param y             Coroutine yield context.
                 * @return True on success.
                 */
                virtual bool                                                                OnFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept override;

                /**
                 * @brief Handles an FRP UDP data packet from the client.
                 *
                 * @param transmission  Active transmission channel.
                 * @param in            True for inbound; false for outbound.
                 * @param remote_port   Remote port number of the mapping.
                 * @param sourceEP      UDP source endpoint.
                 * @param packet        UDP payload buffer.
                 * @param packet_length Payload length in bytes.
                 * @param y             Coroutine yield context.
                 * @return True on success.
                 */
                virtual bool                                                                OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, const std::shared_ptr<Byte>& owner, Byte* packet, int packet_length, YieldContext& y) noexcept override;

                /**
                 * @brief Handles an FRP TCP connect-acknowledgment from the client.
                 *
                 * @param transmission  Active transmission channel.
                 * @param connection_id FRP TCP sub-connection identifier.
                 * @param in            True for inbound; false for outbound.
                 * @param remote_port   Remote port number of the mapping.
                 * @param error_code    Zero on success; non-zero on connect failure.
                 * @param y             Coroutine yield context.
                 * @return True on success.
                 */
                virtual bool                                                                OnFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept override;

                /**
                 * @brief Handles an FRP TCP disconnect notification from the client.
                 *
                 * @param transmission  Active transmission channel.
                 * @param connection_id FRP TCP sub-connection identifier.
                 * @param in            True for inbound; false for outbound.
                 * @param remote_port   Remote port number of the mapping.
                 * @return True on success.
                 */
                virtual bool                                                                OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept override;

                /**
                 * @brief Handles an FRP TCP stream payload from the client.
                 *
                 * @param transmission  Active transmission channel.
                 * @param connection_id FRP TCP sub-connection identifier.
                 * @param in            True for inbound; false for outbound.
                 * @param remote_port   Remote port number of the mapping.
                 * @param packet        TCP stream payload buffer.
                 * @param packet_length Payload length in bytes.
                 * @return True on success.
                 */
                virtual bool                                                                OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const std::shared_ptr<Byte>& owner, const void* packet, int packet_length) noexcept override;
    
            private:    
                SynchronizedObject                                                          syncobj_;                   ///< Guards datagrams_, timeouts_, and mappings_.
                std::atomic_bool                                                            disposed_{false};           ///< Atomic one-shot flag; true after Dispose()/Finalize().
                uint32_t                                                                    address_  = 0;              ///< Client LAN IPv4 address registered in NAT table.
                int                                                                         preferred_tun_fd_ = -1;     ///< Preferred TUN fd hint for the forwarding layer.
                VirtualEthernetSwitcherPtr                                                  switcher_;                  ///< Parent switcher reference.
                std::shared_ptr<Byte>                                                       buffer_;                    ///< Shared scratch buffer for packet processing.
                FirewallPtr                                                                 firewall_;                  ///< Session-level firewall (may fall back to switcher-level).
                TimeoutEventHandlerTable                                                    timeouts_;                  ///< Active DNS redirect timeout handlers.
                VirtualInternetControlMessageProtocolPtr                                    echo_;                      ///< ICMP echo forwarding helper.
                std::unique_ptr<udp::ServerDatagramPortManager>                             datagram_manager_;          ///< Owns the UDP relay session table (extracted P2-e).
                std::unique_ptr<udp::StaticDatagramPortManager>                             static_datagram_manager_;   ///< Owns the static-echo relay session table (extracted P2-f).
                mutable std::mutex                                                          carrier_mutex_;             ///< Guards carrier pointer, generation, and authenticated recovery state.
                SessionRecoveryState                                                        recovery_state_;            ///< Same-process carrier recovery state machine.
                ppp::app::protocol::SessionResumeId                                         recovery_session_id_{};      ///< Canonical binary session identifier.
                ppp::app::protocol::SessionResumeSecret                                     retained_root_;             ///< Root retained only after authenticated fresh acceptance.
                ppp::app::protocol::SessionResumeSecret                                     pending_fresh_root_;        ///< Temporary root awaiting fresh acceptance.
                ppp::app::protocol::SessionResumeNonce                                      pending_fresh_server_nonce_{}; ///< Fresh offer nonce.
                ITransmissionPtr                                                            pending_fresh_transmission_; ///< Carrier allowed to accept the fresh offer.
                UInt64                                                                      pending_fresh_deadline_ = 0; ///< Monotonic deadline for unaccepted fresh offers.
                bool                                                                        recovery_armed_ = false;      ///< True only after fresh proof verification.
                ppp::app::protocol::SessionResumePendingAttempt                             resume_attempt_;            ///< Authenticated reserved resume transaction.
                ITransmissionPtr                                                            resume_candidate_;          ///< Carrier owning the current reservation.
                VirtualInternetControlMessageProtocolPtr                                    resume_replacement_echo_;   ///< Prepared echo helper, unpublished until committed INFO is sent.
                ITransmissionStatisticsPtr                                                  resume_replacement_statistics_; ///< Prepared carrier statistics for publication.
                std::uint64_t                                                               next_resume_token_ = 0;      ///< Monotonic nonzero local reservation token.
                ITransmissionPtr                                                            transmission_;              ///< Active session transmission channel.
                VirtualEthernetManagedServerPtr                                             managed_server_;            ///< Go managed-server bridge reference.
                ITransmissionStatisticsPtr                                                  statistics_last_;           ///< Statistics snapshot from the previous upload tick.
                VirtualEthernetMappingPortTable                                             mappings_;                  ///< Active FRP port-mapping objects.
                ITransmissionStatisticsPtr                                                  statistics_;                ///< Current traffic statistics for this session.
                ppp::diagnostics::LinkTelemetry                                             link_telemetry_;            ///< Per-session link fault telemetry.
                std::unique_ptr<ppp::app::mux::MuxCoordinator>                              mux_coordinator_;           ///< Owns the VMUX session and runtime projection.

                std::shared_ptr<VirtualInternetControlMessageProtocolStatic>                static_echo_;                       ///< Static-echo ICMP forwarding helper.
                VirtualEthernetStaticEchoAllocatedContextPtr                                static_allocated_context_;          ///< Active static-echo allocation context.
                boost::asio::ip::udp::endpoint                                              static_echo_source_ep_;             ///< Most-recent static-echo sender endpoint.
                std::atomic<int>                                                            static_echo_session_id_ = 0;        ///< Atomic slot index for the static-echo session.
            };
        }
    }
}
