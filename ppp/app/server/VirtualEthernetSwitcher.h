#pragma once

/**
 * @file VirtualEthernetSwitcher.h
 * @brief Declares the server-side virtual ethernet switcher and its control helpers.
 *
 * @details `VirtualEthernetSwitcher` is the central server component that:
 *          - Accepts inbound TCP connections over plain TCP, WebSocket, WebSocket/TLS,
 *            and two CDN relay transports (`CDN1`, `CDN2`).
 *          - Performs initial protocol handshake ("flower arrangement") and creates
 *            per-session `VirtualEthernetExchanger` objects.
 *          - Manages IPv4 NAT ownership tables and IPv6 lease / transit plane.
 *          - Maintains a static-echo UDP channel for low-latency bypass datagrams.
 *          - Integrates with the Go managed-server backend via `VirtualEthernetManagedServer`.
 *          - Caches DNS responses via `VirtualEthernetNamespaceCache`.
 *
 *          State machine:
 *          - `Open()`    — binds acceptors, opens logger, managed server, static-echo socket.
 *          - `Run()`     — starts accept coroutines and periodic tick timer.
 *          - `Dispose()` — tears down all acceptors, exchangers, connections and resources.
 *
 *          Thread safety:
 *          - `syncobj_` (std::mutex) guards all shared tables (`exchangers_`, `nats_`,
 *            `ipv6s_`, `connections_`, `static_echo_allocateds_`, IPv6 lease/request tables).
 *          - A separate `static_echo_syncobj_` exists on `VirtualEthernetExchanger` for
 *            static-echo state — do not mix the two locks.
 *          - IO-bound operations run on the single `context_` io_context.
 *
 * @license GPL-3.0
 */

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/net/Firewall.h>
#include <ppp/net/native/rib.h>
#include <ppp/threading/Timer.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
namespace ppp::configurations { class AppConfiguration; }
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/app/server/IPv4LeasePool.h>
#include <ppp/p2p/P2PNatClassifier.h>
#include <ppp/tap/ITap.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualInternetControlMessageProtocolStatic;
            class VirtualEthernetManagedServer;
            class VirtualEthernetExchanger;
            class VirtualEthernetNetworkTcpipConnection;
            class VirtualEthernetNamespaceCache;

            /**
             * @brief Coordinates virtual ethernet sessions, forwarding, and control planes.
             *
             * @details This class is the main orchestrator for the server mode of openppp2.
             *          It owns all per-session exchangers, the firewall, the static-echo UDP
             *          relay, the IPv4 NAT table, and the IPv6 transit TAP device.
             *
             * @note Must be created via `std::make_shared<VirtualEthernetSwitcher>(...)` so
             *       that `shared_from_this()` works from any member function.
             */
            class VirtualEthernetSwitcher : public std::enable_shared_from_this<VirtualEthernetSwitcher> {
                friend class                                            VirtualEthernetNetworkTcpipConnection;
                friend class                                            VirtualEthernetExchanger;
                friend class                                            VirtualEthernetManagedServer;
                friend class                                            VirtualInternetControlMessageProtocolStatic;
                friend class                                            VirtualEthernetDatagramPortStatic;

                /**
                 * @brief Stores NAT ownership and subnet mask for one assigned IPv4 address.
                 *
                 * @details Each `VirtualEthernetExchanger` announces its LAN (IP + mask) via
                 *          `OnLan()`.  The switcher records this information in `nats_` so that
                 *          inbound packets destined for that IP can be forwarded to the right
                 *          exchanger.
                 *
                 * Structure fields:
                 *   - IPAddress      = uint32_t  ///< Assigned client IPv4 address (host-byte order).
                 *   - SubmaskAddress = uint32_t  ///< Subnet mask (host-byte order).
                 *   - Exchanger      = shared_ptr<VirtualEthernetExchanger>  ///< Owning exchanger.
                 */
                struct NatInformation {
                    uint32_t                                            IPAddress;      ///< Assigned client IPv4 address (host-byte order).
                    uint32_t                                            SubmaskAddress; ///< Subnet mask (host-byte order).
                    std::shared_ptr<VirtualEthernetExchanger>           Exchanger;      ///< Exchanger that owns this NAT entry.
                };
                typedef std::shared_ptr<NatInformation>                 NatInformationPtr;
                typedef std::unordered_map<uint32_t, NatInformationPtr> NatInformationTable;
                typedef std::unordered_map<ppp::string, std::shared_ptr<class VirtualEthernetExchanger>> IPv6ExchangerTable;

                /**
                 * @brief Tracks the IPv6 assignment request/response state for one session.
                 *
                 * @details Populated by `UpdateIPv6Request()` and consumed by
                 *          `BuildInformationIPv6Extensions()`.
                 *
                 * Structure fields:
                 *   - Present         = bool     ///< True if a request has been received.
                 *   - Accepted        = bool     ///< True if the request was granted.
                 *   - StatusCode      = Byte     ///< IPv6Status_* code from protocol.
                 *   - RequestedAddress= address  ///< Address requested by the client.
                 *   - StatusMessage   = string   ///< Human-readable status detail.
                 */
                struct IPv6RequestEntry {
                    bool                                                 Present = false;         ///< True after a request is received.
                    bool                                                 Accepted = false;        ///< True when the request is granted.
                    Byte                                                 StatusCode = VirtualEthernetInformationExtensions::IPv6Status_None; ///< Protocol status code.
                    boost::asio::ip::address                             RequestedAddress;        ///< Client-requested IPv6 address.
                    ppp::string                                          StatusMessage;           ///< Human-readable status message.
                };

                /**
                 * @brief Represents an active IPv6 lease bound to one session.
                 *
                 * @details Leases are created by `AddIPv6Exchanger()` and expired by
                 *          `TickIPv6Leases()`.
                 *
                 * Structure fields:
                 *   - SessionId          = Int128   ///< Owning session identifier.
                 *   - ExpiresAt          = UInt64   ///< Expiry tick (milliseconds).
                 *   - Address            = address  ///< Assigned IPv6 address.
                 *   - AddressPrefixLength= Byte     ///< Prefix length of the assigned address.
                 *   - StaticBinding      = bool     ///< True if the binding is permanent.
                 */
                struct IPv6LeaseEntry {
                    Int128                                               SessionId = 0;            ///< Session that owns this lease.
                    UInt64                                               ExpiresAt = 0;            ///< Expiry timestamp in milliseconds.
                    boost::asio::ip::address                             Address;                  ///< Leased IPv6 address.
                    Byte                                                 AddressPrefixLength = 0;  ///< Prefix length.
                    bool                                                 StaticBinding = false;    ///< True for permanent static bindings.
                };
                typedef ppp::unordered_map<Int128, IPv6RequestEntry>     IPv6RequestTable;
                typedef ppp::unordered_map<Int128, IPv6LeaseEntry>       IPv6LeaseTable;

            public:
                struct P2PPeerRecord {
                    Int128                                               SessionId = 0;            ///< Session that owns this peer record.
                    uint32_t                                             VirtualIP = 0;            ///< Client virtual IPv4 in network byte order.
                    ppp::string                                          Mode;                     ///< Client-requested P2P mode.
                    boost::asio::ip::udp::endpoint                       ObservedEndpoint;         ///< Authenticated static-echo UDP source endpoint.
                    ppp::vector<ppp::app::protocol::P2PEndpointCandidate> Candidates;              ///< Client-advertised UDP/STUN candidates.
                    UInt64                                               LastSeen = 0;             ///< Last control update tick.
                    UInt64                                               LastOfferAt = 0;          ///< Last peer-offer send tick for coarse throttling.
                    UInt64                                               LastOfferGeneration = 0;  ///< Unique owner of the current asynchronous offer reservation.
                    std::weak_ptr<VirtualEthernetExchanger>              Exchanger;                ///< Owning exchanger.
                    ppp::p2p::P2PNatType                                 NatType = ppp::p2p::P2PNatType::Unknown; ///< Inferred NAT type from relay traffic.
                };
                typedef ppp::unordered_map<Int128, P2PPeerRecord>        P2PPeerTable;

                struct PeerPrefixGatewayRecord {
                    Int128                                               SessionId = 0;            ///< Session that owns the gateway prefixes.
                    uint32_t                                             VirtualIP = 0;            ///< Gateway peer virtual IPv4 in network byte order.
                    ppp::vector<ppp::app::protocol::PeerPrefixRouteEntry> Prefixes;              ///< Prefixes reachable via this gateway peer.
                    std::weak_ptr<VirtualEthernetExchanger>              Exchanger;                ///< Owning exchanger.
                };
                typedef ppp::unordered_map<Int128, PeerPrefixGatewayRecord> PeerPrefixGatewayTable;

            private:
                typedef ppp::cryptography::Ciphertext                   Ciphertext;
                typedef std::shared_ptr<Ciphertext>                     CiphertextPtr;

            public:
                typedef ppp::app::protocol::VirtualEthernetInformation  VirtualEthernetInformation;
                typedef ppp::app::protocol::VirtualEthernetInformationExtensions VirtualEthernetInformationExtensions;
                typedef ppp::app::protocol::VirtualEthernetLinklayer::InformationEnvelope InformationEnvelope;
                typedef std::shared_ptr<VirtualEthernetInformation>     VirtualEthernetInformationPtr;
                typedef std::shared_ptr<VirtualEthernetExchanger>       VirtualEthernetExchangerPtr;
                typedef ppp::unordered_map<Int128,
                    VirtualEthernetExchangerPtr>                        VirtualEthernetExchangerTable;
                typedef std::shared_ptr<VirtualEthernetManagedServer>   VirtualEthernetManagedServerPtr;
                typedef std::shared_ptr<ppp::tap::ITap>                 ITapPtr;
                typedef ppp::app::protocol::VirtualEthernetLogger       VirtualEthernetLogger;
                typedef std::shared_ptr<VirtualEthernetLogger>          VirtualEthernetLoggerPtr;
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::transmissions::ITransmission               ITransmission;
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                typedef ppp::threading::Timer                           Timer;
                typedef std::shared_ptr<Timer>                          TimerPtr;
                typedef ppp::net::Firewall                              Firewall;
                typedef std::shared_ptr<ppp::net::Firewall>             FirewallPtr;
                typedef std::shared_ptr<boost::asio::io_context>        ContextPtr;
                typedef ppp::coroutines::YieldContext                   YieldContext;
                typedef std::mutex                                      SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
                typedef ppp::transmissions::ITransmissionStatistics     ITransmissionStatistics;
                typedef std::shared_ptr<ITransmissionStatistics>        ITransmissionStatisticsPtr;
                typedef std::shared_ptr<
                    VirtualEthernetNetworkTcpipConnection>              VirtualEthernetNetworkTcpipConnectionPtr;
                typedef ppp::unordered_map<void*,
                    VirtualEthernetNetworkTcpipConnectionPtr>           VirtualEthernetNetworkTcpipConnectionTable;

                /**
                 * @brief Stores cryptographic context for one allocated static-echo channel.
                 *
                 * @details Static-echo channels bypass the main session transmission path and
                 *          deliver datagrams directly via a dedicated UDP socket.  Each allocated
                 *          slot receives its own cipher contexts so that it is cryptographically
                 *          isolated from other slots.
                 *
                 * Structure fields:
                 *   - guid      = Int128                        ///< Global unique ID for this allocation.
                 *   - fsid      = Int128                        ///< File-system (session) ID.
                 *   - myid      = int                           ///< Local slot index.
                 *   - transport = shared_ptr<Ciphertext>        ///< Transport-layer cipher.
                 *   - protocol  = shared_ptr<Ciphertext>        ///< Protocol-layer cipher.
                 */
                struct VirtualEthernetStaticEchoAllocatedContext {
                    Int128                                              guid = 0;       ///< Global unique allocation identifier.
                    Int128                                              fsid = 0;       ///< Session file-system identifier.
                    int                                                 myid = 0;       ///< Local allocation slot index.
                    std::shared_ptr<ppp::cryptography::Ciphertext>      transport;      ///< Transport-layer cipher context.
                    std::shared_ptr<ppp::cryptography::Ciphertext>      protocol;       ///< Protocol-layer cipher context.
                };
                typedef std::shared_ptr<
                    VirtualEthernetStaticEchoAllocatedContext>          VirtualEthernetStaticEchoAllocatedContextPtr;
                typedef ppp::unordered_map<int,
                    VirtualEthernetStaticEchoAllocatedContextPtr>       VirtualEthernetStaticEchoAllocatedTable;
                typedef ppp::app::server::VirtualEthernetNamespaceCache VirtualEthernetNamespaceCache;
                typedef std::shared_ptr<VirtualEthernetNamespaceCache>  VirtualEthernetNamespaceCachePtr;

            public:
                /**
                 * @brief Creates a virtual switcher instance.
                 *
                 * @param configuration Shared application configuration snapshot.
                 * @param tun_name      Optional name of the TUN/TAP interface for IPv6 transit;
                 *                      empty string disables the transit plane.
                 * @param tun_ssmt      Number of SSMT worker io_contexts for the transit TAP;
                 *                      0 means single-threaded.
                 * @param tun_ssmt_mq   When true, enables multi-queue mode on the transit TAP.
                 */
                VirtualEthernetSwitcher(const AppConfigurationPtr& configuration, const ppp::string& tun_name = ppp::string(), int tun_ssmt = 0, bool tun_ssmt_mq = false) noexcept;

                /**
                 * @brief Destroys the switcher and releases all owned resources.
                 *
                 * @details Calls `Finalize()` to ensure all acceptors, exchangers, and the
                 *          static-echo socket are closed even if `Dispose()` was never called.
                 */
                virtual ~VirtualEthernetSwitcher() noexcept;

            public:
                /** @brief Gets the configured logical node identifier from configuration. */
                int                                                     GetNode() noexcept;
                /** @brief Gets a shared self-reference via `shared_from_this()`. */
                std::shared_ptr<VirtualEthernetSwitcher>                GetReference() noexcept          { return shared_from_this(); }
                /** @brief Gets the firewall instance used to filter inbound sessions. */
                FirewallPtr                                             GetFirewall() noexcept           { return firewall_; }
                /** @brief Gets the primary Boost.Asio io_context. */
                ContextPtr                                              GetContext() noexcept            { return context_; }
                /** @brief Gets the active application configuration snapshot. */
                AppConfigurationPtr                                     GetConfiguration() noexcept      { return configuration_; }
                /** @brief Gets the internal synchronization mutex (guards all shared tables). */
                SynchronizedObject&                                     GetSynchronizedObject() noexcept { return syncobj_; }
                /** @brief Gets the virtual ethernet session logger. */
                VirtualEthernetLoggerPtr                                GetLogger() noexcept             { return logger_; }
                /** @brief Gets the managed-server bridge (may be null if not configured). */
                VirtualEthernetManagedServerPtr                         GetManagedServer() noexcept      { return managed_server_; }
                /** @brief Gets the DNS namespace cache (may be null if TTL is zero). */
                VirtualEthernetNamespaceCachePtr                        GetNamespaceCache() noexcept     { return namespace_cache_; }
                /**
                 * @brief Sets the preferred NIC name used for routing and proxy operations.
                 * @param nic Interface name string (e.g. `"eth0"`).
                 */
                void                                                    PreferredNic(const ppp::string& nic) noexcept { preferred_nic_ = nic; }

            public:
                /**
                 * @brief Opens switcher services including firewall, acceptors, and the static-echo socket.
                 *
                 * @param firewall Path to the firewall ruleset file; empty to disable.
                 * @return True on success; false if any critical resource fails to open.
                 */
                virtual bool                                            Open(const ppp::string& firewall) noexcept;

                /**
                 * @brief Runs the accept coroutines and starts the periodic maintenance timer.
                 *
                 * @return True if all coroutines and the timer are scheduled successfully.
                 */
                virtual bool                                            Run() noexcept;

                /**
                 * @brief Disposes all switcher resources including acceptors, exchangers, and connections.
                 *
                 * @details Sets `disposed_ = true` and delegates to `Finalize()`.  Safe to call
                 *          multiple times; subsequent calls are no-ops.
                 */
                virtual void                                            Dispose() noexcept;
                void                                                    Dispose(ppp::function<void()> completion) noexcept;

                /**
                 * @brief Returns true if the switcher has been disposed.
                 * @return Disposal state.
                 */
                virtual bool                                            IsDisposed() noexcept;
                bool                                                    IsRunning() const noexcept { return running_.load(std::memory_order_acquire); }

            public:
                /** @brief Gets the global traffic statistics collector. */
                ITransmissionStatisticsPtr&                             GetStatistics() noexcept        { return statistics_; }
                /** @brief Gets the local interface IP address used by the switcher. */
                boost::asio::ip::address                                GetInterfaceIP() noexcept       { return interfaceIP_; }
                /** @brief Gets the configured DNS upstream UDP endpoint. */
                boost::asio::ip::udp::endpoint                          GetDnsserverEndPoint() noexcept { return dnsserverEP_; }
                /** @brief Returns the count of currently active exchanger sessions. */
                int                                                     GetAllExchangerNumber() noexcept;

                /**
                 * @brief Returns the IPv6 data-plane runtime state.
                 *
                 * @details Encoding:
                 *  - 0 = off (IPv6 disabled or not yet opened)
                 *  - 1 = nat66 (NAT66 transit plane active)
                 *  - 2 = gua  (GUA transit plane with NDP proxy active)
                 *  - 3 = failed (transit plane attempted but could not be established)
                 *
                 * @return Atomic load with acquire semantics for safe cross-thread reads.
                 */
                uint8_t                                                 GetIPv6RuntimeState() noexcept { return ipv6_runtime_state_.load(std::memory_order_acquire); }

                /**
                 * @brief Returns the error code that caused the last IPv6 plane failure.
                 *
                 * @details Set atomically whenever the transit plane transitions to
                 *          state 3 (failed).  Zero when no failure has occurred.
                 *
                 * @return Atomic load with acquire semantics.
                 */
                uint32_t                                                GetIPv6RuntimeCause() noexcept { return ipv6_runtime_cause_.load(std::memory_order_acquire); }

            public:
                /**
                 * @brief Enumerates inbound TCP acceptor categories used by the switcher.
                 *
                 * @details Each category maps to one acceptor in `acceptors_[]`.
                 *
                 *  - `NetworkAcceptorCategories_Tcpip`      — plain TCP acceptor.
                 *  - `NetworkAcceptorCategories_WebSocket`  — WebSocket acceptor.
                 *  - `NetworkAcceptorCategories_WebSocketSSL` — WebSocket/TLS acceptor.
                 *  - `NetworkAcceptorCategories_CDN1`       — first CDN relay acceptor.
                 *  - `NetworkAcceptorCategories_CDN2`       — second CDN relay acceptor.
                 *  - `NetworkAcceptorCategories_Udpip`      — UDP static-echo acceptor (sentinel).
                 */
                typedef enum {
                    NetworkAcceptorCategories_Min,
                    NetworkAcceptorCategories_Tcpip       = NetworkAcceptorCategories_Min, ///< Plain TCP acceptor.
                    NetworkAcceptorCategories_WebSocket,                                   ///< WebSocket acceptor.
                    NetworkAcceptorCategories_WebSocketSSL,                                ///< WebSocket/TLS acceptor.
                    NetworkAcceptorCategories_CDN1,                                        ///< CDN relay acceptor 1.
                    NetworkAcceptorCategories_CDN2,                                        ///< CDN relay acceptor 2.
                    NetworkAcceptorCategories_Max,
                    NetworkAcceptorCategories_Udpip       = NetworkAcceptorCategories_Max, ///< UDP static-echo (sentinel).
                }                                                       NetworkAcceptorCategories;

                /**
                 * @brief Gets the local TCP endpoint bound for a given acceptor category.
                 *
                 * @param categories Acceptor category to query.
                 * @return Bound endpoint; default-constructed when the acceptor is not open.
                 */
                boost::asio::ip::tcp::endpoint                          GetLocalEndPoint(NetworkAcceptorCategories categories) noexcept;

            protected:
                /**
                 * @brief Creates and returns a transmission object for an accepted socket.
                 *
                 * @param categories Acceptor category that produced the socket.
                 * @param context    I/O context for the new transmission.
                 * @param socket     Accepted TCP socket (ownership transferred).
                 * @return Newly constructed transmission, or null on failure.
                 */
                virtual ITransmissionPtr                                Accept(int categories, const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;

                /**
                 * @brief Completes protocol-level session establishment after handshake.
                 *
                 * @param transmission Active transmission channel.
                 * @param session_id   Negotiated 128-bit session identifier.
                 * @param i            Virtual ethernet information from the client.
                 * @param y            Coroutine yield context.
                 * @return True if the session is successfully established.
                 */
                virtual bool                                            Establish(const ITransmissionPtr& transmission, const Int128& session_id, const VirtualEthernetInformationPtr& i, YieldContext& y) noexcept;

                /**
                 * @brief Performs the protocol connect handshake for a new transmission.
                 *
                 * @param transmission Active transmission channel.
                 * @param session_id   128-bit session identifier assigned to this session.
                 * @param y            Coroutine yield context.
                 * @return 0 on success; negative on protocol error; positive on soft failure.
                 */
                virtual int                                             Connect(const ITransmissionPtr& transmission, const Int128& session_id, YieldContext& y) noexcept;

                /**
                 * @brief Handles one periodic maintenance tick.
                 *
                 * @param now Current monotonic tick count in milliseconds.
                 * @return True to continue ticking; false to stop the timer.
                 */
                virtual bool                                            OnTick(UInt64 now) noexcept;

                /**
                 * @brief Handles a control information packet for a specific session.
                 *
                 * @param session_id Session that sent the information packet.
                 * @param info       Parsed information payload.
                 * @param y          Coroutine yield context.
                 * @return True on success; false if the session should be torn down.
                 */
                virtual bool                                            OnInformation(const Int128& session_id, const std::shared_ptr<VirtualEthernetInformation>& info, YieldContext& y) noexcept;

            protected:
                /** @brief Factory: creates the virtual ethernet session logger. */
                virtual VirtualEthernetLoggerPtr                        NewLogger() noexcept;
                /** @brief Factory: creates the Go managed-server bridge. */
                virtual VirtualEthernetManagedServerPtr                 NewManagedServer() noexcept;
                /** @brief Factory: creates the packet firewall instance. */
                virtual FirewallPtr                                     NewFirewall() noexcept;
                /**
                 * @brief Factory: creates the DNS namespace cache with the given TTL.
                 * @param ttl Cache entry TTL in seconds.
                 */
                virtual VirtualEthernetNamespaceCachePtr                NewNamespaceCache(int ttl) noexcept;
                /** @brief Factory: creates the transmission statistics collector. */
                virtual ITransmissionStatisticsPtr                      NewStatistics() noexcept;
                /**
                 * @brief Factory: creates an exchanger for a connected session.
                 * @param transmission Active transmission channel.
                 * @param session_id   Session identifier.
                 */
                virtual VirtualEthernetExchangerPtr                     NewExchanger(const ITransmissionPtr& transmission, const Int128& session_id) noexcept;
                /**
                 * @brief Factory: creates a TCP/IP connection wrapper for a session.
                 * @param transmission Active transmission channel.
                 * @param session_id   Session identifier.
                 */
                virtual VirtualEthernetNetworkTcpipConnectionPtr        NewConnection(const ITransmissionPtr& transmission, const Int128& session_id) noexcept;

            private:
                /** @brief Releases all owned resources synchronously. */
                void                                                    Finalize() noexcept;
                void                                                    Finalize(ppp::function<void()> completion) noexcept;
                /**
                 * @brief Accepts a socket and dispatches it under the specified category.
                 * @param context    I/O context for the new connection.
                 * @param socket     Accepted socket.
                 * @param categories Acceptor category that produced the socket.
                 * @return True if the connection is dispatched.
                 */
                bool                                                    Accept(const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, int categories) noexcept;
                /**
                 * @brief Runs the protocol processing loop for one transmission.
                 * @param context      I/O context.
                 * @param transmission Active transmission.
                 * @param y            Coroutine yield context.
                 * @return 0 on clean exit; non-zero on error.
                 */
                int                                                     Run(const ContextPtr& context, const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                /**
                 * @brief Authenticates a negotiated plain TCP/WebSocket carrier before session dispatch.
                 * @return True for a completed authentication or a policy-gated legacy bypass.
                 */
                bool                                                    AuthenticatePlainTransport(const ITransmissionPtr& transmission, const Int128& session_id, YieldContext& y) noexcept;
                /**
                 * @brief Removes an exchanger from the table by raw pointer key.
                 * @param exchanger Raw pointer used as the lookup key.
                 * @return Shared pointer to the removed exchanger; null if not found.
                 */
                VirtualEthernetExchangerPtr                             DeleteExchanger(VirtualEthernetExchanger* exchanger) noexcept;
                /**
                 * @brief Finds an exchanger by 128-bit session identifier.
                 * @param session_id Session to look up.
                 * @return Shared pointer to the exchanger; null if not found.
                 */
                VirtualEthernetExchangerPtr                             GetExchanger(const Int128& session_id) noexcept;
                /**
                 * @brief Creates and registers a new exchanger for a session.
                 * @param transmission Active transmission channel.
                 * @param session_id   Session identifier.
                 * @return Shared pointer to the newly registered exchanger; null on failure.
                 */
                VirtualEthernetExchangerPtr                             AddNewExchanger(const ITransmissionPtr& transmission, const Int128& session_id) noexcept;
                /**
                 * @brief Creates and registers a new TCP/IP connection object.
                 * @param transmission Active transmission channel.
                 * @param session_id   Session identifier.
                 * @return Shared pointer to the registered connection; null on failure.
                 */
                VirtualEthernetNetworkTcpipConnectionPtr                AddNewConnection(const ITransmissionPtr& transmission, const Int128& session_id) noexcept;
                /**
                 * @brief Removes a registered TCP/IP connection from the table.
                 * @param connection Raw pointer key of the connection to remove.
                 * @return True if the connection was found and removed.
                 */
                bool                                                    DeleteConnection(const VirtualEthernetNetworkTcpipConnection* connection) noexcept;

            private:
                /**
                 * @brief Parses a DNS server endpoint string into a UDP endpoint.
                 * @param dnserver_endpoint Endpoint string in `"host:port"` format.
                 * @return Parsed UDP endpoint; default-constructed on parse failure.
                 */
                boost::asio::ip::udp::endpoint                          ParseDNSEndPoint(const ppp::string& dnserver_endpoint) noexcept;
                /**
                 * @brief Calls `Update()` on all active exchangers.
                 * @param now Current tick count in milliseconds.
                 */
                void                                                    TickAllExchangers(UInt64 now) noexcept;
                /**
                 * @brief Calls `Update()` on all active TCP/IP connections.
                 * @param now Current tick count in milliseconds.
                 */
                void                                                    TickAllConnections(UInt64 now) noexcept;
                /** @brief Starts the managed server if the URL is configured. */
                bool                                                    OpenManagedServerIfNeed() noexcept;
                /** @brief Returns true if the runtime and platform support IPv6 data plane. */
                bool                                                    SupportsIPv6DataPlane() noexcept;
                /** @brief Returns true if the server-side IPv6 feature is enabled in configuration. */
                bool                                                    IsIPv6ServerEnabled() noexcept;
                /** @brief Opens the IPv6 transit TAP device and starts SSMT workers if needed. */
                bool                                                    OpenIPv6TransitIfNeed() noexcept;
                /**
                 * @brief Spawns SSMT io_context workers for the IPv6 transit TAP device.
                 * @param tap Shared TAP device to bind workers to.
                 * @return True if all SSMT contexts are started.
                 */
                bool                                                    OpenIPv6TransitSsmtIfNeed(const ITapPtr& tap) noexcept;
                /** @brief Stops and destroys all IPv6 transit SSMT io_contexts. */
                void                                                    CloseIPv6TransitSsmtContexts() noexcept;
                /** @brief Returns the configured IPv6 transit gateway address. */
                boost::asio::ip::address                                GetIPv6TransitGateway() noexcept;

            private:
                /**
                 * @brief Releases a static-echo allocation slot and returns its context.
                 * @param allocated_id Slot index to release.
                 * @return Removed context; null if the slot was not found.
                 */
                VirtualEthernetStaticEchoAllocatedContextPtr            StaticEchoUnallocated(int allocated_id) noexcept;
                /**
                 * @brief Retrieves the static-echo context for a given allocation id.
                 * @param allocated_id           Slot index to query.
                 * @param allocated_context[out] Filled with the context on success.
                 * @return True if the slot is found and `allocated_context` is set.
                 */
                bool                                                    StaticEchoQuery(int allocated_id, VirtualEthernetStaticEchoAllocatedContextPtr& allocated_context) noexcept;
                /**
                 * @brief Allocates a new static-echo slot for a session.
                 * @param session_id     Owning session identifier.
                 * @param allocated_id[out]  Assigned slot index.
                 * @param remote_port[out]   Assigned remote UDP port.
                 * @return Shared pointer to the new context; null if no slot is available.
                 */
                VirtualEthernetStaticEchoAllocatedContextPtr            StaticEchoAllocated(Int128 session_id, int& allocated_id, int& remote_port) noexcept;
                /**
                 * @brief Processes an inbound static-echo UDP packet.
                 * @param allocated_context Slot context for this packet.
                 * @param allocator         Buffer swap allocator for temporary storage.
                 * @param packet            Parsed virtual ethernet packet.
                 * @param packet_length     Length of the packet payload.
                 * @param sourceEP          UDP source endpoint of the sender.
                 * @return True if the packet is forwarded successfully.
                 */
                bool                                                    StaticEchoPacketInput(const VirtualEthernetStaticEchoAllocatedContextPtr& allocated_context, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                /**
                 * @brief Selects protocol or transport cipher for a static-echo slot.
                 * @param allocated_id           Slot index.
                 * @param protocol_or_transport  True for protocol cipher; false for transport.
                 * @param allocated_context[out] Filled with the slot context on success.
                 * @return Selected ciphertext; null if the slot is not found.
                 */
                std::shared_ptr<ppp::cryptography::Ciphertext>          StaticEchoSelectCiphertext(int allocated_id, bool protocol_or_transport, VirtualEthernetStaticEchoAllocatedContextPtr& allocated_context) noexcept;

            private:
                /**
                 * @brief Loads and applies the firewall ruleset from the given path.
                 * @param path Ruleset file path.
                 * @return True if the ruleset is loaded without errors.
                 */
                bool                                                    CreateFirewall(const ppp::string& path) noexcept;
                /** @brief Closes and nullifies all entries in `acceptors_[]`. */
                void                                                    CloseAllAcceptors() noexcept;
                /** @brief Creates all configured TCP acceptors and starts their accept loops. */
                bool                                                    CreateAllAcceptors() noexcept;
                /** @brief Cancels the global maintenance timer if it is running. */
                bool                                                    CloseAlwaysTimeout() noexcept;
                /** @brief Creates and arms the global maintenance timer. */
                bool                                                    CreateAlwaysTimeout() noexcept;
                /** @brief Opens the UDP socket for static-echo datagram processing. */
                bool                                                    OpenDatagramSocket() noexcept;
                /** @brief Creates and starts the DNS namespace cache if the TTL is non-zero. */
                bool                                                    OpenNamespaceCacheIfNeed() noexcept;
                /** @brief Enables loopback receive path on the static-echo UDP socket. */
                bool                                                    LoopbackDatagramSocket() noexcept;
                /** @brief Opens and configures the session logger if available. */
                bool                                                    OpenLogger() noexcept;
                /**
                 * @brief Runs the full initial-handshake ("flower arrangement") workflow.
                 * @param transmission Active transmission channel.
                 * @param y            Coroutine yield context.
                 * @return True if the handshake succeeds and a session is created.
                 */
                bool                                                    FlowerArrangement(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                /**
                 * @brief Constructs the outbound information envelope for a session.
                 * @param session_id Session identifier.
                 * @param info       Virtual ethernet information to embed.
                 * @return Populated `InformationEnvelope`.
                 */
                InformationEnvelope                                     BuildInformationEnvelope(const Int128& session_id, const VirtualEthernetInformation& info) noexcept;
                /**
                 * @brief Fills the IPv6 extension fields in the outbound information envelope.
                 * @param session_id  Session identifier.
                 * @param extensions  Extension struct to populate.
                 * @return True if IPv6 extension data is available and written.
                 */
                bool                                                    BuildInformationIPv6Extensions(const Int128& session_id, VirtualEthernetInformationExtensions& extensions) noexcept;
                /**
                 * @brief Returns true if an IPv6 assignment was already granted for the session.
                 * @param session_id  Session to query.
                 * @param extensions  Populated with the existing assignment data on success.
                 */
                bool                                                    TryGetAssignedIPv6Extensions(const Int128& session_id, VirtualEthernetInformationExtensions& extensions) noexcept;
                /**
                 * @brief Updates stored client IPv6 request and recomputes assignment.
                 * @param session_id Session identifier.
                 * @param request Client-requested extension fields.
                 * @param response Receives updated server response extension fields.
                 * @return true when response contains any extension value.
                 */
                bool                                                    UpdateIPv6Request(const Int128& session_id, const VirtualEthernetInformationExtensions& request, VirtualEthernetInformationExtensions& response) noexcept;
                /**
                 * @brief Removes IPv6 leases that have passed their expiry timestamp.
                 * @param now Current tick count in milliseconds.
                 */
                void                                                    TickIPv6Leases(UInt64 now) noexcept;
                /**
                 * @brief Removes the IPv6 lease bound to the specified session.
                 * @param session_id Session whose lease should be revoked.
                 */
                void                                                    RevokeIPv6Lease(const Int128& session_id) noexcept;
                /**
                 * @brief Releases the IPv4 lease held by the specified session.
                 * @param session_id Session whose IPv4 lease should be released.
                 */
                void                                                    DeleteIPv4Lease(const Int128& session_id) noexcept;
                /**
                 * @brief Reserves a specific IPv4 address in the lease pool for a session.
                 *
                 * @details Used by the legacy Arp/OnLan path so that addresses chosen
                 *          unilaterally by old clients are also marked as taken in the
                 *          IPv4 lease pool, preventing AcquireAuto() from later handing
                 *          the same address to a new-protocol client.  If the pool is
                 *          not configured, the address is unspecified, or the address
                 *          is already leased to another session, the call returns false
                 *          (and any pool fallback IP is reverted) so the caller's
                 *          legacy view of the address remains the only source of truth.
                 *
                 * @param session_id Session that owns the legacy address.
                 * @param ip         IPv4 address (host byte order) to reserve.
                 * @return true when the exact IP was reserved for this session.
                 */
                bool                                                    ReserveIPv4Lease(const Int128& session_id, uint32_t ip) noexcept;
                /**
                 * @brief Processes a client IPv4 address request and fills the response.
                 *
                 * @details If the pool is configured, allocates (auto or manual) and
                 *          fills the ClientIPv4Assignment in @p response.  If the pool
                 *          is not configured, this is a no-op and returns false.
                 *
                 * @param session_id Session that sent the request.
                 * @param request    Client-supplied IPv4 request extensions.
                 * @param response   Filled with the server's IPv4 assignment response.
                 * @return true if an IPv4 assignment was processed (pool is configured).
                 */
                bool                                                    UpdateIPv4Request(const Int128& session_id, const VirtualEthernetInformationExtensions& request, VirtualEthernetInformationExtensions& response) noexcept;
                /**
                 * @brief Adds an IPv6 exchanger mapping derived from extension data.
                 * @param session_id Session identifier.
                 * @param extensions Extension data containing the assigned IPv6 address.
                 * @return True if the mapping is inserted successfully.
                 */
                bool                                                    AddIPv6Exchanger(const Int128& session_id, const VirtualEthernetInformationExtensions& extensions) noexcept;
                /**
                 * @brief Removes the IPv6 exchanger mapping for a session.
                 * @param session_id Session whose mapping should be removed.
                 * @return True if the entry was present and removed.
                 */
                bool                                                    DeleteIPv6Exchanger(const Int128& session_id) noexcept;
                /**
                 * @brief Removes the IPv6 exchanger mapping using extension-derived key data.
                 * @param session_id Session identifier.
                 * @param extensions Extension data used to compute the map key.
                 * @return True if the entry was present and removed.
                 */
                bool                                                    DeleteIPv6Exchanger(const Int128& session_id, const VirtualEthernetInformationExtensions& extensions) noexcept;
                /**
                 * @brief Finds the exchanger for an inbound IPv6 destination address.
                 * @param ip Destination IPv6 address.
                 * @return Owning exchanger; null if not found.
                 */
                VirtualEthernetExchangerPtr                             FindIPv6Exchanger(const boost::asio::ip::address& ip) noexcept;
                /** @brief Opens the IPv6 neighbor proxy on the transit interface if required. */
                bool                                                    OpenIPv6NeighborProxyIfNeed() noexcept;
                /** @brief Closes the IPv6 neighbor proxy if it was opened by this switcher. */
                bool                                                    CloseIPv6NeighborProxyIfNeed() noexcept;
                /** @brief Re-applies neighbor proxy entries that may have been lost after a link event. */
                bool                                                    RefreshIPv6NeighborProxyIfNeed() noexcept;
                /**
                 * @brief Adds one IPv6 neighbor proxy (NDP proxy) entry for a leased address.
                 * @param ip Leased IPv6 address to advertise via NDP proxy.
                 * @return True if the kernel entry is created successfully.
                 */
                bool                                                    AddIPv6NeighborProxy(const boost::asio::ip::address& ip) noexcept;
                /**
                 * @brief Removes the NDP proxy entry for a specific IPv6 address.
                 * @param ip Address to remove.
                 * @return True if the entry was removed.
                 */
                bool                                                    DeleteIPv6NeighborProxy(const boost::asio::ip::address& ip) noexcept;
                /**
                 * @brief Removes the NDP proxy entry on a specific interface.
                 * @param ifname Interface name.
                 * @param ip     Address to remove.
                 * @return True if the entry was removed.
                 */
                bool                                                    DeleteIPv6NeighborProxy(const ppp::string& ifname, const boost::asio::ip::address& ip) noexcept;
                /**
                 * @brief Adds a host route for an IPv6 prefix into the transit routing table.
                 * @param ip            IPv6 prefix address.
                 * @param prefix_length Prefix length in bits.
                 * @return True if the route is added.
                 */
                bool                                                    AddIPv6TransitRoute(const boost::asio::ip::address& ip, int prefix_length) noexcept;
                /**
                 * @brief Removes a host route for an IPv6 prefix from the transit routing table.
                 * @param ip            IPv6 prefix address.
                 * @param prefix_length Prefix length in bits.
                 * @return True if the route is removed.
                 */
                bool                                                    DeleteIPv6TransitRoute(const boost::asio::ip::address& ip, int prefix_length) noexcept;
                /**
                 * @brief Snapshots IPv6 cleanup keys and clears exchanger/lease state without acquiring `syncobj_`.
                 * @warning Caller must hold `syncobj_` before calling this function. Owned-neighbor records
                 *          remain until lock-free kernel cleanup confirms deletion.
                 */
                void                                                    ClearIPv6ExchangersUnsafe(ppp::unordered_set<ppp::string>& cleanup_keys, ppp::unordered_set<ppp::string>& cleanup_owned_neighbors) noexcept;
                /**
                 * @brief Injects a raw packet into the IPv6 transit TAP device.
                 * @param packet        Pointer to the raw IP packet buffer.
                 * @param packet_length Packet length in bytes.
                 * @return True if the write succeeds.
                 */
                bool                                                    SendIPv6TransitPacket(Byte* packet, int packet_length) noexcept;
                /**
                 * @brief Processes a raw packet received from the IPv6 transit TAP device.
                 * @param packet        Pointer to the raw IP packet buffer.
                 * @param packet_length Packet length in bytes.
                 * @return True if the packet is dispatched.
                 */
                bool                                                    ReceiveIPv6TransitPacket(Byte* packet, int packet_length) noexcept;
                /**
                 * @brief Sends an IPv6 packet to the specified client session.
                 * @param transmission  Transmission channel for the target session.
                 * @param session_id    Target session identifier.
                 * @param packet        Raw IPv6 packet buffer.
                 * @param packet_length Packet length in bytes.
                 * @return True if the send succeeds.
                 */
                bool                                                    SendIPv6PacketToClient(const ITransmissionPtr& transmission, const Int128& session_id, Byte* packet, int packet_length) noexcept;
                /**
                 * @brief Removes a NAT entry owned by an exchanger for the given IPv4 address.
                 * @param key Exchanger raw pointer used as the lookup key.
                 * @param ip  IPv4 address (host-byte order) of the NAT entry.
                 * @return True if the entry was found and removed.
                 */
                bool                                                    DeleteNatInformation(VirtualEthernetExchanger* key, uint32_t ip) noexcept;
                /**
                 * @brief Finds the NAT information entry for a given IPv4 address.
                 * @param ip IPv4 address (host-byte order).
                 * @return Shared pointer to the entry; null if not found.
                 */
                NatInformationPtr                                       FindNatInformation(uint32_t ip) noexcept;
                /**
                 * @brief Creates and registers a NAT entry for an exchanger's IPv4 subnet.
                 * @param exchanger Owning exchanger.
                 * @param ip        Client IPv4 address (host-byte order).
                 * @param mask      Subnet mask (host-byte order).
                 * @return Shared pointer to the new entry; null if insertion fails.
                 */
                NatInformationPtr                                       AddNatInformation(const std::shared_ptr<VirtualEthernetExchanger>& exchanger, uint32_t ip, uint32_t mask) noexcept;
                /** @brief Updates server-side P2P peer state from an INFO extension. */
                bool                                                    UpdateP2PPeer(const std::shared_ptr<VirtualEthernetExchanger>& exchanger, const ITransmissionPtr& transmission, const VirtualEthernetInformationExtensions& request, VirtualEthernetInformationExtensions& response) noexcept;
                /** @brief Records an authenticated static-echo UDP endpoint after NAT ownership validation. */
                bool                                                    ObserveP2PUdpEndpoint(const std::shared_ptr<VirtualEthernetExchanger>& exchanger, uint32_t virtual_ip, const boost::asio::ip::udp::endpoint& source) noexcept;
                /** @brief Removes P2P peer state for a disconnected session. */
                bool                                                    DeleteP2PPeer(const Int128& session_id) noexcept;
                /** @brief Sends peer endpoint hints to both sides while preserving server relay fallback. */
                bool                                                    OfferP2PPeerHints(uint32_t source_ip, uint32_t destination_ip, YieldContext& y) noexcept;
                /** @brief Registers or refreshes peer prefix gateway announcements. */
                bool                                                    UpdatePeerRouteAnnounce(const std::shared_ptr<VirtualEthernetExchanger>& exchanger, const VirtualEthernetInformationExtensions& request, VirtualEthernetInformationExtensions& response) noexcept;
                /** @brief Removes prefix gateway state for a disconnected session. */
                bool                                                    DeletePeerPrefixGateway(const Int128& session_id) noexcept;
                /** @brief Returns true when server peer prefix routing is enabled. */
                bool                                                    IsPeerRoutingEnabled() const noexcept;
                /** @brief Resolves the gateway peer virtual IP for a destination address. */
                uint32_t                                                FindGatewayVirtualIPForDestination(uint32_t destination) noexcept;
                /** @brief Fills a peer-route-table snapshot for clients. */
                void                                                    BuildPeerRouteTableSnapshot(ppp::app::protocol::PeerRouteTableMessage& table, const Int128* exclude_session_id = NULLPTR) noexcept;
                /** @brief Pushes the current peer-route-table snapshot to all connected clients. */
                void                                                    BroadcastPeerRouteTable(YieldContext& y) noexcept;

            private:
                void                                                    RebuildPeerPrefixRibLocked() noexcept;
                template <typename TTransmission>
                typename std::enable_if<std::is_base_of<ITransmission, TTransmission>::value, std::shared_ptr<TTransmission>/**/>::type
                /**
                 * @brief Creates a WebSocket transmission and applies configured host/path overrides.
                 *
                 * @tparam TTransmission Concrete transmission type derived from `ITransmission`.
                 * @param context I/O context used to construct the transmission.
                 * @param socket  Accepted TCP socket transferred to the transmission.
                 * @return Constructed transmission on success; null on allocation failure.
                 * @note When both `configuration_->websocket.host` and `configuration_->websocket.path`
                 *       are non-empty, they are applied to the new transmission object.
                 */
                                                                        NewWebsocketTransmission(const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;

            private:
                SynchronizedObject                                      syncobj_;           ///< Mutex guarding all shared mutable tables.
                SynchronizedObject                                      ipv6_transit_lifecycle_syncobj_; ///< Serializes TAP-backed route/neighbor lifecycle operations with Finalize().
                /** @brief Set to true after Dispose() begins; atomic for lock-free cross-thread reads via IsDisposed(). */
                std::atomic<bool>                                       disposed_{false};
                std::atomic<bool>                                       running_{false};

                VirtualEthernetLoggerPtr                                logger_;                        ///< Session activity logger.
                NatInformationTable                                     nats_;                          ///< IPv4 NAT ownership table (key = IP).
                IPv6ExchangerTable                                      ipv6s_;                         ///< IPv6 address → exchanger mapping.
                ppp::unordered_set<ppp::string>                          ipv6_transit_neighbor_owned_;   ///< Permanent transit neighbors created by this switcher.
                IPv6RequestTable                                        ipv6_requests_;                 ///< Per-session IPv6 request state.
                IPv6LeaseTable                                          ipv6_leases_;                   ///< Active IPv6 lease records.
                P2PPeerTable                                            p2p_peers_;                     ///< P2P control-plane peer records (key = session_id).
                ppp::unordered_map<uint32_t, Int128>                    p2p_virtual_ips_;               ///< Reverse index: virtual_ip → session_id for dedup and NAT-ownership validation.
                UInt64                                                  p2p_offer_generation_ = 0;      ///< Monotonic offer reservation identity guarded by syncobj_.
                PeerPrefixGatewayTable                                  peer_prefix_gateways_;          ///< Prefix gateway records keyed by session_id.
                ppp::net::native::RouteInformationTable                 peer_prefix_rib_;               ///< Prefix → gateway virtual IP lookup table.
                ppp::p2p::P2PNatClassifier                              p2p_nat_classifier_;            ///< Server-side NAT type inference from relay traffic.
                FirewallPtr                                             firewall_;                      ///< Packet firewall.
                VirtualEthernetExchangerTable                           exchangers_;                    ///< Active session exchangers (key = session_id).
                TimerPtr                                                timeout_;                       ///< Global maintenance timer.
                AppConfigurationPtr                                     configuration_;                 ///< Immutable configuration snapshot.
                ContextPtr                                              context_;                       ///< Primary Boost.Asio io_context.
                boost::asio::ip::udp::endpoint                          dnsserverEP_;                   ///< Upstream DNS server endpoint.
                boost::asio::ip::address                                interfaceIP_;                   ///< Local interface IP address.
                ppp::string                                             tun_name_;                      ///< IPv6 transit TUN/TAP interface name.
                int                                                     tun_ssmt_ = 0;                  ///< Number of SSMT workers for the transit TAP.
                bool                                                    tun_ssmt_mq_ = false;           ///< Multi-queue mode flag for the transit TAP.
                ppp::string                                             preferred_nic_;                 ///< Preferred NIC for routing/proxy operations.
                ppp::string                                             ipv6_neighbor_proxy_ifname_;    ///< Interface used for NDP proxy entries.
                bool                                                    ipv6_neighbor_proxy_owned_ = false;    ///< True if this switcher opened the NDP proxy.
                bool                                                    ipv6_ndp_proxy_applied_ = false;       ///< True once the sysctl proxy_ndp enable has been run for the current uplink interface.
                ITapPtr                                                 ipv6_transit_tap_;              ///< IPv6 transit TAP device handle.
                ppp::vector<std::shared_ptr<boost::asio::io_context>>   ipv6_transit_ssmt_contexts_;    ///< SSMT io_contexts for the transit TAP.
                std::atomic<uint8_t>                                    ipv6_runtime_state_{0};         ///< IPv6 plane state: 0=off, 1=nat66, 2=gua, 3=failed.
                std::atomic<uint32_t>                                   ipv6_runtime_cause_{0};         ///< ErrorCode of the last IPv6 plane state-transition failure.
                VirtualEthernetNetworkTcpipConnectionTable              connections_;                   ///< Active TCP/IP connection objects.
                ITransmissionStatisticsPtr                              statistics_;                    ///< Aggregate traffic statistics.
                VirtualEthernetManagedServerPtr                         managed_server_;                ///< Go managed-server bridge.
                VirtualEthernetNamespaceCachePtr                        namespace_cache_;               ///< DNS response cache.
                boost::asio::ip::udp::socket                            static_echo_socket_;            ///< UDP socket for static-echo relay.
                int                                                     static_echo_bind_port_ = 0;    ///< Local port bound for static-echo.
                std::shared_ptr<Byte>                                   static_echo_buffers_;           ///< Receive buffer for static-echo socket.
                boost::asio::ip::udp::endpoint                          static_echo_source_ep_;         ///< Most-recently-received static-echo source EP.
                VirtualEthernetStaticEchoAllocatedTable                 static_echo_allocateds_;        ///< Active static-echo allocation slots.
                IPv4LeasePool                                           ipv4_pool_;                     ///< IPv4 address lease pool for automatic/manual client assignment.

                std::shared_ptr<boost::asio::ip::tcp::acceptor>         acceptors_[NetworkAcceptorCategories_Max]; ///< One acceptor per category.
            };
        }
    }
}
