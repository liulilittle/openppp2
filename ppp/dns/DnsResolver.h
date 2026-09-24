#pragma once

/**
 * @file DnsResolver.h
 * @brief Multi-protocol upstream DNS resolver for provider-based dns-rules.
 */

#include <ppp/stdafx.h>
#include <ppp/dns/DnsUdpFlowRegistry.h>
#include <atomic>
#include <chrono>
#include <mutex>

namespace boost {
    namespace asio {
        namespace ssl {
            class context;
        }
    }
}

/* Forward-declare OpenSSL session type so the public header does not pull in
 * <openssl/ssl.h>. The cache stores opaque SSL_SESSION pointers, lifetime
 * managed via SSL_SESSION_up_ref / SSL_SESSION_free in the implementation. */
struct ssl_session_st;

namespace ppp {
    namespace dns {

        enum class Protocol {
            UDP,
            TCP,
            DoH,
            DoT,
        };

        struct ServerEntry {
            Protocol                                        protocol = Protocol::UDP;
            ppp::string                                     url;
            ppp::string                                     hostname;
            ppp::string                                     address;
            ppp::vector<boost::asio::ip::address>           bootstrap_ips;
        };

        /**
         * @brief A STUN server candidate with pre-resolved IP and port.
         */
        struct StunCandidate {
            boost::asio::ip::address                        ip;
            int                                             port = 19302;
        };

        /**
         * @brief STUN candidate specified as hostname:port; resolved at probe time.
         */
        struct StunHostnameCandidate {
            ppp::string                                     hostname;
            int                                             port = 3478;
        };

        class DnsResolver final : public std::enable_shared_from_this<DnsResolver> {
        public:
            typedef ppp::function<bool(int native_handle)>  ProtectSocketCallback;
            typedef ppp::function<void(ppp::vector<Byte>)>  ResolveCallback;
            typedef ppp::function<void(boost::asio::ip::address)> ExitIpCallback;

        public:
            explicit DnsResolver(boost::asio::io_context& context) noexcept;
            ~DnsResolver() noexcept;

            void                                            SetProtectSocketCallback(const ProtectSocketCallback& cb) noexcept;
            void                                            SetUdpFlowRegistry(const std::shared_ptr<DnsUdpFlowRegistry>& registry) noexcept;

            /**
             * @brief Sets the client exit IP used as the ECS source address.
             *
             * @details When ECS is enabled and no override_ip is configured,
             *          this address is used for the EDNS Client Subnet option.
             *          Typically populated from the server's ClientExitIP field
             *          in VirtualEthernetInformationExtensions.
             *
             * @param ip  Client exit IPv4/IPv6 address.
             */
            void                                            SetExitIP(const boost::asio::ip::address& ip) noexcept;

            /**
             * @brief Configures EDNS Client Subnet (ECS) injection behaviour.
             *
             * @param enabled     When true, ECS OPT RR is injected into domestic queries.
             * @param override_ip Highest-priority ECS IP; empty string defers to exit_ip.
             */
            void                                            SetEcsConfig(bool enabled, const ppp::string& override_ip) noexcept;

            /**
             * @brief Enables or disables peer certificate verification for DoH/DoT.
             *
             * @details When enabled, DnsResolver verifies the upstream certificate
             *          chain using the project's bundled roots, optional cacert.pem,
             *          and system default CA locations.  Hostname verification is
             *          also applied when SNI/hostname is available.
             */
            void                                            SetTlsVerifyPeer(bool verify_peer) noexcept;

            /**
             * @brief Stores default domestic and foreign provider names used as
             *        fallback when ResolveAsyncWithFallback is called.
             *
             * @param domestic  Provider short-name for domestic queries (e.g. "doh.pub").
             * @param foreign   Provider short-name for foreign  queries (e.g. "cloudflare").
             */
            void                                            SetDefaultProviders(
                const ppp::string&                          domestic,
                const ppp::string&                          foreign) noexcept;

            /**
             * @brief Configures the STUN candidate list for exit IP detection.
             *
             * @details Replaces the built-in STUN server list with user-provided
             *          candidates.  Candidates that are IP:port literals are used
             *          directly; hostnames are resolved at call time via bootstrap.
             *
             * @param candidates  Vector of "ip:port" or "hostname:port" strings.
             */
            void                                            SetStunCandidates(ppp::vector<StunCandidate> candidates) noexcept;

            void                                            SetStunHostnameCandidates(
                ppp::vector<StunHostnameCandidate>          candidates) noexcept;

            /**
             * @brief Resolves a DNS query through a named provider, with up to two
             *        additional fallback providers tried in order on failure.
             *
             * @details Provider selection order:
             *          1. @p provider_name
             *          2. @p fallback1   (may be empty)
             *          3. @p fallback2   (may be empty)
             *
             *          Each step delegates to ResolveAsync, which itself tries all
             *          protocols (DoH → DoT → TCP → UDP) for that provider.  The
             *          callback is invoked exactly once with the first successful
             *          response, or with an empty vector if every attempt fails.
             *
             * @param provider_name  Primary provider short-name.
             * @param fallback1      First fallback provider short-name (or empty).
             * @param fallback2      Second fallback provider short-name (or empty).
             * @param packet         Raw DNS query bytes.
             * @param length         Length of @p packet in bytes.
             * @param callback       Completion callback; invoked exactly once.
             */
            void                                            ResolveAsyncWithFallback(
                const ppp::string&                          provider_name,
                const ppp::string&                          fallback1,
                const ppp::string&                          fallback2,
                const Byte*                                 packet,
                int                                         length,
                const ResolveCallback&                      callback) noexcept;

            void                                            ResolveAsync(
                const ppp::string&                          provider_name,
                bool                                        domestic,
                const Byte*                                 packet,
                int                                         length,
                const ResolveCallback&                      callback) noexcept;

            /**
             * @brief Resolves a DNS query using explicit server entries.
             *
             * @details Unlike ResolveAsync which looks up a provider by name,
             *          this method uses the supplied entries directly.  Protocol
             *          cascade (DoH → DoT → TCP → UDP) is applied per-entry.
             *          ECS injection is applied when the query is domestic and
             *          ECS is enabled.
             *
             * @param entries   Explicit server entries to resolve through.
             * @param domestic  True if this is a domestic query (ECS eligible).
             * @param packet    Raw DNS query bytes.
             * @param length    Length of @p packet in bytes.
             * @param callback  Completion callback; invoked exactly once.
             */
            void                                            ResolveAsyncWithEntries(
                const ppp::vector<ServerEntry>&             entries,
                bool                                        domestic,
                const Byte*                                 packet,
                int                                         length,
                const ResolveCallback&                      callback) noexcept;

            static bool                                     HasProvider(const ppp::string& name) noexcept;
            static const ppp::vector<ServerEntry>*          GetProvider(const ppp::string& name) noexcept;

            /**
             * @brief Controls whether AAAA (IPv6) responses are propagated to clients.
             *
             * @details When the VPN session has not been assigned a managed IPv6
             *          address by the server, returning AAAA records to local
             *          applications causes 30+ second connect delays because the
             *          OS will attempt the IPv6 destination before falling back to
             *          IPv4. Setting allow=false makes the resolver synthesize an
             *          immediate empty NOERROR response for any AAAA query, which
             *          eliminates that latency without changing A-record behaviour.
             *          The default is false: AAAA queries are filtered until the
             *          server confirms an IPv6 assignment via OnInformation. This
             *          is the safer default because most VPN sessions are IPv4-only
             *          and an unsolicited AAAA pass-through would cause client
             *          applications to attempt unreachable IPv6 destinations.
             *
             * @param allow  Pass false to filter AAAA queries; true to permit them.
             */
            void                                            SetAllowIPv6Response(bool allow) noexcept { allow_ipv6_response_.store(allow, std::memory_order_relaxed); }
            bool                                            IsAllowIPv6Response() const noexcept { return allow_ipv6_response_.load(std::memory_order_relaxed); }

            /**
             * @brief Returns true when the supplied DNS query is asking for AAAA records.
             *
             * @param packet  Raw DNS wire-format query bytes.
             * @param length  Length of @p packet.
             */
            static bool                                     IsAaaaQuery(const Byte* packet, int length) noexcept;

            /**
             * @brief Builds an empty NOERROR response for the supplied AAAA query.
             *
             * @details Copies the question section verbatim, flips QR=1, sets RA=1,
             *          and zeros all answer counts. Used to short-circuit AAAA
             *          queries when IPv6 is not available end-to-end.
             *
             * @param packet  Original AAAA query bytes.
             * @param length  Length of @p packet.
             * @return Synthesised response bytes; empty vector on parse failure.
             */
            static ppp::vector<Byte>                        BuildAaaaBlockedResponse(const Byte* packet, int length) noexcept;

        private:
            void                                            TryProtocols(
                std::shared_ptr<ppp::vector<ServerEntry> >  entries,
                std::size_t                                 index,
                std::shared_ptr<ppp::vector<Byte> >         packet,
                const ResolveCallback&                      callback,
                bool                                        domestic = false) noexcept;

            void                                            SendUdp(
                const ServerEntry&                          entry,
                std::shared_ptr<ppp::vector<Byte> >         packet,
                const ResolveCallback&                      callback) noexcept;

            void                                            SendTcp(
                const ServerEntry&                          entry,
                std::shared_ptr<ppp::vector<Byte> >         packet,
                const ResolveCallback&                      callback) noexcept;

            void                                            SendDoh(
                const ServerEntry&                          entry,
                std::shared_ptr<ppp::vector<Byte> >         packet,
                const ResolveCallback&                      callback) noexcept;

            void                                            SendDot(
                const ServerEntry&                          entry,
                std::shared_ptr<ppp::vector<Byte> >         packet,
                const ResolveCallback&                      callback) noexcept;

            bool                                            ProtectSocket(int native_handle) noexcept;

            /**
             * @brief Looks up a previously cached TLS session for a given upstream.
             *
             * @details Returned pointer is up-ref'd; the caller takes ownership and
             *          must release it via SSL_SESSION_free (or pass it to
             *          SSL_set_session, which up-refs again — in that case the
             *          caller must still free its own reference).
             *
             * @param host_key  Cache key composed from "<host>:<port>".
             * @return SSL_SESSION* on cache hit; nullptr if no usable session is cached.
             */
            ssl_session_st*                                 AcquireTlsSession(const ppp::string& host_key) noexcept;

            std::shared_ptr<boost::asio::ssl::context>       AcquireClientSslContext(bool verify_peer) noexcept;

            /**
             * @brief Stores a TLS session for future resumption.
             *
             * @details Replaces any previously cached session for the same key.
             *          Takes ownership of @p session (the caller's reference is
             *          consumed; the cache will free it when evicted or on
             *          DnsResolver destruction).
             */
            void                                            StoreTlsSession(const ppp::string& host_key, ssl_session_st* session) noexcept;

            /**
             * @brief Returns the effective ECS IP address (override_ip > exit_ip).
             *
             * @return ECS IP address, or unspecified if none available.
             */
            boost::asio::ip::address                        GetEcsIp() const noexcept;

            void                                            ClearStunEcsCache() noexcept;

            void                                            GetOrDetectEcsIpViaStun(const ExitIpCallback& callback) noexcept;

            /**
             * @brief Appends or merges an EDNS Client Subnet OPT RR into a raw DNS query packet.
             *
             * @details Modifies @p packet in-place.  When ARCOUNT == 0, a fresh OPT RR is
             *          appended.  When ARCOUNT > 0, the additional-section is scanned for
             *          an existing OPT RR (TYPE=41 at root label); if found, its ECS option
             *          (option-code 8) is replaced or appended within the OPT RDATA.
             *          If the packet cannot be safely parsed, it is left unchanged.
             *
             * @param packet  DNS query packet bytes (modified in-place on success).
             * @param ecs_ip  IPv4 address to embed in the ECS option; last byte is
             *                zeroed to represent a /24 prefix.
             * @return true if the OPT RR was injected or merged; false on error or skip.
             */
            static bool                                     InjectEcsOptRr(ppp::vector<Byte>& packet, const boost::asio::ip::address& ecs_ip) noexcept;

            /**
             * @brief Detects the client's public IPv4 address via STUN Binding Request.
             *
             * @details Sends a STUN Binding Request (RFC 5389) to a well-known STUN
             *          server and parses the XOR-MAPPED-ADDRESS from the response.
             *          Used as a last-resort fallback when ECS is enabled but no
             *          override_ip or exit_ip is configured.
             *
             *          When custom STUN candidates are configured (via SetStunCandidates),
             *          candidates are tried in round-robin order.  On each call the
             *          starting index is rotated so that repeated calls distribute
             *          load across candidates.
             *
             * @param callback  Invoked with the detected public IPv4 address, or an
             *                  unspecified address on failure/timeout.
             */
            void                                            DetectExitIPViaStun(const ExitIpCallback& callback) noexcept;

            /**
             * @brief Attempts STUN detection against a single candidate.
             *
             * @param candidate  STUN server IP and port.
             * @param callback   Invoked with the detected address or unspecified on failure.
             */
            void                                            TryStunCandidate(
                const StunCandidate&                        candidate,
                const ExitIpCallback&                       callback) noexcept;

            /**
             * @brief Resolves a hostname to an IPv4 address using the system DNS resolver.
             *
             * @details A reusable bootstrap DNS helper that does NOT depend on the
             *          provider infrastructure.  Sends a raw DNS A-record query
             *          to well-known public DNS servers (e.g. 8.8.8.8) via UDP.
             *          Intended for resolving DoH/DoT hostnames during bootstrap
             *          when provider IPs are not yet known.
             *
             * @param hostname  The hostname to resolve.
             * @param callback  Invoked with the first resolved IPv4 address, or
             *                  an unspecified address on failure/timeout.
             */
            void                                            ResolveHostnameAsync(
                const ppp::string&                          hostname,
                const ExitIpCallback&                       callback) noexcept;

        private:
            /**
             * @brief Immutable resolver configuration snapshot.
             *
             * @details Setters copy the current snapshot, apply their change, and publish
             *          the new snapshot with std::atomic_store; query paths take one
             *          snapshot with std::atomic_load, so configuration hot-updates from
             *          the management thread never race with in-flight queries running
             *          on the io_context workers.
             */
            struct Config {
                ProtectSocketCallback                       protect_socket;
                std::shared_ptr<DnsUdpFlowRegistry>         udp_flow_registry;
                ppp::string                                 default_domestic;
                ppp::string                                 default_foreign;
                boost::asio::ip::address                    exit_ip;
                bool                                        ecs_enabled = false;
                ppp::string                                 ecs_override_ip;
                bool                                        tls_verify_peer = true;
                ppp::vector<StunCandidate>                  stun_candidates;
                ppp::vector<StunHostnameCandidate>          stun_hostname_candidates;
            };

            /** @brief Returns the currently published immutable configuration snapshot. */
            std::shared_ptr<const Config>                   GetConfig() const noexcept { return std::atomic_load(&config_); }

            /**
             * @brief Publishes a new configuration snapshot via copy-on-write.
             * @param mutate Mutation applied to the copied snapshot before publication.
             */
            void                                            UpdateConfig(const ppp::function<void(Config&)>& mutate) noexcept;

        private:
            boost::asio::io_context&                        context_;
            /** @brief Serializes copy-on-write configuration updates (setters only). */
            mutable std::mutex                              config_mutex_;
            /** @brief Atomically published immutable configuration snapshot. */
            std::shared_ptr<const Config>                   config_ = make_shared_object<Config>();
            std::atomic<std::size_t>                        stun_rotation_{ 0 };
            std::atomic<bool>                               allow_ipv6_response_{ false }; ///< When false, AAAA queries are answered with empty NOERROR. Default false; promoted to true by OnInformation when the server assigns IPv6.

            mutable std::mutex                              stun_ecs_mutex_;
            boost::asio::ip::address                        stun_ecs_ip_;
            std::chrono::steady_clock::time_point            stun_ecs_expires_at_{};
            std::chrono::steady_clock::time_point            stun_ecs_negative_expires_at_{};
            bool                                            stun_ecs_probe_inflight_ = false;
            ppp::vector<ExitIpCallback>                     stun_ecs_pending_callbacks_;

            /**
             * @brief Cache of OpenSSL session tickets keyed by "<host>:<port>".
             *
             * @details Populated after each successful DoH/DoT TLS handshake and
             *          consumed before the next handshake to the same upstream so
             *          that TLS 1.2/1.3 session resumption (1-RTT or 0-RTT) is
             *          used in place of a full handshake. Lifetime of the stored
             *          SSL_SESSION* is owned by this map; SSL_SESSION_free is
             *          called on replace and on resolver destruction.
             */
            struct TlsSessionCacheEntry {
                ssl_session_st*                         session = NULLPTR;
                ppp::list<ppp::string>::iterator        lru;
            };

            mutable std::mutex                              tls_session_mutex_;
            ppp::list<ppp::string>                          tls_session_lru_;
            ppp::unordered_map<ppp::string, TlsSessionCacheEntry> tls_session_cache_;

            mutable std::mutex                              tls_context_mutex_;
            std::shared_ptr<boost::asio::ssl::context>       tls_client_ssl_ctx_;
            bool                                            tls_client_ssl_ctx_verify_peer_ = true;
        };

    } // namespace dns
} // namespace ppp
