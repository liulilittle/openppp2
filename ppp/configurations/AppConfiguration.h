#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/configurations/DnsServerEntry.h>
#include <ppp/configurations/MappingConfiguration.h>
#include <ppp/configurations/TransportAuthConfiguration.h>

namespace Json {
    class Value;
}

/**
 * @file AppConfiguration.h
 * @brief Application configuration model and serialization APIs.
 */

namespace ppp {
    namespace configurations {
        /**
         * @brief Trims canonical client routing string sources and removes empties.
         * @param values String source list to normalize in place.
         */
        inline void NormalizeClientRoutingStringList(ppp::vector<ppp::string>& values) noexcept {
            for (ppp::string& value : values) {
                value = LTrim(RTrim(value));
            }
            values.erase(
                std::remove_if(values.begin(), values.end(),
                    [](const ppp::string& value) noexcept { return value.empty(); }),
                values.end());
        }

        /**
         * @brief Stores runtime and networking configuration for the application.
         */
        class AppConfiguration final {
        public:
            using DnsServerEntry = configurations::DnsServerEntry;

            using MappingConfiguration = ::ppp::configurations::MappingConfiguration;

            /**
             * @brief Route source configuration for client route imports.
             *
             * Specifies an external route file or a vBGP peer whose prefixes the
             * client should install after establishing the tunnel.
             */
            struct RouteConfiguration final {
#if defined(_LINUX)
                ppp::string                                                 nic;   ///< Linux NIC name used as the route output interface.
#endif
                uint32_t                                                    ngw;   ///< Next-hop gateway IPv4 address in host byte order; 0 means use tunnel default.
                ppp::string                                                 path;  ///< Path to a static route file listing CIDR prefixes to import.
                ppp::string                                                 vbgp;  ///< vBGP peer address string; empty disables dynamic route learning.
            };

            /**
             * @brief Static or announced peer prefix route entry.
             *
             * Static client routes set @c via to the gateway peer virtual IPv4.
             * Gateway peers omit @c via and only publish @c network/@c prefix.
             */
            struct PeerPrefixRouteConfiguration final {
                ppp::string                                                 network; ///< Prefix network, e.g. "10.0.0.0".
                int                                                         prefix = 0; ///< Prefix length, e.g. 24.
                ppp::string                                                 via;     ///< Gateway peer virtual IPv4, e.g. "10.1.0.2"; empty for announce-only.
                ppp::string                                                 guid;    ///< Server allowlist owner client GUID; empty for client static routes.
            };

            /**
             * @brief Canonical client routing policy model.
             *
             * The model is present under @c client.routing when the canonical
             * object was supplied.  It carries only IP and DNS policy sources:
             * each @c ip and @c dns item may identify a file or contain inline
             * text.  The independent @c client.proxy-only flag controls runtime
             * mode.  During the compatibility period, canonical routes are
             * mirrored to the legacy @c client.routes and @c client.peer-routes,
             * while legacy-only input is projected into this model for
             * serialization.
             */
            struct ClientRoutingConfiguration final {
                bool                                                        configured;  ///< True when client.routing was supplied as a JSON object.
                ppp::vector<ppp::string>                                    bypass;      ///< IP bypass source files or inline text.
                ppp::vector<RouteConfiguration>                             routes;      ///< Canonical IP route sources.
                ppp::vector<PeerPrefixRouteConfiguration>                   peer_routes; ///< Canonical peer-prefix routes.
                ppp::vector<ppp::string>                                    dns_rules;   ///< DNS rule source files or inline text.
            };

            /**
             * @brief IPv6 address assignment mode for server-side data plane.
             *
             * Controls which IPv6 provisioning strategy the server uses when
             * allocating an IPv6 prefix or address for a connected client.
             */
            enum IPv6Mode {
                IPv6Mode_None  = 0,   ///< IPv6 provisioning is disabled; clients receive IPv4 only.
                IPv6Mode_Nat66 = 1,   ///< NAT66 is used to translate a ULA prefix to a global prefix.
                IPv6Mode_Gua   = 2,   ///< Globally Unique Address (GUA) is delegated directly to the client.
            };

        public:
            int                                                             concurrent;   ///< Number of concurrent IO worker threads; typically set to CPU core count.
            int                                                             cdn[2];       ///< CDN acceleration port pair [plain, tls]; 0 disables the respective CDN path.
            struct {
                ppp::string                                                 public_;      ///< Public-facing IPv4/IPv6 address advertised to remote peers.
                ppp::string                                                 interface_;   ///< Local network interface address used for binding sockets.
            }                                                               ip;           ///< IP address binding configuration.
            struct {
                struct {
                    int                                                     timeout;      ///< Idle timeout in seconds before a UDP session is torn down.
                }                                                           inactive;
                struct {
                    int                                                     timeout;      ///< DNS query timeout in seconds.
                    int                                                     ttl;          ///< DNS response TTL in seconds used for local cache entries.
                    bool                                                    turbo;        ///< Enable turbo (parallel/aggressive) DNS query mode.
                    bool                                                    cache;        ///< Enable local DNS response caching.
                    ppp::string                                             redirect;     ///< Upstream DNS server address to redirect queries to; empty = system default.
                }                                                           dns;
                struct {
                    int                                                     port;         ///< UDP listen port; 0 lets the OS choose an ephemeral port.
                }                                                           listen;
                struct {
                    int                                                     keep_alived[2]; ///< Keep-alive interval range [min, max] in seconds for static UDP mappings.
                    bool                                                    dns;            ///< Forward DNS traffic through the static channel.
                    bool                                                    quic;           ///< Enable QUIC acceleration for static UDP sessions.
                    bool                                                    icmp;           ///< Allow ICMP echo through the static channel.
                    int                                                     aggligator;     ///< Aggligator aggregation factor; 0 disables UDP link aggregation.
                    ppp::unordered_set<ppp::string>                         servers;        ///< Set of static server addresses used as tunnel uplink endpoints.
                }                                                           static_;
                int                                                         cwnd;           ///< UDP congestion window size in packets; 0 means system default.
                int                                                         rwnd;           ///< UDP receive window size in packets; 0 means system default.
            }                                                               udp;            ///< UDP protocol and session parameters.
            struct {
                struct {
                    int                                                     timeout;        ///< Idle timeout in seconds before an established TCP session is closed.
                }                                                           inactive;
                struct {
                    int                                                     timeout;        ///< TCP connect handshake timeout in seconds.
                    int                                                     nexcept;        ///< Maximum allowed consecutive connect exceptions before circuit-break.
                }                                                           connect;
                struct {
                    int                                                     port;           ///< TCP listen port; 0 lets the OS choose an ephemeral port.
                }                                                           listen;
                bool                                                        turbo;          ///< Enable TCP turbo mode (Nagle disabled, immediate flush).
                int                                                         backlog;        ///< Listen backlog depth for the TCP acceptor socket.
                int                                                         cwnd;           ///< TCP congestion window size override; 0 means kernel default.
                int                                                         rwnd;           ///< TCP receive window size override; 0 means kernel default.
                bool                                                        fast_open;      ///< Enable TCP Fast Open (TFO) for reduced handshake latency.
            }                                                               tcp;            ///< TCP protocol and session parameters.
            struct {
                struct {
                    int                                                     timeout;        ///< Idle timeout in seconds for a MUX sub-channel.
                }                                                           inactive;
                struct {
                    int                                                     timeout;        ///< MUX connect handshake timeout in seconds.
                }                                                           connect;
                ppp::string                                                 mode;           ///< MUX transmit scheduler mode: compat or flow.
                int                                                         congestions;    ///< MUX congestion control level; higher values reduce burst aggressiveness.
                int                                                         keep_alived[2]; ///< MUX keep-alive interval range [min, max] in seconds.
                bool                                                        turbo;          ///< flow-mode turbo: best-link-first first packet + prewarmed carrier links (--mux-mode-turbo); default false.
                struct {
                    struct {
                        int                                                 bytes;          ///< Per-connection reorder buffer byte cap (flow v2); strictly > 0.
                        int                                                 timeout;        ///< Per-connection gap wait timeout in milliseconds (flow v2); strictly > 0.
                    }                                                       reorder;
                    struct {
                        int                                                 bytes;          ///< Session-wide reorder buffer byte cap across all flows; strictly > 0.
                    }                                                       session_reorder;
                    int                                                     max_open;       ///< Max open logical flows (skts + pre-open); strictly > 0.
                    struct {
                        int                                                 max;            ///< Unknown-cid receive budget; strictly > 0 (P0 drops beyond this count).
                    }                                                       unknown_cid;
                }                                                           flow;           ///< Per-flow (flow v2) receiver ordering parameters.
                struct {
                    struct {
                        int                                                 max;            ///< Data tx-queue high-water depth; acceleration read-pump throttles at/above it (D11). > 0.
                        int                                                 stall;          ///< Milliseconds the data tx-queue may stay backlogged before the session is rebuilt (D11 watchdog). > 0.
                    }                                                       queue;
                    struct {
                        int                                                 budget_frames;  ///< Max control frames drained before data per process_tx_all_packets turn; strictly > 0.
                    }                                                       ctrl;
                }                                                           tx;             ///< Transmit-side flow-control / backpressure parameters.
                struct {
                    ppp::string                                             key;            ///< Shared debug secret (`--debug-key`); empty disables remote mux-mode control.
                    ppp::string                                             set_mode;       ///< Transient `--mux-mode-set` request; pushes a mode change to the peer once at startup.
                }                                                           debug;          ///< Debug-only remote control of the peer's scheduler mode.
                struct {
                    bool                                                    enabled;        ///< QUIC-style reliability sub-protocol (ACK + fast retransmit + PTO); negotiated, falls back when the peer lacks it.
                    struct {
                        int                                                 bytes;          ///< Session-wide retransmit buffer byte cap; strictly > 0.
                        int                                                 max_attempts;   ///< Per-frame retransmit attempts before flow reset / session rebuild; strictly > 0.
                    }                                                       rtx;
                    struct {
                        int                                                 delay;          ///< Max delayed-ACK wait in milliseconds; strictly > 0.
                    }                                                       ack;
                    struct {
                        int                                                 timeout;        ///< Gap wait timeout in milliseconds when reliability is active; strictly > 0.
                    }                                                       gap;
                }                                                           reliability;    ///< Negotiated frame-level reliability (ACK / fast retransmit / PTO) parameters.
                struct {
                    bool                                                    enabled;        ///< XOR parity FEC over reliable data frames; requires reliability; default false (bandwidth overhead).
                    int                                                     group;          ///< Data frames per parity group; strictly > 0.
                    int                                                     flush;          ///< Milliseconds a partial group may age before being flushed; strictly > 0.
                }                                                           fec;            ///< Forward-error-correction parameters.
            }                                                               mux;            ///< Multiplexed connection channel parameters.
            struct {
                struct {
                    int                                                     ws;             ///< Plain WebSocket listen port (ws://); 0 disables plain WS.
                    int                                                     wss;            ///< Secure WebSocket listen port (wss://); 0 disables WSS.
                }                                                           listen;
                struct {
                    std::string                                             certificate_file;          ///< Path to PEM-encoded TLS certificate file.
                    std::string                                             certificate_key_file;      ///< Path to PEM-encoded private key file matching the certificate.
                    std::string                                             certificate_chain_file;    ///< Path to PEM-encoded intermediate CA chain file.
                    std::string                                             certificate_key_password;  ///< Passphrase protecting the private key; empty if key is unencrypted.
                    std::string                                             ciphersuites;              ///< Colon-separated TLS 1.3 cipher suite list; empty = OpenSSL default.
                    bool                                                    verify_peer;               ///< Require and verify client certificate when true.
                }                                                           ssl;
                ppp::string                                                 host;           ///< Expected HTTP `Host` header value for WebSocket upgrade validation.
                ppp::string                                                 path;           ///< WebSocket upgrade path (e.g. "/ws"); must begin with '/'.
                struct {
                    std::string                                             error;          ///< Body returned for non-WebSocket HTTP requests (plain text or HTML).
                    ppp::map<ppp::string, ppp::string>                      request;        ///< Extra HTTP headers injected into the client upgrade request.
                    ppp::map<ppp::string, ppp::string>                      response;       ///< Extra HTTP headers injected into the server upgrade response.
                }                                                           http;
            }                                                               websocket;      ///< WebSocket transport (WS/WSS) parameters.
            struct {
                int                                                         kf;             ///< Key-frame interval (packets between re-key events).
                int                                                         kh;             ///< Key hash iterations for KDF strengthening.
                int                                                         kl;             ///< Key length in bits (e.g. 128, 256).
                int                                                         kx;             ///< Key exchange algorithm selector.
                int                                                         sb;             ///< Shuffle block size used by `shuffle_data` mode.
                ppp::string                                                 protocol;       ///< Protocol-layer cipher algorithm name (e.g. "aes-256-cfb").
                ppp::string                                                 protocol_key;   ///< Passphrase used to derive the protocol-layer cipher key.
                ppp::string                                                 transport;      ///< Transport-layer cipher algorithm name (e.g. "aes-128-cfb").
                ppp::string                                                 transport_key;  ///< Passphrase used to derive the transport-layer cipher key.
                bool                                                        masked;         ///< Apply a masking XOR pass over packet headers when true.
                bool                                                        plaintext;      ///< Transmit data in plaintext (no encryption) when true; for debugging only.
                bool                                                        delta_encode;   ///< Apply delta encoding to payload bytes before encryption.
                bool                                                        shuffle_data;   ///< Randomly reorder payload blocks within each packet when true.
                bool                                                        simd_auto;      ///< Transparently run aes-*-cfb via AES-NI when the CPU supports it (default true).
            }                                                               key;            ///< Cryptographic key and cipher configuration.
            TransportAuthConfiguration                                      transport_auth; ///< Shared transport-auth metadata and keyring references; decoded secrets are never stored here.
            std::shared_ptr<const TransportAuthKeyringSnapshot>              transport_auth_keyring; ///< Runtime decoded keyring snapshot; never serialized.
            struct {
                int64_t                                                     size;           ///< Virtual memory file size in bytes; 0 disables vmem backing.
                ppp::string                                                 path;           ///< File path used for memory-mapped virtual memory backing store.
            }                                                               vmem;           ///< Virtual memory (disk-backed buffer) configuration.
            struct {
                int                                                         node;           ///< Server node identifier used for clustering and session routing.
                ppp::string                                                 log;            ///< Path to the structured event log file; empty disables logging.
                bool                                                        subnet;         ///< Advertise client subnets between sessions when true.
                bool                                                        mapping;        ///< Enable server-side static port mapping support when true.
                ppp::string                                                 backend;        ///< URL or address of the authentication/management backend.
                ppp::string                                                 backend_key;    ///< HMAC key used to sign backend API requests.
                struct {
                    IPv6Mode                                                mode;           ///< IPv6 provisioning strategy for connected clients.
                    ppp::string                                             cidr;           ///< IPv6 CIDR prefix pool from which client addresses are allocated.
                    int                                                     prefix_length;  ///< Prefix length delegated to each client (e.g. 64 for /64).
                    ppp::string                                             gateway;        ///< IPv6 gateway address announced to clients.
                    ppp::string                                             dns1;           ///< Primary IPv6 DNS server address announced to clients.
                    ppp::string                                             dns2;           ///< Secondary IPv6 DNS server address announced to clients.
                    int                                                     lease_time;     ///< IPv6 address lease duration in seconds.
                    ppp::map<ppp::string, ppp::string>                      static_addresses; ///< Map of client GUID to statically assigned IPv6 address string.
                }                                                           ipv6;
                /**
                 * @brief Server-side IPv4 address pool configuration.
                 *
                 * When present in the JSON configuration file, the server
                 * enables automatic IPv4 address assignment for connected
                 * clients.  The @c configured flag is set to true whenever
                 * the @c server.ipv4-pool JSON object exists, even if
                 * individual fields are missing.
                 */
                struct {
                    bool                                            configured;  ///< True when @c server.ipv4-pool was present in the JSON config.
                    ppp::string                                     network;     ///< IPv4 network address (e.g. "10.0.0.0").
                    ppp::string                                     mask;        ///< IPv4 subnet mask (e.g. "255.255.255.0").
                }                                                           ipv4_pool;
                struct {
                    bool                                                    enabled;    ///< Enable peer prefix routing on the server.
                    bool                                                    distribute; ///< Push route snapshots to all connected clients.
                    ppp::vector<PeerPrefixRouteConfiguration>               allowed_routes; ///< Fail-closed per-client announce allowlist (guid+network+prefix).
                }                                                           peer_routing;
                struct {
                    bool                                                    enabled;    ///< Permit same-process recovery of suspended authenticated sessions.
                    int64_t                                                 grace_ms;   ///< Maximum carrier outage grace period in milliseconds.
                }                                                           session_resume;
                struct {
                    bool                                                    enabled;    ///< Require transport-auth PSK during server handshakes.
                }                                                           transport_auth;
            }                                                               server;         ///< Server-mode specific parameters.
            struct {
                ppp::string                                                 guid;           ///< Client GUID string used for authentication and session tracking.
                ppp::string                                                 server;         ///< Primary VPN server address in "host:port" format.
                ppp::string                                                 server_proxy;   ///< HTTP/SOCKS proxy address used to reach the VPN server; empty = direct.
                int64_t                                                     bandwidth;      ///< Client-side bandwidth cap in bits per second; 0 = unlimited.
                struct {
                    int                                                     timeout;        ///< Base seconds to wait before attempting a reconnection.
                    int                                                     max_delay;      ///< Maximum exponential reconnect delay in seconds.
                    int                                                     jitter_percent; ///< Symmetric reconnect-delay jitter percentage (0..100).
                }                                                           reconnections;
                struct {
                    bool                                                    enabled;        ///< Enable authenticated L3 session roaming on the client.
                }                                                           session_resume;
                struct {
                    bool                                                    enabled;        ///< Require transport-auth PSK during client handshakes.
                }                                                           transport_auth;
                ClientRoutingConfiguration                                   routing;        ///< Canonical routing policy; legacy route/proxy fields remain mirrored during migration.
#if defined(_WIN32)
                struct {
                    bool                                                    tcp;            ///< Enable Paper Airplane TCP acceleration driver on Windows when true.
                }                                                           paper_airplane;
#endif
                ppp::vector<MappingConfiguration>                           mappings;       ///< List of static port mapping rules activated on connect.
                ppp::vector<RouteConfiguration>                             routes;         ///< List of route sources imported after tunnel establishment.
                ppp::vector<PeerPrefixRouteConfiguration>                   peer_routes;    ///< Static peer-gateway routes installed on connect.
                ppp::vector<PeerPrefixRouteConfiguration>                   peer_route_announce; ///< Prefixes this client advertises as a gateway.
                bool                                                        peer_gateway_forward = false; ///< Forward received remote-prefix packets to the local LAN.
                struct {
                    int                                                     port;           ///< HTTP proxy listen port; 0 disables the local HTTP proxy.
                    ppp::string                                             bind;           ///< HTTP proxy bind address; empty = loopback only.
                }                                                           http_proxy;
                struct {
                    int                                                     port;           ///< SOCKS5 proxy listen port; 0 disables the local SOCKS5 proxy.
                    ppp::string                                             bind;           ///< SOCKS5 proxy bind address; empty = loopback only.
                    ppp::string                                             username;       ///< SOCKS5 authentication username; empty = no authentication.
                    ppp::string                                             password;       ///< SOCKS5 authentication password; empty = no authentication.
                }                                                           socks_proxy;
                bool                                                        proxy_only;     ///< Local HTTP/SOCKS runtime; suppresses host TUN routes/DNS takeover while native policy remains active (also implied by --mode=proxy).
            }                                                               client;         ///< Client-mode specific parameters.
            struct {
                int                                                         update_interval; ///< VIRR (virtual interface routing refresh) update interval in seconds.
                int                                                         retry_interval;  ///< Interval in seconds between VIRR retries on failure.
            }                                                               virr;            ///< Virtual interface routing refresh (VIRR) configuration.
            struct {
                int                                                         update_interval; ///< vBGP route announcement refresh interval in seconds.
            }                                                               vbgp;            ///< Virtual BGP (vBGP) route propagation configuration.
            struct {
                bool                                                        enabled;        ///< Enable telemetry output when true; default false for zero-cost on low-end hardware.
                int                                                         level;          ///< Minimum verbosity level to output: 0=INFO, 1=VERB, 2=DEBUG, 3=TRACE.
                bool                                                        count;          ///< Enable counter metrics when true.
                bool                                                        span;           ///< Enable trace spans when true.
                ppp::string                                                 endpoint;       ///< Optional OTLP/gRPC endpoint; empty uses built-in stderr backend.
                ppp::string                                                 log_file;       ///< Optional local log file path; empty disables file output.
                bool                                                        console_log;    ///< Show log events on local console/file sink.
                bool                                                        console_metric; ///< Show counter/gauge/histogram events on local console/file sink.
                bool                                                        console_span;   ///< Show span events on local console/file sink.
            }                                                               telemetry;       ///< Optional telemetry/observability configuration.
            struct {
                bool                                                        enabled;        ///< Enable server-coordinated P2P path discovery.
                ppp::string                                                 mode;           ///< "relay" keeps server relay only; "direct-preferred" advertises peer candidates.
                int                                                         punch_timeout;  ///< UDP punch timeout in seconds.
                int                                                         keep_alived;    ///< P2P keep-alive interval in seconds.
                ppp::vector<ppp::string>                                    stun_servers;   ///< STUN servers used for future UDP candidate discovery.
                int                                                         max_probes;             ///< Max probe rounds before relay fallback (default 2).
                int                                                         probe_timeout_ms;       ///< Per-round probe timeout in ms (default 2000).
                int                                                         heartbeat_interval_ms;  ///< Heartbeat send interval in ms (default 1000).
                int                                                         heartbeat_miss_max;     ///< Missed heartbeats before Suspect (default 2).
                int                                                         suspect_timeout_ms;     ///< Suspect recovery timeout in ms (default 2000).
                int                                                         migration_grace_ms;     ///< NAT rebind grace period in ms (default 5000).
                int                                                         buffer_pool_count;      ///< Buffer pool count per channel (default 64).
            }                                                               p2p;            ///< Optional P2P virtual-subnet coordination settings.
            struct {
                ppp::string                                                 rules;            ///< Explicit human-readable routing rules file path; empty preserves legacy routing inputs.
                bool                                                        tcp_domain_sniff; ///< Inspect initial TCP payloads for routing domains when true; default false.
            }                                                               routing;          ///< Unified human routing rules configuration.
            /**
             * @brief GeoIP/GeoSite rule generation configuration (Phase G).
             *
             * When enabled, generates bypass CIDR and DNS rule files from
             * text-format GeoIP/GeoSite inputs. Generated files are appended
             * to the existing bypass and dns-rules loading paths.
             *
             * Binary geoip.dat/geosite.dat files can also be downloaded and
             * are parsed by the human routing rules parser when referenced by
             * its GeoIP or GeoSite declarations.
             */
            struct GeoRulesConfiguration final {
                bool                                                        enabled;               ///< Enable geo-rules generation; default false (no-op).
                ppp::string                                                 country;               ///< Target country/region code; default "cn".
                ppp::string                                                 geoip_dat;             ///< Local GeoIP dat cache path for downloads; default "GeoIP.dat".
                ppp::string                                                 geosite_dat;           ///< Local GeoSite dat cache path for downloads; default "GeoSite.dat".
                ppp::string                                                 geoip_download_url;    ///< Optional URL used to download/update geoip_dat before generation.
                ppp::string                                                 geosite_download_url;  ///< Optional URL used to download/update geosite_dat before generation.
                ppp::vector<ppp::string>                                    geoip;                 ///< GeoIP/CIDR source file paths (text CIDR format).
                ppp::vector<ppp::string>                                    geosite;               ///< GeoSite/domain source file paths (text domain format).
                ppp::string                                                 dns_provider_domestic; ///< DNS provider for domestic rules; falls back to dns.servers.domestic or "doh.pub".
                ppp::string                                                 dns_provider_foreign;  ///< DNS provider for foreign rules (reserved); falls back to dns.servers.foreign or "cloudflare".
                ppp::string                                                 output_bypass;         ///< Generated bypass output file path; default "./generated/bypass-cn.txt".
                ppp::string                                                 output_dns_rules;      ///< Generated DNS rules output file path; default "./generated/dns-rules-cn.txt".
                ppp::vector<ppp::string>                                    append_bypass;         ///< Extra CIDR lines or file paths appended after GeoIP results.
                ppp::vector<ppp::string>                                    append_dns_rules;      ///< Extra DNS rule lines, file paths, or rules:// URLs appended after GeoSite results.
            };

            /**
             * @brief DNS resolver configuration for multi-protocol upstream support.
             *
             * Controls domestic/foreign DNS server selection, unmatched-query
             * interception policy, and EDNS Client Subnet (ECS) behavior.
             * New defaults use provider-based full interception: unmatched
             * queries prefer foreign DNS, then domestic DNS, then Cloudflare.
             */
        struct {
            struct {
                ppp::string                                         domestic;        ///< Domestic DNS server identifier (provider shorthand, IP, or URL).
                ppp::string                                         foreign;         ///< Foreign DNS server identifier (provider shorthand, IP, or URL).
                ppp::vector<DnsServerEntry>                         domestic_entries; ///< Structured domestic DNS server entries; populated from object/array forms.
                ppp::vector<DnsServerEntry>                         foreign_entries;  ///< Structured foreign DNS server entries; populated from object/array forms.
            }                                                       servers;         ///< DNS server selection for domestic and foreign queries.
            bool                                                    intercept_unmatched; ///< When true, unmatched DNS queries are intercepted and routed through foreign->domestic->cloudflare; default true.
            struct {
                bool                                                enabled;         ///< Enable EDNS Client Subnet (ECS) OPT RR injection for domestic queries; default false.
                ppp::string                                         override_ip;     ///< Manual exit IP for ECS; highest-priority source. Empty = auto-detect from server or STUN.
            }                                                       ecs;             ///< EDNS Client Subnet configuration.
            struct {
                bool                                                verify_peer;     ///< Verify DoH/DoT server certificates with system/bundled CA roots; default true.
            }                                                       tls;             ///< TLS verification configuration for encrypted DNS upstreams.
            struct {
                ppp::vector<ppp::string>                            candidates;      ///< STUN server candidates for exit IP detection (ip:port or hostname:port).
            }                                                       stun;            ///< STUN server configuration for ECS fallback.
            struct {
                bool                                                enabled = false; ///< Return Clash-style fake IPs for A queries; default false.
                ppp::string                                         range = "198.18.0.1/16"; ///< Assignable IPv4 CIDR for the fake-ip pool.
            }                                                       fake_ip;         ///< Fake-ip mode (Plan C).
        }                                                           dns;             ///< DNS resolver extension configuration.
            GeoRulesConfiguration                                       geo_rules;       ///< GeoIP/GeoSite rule generation configuration (Phase G).
        public:
            /**
             * @brief Initializes configuration fields to default values.
             */
            AppConfiguration() noexcept;

        public:
            /**
             * @brief Resets all fields to built-in defaults.
             */
            void                                                            Clear() noexcept;
            /**
             * @brief Loads configuration data from a JSON object.
             * @param json Source JSON object.
             * @return True when loading and normalization succeed.
             */
            bool                                                            Load(Json::Value& json) noexcept;
            /**
             * @brief Loads configuration data from a JSON file path.
             * @param path Path to the configuration file.
             * @return True when loading and normalization succeed.
             */
            bool                                                            Load(const ppp::string& path) noexcept;

        public:
            /**
             * @brief Internal LCG modifier slot identifiers.
             *
             * Each slot holds a precomputed linear-congruential modifier value
             * derived from the configured key parameters.  The value is used to
             * vary packet framing offsets at runtime, making traffic patterns
             * less predictable.
             */
            enum LcgmodType {
                LCGMOD_TYPE_TRANSMISSION,   ///< Modifier applied to the protocol transmission layer framing.
                LCGMOD_TYPE_STATIC,         ///< Modifier applied to static UDP channel framing.
                LCGMOD_TYPE_MAX             ///< Sentinel value equal to the number of defined modifier slots.
            };
            /**
             * @brief Gets the computed LCG modifier for a type.
             * @param tp Modifier type.
             * @return Computed modifier value.
             */
            int                                                             Lcgmod(LcgmodType tp) noexcept { return _lcgmods[(int)tp]; }

        public:
            /**
             * @brief Gets the current buffer allocator.
             * @return Shared pointer to the allocator.
             */
            std::shared_ptr<ppp::threading::BufferswapAllocator>            GetBufferAllocator() noexcept { return this->_BufferAllocator; }
            /**
             * @brief Replaces the current buffer allocator.
             * @param allocator New allocator instance.
             * @return Previous allocator instance.
             */
            std::shared_ptr<ppp::threading::BufferswapAllocator>            SetBufferAllocator(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<ppp::threading::BufferswapAllocator> result = std::move(this->_BufferAllocator);
                this->_BufferAllocator = allocator;
                return result;
            }

        public:
            /**
             * @brief Serializes configuration to a JSON value.
             * @return JSON object representation.
             */
            Json::Value                                                     ToJson() noexcept;
            /**
             * @brief Serializes configuration to a JSON string.
             * @return JSON string representation.
             */
            ppp::string                                                     ToString() noexcept;
            /**
             * @brief Emits a startup security diagnostics report.
             *
             * Scans the loaded configuration for weak/default/short keys and
             * plaintext mode.  Each finding is logged via the telemetry subsystem
             * and written to the console.  All findings are non-fatal warnings;
             * startup never fails as a result of this call.
             *
             * @note Called once during application startup after telemetry is
             *       configured.  Safe to call multiple times (idempotent).
             */
            void                                                            EmitSecurityDiagnostics() noexcept;

            /**
             * @brief Emits a startup report describing the active MUX scheduler.
             *
             * Logs the active `mux.mode` (Phase 1 observability) and, when the
             * loaded value was normalized (reserved-but-unimplemented mode or an
             * unrecognized value), emits a non-fatal warning describing the
             * fallback. Startup never fails as a result of this call.
             *
             * @note Called once during application startup after telemetry is
             *       configured.  Safe to call multiple times (idempotent).
             */
            void                                                            EmitMuxDiagnostics() noexcept;

            /**
             * @brief Applies proxy-only defaults (local bind addresses and listen ports).
             */
            void                                                            ApplyProxyModeDefaults() noexcept;

            /**
             * @brief Re-runs configuration normalization after runtime CLI overrides.
             * @return True when normalization completes.
             */
            bool                                                            Normalize() noexcept { return Loaded(); }

        private:
            /**
             * @brief Validates and normalizes loaded values.
             * @return True after normalization completes.
             * @note Called internally by both `Load` overloads after JSON parsing.
             *       Clamps out-of-range integers, derives LCG modifiers, and
             *       initialises the buffer allocator when not already set.
             */
            bool                                                            Loaded() noexcept;

        private:
            int                                                             _lcgmods[LCGMOD_TYPE_MAX]; ///< Precomputed LCG modifier values indexed by `LcgmodType`.
            std::shared_ptr<ppp::threading::BufferswapAllocator>            _BufferAllocator;           ///< Shared buffer pool for packet allocation; may be null until explicitly set.
            ppp::string                                                     _mux_mode_diagnostic;       ///< Transient note set by Loaded() when mux.mode was normalized; emitted at startup.
            std::atomic<int>                                                _mux_mode_runtime_override{ -1 }; ///< Debug-only runtime scheduler override (-1=none, else mux::vmux_net::mux_mode); set by remote mux-mode-set, survives session rebuilds.

        public:
            /**
             * @brief Returns the effective scheduler mode token for new mux sessions.
             *
             * Returns the debug runtime override (set by an accepted remote
             * `mux-mode-set`) when present; otherwise the configured `mux.mode`.
             * Safe to call from any thread.
             */
            ppp::string                                                     GetEffectiveMuxMode() const noexcept;
            /**
             * @brief Records a debug-only runtime scheduler override.
             * @param mode_value Scheduler mode value (mux::vmux_net::mux_mode), or -1 to clear.
             * @note Lock-free; readable by the session-rebuild path on another thread.
             */
            void                                                            SetMuxModeRuntimeOverride(int mode_value) noexcept;
        };

        namespace extensions {
            /**
             * @brief Checks whether protocol and transport cipher settings are present.
             * @param configuration Configuration instance to check.
             * @return True when required cipher fields are all non-empty.
             */
            bool                                                            IsHaveCiphertext(const AppConfiguration& configuration) noexcept;
            /**
             * @brief Pointer overload for @ref IsHaveCiphertext.
             * @param configuration Optional configuration pointer.
             * @return True when pointer is valid and ciphertext fields are present.
             */
            inline bool                                                     IsHaveCiphertext(const AppConfiguration* configuration) noexcept { return NULLPTR != configuration ? IsHaveCiphertext(*configuration) : false; }
        }
    }
}
