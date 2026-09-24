#include <ppp/configurations/AppConfiguration.h>

#include <json/json.h>

#include <ppp/configurations/DnsServerValidation.h>
#include <ppp/app/ApplicationMode.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/cryptography/ssea.h>
#include <ppp/threading/Thread.h>
#include <ppp/threading/Executors.h>
#include <ppp/io/File.h>
#include <ppp/ssl/SSL.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>
#include <ppp/ipv6/IPv6Packet.h>
#include <ppp/net/http/HttpClient.h>
#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>

#include <openssl/evp.h>  /* EVP_get_cipherbyname, EVP_CIPHER_key_length - used for legacy cipher detection */

/**
 * @file AppConfiguration.cpp
 * @brief AppConfiguration loading, normalization, and JSON serialization implementation.
 */

using ppp::auxiliary::StringAuxiliary;
using ppp::auxiliary::JsonAuxiliary;
using ppp::cryptography::Ciphertext;
using ppp::io::File;
using ppp::io::FileAccess;
using ppp::net::Ipep;
using ppp::net::AddressFamily;
using ppp::net::IPEndPoint;
using ppp::threading::Thread;
using ppp::threading::Executors;

namespace {
    /**
     * @brief Indicates whether server-side IPv6 data-plane support is available on this platform.
     * @return True on Linux builds, otherwise false.
     */
    static bool                                             SupportsServerIPv6DataPlane() noexcept {
#if defined(_LINUX) && !defined(_ANDROID)
        return true;
#else
        return false;
#endif
    }

    /**
     * @brief Parses textual IPv6 mode into enum value.
     * @param mode Text mode value.
     * @return Parsed IPv6 mode; defaults to none.
     */
    static ppp::configurations::AppConfiguration::IPv6Mode  ParseIPv6Mode(const ppp::string& mode) noexcept {
        ppp::string value = ToLower(mode);
        if (value == "nat66") {
            return ppp::configurations::AppConfiguration::IPv6Mode_Nat66;
        }
        if (value == "gua") {
            return ppp::configurations::AppConfiguration::IPv6Mode_Gua;
        }
        return ppp::configurations::AppConfiguration::IPv6Mode_None;
    }

    /**
     * @brief Converts IPv6 mode enum to configuration string.
     * @param mode IPv6 mode.
     * @return Mode string used in JSON.
     */
    static ppp::string                                      IPv6ModeToString(ppp::configurations::AppConfiguration::IPv6Mode mode) noexcept {
        switch (mode) {
        case ppp::configurations::AppConfiguration::IPv6Mode_Nat66:
            return "nat66";
        case ppp::configurations::AppConfiguration::IPv6Mode_Gua:
            return "gua";
        default:
            return "";
        }
    }

    /**
     * @brief Restricts IPv6 mode to supported values.
     * @param mode Candidate mode.
     * @return Normalized mode value.
     */
    static ppp::configurations::AppConfiguration::IPv6Mode  NormalizeIPv6Mode(ppp::configurations::AppConfiguration::IPv6Mode mode) noexcept {
        switch (mode) {
        case ppp::configurations::AppConfiguration::IPv6Mode_Nat66:
        case ppp::configurations::AppConfiguration::IPv6Mode_Gua:
            return mode;
        default:
            return ppp::configurations::AppConfiguration::IPv6Mode_None;
        }
    }

    /**
     * @brief Normalizes textual MUX scheduler mode.
     *
     * Accepts the implemented schedulers (`compat`, `flow`) plus a few
     * convenience aliases. Design modes that are reserved but not yet
     * implemented (`balance`, `stripe`) and any unrecognized value are
     * normalized to a supported scheduler and described through the optional
     * @p note out-parameter so startup can warn without failing.
     *
     * @param mode Text mode value as written in JSON or on the CLI.
     * @param note Optional out-parameter describing why the value changed.
     * @return Supported mode string; defaults to compat.
     */
    static ppp::string                                      NormalizeMuxMode(const ppp::string& mode, ppp::string* note = nullptr) noexcept {
        if (NULLPTR != note) {
            note->clear();
        }

        ppp::string value = ToLower(LTrim(RTrim(mode)));
        if (value == "flow" || value == "flow-v1" || value == "primary" || value == "primary-link") {
            return "flow";
        }

        if (value == "compat" || value == "legacy" || value == "default") {
            return "compat";
        }

        if (value == "balance" || value == "balanced" || value == "lb" || value == "load-balance") {
            return "balance";
        }

        if (value == "stripe" || value == "striped" || value == "striping") {
            return "stripe";
        }

        if (value.empty()) {
            // Missing field: keep the historical/compatible scheduler silently.
            return "compat";
        }

        if (NULLPTR != note) {
            *note = "mux.mode '" + value + "' is not a recognized scheduler; falling back to 'compat'";
        }
        return "compat";
    }

    /**
     * @brief Parses an IPv6 CIDR string into prefix and prefix length.
     * @param cidr CIDR input.
     * @param prefix Output prefix string.
     * @param prefix_length Output prefix length.
     * @return True when a usable prefix is produced.
     */
    static bool                                             ParseIPv6Cidr(const ppp::string& cidr, ppp::string& prefix, int& prefix_length) noexcept {
        prefix.clear();
        prefix_length = 0;
        if (cidr.empty()) {
            return false;
        }

        std::size_t slash = cidr.find('/');
        if (slash == ppp::string::npos) {
            prefix = cidr;
            prefix_length = ppp::ipv6::IPv6_DEFAULT_PREFIX_LENGTH;
            return true;
        }

        prefix = cidr.substr(0, slash);

        /**
         * @brief Validate prefix length using strtol for proper error detection.
         * @note Reject invalid numeric strings and out-of-range values.
         */
        const ppp::string plen_str = cidr.substr(slash + 1);
        char* endptr = NULLPTR;
        long parsed = strtol(plen_str.c_str(), &endptr, 10);
        if (NULLPTR == endptr || endptr == plen_str.c_str() || *endptr != '\x0' || parsed < ppp::ipv6::IPv6_MIN_PREFIX_LENGTH || parsed > ppp::ipv6::IPv6_MAX_PREFIX_LENGTH)
        {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6PrefixInvalid);
            return false;
        }

        prefix_length = static_cast<int>(parsed);
        return !prefix.empty();
    }

    /**
     * @brief Computes the first host address inside an IPv6 prefix.
     * @param network Network prefix address.
     * @param prefix_length Prefix length.
     * @param host Output host address.
     * @return True when a valid host address is generated.
     */
    static bool                                             TryGetFirstHostIPv6(const boost::asio::ip::address_v6& network, int prefix_length, boost::asio::ip::address_v6& host) noexcept {
        prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));
        if (prefix_length >= ppp::ipv6::IPv6_MAX_PREFIX_LENGTH) {
            return false;
        }

        boost::asio::ip::address_v6::bytes_type bytes = ppp::ipv6::ComputeNetworkAddress(network, prefix_length).to_bytes();
        for (int i = 15; i >= 0; --i) {
            if (bytes[i] != 0xff) {
                ++bytes[i];
                for (int j = i + 1; j < 16; ++j) {
                    bytes[j] = 0;
                }
                host = boost::asio::ip::address_v6(bytes);
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Checks whether an IPv6 prefix is globally routable unicast.
     * @param prefix IPv6 prefix address.
     * @return True when prefix belongs to 2000::/3.
     */
    static bool                                             IsGlobalUnicastIPv6Prefix(const boost::asio::ip::address_v6& prefix) noexcept {
        boost::asio::ip::address_v6::bytes_type bytes = prefix.to_bytes();
        return (bytes[0] & 0xe0) == 0x20;
    }

    /**
     * @brief Clears all server IPv6 runtime settings.
     * @param config Configuration object to update.
     */
    static void                                             DisableServerIPv6(ppp::configurations::AppConfiguration& config) noexcept {
        config.server.ipv6.mode = ppp::configurations::AppConfiguration::IPv6Mode_None;
        config.server.ipv6.cidr.clear();
        config.server.ipv6.prefix_length = 0;
        config.server.ipv6.gateway.clear();
        config.server.ipv6.dns1.clear();
        config.server.ipv6.dns2.clear();
        config.server.ipv6.lease_time = 0;
        config.server.ipv6.static_addresses.clear();
    }
}

namespace ppp {
    namespace configurations {
        static constexpr int                            EVP_HEADER_MSS_MIN_MOD = 64 * 64 * 64;
        static constexpr int                            EVP_HEADER_MSS_MAX_MOD = 94 * 94 * 94;
        static constexpr int                            VEP_HEADER_MSS_MAX_MOD = 1 << 8;
        static constexpr int                            VEP_HEADER_MSS_MIN_MOD = 1 << 7;

        /**
         * @brief Constructs configuration with default values.
         */
        AppConfiguration::AppConfiguration() noexcept {
            Clear();
        }

        /**
         * @brief Resets every configuration section to defaults.
         */
        void AppConfiguration::Clear() noexcept {
            AppConfiguration& config = *this;
            config.concurrent = Thread::GetProcessorCount();
            config.cdn[0] = IPEndPoint::MinPort;
            config.cdn[1] = IPEndPoint::MinPort;
            config.ip.public_ = "";
            config.ip.interface_ = "";

            config.udp.dns.timeout = PPP_DEFAULT_DNS_TIMEOUT;
            config.udp.dns.redirect = "";
            config.udp.dns.ttl = PPP_DEFAULT_DNS_TTL;
            config.udp.dns.turbo = false;
            config.udp.dns.cache = true;
            config.udp.cwnd = 0;
            config.udp.rwnd = 0;
            config.udp.inactive.timeout = PPP_UDP_INACTIVE_TIMEOUT;
            config.udp.listen.port = IPEndPoint::MinPort;
            config.udp.static_.dns = true;
            config.udp.static_.quic = true;
            config.udp.static_.icmp = true;
            config.udp.static_.aggligator = 0;
            config.udp.static_.servers.clear();
            config.udp.static_.keep_alived[0] = PPP_UDP_KEEP_ALIVED_MIN_TIMEOUT;
            config.udp.static_.keep_alived[1] = PPP_UDP_KEEP_ALIVED_MAX_TIMEOUT;

            config.tcp.turbo = false;
            config.tcp.backlog = PPP_LISTEN_BACKLOG;
            config.tcp.fast_open = false;
            config.tcp.listen.port = IPEndPoint::MinPort;
            config.tcp.connect.timeout = PPP_TCP_CONNECT_TIMEOUT;
            config.tcp.connect.nexcept = PPP_TCP_CONNECT_NEXCEPT;
            config.tcp.inactive.timeout = PPP_TCP_INACTIVE_TIMEOUT;
            config.tcp.cwnd = 0;
            config.tcp.rwnd = 0;

            config.mux.connect.timeout = PPP_MUX_CONNECT_TIMEOUT;
            config.mux.inactive.timeout = PPP_MUX_INACTIVE_TIMEOUT;
            config.mux.mode = "compat";
            config.mux.congestions = PPP_MUX_DEFAULT_CONGESTIONS;
            config.mux.keep_alived[0] = PPP_TCP_CONNECT_TIMEOUT;
            config.mux.keep_alived[1] = PPP_MUX_CONNECT_TIMEOUT;
            config.mux.turbo = false;
            config.mux.flow.reorder.bytes = PPP_MUX_FLOW_REORDER_BYTES;
            config.mux.flow.reorder.timeout = PPP_MUX_FLOW_REORDER_TIMEOUT;
            config.mux.flow.session_reorder.bytes = PPP_MUX_FLOW_SESSION_REORDER_BYTES;
            config.mux.flow.max_open = PPP_MUX_FLOW_MAX_OPEN;
            config.mux.flow.unknown_cid.max = PPP_MUX_FLOW_UNKNOWN_CID_MAX;
            config.mux.tx.queue.max = PPP_MUX_TX_QUEUE_HIGH_WATER;
            config.mux.tx.queue.stall = PPP_MUX_TX_BACKLOG_STALL_TIMEOUT;
            config.mux.tx.ctrl.budget_frames = PPP_MUX_TX_CTRL_BUDGET_FRAMES;
            config.mux.debug.key = "";
            config.mux.debug.set_mode = "";
            config.mux.reliability.enabled = true;
            config.mux.reliability.rtx.bytes = PPP_MUX_RELIABILITY_RTX_BYTES;
            config.mux.reliability.rtx.max_attempts = PPP_MUX_RELIABILITY_RTX_MAX_ATTEMPTS;
            config.mux.reliability.ack.delay = PPP_MUX_RELIABILITY_ACK_DELAY;
            config.mux.reliability.gap.timeout = PPP_MUX_RELIABILITY_GAP_TIMEOUT;
            config.mux.fec.enabled = false;
            config.mux.fec.group = PPP_MUX_FEC_GROUP;
            config.mux.fec.flush = PPP_MUX_FEC_FLUSH;

            config.websocket.listen.ws = IPEndPoint::MinPort;
            config.websocket.listen.wss = IPEndPoint::MinPort;
            config.websocket.ssl.verify_peer = true;
            config.websocket.ssl.certificate_file = "";
            config.websocket.ssl.certificate_key_file = "";
            config.websocket.ssl.certificate_chain_file = "";
            config.websocket.ssl.certificate_key_password = "";
            config.websocket.ssl.ciphersuites = GetDefaultCipherSuites();
            config.websocket.host = "";
            config.websocket.path = "";
            config.websocket.http.error = "";
            config.websocket.http.request.clear();
            config.websocket.http.response.clear();

            config.key.kf = 154543927;
            config.key.kh = 12;
            config.key.kl = 10;
            config.key.kx = 128;
            config.key.sb = 0;

            config.key.protocol = PPP_DEFAULT_KEY_PROTOCOL;
            config.key.protocol_key = BOOST_BEAST_VERSION_STRING;
            config.key.transport = PPP_DEFAULT_KEY_TRANSPORT;
            config.key.transport_key = BOOST_BEAST_VERSION_STRING;
            config.key.masked = true;
            config.key.plaintext = true;
            config.key.delta_encode = true;
            config.key.shuffle_data = true;
            config.key.simd_auto = true;
            config.transport_auth.Clear();
            config.transport_auth_keyring.reset();

            config.server.log = "";
            config.server.node = 0;
            config.server.subnet = true;
            config.server.mapping = true;
            config.server.backend = "";
            config.server.backend_key = "";
            config.server.ipv6.mode = AppConfiguration::IPv6Mode_None;
            config.server.ipv6.cidr = "";
            config.server.ipv6.prefix_length = ppp::ipv6::IPv6_MAX_PREFIX_LENGTH;
            config.server.ipv6.gateway = "";
            config.server.ipv6.dns1 = "";
            config.server.ipv6.dns2 = "";
            config.server.ipv6.lease_time = 300;
            config.server.ipv6.static_addresses.clear();

            config.server.ipv4_pool.configured = false;
            config.server.ipv4_pool.network = "";
            config.server.ipv4_pool.mask = "";
            config.server.peer_routing.enabled = false;
            config.server.peer_routing.distribute = true;
            config.server.session_resume.enabled = false;
            config.server.session_resume.grace_ms = 60000;
            config.server.transport_auth.enabled = false;

            config.client.mappings.clear();
            config.client.guid = StringAuxiliary::Int128ToGuidString(MAKE_OWORD(UINT64_MAX, UINT64_MAX));
            config.client.server = "";
            config.client.server_proxy = "";
            config.client.bandwidth = 0;
            config.client.reconnections.timeout = PPP_TCP_CONNECT_TIMEOUT;
            config.client.reconnections.max_delay = 15;
            config.client.reconnections.jitter_percent = 20;
            config.client.session_resume.enabled = false;
            config.client.transport_auth.enabled = false;
            config.client.routing.configured = false;
            config.client.routing.bypass.clear();
            config.client.routing.routes.clear();
            config.client.routing.peer_routes.clear();
            config.client.routing.dns_rules.clear();
            config.client.http_proxy.bind = "";
            config.client.http_proxy.port = PPP_DEFAULT_HTTP_PROXY_PORT;
            config.client.socks_proxy.bind = "";
            config.client.socks_proxy.port = PPP_DEFAULT_SOCKS_PROXY_PORT;
            config.client.socks_proxy.password = "";
            config.client.socks_proxy.username = "";
            config.client.proxy_only = false;
            config.client.routes.clear();
            config.client.peer_routes.clear();
            config.client.peer_route_announce.clear();
            config.client.peer_gateway_forward = false;
#if defined(_WIN32)
            config.client.paper_airplane.tcp = true;
#endif

            config.virr.update_interval = 86400;
            config.virr.retry_interval = 300;
            config.vbgp.update_interval = 3600;

            config.telemetry.enabled = false;
            config.telemetry.level = 0;
            config.telemetry.count = false;
            config.telemetry.span = false;
            config.telemetry.endpoint = "";
            config.telemetry.log_file = "";
            config.telemetry.console_log = true;
            config.telemetry.console_metric = true;
            config.telemetry.console_span = true;

            config.p2p.enabled = false;
            config.p2p.mode = "relay";
            config.p2p.punch_timeout = 5;
            config.p2p.keep_alived = 15;
            config.p2p.stun_servers.clear();
            config.p2p.max_probes = 2;
            config.p2p.probe_timeout_ms = 2000;
            config.p2p.heartbeat_interval_ms = 1000;
            config.p2p.heartbeat_miss_max = 2;
            config.p2p.suspect_timeout_ms = 2000;
            config.p2p.migration_grace_ms = 5000;
            config.p2p.buffer_pool_count = 64;

            config.routing.rules = "";
            config.routing.tcp_domain_sniff = false;

            config.dns.servers.domestic = "doh.pub";
            config.dns.servers.foreign = "cloudflare";
            config.dns.servers.domestic_entries.clear();
            config.dns.servers.foreign_entries.clear();
            config.dns.intercept_unmatched = true;
            config.dns.ecs.enabled = false;
            config.dns.ecs.override_ip = "";
            config.dns.tls.verify_peer = true;
            config.dns.stun.candidates.clear();
            config.dns.fake_ip.enabled = false;
            config.dns.fake_ip.range = "198.18.0.1/16";

            config.geo_rules.enabled = false;
            config.geo_rules.country = "cn";
            config.geo_rules.geoip_dat = "GeoIP.dat";
            config.geo_rules.geosite_dat = "GeoSite.dat";
            config.geo_rules.geoip_download_url = "";
            config.geo_rules.geosite_download_url = "";
            config.geo_rules.geoip.clear();
            config.geo_rules.geosite.clear();
            config.geo_rules.dns_provider_domestic = "";
            config.geo_rules.dns_provider_foreign = "";
            config.geo_rules.output_bypass = "./generated/bypass-cn.txt";
            config.geo_rules.output_dns_rules = "./generated/dns-rules-cn.txt";
            config.geo_rules.append_bypass.clear();
            config.geo_rules.append_dns_rules.clear();

            config._mux_mode_diagnostic.clear();
            memset(config._lcgmods, 0, sizeof(config._lcgmods));
        }

        template <class _Uty>
        /**
         * @brief Trims whitespace from each string pointer in an array.
         * @tparam _Uty Pointer array element type.
         * @param s Pointer array.
         * @param length Number of elements in @p s.
         */
        static void LRTrim(_Uty* s, int length) noexcept {
            for (int i = 0; i < length; i++) {
                *s[i] = LTrim(RTrim(*s[i]));
            }
        }

        /**
         * @brief Returns the cipher key length in bits for a named algorithm via OpenSSL EVP.
         * @param method Cipher algorithm name.
         * @return Key length in bits, or 0 when the method is not recognized by EVP.
         */
        static int GetCipherKeyLengthBits(const ppp::string& method) noexcept {
            const EVP_CIPHER* cipher = EVP_get_cipherbyname(method.data());
            if (NULLPTR != cipher) {
                return EVP_CIPHER_key_length(cipher) * 8;
            }
            return 0;
        }

        /**
         * @brief Emits a kWarning if the configured cipher algorithm is legacy or has a short key.
         *
         * Legacy algorithms detected: RC4, DES (single), Blowfish, CAST5, SEED, IDEA.
         * Short key threshold: below 128 bits.
         *
         * @param method Cipher algorithm name (e.g. "aes-256-cfb", "rc4", "des-cbc").
         */
        static void WarnLegacyCipherAlgorithm(const ppp::string& method) noexcept {
            if (method.empty()) {
                return;
            }

            ppp::string method_lower = ToLower(method);

            /* Detect legacy/broken algorithm families by name. */
            if (method_lower.find("rc4") != ppp::string::npos ||
                method_lower.find("des-") != ppp::string::npos ||   /* catches des-cbc, des-ede*, des-cfb - but not aes-256-cfb */
                (method_lower.size() >= 3 && method_lower[0] == 'd' && method_lower[1] == 'e' && method_lower[2] == 's' && (method_lower.size() == 3 || method_lower[3] == '-')) ||
                method_lower.find("bf-") != ppp::string::npos ||   /* Blowfish */
                method_lower.find("cast5") != ppp::string::npos ||
                method_lower.find("seed-") != ppp::string::npos ||
                method_lower.find("idea-") != ppp::string::npos)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigLegacyCipherAlgorithm);
            }

            /* Detect cipher key length below 128 bits (via OpenSSL EVP metadata). */
            int key_bits = GetCipherKeyLengthBits(method);
            if (key_bits > 0 && key_bits < 128) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigLegacyCipherShortKey);
            }
        }

        /**
         * @brief Trims selected string fields from configuration groups.
         * @param config Configuration object.
         * @param level Selection level for field groups.
         */
        static void LRTrim(AppConfiguration& config, int level) noexcept {
            if (level) {
                ppp::string* strings[] = {
                    &config.ip.public_,
                    &config.ip.interface_,
                    &config.udp.dns.redirect,
                    &config.vmem.path,
                    &config.server.backend,
                    &config.server.backend_key,
                    &config.server.log,
                    &config.server.ipv6.cidr,
                    &config.server.ipv6.gateway,
                    &config.server.ipv6.dns1,
                    &config.server.ipv6.dns2,
                    &config.server.ipv4_pool.network,
                    &config.server.ipv4_pool.mask,
                    &config.client.guid,
                    &config.client.server,
                    &config.client.server_proxy,
                    &config.client.http_proxy.bind,
                    &config.client.socks_proxy.bind,
                    &config.client.socks_proxy.password,
                    &config.client.socks_proxy.username,
                    &config.websocket.host,
                    &config.websocket.path,
                    &config.key.protocol,
                    &config.key.protocol_key,
                    &config.key.transport,
                    &config.key.transport_key,
                    &config.dns.servers.domestic,
                    &config.dns.servers.foreign,
                    &config.dns.ecs.override_ip,
                    &config.routing.rules,
                    &config.geo_rules.country,
                    &config.geo_rules.geoip_dat,
                    &config.geo_rules.geosite_dat,
                    &config.geo_rules.geoip_download_url,
                    &config.geo_rules.geosite_download_url,
                    &config.geo_rules.dns_provider_domestic,
                    &config.geo_rules.dns_provider_foreign,
                    &config.geo_rules.output_bypass,
                    &config.geo_rules.output_dns_rules,
                    &config.p2p.mode,
                };
                LRTrim(strings, arraysizeof(strings));
            }
            else {
                std::string* strings[] = {
                    &config.websocket.ssl.certificate_file,
                    &config.websocket.ssl.certificate_key_file,
                    &config.websocket.ssl.certificate_chain_file,
                    &config.websocket.ssl.certificate_key_password,
                    &config.websocket.ssl.ciphersuites,
                };
                LRTrim(strings, arraysizeof(strings));
            }
        }

        /**
         * @brief Loads and deduplicates client mapping rules from JSON.
         * @param config Target configuration object.
         * @param json JSON mapping node (array or single object).
         * @return True when input shape is supported.
         */
        static bool LoadAllMappings(AppConfiguration& config, Json::Value& json) noexcept {
            using MappingConfiguration = AppConfiguration::MappingConfiguration;

            if (json.isObject()) {
                Json::Value json_array;
                json_array.append(json);

                json = json_array;
            }

            if (!json.isArray()) {
                return false;
            }

            Json::ArrayIndex json_length = json.size();
            ppp::unordered_map<boost::asio::ip::tcp::endpoint, MappingConfiguration> tcp_mappings;
            ppp::unordered_map<boost::asio::ip::udp::endpoint, MappingConfiguration> udp_mappings;

            for (Json::ArrayIndex json_index = 0; json_index < json_length; json_index++) {
                Json::Value& jo = json[json_index];
                if (!jo.isObject()) {
                    continue;
                }

                MappingConfiguration mapping;
                mapping.protocol_tcp_or_udp = ToLower(LTrim(RTrim(JsonAuxiliary::AsString(jo["protocol"])))) != "udp";
                mapping.local_ip = LTrim(RTrim(JsonAuxiliary::AsString(jo["local-ip"])));
                mapping.local_port = JsonAuxiliary::AsValue<int>(jo["local-port"]);
                mapping.remote_ip = LTrim(RTrim(JsonAuxiliary::AsString(jo["remote-ip"])));
                mapping.remote_port = JsonAuxiliary::AsValue<int>(jo["remote-port"]);

                if (mapping.local_port <= IPEndPoint::MinPort || mapping.local_port > IPEndPoint::MaxPort) {
                    continue;
                }

                if (mapping.remote_port <= IPEndPoint::MinPort || mapping.remote_port > IPEndPoint::MaxPort) {
                    continue;
                }

                if (mapping.local_ip.empty() || mapping.remote_ip.empty()) {
                    continue;
                }

                boost::system::error_code ec;
                boost::asio::ip::address local_ip = StringToAddress(mapping.local_ip.data(), ec);
                if (ec) {
                    continue;
                }

                boost::asio::ip::address remote_ip = StringToAddress(mapping.remote_ip.data(), ec);
                if (ec) {
                    continue;
                }

                if (IPEndPoint::IsInvalid(local_ip)) {
                    continue;
                }

                if (!remote_ip.is_unspecified()) {
                    if (IPEndPoint::IsInvalid(remote_ip)) {
                        continue;
                    }
                }

                if (local_ip.is_multicast() || remote_ip.is_multicast()) {
                    continue;
                }

                mapping.local_ip = local_ip.to_string();
                mapping.remote_ip = remote_ip.to_string();

                if (mapping.protocol_tcp_or_udp) {
                    boost::asio::ip::tcp::endpoint remote_ep = boost::asio::ip::tcp::endpoint(remote_ip, mapping.remote_port);
                    tcp_mappings.emplace(remote_ep, mapping);
                }
                else {
                    boost::asio::ip::udp::endpoint remote_ep = boost::asio::ip::udp::endpoint(remote_ip, mapping.remote_port);
                    udp_mappings.emplace(remote_ep, mapping);
                }
            }

            ppp::vector<MappingConfiguration>& client_mappings = config.client.mappings;
            client_mappings.clear();

            for (auto&& [_, mapping] : tcp_mappings) {
                client_mappings.emplace_back(mapping);
            }

            for (auto&& [_, mapping] : udp_mappings) {
                client_mappings.emplace_back(mapping);
            }

            return true;
        }

        /**
         * @brief Normalizes and validates loaded configuration values.
         * @return True when normalization completes.
         */
        bool AppConfiguration::Loaded() noexcept {
            AppConfiguration& config = *this;
            std::shared_ptr<const TransportAuthKeyringSnapshot> transport_auth_candidate;
            if (config.concurrent < 1) {
                config.concurrent = Thread::GetProcessorCount();
            }

            config.server.node = std::max<int>(0, config.server.node);
            config.server.ipv6.prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, config.server.ipv6.prefix_length));
            config.udp.dns.ttl = std::max<int>(0, config.udp.dns.ttl);

            if (config.udp.dns.timeout < 1) {
                config.udp.dns.timeout = PPP_DEFAULT_DNS_TIMEOUT;
            }

            if (config.udp.inactive.timeout < 1) {
                config.udp.inactive.timeout = PPP_UDP_INACTIVE_TIMEOUT;
            }

            if (config.tcp.backlog < 1) {
                config.tcp.backlog = PPP_LISTEN_BACKLOG;
            }

            if (config.tcp.connect.timeout < 1) {
                config.tcp.connect.timeout = PPP_TCP_CONNECT_TIMEOUT;
            }

            if (config.tcp.connect.nexcept < 0) {
                config.tcp.connect.nexcept = PPP_TCP_CONNECT_NEXCEPT;
            }

            if (config.tcp.inactive.timeout < 1) {
                config.tcp.inactive.timeout = PPP_TCP_INACTIVE_TIMEOUT;
            }

            if (config.mux.connect.timeout < 1) {
                config.mux.connect.timeout = PPP_MUX_CONNECT_TIMEOUT;
            }

            if (config.mux.inactive.timeout < 1) {
                config.mux.inactive.timeout = PPP_MUX_INACTIVE_TIMEOUT;
            }

            if (config.mux.congestions < 0 || (config.mux.congestions > 0 && config.mux.congestions < PPP_MUX_MIN_CONGESTIONS)) {
                config.mux.congestions = PPP_MUX_DEFAULT_CONGESTIONS;
            }

            config.mux.mode = NormalizeMuxMode(config.mux.mode, &config._mux_mode_diagnostic);
            config.mux.debug.key = LTrim(RTrim(config.mux.debug.key));
            config.mux.debug.set_mode = LTrim(RTrim(config.mux.debug.set_mode));

            if (config.mux.flow.reorder.bytes <= 0) {
                config.mux.flow.reorder.bytes = PPP_MUX_FLOW_REORDER_BYTES;
            }

            if (config.mux.flow.reorder.timeout <= 0) {
                config.mux.flow.reorder.timeout = PPP_MUX_FLOW_REORDER_TIMEOUT;
            }

            if (config.mux.flow.session_reorder.bytes <= 0) {
                config.mux.flow.session_reorder.bytes = PPP_MUX_FLOW_SESSION_REORDER_BYTES;
            }

            if (config.mux.flow.max_open <= 0) {
                config.mux.flow.max_open = PPP_MUX_FLOW_MAX_OPEN;
            }

            if (config.mux.flow.unknown_cid.max <= 0) {
                config.mux.flow.unknown_cid.max = PPP_MUX_FLOW_UNKNOWN_CID_MAX;
            }

            if (config.mux.tx.queue.max <= 0) {
                config.mux.tx.queue.max = PPP_MUX_TX_QUEUE_HIGH_WATER;
            }

            if (config.mux.tx.queue.stall <= 0) {
                config.mux.tx.queue.stall = PPP_MUX_TX_BACKLOG_STALL_TIMEOUT;
            }

            if (config.mux.tx.ctrl.budget_frames <= 0) {
                config.mux.tx.ctrl.budget_frames = PPP_MUX_TX_CTRL_BUDGET_FRAMES;
            }

            if (config.mux.reliability.rtx.bytes <= 0) {
                config.mux.reliability.rtx.bytes = PPP_MUX_RELIABILITY_RTX_BYTES;
            }

            if (config.mux.reliability.rtx.max_attempts <= 0) {
                config.mux.reliability.rtx.max_attempts = PPP_MUX_RELIABILITY_RTX_MAX_ATTEMPTS;
            }

            if (config.mux.reliability.ack.delay <= 0) {
                config.mux.reliability.ack.delay = PPP_MUX_RELIABILITY_ACK_DELAY;
            }

            if (config.mux.reliability.gap.timeout <= 0) {
                config.mux.reliability.gap.timeout = PPP_MUX_RELIABILITY_GAP_TIMEOUT;
            }

            if (config.mux.fec.group <= 0) {
                config.mux.fec.group = PPP_MUX_FEC_GROUP;
            }

            if (config.mux.fec.flush <= 0) {
                config.mux.fec.flush = PPP_MUX_FEC_FLUSH;
            }

            if (config.udp.static_.aggligator < 0) {
                config.udp.static_.aggligator = 0;
            }

            LRTrim(config, 0);
            LRTrim(config, 1);

            if (config.client.routing.configured) {
                NormalizeClientRoutingStringList(config.client.routing.bypass);
                NormalizeClientRoutingStringList(config.client.routing.dns_rules);
                config.client.routes = config.client.routing.routes;
                config.client.peer_routes = config.client.routing.peer_routes;
            }
            else {
                // Legacy input remains supported, but is exposed through the
                // canonical projection for callers that consume client.routing.
                // The independent client.proxy_only flag is not projected here.
                config.client.routing.routes = config.client.routes;
                config.client.routing.peer_routes = config.client.peer_routes;
                NormalizeClientRoutingStringList(config.client.routing.bypass);
                NormalizeClientRoutingStringList(config.client.routing.dns_rules);
            }

            // Trim string fields inside structured DNS server entries.
            for (auto* entries : { &config.dns.servers.domestic_entries, &config.dns.servers.foreign_entries }) {
                for (auto& entry : *entries) {
                    entry.protocol  = LTrim(RTrim(entry.protocol));
                    entry.url       = LTrim(RTrim(entry.url));
                    entry.hostname  = LTrim(RTrim(entry.hostname));
                    entry.address   = LTrim(RTrim(entry.address));
                    for (auto& b : entry.bootstrap) {
                        b = LTrim(RTrim(b));
                    }
                    // Remove empty bootstrap entries.
                    entry.bootstrap.erase(
                        std::remove_if(entry.bootstrap.begin(), entry.bootstrap.end(),
                            [](const ppp::string& s) noexcept { return s.empty(); }),
                        entry.bootstrap.end());
                }
            }

            for (auto* vec : { &config.geo_rules.geoip, &config.geo_rules.geosite,
                               &config.geo_rules.append_bypass, &config.geo_rules.append_dns_rules,
                               &config.p2p.stun_servers }) {
                for (auto& s : *vec) {
                    s = LTrim(RTrim(s));
                }
                vec->erase(
                    std::remove_if(vec->begin(), vec->end(),
                        [](const ppp::string& s) noexcept { return s.empty(); }),
                    vec->end());
            }

            if (config.client.guid.empty()) {
                config.client.guid = StringAuxiliary::Int128ToGuidString(MAKE_OWORD(UINT64_MAX, UINT64_MAX));
            }

            if (config.server.session_resume.grace_ms < 1000) {
                config.server.session_resume.grace_ms = 1000;
            }
            elif(config.server.session_resume.grace_ms > 3600000) {
                config.server.session_resume.grace_ms = 3600000;
            }

            if (config.client.reconnections.timeout < 1) {
                config.client.reconnections.timeout = PPP_TCP_CONNECT_TIMEOUT;
            }
            if (config.client.reconnections.max_delay < config.client.reconnections.timeout) {
                config.client.reconnections.max_delay = config.client.reconnections.timeout;
            }
            config.client.reconnections.jitter_percent =
                std::max(0, std::min(100, config.client.reconnections.jitter_percent));

            const bool transport_auth_enabled =
                config.client.transport_auth.enabled || config.server.transport_auth.enabled;
            if (!config.transport_auth.Normalize(transport_auth_enabled)) {
                return false;
            }
            if (transport_auth_enabled) {
                transport_auth_candidate = BuildTransportAuthKeyringSnapshot(config.transport_auth);
                if (!transport_auth_candidate) {
                    return false;
                }
            }

            int* pts[] = {
                &config.tcp.listen.port,
                &config.websocket.listen.ws,
                &config.websocket.listen.wss,
                &config.client.http_proxy.port,
                &config.client.socks_proxy.port,
                &config.udp.listen.port
            };

            for (int i = 0; i < arraysizeof(pts); i++) {
                int& port = *pts[i];
                if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    port = IPEndPoint::MinPort;
                }
            }

            for (int i = 0; i < arraysizeof(config.cdn); i++) {
                int& cdn = config.cdn[i];
                if (cdn < IPEndPoint::MinPort || cdn > IPEndPoint::MaxPort) {
                    cdn = IPEndPoint::MinPort;
                }
            }

            for (int i = 0; i < arraysizeof(config.udp.static_.keep_alived); i++) {
                int& keep_alived = config.udp.static_.keep_alived[i];
                keep_alived = std::max<int>(0, keep_alived);
            }

            for (int i = 0; i < arraysizeof(config.mux.keep_alived); i++) {
                int& keep_alived = config.mux.keep_alived[i];
                keep_alived = std::max<int>(0, keep_alived);
            }

            ppp::string* ips[] = {
                &config.ip.public_,
                &config.ip.interface_,
                &config.client.http_proxy.bind,
                &config.client.socks_proxy.bind,
            };
            for (int i = 0; i < arraysizeof(ips); i++) {
                ppp::string& ip = *ips[i];
                if (ip.empty()) {
                    continue;
                }

                boost::system::error_code ec;
                boost::asio::ip::address address = StringToAddress(ip.data(), ec);
                if (ec) {
                    ip = "";
                }
                elif(IPEndPoint::IsInvalid(address) && !(address.is_unspecified() && (address.is_v4() || address.is_v6()))) {
                    ip = "";
                }
                else {
                    ip = Ipep::ToAddressString<ppp::string>(address);
                }
            }

            config.server.ipv6.mode = NormalizeIPv6Mode(config.server.ipv6.mode);
            bool ipv6_server_enabled = config.server.ipv6.mode == AppConfiguration::IPv6Mode_Nat66 ||
                config.server.ipv6.mode == AppConfiguration::IPv6Mode_Gua;
            if (ipv6_server_enabled && !SupportsServerIPv6DataPlane()) {
                if (config.server.ipv6.mode == AppConfiguration::IPv6Mode_Nat66) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6Nat66Unavailable);
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::PlatformNotSupportGUAMode);
                }
                return false;
            }

            ppp::string ipv6_prefix;
            ParseIPv6Cidr(config.server.ipv6.cidr, ipv6_prefix, config.server.ipv6.prefix_length);

            if (ipv6_server_enabled) {
                if (config.server.ipv6.mode == AppConfiguration::IPv6Mode_Nat66) {
                    if (ipv6_prefix.empty()) {
                        ipv6_prefix = ppp::ipv6::IPV6_DEFAULT_PREFIX;
                        config.server.ipv6.prefix_length = 64;
                    }
                }

                if (config.server.ipv6.prefix_length <= ppp::ipv6::IPv6_MIN_PREFIX_LENGTH || config.server.ipv6.prefix_length >= ppp::ipv6::IPv6_MAX_PREFIX_LENGTH) {
                    DisableServerIPv6(config);
                    ipv6_prefix = "";
                    ipv6_server_enabled = false;
                }
            }
            else {
                config.server.ipv6.mode = AppConfiguration::IPv6Mode_None;
            }

            if (ipv6_server_enabled) {
                boost::asio::ip::address_v6 cidr_prefix = boost::asio::ip::address_v6();
                boost::system::error_code cidr_ec;
                if (!ipv6_prefix.empty()) {
                    cidr_prefix = boost::asio::ip::make_address_v6(ipv6_prefix.c_str(), cidr_ec);
                    if (!cidr_ec) {
                        cidr_prefix = ppp::ipv6::ComputeNetworkAddress(cidr_prefix, config.server.ipv6.prefix_length);
                        ipv6_prefix = cidr_prefix.to_string();
                    }
                }

                bool invalid_server_prefix = cidr_ec || ipv6_prefix.empty() || cidr_prefix.is_unspecified() || cidr_prefix.is_multicast() || cidr_prefix.is_loopback();
                if (!invalid_server_prefix && config.server.ipv6.mode == AppConfiguration::IPv6Mode_Gua) {
                    invalid_server_prefix = !IsGlobalUnicastIPv6Prefix(cidr_prefix);
                }
                if (invalid_server_prefix) {
                    DisableServerIPv6(config);
                    ipv6_prefix.clear();
                    ipv6_server_enabled = false;
                }
            }

            if (ipv6_server_enabled) {
                boost::asio::ip::address_v6 cidr_prefix = boost::asio::ip::address_v6();
                boost::system::error_code cidr_ec;
                if (!ipv6_prefix.empty()) {
                    cidr_prefix = boost::asio::ip::make_address_v6(ipv6_prefix.c_str(), cidr_ec);
                }

                boost::system::error_code gateway_ec;
                boost::asio::ip::address configured_gateway = StringToAddress(config.server.ipv6.gateway, gateway_ec);
                boost::asio::ip::address_v6 effective_gateway_v6 = boost::asio::ip::address_v6();
                bool has_effective_gateway = false;
                if (gateway_ec || !configured_gateway.is_v6() || cidr_ec) {
                    config.server.ipv6.gateway.clear();
                }
                elif (!ppp::ipv6::PrefixMatch(configured_gateway.to_v6(), cidr_prefix, config.server.ipv6.prefix_length)) {
                    config.server.ipv6.gateway.clear();
                }
                elif (configured_gateway.to_v6() == cidr_prefix) {
                    config.server.ipv6.gateway.clear();
                }
                else {
                    effective_gateway_v6 = configured_gateway.to_v6();
                    has_effective_gateway = true;
                }

                if (!has_effective_gateway && !cidr_ec) {
                    has_effective_gateway = TryGetFirstHostIPv6(cidr_prefix, config.server.ipv6.prefix_length, effective_gateway_v6);
                }

                ppp::map<ppp::string, ppp::string> normalized_static_addresses;
                ppp::unordered_set<ppp::string> used_static_addresses;
                /**
                 * @brief Normalize static IPv6 leases to valid, unique, in-prefix addresses.
                 */
                for (const auto& kv : config.server.ipv6.static_addresses) {
                    Int128 static_guid_id = auxiliary::StringAuxiliary::GuidStringToInt128(kv.first);
                    if (static_guid_id == 0) {
                        continue;
                    }

                    boost::system::error_code static_ec;
                    boost::asio::ip::address static_address = StringToAddress(kv.second, static_ec);
                    if (static_ec || !static_address.is_v6()) {
                        continue;
                    }

                    boost::asio::ip::address_v6 static_v6 = static_address.to_v6();
                    if (cidr_ec || !ppp::ipv6::PrefixMatch(static_v6, cidr_prefix, config.server.ipv6.prefix_length)) {
                        continue;
                    }

                    if (has_effective_gateway && static_v6 == effective_gateway_v6) {
                        continue;
                    }

                    std::string normalized_address_std = static_v6.to_string();
                    ppp::string normalized_address(normalized_address_std.data(), normalized_address_std.size());
                    if (used_static_addresses.emplace(normalized_address).second) {
                        normalized_static_addresses[auxiliary::StringAuxiliary::Int128ToGuidString(static_guid_id)] = normalized_address;
                    }
                }
                config.server.ipv6.static_addresses = std::move(normalized_static_addresses);
            }

            if (!Ciphertext::Support(config.key.protocol)) {
                config.key.protocol = PPP_DEFAULT_KEY_PROTOCOL;
            }

            if (!Ciphertext::Support(config.key.transport)) {
                config.key.transport = PPP_DEFAULT_KEY_TRANSPORT;
            }

            if (config.key.protocol_key.empty()) {
                config.key.protocol_key = BOOST_BEAST_VERSION_STRING;
            }

            if (config.key.transport_key.empty()) {
                config.key.transport_key = BOOST_BEAST_VERSION_STRING;
            }

            /**
             * @brief Security posture warnings (P0-2).
             *
             * Weak keys, example keys, short keys and plaintext mode are detected here
             * and surfaced as non-fatal warnings.  They never block startup — the
             * application continues to function for backward compatibility.  Production
             * deployments should replace these with strong, unique keys and disable
             * plaintext mode.
             */
            {
                const ppp::string default_key = BOOST_BEAST_VERSION_STRING;  /* well-known "ppp" */

                /* Protocol key warnings */
                if (config.key.protocol_key == default_key) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigWeakKeyDefault);
                }
                elif(config.key.protocol_key.size() < 8) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigWeakKeyShort);
                }

                /* Transport key warnings */
                if (config.key.transport_key == default_key) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigWeakKeyDefault);
                }
                elif(config.key.transport_key.size() < 8) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigWeakKeyShort);
                }

                /* Plaintext mode warning */
                if (config.key.plaintext) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigPlaintextEnabled);
                }

                /**
                 * @brief Legacy cipher algorithm warnings (P1-7).
                 *
                 * Detects RC4, single-DES, Blowfish, CAST5, SEED, IDEA and
                 * cipher key lengths below 128 bits.  These warnings never
                 * block startup — legacy algorithms remain fully functional
                 * for backward compatibility.  Production deployments should
                 * migrate to AES-256-GCM / ChaCha20-Poly1305.
                 */
                WarnLegacyCipherAlgorithm(config.key.protocol);
                WarnLegacyCipherAlgorithm(config.key.transport);

                /* EVP::initKey currently derives keys via EVP_BytesToKey(..., EVP_md5(), ...).
                 * This informational warning documents the legacy KDF debt without changing behavior. */
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigLegacyKdfMd5);
            }

            if (!Ipep::IsDomainAddress(config.websocket.host) || config.websocket.path.empty() || config.websocket.path[0] != '/') {
                config.websocket.listen.ws = IPEndPoint::MinPort;
                config.websocket.listen.wss = IPEndPoint::MinPort;
            }
            elif(!ppp::ssl::SSL::VerifySslCertificate(config.websocket.ssl.certificate_file, config.websocket.ssl.certificate_key_file, config.websocket.ssl.certificate_chain_file)) {
                config.websocket.listen.wss = IPEndPoint::MinPort;
            }

            if (config.websocket.listen.wss == IPEndPoint::MinPort) {
                config.websocket.ssl.certificate_file = "";
                config.websocket.ssl.certificate_key_file = "";
                config.websocket.ssl.certificate_chain_file = "";
                config.websocket.ssl.certificate_key_password = "";
            }
            elif(config.websocket.ssl.ciphersuites.empty()) {
                config.websocket.ssl.ciphersuites = GetDefaultCipherSuites();
            }

            if (config.websocket.listen.ws == IPEndPoint::MinPort) {
                config.websocket.path = "";
                config.websocket.host = "";
                config.websocket.http.error = "";
                config.websocket.http.request.clear();
                config.websocket.http.response.clear();
            }

            config.server.ipv6.prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, config.server.ipv6.prefix_length));
            config.server.ipv6.lease_time = std::max<int>(0, config.server.ipv6.lease_time);
            config.server.ipv6.cidr = ipv6_prefix;
            if (config.server.ipv6.prefix_length > 0) {
                config.server.ipv6.cidr.append("/");
                config.server.ipv6.cidr.append(stl::to_string<ppp::string>(config.server.ipv6.prefix_length));
            }

            {
                int destinationPort = IPEndPoint::MinPort;
                ppp::string destinationIP;

                ppp::string& redirect_string = config.udp.dns.redirect;
                if (!Ipep::ParseEndPoint(redirect_string, destinationIP, destinationPort)) {
                    redirect_string = "";
                }
                else {
                    boost::system::error_code ec;
                    boost::asio::ip::address address = StringToAddress(destinationIP.data(), ec);
                    if (ec) {
                        if (!Ipep::IsDomainAddress(destinationIP)) {
                            redirect_string = "";
                        }
                    }
                    elif(IPEndPoint::IsInvalid(address)) {
                        redirect_string = "";
                    }
                }
            }

            if (config.vmem.path.empty() || config.vmem.size < 1) {
                config.vmem.size = 0;
                config.vmem.path = "";
            }

            ppp::string& log = config.server.log;
            if (log.size() > 0) {
                log = File::GetFullPath(File::RewritePath(log.data()).data());
            }

            config.key.kh = std::max<int>(0, config.key.kh);
            config.key.kl = std::max<int>(0, config.key.kl);
            config.key.kx = std::max<int>(0, config.key.kx);
            config.key.kh = std::min<int>(16, config.key.kh);
            config.key.kl = std::min<int>(16, config.key.kl);
            config.key.sb = std::min<int>(std::max<int>(0, PPP_BUFFER_SIZE - PPP_BUFFER_SIZE_SKATEBOARDING), std::max<int>(0, config.key.sb));

            config.client.bandwidth = std::max<int64_t>(0, config.client.bandwidth);

            config.virr.retry_interval = std::max<int>(1, config.virr.retry_interval);
            config.virr.update_interval = std::max<int>(1, config.virr.update_interval);
            config.vbgp.update_interval = std::max<int>(1, config.vbgp.update_interval);

            config.p2p.mode = ToLower(config.p2p.mode);
            if (config.p2p.mode != "direct-preferred") {
                config.p2p.mode = "relay";
            }
            if (!config.p2p.enabled) {
                config.p2p.mode = "relay";
            }
            config.p2p.punch_timeout = std::max<int>(1, config.p2p.punch_timeout);
            config.p2p.keep_alived = std::max<int>(1, config.p2p.keep_alived);
            config.p2p.max_probes = std::clamp<int>(config.p2p.max_probes, 1, 10);
            config.p2p.probe_timeout_ms = std::clamp<int>(config.p2p.probe_timeout_ms, 500, 10000);
            config.p2p.heartbeat_interval_ms = std::clamp<int>(config.p2p.heartbeat_interval_ms, 500, 5000);
            config.p2p.heartbeat_miss_max = std::clamp<int>(config.p2p.heartbeat_miss_max, 1, 10);
            config.p2p.suspect_timeout_ms = std::clamp<int>(config.p2p.suspect_timeout_ms, 500, 10000);
            config.p2p.migration_grace_ms = std::clamp<int>(config.p2p.migration_grace_ms, 1000, 30000);
            config.p2p.buffer_pool_count = std::clamp<int>(config.p2p.buffer_pool_count, 8, 256);

            // Validate dns.ecs.override_ip: if non-empty, must be a valid IP address.
            // Accept both IPv4 and IPv6.  ECS first version primarily uses IPv4,
            // but the configuration field itself allows either family.
            if (!config.dns.ecs.override_ip.empty()) {
                boost::system::error_code dns_ec;
                boost::asio::ip::address dns_addr = StringToAddress(config.dns.ecs.override_ip.data(), dns_ec);
                if (dns_ec || IPEndPoint::IsInvalid(dns_addr)) {
                    config.dns.ecs.override_ip = "";
                }
                else {
                    config.dns.ecs.override_ip = Ipep::ToAddressString<ppp::string>(dns_addr);
                }
            }

            config._lcgmods[LCGMOD_TYPE_TRANSMISSION] = ppp::cryptography::ssea::lcgmod(config.key.kf, EVP_HEADER_MSS_MIN_MOD, EVP_HEADER_MSS_MAX_MOD);
            config._lcgmods[LCGMOD_TYPE_STATIC] = ppp::cryptography::ssea::lcgmod(config.key.kf, VEP_HEADER_MSS_MIN_MOD, VEP_HEADER_MSS_MAX_MOD);
            config.transport_auth_keyring = std::move(transport_auth_candidate);
            return true;
        }

        /**
         * @brief Loads configuration from a JSON file path.
         * @param path Configuration file path.
         * @return True when file parsing and normalization succeed.
         */
        bool AppConfiguration::Load(const ppp::string& path) noexcept {
            Clear();
            if (path.empty()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigPathInvalid);
            }

            ppp::string file_path = File::GetFullPath(File::RewritePath(path.data()).data());
            if (file_path.empty()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigPathInvalid);
            }

            ppp::string json_string = File::ReadAllText(file_path.data());
            if (json_string.empty()) {
                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigFileEmpty);
                }

                return false;
            }

            Json::Value json = JsonAuxiliary::FromString(json_string);
            if (!json.isObject()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::AppConfigurationLoadJsonNotObject);
            }
            else {
                bool loaded = Load(json);
                if (!loaded && ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigLoadFailed);
                }
                return loaded;
            }
        }

        template <typename TMap>
        /**
         * @brief Reads object/array JSON values into a key-value map.
         * @tparam TMap Map-like target container type.
         * @param json Source JSON node.
         * @param map Output map.
         * @return True when JSON type is object or array.
         */
        static bool ReadJsonAllTokensToMap(const Json::Value& json, TMap& map) noexcept {
            map.clear();

            if (json.isObject()) {
                for (ppp::string& k : json.getMemberNames()) {
                    Json::Value v = json[k.data()];
                    map[k] = LTrim(RTrim(JsonAuxiliary::AsString(v)));
                }

                return true;
            }
            elif(json.isArray()) {
                Json::ArrayIndex json_size = json.size();
                for (Json::ArrayIndex json_index = 0; json_index < json_size; json_index++) {
                    Json::Value v = json[json_index];
                    map[stl::to_string<ppp::string>(json_index)] = LTrim(RTrim(JsonAuxiliary::AsString(v)));
                }

                return true;
            }

            return false;
        }

        template <typename TSet>
        /**
         * @brief Reads object/array/string JSON values into a string set.
         * @tparam TSet Set-like target container type.
         * @param json Source JSON node.
         * @param s Output set.
         * @return True when JSON type is object or array.
         */
        static bool ReadJsonAllTokensToSet(const Json::Value& json, TSet& s) noexcept {
            s.clear();

            auto emplace =
                [](const ppp::string& v, TSet& s) noexcept {
                ppp::string x = LTrim(RTrim(JsonAuxiliary::AsString(v)));
                if (!x.empty()) {
                    s.emplace(x);
                }
                };

            if (json.isObject()) {
                for (ppp::string& k : json.getMemberNames()) {
                    Json::Value v = json[k.data()];
                    emplace(JsonAuxiliary::AsString(v), s);
                }

                return true;
            }
            elif(json.isArray()) {
                Json::ArrayIndex json_size = json.size();
                for (Json::ArrayIndex json_index = 0; json_index < json_size; json_index++) {
                    Json::Value v = json[json_index];
                    emplace(JsonAuxiliary::AsString(v), s);
                }

                return true;
            }
            elif(json.isString()) {
                emplace(JsonAuxiliary::AsString(json), s);
            }

            return false;
        }

        /**
         * @brief Validates that a string is an IP literal or domain name.
         * @param host_string Input host text.
         * @param out Optional parsed address output when host is an IP.
         * @return True when host is valid.
         */
        static bool IPOrHostIsValid(const ppp::string& host_string, boost::asio::ip::address* out = NULLPTR) noexcept {
            if (host_string.empty()) {
                return false;
            }

            boost::system::error_code ec;
            boost::asio::ip::address address = StringToAddress(host_string, ec);
            if (ec) {
                return ppp::net::Ipep::IsDomainAddress(host_string);
            }
            elif(address.is_v4() || address.is_v6()) {
                bool valid = !IPEndPoint::IsInvalid(address);
                if (NULLPTR != out && valid) {
                    *out = address;
                }

                return valid;
            }
            else {
                return false;
            }
        }

        /**
         * @brief Reads and validates endpoint strings into a normalized set.
         * @param json Source JSON node.
         * @param s Output endpoint set.
         * @return True when token extraction succeeds.
         */
        static bool ReadJsonAllAddressStringToSet(const Json::Value& json, ppp::unordered_set<ppp::string>& s) noexcept {
            s.clear();

            ppp::unordered_set<ppp::string> sets;
            if (!ReadJsonAllTokensToSet(json, sets)) {
                return false;
            }

            for (const ppp::string& server_string : sets) {
                if (server_string.empty()) {
                    continue;
                }

                ppp::string host_string;
                int port;

                if (!ppp::net::Ipep::ParseEndPoint(server_string, host_string, port)) {
                    continue;
                }

                if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    continue;
                }

                if (!IPOrHostIsValid(host_string)) {
                    continue;
                }

                host_string = LTrim(RTrim(host_string));
                if (!host_string.empty()) {
                    s.emplace(host_string + ":" + stl::to_string<ppp::string>(port));
                }
            }
            return true;
        }

        template <typename TValue>
        /**
         * @brief Assigns a JSON value when the node is present.
         * @tparam TValue Destination type.
         * @param destination Output destination value.
         * @param json Source JSON node.
         * @return True when assignment is performed.
         */
        static bool AssignIfPresent(TValue& destination, const Json::Value& json) noexcept {
            if (json.isNull()) {
                return false;
            }

            destination = JsonAuxiliary::AsValue<TValue>(json);
            return true;
        }

        /**
         * @brief Assigns a boolean JSON value when the node is present.
         * @param destination Output destination value.
         * @param json Source JSON node.
         * @return True when assignment is performed.
         */
        static bool AssignBoolIfPresent(bool& destination, const Json::Value& json) noexcept {
            if (json.isNull()) {
                return false;
            }

            destination = JsonAuxiliary::AsValue<bool>(json);
            return true;
        }

        static bool ReadJsonToPeerPrefixRoute(AppConfiguration::PeerPrefixRouteConfiguration& route, const Json::Value& json) noexcept {
            if (!json.isObject()) {
                return false;
            }

            route.network = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(json["network"])));
            route.prefix = static_cast<int>(JsonAuxiliary::AsInt64(json["prefix"], 0));
            route.via = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(json["via"])));
            route.guid = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(json["guid"])));
            return !route.network.empty() && route.prefix > 0 && route.prefix <= ppp::net::native::MAX_PREFIX_VALUE_V4;
        }

        static void LoadAllPeerPrefixRoutes(ppp::vector<AppConfiguration::PeerPrefixRouteConfiguration>& routes, const Json::Value& json) noexcept {
            routes.clear();
            if (!json.isArray()) {
                return;
            }

            for (const auto& item : json) {
                AppConfiguration::PeerPrefixRouteConfiguration route;
                if (ReadJsonToPeerPrefixRoute(route, item)) {
                    routes.emplace_back(std::move(route));
                }
            }
        }

        /**
         * @brief Parses one route configuration object.
         * @param route Output route object.
         * @param json Source JSON node.
         * @return True when route data is valid.
         */
        static bool ReadJsonToRoute(AppConfiguration::RouteConfiguration& route, const Json::Value& json) noexcept {
            if (json.isNull()) {
                return false;
            }

            boost::asio::ip::address ngw;
            if (!IPOrHostIsValid(JsonAuxiliary::AsValue<ppp::string>(json["ngw"]), addressof(ngw))) {
                return false;
            }

            if (!ngw.is_v4()) {
                return false;
            }

            ppp::string path = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(json["path"])));
            if (path.empty()) {
                return false;
            }

            ppp::string vbgp = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(json["vbgp"])));
            if (!ppp::net::http::HttpClient::VerifyUri(vbgp, NULLPTR, NULLPTR, NULLPTR, NULLPTR)) {
                if (ppp::diagnostics::ErrorCode::Success != ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);
                }
                vbgp = ppp::string();
            }

            route.ngw = htonl(ngw.to_v4().to_uint());
            route.path = path;
            route.vbgp = vbgp;
#if defined(_LINUX)
            route.nic = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(json["nic"])));
#endif
            return true;
        }

        /**
         * @brief Loads route configuration list from JSON.
         * @param s Output route vector.
         * @param json Source JSON node.
         */
        static void LoadAllRoutes(ppp::vector<AppConfiguration::RouteConfiguration>& s, const Json::Value& json) noexcept {
            using RouteConfiguration = AppConfiguration::RouteConfiguration;

            s.clear();

            if (json.isArray()) {
                Json::ArrayIndex json_size = json.size();
                RouteConfiguration route;
                for (Json::ArrayIndex json_index = 0; json_index < json_size; json_index++) {
                    Json::Value v = json[json_index];
                    if (ReadJsonToRoute(route, v)) {
                        s.emplace_back(route);
                    }
                }
            }
            elif(json.isObject()) {
                RouteConfiguration route;
                if (ReadJsonToRoute(route, json)) {
                    s.emplace_back(route);
                }
            }
        }

        /**
         * @brief Loads a canonical routing string source list from JSON.
         * @param values Output source list.
         * @param json Source JSON string or string array.
         *
         * Invalid shapes and non-string array elements are ignored.  Empty
         * entries are removed after trimming so file and inline-text sources
         * have identical normalization semantics.
         */
        static void LoadClientRoutingStringList(ppp::vector<ppp::string>& values, const Json::Value& json) noexcept {
            values.clear();
            if (json.isString()) {
                values.emplace_back(JsonAuxiliary::AsString(json));
            }
            elif(json.isArray()) {
                for (Json::ArrayIndex i = 0; i < json.size(); i++) {
                    if (json[i].isString()) {
                        values.emplace_back(JsonAuxiliary::AsString(json[i]));
                    }
                }
            }
            NormalizeClientRoutingStringList(values);
        }

        /**
         * @brief Normalizes a DNS protocol string and applies DoQ→DoT fallback.
         * @param raw_protocol Raw protocol string from JSON.
         * @return Normalized lowercase protocol string.
         *
         * DoQ is downgraded to "dot" because the resolver does not yet
         * implement QUIC transport, so advertising DoQ would be an
         * empty promise.
         */
        static ppp::string NormalizeDnsProtocol(const ppp::string& raw_protocol) noexcept {
            ppp::string proto = ToLower(LTrim(RTrim(raw_protocol)));
            if (proto == "doq") {
                return "dot";
            }
            return proto;
        }

        static bool IsDnsServerAddressLiteralSpec(const ppp::string& value) noexcept {
            ppp::string host;
            int port = 0;
            if (!Ipep::ParseEndPoint(value, host, port)) {
                host = value;
            }

            host = ATrim(host);
            if (host.empty()) {
                return false;
            }

            boost::system::error_code ec;
            boost::asio::ip::address ip = ppp::StringToAddress(host.data(), ec);
            return !ec && !ip.is_unspecified();
        }

        /**
         * @brief Parses a single DNS server entry from a JSON object.
         * @param entry Output DnsServerEntry.
         * @param json Source JSON node (must be an object).
         * @return True when at least one meaningful field is populated.
         */
        static bool ParseDnsServerEntry(AppConfiguration::DnsServerEntry& entry, const Json::Value& json) noexcept {
            if (!json.isObject()) {
                return false;
            }

            entry.protocol  = detail::NormalizeDnsProtocol(JsonAuxiliary::AsValue<ppp::string>(json["protocol"]));
            if (!detail::IsSupportedDnsProtocol(entry.protocol)) {
                return false;
            }
            entry.url       = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(json["url"])));
            entry.hostname  = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(json["hostname"])));
            entry.address   = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(json["address"])));
            entry.bootstrap.clear();

            // Parse bootstrap list: accept array, object values, or single string.
            const Json::Value& bootstrap_json = json["bootstrap"];
            if (bootstrap_json.isArray()) {
                for (Json::ArrayIndex i = 0; i < bootstrap_json.size(); i++) {
                    ppp::string s = LTrim(RTrim(JsonAuxiliary::AsString(bootstrap_json[i])));
                    if (!s.empty()) {
                        entry.bootstrap.emplace_back(std::move(s));
                    }
                }
            }
            elif(bootstrap_json.isString()) {
                ppp::string s = LTrim(RTrim(JsonAuxiliary::AsString(bootstrap_json)));
                if (!s.empty()) {
                    entry.bootstrap.emplace_back(std::move(s));
                }
            }

            // Accept if any identifying field is present.
            return !entry.protocol.empty() || !entry.url.empty() ||
                   !entry.hostname.empty() || !entry.address.empty();
        }

        /**
         * @brief Parses a DNS server specification that may be a string, object, or array.
         *
         * - **string**: Stored in the shorthand field. IP literals are also converted
         *   into a structured entry; provider names remain on the provider fallback path.
         * - **object**: Parsed as a structured DnsServerEntry into the entries list.
         * - **array**: Each element is parsed individually; strings go to legacy shorthand
         *   (first element only) and entries list, objects go to entries list only.
         *
         * @param shorthand Output legacy string shorthand (single string or first of array).
         * @param entries   Output structured entry list.
         * @param json      Source JSON node.
         * @return True when at least one entry or shorthand was produced.
         */
        static bool ParseDnsServerSpec(ppp::string& shorthand, ppp::vector<AppConfiguration::DnsServerEntry>& entries, const Json::Value& json) noexcept {
            using DnsServerEntry = AppConfiguration::DnsServerEntry;

            shorthand.clear();
            entries.clear();

            if (json.isNull()) {
                return false;
            }

            // --- string shorthand: "cloudflare", "1.1.1.1:53", etc. ---
            // Provider strings stay on the provider fallback path. Raw IP strings
            // still populate entries so legacy dns.servers IP shorthand works.
            if (json.isString()) {
                shorthand = LTrim(RTrim(JsonAuxiliary::AsString(json)));
                if (!shorthand.empty() && IsDnsServerAddressLiteralSpec(shorthand)) {
                    DnsServerEntry entry;
                    entry.address = shorthand;
                    entries.emplace_back(std::move(entry));
                }
                return !shorthand.empty();
            }

            // --- object: single structured entry ---
            if (json.isObject()) {
                DnsServerEntry entry;
                if (ParseDnsServerEntry(entry, json)) {
                    entries.emplace_back(std::move(entry));
                    return true;
                }
                return false;
            }

            // --- array: mixed string/object entries ---
            if (json.isArray()) {
                bool first_string = true;
                for (Json::ArrayIndex i = 0; i < json.size(); i++) {
                    const Json::Value& element = json[i];

                    if (element.isString()) {
                        ppp::string s = LTrim(RTrim(JsonAuxiliary::AsString(element)));
                        if (!s.empty()) {
                            // First string element also populates the legacy shorthand.
                            if (first_string) {
                                shorthand = s;
                                first_string = false;
                            }
                            DnsServerEntry entry;
                            entry.address = s;
                            entries.emplace_back(std::move(entry));
                        }
                    }
                    elif(element.isObject()) {
                        DnsServerEntry entry;
                        if (ParseDnsServerEntry(entry, element)) {
                            entries.emplace_back(std::move(entry));
                        }
                    }
                }
                return !entries.empty();
            }

            return false;
        }

        /**
         * @brief Serializes a DnsServerEntry to a JSON object.
         * @param entry Source entry.
         * @return JSON object with populated fields only.
         */
        static Json::Value DnsServerEntryToJson(const AppConfiguration::DnsServerEntry& entry) noexcept {
            Json::Value jo;
            if (!entry.protocol.empty()) {
                jo["protocol"] = entry.protocol;
            }
            if (!entry.url.empty()) {
                jo["url"] = entry.url;
            }
            if (!entry.hostname.empty()) {
                jo["hostname"] = entry.hostname;
            }
            if (!entry.address.empty()) {
                jo["address"] = entry.address;
            }
            if (!entry.bootstrap.empty()) {
                Json::Value arr(Json::arrayValue);
                for (const ppp::string& b : entry.bootstrap) {
                    arr.append(b);
                }
                jo["bootstrap"] = arr;
            }
            return jo;
        }

        /**
         * @brief Loads configuration from a JSON object.
         * @param json Source JSON object.
         * @return True when loading and normalization succeed.
         */
        bool AppConfiguration::Load(Json::Value& json) noexcept {
            Clear();
            if (!json.isObject()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigTypeMismatch);
            }

            AppConfiguration& config = *this;
            config.concurrent = JsonAuxiliary::AsValue<int>(json["concurrent"]);
            config.cdn[0] = JsonAuxiliary::AsValue<int>(json["cdn"][0]);
            config.cdn[1] = JsonAuxiliary::AsValue<int>(json["cdn"][1]);

            config.ip.public_ = JsonAuxiliary::AsValue<ppp::string>(json["ip"]["public"]);
            config.ip.interface_ = JsonAuxiliary::AsValue<ppp::string>(json["ip"]["interface"]);

            config.vmem.size = JsonAuxiliary::AsValue<int64_t>(json["vmem"]["size"]);
            config.vmem.path = JsonAuxiliary::AsValue<ppp::string>(json["vmem"]["path"]);

            config.udp.inactive.timeout = JsonAuxiliary::AsValue<int>(json["udp"]["inactive"]["timeout"]);
            AssignIfPresent(config.udp.dns.timeout, json["udp"]["dns"]["timeout"]);
            AssignIfPresent(config.udp.dns.ttl, json["udp"]["dns"]["ttl"]);
            AssignBoolIfPresent(config.udp.dns.turbo, json["udp"]["dns"]["turbo"]);
            if (!json["udp"]["dns"]["cache"].isNull()) {
                config.udp.dns.cache = JsonAuxiliary::AsInt64(json["udp"]["dns"]["cache"], 1) != 0;
            }
            AssignIfPresent(config.udp.dns.redirect, json["udp"]["dns"]["redirect"]);
            config.udp.listen.port = JsonAuxiliary::AsValue<int>(json["udp"]["listen"]["port"]);
            config.udp.cwnd = std::max<int>(0, JsonAuxiliary::AsValue<int>(json["udp"]["cwnd"]));
            config.udp.rwnd = std::max<int>(0, JsonAuxiliary::AsValue<int>(json["udp"]["rwnd"]));
            AssignBoolIfPresent(config.udp.static_.dns, json["udp"]["static"]["dns"]);
            AssignBoolIfPresent(config.udp.static_.quic, json["udp"]["static"]["quic"]);
            AssignBoolIfPresent(config.udp.static_.icmp, json["udp"]["static"]["icmp"]);
            config.udp.static_.aggligator = JsonAuxiliary::AsValue<int>(json["udp"]["static"]["aggligator"]);
            config.udp.static_.keep_alived[0] = JsonAuxiliary::AsValue<int>(json["udp"]["static"]["keep-alived"][0]);
            config.udp.static_.keep_alived[1] = JsonAuxiliary::AsValue<int>(json["udp"]["static"]["keep-alived"][1]);
            if (!ReadJsonAllAddressStringToSet(json["udp"]["static"]["servers"], config.udp.static_.servers)) {
                ReadJsonAllAddressStringToSet(json["udp"]["static"]["server"], config.udp.static_.servers);
            }

            config.tcp.inactive.timeout = JsonAuxiliary::AsValue<int>(json["tcp"]["inactive"]["timeout"]);
            config.tcp.connect.timeout = JsonAuxiliary::AsValue<int>(json["tcp"]["connect"]["timeout"]);
            config.tcp.connect.nexcept = (int)JsonAuxiliary::AsInt64(json["tcp"]["connect"]["nexcept"], PPP_TCP_CONNECT_NEXCEPT);

            config.tcp.listen.port = JsonAuxiliary::AsValue<int>(json["tcp"]["listen"]["port"]);
            config.tcp.turbo = JsonAuxiliary::AsValue<bool>(json["tcp"]["turbo"]);
            config.tcp.backlog = JsonAuxiliary::AsValue<int>(json["tcp"]["backlog"]);
            config.tcp.fast_open = JsonAuxiliary::AsValue<bool>(json["tcp"]["fast-open"]);
            config.tcp.cwnd = std::max<int>(0, JsonAuxiliary::AsValue<int>(json["tcp"]["cwnd"]));
            config.tcp.rwnd = std::max<int>(0, JsonAuxiliary::AsValue<int>(json["tcp"]["rwnd"]));

            config.mux.inactive.timeout = JsonAuxiliary::AsValue<int>(json["mux"]["inactive"]["timeout"]);
            config.mux.connect.timeout = JsonAuxiliary::AsValue<int>(json["mux"]["connect"]["timeout"]);
            config.mux.congestions = (int)JsonAuxiliary::AsInt64(json["mux"]["congestions"], -1);
            config.mux.mode = JsonAuxiliary::AsValue<ppp::string>(json["mux"]["mode"]);
            config.mux.turbo = JsonAuxiliary::AsValue<bool>(json["mux"]["turbo"]);
            config.mux.flow.reorder.bytes = JsonAuxiliary::AsValue<int>(json["mux"]["flow"]["reorder"]["bytes"]);
            config.mux.flow.reorder.timeout = JsonAuxiliary::AsValue<int>(json["mux"]["flow"]["reorder"]["timeout"]);
            config.mux.flow.session_reorder.bytes = JsonAuxiliary::AsValue<int>(json["mux"]["flow"]["session_reorder"]["bytes"]);
            config.mux.flow.max_open = JsonAuxiliary::AsValue<int>(json["mux"]["flow"]["max_open"]);
            config.mux.flow.unknown_cid.max = JsonAuxiliary::AsValue<int>(json["mux"]["flow"]["unknown_cid"]["max"]);
            config.mux.tx.queue.max = JsonAuxiliary::AsValue<int>(json["mux"]["tx"]["queue"]["max"]);
            config.mux.tx.queue.stall = JsonAuxiliary::AsValue<int>(json["mux"]["tx"]["queue"]["stall"]);
            config.mux.tx.ctrl.budget_frames = JsonAuxiliary::AsValue<int>(json["mux"]["tx"]["ctrl"]["budget_frames"]);
            AssignBoolIfPresent(config.mux.reliability.enabled, json["mux"]["reliability"]["enabled"]);
            config.mux.reliability.rtx.bytes = JsonAuxiliary::AsValue<int>(json["mux"]["reliability"]["rtx"]["bytes"]);
            config.mux.reliability.rtx.max_attempts = JsonAuxiliary::AsValue<int>(json["mux"]["reliability"]["rtx"]["max_attempts"]);
            config.mux.reliability.ack.delay = JsonAuxiliary::AsValue<int>(json["mux"]["reliability"]["ack"]["delay"]);
            config.mux.reliability.gap.timeout = JsonAuxiliary::AsValue<int>(json["mux"]["reliability"]["gap"]["timeout"]);
            AssignBoolIfPresent(config.mux.fec.enabled, json["mux"]["fec"]["enabled"]);
            config.mux.fec.group = JsonAuxiliary::AsValue<int>(json["mux"]["fec"]["group"]);
            config.mux.fec.flush = JsonAuxiliary::AsValue<int>(json["mux"]["fec"]["flush"]);
            config.mux.debug.key = JsonAuxiliary::AsValue<ppp::string>(json["mux"]["debug"]["key"]);
            config.mux.keep_alived[0] = JsonAuxiliary::AsValue<int>(json["mux"]["keep-alived"][0]);
            config.mux.keep_alived[1] = JsonAuxiliary::AsValue<int>(json["mux"]["keep-alived"][1]);

            config.websocket.listen.ws = JsonAuxiliary::AsValue<int>(json["websocket"]["listen"]["ws"]);
            config.websocket.listen.wss = JsonAuxiliary::AsValue<int>(json["websocket"]["listen"]["wss"]);
            config.websocket.ssl.certificate_file = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["certificate-file"]);
            config.websocket.ssl.certificate_key_file = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["certificate-key-file"]);
            config.websocket.ssl.certificate_chain_file = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["certificate-chain-file"]);
            config.websocket.ssl.certificate_key_password = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["certificate-key-password"]);
            config.websocket.ssl.ciphersuites = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["ciphersuites"]);
            if (!AssignBoolIfPresent(config.websocket.ssl.verify_peer, json["websocket"]["ssl"]["verify-peer"])) {
                AssignBoolIfPresent(config.websocket.ssl.verify_peer, json["websocket"]["verify-peer"]);
            }
            config.websocket.host = JsonAuxiliary::AsValue<ppp::string>(json["websocket"]["host"]);
            config.websocket.path = JsonAuxiliary::AsValue<ppp::string>(json["websocket"]["path"]);
            config.websocket.http.error = JsonAuxiliary::AsValue<ppp::string>(json["websocket"]["http"]["error"]);
            ReadJsonAllTokensToMap(json["websocket"]["http"]["request"], config.websocket.http.request);
            ReadJsonAllTokensToMap(json["websocket"]["http"]["response"], config.websocket.http.response);

            config.key.kf = JsonAuxiliary::AsValue<int>(json["key"]["kf"]);
            config.key.kl = JsonAuxiliary::AsValue<int>(json["key"]["kl"]);
            config.key.kh = JsonAuxiliary::AsValue<int>(json["key"]["kh"]);
            config.key.kx = JsonAuxiliary::AsValue<int>(json["key"]["kx"]);
            config.key.sb = JsonAuxiliary::AsValue<int>(json["key"]["sb"]);

            config.key.protocol = JsonAuxiliary::AsValue<ppp::string>(json["key"]["protocol"]);
            config.key.protocol_key = JsonAuxiliary::AsValue<ppp::string>(json["key"]["protocol-key"]);
            config.key.transport = JsonAuxiliary::AsValue<ppp::string>(json["key"]["transport"]);
            config.key.transport_key = JsonAuxiliary::AsValue<ppp::string>(json["key"]["transport-key"]);
            AssignBoolIfPresent(config.key.masked, json["key"]["masked"]);
            AssignBoolIfPresent(config.key.plaintext, json["key"]["plaintext"]);
            AssignBoolIfPresent(config.key.delta_encode, json["key"]["delta-encode"]);
            AssignBoolIfPresent(config.key.shuffle_data, json["key"]["shuffle-data"]);
            AssignBoolIfPresent(config.key.simd_auto, json["key"]["simd-auto"]);
            ppp::cryptography::EVP::SetSimdAuto(config.key.simd_auto);

            const Json::Value& transport_auth_json = json["transport-auth"];
            if (transport_auth_json.isObject()) {
                AssignIfPresent(config.transport_auth.handshake_timeout_ms,
                    transport_auth_json["handshake-timeout-ms"]);
                const Json::Value& keys_json = transport_auth_json["keys"];
                if (!keys_json.isNull()) {
                    if (!keys_json.isArray()) {
                        return false;
                    }
                    config.transport_auth.keys.clear();
                    for (Json::ArrayIndex i = 0; i < keys_json.size(); ++i) {
                        const Json::Value& key_json = keys_json[i];
                        if (!key_json.isObject()) {
                            return false;
                        }
                        TransportAuthKeyMetadata metadata;
                        metadata.id = JsonAuxiliary::AsValue<std::string>(key_json["id"]);
                        metadata.secret_file = JsonAuxiliary::AsValue<std::string>(key_json["secret-file"]);
                        const std::string state = JsonAuxiliary::AsValue<std::string>(key_json["state"]);
                        if (!TryParseTransportAuthKeyState(state, metadata.state)) {
                            return false;
                        }
                        config.transport_auth.keys.emplace_back(std::move(metadata));
                    }
                }
            }

            config.server.log = JsonAuxiliary::AsValue<ppp::string>(json["server"]["log"]);
            config.server.node = JsonAuxiliary::AsValue<int>(json["server"]["node"]);
            AssignBoolIfPresent(config.server.subnet, json["server"]["subnet"]);
            AssignBoolIfPresent(config.server.mapping, json["server"]["mapping"]);
            config.server.backend = JsonAuxiliary::AsValue<ppp::string>(json["server"]["backend"]);
            config.server.backend_key = JsonAuxiliary::AsValue<ppp::string>(json["server"]["backend-key"]);
            config.server.ipv6.mode = ParseIPv6Mode(JsonAuxiliary::AsValue<ppp::string>(json["server"]["ipv6"]["mode"]));
            AssignIfPresent(config.server.ipv6.cidr, json["server"]["ipv6"]["cidr"]);
            AssignIfPresent(config.server.ipv6.gateway, json["server"]["ipv6"]["gateway"]);
            AssignIfPresent(config.server.ipv6.dns1, json["server"]["ipv6"]["dns1"]);
            AssignIfPresent(config.server.ipv6.dns2, json["server"]["ipv6"]["dns2"]);
            AssignIfPresent(config.server.ipv6.lease_time, json["server"]["ipv6"]["lease-time"]);
            if (Json::Value& static_addresses = json["server"]["ipv6"]["static-addresses"]; static_addresses.isObject()) {
                config.server.ipv6.static_addresses.clear();
                for (Json::ValueConstIterator it = static_addresses.begin(); it != static_addresses.end(); ++it) {
                    config.server.ipv6.static_addresses[it.name()] = JsonAuxiliary::AsValue<ppp::string>(*it);
                }
            }

            // Parse server.ipv4-pool: presence alone enables IPv4 assignment.
            {
                const Json::Value& ipv4_pool_json = json["server"]["ipv4-pool"];
                if (ipv4_pool_json.isObject()) {
                    config.server.ipv4_pool.configured = true;
                    config.server.ipv4_pool.network = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(ipv4_pool_json["network"])));
                    config.server.ipv4_pool.mask    = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(ipv4_pool_json["mask"])));
                }
            }

            {
                const Json::Value& peer_routing_json = json["server"]["peer-routing"];
                if (peer_routing_json.isObject()) {
                    AssignBoolIfPresent(config.server.peer_routing.enabled, peer_routing_json["enabled"]);
                    AssignBoolIfPresent(config.server.peer_routing.distribute, peer_routing_json["distribute"]);
                    LoadAllPeerPrefixRoutes(
                        config.server.peer_routing.allowed_routes,
                        peer_routing_json["allowed-routes"]);
                }
            }

            AssignBoolIfPresent(config.server.session_resume.enabled,
                json["server"]["session_resume"]["enabled"]);
            AssignIfPresent(config.server.session_resume.grace_ms,
                json["server"]["session_resume"]["grace_ms"]);
            AssignBoolIfPresent(config.server.transport_auth.enabled,
                json["server"]["transport-auth"]["enabled"]);

            LoadAllMappings(config, json["client"]["mappings"]);
            LoadAllRoutes(config.client.routes, json["client"]["routes"]);
            LoadAllPeerPrefixRoutes(config.client.peer_routes, json["client"]["peer-routes"]);
            LoadAllPeerPrefixRoutes(config.client.peer_route_announce, json["client"]["peer-route-announce"]);
            AssignBoolIfPresent(config.client.peer_gateway_forward, json["client"]["peer-gateway-forward"]);

            config.client.reconnections.timeout = JsonAuxiliary::AsValue<int>(json["client"]["reconnections"]["timeout"]);
            AssignIfPresent(config.client.reconnections.max_delay,
                json["client"]["reconnections"]["max_delay"]);
            AssignIfPresent(config.client.reconnections.jitter_percent,
                json["client"]["reconnections"]["jitter_percent"]);
            AssignBoolIfPresent(config.client.session_resume.enabled,
                json["client"]["session_resume"]["enabled"]);
            AssignBoolIfPresent(config.client.transport_auth.enabled,
                json["client"]["transport-auth"]["enabled"]);
            config.client.guid = JsonAuxiliary::AsValue<ppp::string>(json["client"]["guid"]);
            config.client.server = JsonAuxiliary::AsValue<ppp::string>(json["client"]["server"]);
            config.client.server_proxy = JsonAuxiliary::AsValue<ppp::string>(json["client"]["server-proxy"]);
            config.client.bandwidth = JsonAuxiliary::AsValue<int64_t>(json["client"]["bandwidth"]);
            config.client.http_proxy.port = JsonAuxiliary::AsValue<int>(json["client"]["http-proxy"]["port"]);
            config.client.http_proxy.bind = JsonAuxiliary::AsValue<ppp::string>(json["client"]["http-proxy"]["bind"]);
            config.client.socks_proxy.port = JsonAuxiliary::AsValue<int>(json["client"]["socks-proxy"]["port"]);
            config.client.socks_proxy.bind = JsonAuxiliary::AsValue<ppp::string>(json["client"]["socks-proxy"]["bind"]);
            config.client.socks_proxy.username = JsonAuxiliary::AsValue<ppp::string>(json["client"]["socks-proxy"]["username"]);
            config.client.socks_proxy.password = JsonAuxiliary::AsValue<ppp::string>(json["client"]["socks-proxy"]["password"]);
            AssignBoolIfPresent(config.client.proxy_only, json["client"]["proxy-only"]);

            // Canonical client.routing is authoritative when present.  The
            // nested ip/dns locations are preferred over direct aliases so a
            // future schema can add unrelated routing keys without ambiguity.
            // client.proxy-only remains an independent top-level runtime flag.
            {
                const Json::Value& routing_json = json["client"]["routing"];
                if (routing_json.isObject()) {
                    config.client.routing.configured = true;

                    const Json::Value& ip_json = routing_json["ip"];
                    const Json::Value& bypass_json =
                        ip_json.isObject() && !ip_json["bypass"].isNull()
                            ? ip_json["bypass"] : routing_json["bypass"];
                    const Json::Value& routes_json =
                        ip_json.isObject() && !ip_json["routes"].isNull()
                            ? ip_json["routes"] : routing_json["routes"];
                    const Json::Value& peer_routes_json =
                        ip_json.isObject() && !ip_json["peer-routes"].isNull()
                            ? ip_json["peer-routes"] : routing_json["peer-routes"];
                    const Json::Value& dns_json = routing_json["dns"];
                    const Json::Value& dns_rules_json =
                        dns_json.isObject() && !dns_json["rules"].isNull()
                            ? dns_json["rules"] : routing_json["dns-rules"];

                    LoadClientRoutingStringList(config.client.routing.bypass, bypass_json);
                    LoadAllRoutes(config.client.routing.routes, routes_json);
                    LoadAllPeerPrefixRoutes(config.client.routing.peer_routes, peer_routes_json);
                    LoadClientRoutingStringList(config.client.routing.dns_rules, dns_rules_json);

                    // Keep existing consumers on the same effective policy
                    // until they migrate from the legacy fields.
                    config.client.routes = config.client.routing.routes;
                    config.client.peer_routes = config.client.routing.peer_routes;
                }
            }
#if defined(_WIN32)
            AssignBoolIfPresent(config.client.paper_airplane.tcp, json["client"]["paper-airplane"]["tcp"]);
#endif

            AssignIfPresent(config.virr.update_interval, json["virr"]["update-interval"]);
            AssignIfPresent(config.virr.retry_interval, json["virr"]["retry-interval"]);
            AssignIfPresent(config.vbgp.update_interval, json["vbgp"]["update-interval"]);
            AssignIfPresent(config.routing.rules, json["routing"]["rules"]);
            AssignBoolIfPresent(config.routing.tcp_domain_sniff, json["routing"]["tcp-domain-sniff"]);

            AssignBoolIfPresent(config.telemetry.enabled, json["telemetry"]["enabled"]);
            AssignIfPresent(config.telemetry.level, json["telemetry"]["level"]);
            AssignBoolIfPresent(config.telemetry.count, json["telemetry"]["count"]);
            AssignBoolIfPresent(config.telemetry.span, json["telemetry"]["span"]);
            AssignIfPresent(config.telemetry.endpoint, json["telemetry"]["endpoint"]);
            AssignIfPresent(config.telemetry.log_file, json["telemetry"]["log-file"]);
            AssignBoolIfPresent(config.telemetry.console_log, json["telemetry"]["console-log"]);
            AssignBoolIfPresent(config.telemetry.console_metric, json["telemetry"]["console-metric"]);
            AssignBoolIfPresent(config.telemetry.console_span, json["telemetry"]["console-span"]);

            {
                const Json::Value& p2p_json = json["p2p"];
                if (p2p_json.isObject()) {
                    AssignBoolIfPresent(config.p2p.enabled, p2p_json["enabled"]);
                    AssignIfPresent(config.p2p.mode, p2p_json["mode"]);
                    AssignIfPresent(config.p2p.punch_timeout, p2p_json["punch-timeout"]);
                    AssignIfPresent(config.p2p.keep_alived, p2p_json["keep-alived"]);

                    const Json::Value& stun_json = p2p_json["stun"]["servers"];
                    if (stun_json.isArray()) {
                        config.p2p.stun_servers.clear();
                        for (Json::ArrayIndex i = 0; i < stun_json.size(); i++) {
                            ppp::string s = LTrim(RTrim(JsonAuxiliary::AsString(stun_json[i])));
                            if (!s.empty()) {
                                config.p2p.stun_servers.emplace_back(std::move(s));
                            }
                        }
                    }
                    AssignIfPresent(config.p2p.max_probes, p2p_json["max-probes"]);
                    AssignIfPresent(config.p2p.probe_timeout_ms, p2p_json["probe-timeout-ms"]);
                    AssignIfPresent(config.p2p.heartbeat_interval_ms, p2p_json["heartbeat-interval-ms"]);
                    AssignIfPresent(config.p2p.heartbeat_miss_max, p2p_json["heartbeat-miss-max"]);
                    AssignIfPresent(config.p2p.suspect_timeout_ms, p2p_json["suspect-timeout-ms"]);
                    AssignIfPresent(config.p2p.migration_grace_ms, p2p_json["migration-grace-ms"]);
                    AssignIfPresent(config.p2p.buffer_pool_count, p2p_json["buffer-pool-count"]);
                }
            }

            // DNS resolver extension configuration.
            // domestic/foreign accept three forms:
            //   string  → legacy shorthand stored in domestic/foreign + single entry
            //   object  → structured DnsServerEntry
            //   array   → mixed string/object entries, first string → legacy shorthand
            {
                ppp::string domestic_shorthand;
                ppp::vector<DnsServerEntry> domestic_entries;
                if (ParseDnsServerSpec(domestic_shorthand, domestic_entries, json["dns"]["servers"]["domestic"])) {
                    config.dns.servers.domestic = domestic_shorthand;
                    config.dns.servers.domestic_entries = std::move(domestic_entries);
                }

                ppp::string foreign_shorthand;
                ppp::vector<DnsServerEntry> foreign_entries;
                if (ParseDnsServerSpec(foreign_shorthand, foreign_entries, json["dns"]["servers"]["foreign"])) {
                    config.dns.servers.foreign = foreign_shorthand;
                    config.dns.servers.foreign_entries = std::move(foreign_entries);
                }
            }
            AssignBoolIfPresent(config.dns.intercept_unmatched, json["dns"]["intercept-unmatched"]);
            AssignBoolIfPresent(config.dns.ecs.enabled, json["dns"]["ecs"]["enabled"]);
            config.dns.ecs.override_ip = JsonAuxiliary::AsValue<ppp::string>(json["dns"]["ecs"]["override-ip"]);
            AssignBoolIfPresent(config.dns.tls.verify_peer, json["dns"]["tls"]["verify-peer"]);

            // STUN candidates: array of "ip:port" or "hostname:port" strings.
            {
                const Json::Value& stun_json = json["dns"]["stun"]["candidates"];
                if (stun_json.isArray()) {
                    config.dns.stun.candidates.clear();
                    for (Json::ArrayIndex i = 0; i < stun_json.size(); i++) {
                        ppp::string s = LTrim(RTrim(JsonAuxiliary::AsString(stun_json[i])));
                        if (!s.empty()) {
                            config.dns.stun.candidates.emplace_back(std::move(s));
                        }
                    }
                }
            }

            AssignBoolIfPresent(config.dns.fake_ip.enabled, json["dns"]["fake-ip"]["enabled"]);
            {
                ppp::string range = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(json["dns"]["fake-ip"]["range"])));
                if (!range.empty()) {
                    config.dns.fake_ip.range = std::move(range);
                }
            }

            // Geo-rules configuration (Phase G).
            // geoip/geosite accept string or string[].
            // append-bypass/append-dns-rules accept string[].
            {
                const Json::Value& gr = json["geo-rules"];
                if (gr.isObject()) {
                    AssignBoolIfPresent(config.geo_rules.enabled, gr["enabled"]);
                    auto assign_string_if_nonempty = [](ppp::string& target, const Json::Value& v) noexcept {
                        ppp::string s = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(v)));
                        if (!s.empty()) { target = std::move(s); }
                    };
                    assign_string_if_nonempty(config.geo_rules.country, gr["country"]);
                    assign_string_if_nonempty(config.geo_rules.geoip_dat, gr["geoip-dat"]);
                    assign_string_if_nonempty(config.geo_rules.geosite_dat, gr["geosite-dat"]);
                    assign_string_if_nonempty(config.geo_rules.geoip_download_url, gr["geoip-download-url"]);
                    assign_string_if_nonempty(config.geo_rules.geosite_download_url, gr["geosite-download-url"]);
                    assign_string_if_nonempty(config.geo_rules.geoip_dat, gr["geoip_dat"]);
                    assign_string_if_nonempty(config.geo_rules.geosite_dat, gr["geosite_dat"]);
                    assign_string_if_nonempty(config.geo_rules.geoip_download_url, gr["geoip_download_url"]);
                    assign_string_if_nonempty(config.geo_rules.geosite_download_url, gr["geosite_download_url"]);
                    assign_string_if_nonempty(config.geo_rules.dns_provider_domestic, gr["dns-provider-domestic"]);
                    assign_string_if_nonempty(config.geo_rules.dns_provider_foreign, gr["dns-provider-foreign"]);
                    assign_string_if_nonempty(config.geo_rules.output_bypass, gr["output-bypass"]);
                    assign_string_if_nonempty(config.geo_rules.output_dns_rules, gr["output-dns-rules"]);
                    auto load_string_or_array = [](const Json::Value& v, ppp::vector<ppp::string>& out) noexcept {
                        out.clear();
                        if (v.isString()) {
                            ppp::string s = LTrim(RTrim(JsonAuxiliary::AsString(v)));
                            if (!s.empty()) { out.emplace_back(std::move(s)); }
                        }
                        elif(v.isArray()) {
                            for (Json::ArrayIndex i = 0; i < v.size(); i++) {
                                ppp::string s = LTrim(RTrim(JsonAuxiliary::AsString(v[i])));
                                if (!s.empty()) { out.emplace_back(std::move(s)); }
                            }
                        }
                    };
                    load_string_or_array(gr["geoip"], config.geo_rules.geoip);
                    load_string_or_array(gr["geosite"], config.geo_rules.geosite);
                    auto load_string_array = [](const Json::Value& v, ppp::vector<ppp::string>& out) noexcept {
                        if (v.isArray()) {
                            out.clear();
                            for (Json::ArrayIndex i = 0; i < v.size(); i++) {
                                ppp::string s = LTrim(RTrim(JsonAuxiliary::AsString(v[i])));
                                if (!s.empty()) { out.emplace_back(std::move(s)); }
                            }
                        }
                    };
                    load_string_array(gr["append-bypass"], config.geo_rules.append_bypass);
                    load_string_array(gr["append-dns-rules"], config.geo_rules.append_dns_rules);
                }
            }

            bool loaded = Loaded();
            if (!loaded && ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigFieldInvalid);
            }
            return loaded;
        }

        /**
         * @brief Converts current configuration to a JSON object.
         * @return Serialized JSON tree.
         */
        Json::Value AppConfiguration::ToJson() noexcept {
            Json::Value root;
            AppConfiguration& config = *this;

            // Set concurrent
            root["concurrent"] = config.concurrent;

            // Set cdn array
            Json::Value cdn(Json::arrayValue);
            cdn.append(config.cdn[0]);
            cdn.append(config.cdn[1]);
            root["cdn"] = cdn;

            // Set ip structure
            Json::Value ip;
            ip["public"] = config.ip.public_;
            ip["interface"] = config.ip.interface_;
            root["ip"] = ip;

            // Set vmem structure
            Json::Value vmem;
            vmem["size"] = config.vmem.size;
            vmem["path"] = config.vmem.path;
            root["vmem"] = vmem;

            // Set udp structure
            Json::Value udp;
            udp["inactive"]["timeout"] = config.udp.inactive.timeout;
            udp["dns"]["timeout"] = config.udp.dns.timeout;
            udp["dns"]["ttl"] = config.udp.dns.ttl;
            udp["dns"]["turbo"] = config.udp.dns.turbo;
            udp["dns"]["cache"] = config.udp.dns.cache;
            udp["dns"]["redirect"] = config.udp.dns.redirect;
            udp["listen"]["port"] = config.udp.listen.port;
            udp["cwnd"] = config.udp.cwnd;
            udp["rwnd"] = config.udp.rwnd;

            // Set keep-alived structure
            Json::Value config_udp_static_keep_alived(Json::arrayValue);
            config_udp_static_keep_alived.append(config.udp.static_.keep_alived[0]);
            config_udp_static_keep_alived.append(config.udp.static_.keep_alived[1]);
            udp["static"]["keep-alived"] = config_udp_static_keep_alived;

            // Set servers structure
            Json::Value servers(Json::arrayValue);
            for (const ppp::string& server : config.udp.static_.servers) {
                if (!server.empty()) {
                    servers.append(server);
                }
            }

            udp["static"]["servers"] = servers;
            udp["static"]["server"] = servers;
            udp["static"]["dns"] = config.udp.static_.dns;
            udp["static"]["quic"] = config.udp.static_.quic;
            udp["static"]["icmp"] = config.udp.static_.icmp;
            udp["static"]["aggligator"] = config.udp.static_.aggligator;
            root["udp"] = udp;

            // Set tcp structure
            Json::Value tcp;
            tcp["inactive"]["timeout"] = config.tcp.inactive.timeout;
            tcp["connect"]["timeout"] = config.tcp.connect.timeout;
            tcp["connect"]["nexcept"] = config.tcp.connect.nexcept;
            tcp["listen"]["port"] = config.tcp.listen.port;
            tcp["turbo"] = config.tcp.turbo;
            tcp["backlog"] = config.tcp.backlog;
            tcp["fast-open"] = config.tcp.fast_open;
            tcp["cwnd"] = config.tcp.cwnd;
            tcp["rwnd"] = config.tcp.rwnd;
            root["tcp"] = tcp;

            // Set mux structure
            Json::Value mux;
            mux["inactive"]["timeout"] = config.mux.inactive.timeout;
            mux["connect"]["timeout"] = config.mux.connect.timeout;
            mux["congestions"] = config.mux.congestions;
            mux["mode"] = config.mux.mode;
            mux["turbo"] = config.mux.turbo;
            mux["flow"]["reorder"]["bytes"] = config.mux.flow.reorder.bytes;
            mux["flow"]["reorder"]["timeout"] = config.mux.flow.reorder.timeout;
            mux["flow"]["session_reorder"]["bytes"] = config.mux.flow.session_reorder.bytes;
            mux["flow"]["max_open"] = config.mux.flow.max_open;
            mux["flow"]["unknown_cid"]["max"] = config.mux.flow.unknown_cid.max;
            mux["tx"]["queue"]["max"] = config.mux.tx.queue.max;
            mux["tx"]["queue"]["stall"] = config.mux.tx.queue.stall;
            mux["tx"]["ctrl"]["budget_frames"] = config.mux.tx.ctrl.budget_frames;
            mux["reliability"]["enabled"] = config.mux.reliability.enabled;
            mux["reliability"]["rtx"]["bytes"] = config.mux.reliability.rtx.bytes;
            mux["reliability"]["rtx"]["max_attempts"] = config.mux.reliability.rtx.max_attempts;
            mux["reliability"]["ack"]["delay"] = config.mux.reliability.ack.delay;
            mux["reliability"]["gap"]["timeout"] = config.mux.reliability.gap.timeout;
            mux["fec"]["enabled"] = config.mux.fec.enabled;
            mux["fec"]["group"] = config.mux.fec.group;
            mux["fec"]["flush"] = config.mux.fec.flush;
            if (!config.mux.debug.key.empty()) {
                mux["debug"]["key"] = config.mux.debug.key;
            }

            // Set keep-alived structure
            Json::Value config_mux_keep_alived(Json::arrayValue);
            config_mux_keep_alived.append(config.mux.keep_alived[0]);
            config_mux_keep_alived.append(config.mux.keep_alived[1]);
            mux["keep-alived"] = config_mux_keep_alived;

            root["mux"] = mux;

            // Set websocket structure
            Json::Value websocket;
            websocket["listen"]["ws"] = config.websocket.listen.ws;
            websocket["listen"]["wss"] = config.websocket.listen.wss;
            websocket["ssl"]["certificate-file"] = stl::transform<ppp::string>(config.websocket.ssl.certificate_file);
            websocket["ssl"]["certificate-key-file"] = stl::transform<ppp::string>(config.websocket.ssl.certificate_key_file);
            websocket["ssl"]["certificate-chain-file"] = stl::transform<ppp::string>(config.websocket.ssl.certificate_chain_file);
            websocket["ssl"]["certificate-key-password"] = stl::transform<ppp::string>(config.websocket.ssl.certificate_key_password);
            websocket["ssl"]["ciphersuites"] = stl::transform<ppp::string>(config.websocket.ssl.ciphersuites);
            websocket["ssl"]["verify-peer"] = config.websocket.ssl.verify_peer;
            websocket["verify-peer"] = config.websocket.ssl.verify_peer;
            websocket["http"]["error"] = stl::transform<ppp::string>(config.websocket.http.error);

            // Set websocket structure
            Json::Value& request = websocket["http"]["request"];
            for (auto&& [k, v] : config.websocket.http.request) {
                request[k.data()] = stl::transform<ppp::string>(v);
            }

            // Set response structure
            Json::Value& response = websocket["http"]["response"];
            for (auto&& [k, v] : config.websocket.http.response) {
                response[k.data()] = stl::transform<ppp::string>(v);
            }

            websocket["host"] = config.websocket.host;
            websocket["path"] = config.websocket.path;
            root["websocket"] = websocket;

            // Set key structure
            Json::Value key;
            key["kf"] = config.key.kf;
            key["kl"] = config.key.kl;
            key["kh"] = config.key.kh;
            key["kx"] = config.key.kx;
            key["sb"] = config.key.sb;

            key["protocol"] = config.key.protocol;
            key["protocol-key"] = config.key.protocol_key;
            key["transport"] = config.key.transport;
            key["transport-key"] = config.key.transport_key;
            key["masked"] = config.key.masked;
            key["plaintext"] = config.key.plaintext;
            key["delta-encode"] = config.key.delta_encode;
            key["shuffle-data"] = config.key.shuffle_data;
            key["simd-auto"] = config.key.simd_auto;
            root["key"] = key;

            if (config.client.transport_auth.enabled || config.server.transport_auth.enabled ||
                config.transport_auth.handshake_timeout_ms != TransportAuthConfiguration::DefaultHandshakeTimeoutMs ||
                !config.transport_auth.keys.empty()) {
                Json::Value transport_auth;
                transport_auth["handshake-timeout-ms"] = config.transport_auth.handshake_timeout_ms;
                Json::Value keys(Json::arrayValue);
                for (const TransportAuthKeyMetadata& metadata : config.transport_auth.keys) {
                    Json::Value item;
                    item["id"] = metadata.id.c_str();
                    item["state"] = TransportAuthKeyStateToString(metadata.state);
                    if (!metadata.secret_file.empty()) {
                        item["secret-file"] = metadata.secret_file.c_str();
                    }
                    keys.append(item);
                }
                transport_auth["keys"] = keys;
                root["transport-auth"] = transport_auth;
            }

            // Set server structure
            Json::Value server;
            server["log"] = config.server.log;
            server["node"] = config.server.node;
            server["subnet"] = config.server.subnet;
            server["mapping"] = config.server.mapping;
            server["backend"] = config.server.backend; /* ws://192.168.0.24/ppp/webhook */
            server["backend-key"] = config.server.backend_key;
            server["ipv6"]["mode"] = IPv6ModeToString(config.server.ipv6.mode);
            server["ipv6"]["cidr"] = config.server.ipv6.cidr;
            server["ipv6"]["gateway"] = config.server.ipv6.gateway;
            server["ipv6"]["dns1"] = config.server.ipv6.dns1;
            server["ipv6"]["dns2"] = config.server.ipv6.dns2;
            server["ipv6"]["lease-time"] = config.server.ipv6.lease_time;
            Json::Value static_addresses;
            for (const auto& kv : config.server.ipv6.static_addresses) {
                static_addresses[kv.first] = kv.second;
            }
            server["ipv6"]["static-addresses"] = static_addresses;
            if (config.server.ipv4_pool.configured) {
                Json::Value ipv4_pool;
                ipv4_pool["network"] = config.server.ipv4_pool.network;
                ipv4_pool["mask"]    = config.server.ipv4_pool.mask;
                server["ipv4-pool"] = ipv4_pool;
            }

            if (config.server.peer_routing.enabled ||
                !config.server.peer_routing.allowed_routes.empty()) {
                Json::Value peer_routing;
                peer_routing["enabled"] = config.server.peer_routing.enabled;
                peer_routing["distribute"] = config.server.peer_routing.distribute;
                Json::Value& allowed_routes = peer_routing["allowed-routes"];
                for (const PeerPrefixRouteConfiguration& route :
                    config.server.peer_routing.allowed_routes) {
                    Json::Value jo;
                    jo["network"] = route.network;
                    jo["prefix"] = route.prefix;
                    if (!route.via.empty()) {
                        jo["via"] = route.via;
                    }
                    if (!route.guid.empty()) {
                        jo["guid"] = route.guid;
                    }
                    allowed_routes.append(jo);
                }
                server["peer-routing"] = peer_routing;
            }
            server["session_resume"]["enabled"] = config.server.session_resume.enabled;
            server["session_resume"]["grace_ms"] = config.server.session_resume.grace_ms;
            if (config.server.transport_auth.enabled) {
                server["transport-auth"]["enabled"] = true;
            }
            root["server"] = server;

            // Set client structure
            Json::Value client;
            Json::Value& mappings = client["mappings"];
            for (MappingConfiguration& mapping : config.client.mappings) {
                Json::Value jo;
                jo["protocol"] = mapping.protocol_tcp_or_udp ? "tcp" : "udp";
                jo["local-ip"] = mapping.local_ip;
                jo["local-port"] = mapping.local_port;
                jo["remote-ip"] = mapping.remote_ip;
                jo["remote-port"] = mapping.remote_port;
                mappings.append(jo);
            }

            const AppConfiguration::ClientRoutingConfiguration& canonical_routing = config.client.routing;
            const bool emit_canonical_routing =
                canonical_routing.configured ||
                !canonical_routing.bypass.empty() ||
                !canonical_routing.routes.empty() ||
                !canonical_routing.peer_routes.empty() ||
                !canonical_routing.dns_rules.empty() ||
                !config.client.routes.empty() ||
                !config.client.peer_routes.empty();
            const bool use_canonical_routing = canonical_routing.configured;
            const ppp::vector<RouteConfiguration>& effective_routes = use_canonical_routing
                ? canonical_routing.routes : config.client.routes;
            const ppp::vector<PeerPrefixRouteConfiguration>& effective_peer_routes = use_canonical_routing
                ? canonical_routing.peer_routes : config.client.peer_routes;

            if (emit_canonical_routing) {
                Json::Value routing;

                Json::Value bypass(Json::arrayValue);
                for (const ppp::string& source : canonical_routing.bypass) {
                    bypass.append(source);
                }
                routing["ip"]["bypass"] = bypass;

                Json::Value canonical_routes(Json::arrayValue);
                for (const RouteConfiguration& route : effective_routes) {
                    Json::Value jo;
                    jo["ngw"] = Ipep::ToAddressString<ppp::string>(Ipep::ToAddress(route.ngw));
#if defined(_LINUX)
                    jo["nic"] = route.nic;
#endif
                    jo["path"] = route.path;
                    jo["vbgp"] = route.vbgp;
                    canonical_routes.append(jo);
                }
                routing["ip"]["routes"] = canonical_routes;

                Json::Value canonical_peer_routes(Json::arrayValue);
                for (const PeerPrefixRouteConfiguration& route : effective_peer_routes) {
                    Json::Value jo;
                    jo["network"] = route.network;
                    jo["prefix"] = route.prefix;
                    if (!route.via.empty()) {
                        jo["via"] = route.via;
                    }
                    if (!route.guid.empty()) {
                        jo["guid"] = route.guid;
                    }
                    canonical_peer_routes.append(jo);
                }
                routing["ip"]["peer-routes"] = canonical_peer_routes;

                Json::Value dns_rules(Json::arrayValue);
                for (const ppp::string& source : canonical_routing.dns_rules) {
                    dns_rules.append(source);
                }
                routing["dns"]["rules"] = dns_rules;
                client["routing"] = routing;
            }

            // Legacy top-level client.routes and client.peer-routes are only
            // emitted when canonical routing is absent.  When canonical routing
            // is present the data already lives under routing.ip.routes /
            // routing.ip.peer-routes; writing it again to the legacy keys would
            // cause a silent canonical-override the next time the file is loaded.
            if (!use_canonical_routing) {
                Json::Value& routes = client["routes"];
                for (const RouteConfiguration& route : effective_routes) {
                    Json::Value jo;
                    jo["ngw"] = Ipep::ToAddressString<ppp::string>(Ipep::ToAddress(route.ngw));
#if defined(_LINUX)
                    jo["nic"] = route.nic;
#endif
                    jo["path"] = route.path;
                    jo["vbgp"] = route.vbgp;
                    routes.append(jo);
                }

                Json::Value& peer_routes = client["peer-routes"];
                for (const PeerPrefixRouteConfiguration& route : effective_peer_routes) {
                    Json::Value jo;
                    jo["network"] = route.network;
                    jo["prefix"] = route.prefix;
                    if (!route.via.empty()) {
                        jo["via"] = route.via;
                    }
                    peer_routes.append(jo);
                }
            }

            Json::Value& peer_route_announce = client["peer-route-announce"];
            for (const PeerPrefixRouteConfiguration& route : config.client.peer_route_announce) {
                Json::Value jo;
                jo["network"] = route.network;
                jo["prefix"] = route.prefix;
                peer_route_announce.append(jo);
            }

            client["peer-gateway-forward"] = config.client.peer_gateway_forward;

            client["http-proxy"]["bind"] = config.client.http_proxy.bind;
            client["http-proxy"]["port"] = config.client.http_proxy.port;
            client["socks-proxy"]["bind"] = config.client.socks_proxy.bind;
            client["socks-proxy"]["port"] = config.client.socks_proxy.port;
            client["socks-proxy"]["password"] = config.client.socks_proxy.password;
            client["socks-proxy"]["username"] = config.client.socks_proxy.username;
            client["proxy-only"] = config.client.proxy_only;
            client["reconnections"]["timeout"] = config.client.reconnections.timeout;
            client["reconnections"]["max_delay"] = config.client.reconnections.max_delay;
            client["reconnections"]["jitter_percent"] = config.client.reconnections.jitter_percent;
            client["session_resume"]["enabled"] = config.client.session_resume.enabled;
            if (config.client.transport_auth.enabled) {
                client["transport-auth"]["enabled"] = true;
            }
            client["guid"] = config.client.guid;
            client["server"] = config.client.server;
            client["server-proxy"] = config.client.server_proxy;
            client["bandwidth"] = config.client.bandwidth;
#if defined(_WIN32)
            client["paper-airplane"]["tcp"] = config.client.paper_airplane.tcp;
#endif

            root["client"] = client;

            Json::Value virr;
            virr["update-interval"] = config.virr.update_interval;
            virr["retry-interval"] = config.virr.retry_interval;
            root["virr"] = virr;

            Json::Value vbgp;
            vbgp["update-interval"] = config.vbgp.update_interval;
            root["vbgp"] = vbgp;

            root["routing"]["rules"] = config.routing.rules;
            root["routing"]["tcp-domain-sniff"] = config.routing.tcp_domain_sniff;

            Json::Value telemetry;
            telemetry["enabled"] = config.telemetry.enabled;
            telemetry["level"] = config.telemetry.level;
            telemetry["count"] = config.telemetry.count;
            telemetry["span"] = config.telemetry.span;
            telemetry["endpoint"] = config.telemetry.endpoint;
            telemetry["log-file"] = config.telemetry.log_file;
            telemetry["console-log"] = config.telemetry.console_log;
            telemetry["console-metric"] = config.telemetry.console_metric;
            telemetry["console-span"] = config.telemetry.console_span;
            root["telemetry"] = telemetry;

            Json::Value p2p;
            p2p["enabled"] = config.p2p.enabled;
            p2p["mode"] = config.p2p.mode;
            p2p["punch-timeout"] = config.p2p.punch_timeout;
            p2p["keep-alived"] = config.p2p.keep_alived;
            p2p["max-probes"] = config.p2p.max_probes;
            p2p["probe-timeout-ms"] = config.p2p.probe_timeout_ms;
            p2p["heartbeat-interval-ms"] = config.p2p.heartbeat_interval_ms;
            p2p["heartbeat-miss-max"] = config.p2p.heartbeat_miss_max;
            p2p["suspect-timeout-ms"] = config.p2p.suspect_timeout_ms;
            p2p["migration-grace-ms"] = config.p2p.migration_grace_ms;
            p2p["buffer-pool-count"] = config.p2p.buffer_pool_count;
            if (!config.p2p.stun_servers.empty()) {
                Json::Value stun_servers(Json::arrayValue);
                for (const ppp::string& s : config.p2p.stun_servers) {
                    stun_servers.append(s);
                }
                p2p["stun"]["servers"] = stun_servers;
            }
            root["p2p"] = p2p;

            Json::Value dns;
            // Serialize domestic/foreign: emit structured array when entries exist,
            // otherwise emit legacy string shorthand.
            if (!config.dns.servers.domestic_entries.empty()) {
                Json::Value arr(Json::arrayValue);
                for (const DnsServerEntry& entry : config.dns.servers.domestic_entries) {
                    arr.append(DnsServerEntryToJson(entry));
                }
                dns["servers"]["domestic"] = arr;
            }
            else {
                dns["servers"]["domestic"] = config.dns.servers.domestic;
            }

            if (!config.dns.servers.foreign_entries.empty()) {
                Json::Value arr(Json::arrayValue);
                for (const DnsServerEntry& entry : config.dns.servers.foreign_entries) {
                    arr.append(DnsServerEntryToJson(entry));
                }
                dns["servers"]["foreign"] = arr;
            }
            else {
                dns["servers"]["foreign"] = config.dns.servers.foreign;
            }
            dns["intercept-unmatched"] = config.dns.intercept_unmatched;
            dns["ecs"]["enabled"] = config.dns.ecs.enabled;
            dns["ecs"]["override-ip"] = config.dns.ecs.override_ip;
            dns["tls"]["verify-peer"] = config.dns.tls.verify_peer;
            dns["fake-ip"]["enabled"] = config.dns.fake_ip.enabled;
            dns["fake-ip"]["range"] = config.dns.fake_ip.range;
            if (!config.dns.stun.candidates.empty()) {
                Json::Value stun_cands(Json::arrayValue);
                for (const ppp::string& c : config.dns.stun.candidates) {
                    stun_cands.append(c);
                }
                dns["stun"]["candidates"] = stun_cands;
            }
            root["dns"] = dns;

            Json::Value geo_rules;
            geo_rules["enabled"] = config.geo_rules.enabled;
            geo_rules["country"] = config.geo_rules.country;
            geo_rules["geoip-dat"] = config.geo_rules.geoip_dat;
            geo_rules["geosite-dat"] = config.geo_rules.geosite_dat;
            if (!config.geo_rules.geoip_download_url.empty()) { geo_rules["geoip-download-url"] = config.geo_rules.geoip_download_url; }
            if (!config.geo_rules.geosite_download_url.empty()) { geo_rules["geosite-download-url"] = config.geo_rules.geosite_download_url; }
            if (!config.geo_rules.geoip.empty()) {
                Json::Value arr(Json::arrayValue);
                for (const ppp::string& s : config.geo_rules.geoip) { arr.append(s); }
                geo_rules["geoip"] = arr;
            }
            if (!config.geo_rules.geosite.empty()) {
                Json::Value arr(Json::arrayValue);
                for (const ppp::string& s : config.geo_rules.geosite) { arr.append(s); }
                geo_rules["geosite"] = arr;
            }
            if (!config.geo_rules.dns_provider_domestic.empty()) { geo_rules["dns-provider-domestic"] = config.geo_rules.dns_provider_domestic; }
            if (!config.geo_rules.dns_provider_foreign.empty()) { geo_rules["dns-provider-foreign"] = config.geo_rules.dns_provider_foreign; }
            geo_rules["output-bypass"] = config.geo_rules.output_bypass;
            geo_rules["output-dns-rules"] = config.geo_rules.output_dns_rules;
            if (!config.geo_rules.append_bypass.empty()) {
                Json::Value arr(Json::arrayValue);
                for (const ppp::string& s : config.geo_rules.append_bypass) { arr.append(s); }
                geo_rules["append-bypass"] = arr;
            }
            if (!config.geo_rules.append_dns_rules.empty()) {
                Json::Value arr(Json::arrayValue);
                for (const ppp::string& s : config.geo_rules.append_dns_rules) { arr.append(s); }
                geo_rules["append-dns-rules"] = arr;
            }
            root["geo-rules"] = geo_rules;

            return root;
        }

        /**
         * @brief Converts current configuration to JSON text.
         * @return Serialized JSON string.
         */
        ppp::string AppConfiguration::ToString() noexcept {
            Json::Value json = ToJson();
            return JsonAuxiliary::ToString(json);
        }

        /**
         * @brief Emits a startup security diagnostics report.
         *
         * Scans the loaded configuration for weak/default/short keys and
         * plaintext mode.  Each finding is logged via the telemetry subsystem
         * and written to the console.  All findings are non-fatal warnings;
         * startup never fails as a result of this call.
         */
        void AppConfiguration::EmitSecurityDiagnostics() noexcept {
            const AppConfiguration& config = *this;
            const ppp::string default_key = BOOST_BEAST_VERSION_STRING;
            int warnings = 0;

            /* Protocol key */
            if (config.key.protocol_key == default_key) {
                ++warnings;
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "security",
                    "Protocol key uses well-known default value; change for production use");
                ppp::ConsoleFormat("[security] WARN: protocol key uses well-known default — change for production\n");
            }
            else if (config.key.protocol_key.size() < 8) {
                ++warnings;
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "security",
                    "Protocol key shorter than 8 bytes; trivially brute-forced");
                ppp::ConsoleFormat("[security] WARN: protocol key shorter than 8 bytes — trivially brute-forced\n");
            }

            /* Transport key */
            if (config.key.transport_key == default_key) {
                ++warnings;
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "security",
                    "Transport key uses well-known default value; change for production use");
                ppp::ConsoleFormat("[security] WARN: transport key uses well-known default — change for production\n");
            }
            else if (config.key.transport_key.size() < 8) {
                ++warnings;
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "security",
                    "Transport key shorter than 8 bytes; trivially brute-forced");
                ppp::ConsoleFormat("[security] WARN: transport key shorter than 8 bytes — trivially brute-forced\n");
            }

            /* Plaintext mode */
            if (config.key.plaintext) {
                ++warnings;
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "security",
                    "Plaintext mode enabled (key.plaintext=true); packets transmitted without encryption");
                    ppp::ConsoleFormat("[security] WARN: plaintext mode enabled (key.plaintext=true) - not suitable for untrusted networks\n");
            }

            /* Summary */
            if (warnings > 0) {
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "security",
                    "Startup security diagnostics: %d warning(s) - startup continues (non-fatal)", warnings);
                ppp::ConsoleFormat("[security] Startup security diagnostics: %d warning(s) - startup continues (non-fatal)\n", warnings);
            }
            else {
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "security",
                    "Startup security diagnostics: all checks passed");
            }
        }

        /**
         * @brief Emits the active MUX scheduler mode and any normalization note.
         *
         * The active `mux.mode` is reported for observability (Phase 1). When
         * `Loaded()` normalized the configured value (a reserved-but-unimplemented
         * mode such as `balance`/`stripe`, or an unrecognized token), the captured
         * note is emitted as a non-fatal warning on both telemetry and console.
         */
        void AppConfiguration::EmitMuxDiagnostics() noexcept {
            const AppConfiguration& config = *this;

            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux",
                "Active scheduler mode: %s", config.mux.mode.c_str());
            ppp::ConsoleFormat("[mux] scheduler mode: %s\n", config.mux.mode.c_str());

            if (!config._mux_mode_diagnostic.empty()) {
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "%s", config._mux_mode_diagnostic.c_str());
                ppp::ConsoleFormat("[mux] WARN: %s - startup continues (non-fatal)\n", config._mux_mode_diagnostic.c_str());
            }
        }

        void AppConfiguration::ApplyProxyModeDefaults() noexcept {
            client.proxy_only = true;
            ppp::app::ApplyProxyOnlyListenerDefaults(
                client.http_proxy.bind,
                client.http_proxy.port,
                client.socks_proxy.bind,
                client.socks_proxy.port);
        }

        /**
         * @brief Returns the scheduler mode token for newly created mux sessions.
         *
         * A debug runtime override (0=compat, 1=flow, 2=balance, 3=stripe) takes
         * precedence over the configured `mux.mode` so a peer-pushed change
         * survives session rebuilds.
         */
        ppp::string AppConfiguration::GetEffectiveMuxMode() const noexcept {
            switch (_mux_mode_runtime_override.load(std::memory_order_acquire)) {
            case 0:
                return "compat";
            case 1:
                return "flow";
            case 2:
                return "balance";
            case 3:
                return "stripe";
            default:
                return this->mux.mode;
            }
        }

        /**
         * @brief Records (or clears) the debug-only runtime scheduler override.
         */
        void AppConfiguration::SetMuxModeRuntimeOverride(int mode_value) noexcept {
            int normalized = (mode_value >= 0 && mode_value <= 3) ? mode_value : -1;
            _mux_mode_runtime_override.store(normalized, std::memory_order_release);
        }

        namespace extensions {
            /**
             * @brief Verifies whether encryption algorithm fields are configured.
             * @param configuration Configuration object.
             * @return True when protocol/transport names and keys are all non-empty.
             */
            bool IsHaveCiphertext(const AppConfiguration& configuration) noexcept {
                return
                    !configuration.key.protocol.empty() &&
                    !configuration.key.protocol_key.empty() &&
                    !configuration.key.transport.empty() &&
                    !configuration.key.transport_key.empty();
            }
        }
    }
}
