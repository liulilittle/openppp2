/**
 * @file ApplicationConfig.cpp
 * @brief Command-line and configuration loading helpers for PPP application startup.
 */

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/ApplicationClientBootstrap.h>
#include <ppp/app/PppApplicationInternal.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/dns/DnsResolver.h>

namespace ppp::app {

/**
 * @brief Returns the active buffer allocator from loaded configuration.
 * @return Allocator instance, or null when configuration is unavailable.
 */
std::shared_ptr<BufferswapAllocator> PppApplication::GetBufferAllocator() noexcept {
    std::shared_ptr<AppConfiguration> configuration = GetConfiguration();
    if (NULLPTR == configuration) {
        return NULLPTR;
    }
    return configuration->GetBufferAllocator();
}

/**
 * @brief Parses command-line arguments and prepares global runtime configuration.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Zero on success, negative value when initialization should abort.
 */
int PppApplication::PreparedArgumentEnvironment(int argc, const char* argv[]) noexcept {
    Socket::SetDefaultFlashTypeOfService(ppp::ToBoolean(ppp::GetCommandArgument("--tun-flash", argc, argv).data()));

    stats_json_path_ = ppp::GetCommandArgument("--stats-json", argc, argv);
    if (!stats_json_path_.empty() && stats_json_path_ != "stdout") {
        std::FILE* output = std::fopen(stats_json_path_.c_str(), "wb");
        if (NULLPTR != output) {
            std::fclose(output);
        } else {
            stats_json_path_.clear();
        }
    }
    acceptance_boundary_.ConfigureFromEnvironment();

    if (ppp::IsInputHelpCommand(argc, argv)) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppHelpRequested);
        return -1;
    }

    ppp::string path;
    std::shared_ptr<AppConfiguration> configuration = LoadConfiguration(argc, argv, path);
    if (NULLPTR == configuration) {
        if (ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigLoadFailed);
        }
        return -1;
    }

    if (ppp::HasCommandArgument("--mux-mode", argc, argv)) {
        configuration->mux.mode = ppp::GetCommandArgument("--mux-mode", argc, argv);
        if (!configuration->Normalize()) {
            return -1;
        }
    }

    // flow-mode turbo: best-link-first first packet + prewarmed carrier links.
    // Opt-in (default off); only meaningful under --mux-mode=flow.
    if (ppp::HasCommandArgument("--mux-mode-turbo", argc, argv)) {
        configuration->mux.turbo = ppp::ToBoolean(ppp::GetCommandArgument("--mux-mode-turbo", argc, argv).data());
    }

    /**
     * @brief Debug-only remote mux-mode control (opt-in).
     *
     * `--debug-key=<secret>` sets a shared secret. When both peers carry the
     * same non-empty key, a peer may push a scheduler change to the other via
     * `--mux-mode-set=<compat|flow>`. The key is the authorization gate; the
     * set request is transient and applied once after the mux session is up.
     */
    if (ppp::HasCommandArgument("--debug-key", argc, argv)) {
        configuration->mux.debug.key = ppp::GetCommandArgument("--debug-key", argc, argv);
    }

    if (ppp::HasCommandArgument("--mux-mode-set", argc, argv)) {
        configuration->mux.debug.set_mode = ppp::GetCommandArgument("--mux-mode-set", argc, argv);
    }

    if (ppp::HasCommandArgument("--debug-key", argc, argv) || ppp::HasCommandArgument("--mux-mode-set", argc, argv)) {
        if (!configuration->Normalize()) {
            return -1;
        }
    }

    application_mode_ = ResolveApplicationModeFromArgv(argc, argv);
    client_mode_ = IsClientRuntimeMode(application_mode_);
    proxy_mode_ = ApplicationMode::Proxy == application_mode_;

    if (NormalizeClientProxyOnlyRuntime(proxy_mode_, configuration->client.proxy_only)) {
        configuration->ApplyProxyModeDefaults();
    }

    if (ppp::HasCommandArgument("--proxy-http-port", argc, argv)) {
        ppp::string port_arg = ppp::GetCommandArgument("--proxy-http-port", argc, argv);
        configuration->client.http_proxy.port = static_cast<int>(strtol(port_arg.data(), NULLPTR, 10));
    }

    if (ppp::HasCommandArgument("--proxy-socks-port", argc, argv)) {
        ppp::string port_arg = ppp::GetCommandArgument("--proxy-socks-port", argc, argv);
        configuration->client.socks_proxy.port = static_cast<int>(strtol(port_arg.data(), NULLPTR, 10));
    }

    int max_concurrent = configuration->concurrent - 1;
    if (max_concurrent > 0) {
        Executors::SetMaxSchedulers(max_concurrent);
        if (!client_mode_) {
            Executors::SetMaxThreads(configuration->GetBufferAllocator(), max_concurrent);
        }
    }

    /**
     * @brief Publish configuration before constructing the network interface so
     *        downstream helpers (e.g. GetDnsAddresses) can derive defaults
     *        from the loaded dns.servers settings.
     */
    configuration_path_ = path;
    configuration_ = configuration;

    std::shared_ptr<NetworkInterface> network_interface = GetNetworkInterface(argc, argv);
    if (NULLPTR == network_interface) {
        if (ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
        }
        return -1;
    }

    network_interface_ = network_interface;

    ppp::net::asio::vdns::ttl = configuration->udp.dns.cache ? configuration->udp.dns.ttl : 0;
    ppp::net::asio::vdns::enabled = configuration->udp.dns.turbo;
    ppp::net::asio::vdns::ClearCache();

    ppp::telemetry::SetEnabled(configuration->telemetry.enabled);
    ppp::telemetry::SetMinLevel(configuration->telemetry.level);
    ppp::telemetry::SetCountEnabled(configuration->telemetry.count);
    ppp::telemetry::SetSpanEnabled(configuration->telemetry.span);
    ppp::telemetry::SetConsoleLogEnabled(configuration->telemetry.console_log);
    ppp::telemetry::SetConsoleMetricEnabled(configuration->telemetry.console_metric);
    ppp::telemetry::SetConsoleSpanEnabled(configuration->telemetry.console_span);
    ppp::telemetry::Configure(configuration->telemetry.endpoint.c_str());
    ppp::telemetry::SetLogFile(configuration->telemetry.log_file.c_str());

    /**
     * @brief Emit startup security diagnostics report (P1-5).
     *
     * Scans the loaded configuration for weak/default/short keys and plaintext
     * mode.  All findings are non-fatal warnings — startup never fails.
     * Placed here after telemetry is configured so findings are captured in
     * both the telemetry log and the console.
     */
    configuration->EmitSecurityDiagnostics();

    /**
     * @brief Emit the active MUX scheduler mode and any mux.mode normalization
     *        warning (Phase 1 observability). Non-fatal; placed after telemetry
     *        is configured so the report reaches both telemetry and console.
     */
    configuration->EmitMuxDiagnostics();

    return 0;
}

/**
 * @brief Resolves an IPv4/IPv6 address argument or CIDR prefix into an address.
 * @param name Command-line key name.
 * @param MIN_PREFIX_ADDRESS Minimum accepted numeric prefix.
 * @param MAX_PREFIX_ADDRESS Maximum accepted numeric prefix.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Parsed address, or IPv4 any-address when invalid/missing.
 */
boost::asio::ip::address PppApplication::GetNetworkAddress(const char* name, int MIN_PREFIX_ADDRESS, int MAX_PREFIX_ADDRESS, int argc, const char* argv[]) noexcept {
    ppp::string address_string = ppp::GetCommandArgument(name, argc, argv);
    if (address_string.empty()) {
        return boost::asio::ip::address_v4::any();
    }

    address_string = ppp::LTrim<ppp::string>(address_string);
    address_string = ppp::RTrim<ppp::string>(address_string);
    if (address_string.empty()) {
        return boost::asio::ip::address_v4::any();
    }

    boost::asio::ip::address address;
    if (StringAuxiliary::WhoisIntegerValueString(address_string)) {
        int prefix = atoll(address_string.data());
        if (prefix < 1 || prefix > MAX_PREFIX_ADDRESS) {
            prefix = MAX_PREFIX_ADDRESS;
        }
        elif (MIN_PREFIX_ADDRESS > 0 && prefix < MIN_PREFIX_ADDRESS) {
            prefix = MIN_PREFIX_ADDRESS;
        }

        auto prefix_to_netmask = IPEndPoint::PrefixToNetmask(prefix);
        address = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(prefix_to_netmask, 0).address();
    } else {
        address = Ipep::ToAddress(address_string, true);
    }

    if (IPEndPoint::IsInvalid(address)) {
        return boost::asio::ip::address_v4::any();
    }

    return address;
}

/**
 * @brief Resolves an address argument and falls back to a default literal.
 * @param name Command-line key name.
 * @param MIN_PREFIX_ADDRESS Minimum accepted numeric prefix.
 * @param MAX_PREFIX_ADDRESS Maximum accepted numeric prefix.
 * @param default_address_string Fallback textual address when argument is absent/invalid.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Parsed address, or fallback default address.
 */
boost::asio::ip::address PppApplication::GetNetworkAddress(const char* name, int MIN_PREFIX_ADDRESS, int MAX_PREFIX_ADDRESS, const char* default_address_string, int argc, const char* argv[]) noexcept {
    boost::asio::ip::address address = GetNetworkAddress(name, MIN_PREFIX_ADDRESS, MAX_PREFIX_ADDRESS, argc, argv);
    if (IPEndPoint::IsInvalid(address)) {
        address = boost::asio::ip::address_v4::any();
    }

    if (IPEndPoint::IsInvalid(address)) {
        if (NULLPTR == default_address_string) {
            default_address_string = "";
        }
        return Ipep::ToAddress(default_address_string, false);
    }

    return address;
}

/**
 * @brief Parses DNS arguments and guarantees a usable default resolver set.
 * @param addresses Output container receiving DNS server addresses.
 * @param argc Argument count.
 * @param argv Argument vector.
 */
void PppApplication::GetDnsAddresses(ppp::vector<boost::asio::ip::address>& addresses, int argc, const char* argv[]) noexcept {
    GetDnsAddresses(addresses, NULLPTR, argc, argv);
}

void PppApplication::GetDnsAddresses(ppp::vector<boost::asio::ip::address>& addresses, ppp::vector<ppp::string>* labels, int argc, const char* argv[]) noexcept {
#if defined(_WIN32)
    bool at_least_two = client_mode_;
#else
    bool at_least_two = false;
#endif

    auto append_padding = [labels](std::size_t target_size) noexcept {
        if (NULLPTR != labels) {
            while (labels->size() < target_size) {
                labels->emplace_back();
            }
        }
    };

    ppp::string dns = ppp::GetCommandArgument("--dns", argc, argv);
    if (Ipep::ToDnsAddresses(dns, addresses, at_least_two) >= 1) {
        append_padding(addresses.size());
        return;
    }

    /**
     * @brief Derive the OS-pushed DNS from the configured upstream providers
     *        so the value displayed in TUN status (and used by leak/fallback)
     *        matches what ppp actually queries via DoH/DoT/UDP.
     *
     * Order: foreign first, domestic second. For each side we try in turn:
     *   1) the first structured DnsServerEntry; the entry's literal IP is
     *      pushed and, when the protocol is DoH/DoT, the optional hostname
     *      is recorded as the parallel display label;
     *   2) the first UDP entry of the built-in provider registered as that
     *      name (e.g. "cloudflare" -> 1.1.1.1, "doh.pub" -> 119.29.29.29) -
     *      the corresponding DoH/DoT hostname (when present in the same
     *      provider entry list) is recorded as the display label;
     *   3) the field treated as a literal IP (no label).
     * Falls back to the legacy 8.8.8.8 / 8.8.4.4 placeholders only when
     * nothing useful can be derived from configuration.
     */
    auto try_push_address = [&addresses, labels, &append_padding](const boost::asio::ip::address& addr, const ppp::string& label) noexcept -> bool {
        if (addr.is_unspecified()) {
            return false;
        }
        for (const boost::asio::ip::address& existing : addresses) {
            if (existing == addr) {
                return false; // dedupe
            }
        }
        addresses.emplace_back(addr);
        if (NULLPTR != labels) {
            append_padding(addresses.size() - 1u);
            labels->emplace_back(label);
        }
        return true;
    };

    auto host_to_address = [](const ppp::string& host) noexcept -> boost::asio::ip::address {
        if (host.empty()) {
            return boost::asio::ip::address();
        }
        boost::system::error_code ec;
        boost::asio::ip::address addr = ppp::StringToAddress(host.data(), ec);
        if (ec) {
            return boost::asio::ip::address();
        }
        return addr;
    };

    auto build_protocol_label = [](ppp::dns::Protocol protocol, const ppp::string& hostname) noexcept -> ppp::string {
        if (hostname.empty()) {
            return ppp::string();
        }
        const char* tag = NULLPTR;
        if (protocol == ppp::dns::Protocol::DoH) {
            tag = " (DoH)";
        } else if (protocol == ppp::dns::Protocol::DoT) {
            tag = " (DoT)";
        }
        if (NULLPTR == tag) {
            return ppp::string();
        }
        ppp::string out = hostname;
        out += tag;
        return out;
    };

    auto pick_first = [&](const ppp::string& provider_or_ip,
                          const ppp::vector<AppConfiguration::DnsServerEntry>& entries) noexcept -> bool {
        for (const auto& e : entries) {
            if (e.address.empty()) {
                continue;
            }
            ppp::string host;
            int port = 0;
            if (!Ipep::ParseEndPoint(e.address, host, port)) {
                continue;
            }
            boost::asio::ip::address addr = host_to_address(host);
            if (addr.is_unspecified()) {
                continue;
            }

            ppp::dns::Protocol proto = ppp::dns::Protocol::UDP;
            ppp::string proto_lower = e.protocol;
            for (char& c : proto_lower) {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            }
            if (proto_lower == "doh") {
                proto = ppp::dns::Protocol::DoH;
            } else if (proto_lower == "dot" || proto_lower == "doq") {
                proto = ppp::dns::Protocol::DoT;
            } else if (proto_lower == "tcp") {
                proto = ppp::dns::Protocol::TCP;
            }

            ppp::string label = build_protocol_label(proto, e.hostname);
            if (try_push_address(addr, label)) {
                return true;
            }
        }

        if (provider_or_ip.empty()) {
            return false;
        }

        const ppp::vector<ppp::dns::ServerEntry>* provider = ppp::dns::DnsResolver::GetProvider(provider_or_ip);
        if (NULLPTR != provider) {
            ppp::string preferred_label;
            for (const ppp::dns::ServerEntry& se : *provider) {
                if ((se.protocol == ppp::dns::Protocol::DoH || se.protocol == ppp::dns::Protocol::DoT) &&
                    !se.hostname.empty() && preferred_label.empty()) {
                    preferred_label = build_protocol_label(se.protocol, se.hostname);
                }
            }

            for (const ppp::dns::ServerEntry& se : *provider) {
                if (se.protocol != ppp::dns::Protocol::UDP || se.address.empty()) {
                    continue;
                }
                ppp::string host;
                int port = 0;
                if (!Ipep::ParseEndPoint(se.address, host, port)) {
                    continue;
                }
                boost::asio::ip::address addr = host_to_address(host);
                if (try_push_address(addr, preferred_label)) {
                    return true;
                }
            }
        }

        return try_push_address(host_to_address(provider_or_ip), ppp::string());
    };

    if (NULLPTR != configuration_) {
        pick_first(configuration_->dns.servers.foreign,
                   configuration_->dns.servers.foreign_entries);
        pick_first(configuration_->dns.servers.domestic,
                   configuration_->dns.servers.domestic_entries);
    }

    boost::system::error_code ec;
    if (addresses.empty()) {
        addresses.emplace_back(ppp::StringToAddress(PPP_PREFERRED_DNS_SERVER_1, ec));
    }
    if (at_least_two && addresses.size() < 2) {
        addresses.emplace_back(ppp::StringToAddress(PPP_PREFERRED_DNS_SERVER_2, ec));
    }
    append_padding(addresses.size());
}

/**
 * @brief Builds and populates network interface options from command-line arguments.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Constructed network interface object, or null on allocation, invalid input, or unsupported mode.
 */
std::shared_ptr<NetworkInterface> PppApplication::GetNetworkInterface(int argc, const char* argv[]) noexcept {
    std::shared_ptr<NetworkInterface> ni = ppp::make_shared_object<NetworkInterface>();
    if (NULLPTR != ni) {
#if defined(_WIN32)
        const bool platform_default_lwip = !ppp::tap::TapWindows::IsWintun();
#else
        const bool platform_default_lwip = false;
#endif
#if defined(PPP_ENABLE_XTCP) && defined(PPP_XTCP_RUNTIME_WIRED)
        const bool xtcp_available = true;
#else
        const bool xtcp_available = false;
#endif
        const bool tcp_stack_specified = ppp::HasCommandArgument("--tcp-stack", argc, argv);
        const bool legacy_lwip_specified = ppp::HasCommandArgument("--lwip", argc, argv);
        const ppp::string tcp_stack_value = ppp::GetCommandArgument("--tcp-stack", argc, argv);
        const ppp::string legacy_lwip_value = ppp::GetCommandArgument("--lwip", argc, argv);
        const TcpStackModeResult tcp_stack = ResolveTcpStackMode({
            platform_default_lwip,
            tcp_stack_specified,
            tcp_stack_value,
            legacy_lwip_specified,
            ppp::ToBoolean(legacy_lwip_value.data()),
            xtcp_available,
        });
        if (tcp_stack.Status != TcpStackModeStatus::Success) {
            const ppp::diagnostics::ErrorCode error = tcp_stack.Status == TcpStackModeStatus::XtcpUnavailable
                ? ppp::diagnostics::ErrorCode::NetworkProtocolUnsupported
                : ppp::diagnostics::ErrorCode::ConfigFieldInvalid;
            ppp::diagnostics::SetLastErrorCode(error);
            return NULLPTR;
        }

        ni->TcpStack = tcp_stack.Mode;
        ni->Lwip = ni->TcpStack == TcpStackMode::Lwip;
        ni->Nic = ppp::RTrim(ppp::LTrim(ppp::GetCommandArgument("--nic", argc, argv)));
        ni->BlockQUIC = ppp::ToBoolean(ppp::GetCommandArgument("--block-quic", argc, argv).data());

        GetDnsAddresses(ni->DnsAddresses, &ni->DnsLabels, argc, argv);
        if (!ni->DnsAddresses.empty()) {
            // Publish a new immutable server list; in-place mutation would race with readers.
            auto dns_servers = ppp::make_shared_object<ppp::net::asio::vdns::IPEndPointVector>();
            if (NULLPTR != dns_servers) {
                for (const boost::asio::ip::address& dns_server : ni->DnsAddresses) {
                    dns_servers->emplace_back(boost::asio::ip::udp::endpoint(dns_server, PPP_DNS_SYS_PORT));
                }
                std::atomic_store(&ppp::net::asio::vdns::servers, dns_servers);
            }
        }

        ni->Ngw = GetNetworkAddress("--ngw", 0, 32, "0.0.0.0", argc, argv);
        ni->IPAddress = GetNetworkAddress("--tun-ip", 0, 32, "10.0.0.2", argc, argv);
        ni->IPv6Address = GetNetworkAddress("--tun-ipv6", 0, 128, argc, argv);
        ni->SubmaskAddress = GetNetworkAddress("--tun-mask", 16, 32, "255.255.255.252", argc, argv);
        ni->GatewayServer = GetNetworkAddress("--tun-gw", 0, 32, "10.0.0.1", argc, argv);

#if defined(_WIN32)
        ni->LeaseTimeInSeconds = strtoul(ppp::GetCommandArgument("--tun-lease-time-in-seconds", argc, argv).data(), NULLPTR, 10);
        if (ni->LeaseTimeInSeconds < 1) {
            ni->LeaseTimeInSeconds = 7200;
        }
#endif

        ni->IPAddress = Ipep::FixedIPAddress(ni->IPAddress, ni->GatewayServer, ni->SubmaskAddress);
        ni->StaticMode = ppp::ToBoolean(ppp::GetCommandArgument("--tun-static", argc, argv).data());

        // If the user explicitly passed --tun-ip on the command line, implicitly enable
        // static mode so the client sends "manual" to the server instead of requesting
        // DHCP auto-allocation.  This matches user expectation: specifying an IP means
        // "use this IP, don't let the server override it".
        if (!ni->StaticMode && ppp::HasCommandArgument("--tun-ip", argc, argv)) {
            ni->StaticMode = true;
        }
        ni->HostedNetwork = ppp::ToBoolean(ppp::GetCommandArgument("--tun-host", argc, argv, "y").data());
        ni->VNet = ppp::ToBoolean(ppp::GetCommandArgument("--tun-vnet", argc, argv, "y").data());

#if defined(_LINUX)
        ni->BypassNic = ppp::RTrim(ppp::LTrim(ppp::GetCommandArgument("--bypass-nic", argc, argv)));
#endif
        ni->BypassNgw = GetNetworkAddress("--bypass-ngw", 0, 32, "0.0.0.0", argc, argv);
        ni->BypassLoadList(File::GetFullPath(File::RewritePath(ppp::LTrim(ppp::RTrim(ppp::GetCommandArgument("--bypass", argc, argv, "./ip.txt"))).data()).data()));

        ni->DNSRules = ppp::GetCommandArgument("--dns-rules", argc, argv, "./dns-rules.txt");
        ni->FirewallRules = ppp::GetCommandArgument("--firewall-rules", argc, argv, "./firewall-rules.txt");

        {
            ppp::string tun_mux_arg = ppp::GetCommandArgument("--tun-mux", argc, argv);
            char* endptr = NULLPTR;
            long tun_mux_val = strtol(tun_mux_arg.data(), &endptr, 10);
            ni->Mux = (NULLPTR != endptr && endptr != tun_mux_arg.data() && *endptr == '\x0') ? static_cast<uint16_t>(std::max<long>(0, tun_mux_val)) : 0;
        }
        {
            ppp::string tun_mux_accel_arg = ppp::GetCommandArgument("--tun-mux-acceleration", argc, argv);
            char* endptr = NULLPTR;
            long tun_mux_accel_val = strtol(tun_mux_accel_arg.data(), &endptr, 10);
            ni->MuxAcceleration = (NULLPTR != endptr && endptr != tun_mux_accel_arg.data() && *endptr == '\x0') ? static_cast<uint8_t>(std::max<long>(0, tun_mux_accel_val)) : 0;
        }
        if (ni->MuxAcceleration > PPP_MUX_ACCELERATION_MAX) {
            ni->MuxAcceleration = 0;
        }

#if defined(_WIN32)
        ni->SetHttpProxy = ppp::ToBoolean(ppp::GetCommandArgument("--set-http-proxy", argc, argv).data());
        ni->Wintun = ppp::GetCommandArgument("--tun", argc, argv, NetworkInterface::GetDefaultTun());
        ni->ComponentId = ppp::tap::TapWindows::FindComponentId(ni->Wintun);
#else
        ni->ComponentId = ppp::GetCommandArgument("--tun", argc, argv, NetworkInterface::GetDefaultTun());

#if defined(_LINUX)
        if (ppp::ToBoolean(ppp::GetCommandArgument("--tun-route", argc, argv).data())) {
            ppp::tap::TapLinux::CompatibleRoute(true);
        }

        ni->ProtectNetwork = ppp::ToBoolean(ppp::GetCommandArgument("--tun-protect", argc, argv, "y").data());
        ni->Ssmt = 0;
        ni->SsmtMQ = false;

        if (ppp::string ssmt = ppp::GetCommandArgument("--tun-ssmt", argc, argv); !ssmt.empty()) {
            char ssmt_mq_keys[] = {'m', 'q'};
            for (int j = 0; j < arraysizeof(ssmt_mq_keys); j++) {
                if (ssmt.find(ssmt_mq_keys[j]) != ppp::string::npos) {
                    ni->SsmtMQ = true;
                    break;
                }
            }
            ni->Ssmt = std::max<int>(0, static_cast<int>(strtol(ssmt.data(), NULLPTR, 10)));
        }
#elif defined(_MACOS)
        {
            ppp::string ssmt_arg = ppp::GetCommandArgument("--tun-ssmt", argc, argv);
            char* endptr = NULLPTR;
            long ssmt_val = strtol(ssmt_arg.data(), &endptr, 10);
            ni->Ssmt = (NULLPTR != endptr && endptr != ssmt_arg.data() && *endptr == '\x0') ? static_cast<int>(std::max<long>(0, ssmt_val)) : 0;
        }
#endif

#if defined(_MACOS) || defined(_LINUX)
        ni->Promisc = ppp::ToBoolean(ppp::GetCommandArgument("--tun-promisc", argc, argv, "y").data());
#endif
#endif

        ni->ComponentId = ppp::LTrim<ppp::string>(ni->ComponentId);
        ni->ComponentId = ppp::RTrim<ppp::string>(ni->ComponentId);
    }
    return ni;
}

/**
 * @brief Determines whether process should run in client mode.
 */
bool PppApplication::IsModeClientOrServer(int argc, const char* argv[]) noexcept {
    return IsClientRuntimeMode(ResolveApplicationModeFromArgv(argc, argv));
}

/**
 * @brief Loads application configuration from explicit or default candidate paths.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param path Receives the effective configuration path on success.
 * @return Loaded configuration object, or null when loading fails.
 */
std::shared_ptr<AppConfiguration> PppApplication::LoadConfiguration(int argc, const char* argv[], ppp::string& path) noexcept {
    static constexpr const char* argument_keys[] = {"-c", "--c", "-config", "--config"};

    for (const char* argument_key : argument_keys) {
        ppp::string argument_value = ppp::GetCommandArgument(argument_key, argc, argv);
        if (argument_value.empty()) {
            continue;
        }

        argument_value = File::RewritePath(argument_value.data());
        argument_value = File::GetFullPath(argument_value.data());
        if (argument_value.empty()) {
            continue;
        }

        if (File::CanAccess(argument_value.data(), FileAccess::Read)) {
            path = std::move(argument_value);
            break;
        }
    }

    ppp::string configuration_paths[] = {
        path,
        "./config.json",
        "./appsettings.json",
    };

    bool found_configuration_file = false;

    /**
     * @brief Iterates candidate configuration files until one loads successfully.
     *
     * The loop normalizes each candidate path, verifies file existence, allocates a
     * configuration object, then loads and optionally wires a virtual-memory allocator.
     */
    for (ppp::string& configuration_path : configuration_paths) {
        if (configuration_path.empty()) {
            continue;
        }

        configuration_path = File::GetFullPath(File::RewritePath(configuration_path.data()).data());
        if (!File::Exists(configuration_path.data())) {
            continue;
        }

        found_configuration_file = true;

        std::shared_ptr<AppConfiguration> configuration = ppp::make_shared_object<AppConfiguration>();
        if (NULLPTR == configuration) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
            path.clear();
            return NULLPTR;
        }

        if (!configuration->Load(configuration_path)) {
            // PlatformNotSupportGUAMode is a soft-degrade condition: the configuration
            // file was parsed successfully but requested GUA mode on a platform that does
            // not support it (e.g. Windows).  Treat this as a non-fatal warning and try
            // the next candidate path rather than aborting the entire config search.
            continue;
        }

#if defined(_WIN32)
        if (configuration->vmem.size > 0)
#else
        if (configuration->vmem.path.size() > 0 && configuration->vmem.size > 0)
#endif
        {
            std::shared_ptr<BufferswapAllocator> allocator = ppp::make_shared_object<BufferswapAllocator>(
                configuration->vmem.path,
                std::max<int64_t>((int64_t)1LL << (int64_t)25LL, (int64_t)configuration->vmem.size << (int64_t)20LL));
            if (NULLPTR != allocator && allocator->IsVaild()) {
                configuration->SetBufferAllocator(allocator);
            }
        }

        path = configuration_path;
        return configuration;
    }

    path.clear();
    if (ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success) {
        ppp::diagnostics::SetLastErrorCode(found_configuration_file
            ? ppp::diagnostics::ErrorCode::ConfigLoadFailed
            : ppp::diagnostics::ErrorCode::ConfigFileNotFound);
    }

    return NULLPTR;
}

} // namespace ppp::app
