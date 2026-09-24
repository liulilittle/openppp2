#include <ios/OpenPPP2PacketTunnelBridge.h>
#include <ios/IosP2PDatagramTransport.h>
#include <ios/ppp/tap/TapIos.h>
#include <ppp/app/ApplicationClientBootstrap.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/runtime/RuntimeLifecycle.h>
#include <ppp/app/runtime/RuntimeSnapshotJson.h>
#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/IDisposable.h>
#include <ppp/io/File.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/vdns.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITransmissionStatistics.h>

#include <algorithm>
#include <atomic>
#include <cinttypes>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <mutex>
#include <os/log.h>
#include <pthread.h>
#include <system_error>
#include <thread>

struct openppp2_ios_tap
{
    std::mutex                                                                  sync;
    std::condition_variable                                                     start_condition;
    std::shared_ptr<ppp::tap::TapIos>                                           tap;
    std::shared_ptr<ppp::configurations::AppConfiguration>                      configuration;
    std::shared_ptr<ppp::app::client::VEthernetNetworkSwitcher>                 client;
    std::shared_ptr<boost::asio::io_context>                                    context;
    std::shared_ptr<ppp::threading::BufferswapAllocator>                        allocator;
    std::shared_ptr<ppp::p2p::IP2PDatagramTransportFactory>                    p2p_datagram_factory;
    ppp::string                                                                 start_stage = "idle";
    std::thread                                                                 runtime_thread;
    openppp2_ios_packet_writer                                                  writer = nullptr;
    void*                                                                       user_data = nullptr;
    uint64_t                                                                    inbound_total = 0;
    uint64_t                                                                    outbound_total = 0;
    int                                                                         link_state = 6;
    int                                                                         start_result = 1;
    bool                                                                        start_completed = false;
    bool                                                                        running = false;
    bool                                                                        stopping = false;
    std::atomic<bool>                                                           packet_logging { false };
    ppp::app::runtime::RuntimeLifecycle                                         runtime_lifecycle;
};

namespace
{
    using ppp::app::client::VEthernetExchanger;
    using ppp::app::client::VEthernetNetworkSwitcher;
    using ppp::auxiliary::JsonAuxiliary;
    using ppp::configurations::AppConfiguration;
    using ppp::diagnostics::ErrorCode;
    using ppp::diagnostics::FormatErrorString;
    using ppp::diagnostics::GetLastErrorCodeSnapshot;
    using ppp::diagnostics::SetLastErrorCode;
    using ppp::net::IPEndPoint;
    using ppp::net::Ipep;
    using ppp::threading::BufferswapAllocator;
    using ppp::threading::Executors;
    using ppp::transmissions::ITransmissionStatistics;

    std::mutex g_last_error_mutex;
    ppp::string g_last_error_text = "success";
    std::once_flag g_runtime_bootstrap_once;
    std::once_flag g_telemetry_sink_once;

    uint64_t runtime_now_ms() noexcept
    {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    void refresh_runtime(openppp2_ios_tap* tap) noexcept
    {
        if (tap == nullptr)
        {
            return;
        }

        const ppp::app::runtime::RuntimeSnapshot runtime = tap->runtime_lifecycle.GetSnapshot();
        if (runtime.generation == 0 || runtime.phase == ppp::app::runtime::RuntimePhase::Stopping)
        {
            return;
        }

        std::shared_ptr<VEthernetNetworkSwitcher> client;
        {
            std::lock_guard<std::mutex> scope(tap->sync);
            client = tap->client;
        }
        if (client == nullptr)
        {
            tap->runtime_lifecycle.Transition(
                runtime.generation,
                ppp::app::runtime::RuntimePhase::Connecting,
                runtime_now_ms());
            return;
        }

        std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger();
        if (exchanger == nullptr)
        {
            tap->runtime_lifecycle.Transition(
                runtime.generation,
                ppp::app::runtime::RuntimePhase::Connecting,
                runtime_now_ms());
            return;
        }
        tap->runtime_lifecycle.UpdateMuxState(
            runtime.generation,
            exchanger->GetMuxRuntimeState(),
            runtime_now_ms());
        // Lifetime counters, read straight from the atomics: the delta helper
        // rebases its reference and would make the totals non-monotonic.
        if (std::shared_ptr<ITransmissionStatistics> statistics = client->GetStatistics(); statistics != nullptr)
        {
            ppp::app::runtime::RuntimeTraffic traffic;
            traffic.rx_bytes = statistics->IncomingTraffic.load();
            traffic.tx_bytes = statistics->OutgoingTraffic.load();
            tap->runtime_lifecycle.UpdateTraffic(runtime.generation, traffic, runtime_now_ms());
        }
        if (exchanger->GetNetworkState() == VEthernetExchanger::NetworkState_Reconnecting)
        {
            tap->runtime_lifecycle.Transition(
                runtime.generation,
                ppp::app::runtime::RuntimePhase::Reconnecting,
                runtime_now_ms());
        }
        else if (exchanger->GetNetworkState() == VEthernetExchanger::NetworkState_Established)
        {
            tap->runtime_lifecycle.UpdateReadiness(
                runtime.generation,
                client->GetRuntimeReadiness(),
                runtime_now_ms());
            tap->runtime_lifecycle.Transition(
                runtime.generation,
                ppp::app::runtime::RuntimePhase::Connected,
                runtime_now_ms());
        }
        else
        {
            tap->runtime_lifecycle.Transition(
                runtime.generation,
                ppp::app::runtime::RuntimePhase::Handshaking,
                runtime_now_ms());
        }
    }

    void native_logf(const char* format, ...) noexcept
    {
        if (format == nullptr)
        {
            return;
        }

        char buffer[512];
        va_list args;
        va_start(args, format);
        std::vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        buffer[sizeof(buffer) - 1] = '\0';
        os_log(OS_LOG_DEFAULT, "%{public}s", buffer);
    }

    void telemetry_os_log_sink(const char* line) noexcept
    {
        if (line == nullptr)
        {
            return;
        }

        os_log(OS_LOG_DEFAULT, "OpenPPP2 telemetry: %{public}s", line);
    }

    void set_start_stage(openppp2_ios_tap* tap, const char* stage) noexcept
    {
        if (tap == nullptr || stage == nullptr)
        {
            return;
        }

        {
            std::lock_guard<std::mutex> scope(tap->sync);
            tap->start_stage = stage;
        }
        native_logf("OpenPPP2 native start: %s", stage);
    }

    void ensure_runtime_bootstrap() noexcept
    {
        std::call_once(g_runtime_bootstrap_once, []() noexcept {
            ppp::global::cctor();
        });
        std::call_once(g_telemetry_sink_once, []() noexcept {
            ppp::telemetry::SetConsoleSink(telemetry_os_log_sink);
        });
    }

    template<typename Callable>
    std::thread start_thread_with_stack_size(Callable&& callable, size_t stack_size)
    {
        using CallableType = std::decay_t<Callable>;
        auto* wrapper = new CallableType(std::forward<Callable>(callable));

        pthread_attr_t attributes;
        pthread_attr_init(&attributes);
        pthread_attr_setstacksize(&attributes, stack_size);

        pthread_t pthread_id;
        const int rc = pthread_create(
            &pthread_id,
            &attributes,
            [](void* arg) -> void*
            {
                auto* callable_ptr = static_cast<CallableType*>(arg);
                (*callable_ptr)();
                delete callable_ptr;
                return nullptr;
            },
            wrapper);
        pthread_attr_destroy(&attributes);

        if (rc != 0)
        {
            delete wrapper;
            throw std::system_error(rc, std::generic_category(), "pthread_create failed");
        }

        return std::thread([pthread_id]()
        {
            pthread_join(pthread_id, nullptr);
        });
    }

    void configure_native_telemetry(const std::shared_ptr<AppConfiguration>& configuration) noexcept
    {
        if (configuration == nullptr)
        {
            return;
        }

        ppp::telemetry::SetEnabled(configuration->telemetry.enabled);
        ppp::telemetry::SetMinLevel(configuration->telemetry.level);
        ppp::telemetry::SetCountEnabled(configuration->telemetry.count);
        ppp::telemetry::SetSpanEnabled(configuration->telemetry.span);
        ppp::telemetry::SetConsoleLogEnabled(true);
        ppp::telemetry::SetConsoleMetricEnabled(true);
        ppp::telemetry::SetConsoleSpanEnabled(true);
#if defined(_IPHONE)
        // Extension memory budget: keep metrics disabled, but allow explicit TRACE/spans for diagnostics.
        ppp::telemetry::SetCountEnabled(false);
        ppp::telemetry::SetConsoleMetricEnabled(false);
#endif
        ppp::telemetry::Configure(configuration->telemetry.endpoint.c_str());
        ppp::telemetry::SetLogFile(configuration->telemetry.log_file.c_str());

        native_logf(
            "OpenPPP2 telemetry configured enabled=%d level=%d count=%d span=%d console_log=1 console_metric=%d console_span=%d endpoint=%s",
            configuration->telemetry.enabled ? 1 : 0,
            configuration->telemetry.level,
            configuration->telemetry.count ? 1 : 0,
            configuration->telemetry.span ? 1 : 0,
#if defined(_IPHONE)
            0,
            configuration->telemetry.span ? 1 : 0,
#else
            1,
            1,
#endif
            configuration->telemetry.endpoint.empty() ? "(empty)" : configuration->telemetry.endpoint.c_str());
    }

    void set_last_error(const char* text) noexcept
    {
        std::lock_guard<std::mutex> scope(g_last_error_mutex);
        g_last_error_text = text == nullptr ? "unknown" : text;
    }

    void set_last_error_from_diagnostics(const char* fallback) noexcept
    {
        ErrorCode code = GetLastErrorCodeSnapshot();
        const char* formatted = FormatErrorString(code);
        if (formatted != nullptr && std::strcmp(formatted, "success") != 0)
        {
            set_last_error(formatted);
        }
        else
        {
            set_last_error(fallback);
        }
    }

    bool copy_text(const ppp::string& source, char* buffer, int buffer_size) noexcept
    {
        if (buffer == nullptr || buffer_size < 1)
        {
            return false;
        }

        int count = std::min<int>(static_cast<int>(source.size()), buffer_size - 1);
        if (count > 0)
        {
            std::memcpy(buffer, source.data(), static_cast<size_t>(count));
        }
        buffer[count] = '\0';
        return true;
    }

    ppp::string c_string_or_empty(const char* value) noexcept
    {
        return value == nullptr ? ppp::string() : ppp::string(value);
    }

    ppp::string resolve_routing_source(ppp::string source) noexcept
    {
        source = ppp::LTrim(ppp::RTrim(source));
        const bool has_file_uri_prefix = source.size() >= 7 &&
            (source[0] == 'f' || source[0] == 'F') &&
            (source[1] == 'i' || source[1] == 'I') &&
            (source[2] == 'l' || source[2] == 'L') &&
            (source[3] == 'e' || source[3] == 'E') &&
            source[4] == ':' && source[5] == '/' && source[6] == '/';
        if (has_file_uri_prefix)
        {
            source = ppp::LTrim(ppp::RTrim(source.substr(7)));
        }

        if (!source.empty())
        {
            ppp::string path = ppp::io::File::RewritePath(source.data());
            if (!path.empty() && ppp::io::File::Exists(path.data()))
            {
                return ppp::LTrim(ppp::RTrim(ppp::io::File::ReadAllText(path.data())));
            }
        }
        return source;
    }

    ppp::string resolve_routing_sources(const ppp::vector<ppp::string>& sources) noexcept
    {
        ppp::string resolved;
        for (const ppp::string& source : sources)
        {
            ppp::string item = resolve_routing_source(source);
            if (item.empty())
            {
                continue;
            }
            if (!resolved.empty())
            {
                resolved += "\n";
            }
            resolved += item;
        }
        return resolved;
    }

    struct tunnel_options_snapshot
    {
        int         mux = 0;
        int         vnet = 0;
        int         lwip = 0;
        int         block_quic = 0;
        int         static_mode = 0;
        ppp::string ip;
        ppp::string mask;
        ppp::string bypass_ip_list;
        ppp::string dns_rules_list;
        ppp::string root_path;
        int         packet_logging = 0;
        ppp::string dns1;
        ppp::string dns2;
    };

    tunnel_options_snapshot snapshot_options(const openppp2_ios_tunnel_options& options) noexcept
    {
        tunnel_options_snapshot snapshot;
        snapshot.mux = options.mux;
        snapshot.vnet = options.vnet;
        snapshot.lwip = options.lwip;
        snapshot.block_quic = options.block_quic;
        snapshot.static_mode = options.static_mode;
        snapshot.ip = c_string_or_empty(options.ip);
        snapshot.mask = c_string_or_empty(options.mask);
        snapshot.bypass_ip_list = c_string_or_empty(options.bypass_ip_list);
        snapshot.dns_rules_list = c_string_or_empty(options.dns_rules_list);
        snapshot.root_path = c_string_or_empty(options.root_path);
        snapshot.packet_logging = options.packet_logging;
        snapshot.dns1 = c_string_or_empty(options.dns1);
        snapshot.dns2 = c_string_or_empty(options.dns2);
        return snapshot;
    }

    bool parse_ipv4(const char* text, boost::asio::ip::address& address, const char* error_text) noexcept
    {
        ppp::string value = c_string_or_empty(text);
        if (value.empty())
        {
            set_last_error(error_text);
            return false;
        }

        boost::system::error_code ec;
        address = ppp::StringToAddress(value.data(), ec);
        if (ec || !address.is_v4())
        {
            set_last_error(error_text);
            return false;
        }

        return true;
    }

    bool parse_configuration(const char* configuration_json, std::shared_ptr<AppConfiguration>& configuration) noexcept
    {
        if (configuration_json == nullptr || configuration_json[0] == '\0')
        {
            set_last_error("configuration json is empty");
            return false;
        }

        std::shared_ptr<AppConfiguration> parsed = ppp::make_shared_object<AppConfiguration>();
        if (parsed == nullptr)
        {
            set_last_error("failed to allocate app configuration");
            return false;
        }

        Json::Value json = JsonAuxiliary::FromString(configuration_json);
        if (!json.isObject())
        {
            set_last_error("configuration json is not an object");
            return false;
        }

        if (!parsed->Load(json))
        {
            set_last_error_from_diagnostics("failed to load app configuration");
            return false;
        }

        ppp::net::asio::vdns::ttl = parsed->udp.dns.ttl;
        ppp::net::asio::vdns::enabled = parsed->udp.dns.turbo;
        configuration = parsed;
        configure_native_telemetry(configuration);
        return true;
    }

    bool configure_vdns_servers(
        const std::shared_ptr<AppConfiguration>& configuration,
        const ppp::string&                         dns1,
        const ppp::string&                         dns2) noexcept
    {
        if (configuration == nullptr)
        {
            return false;
        }

        ppp::string dns_csv;
        if (!dns1.empty())
        {
            dns_csv = dns1;
        }
        if (!dns2.empty())
        {
            if (!dns_csv.empty())
            {
                dns_csv += ",";
            }
            dns_csv += dns2;
        }
        if (dns_csv.empty())
        {
            native_logf("OpenPPP2 native: tunnel DNS servers are empty");
            return false;
        }

        ppp::vector<boost::asio::ip::address> ips;
        ppp::net::Ipep::ToDnsAddresses(dns_csv, ips);
        if (ips.empty())
        {
            native_logf("OpenPPP2 native: invalid tunnel DNS servers '%s'", dns_csv.c_str());
            return false;
        }

        std::shared_ptr<ppp::net::asio::vdns::IPEndPointVector> addresses =
            ppp::make_shared_object<ppp::net::asio::vdns::IPEndPointVector>();
        if (addresses == nullptr)
        {
            set_last_error("failed to allocate vdns server list");
            return false;
        }

        for (const boost::asio::ip::address& ip : ips)
        {
            addresses->emplace_back(boost::asio::ip::udp::endpoint(ip, PPP_DNS_SYS_PORT));
        }

        ppp::net::asio::vdns::enabled = configuration->udp.dns.turbo;
        ppp::net::asio::vdns::ttl = configuration->udp.dns.ttl;
        ppp::net::asio::vdns::servers = addresses;
        ppp::net::asio::vdns::ClearCache();
        native_logf(
            "OpenPPP2 native: configured vdns servers=%s turbo=%d ttl=%d",
            dns_csv.c_str(),
            configuration->udp.dns.turbo ? 1 : 0,
            configuration->udp.dns.ttl);
        return true;
    }

    bool normalize_tunnel_addresses(
        const tunnel_options_snapshot& options,
        boost::asio::ip::address&      ip_address,
        boost::asio::ip::address&      mask_address,
        boost::asio::ip::address&      gateway_address,
        uint32_t&                      ip,
        uint32_t&                      mask,
        uint32_t&                      gateway) noexcept
    {
        if (!parse_ipv4(options.ip.c_str(), ip_address, "tunnel ip is invalid"))
        {
            return false;
        }

        if (!parse_ipv4(options.mask.c_str(), mask_address, "tunnel mask is invalid"))
        {
            return false;
        }

        ip = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(ip_address, IPEndPoint::MinPort)).GetAddress();
        mask = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(mask_address, IPEndPoint::MinPort)).GetAddress();
        if (ip == IPEndPoint::AnyAddress || ip == IPEndPoint::LoopbackAddress || ip == IPEndPoint::NoneAddress)
        {
            set_last_error("tunnel ip is unusable");
            return false;
        }

        int prefix = IPEndPoint::NetmaskToPrefix(mask);
        if (prefix < 16)
        {
            set_last_error("tunnel mask range is too large");
            return false;
        }

        if (prefix > 30)
        {
            mask = IPEndPoint::NetmaskToPrefix(prefix);
            mask_address = Ipep::ToAddress(mask);
        }

        if (IPEndPoint::IsInvalid(ip_address))
        {
            set_last_error("tunnel ip is invalid");
            return false;
        }

        gateway_address = Ipep::FixedIPAddress(ip_address, mask_address);
        ip_address = Ipep::FixedIPAddress(ip_address, gateway_address, mask_address);
        ip = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(ip_address, IPEndPoint::MinPort)).GetAddress();
        gateway = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(gateway_address, IPEndPoint::MinPort)).GetAddress();
        return true;
    }

    int map_link_state(const std::shared_ptr<VEthernetNetworkSwitcher>& client) noexcept
    {
        if (client == nullptr)
        {
            return 2;
        }

        std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger();
        if (exchanger == nullptr)
        {
            return 3;
        }

        VEthernetExchanger::NetworkState state = exchanger->GetNetworkState();
        if (state == VEthernetExchanger::NetworkState_Connecting)
        {
            return 5;
        }

        if (state == VEthernetExchanger::NetworkState_Reconnecting)
        {
            return 4;
        }

        if (state == VEthernetExchanger::NetworkState_Established)
        {
            return 0;
        }

        return 1;
    }

    bool change_working_directory(const char* root_path) noexcept
    {
        if (root_path == nullptr || root_path[0] == '\0')
        {
            return true;
        }

        if (::chdir(root_path) == 0)
        {
            return true;
        }

        set_last_error("failed to switch OpenPPP2 root path");
        return false;
    }

    int complete_start(openppp2_ios_tap* tap, int result) noexcept
    {
        if (tap != nullptr)
        {
            {
                std::lock_guard<std::mutex> scope(tap->sync);
                if (!tap->start_completed)
                {
                    tap->start_result = result;
                    tap->start_completed = true;
                }
            }
            tap->start_condition.notify_all();
        }
        return result;
    }

    bool start_runtime(
        openppp2_ios_tap*                  tap,
        const char*                        configuration_json,
        const openppp2_ios_tunnel_options* options) noexcept
    {
        if (tap == nullptr || tap->writer == nullptr)
        {
            set_last_error("tap bridge is not initialized");
            return false;
        }

        if (options == nullptr)
        {
            set_last_error("tunnel options are null");
            return false;
        }

        ensure_runtime_bootstrap();

        tunnel_options_snapshot options_copy = snapshot_options(*options);

        if (!change_working_directory(options_copy.root_path.c_str()))
        {
            return false;
        }

        std::shared_ptr<AppConfiguration> configuration;
        if (!parse_configuration(configuration_json, configuration))
        {
            return false;
        }

        const bool proxy_only_runtime = configuration->client.proxy_only;
        if (proxy_only_runtime) {
            // Mirror the desktop/Android behaviour: force loopback listener
            // defaults so the HTTP/SOCKS proxy is never bound to a non-loopback
            // address inside the iOS app sandbox.
            configuration->ApplyProxyModeDefaults();
        }
        ppp::string resolved_bypass_ip_list;
        ppp::string resolved_dns_rules;
        if (configuration->client.routing.configured)
        {
            resolved_bypass_ip_list = resolve_routing_sources(configuration->client.routing.bypass);
            resolved_dns_rules = resolve_routing_sources(configuration->client.routing.dns_rules);
        }
        else
        {
            resolved_bypass_ip_list = resolve_routing_source(options_copy.bypass_ip_list);
            resolved_dns_rules = resolve_routing_source(options_copy.dns_rules_list);
        }

        if (!proxy_only_runtime && !configure_vdns_servers(configuration, options_copy.dns1, options_copy.dns2))
        {
            native_logf("OpenPPP2 native: vdns servers not configured; gateway DNS may fail");
        }

        boost::asio::ip::address ip_address;
        boost::asio::ip::address mask_address;
        boost::asio::ip::address gateway_address;
        uint32_t ip = IPEndPoint::AnyAddress;
        uint32_t mask = IPEndPoint::AnyAddress;
        uint32_t gateway = IPEndPoint::AnyAddress;
        if (!normalize_tunnel_addresses(options_copy, ip_address, mask_address, gateway_address, ip, mask, gateway))
        {
            return false;
        }

        {
            std::lock_guard<std::mutex> scope(tap->sync);
            tap->start_completed = false;
            tap->start_result = 1;
            tap->stopping = false;
            tap->running = true;
            tap->link_state = 5;
            tap->configuration = configuration;
            tap->inbound_total = 0;
            tap->outbound_total = 0;
            tap->start_stage = "runtime thread pending";
            tap->packet_logging.store(options_copy.packet_logging != 0, std::memory_order_relaxed);
        }

        try
        {
            native_logf("OpenPPP2 native start: creating runtime thread");
            tap->runtime_thread = start_thread_with_stack_size(
                [tap, configuration, options_copy, proxy_only_runtime, resolved_bypass_ip_list, resolved_dns_rules, ip, gateway, mask]() mutable noexcept
            {
                auto start = [tap, configuration, &options_copy, proxy_only_runtime, resolved_bypass_ip_list, resolved_dns_rules, ip, gateway, mask](int, const char**) noexcept -> int
                {
                    set_start_stage(tap, "executor callback entered");
                    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
                    if (context == nullptr)
                    {
                        set_last_error("OpenPPP2 runtime context is unavailable");
                        return complete_start(tap, 1);
                    }

                    set_start_stage(tap, "configuring executors");
                    int max_concurrent = std::max<int>(1, ppp::GetProcesserCount());
#if defined(_IPHONE)
                    // Network Extension memory budget: cap worker threads (keep >= 2 for ctcp accept/connect).
                    max_concurrent = std::min(max_concurrent, 2);
#endif
                    Executors::SetMaxThreads(configuration->GetBufferAllocator(), max_concurrent);
                    Executors::SetMaxSchedulers(max_concurrent);

                    set_start_stage(tap, "creating TapIos");
                    std::shared_ptr<ppp::tap::TapIos> ios_tap = ppp::tap::TapIos::Create(
                        context,
                        "packet-tunnel",
                        ip,
                        gateway,
                        mask,
                        false,
                        true,
                        ppp::vector<uint32_t>());

                    if (ios_tap == nullptr)
                    {
                        set_last_error("failed to create iOS packet tap");
                        return complete_start(tap, 1);
                    }

                    ios_tap->SetP2PDatagramTransportFactory(
                        ppp::p2p::GetIosProviderP2PDatagramTransportFactory(tap));

                    set_start_stage(tap, "installing packet output");
                    ios_tap->SetPacketOutput(
                        [tap](const void* packet, int packet_size, void* packet_context, ppp::tap::TapIos::PacketOutputReleaseHandler packet_release) noexcept -> bool
                        {
                            bool ok = tap->writer(packet, packet_size, packet_context, packet_release, tap->user_data) != 0;
                            if (packet_size > 0 && tap->packet_logging.load(std::memory_order_relaxed))
                            {
                                static std::atomic<uint64_t> output_count { 0 };
                                uint64_t n = ++output_count;
                                if (n <= 20 || (n % 50) == 0 || !ok)
                                {
                                    native_logf("OpenPPP2 native output #%llu bytes=%d ok=%d", (unsigned long long)n, packet_size, ok ? 1 : 0);
                                }
                            }
                            if (ok && packet_size > 0)
                            {
                                std::lock_guard<std::mutex> scope(tap->sync);
                                tap->outbound_total += static_cast<uint64_t>(packet_size);
                            }
                            return ok;
                        });

                    set_start_stage(tap, "opening TapIos");
                    if (!ios_tap->Open())
                    {
                        set_last_error("failed to open iOS packet tap");
                        return complete_start(tap, 1);
                    }

                    set_start_stage(tap, "creating network switcher");
                    bool lwip = options_copy.lwip != 0;
                    bool vnet = options_copy.vnet != 0;
                    bool mta = false;
                    std::shared_ptr<VEthernetNetworkSwitcher> client =
                        ppp::make_shared_object<VEthernetNetworkSwitcher>(context, lwip, vnet, mta, configuration);
                    if (client == nullptr)
                    {
                        set_last_error("failed to create OpenPPP2 client");
                        ios_tap->Dispose();
                        return complete_start(tap, 1);
                    }

                    bool proxy_only_flag = proxy_only_runtime;
                    client->ProxyOnly(&proxy_only_flag);

                    set_start_stage(tap, "configuring network switcher");
                    int requested_mux = options_copy.mux;
                    int effective_mux = requested_mux > 0 ? std::min<int>(requested_mux, UINT16_MAX) : 0;
                    uint16_t mux = static_cast<uint16_t>(effective_mux);
                    bool vmux_active = effective_mux > 0;
                    native_logf("OpenPPP2 native dataplane: lwip=%d vnet=%d mta=%d mux=%d requested_mux=%d effective_mux=%d vmux_active=%d max_concurrent=%d stack_mb=5",
                        lwip ? 1 : 0, vnet ? 1 : 0, mta ? 1 : 0, static_cast<int>(mux), requested_mux, effective_mux, vmux_active ? 1 : 0, max_concurrent);
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "ios_tunnel",
                        "dataplane start lwip=%d mux=%d requested_mux=%d effective_mux=%d vmux_active=%d max_concurrent=%d stack_mb=5",
                        lwip ? 1 : 0, static_cast<int>(mux), requested_mux, effective_mux, vmux_active ? 1 : 0, max_concurrent);
                    bool static_mode = ppp::app::NormalizeClientStaticMode(options_copy.static_mode != 0, proxy_only_runtime);
                    client->Mux(&mux);
                    client->StaticMode(&static_mode);
                    client->BlockQUIC(options_copy.block_quic != 0);

                    // Native bypass and DNS policy is shared by TUN and
                    // proxy-only modes; only host DNS/route takeover remains
                    // TUN-only in the platform bridge.
                    ppp::string dns_rules = resolved_dns_rules;
                    if (!dns_rules.empty())
                    {
                        client->LoadAllDnsRules(dns_rules, false);
                    }

                    ppp::string bypass_ip_list = resolved_bypass_ip_list;
                    if (!bypass_ip_list.empty())
                    {
                        client->SetBypassIpList(std::move(bypass_ip_list));
                    }

                    // Mobile route sources are loaded into the native RIB/FIB
                    // by RouteCoordinator_mobile during ClientConnectionOpener::AddAllRoute.
                    // The mobile switcher intentionally has no desktop
                    // AddLoadIPList API, so do not duplicate that load here.

                    set_start_stage(tap, "opening OpenPPP2 client");
                    if (!client->Open(ios_tap))
                    {
                        set_last_error_from_diagnostics("failed to open OpenPPP2 client");
                        ppp::IDisposable::DisposeReferences(ios_tap, client);
                        return complete_start(tap, 1);
                    }

                    set_start_stage(tap, "publishing runtime objects");
                    {
                        std::lock_guard<std::mutex> scope(tap->sync);
                        tap->tap = ios_tap;
                        tap->client = client;
                        tap->context = context;
                        tap->link_state = 0;
                    }

                    set_last_error("success");
                    set_start_stage(tap, "client opened");
                    return complete_start(tap, 0);
                };

                int rc = 1;
                try
                {
                    set_start_stage(tap, "running executor");
                    rc = Executors::Run(configuration->GetBufferAllocator(), start);
                    native_logf("OpenPPP2 native start: executor exited rc=%d", rc);
                }
                catch (const std::exception& e)
                {
                    set_last_error(e.what());
                    complete_start(tap, 1);
                    rc = 1;
                }
                catch (...)
                {
                    set_last_error("OpenPPP2 runtime failed");
                    complete_start(tap, 1);
                    rc = 1;
                }

                {
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "ios_tunnel",
                        "runtime thread exiting rc=%d stopping=%d inbound=%llu outbound=%llu error=%s",
                        rc,
                        tap->stopping ? 1 : 0,
                        (unsigned long long)tap->inbound_total,
                        (unsigned long long)tap->outbound_total,
                        g_last_error_text.c_str());
                    ppp::telemetry::Count("ios_tunnel.runtime_exit", 1);

                    std::lock_guard<std::mutex> scope(tap->sync);
                    tap->running = false;
                    tap->context.reset();
                    if (tap->start_result != 0)
                    {
                        tap->tap.reset();
                        tap->client.reset();
                        tap->configuration.reset();
                    }
                    tap->link_state = tap->stopping ? 2 : tap->link_state;
                    tap->start_stage = tap->stopping ? "runtime exited (stop requested)" : "runtime exited (unexpected)";
                }
                tap->start_condition.notify_all();
                (void)rc;
            // iOS Network Extension memory budget is tight (~15-50MB). Reserve a
            // moderate stack: 32MB risks Jetsam; 4MB was too small for ctcp load.
            }, static_cast<size_t>(5) * 1024 * 1024);
        }
        catch (const std::exception& e)
        {
            set_last_error(e.what());
            complete_start(tap, 1);
        }
        catch (...)
        {
            set_last_error("failed to start OpenPPP2 runtime thread");
            complete_start(tap, 1);
        }

        {
            std::unique_lock<std::mutex> lock(tap->sync);
            while (!tap->start_completed)
            {
                ppp::string stage = tap->start_stage;
                if (tap->start_condition.wait_for(lock, std::chrono::seconds(3), [tap]() noexcept { return tap->start_completed; }))
                {
                    break;
                }
                lock.unlock();
                native_logf("OpenPPP2 native start: still waiting at %s", stage.c_str());
                lock.lock();
            }
            bool ok = tap->start_result == 0;
            lock.unlock();
            if (!ok && tap->runtime_thread.joinable())
            {
                tap->runtime_thread.join();
            }
            return ok;
        }
    }
}

const char* openppp2_ios_version(void)
{
    return "openppp2-ios";
}

openppp2_ios_tap* openppp2_ios_tap_create(
    openppp2_ios_packet_writer writer,
    void*                      user_data)
{
    if (nullptr == writer)
    {
        set_last_error("packet writer is null");
        return nullptr;
    }

    openppp2_ios_tap* bridge = new (std::nothrow) openppp2_ios_tap();
    if (nullptr == bridge)
    {
        set_last_error("failed to allocate tap bridge");
        return nullptr;
    }

    bridge->writer = writer;
    bridge->user_data = user_data;
    return bridge;
}

int openppp2_ios_tap_set_p2p_datagram_provider(
    openppp2_ios_tap*                           tap,
    const openppp2_ios_p2p_datagram_provider* provider,
    void*                                       user_data)
{
    if (nullptr == tap || nullptr == provider || nullptr == user_data)
    {
        return 0;
    }

    auto factory = ppp::p2p::CreateIosProviderP2PDatagramTransportFactory(
        *provider, user_data);
    if (nullptr == factory)
    {
        return 0;
    }

    std::lock_guard<std::mutex> scope(tap->sync);
    if (tap->running || nullptr != tap->p2p_datagram_factory)
    {
        return 0;
    }
    tap->p2p_datagram_factory = std::move(factory);
    return 1;
}

void openppp2_ios_tap_clear_p2p_datagram_provider(openppp2_ios_tap* tap)
{
    if (nullptr == tap)
    {
        return;
    }
    std::lock_guard<std::mutex> scope(tap->sync);
    tap->p2p_datagram_factory.reset();
}

namespace ppp {
    namespace p2p {
        std::shared_ptr<IP2PDatagramTransportFactory>
        GetIosProviderP2PDatagramTransportFactory(
                openppp2_ios_tap* tap) noexcept
        {
            if (nullptr == tap)
            {
                return nullptr;
            }
            std::lock_guard<std::mutex> scope(tap->sync);
            return tap->p2p_datagram_factory;
        }
    }
}

void openppp2_ios_tap_destroy(openppp2_ios_tap* tap)
{
    if (nullptr == tap)
    {
        return;
    }

    tap->p2p_datagram_factory.reset();
    delete tap;
}

int openppp2_ios_tap_start(
    openppp2_ios_tap*                  tap,
    const char*                        configuration_json,
    const openppp2_ios_tunnel_options* options)
{
    if (nullptr == tap || nullptr == tap->writer)
    {
        set_last_error("tap bridge is not initialized");
        return 1;
    }

    {
        std::lock_guard<std::mutex> scope(tap->sync);
        if (tap->running || nullptr != tap->tap || nullptr != tap->client)
        {
            return 0;
        }
    }

    ppp::app::runtime::RuntimeSnapshot runtime_seed;
    runtime_seed.role = "client";
    runtime_seed.capabilities = {
        "mux.compat", "mux.flow", "mux.balance", "mux.stripe"};
    const uint64_t runtime_generation = tap->runtime_lifecycle.Begin(
        std::move(runtime_seed),
        runtime_now_ms());
    tap->runtime_lifecycle.Transition(
        runtime_generation,
        ppp::app::runtime::RuntimePhase::PreparingHost,
        runtime_now_ms());
    tap->runtime_lifecycle.Transition(
        runtime_generation,
        ppp::app::runtime::RuntimePhase::Connecting,
        runtime_now_ms());

    if (!start_runtime(tap, configuration_json, options))
    {
        ppp::app::runtime::RuntimeError error;
        error.code = static_cast<uint32_t>(std::max(0, openppp2_ios_last_error_code()));
        error.severity = "error";
        error.user_message_key = "RuntimeFailed";
        if (tap->runtime_lifecycle.TryBeginStop(runtime_generation, runtime_now_ms()))
        {
            tap->runtime_lifecycle.CompleteStop(
                runtime_generation,
                false,
                std::move(error),
                runtime_now_ms());
        }
        return 1;
    }

    tap->runtime_lifecycle.Transition(
        runtime_generation,
        ppp::app::runtime::RuntimePhase::Handshaking,
        runtime_now_ms());

    return 0;
}

    const char* stop_reason_name(int stop_reason) noexcept
    {
        switch (stop_reason)
        {
        case 0:
            return "none";
        case 1:
            return "user_initiated";
        case 2:
            return "provider_failed";
        case 3:
            return "no_network";
        case 4:
            return "network_change";
        case 5:
            return "provider_disabled";
        case 6:
            return "auth_canceled";
        case 7:
            return "config_failed";
        case 8:
            return "idle_timeout";
        case 9:
            return "config_disabled";
        case 10:
            return "config_removed";
        case 11:
            return "supervisor";
        default:
            return stop_reason < 0 ? "unknown" : "other";
        }
    }

int openppp2_ios_tap_stop(openppp2_ios_tap* tap, int stop_reason)
{
    if (nullptr == tap)
    {
        return 0;
    }

    const ppp::app::runtime::RuntimeSnapshot runtime = tap->runtime_lifecycle.GetSnapshot();
    const bool stop_owner = runtime.generation != 0 &&
        tap->runtime_lifecycle.TryBeginStop(runtime.generation, runtime_now_ms());
    if (runtime.generation != 0 && !stop_owner)
    {
        return 0;
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client;
    std::shared_ptr<ppp::tap::TapIos> ios_tap;
    std::shared_ptr<boost::asio::io_context> context;
    {
        std::lock_guard<std::mutex> scope(tap->sync);
        tap->stopping = true;
        client = tap->client;
        ios_tap = tap->tap;
        context = tap->context;
    }

    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "ios_tunnel",
        "tap stop reason=%d name=%s inbound=%llu outbound=%llu",
        stop_reason,
        stop_reason_name(stop_reason),
        (unsigned long long)tap->inbound_total,
        (unsigned long long)tap->outbound_total);
    ppp::telemetry::Count("ios_tunnel.stop", 1);
    ppp::telemetry::Flush(3000);

    auto cleanup_complete =
        [tap, runtime, stop_owner, ios_tap, context](
            bool cleanup_success) mutable noexcept
        {
            if (nullptr != ios_tap)
            {
                ios_tap->Dispose();
            }
            if (stop_owner)
            {
                ppp::app::runtime::RuntimeError error;
                if (!cleanup_success)
                {
                    error.code = static_cast<uint32_t>(
                        ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                    error.severity = "error";
                    error.retryable = true;
                    error.user_message_key = "CleanupFailed";
                }
                tap->runtime_lifecycle.CompleteStop(
                    runtime.generation,
                    cleanup_success,
                    std::move(error),
                    runtime_now_ms());
            }
            if (nullptr != context)
            {
                Executors::Exit(context);
            }
        };

    if (nullptr != client)
    {
        client->Dispose(cleanup_complete);
    }
    else
    {
        cleanup_complete(true);
    }

    if (tap->runtime_thread.joinable())
    {
        tap->runtime_thread.join();
    }

    {
        std::lock_guard<std::mutex> scope(tap->sync);
        tap->tap.reset();
        tap->client.reset();
        tap->context.reset();
        tap->configuration.reset();
        tap->running = false;
        tap->stopping = false;
        tap->link_state = 2;
    }
    return 0;
}

int openppp2_ios_tap_input(
    openppp2_ios_tap* tap,
    const void*       packet,
    int               packet_size)
{
    if (nullptr == tap || nullptr == packet || packet_size < 1)
    {
        return 0;
    }

    std::shared_ptr<ppp::tap::TapIos> ios_tap;
    {
        std::lock_guard<std::mutex> scope(tap->sync);
        ios_tap = tap->tap;
    }

    if (nullptr == ios_tap)
    {
        return 0;
    }

    bool ok = ios_tap->Input(packet, packet_size);
    if (tap->packet_logging.load(std::memory_order_relaxed))
    {
        static std::atomic<uint64_t> input_count { 0 };
        uint64_t n = ++input_count;
        if (n <= 20 || (n % 50) == 0 || !ok)
        {
            native_logf("OpenPPP2 native input #%llu bytes=%d ok=%d", (unsigned long long)n, packet_size, ok ? 1 : 0);
        }
    }
    if (ok)
    {
        std::lock_guard<std::mutex> scope(tap->sync);
        tap->inbound_total += static_cast<uint64_t>(packet_size);
    }
    return ok ? 1 : 0;
}

int openppp2_ios_tap_get_link_state(openppp2_ios_tap* tap)
{
    if (nullptr == tap)
    {
        return 6;
    }

    std::lock_guard<std::mutex> scope(tap->sync);
    if (nullptr == tap->tap)
    {
        return 2;
    }

    tap->link_state = map_link_state(tap->client);
    if (tap->start_completed && tap->start_result == 0 && tap->link_state == 5)
    {
        tap->link_state = 0;
    }
    return tap->link_state;
}

int openppp2_ios_tap_get_runtime_snapshot(
    openppp2_ios_tap* tap,
    char*             buffer,
    int               buffer_size)
{
    if (nullptr == tap)
    {
        return 0;
    }

    refresh_runtime(tap);
    const std::string encoded = ppp::app::runtime::SerializeRuntimeSnapshot(
        tap->runtime_lifecycle.GetSnapshot());
    const ppp::string snapshot(encoded.data(), encoded.size());
    if (!copy_text(snapshot, buffer, buffer_size))
    {
        return 0;
    }
    return static_cast<int>(snapshot.size());
}

int openppp2_ios_tap_get_start_stage(
    openppp2_ios_tap* tap,
    char*             buffer,
    int               buffer_size)
{
    if (nullptr == tap)
    {
        return 0;
    }

    ppp::string stage;
    {
        std::lock_guard<std::mutex> scope(tap->sync);
        stage = tap->start_stage;
    }

    if (!copy_text(stage, buffer, buffer_size))
    {
        return 0;
    }
    return static_cast<int>(stage.size());
}

const char* openppp2_ios_last_error_text(void)
{
    ErrorCode code = GetLastErrorCodeSnapshot();
    if (code != ErrorCode::Success)
    {
        const char* formatted = FormatErrorString(code);
        if (formatted != nullptr)
        {
            set_last_error(formatted);
        }
    }
    else
    {
        set_last_error("success");
    }

    std::lock_guard<std::mutex> scope(g_last_error_mutex);
    return g_last_error_text.c_str();
}

int openppp2_ios_last_error_code(void)
{
    return static_cast<int>(GetLastErrorCodeSnapshot());
}

namespace
{
    openppp2_ios_http_post_fn g_ios_http_post = nullptr;
    void*                       g_ios_http_post_user_data = nullptr;

    bool ios_http_post_sink(const char* url, const void* body, size_t body_len, void* user_data) noexcept
    {
        (void)user_data;
        if (g_ios_http_post == nullptr || url == nullptr || body == nullptr || body_len == 0)
        {
            return false;
        }

        return g_ios_http_post(url, body, static_cast<int>(body_len), g_ios_http_post_user_data) != 0;
    }
}

void openppp2_ios_set_telemetry_http_post(openppp2_ios_http_post_fn fn, void* user_data)
{
    g_ios_http_post = fn;
    g_ios_http_post_user_data = user_data;
    ppp::telemetry::SetHttpPostSink(fn != nullptr ? ios_http_post_sink : nullptr, nullptr);
}

void openppp2_ios_set_telemetry_resource_attribute(const char* key, const char* value)
{
    ppp::telemetry::SetResourceAttribute(key, value);
}

void openppp2_ios_clear_telemetry_resource_attributes(void)
{
    ppp::telemetry::ClearResourceAttributes();
}
