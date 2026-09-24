/**
 * @file ApplicationMainLoop.cpp
 * @brief Runtime loop, periodic tasks, and utility command handlers.
 */

#include <ppp/configurations/AppConfiguration.h>
#include <common/aggligator/aggligator.h>
#include <ppp/transmissions/proxys/IForwarding.h>
#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetSocksProxySwitcher.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/proxys/VEthernetLocalProxySwitcher.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetManagedServer.h>
#include <ppp/app/PppApplicationInternal.h>
#include <ppp/app/runtime/RuntimeStatsJson.h>
#include <ppp/app/tui/TuiRuntimeAdapter.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/LinkTelemetry.h>
#include <ppp/diagnostics/Telemetry.h>
#include <cstdio>
#if defined(_WIN32)
#include <windows/ppp/app/client/lsp/PaperAirplaneController.h>
#endif

namespace ppp::app {

using client::VEthernetExchanger;
using client::VEthernetNetworkSwitcher;
using client::proxys::VEthernetLocalProxySwitcher;
using server::VirtualEthernetSwitcher;

/**
 * @brief Appends one formatted line with aligned key column to environment output.
 * @param lines Output line vector.
 * @param key Left-side label text.
 * @param value Right-side value text.
 */
static void AppendEnvLine(ppp::vector<ppp::string>& lines, const char* key, const ppp::string& value) noexcept {
    ppp::string line = key;
    line = ppp::PaddingRight<ppp::string>(line, 22u, ' ');
    line += ": ";
    line += value;
    lines.emplace_back(std::move(line));
}

/**
 * @brief Builds a repeated section separator line at fixed width.
 * @param width Number of characters in the separator.
 * @return String filled with '-' characters.
 */
static ppp::string BuildSectionSeparator(std::size_t width) noexcept {
    ppp::string separator;
    separator = ppp::PaddingRight<ppp::string>(separator, width, '-');
    return separator;
}

/**
 * @brief Converts current build flavor to printable hosting environment text.
 * @param client_mode Whether process currently runs in client mode.
 * @return String in format "client:production" / "server:development".
 */
static ppp::string BuildHostingEnvironmentText(ApplicationMode mode) noexcept {
#if defined(_DEBUG)
    ppp::string env = "development";
#else
    ppp::string env = "production";
#endif
    ppp::string prefix = "server:";
    if (ApplicationMode::Client == mode) {
        prefix = "client:";
    }
    else if (ApplicationMode::Proxy == mode) {
        prefix = "proxy:";
    }
    return prefix + env;
}

static const char* RuntimeStatsGradeName(
    ppp::diagnostics::LinkQualityGrade grade) noexcept {
    using Grade = ppp::diagnostics::LinkQualityGrade;
    switch (grade) {
        case Grade::Excellent: return "Excellent";
        case Grade::Outstanding: return "Outstanding";
        case Grade::Good: return "Good";
        case Grade::Average: return "Average";
        case Grade::Poor: return "Poor";
        case Grade::Terrible: return "Terrible";
        case Grade::Unusable: return "Unusable";
        default: return "Unknown";
    }
}

static bool WriteRuntimeStatsLine(
    const ppp::string& path,
    const ppp::app::runtime::RuntimeStatsSample& sample) noexcept {
    if (path.empty()) {
        return false;
    }

    const std::string json = ppp::app::runtime::SerializeRuntimeStats(sample);
    if (json.empty()) {
        return false;
    }
    std::FILE* output = stdout;
    bool close_output = false;
    if (path != "stdout") {
        output = std::fopen(path.c_str(), "ab");
        close_output = true;
    }
    if (NULLPTR == output) {
        return false;
    }

    const bool written = std::fwrite(json.data(), 1, json.size(), output) == json.size() &&
        std::fputc('\n', output) != EOF && std::fflush(output) == 0 && !std::ferror(output);
    if (!close_output) {
        return written;
    }
    const int close_result = std::fclose(output);
    return written && close_result == 0;
}

/**
 * @brief Formats exchanger link state enum to printable text.
 * @param state Exchanger runtime network state.
 * @return One of connecting/established/reconnecting.
 */
static const char* ToNetworkStateString(VEthernetExchanger::NetworkState state) noexcept {
    switch (state) {
        case VEthernetExchanger::NetworkState_Established:
            return "established";
        case VEthernetExchanger::NetworkState_Reconnecting:
            return "reconnecting";
        default:
            return "connecting";
    }
}

/**
 * @brief Builds full runtime environment lines mirrored from legacy foreground console output.
 * @param lines Output line vector receiving formatted environment rows.
 */
void PppApplication::GetEnvironmentInformationLines(ppp::vector<ppp::string>& lines,
    uint64_t incoming_traffic,
    uint64_t outgoing_traffic,
    const std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept {
    lines.clear();
    lines.reserve(160u);

    static constexpr std::size_t kSectionSeparatorWidth = 96u;
    ppp::string section_separator = BuildSectionSeparator(kSectionSeparatorWidth);

    ppp::string hosting_environment = BuildHostingEnvironmentText(application_mode_);

    ppp::string app_label = PPP_APPLICATION_NAME;
    app_label += " v";
    app_label += PPP_APPLICATION_VERSION;
    app_label += " (";
    app_label += ApplicationModeName(application_mode_);
    app_label += ")";

    AppendEnvLine(lines, "Application", app_label);
    AppendEnvLine(lines, "Max Concurrent", stl::to_string<ppp::string>(
        configuration_ ? configuration_->concurrent : 0));
    AppendEnvLine(lines, "Process", stl::to_string<ppp::string>(
        static_cast<Int32>(ppp::GetCurrentProcessId())));

#if defined(__SIMD__)
    if (aesni::aes_cpu_is_support()) {
        AppendEnvLine(lines, "Triplet", ppp::string(ppp::GetSystemCode()) + ":" + ppp::GetPlatformCode() + "[SIMD]");
    } else {
        AppendEnvLine(lines, "Triplet", ppp::string(ppp::GetSystemCode()) + ":" + ppp::GetPlatformCode());
    }
#else
    AppendEnvLine(lines, "Triplet", ppp::string(ppp::GetSystemCode()) + ":" + ppp::GetPlatformCode());
#endif

    AppendEnvLine(lines, "Cwd", ppp::GetCurrentDirectoryPath());
    AppendEnvLine(lines, "Template", configuration_path_);

    std::shared_ptr<VirtualEthernetSwitcher> server = server_;
    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;

    if (NULLPTR != server) {
        auto managed_server = server->GetManagedServer();
        if (NULLPTR != managed_server) {
            const char* link_state = "connecting";
            if (managed_server->LinkIsAvailable()) {
                link_state = "established";
            } else if (managed_server->LinkIsReconnecting()) {
                link_state = "reconnecting";
            }

            AppendEnvLine(lines, "Managed Server", managed_server->GetUri() + " @(" + link_state + ")");
        }
    }

    if (NULLPTR != client) {
#if !defined(_ANDROID) && !defined(_IPHONE)
        if (ppp::string remote_uri = client->GetRemoteUri(); !remote_uri.empty()) {
            std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger();
            ppp::string mode_text = (NULLPTR != exchanger && exchanger->StaticEchoAllocated()) ? "static" : "dynamic";
            AppendEnvLine(lines, "VPN Server", remote_uri + " [" + mode_text + "]");
        }
#endif

        struct {
            const char* tab;
            std::shared_ptr<VEthernetLocalProxySwitcher> switcher;
        } proxys[] = {
            { "http", client->GetHttpProxy() },
            { "socks", client->GetSocksProxy() }
        };
        for (const auto& proxy : proxys) {
            std::shared_ptr<VEthernetLocalProxySwitcher> switcher = proxy.switcher;
            if (NULLPTR == switcher) {
                continue;
            }

            boost::asio::ip::tcp::endpoint localEP = switcher->GetLocalEndPoint();
            boost::asio::ip::address localIP = localEP.address();
            if (localIP.is_unspecified()) {
#if !defined(_ANDROID) && !defined(_IPHONE)
                if (auto ni = client->GetUnderlyingNetworkInterface(); NULLPTR != ni) {
                    localIP = ni->IPAddress;
                }
#endif
            }

            ppp::string endpoint_text = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(localIP, localEP.port())).ToString();
            if ("http" == ppp::string(proxy.tab)) {
                AppendEnvLine(lines, "Http Proxy", endpoint_text + "/http");
            } else {
                AppendEnvLine(lines, "Socks Proxy", endpoint_text + "/socks");
            }
        }

#if defined(_WIN32)
        AppendEnvLine(lines, "P/A Controller", client->GetPaperAirplaneController() ? "on" : "off");
#endif
    }

    if (NULLPTR != server) {
        if (std::shared_ptr<AppConfiguration> configuration = configuration_; NULLPTR != configuration) {
            AppendEnvLine(lines, "Public IP", configuration->ip.public_);
            AppendEnvLine(lines, "Interface IP", configuration->ip.interface_);

            // Server advertises its preferred/allowed scheduler mode; per-session
            // ordering is negotiated with each client (see OnMux). Show the
            // configured preferred mode here (not a per-session live value).
            ppp::string mux_mode_text = configuration->GetEffectiveMuxMode();
            if (configuration->mux.turbo) {
                mux_mode_text += "+turbo";
            }
            AppendEnvLine(lines, "Mux Mode", mux_mode_text);
        }

        using NAC = VirtualEthernetSwitcher::NetworkAcceptorCategories;
        const char* categories[] = { "ppp+tcp", "ppp+udp", "ppp+ws", "ppp+wss", "cdn+1", "cdn+2" };
        NAC category_values[] = {
            NAC::NetworkAcceptorCategories_Tcpip,
            NAC::NetworkAcceptorCategories_Udpip,
            NAC::NetworkAcceptorCategories_WebSocket,
            NAC::NetworkAcceptorCategories_WebSocketSSL,
            NAC::NetworkAcceptorCategories_CDN1,
            NAC::NetworkAcceptorCategories_CDN2,
        };

        for (int i = 0, service_index = 0; i < arraysizeof(categories); ++i) {
            boost::asio::ip::tcp::endpoint serverEP = server->GetLocalEndPoint(category_values[i]);
            if (serverEP.port() <= IPEndPoint::MinPort || serverEP.port() > IPEndPoint::MaxPort) {
                continue;
            }

            ppp::string service_name = "Service ";
            service_name += stl::to_string<ppp::string>(++service_index);
            service_name = ppp::PaddingRight<ppp::string>(service_name, 22u, ' ');
            service_name += ": ";
            service_name += IPEndPoint::ToEndPoint(serverEP).ToString();
            service_name += "/";
            service_name += categories[i];
            lines.emplace_back(std::move(service_name));
        }
    }

    AppendEnvLine(lines, "Hosting Environment", hosting_environment);
    lines.emplace_back(ppp::string());

#if !defined(_ANDROID) && !defined(_IPHONE)
    if (NULLPTR != client) {
        struct {
            std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> ni;
            const char* tab;
            bool tun;
        } stnis[] = {
            { client->GetTapNetworkInterface(), "TUN", true },
            { client->GetUnderlyingNetworkInterface(), "NIC", false },
        };

        for (const auto& sti : stnis) {
            auto ni = sti.ni;
            if (NULLPTR == ni) {
                continue;
            }

            lines.emplace_back(sti.tab);
            lines.emplace_back(section_separator);

#if defined(_WIN32)
            AppendEnvLine(lines, "Name", ni->Name + "[" + ni->Description + "]");
#else
            AppendEnvLine(lines, "Name", ni->Name);
#endif

            AppendEnvLine(lines, "Index", stl::to_string<ppp::string>(ni->Index));

#if !defined(_MACOS)
            if (!ni->Id.empty()) {
                AppendEnvLine(lines, "Id", ni->Id);
            }
#endif

            ppp::string interface_text;
            interface_text += Ipep::ToAddressString<ppp::string>(ni->IPAddress);
            interface_text += " ";
            interface_text += Ipep::ToAddressString<ppp::string>(ni->GatewayServer);
            interface_text += " ";
            interface_text += Ipep::ToAddressString<ppp::string>(ni->SubmaskAddress);
            AppendEnvLine(lines, "Interface", interface_text);

            if (sti.tun) {
                std::shared_ptr<aggligator::aggligator> aggligator = client->GetAggligator();
                if (NULLPTR != aggligator) {
                    const char* aggligator_states[] = { "none", "unknown", "connecting", "reconnecting", "established" };
                    int max_channel = 0;
                    int max_servers = 0;
                    aggligator->client_fetch_concurrency(max_servers, max_channel);

                    aggligator::aggligator::link_status status = aggligator->status();
                    int state_index = static_cast<int>(status);
                    if (0 > state_index || state_index >= arraysizeof(aggligator_states)) {
                        state_index = 1;
                    }

                    ppp::string aggligator_text = aggligator_states[state_index];
                    aggligator_text += ", ";
                    aggligator_text += stl::to_string<ppp::string>(max_servers);
                    aggligator_text += "-server, ";
                    aggligator_text += stl::to_string<ppp::string>(max_channel);
                    aggligator_text += "-channel";
                    AppendEnvLine(lines, "Aggligator", aggligator_text);
                } else {
                    AppendEnvLine(lines, "Aggligator", "none");
                }

                std::shared_ptr<ppp::transmissions::proxys::IForwarding> forwarding = client->GetForwarding();
                if (NULLPTR != forwarding) {
                    AppendEnvLine(lines, "Proxy Interlayer", forwarding->GetProxyUrl());
                } else {
                    AppendEnvLine(lines, "Proxy Interlayer", "none");
                }

                AppendEnvLine(lines, "TCP/IP CC",
                    client->IsLwip() ? "lwip" :
#ifdef SYSNAT
                    (client->IsSysnat() ? "tc" : "ctcp")
#else
                    "ctcp"
#endif
                );
                AppendEnvLine(lines, "Block QUIC", client->IsBlockQUIC() ? "blocked" : "unblocked");

                std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger();
                if (NULLPTR != exchanger) {
                    ppp::string mux_state;
                    if (client->IsMuxEnabled()) {
                        mux_state = ToNetworkStateString(exchanger->GetMuxNetworkState());
                        mux_state += ", ";
                        mux_state += stl::to_string<ppp::string>(client->Mux(NULLPTR));
                        mux_state += "-channel";

                        // Real-time scheduler mode in effect on the client (includes any
                        // runtime --mux-mode-set override). Turbo is shown when enabled.
                        if (NULLPTR != configuration_) {
                            mux_state += ", mode=";
                            mux_state += configuration_->GetEffectiveMuxMode();
                            if (configuration_->mux.turbo) {
                                mux_state += "+turbo";
                            }
                        }
                    } else {
                        mux_state = "none";
                    }

                    AppendEnvLine(lines, "Mux State", mux_state);
                    AppendEnvLine(lines, "Link State", ToNetworkStateString(exchanger->GetNetworkState()));
                } else {
                    AppendEnvLine(lines, "Mux State", "none");
                    AppendEnvLine(lines, "Link State", "none");
                }
            }

            /**
             * @brief Resolve a friendly label for a DNS server IP by matching
             *        against the application-level NetworkInterface labels.
             *
             * Labels were captured at GetDnsAddresses() time and may carry the
             * DoH/DoT hostname (e.g. "cloudflare-dns.com (DoH)"). When no label
             * is found we fall back to the literal IP rendering.
             */
            auto resolve_dns_label = [this](const boost::asio::ip::address& ip) noexcept -> ppp::string {
                if (NULLPTR == network_interface_) {
                    return ppp::string();
                }
                const std::size_t n = std::min(network_interface_->DnsAddresses.size(),
                                               network_interface_->DnsLabels.size());
                for (std::size_t k = 0; k < n; ++k) {
                    if (network_interface_->DnsAddresses[k] == ip) {
                        return network_interface_->DnsLabels[k];
                    }
                }
                return ppp::string();
            };

            for (std::size_t i = 0, l = ni->DnsAddresses.size(); i < l; ++i) {
                ppp::string dns_key = "DNS Server ";
                dns_key += stl::to_string<ppp::string>(i + 1u);
                dns_key = ppp::PaddingRight<ppp::string>(dns_key, 22u, ' ');
                dns_key += ": ";
                ppp::string label = sti.tun ? resolve_dns_label(ni->DnsAddresses[i]) : ppp::string();
                if (!label.empty()) {
                    dns_key += label;
                    dns_key += " [";
                    dns_key += Ipep::ToAddressString<ppp::string>(ni->DnsAddresses[i]);
                    dns_key += "]";
                } else {
                    dns_key += Ipep::ToAddressString<ppp::string>(ni->DnsAddresses[i]);
                }
                lines.emplace_back(std::move(dns_key));
            }

            lines.emplace_back(ppp::string());
        }
    }
#endif

    lines.emplace_back("VPN");
    lines.emplace_back(section_separator);
    AppendEnvLine(lines, "Duration", stopwatch_.Elapsed().ToString("TT:mm:ss", false));
    if (NULLPTR != server) {
        AppendEnvLine(lines, "Sessions", stl::to_string<ppp::string>(server->GetAllExchangerNumber()));
    }

    AppendEnvLine(lines, "TX", ppp::StrFormatByteSize(static_cast<Int64>(outgoing_traffic)));
    AppendEnvLine(lines, "RX", ppp::StrFormatByteSize(static_cast<Int64>(incoming_traffic)));
    if (NULLPTR != statistics_snapshot) {
        AppendEnvLine(lines, "IN", ppp::StrFormatByteSize(static_cast<Int64>(statistics_snapshot->IncomingTraffic.load())));
        AppendEnvLine(lines, "OUT", ppp::StrFormatByteSize(static_cast<Int64>(statistics_snapshot->OutgoingTraffic.load())));
    }

    /**
     * @brief Link Telemetry section — displayed in right column (two-column mode)
     * or appended after info lines (single-column mode).
     */
    ppp::vector<ppp::string> telemetry_lines;
    telemetry_lines.emplace_back("Link Telemetry");
    telemetry_lines.emplace_back(section_separator);

    {
        ppp::diagnostics::LinkTelemetry& lt = ppp::diagnostics::LinkTelemetryGlobal::GetInstance().GetTotal();
        ppp::diagnostics::LinkTelemetrySnapshot snap = lt.GetSnapshot();

        {
            char quality_buf[64];
            std::snprintf(quality_buf, sizeof(quality_buf), "%.2f%% %s",
                snap.quality_percent,
                ppp::diagnostics::LinkTelemetry::GetQualityGradeName(snap.grade));
            AppendEnvLine(telemetry_lines, "Quality", ppp::string(quality_buf));
        }

        AppendEnvLine(telemetry_lines, "Error Count",
            stl::to_string<ppp::string>(static_cast<Int64>(snap.error_count)));

        AppendEnvLine(telemetry_lines, "Success Count",
            stl::to_string<ppp::string>(static_cast<Int64>(snap.success_count)));

        AppendEnvLine(telemetry_lines, "Total Events",
            stl::to_string<ppp::string>(static_cast<Int64>(snap.total_count)));

        {
            double error_rate = 0.0;
            if (snap.success_count > 0) {
                error_rate = (static_cast<double>(snap.error_count) / static_cast<double>(snap.success_count)) * 100.0;
            } else if (snap.error_count > 0) {
                error_rate = 100.0;
            }
            char rate_buf[64];
            std::snprintf(rate_buf, sizeof(rate_buf), "%.2f%% (relative to OK)", error_rate);
            AppendEnvLine(telemetry_lines, "Error Rate", ppp::string(rate_buf));
        }

        if (snap.grade >= ppp::diagnostics::LinkQualityGrade::Good &&
            snap.grade != ppp::diagnostics::LinkQualityGrade::Unknown) {
            telemetry_lines.emplace_back("  !! Report to OPENPPP2 when quality <= 95%");
        }

        if (snap.grade == ppp::diagnostics::LinkQualityGrade::Unusable) {
            telemetry_lines.emplace_back("  !! CRITICAL: Quality < 90% - STOP OPENPPP2!");
        }
    }

    ConsoleUI::GetInstance().SetTelemetryLines(telemetry_lines);
}

/**
 * @brief Disposes active server/client switchers and clears periodic timers.
 */
void PppApplication::Dispose() noexcept {
    const ppp::app::runtime::RuntimeSnapshot runtime = runtime_lifecycle_.GetSnapshot();
    bool stop_owner = false;
    if (runtime.generation != 0) {
        if (!runtime_lifecycle_.TryBeginStop(
                runtime.generation, Executors::GetTickCount())) {
            return;
        }
        stop_owner = true;
    }

    ConsoleUI::GetInstance().Stop();
    auto complete_stop =
        [self = shared_from_this(), generation = runtime.generation](
            bool cleanup_success) noexcept {
            int error_code = static_cast<int>(ppp::diagnostics::GetLastErrorCode());
            if (!cleanup_success && error_code == 0) {
                error_code = static_cast<int>(
                    ppp::diagnostics::ErrorCode::RouteDeleteFailed);
            }
            ppp::app::runtime::RuntimeError error;
            error.code = static_cast<std::uint32_t>(std::max(0, error_code));
            error.severity = cleanup_success ? std::string() : "error";
            error.retryable = !cleanup_success;
            error.user_message_key = cleanup_success ? std::string() : "CleanupFailed";
            self->runtime_lifecycle_.CompleteStop(
                generation,
                cleanup_success,
                std::move(error),
                Executors::GetTickCount());
        };
    std::shared_ptr<VirtualEthernetSwitcher> server = std::move(server_);
    std::shared_ptr<VEthernetNetworkSwitcher> client = std::move(client_);
    const int teardown_count = (NULLPTR != server ? 1 : 0) + (NULLPTR != client ? 1 : 0);
    auto remaining = std::make_shared<std::atomic<int>>(teardown_count);
    auto cleanup_success = std::make_shared<std::atomic<bool>>(true);
    auto complete_one =
        [complete_stop, remaining, cleanup_success](bool success) noexcept {
            if (!success) {
                cleanup_success->store(false, std::memory_order_release);
            }
            if (remaining->fetch_sub(1, std::memory_order_acq_rel) == 1) {
                complete_stop(cleanup_success->load(std::memory_order_acquire));
            }
        };

    if (NULLPTR != server) {
        ppp::function<void()> completion;
        if (stop_owner) {
            completion = [complete_one]() noexcept { complete_one(true); };
        }
        server->Dispose(std::move(completion));
    }

    if (NULLPTR != client) {
#if defined(_WIN32)
        ppp::net::proxies::HttpProxy::SetSupportExperimentalQuicProtocol(quic_);
        if (network_interface_->SetHttpProxy) {
            client->ClearHttpProxyToSystemEnv();
        }
#endif
        ppp::function<void(bool)> completion;
        if (stop_owner) {
            completion = complete_one;
        }
        client->Dispose(std::move(completion));
    }

    ClearTickAlwaysTimeout();

    ppp::telemetry::Flush(3000);
    ppp::telemetry::Shutdown();

    if (stop_owner && teardown_count == 0) {
        complete_stop(true);
    }
}

/**
 * @brief Retrieves aggregated traffic counters and optional statistics snapshot.
 * @param incoming_traffic Receives inbound bytes.
 * @param outgoing_traffic Receives outbound bytes.
 * @param statistics_snapshot Receives snapshot object when available.
 * @return True when statistics are available and successfully sampled.
 */
bool PppApplication::GetTransmissionStatistics(
    uint64_t& incoming_traffic,
    uint64_t& outgoing_traffic,
    std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept {
    statistics_snapshot = NULLPTR;
    incoming_traffic = 0;
    outgoing_traffic = 0;

    std::shared_ptr<VirtualEthernetSwitcher> server = server_;
    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    if ((NULLPTR != server && !server->IsDisposed()) || (NULLPTR != client && !client->IsDisposed())) {
        std::shared_ptr<ppp::transmissions::ITransmissionStatistics> transmission_statistics;
        if (NULLPTR != client) {
            transmission_statistics = client->GetStatistics();
        } else if (NULLPTR != server) {
            transmission_statistics = server->GetStatistics();
        }

        if (NULLPTR != transmission_statistics) {
            return ppp::transmissions::ITransmissionStatistics::GetTransmissionStatistics(
                transmission_statistics,
                transmission_statistics_,
                incoming_traffic,
                outgoing_traffic,
                statistics_snapshot);
        }
    }

    return false;
}

/**
 * @brief Periodic runtime tick for restart policy and dynamic route refresh.
 * @param now Current monotonic tick in milliseconds.
 * @return True when loop remains healthy; false when no active client state exists.
 */
bool PppApplication::OnTick(uint64_t now) noexcept {
    using RouteIPListTablePtr = VEthernetNetworkSwitcher::RouteIPListTablePtr;
    using NetworkState = VEthernetExchanger::NetworkState;

    uint64_t incoming_traffic = 0;
    uint64_t outgoing_traffic = 0;

    acceptance_boundary_.RetryAcknowledgement();

    std::shared_ptr<ppp::transmissions::ITransmissionStatistics> statistics_snapshot;
    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    std::shared_ptr<VEthernetExchanger> exchanger = NULLPTR;
    if (NULLPTR != client) {
        exchanger = client->GetExchanger();
    }

    ppp::app::runtime::RuntimeSnapshot runtime = runtime_lifecycle_.GetSnapshot();
    if (runtime.generation != 0 && runtime.phase != ppp::app::runtime::RuntimePhase::Stopping) {
        VEthernetExchanger::RuntimeStateSnapshot exchanger_runtime;
        if (NULLPTR != exchanger) {
            exchanger_runtime = exchanger->GetRuntimeState();
            runtime_lifecycle_.UpdateMuxState(
                runtime.generation,
                exchanger->GetMuxRuntimeState(),
                now);
            runtime_lifecycle_.UpdateP2PState(
                runtime.generation,
                exchanger_runtime.p2p_state,
                now);
        }
        if (NULLPTR == client) {
            if (NULLPTR != server_ && !server_->IsDisposed()) {
                const ppp::app::runtime::RuntimeReadiness readiness =
                    ppp::app::runtime::BuildServerRuntimeReadiness(server_->IsRunning());
                runtime_lifecycle_.UpdateReadiness(runtime.generation, readiness, now);
                runtime_lifecycle_.Transition(
                    runtime.generation,
                    ppp::app::runtime::RuntimePhase::Connected,
                    now);
            }
        }
        else if (NULLPTR == exchanger) {
            runtime_lifecycle_.Transition(
                runtime.generation,
                ppp::app::runtime::RuntimePhase::Connecting,
                now);
        }
        else if (exchanger_runtime.network_state == NetworkState::NetworkState_Reconnecting) {
            runtime_lifecycle_.Transition(
                runtime.generation,
                ppp::app::runtime::RuntimePhase::Reconnecting,
                now);
        }
        else if (exchanger_runtime.network_state == NetworkState::NetworkState_Established) {
            if (runtime.phase != ppp::app::runtime::RuntimePhase::Connected &&
                runtime.phase != ppp::app::runtime::RuntimePhase::ApplyingPolicy) {
                runtime_lifecycle_.Transition(
                    runtime.generation,
                    ppp::app::runtime::RuntimePhase::ApplyingPolicy,
                    now);
            }
            runtime_lifecycle_.UpdateReadiness(
                runtime.generation,
                client->GetRuntimeReadiness(),
                now);
            runtime_lifecycle_.Transition(
                runtime.generation,
                ppp::app::runtime::RuntimePhase::Connected,
                now);
        }
        else {
            runtime_lifecycle_.Transition(
                runtime.generation,
                ppp::app::runtime::RuntimePhase::Handshaking,
                now);
        }
    }

    const bool has_transmission_statistics = GetTransmissionStatistics(
        incoming_traffic,
        outgoing_traffic,
        statistics_snapshot);
    if (!has_transmission_statistics) {
        incoming_traffic = 0;
        outgoing_traffic = 0;
    }

    if (runtime.generation != 0 && NULLPTR != statistics_snapshot) {
        ppp::app::runtime::RuntimeTraffic traffic;
        traffic.rx_bytes = statistics_snapshot->IncomingTraffic.load();
        traffic.tx_bytes = statistics_snapshot->OutgoingTraffic.load();
        runtime_lifecycle_.UpdateTraffic(runtime.generation, traffic, now);
    }

    runtime = runtime_lifecycle_.GetSnapshot();
    if (has_transmission_statistics && !stats_json_path_.empty()) {
        const ppp::diagnostics::LinkTelemetrySnapshot link =
            ppp::diagnostics::LinkTelemetryGlobal::GetInstance().GetTotal().GetSnapshot();
        ppp::app::runtime::RuntimeStatsSample sample;
        sample.monotonic_ms = now;
        sample.rx_bytes = incoming_traffic;
        sample.tx_bytes = outgoing_traffic;
        sample.link.quality_percent = link.quality_percent;
        sample.link.grade = RuntimeStatsGradeName(link.grade);
        sample.link.error_count = link.error_count;
        sample.link.success_count = link.success_count;
        sample.runtime = runtime;
        if (NULLPTR != client) {
            const char* tcp_stack = ppp::app::GetTcpStackModeName(client->GetTcpStackMode());
            sample.requested_tcp_stack = tcp_stack;
            sample.active_tcp_stack = tcp_stack;

            ppp::tap::TapRuntimeStats tap_stats;
            if (client->GetTapRuntimeStats(tap_stats)) {
                sample.has_tap_linux = true;
                sample.tap_linux = tap_stats;
            }

            ppp::app::runtime::RuntimeXtcpStats xtcp_stats;
            if (client->GetXtcpRuntimeStats(xtcp_stats)) {
                sample.has_xtcp = true;
                sample.xtcp = xtcp_stats;
            }
        }
        ppp::app::runtime::DatapathAcceptanceBoundaryRecord boundary;
        if (acceptance_boundary_.Poll(boundary)) {
            boundary.monotonic_ms = sample.monotonic_ms;
            boundary.xtcp_runtime_instance_id = sample.has_xtcp
                ? sample.xtcp.runtime_instance_id : 0;
            sample.has_acceptance_boundary = true;
            sample.acceptance_boundary = boundary;
        }
        if (WriteRuntimeStatsLine(stats_json_path_, sample) && sample.has_acceptance_boundary) {
            acceptance_boundary_.MarkStatsWritten(
                sample.monotonic_ms, sample.acceptance_boundary.xtcp_runtime_instance_id);
            acceptance_boundary_.RetryAcknowledgement();
        }
    }
    const std::vector<std::string> runtime_lines =
        ppp::app::tui::BuildStatusLines(runtime);
    ppp::string status = "vpn=";
    status += runtime_lines.empty() ? "Unknown" : runtime_lines.front().c_str();
    status += " rx=" + ppp::StrFormatByteSize((Int64)incoming_traffic);
    status += " tx=" + ppp::StrFormatByteSize((Int64)outgoing_traffic);

    {
        double quality = ppp::diagnostics::LinkTelemetryGlobal::GetInstance().GetTotal().GetQualityPercent();
        ppp::diagnostics::LinkQualityGrade grade = ppp::diagnostics::LinkTelemetry::ClassifyQuality(quality);
        char quality_buf[32];
        std::snprintf(quality_buf, sizeof(quality_buf), " link=%.1f%%", quality);
        status += quality_buf;
        status += " ";
        status += ppp::diagnostics::LinkTelemetry::GetQualityGradeName(grade);
    }

    ConsoleUI::GetInstance().UpdateStatus(status);

    ppp::vector<ppp::string> info;
    GetEnvironmentInformationLines(info, incoming_traffic, outgoing_traffic, statistics_snapshot);
    for (auto line = runtime_lines.rbegin(); line != runtime_lines.rend(); ++line) {
        info.insert(info.begin(), ppp::string(line->data(), line->size()));
    }
    ConsoleUI::GetInstance().SetInfoLines(info);

#if defined(_WIN32)
    ppp::win32::Win32Native::OptimizedProcessWorkingSize();
#endif

    if (GLOBAL_.auto_restart > 0) {
        int64_t elapsed_milliseconds = stopwatch_.ElapsedMilliseconds() / 1000;
        if (elapsed_milliseconds > 0 && elapsed_milliseconds >= GLOBAL_.auto_restart) {
            return ShutdownApplication(true);
        }
    }

    if (NULLPTR == client) {
        return false;
    }

    if (NULLPTR == exchanger) {
        return false;
    }

    NetworkState network_state = exchanger->GetNetworkState();
    if (network_state == NetworkState::NetworkState_Established) {
        if (GLOBAL_.link_restart > 0) {
            if (exchanger->GetReconnectionCount() >= GLOBAL_.link_restart) {
                return ShutdownApplication(true);
            }
        }
    } else {
        return false;
    }

    if (now >= GLOBAL_VIRR_NEXT.load(std::memory_order_relaxed)) {
        GLOBAL_VIRR_NEXT.store(now + (configuration_->virr.update_interval * 1000), std::memory_order_relaxed);
        if (GLOBAL_VIRR.load(std::memory_order_relaxed)) {
            PullIPList(GLOBAL_.virr_argument, true);
        }
    }

    if ((now - GLOBAL_VBGP_LAST.load(std::memory_order_relaxed)) / 1000 >= (uint64_t)configuration_->vbgp.update_interval) {
        GLOBAL_VBGP_LAST.store(now, std::memory_order_relaxed);
        if (RouteIPListTablePtr vbgp = client->GetVbgp(); GLOBAL_VBGP.load(std::memory_order_relaxed) && NULLPTR != vbgp) {

            /**
             * @brief Pulls each configured V-BGP list and restarts when file content changes.
             *
             * For every registered path/url pair, the callback compares downloaded routes
             * with on-disk content. A write of changed content triggers graceful restart.
             */
            for (auto&& kv : *vbgp) {
                const ppp::string& path = kv.first;
                const ppp::string& url = kv.second;
                PullIPList(url,
                    [path](int count, const ppp::set<ppp::string>& ips) noexcept {
                        if (count < 1) {
                            return -1;
                        }

                        ppp::set<ppp::string> olds;
                        ppp::string iplist = ppp::LTrim(ppp::RTrim(File::ReadAllText(path.data())));

                        chnroutes2_getiplist(olds, ppp::string(), iplist);
                        if (!chnroutes2_equals(ips, olds)) {
                            ppp::string news = chnroutes2_toiplist(ips);
                            if (File::WriteAllBytes(path.data(), news.data(), news.size())) {
                                ShutdownApplication(true);
                                return 1;
                            }
                        }

                        return 0;
                    });
            }
        }
    }

    return true;
}

#if defined(_WIN32)
/**
 * @brief Handles `--no-lsp` command to exclude process from LSP interception.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return True when command was present (whether successful or not), false otherwise.
 */
bool Windows_NoLsp(int argc, const char* argv[]) noexcept {
    char key[] = "--no-lsp";
    if (!ppp::HasCommandArgument(key, argc, argv)) {
        return false;
    }

    bool ok = false;
    ppp::diagnostics::ErrorCode error_code = ppp::diagnostics::ErrorCode::Success;
    do {
        ppp::string line = ppp::GetCommandArgument(argc, argv);
        if (line.empty()) {
            error_code = ppp::diagnostics::ErrorCode::AppInvalidCommandLine;
            break;
        }

        std::size_t index = line.find(key);
        if (index == ppp::string::npos) {
            error_code = ppp::diagnostics::ErrorCode::AppInvalidCommandLine;
            break;
        }

        line = line.substr(index + sizeof(key) - 1);
        if (line.empty()) {
            error_code = ppp::diagnostics::ErrorCode::AppInvalidCommandLine;
            break;
        }

        int ch = line[0];
        if (ch != '=' && ch != ' ') {
            error_code = ppp::diagnostics::ErrorCode::AppInvalidCommandLine;
            break;
        }

        line = ppp::RTrim(ppp::LTrim(line.substr(1)));
        if (line.empty()) {
            error_code = ppp::diagnostics::ErrorCode::AppInvalidCommandLine;
            break;
        }

        ok = ppp::app::client::lsp::PaperAirplaneController::NoLsp(line);
        if (!ok) {
            error_code = ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid;
        }
    } while (false);

    if (!ok) {
        ppp::diagnostics::SetLastErrorCode(error_code);
    }

    return true;
}

/**
 * @brief Handles Windows network utility command-line operations.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return True when a supported command was detected, false otherwise.
 */
bool Windows_PreferredNetwork(int argc, const char* argv[]) noexcept {
    bool ok = false;
    if (ppp::HasCommandArgument("--system-network-preferred-ipv4", argc, argv)) {
        ok = ppp::net::proxies::HttpProxy::PreferredNetwork(true);
    } else if (ppp::HasCommandArgument("--system-network-preferred-ipv6", argc, argv)) {
        ok = ppp::net::proxies::HttpProxy::PreferredNetwork(false);
    } else if (ppp::HasCommandArgument("--system-network-reset", argc, argv)) {
        ok = ppp::win32::network::ResetNetworkEnvironment();
    } else {
        return false;
    }

    if (!ok) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
    }

    return true;
}
#endif

} // namespace ppp::app
