#include <ppp/app/ApplicationClientBootstrap.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/PppApplicationInternal.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/ClientRoutingSources.h>
#include <ppp/app/client/GeoRuleGenerator.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/io/File.h>
#include <ppp/net/Ipep.h>
#include <ppp/tap/ITap.h>
#include <ppp/tap/TapStub.h>

namespace ppp::app {

bool PrepareClientLoopbackEnvironment(
    const std::shared_ptr<NetworkInterface>& network_interface,
    const std::shared_ptr<AppConfiguration>& configuration,
    const std::shared_ptr<boost::asio::io_context>& context,
    bool proxy_mode,
    std::shared_ptr<client::VEthernetNetworkSwitcher>& client_out) noexcept {

    client_out.reset();
    std::shared_ptr<client::VEthernetNetworkSwitcher> ethernet = NULLPTR;
    std::shared_ptr<ITap> tap = NULLPTR;
    bool success = false;

    do {
        const bool proxy_only_runtime = NormalizeClientProxyOnlyRuntime(
            proxy_mode, configuration->client.proxy_only);
        if (proxy_mode && !configuration->client.proxy_only) {
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "client",
                "--mode=proxy overrides client.proxy-only=false; running in proxy-only mode");
        }

#if !defined(_ANDROID) && !defined(_IPHONE)
        if (proxy_only_runtime) {
            tap = ppp::tap::TapStub::Create(context);
        }
        else {
#endif
#if defined(_WIN32)
        tap = ITap::Create(context,
            network_interface->ComponentId,
            Ipep::ToAddressString<ppp::string>(network_interface->IPAddress),
            Ipep::ToAddressString<ppp::string>(network_interface->GatewayServer),
            Ipep::ToAddressString<ppp::string>(network_interface->SubmaskAddress),
            network_interface->LeaseTimeInSeconds,
            network_interface->HostedNetwork,
            Ipep::AddressesTransformToStrings(network_interface->DnsAddresses));
#else
        tap = ITap::Create(context,
            network_interface->ComponentId,
            Ipep::ToAddressString<ppp::string>(network_interface->IPAddress),
            Ipep::ToAddressString<ppp::string>(network_interface->GatewayServer),
            Ipep::ToAddressString<ppp::string>(network_interface->SubmaskAddress),
            network_interface->Promisc,
            network_interface->HostedNetwork,
            Ipep::AddressesTransformToStrings(network_interface->DnsAddresses));
#endif
#if !defined(_ANDROID) && !defined(_IPHONE)
        }
#endif
        if (NULLPTR == tap) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
            break;
        }

        tap->BufferAllocator = configuration->GetBufferAllocator();
        if (!tap->Open()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelListenFailed);
            break;
        }

        ethernet = ppp::make_shared_object<client::VEthernetNetworkSwitcher>(context, network_interface->TcpStack, network_interface->VNet, configuration->concurrent > 1, configuration);
        if (NULLPTR == ethernet) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
            break;
        }
        if (network_interface->IPv6Address.is_v6()) {
            std::string requested_ipv6_std = network_interface->IPv6Address.to_string();
            ethernet->RequestedIPv6(ppp::string(requested_ipv6_std.data(), requested_ipv6_std.size()));
        }

#if !defined(_WIN32)
        ethernet->Ssmt(&network_interface->Ssmt);
#if defined(_LINUX)
        ethernet->SsmtMQ(&network_interface->SsmtMQ);
#if !defined(_ANDROID) && !defined(_IPHONE)
        ethernet->ProtectMode(&network_interface->ProtectNetwork);
#endif
#endif
#endif
        ethernet->Mux(&network_interface->Mux);
        ethernet->MuxAcceleration(&network_interface->MuxAcceleration);
        bool static_mode = NormalizeClientStaticMode(network_interface->StaticMode, proxy_only_runtime);
        ethernet->StaticMode(&static_mode);
        {
            bool proxy_only_flag = proxy_only_runtime;
            ethernet->ProxyOnly(&proxy_only_flag);
        }
#if !defined(_ANDROID) && !defined(_IPHONE)
        if (!proxy_only_runtime) {
            ethernet->PreferredNgw(network_interface->Ngw);
            ethernet->PreferredNic(network_interface->Nic);
        }
#endif

        const bool canonical_routing_configured = configuration->client.routing.configured;

        // CLI --dns-rules is the legacy DNS source and is only active when
        // canonical routing is absent.  When client.routing is present its
        // dns.rules array is authoritative (canonical-wins).
        if (!canonical_routing_configured && !network_interface->DNSRules.empty()) {
            ppp::string dns_rules_path = File::GetFullPath(File::RewritePath(network_interface->DNSRules.data()).data());
            if (!dns_rules_path.empty() && File::Exists(dns_rules_path.data())) {
                ppp::string dns_rules_text = File::ReadAllText(dns_rules_path.data());
                dns_rules_text = ppp::LTrim(ppp::RTrim(dns_rules_text));
                if (!dns_rules_text.empty()) {
                    ethernet->LoadAllDnsRules(dns_rules_path, true);
                }
            }
        }

#if !defined(_ANDROID) && !defined(_IPHONE)
        const auto canonical_bypass_sources = ppp::app::client::ParseClientRoutingSources(
            configuration->client.routing.bypass);
        ppp::string inline_bypass_text;
        auto add_inline_bypass = [&ethernet, &network_interface](const ppp::string& text) noexcept {
#if defined(_LINUX)
            ethernet->AddLoadIPListText(text, network_interface->BypassNic, network_interface->BypassNgw);
#else
            ethernet->AddLoadIPListText(text, network_interface->BypassNgw);
#endif
        };

        if (configuration->geo_rules.enabled) {
            ppp::vector<ppp::string> bypass_sources;
            if (canonical_routing_configured) {
                for (const auto& source : canonical_bypass_sources) {
                    if (source.IsFile()) {
                        bypass_sources.emplace_back(source.value);
                    }
                }
            }
            else {
                for (const auto& bypass_path : *network_interface->Bypass) {
                    const auto source = ppp::app::client::ParseClientRoutingSource(bypass_path);
                    if (source.IsFile()) {
                        bypass_sources.emplace_back(source.value);
                    }
                }
            }

            auto geo_result = ppp::app::client::GeoRuleGenerator::Generate(*configuration, &bypass_sources);
            if (!geo_result.output_bypass_path.empty()) {
#if defined(_LINUX)
                ethernet->AddLoadIPList(geo_result.output_bypass_path, network_interface->BypassNic, network_interface->BypassNgw, ppp::string());
#else
                ethernet->AddLoadIPList(geo_result.output_bypass_path, network_interface->BypassNgw, ppp::string());
#endif
            }
            if (!geo_result.output_dns_rules_path.empty()) {
                ethernet->LoadAllDnsRules(geo_result.output_dns_rules_path, true);
            }
        }

        if (canonical_routing_configured) {
            for (const auto& source : canonical_bypass_sources) {
                if (source.IsInline()) {
                    if (!inline_bypass_text.empty()) {
                        inline_bypass_text.push_back('\n');
                    }
                    inline_bypass_text.append(source.value);
                    continue;
                }

                if (!inline_bypass_text.empty()) {
                    add_inline_bypass(inline_bypass_text);
                    inline_bypass_text.clear();
                }
#if defined(_LINUX)
                ethernet->AddLoadIPList(source.value, network_interface->BypassNic, network_interface->BypassNgw, ppp::string());
#else
                ethernet->AddLoadIPList(source.value, network_interface->BypassNgw, ppp::string());
#endif
            }
            if (!inline_bypass_text.empty()) {
                add_inline_bypass(inline_bypass_text);
            }
        }
        elif (!configuration->geo_rules.enabled) {
#if defined(_LINUX)
            for (const auto& bypass_path : *network_interface->Bypass) {
                ethernet->AddLoadIPList(bypass_path, network_interface->BypassNic, network_interface->BypassNgw, ppp::string());
            }
#else
            for (const auto& bypass_path : *network_interface->Bypass) {
                ethernet->AddLoadIPList(bypass_path, network_interface->BypassNgw, ppp::string());
            }
#endif
        }

        // Load canonical ip.routes sources when client.routing is present.
        // This is the authoritative path; the legacy client.routes block below
        // is skipped in this case to avoid double-loading the mirrored entries.
        if (canonical_routing_configured) {
            for (auto&& route : configuration->client.routing.routes) {
                ppp::string path = File::GetFullPath(File::RewritePath(route.path.data()).data());
                if (path.empty()) {
                    continue;
                }
#if defined(_LINUX)
                ethernet->AddLoadIPList(path, route.nic, Ipep::ToAddress(route.ngw), route.vbgp);
#else
                ethernet->AddLoadIPList(path, Ipep::ToAddress(route.ngw), route.vbgp);
#endif
            }
        }

        // When canonical routing is present, routes are already loaded above
        // via configuration->client.routing.routes (mirrored to client.routes
        // during load).  Iterating client.routes again would double-load the
        // same entries into the native RIB/FIB.
        if (!canonical_routing_configured) {
            for (auto&& route : configuration->client.routes) {
                ppp::string path = File::GetFullPath(File::RewritePath(route.path.data()).data());
                if (path.empty()) {
                    continue;
                }

#if defined(_LINUX)
                ethernet->AddLoadIPList(path, route.nic, Ipep::ToAddress(route.ngw), route.vbgp);
#else
                ethernet->AddLoadIPList(path, Ipep::ToAddress(route.ngw), route.vbgp);
#endif
            }
        }

        const auto canonical_dns_sources = ppp::app::client::ParseClientRoutingSources(
            configuration->client.routing.dns_rules);
        for (const auto& source : canonical_dns_sources) {
            ethernet->LoadAllDnsRules(source.value, source.IsFile());
        }
#endif

        if (!ethernet->Open(tap)) {
#if !defined(_ANDROID) && !defined(_IPHONE)
            auto ni = ethernet->GetUnderlyingNetworkInterface();
#else
            auto ni = NULLPTR;
#endif
            if (NULLPTR != ni) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
            } else {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
            }
            break;
        }

        success = true;
        client_out = ethernet;
    } while (false);

    if (!success) {
        client_out.reset();
        if (NULLPTR != ethernet) {
            std::shared_ptr<ppp::tap::ITap> failed_tap = std::move(tap);
            ethernet->Dispose(
                [failed_tap](bool) noexcept {
                    if (NULLPTR != failed_tap) {
                        failed_tap->Dispose();
                    }
                });
        }
        elif (NULLPTR != tap) {
            tap->Dispose();
        }
    }

    return success;
}

} // namespace ppp::app
