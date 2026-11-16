#include <ppp/app/ApplicationClientBootstrap.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/PppApplicationInternal.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/udp/UdpFlowPolicy.h>
#include <ppp/app/client/ClientRoutingSources.h>
#include <ppp/app/client/GeoRuleGenerator.h>
#include <ppp/app/client/policy/LegacyPolicyAdapter.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/io/File.h>
#include <ppp/net/Ipep.h>
#include <ppp/tap/ITap.h>
#include <ppp/tap/TapStub.h>
#include <ppp/tap/TapUserspace.h>
#include <libtcpip/netstack.h>

#include <string>
#include <vector>

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
        ethernet = ppp::make_shared_object<client::VEthernetNetworkSwitcher>(context, network_interface->TcpStack, network_interface->VNet, configuration->concurrent > 1, configuration);
        if (NULLPTR == ethernet) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
            break;
        }
        const bool proxy_only_runtime = NormalizeClientProxyOnlyRuntime(
            proxy_mode, configuration->client.proxy_only);
        if (!ethernet->PreparePolicy(network_interface->IPAddress.is_v4()
                ? network_interface->IPAddress.to_v4().to_uint() : 0, proxy_only_runtime)) {
            break;
        }
        if (configuration->client.policy && !proxy_only_runtime && network_interface->IPAddress.is_v4() &&
            client::udp::UdpRelayIdentity::IsIdentity(network_interface->IPAddress.to_v4().to_uint())) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigPolicyUdpIdentityConflict);
            break;
        }
        if (proxy_mode && !configuration->client.proxy_only) {
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "client",
                "--mode=proxy overrides client.proxy-only=false; running in proxy-only mode");
        }

#if !defined(_ANDROID) && !defined(_IPHONE)
        bool proxy_subnet_userspace = false;
        if (proxy_only_runtime) {
            // Proxy-only never creates a host adapter. With virtual-subnet access on, the
            // in-process stack is the subnet member: peer packets addressed to the virtual IP
            // are handed to it, and its own packets re-enter the client path as adapter input
            // (relay or P2P).
            if (network_interface->ProxySubnet && network_interface->IPAddress.is_v4() &&
                network_interface->GatewayServer.is_v4() && network_interface->SubmaskAddress.is_v4()) {
                std::shared_ptr<ppp::tap::TapUserspace> userspace = ppp::tap::TapUserspace::Create(context,
                    htonl(network_interface->IPAddress.to_v4().to_uint()),
                    htonl(network_interface->GatewayServer.to_v4().to_uint()),
                    htonl(network_interface->SubmaskAddress.to_v4().to_uint()));
                if (NULLPTR != userspace) {
                    userspace->SetHostInput(
                        [](const void* packet, int packet_size) noexcept {
                            return lwip::netstack::input(packet, packet_size);
                        });
                    std::unordered_set<uint16_t> inbound_ports;
                    for (const auto& forward : network_interface->ProxyForwards) {
                        inbound_ports.insert(forward.first);
                    }
                    userspace->SetInboundTcpPorts(inbound_ports);
                    tap = userspace;
                    proxy_subnet_userspace = true;
                }
            }
            if (!proxy_subnet_userspace) {
                tap = ppp::tap::TapStub::Create(context);
            }
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
#if !defined(_ANDROID) && !defined(_IPHONE)
        ethernet->ProxySubnetUserspace(&proxy_subnet_userspace);
        if (proxy_subnet_userspace) {
            ethernet->ProxySubnetForwards(network_interface->ProxyForwards);
        }
        {
            bool proxy_internet = !proxy_only_runtime || network_interface->ProxyInternet;
            ethernet->ProxyInternet(&proxy_internet);
        }
#endif

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
#if !defined(_ANDROID) && !defined(_IPHONE)
        // The in-process subnet stack is a real subnet member, so an explicit --tun-ip is
        // honored; without one the address comes from the server pool.
        ethernet->ManualIPv4(network_interface->ManualIPv4 && (!proxy_only_runtime || proxy_subnet_userspace));
#else
        ethernet->ManualIPv4(network_interface->ManualIPv4 && !proxy_only_runtime);
#endif
        {
            bool proxy_only_flag = proxy_only_runtime;
            ethernet->ProxyOnly(&proxy_only_flag);
        }
#if !defined(_ANDROID) && !defined(_IPHONE)
        if (!proxy_only_runtime || proxy_subnet_userspace) {
            ethernet->PreferredNgw(network_interface->Ngw);
            ethernet->PreferredNic(network_interface->Nic);
        }
#endif

        if (!ethernet->HasPolicyV2()) {
            auto to_std = [](const ppp::string& value) {
                return std::string(value.data(), value.size());
            };
            client::policy::LegacyPolicyAdapterInput legacy_input;
            legacy_input.cli_dns_rules.push_back(to_std(network_interface->DNSRules));
#if defined(_LINUX)
            legacy_input.bypass_nic = to_std(network_interface->BypassNic);
#endif
            legacy_input.bypass_gateway = network_interface->BypassNgw.to_string();
            for (const auto& source : *network_interface->Bypass) {
                legacy_input.cli_bypass.push_back(to_std(source));
            }
            const auto legacy_policy = client::policy::LegacyPolicyAdapter::Adapt(*configuration, legacy_input);
            const bool canonical_routing_configured = legacy_policy.canonical_routing;
            const std::size_t legacy_cli_dns_order = legacy_input.cli_bypass.size();
            auto sources_for = [&legacy_policy](client::policy::LegacySourceRole role) {
                std::vector<const client::policy::LegacyPolicySource*> sources;
                for (const auto& source : legacy_policy.sources) {
                    if (source.role == role) sources.push_back(&source);
                }
                return sources;
            };

            // CLI --dns-rules is the legacy DNS source and is only active when
            // canonical routing is absent.  When client.routing is present its
            // dns.rules array is authoritative (canonical-wins).
            if (!canonical_routing_configured) {
                for (const auto* source : sources_for(client::policy::LegacySourceRole::DnsRules)) {
                    if (source->order != legacy_cli_dns_order ||
                        source->kind != client::policy::LegacySourceKind::File) continue;
                    ppp::string path(source->value.data(), source->value.size());
                    ppp::string text = File::ReadAllText(path.data());
                    text = ppp::LTrim(ppp::RTrim(text));
                    if (!text.empty()) ethernet->LoadAllDnsRules(path, true);
                }
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
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
                for (const auto* source : sources_for(client::policy::LegacySourceRole::Bypass)) {
                    if (source->kind == client::policy::LegacySourceKind::File) {
                        bypass_sources.emplace_back(source->value.data(), source->value.size());
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
                for (const auto* source : sources_for(client::policy::LegacySourceRole::Bypass)) {
                    if (source->kind != client::policy::LegacySourceKind::File) {
                        if (!inline_bypass_text.empty()) {
                            inline_bypass_text.push_back('\n');
                        }
                        inline_bypass_text.append(source->value.data(), source->value.size());
                        continue;
                    }

                    if (!inline_bypass_text.empty()) {
                        add_inline_bypass(inline_bypass_text);
                        inline_bypass_text.clear();
                    }
#if defined(_LINUX)
                    ethernet->AddLoadIPList(ppp::string(source->value.data(), source->value.size()), network_interface->BypassNic, network_interface->BypassNgw, ppp::string());
#else
                    ethernet->AddLoadIPList(ppp::string(source->value.data(), source->value.size()), network_interface->BypassNgw, ppp::string());
#endif
                }
                if (!inline_bypass_text.empty()) {
                    add_inline_bypass(inline_bypass_text);
                }
            }
            elif (!configuration->geo_rules.enabled) {
#if defined(_LINUX)
                for (const auto* source : sources_for(client::policy::LegacySourceRole::Bypass)) {
                    ethernet->AddLoadIPList(ppp::string(source->original.data(), source->original.size()), network_interface->BypassNic, network_interface->BypassNgw, ppp::string());
                }
#else
                for (const auto* source : sources_for(client::policy::LegacySourceRole::Bypass)) {
                    ethernet->AddLoadIPList(ppp::string(source->original.data(), source->original.size()), network_interface->BypassNgw, ppp::string());
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

            for (const auto* source : sources_for(client::policy::LegacySourceRole::DnsRules)) {
                if (!canonical_routing_configured && source->order == legacy_cli_dns_order) continue;
                ethernet->LoadAllDnsRules(ppp::string(source->value.data(), source->value.size()),
                    source->kind == client::policy::LegacySourceKind::File);
            }
#endif

        }
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
