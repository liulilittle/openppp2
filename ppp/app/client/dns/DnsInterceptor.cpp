#include "DnsInterceptor.h"

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/dns/DnsReachability.h>
#include <ppp/app/client/dns/DnsFakeIpResponse.h>
#include <ppp/app/client/dns/DnsRedirectPlan.h>
#include <ppp/app/client/dns/DnsResponseHandler.h>
#include <ppp/app/client/dns/HumanDnsQueryPolicy.h>
#include <ppp/app/client/dns/DnsRouteDispatcher.h>
#include <ppp/app/client/dns/DnsUdpRelay.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/dns/DnsResolver.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/vdns.h>
#if defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif
#include <ppp/ipv6/IPv6Auxiliary.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/tap/ITap.h>

#if defined(_ANDROID)
#include <android/OpenPPP2VpnProtectBridge.h>
#include <android/log.h>

static bool AndroidDnsRedirectTraceEnabled() noexcept {
#ifdef NDEBUG
    return false;
#else
    return true;
#endif
}

#define ANDROID_DNS_REDIRECT_TRACE(...) \
    do { \
        if (AndroidDnsRedirectTraceEnabled()) { \
            __android_log_print(ANDROID_LOG_INFO, "openppp2", __VA_ARGS__); \
        } \
    } while (0)
#endif

#include <common/dnslib/message.h>

using ppp::net::Ipep;
using ppp::net::IPEndPoint;
using ppp::tap::ITap;

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                static bool ParseStunCandidate(const ppp::string& s, ppp::dns::StunCandidate& out) noexcept {
                    ppp::string text = ATrim(s);
                    if (text.empty()) {
                        return false;
                    }

                    int port = 3478;
                    ppp::string host;
                    std::size_t colon = text.rfind(':');
                    if (colon != ppp::string::npos && colon > 0) {
                        host = text.substr(0, colon);
                        ppp::string port_str = text.substr(colon + 1);
                        int p = atoi(port_str.data());
                        if (p > 0 && p <= 65535) {
                            port = p;
                        }
                    }
                    else {
                        host = text;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::address ip = ppp::StringToAddress(host.data(), ec);
                    if (ec || ip.is_unspecified()) {
                        return false;
                    }

                    out.ip = ip;
                    out.port = port;
                    return true;
                }

                static bool ParseStunHostnameCandidate(
                    const ppp::string& s,
                    ppp::dns::StunHostnameCandidate& out) noexcept {

                    ppp::string text = ATrim(s);
                    if (text.empty()) {
                        return false;
                    }

                    out.port = 3478;
                    std::size_t colon = text.rfind(':');
                    if (colon != ppp::string::npos && colon > 0) {
                        out.hostname = text.substr(0, colon);
                        ppp::string port_str = text.substr(colon + 1);
                        int p = atoi(port_str.data());
                        if (p > 0 && p <= 65535) {
                            out.port = p;
                        }
                    }
                    else {
                        out.hostname = text;
                    }

                    if (out.hostname.empty()) {
                        return false;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::address ip = ppp::StringToAddress(out.hostname.data(), ec);
                    return ec || ip.is_unspecified();
                }

                static DnsQueryType ToPlanQueryType(::dns::RecordType type) noexcept {
                    return type == ::dns::RecordType::kAAAA ? DnsQueryType::kAAAA : DnsQueryType::kA;
                }

                static bool ReportHumanRoutingFailure(
                    const routing::HumanRoutingRules& rules) noexcept {
                    for (const routing::RoutingDiagnostic& diagnostic : rules.Diagnostics()) {
                        ppp::telemetry::Log(
                            ppp::telemetry::Level::kInfo,
                            "client",
                            "human routing policy load failed file=%s line=%zu reason=%s",
                            diagnostic.file.c_str(),
                            diagnostic.line,
                            diagnostic.reason.c_str());
                    }
                    return ppp::diagnostics::SetLastError(
                        ppp::diagnostics::ErrorCode::ConfigRouteLoadFailed);
                }

                bool DnsInterceptor::Open(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                    const std::shared_ptr<boost::asio::io_context>& context,
                    bool proxy_only
#if defined(_LINUX)
                    , const std::shared_ptr<ppp::net::ProtectorNetwork>& protect_network
#endif
                ) noexcept {
                    std::shared_ptr<const routing::HumanRoutingRules> human_rules;
                    if (NULLPTR != configuration && !configuration->routing.rules.empty()) {
                        std::shared_ptr<routing::HumanRoutingRules> loaded =
                            make_shared_object<routing::HumanRoutingRules>();
                        if (NULLPTR == loaded) {
                            return ppp::diagnostics::SetLastError(
                                ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        }
                        if (!loaded->LoadFile(configuration->routing.rules)) {
                            return ReportHumanRoutingFailure(*loaded);
                        }
                        if (!loaded->GeoDeclarations().empty()) {
                            routing::HumanGeoDataSources sources;
                            sources.geoip_dat = configuration->geo_rules.geoip_dat;
                            sources.geosite_dat = configuration->geo_rules.geosite_dat;
                            sources.geoip.assign(
                                configuration->geo_rules.geoip.begin(),
                                configuration->geo_rules.geoip.end());
                            sources.geosite.assign(
                                configuration->geo_rules.geosite.begin(),
                                configuration->geo_rules.geosite.end());
                            if (!loaded->CompileGeo(sources)) {
                                return ReportHumanRoutingFailure(*loaded);
                            }
                        }
                        human_rules = std::move(loaded);
                    }

                    const HumanDnsStartupMode startup_mode =
                        HumanDnsQueryPolicy::DecideStartup({
                            NULLPTR != configuration && configuration->dns.fake_ip.enabled,
                            human_rules && !human_rules->DomainRules().empty(),
                        });
                    std::shared_ptr<FakeIpPool> configured_fake_ip_pool;
                    if (startup_mode == HumanDnsStartupMode::FakeIp) {
                        configured_fake_ip_pool = make_shared_object<FakeIpPool>();
                        if (NULLPTR == configured_fake_ip_pool) {
                            return ppp::diagnostics::SetLastError(
                                ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        }
                        if (!configured_fake_ip_pool->Configure(
                                configuration->dns.fake_ip.range)) {
                            ppp::telemetry::Log(
                                ppp::telemetry::Level::kInfo,
                                "client",
                                "human routing policy load failed file=%s line=0 reason=invalid dns.fake-ip.range value=%s",
                                configuration->routing.rules.c_str(),
                                configuration->dns.fake_ip.range.c_str());
                            return ppp::diagnostics::SetLastError(
                                ppp::diagnostics::ErrorCode::ConfigFieldInvalid);
                        }
                    }

                    // In proxy-only mode the DNS rule table is active for native
                    // classification (routing.dns_rules still applies), but the
                    // DNS resolver that performs system DNS takeover is not started.
                    // configuration_, human_routing_rules_ and fake_ip_pool_ are
                    // stored so LoadRules and CollectReachabilityIps work correctly.
                    if (proxy_only || NULLPTR == context || NULLPTR == configuration) {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        configuration_ = configuration;
                        dns_resolver_.reset();
                        std::atomic_store(&human_routing_rules_, human_rules);
                        std::atomic_store(&fake_ip_pool_, configured_fake_ip_pool);
                        return true;
                    }

                    // Configure the resolver locally and publish the complete generation only
                    // after all policy, pool, and resolver validation has succeeded.
                    std::shared_ptr<ppp::dns::DnsResolver> resolver = make_shared_object<ppp::dns::DnsResolver>(*context);
                    if (NULLPTR == resolver) {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        configuration_ = configuration;
                        dns_resolver_.reset();
                        std::atomic_store(&human_routing_rules_, human_rules);
                        std::atomic_store(&fake_ip_pool_, configured_fake_ip_pool);
                        return true;
                    }
                    resolver->SetUdpFlowRegistry(udp_flow_registry_);

#if defined(_ANDROID)
                    resolver->SetProtectSocketCallback(
                        [](int handle) noexcept -> bool {
                            return ppp::android::ProtectSocketFd(handle);
                        });
#elif defined(_LINUX)
                    // Linux route policy installs explicit provider /32 routes. Binding every
                    // resolver socket to the physical NIC would override those routes.
                    (void)protect_network;
#endif

                    ppp::string domestic = configuration->dns.servers.domestic;
                    ppp::string foreign = configuration->dns.servers.foreign;
                    if (!domestic.empty() || !foreign.empty()) {
                        resolver->SetDefaultProviders(domestic, foreign);
                    }

                    resolver->SetEcsConfig(
                        configuration->dns.ecs.enabled,
                        configuration->dns.ecs.override_ip);
                    resolver->SetTlsVerifyPeer(configuration->dns.tls.verify_peer);

                    if (!configuration->dns.stun.candidates.empty()) {
                        ppp::vector<ppp::dns::StunCandidate> stun_cands;
                        ppp::vector<ppp::dns::StunHostnameCandidate> stun_host_cands;
                        for (const ppp::string& cs : configuration->dns.stun.candidates) {
                            ppp::dns::StunCandidate sc;
                            if (ParseStunCandidate(cs, sc)) {
                                stun_cands.emplace_back(std::move(sc));
                                continue;
                            }

                            ppp::dns::StunHostnameCandidate hc;
                            if (ParseStunHostnameCandidate(cs, hc)) {
                                stun_host_cands.emplace_back(std::move(hc));
                                continue;
                            }

                            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "client", "DNS STUN candidate ignored: %s", cs.c_str());
                        }
                        if (!stun_cands.empty()) {
                            resolver->SetStunCandidates(std::move(stun_cands));
                        }
                        if (!stun_host_cands.empty()) {
                            resolver->SetStunHostnameCandidates(std::move(stun_host_cands));
                        }
                    }

                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        configuration_ = configuration;
                        dns_resolver_ = std::move(resolver);
                        std::atomic_store(&human_routing_rules_, human_rules);
                        std::atomic_store(&fake_ip_pool_, configured_fake_ip_pool);
                    }
                    return true;
                }

                void DnsInterceptor::Close() noexcept {
                    std::shared_ptr<FakeIpPool> fake_ip_pool;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        std::atomic_store(
                            &human_routing_rules_,
                            std::shared_ptr<const routing::HumanRoutingRules>());
                        fake_ip_pool = std::atomic_exchange(
                            &fake_ip_pool_, std::shared_ptr<FakeIpPool>());
                        dns_resolver_.reset();
                        for (auto& table : dns_ruless_) {
                            table.clear();
                        }
                        configuration_.reset();
                    }
                    if (NULLPTR != fake_ip_pool) {
                        fake_ip_pool->Clear();
                    }
                }

                void DnsInterceptor::OnSessionInfo(
                    const ppp::app::protocol::VirtualEthernetInformationExtensions& extensions,
                    bool allow_ipv6_response) noexcept {
                    std::shared_ptr<ppp::dns::DnsResolver> resolver;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        resolver = dns_resolver_;
                    }
                    if (NULLPTR == resolver) {
                        return;
                    }

                    if (!extensions.ClientExitIP.is_unspecified()) {
                        resolver->SetExitIP(extensions.ClientExitIP);
                    }

                    resolver->SetAllowIPv6Response(allow_ipv6_response);
                }

                int DnsInterceptor::LoadRules(const ppp::string& rules, bool from_file) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    if (from_file) {
                        return Rule::LoadFile(rules, dns_ruless_[0], dns_ruless_[1], dns_ruless_[2]);
                    }
                    return Rule::Load(rules, dns_ruless_[0], dns_ruless_[1], dns_ruless_[2]);
                }

                void DnsInterceptor::CollectReachabilityIps(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                    bool intercept_unmatched,
                    const ppp::function<void(uint32_t)>& add_tunnel_ip,
                    const ppp::function<void(uint32_t)>& add_nic_ip) noexcept {

                    // Snapshot the rule tables under the lock; the reachability callbacks run unlocked.
                    RuleMap rule_tables[3];
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        for (int i = 0; i < 3; ++i) {
                            rule_tables[i] = dns_ruless_[i];
                        }
                    }

                    for (const auto& table : rule_tables) {
                        DnsReachability::CollectRuleTableReachabilityIps(table, add_tunnel_ip, add_nic_ip);
                    }

                    if (intercept_unmatched) {
                        DnsReachability::CollectInterceptReachabilityIps(configuration, add_tunnel_ip);
                    }
                }

                void DnsInterceptor::SetUdpFlowRegistry(
                    const std::shared_ptr<ppp::dns::DnsUdpFlowRegistry>& registry) noexcept {

                    udp_flow_registry_ = registry;
                    std::shared_ptr<ppp::dns::DnsResolver> resolver;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        resolver = dns_resolver_;
                    }
                    if (resolver) {
                        resolver->SetUdpFlowRegistry(registry);
                    }
                }

                static void ApplyFakeIpBackgroundResponse(
                    FakeIpPool& pool,
                    const ppp::string& hostname,
                    const ppp::vector<Byte>& response,
                    const std::shared_ptr<const routing::HumanRoutingRules>& human_rules) noexcept {

                    if (response.empty()) {
                        pool.SetResolveFailed(hostname);
                        return;
                    }

                    const uint32_t real_ip_host = DnsFakeIpResponse::ParseFirstARecordNetwork(
                        response.data(), static_cast<int>(response.size()));
                    if (real_ip_host == 0) {
                        pool.SetResolveFailed(hostname);
                        return;
                    }

                    routing::RoutingAction action = routing::RoutingAction::Auto;
                    if (human_rules) {
                        const routing::RoutingMatch match = human_rules->MatchIpv4Rule(real_ip_host);
                        action = match.matched ? match.action : human_rules->DefaultAction();
                    }
                    if (!pool.SetResolved(hostname, real_ip_host, action)) {
                        return;
                    }
                    ppp::net::asio::vdns::AddCache(
                        response.data(), static_cast<int>(response.size()));
                    ppp::telemetry::Count("dns.fake_ip.resolved", 1);
                }

                void DnsInterceptor::SpawnFakeIpBackgroundResolve(
                    const std::shared_ptr<FakeIpPool>& pool,
                    const std::shared_ptr<ppp::dns::DnsResolver>& resolver,
                    const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                    const DnsRedirectPlanResult& plan,
                    const Rule::Ptr& rule,
                    const ppp::string& hostname,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                    const std::shared_ptr<const routing::HumanRoutingRules>& human_rules) noexcept {

                    if (NULLPTR == pool) {
                        return;
                    }
                    if (NULLPTR == resolver || NULLPTR == configuration ||
                        NULLPTR == messages) {
                        pool->SetResolveFailed(hostname);
                        return;
                    }

                    auto callback =
                        [pool, hostname, human_rules](ppp::vector<Byte> response) noexcept {
                            ApplyFakeIpBackgroundResponse(*pool, hostname, response, human_rules);
                        };

                    switch (plan.action) {
                    case DnsRouteAction::kResolveProvider:
                        resolver->ResolveAsync(
                            plan.provider_name, plan.provider_domestic,
                            static_cast<const Byte*>(messages->Buffer.get()),
                            messages->Length,
                            callback);
                        return;

                    case DnsRouteAction::kResolveUnmatched:
                    case DnsRouteAction::kDeferToTunnel: {
                        ppp::vector<ppp::dns::ServerEntry> foreign_entries =
                            DnsReachability::BuildResolverEntries(configuration->dns.servers.foreign_entries);
                        if (!foreign_entries.empty()) {
                            resolver->ResolveAsyncWithEntries(
                                foreign_entries, false,
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length, callback);
                            return;
                        }

                        ppp::vector<ppp::dns::ServerEntry> domestic_entries =
                            DnsReachability::BuildResolverEntries(configuration->dns.servers.domestic_entries);
                        if (!domestic_entries.empty()) {
                            resolver->ResolveAsyncWithEntries(
                                domestic_entries, true,
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length, callback);
                            return;
                        }

                        resolver->ResolveAsyncWithFallback(
                            configuration->dns.servers.foreign,
                            configuration->dns.servers.domestic,
                            "cloudflare",
                            static_cast<const Byte*>(messages->Buffer.get()),
                            messages->Length,
                            callback);
                        return;
                    }

                    case DnsRouteAction::kUdpRelay:
                        if (NULLPTR != rule && !rule->ProviderName.empty()) {
                            resolver->ResolveAsync(
                                rule->ProviderName, rule->Nic,
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length,
                                callback);
                            return;
                        }

                        if (NULLPTR != rule && !rule->Server.is_unspecified()) {
                            ppp::dns::ServerEntry entry;
                            entry.protocol = ppp::dns::Protocol::UDP;
                            entry.address = rule->Server.to_string();
                            ppp::vector<ppp::dns::ServerEntry> entries;
                            entries.emplace_back(std::move(entry));
                            resolver->ResolveAsyncWithEntries(
                                entries, rule->Nic,
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length, callback);
                            return;
                        }
                        break;

                    default:
                        break;
                    }
                    pool->SetResolveFailed(hostname);
                }

                bool DnsInterceptor::HandleQuery(
                    const DnsQueryContext& context,
                    const std::shared_ptr<const DnsSessionContext>& session,
                    const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
                    const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept {

                    if (!context.IsValid()) {
                        return false;
                    }

                    ::dns::Message m;
                    if (m.decode(static_cast<uint8_t*>(messages->Buffer.get()), messages->Length) != ::dns::BufferResult::NoError) {
                        return false;
                    }
                    if (m.questions.empty()) {
                        return false;
                    }

                    boost::asio::ip::address destinationIP = Ipep::ToAddress(packet->Destination);
                    ::dns::QuestionSection& qs = *m.questions.data();

                    // Snapshot one complete runtime generation under the publication lock.
                    std::shared_ptr<ppp::dns::DnsResolver> resolver;
                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration;
                    std::shared_ptr<const routing::HumanRoutingRules> human_rules;
                    std::shared_ptr<FakeIpPool> fake_ip_pool;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        resolver = dns_resolver_;
                        configuration = configuration_;
                        human_rules = std::atomic_load(&human_routing_rules_);
                        fake_ip_pool = std::atomic_load(&fake_ip_pool_);
                    }
                    const ppp::string hostname_lower = stl::transform<ppp::string>(qs.mName);
                    routing::RoutingMatch domain_match;
                    if (human_rules) {
                        domain_match = human_rules->MatchDomainRule(hostname_lower);
                    }
                    const bool strict_human_match =
                        domain_match.matched &&
                        domain_match.action != routing::RoutingAction::Auto;
                    const bool is_a_query = qs.mType == ::dns::RecordType::kA;
                    const bool fake_ip_enabled =
                        fake_ip_pool && fake_ip_pool->IsEnabled();
                    const bool hostname_fake_eligible =
                        DnsFakeIpResponse::ShouldUseFakeIp(hostname_lower);
                    const HumanDnsQueryMode human_query_mode =
                        HumanDnsQueryPolicy::DecideQuery({
                            fake_ip_enabled,
                            strict_human_match,
                            is_a_query,
                            hostname_fake_eligible,
                            NULLPTR != configuration &&
                                configuration->routing.tcp_domain_sniff,
                        });
                    if (human_query_mode == HumanDnsQueryMode::Reject) {
                        ppp::telemetry::Count("dns.fake_ip.unavailable", 1);
                        return false;
                    }

                    if (qs.mType == ::dns::RecordType::kAAAA &&
                        (strict_human_match ||
                         (NULLPTR != resolver && !resolver->IsAllowIPv6Response()))) {
                        ppp::vector<Byte> synthesized = ppp::dns::DnsResolver::BuildAaaaBlockedResponse(
                            static_cast<const Byte*>(messages->Buffer.get()),
                            messages->Length);
                        if (!synthesized.empty()) {
                            ppp::telemetry::Count("dns.redirect.aaaa_blocked", 1);
                            return context.datagram_output(
                                IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source),
                                boost::asio::ip::udp::endpoint(destinationIP, PPP_DNS_SYS_PORT),
                                nullptr, synthesized.data(), static_cast<int>(synthesized.size()), false);
                        }
                    }

                    const bool human_fake_eligible =
                        human_rules && is_a_query && fake_ip_enabled &&
                        hostname_fake_eligible;
                    if (human_query_mode != HumanDnsQueryMode::ResolveReal &&
                        !human_fake_eligible &&
                        !ppp::net::asio::vdns::QueryCache2(
                            qs.mName.data(), m,
                            qs.mType == ::dns::RecordType::kA ?
                                ppp::net::asio::vdns::AddressFamily::kA :
                                ppp::net::asio::vdns::AddressFamily::kAAAA).empty()) {
                        std::size_t dns_size = 0;
                        char dns_packet[PPP_MAX_DNS_PACKET_BUFFER_SIZE];
                        if (m.encode(dns_packet, PPP_MAX_DNS_PACKET_BUFFER_SIZE, dns_size) == ::dns::BufferResult::NoError &&
                            dns_size > 0) {
                            return context.datagram_output(
                                IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source),
                                boost::asio::ip::udp::endpoint(destinationIP, PPP_DNS_SYS_PORT),
                                nullptr, dns_packet, static_cast<int>(dns_size), false);
                        }
                    }

                    DnsRedirectPlanInput plan_input;
                    plan_input.qtype = ToPlanQueryType(qs.mType);
                    plan_input.destination = destinationIP;
                    plan_input.intercept_unmatched =
                        NULLPTR != configuration && configuration->dns.intercept_unmatched;
                    plan_input.has_resolver = NULLPTR != resolver;
                    plan_input.allow_ipv6_response =
                        NULLPTR == resolver || resolver->IsAllowIPv6Response();
#if !defined(_ANDROID)
                    plan_input.defer_same_destination_to_tunnel = true;
#endif
                    if (domain_match.matched) {
                        plan_input.has_human_action = true;
                        plan_input.human_action = domain_match.action;
                        for (const routing::DnsProviderRule& provider : human_rules->DnsProviders()) {
                            if (provider.action == domain_match.action) {
                                plan_input.human_provider = provider.provider;
                                break;
                            }
                        }
                        if (plan_input.human_provider.empty() && configuration) {
                            plan_input.human_provider =
                                domain_match.action == routing::RoutingAction::Direct
                                    ? configuration->dns.servers.domestic
                                    : configuration->dns.servers.foreign;
                        }
                    }

                    if (std::shared_ptr<ITap> tap = context.tap; NULLPTR != tap) {
                        const uint32_t dest = packet->Destination;
                        const uint32_t gw = IPEndPoint::ToEndPoint(
                            IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(tap->GatewayServer, IPEndPoint::MinPort)).GetAddress();
                        const uint32_t mask = IPEndPoint::ToEndPoint(
                            IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(tap->SubmaskAddress, IPEndPoint::MinPort)).GetAddress();
                        plan_input.is_gateway_query =
                            DnsRedirectPlan::IsGatewayDnsServer(dest, gw, mask);
                    }

                    if (!domain_match.matched) {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        plan_input.rule = Rule::Get(
                            hostname_lower,
                            dns_ruless_[0], dns_ruless_[1], dns_ruless_[2]);
                    }

                    if (plan_input.is_gateway_query) {
                        auto dnsServers = std::atomic_load(&ppp::net::asio::vdns::servers);
                        plan_input.gateway_upstream_available =
                            NULLPTR != dnsServers && !dnsServers->empty();
                        if (plan_input.gateway_upstream_available) {
                            plan_input.gateway_upstream = dnsServers->begin()->address();
                        }
                    }

                    const DnsRedirectPlanResult plan = DnsRedirectPlan::Decide(plan_input);

                    const bool passthrough =
                        plan.action == DnsRouteAction::kUdpRelay &&
                        NULLPTR == plan_input.rule &&
                        !plan_input.is_gateway_query &&
                        !plan_input.intercept_unmatched;

                    const bool should_attempt_fake =
                        plan.action != DnsRouteAction::kDrop &&
                        is_a_query && fake_ip_enabled && hostname_fake_eligible &&
                        (human_query_mode == HumanDnsQueryMode::AttemptFake ||
                         (human_query_mode == HumanDnsQueryMode::Continue &&
                          (domain_match.matched || !passthrough)));
                    bool fake_allocation_succeeded = false;
                    bool fake_response_built = false;
                    if (should_attempt_fake) {
                        const routing::RoutingAction initial_action = domain_match.matched
                            ? domain_match.action
                            : routing::RoutingAction::Auto;
                        const FakeIpPool::AllocationResult allocation = fake_ip_pool->Allocate(
                            hostname_lower, initial_action, domain_match.matched);
                        fake_allocation_succeeded = allocation.entry.fake_ip_host != 0;
                        if (fake_allocation_succeeded) {
                            ppp::vector<Byte> fake_response = DnsFakeIpResponse::BuildARecordResponse(
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length,
                                allocation.entry.fake_ip_host);
                            fake_response_built = !fake_response.empty();
                            if (fake_response_built) {
                                const boost::asio::ip::udp::endpoint sourceEP =
                                    IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                                const boost::asio::ip::udp::endpoint destEP(destinationIP, PPP_DNS_SYS_PORT);
                                ppp::telemetry::Count("dns.fake_ip.allocated", 1);
                                context.datagram_output(
                                    sourceEP, destEP,
                                    nullptr, fake_response.data(), static_cast<int>(fake_response.size()), false);
                                if (allocation.should_resolve) {
                                    SpawnFakeIpBackgroundResolve(
                                        fake_ip_pool, resolver, configuration, plan,
                                        plan_input.rule, hostname_lower, messages, human_rules);
                                }
                                return true;
                            }
                            if (allocation.should_resolve) {
                                fake_ip_pool->SetResolveFailed(hostname_lower);
                            }
                        }
                    }

                    if (human_query_mode == HumanDnsQueryMode::AttemptFake &&
                        plan.action != DnsRouteAction::kDrop &&
                        HumanDnsQueryPolicy::DecideFakeAttempt(
                            fake_allocation_succeeded,
                            fake_response_built) == HumanDnsFakeAttemptResult::Reject) {
                        ppp::telemetry::Count("dns.fake_ip.allocation_failed", 1);
                        return false;
                    }

                    const boost::asio::ip::udp::endpoint sourceEP =
                        IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                    const boost::asio::ip::udp::endpoint destEP(destinationIP, PPP_DNS_SYS_PORT);

                    DnsRouteDispatcherPorts dispatch_ports;
                    dispatch_ports.drop = []() noexcept { return false; };
                    dispatch_ports.defer_to_tunnel = [&]() noexcept {
                        context.handle_resolver_response(messages, sourceEP, destEP, ppp::vector<Byte>{});
                        return true;
                    };
                    dispatch_ports.udp_relay = [&](const boost::asio::ip::address& relay_target) noexcept {
                        const bool use_underlying_nic =
                            NULLPTR != plan_input.rule && plan_input.rule->Nic;
                        return DnsUdpRelay::Spawn(
                            context, session, packet, frame, messages, relay_target, destinationIP,
                            use_underlying_nic);
                    };
                    dispatch_ports.resolve_unmatched = [&]() noexcept {
                        auto callback =
                            [resolver, context, sourceEP, destEP, messages, packet](ppp::vector<Byte> response) noexcept {
                                (void)resolver;
                                (void)packet;
                                context.handle_resolver_response(messages, sourceEP, destEP, std::move(response));
                            };

                        ppp::vector<ppp::dns::ServerEntry> foreign_entries =
                            DnsReachability::BuildResolverEntries(configuration->dns.servers.foreign_entries);
                        if (!foreign_entries.empty()) {
                            resolver->ResolveAsyncWithEntries(
                                foreign_entries, false,
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length, callback);
                            return true;
                        }

                        ppp::vector<ppp::dns::ServerEntry> domestic_entries =
                            DnsReachability::BuildResolverEntries(configuration->dns.servers.domestic_entries);
                        if (!domestic_entries.empty()) {
                            resolver->ResolveAsyncWithEntries(
                                domestic_entries, true,
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length, callback);
                            return true;
                        }

                        resolver->ResolveAsyncWithFallback(
                            configuration->dns.servers.foreign,
                            configuration->dns.servers.domestic,
                            "cloudflare",
                            static_cast<const Byte*>(messages->Buffer.get()),
                            messages->Length,
                            callback);
                        return true;
                    };
                    dispatch_ports.resolve_provider = [&](const ppp::string& provider_name, bool domestic) noexcept {
                        resolver->ResolveAsync(
                            provider_name, domestic,
                            static_cast<const Byte*>(messages->Buffer.get()),
                            messages->Length,
                            [resolver, context, sourceEP, destEP, messages, packet](ppp::vector<Byte> response) noexcept {
                                (void)resolver;
                                (void)packet;
                                context.handle_resolver_response(messages, sourceEP, destEP, std::move(response));
                            });
                        return true;
                    };

                    return DnsRouteDispatcher::Dispatch(plan, dispatch_ports);
                }

                boost::asio::ip::address DnsInterceptor::RewriteFakeIpAddress(
                    const boost::asio::ip::address& address) const noexcept {
                    if (!address.is_v4()) {
                        return address;
                    }
                    const std::shared_ptr<const FakeIpPool> pool = GetFakeIpPool();
                    if (!pool || !pool->IsEnabled()) {
                        return address;
                    }
                    const uint32_t real_host =
                        pool->LookupRealIpHostOrder(address.to_v4().to_uint());
                    return real_host == 0
                        ? address
                        : boost::asio::ip::address_v4(real_host);
                }

                std::shared_ptr<const routing::HumanRoutingRules>
                DnsInterceptor::GetHumanRoutingRules() const noexcept {
                    return std::atomic_load(&human_routing_rules_);
                }

                bool DnsInterceptor::ResolveDestination(
                    const ppp::net::IPEndPoint& endpoint,
                    routing::ResolvedDestination& destination) const noexcept {
                    destination = routing::ResolvedDestination{};
                    destination.original_endpoint = endpoint;
                    destination.connect_endpoint = endpoint;
                    if (endpoint.GetAddressFamily() != ppp::net::AddressFamily::InterNetwork) {
                        return true;
                    }

                    const uint32_t address_host = ntohl(endpoint.GetAddress());
                    std::shared_ptr<const FakeIpPool> pool;
                    std::shared_ptr<const routing::HumanRoutingRules> human_rules;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        pool = std::atomic_load(&fake_ip_pool_);
                        human_rules = std::atomic_load(&human_routing_rules_);
                    }
                    if (pool && pool->IsEnabled() && pool->ContainsHostOrder(address_host)) {
                        destination.is_fake_ip = true;
                        FakeIpPool::EntrySnapshot entry;
                        if (!pool->Lookup(address_host, entry) || !entry.is_resolved) {
                            destination.is_resolved = false;
                            return true;
                        }
                        destination.hostname = entry.hostname;
                        destination.action = entry.action;
                        destination.connect_endpoint = ppp::net::IPEndPoint(
                            htonl(entry.real_ip_host), endpoint.Port);
                        return true;
                    }

                    if (human_rules) {
                        const routing::RoutingMatch match = human_rules->MatchIpv4Rule(address_host);
                        destination.action = match.matched
                            ? match.action
                            : human_rules->DefaultAction();
                    }
                    return true;
                }

                bool DnsInterceptor::GetFakeIpRoute(
                    uint32_t& network, int& prefix) const noexcept {
                    const std::shared_ptr<const FakeIpPool> pool = GetFakeIpPool();
                    return pool && pool->GetRoute(network, prefix);
                }

            }
        }
    }
}
