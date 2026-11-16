#include <ppp/app/client/policy/LegacyPolicyAdapter.h>

#include <ppp/app/client/ClientRoutingSources.h>
#include <ppp/Filesystem.h>
#include <boost/asio/ip/address_v4.hpp>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace ppp::app::client::policy {
namespace {
namespace routing = ppp::app::client::routing;

std::string Std(const ppp::string& value) {
    return std::string(value.data(), value.size());
}

LegacySourceKind Classify(const ppp::string& raw, std::string& value) {
    const auto source = ppp::app::client::ParseClientRoutingSource(raw);
    value.assign(source.value.data(), source.value.size());
    if (source.IsFile()) return LegacySourceKind::File;
    const auto trimmed = ppp::LTrim(ppp::RTrim(raw));
    if (trimmed.size() >= 7 && ppp::ToLower<ppp::string>(trimmed.substr(0, 7)) == "file://")
        return LegacySourceKind::MissingFileInline;
    return LegacySourceKind::Inline;
}

void AddSources(LegacyPolicyModel& model, LegacySourceRole role,
    const std::vector<std::string>& values, std::size_t& order) {
    for (const auto& raw : values) {
        ppp::string value(raw.data(), raw.size());
        std::string normalized;
        const auto kind = Classify(value, normalized);
        model.sources.push_back({ role, kind, order++, raw, std::move(normalized) });
        if (kind == LegacySourceKind::MissingFileInline)
            model.differences.emplace_back("missing file:// source is interpreted as inline text by the legacy loader");
    }
}

void AddSources(LegacyPolicyModel& model, LegacySourceRole role,
    const ppp::vector<ppp::string>& values, std::size_t& order) {
    std::vector<std::string> copy;
    copy.reserve(values.size());
    for (const auto& value : values) copy.emplace_back(value.data(), value.size());
    AddSources(model, role, copy, order);
}

void AddRoutes(LegacyPolicyModel& model,
    const ppp::vector<ppp::configurations::AppConfiguration::RouteConfiguration>& routes, bool peer_routes) {
    for (const auto& route : routes) {
        LegacyPolicyRoute item;
        item.path.assign(route.path.data(), route.path.size());
#if defined(_LINUX)
        item.nic.assign(route.nic.data(), route.nic.size());
#endif
        item.gateway = std::to_string(route.ngw);
        item.peer.assign(route.vbgp.data(), route.vbgp.size());
        item.peer_route = peer_routes;
        model.routes.emplace_back(std::move(item));
    }
}

void AddPeerRoutes(LegacyPolicyModel& model,
    const ppp::vector<ppp::configurations::AppConfiguration::PeerPrefixRouteConfiguration>& routes) {
    for (const auto& route : routes) {
        LegacyPolicyRoute item;
        item.path = std::string(route.network.data(), route.network.size()) + "/" + std::to_string(route.prefix);
        item.gateway.assign(route.via.data(), route.via.size());
        item.peer.assign(route.guid.data(), route.guid.size());
        item.peer_route = true;
        model.routes.emplace_back(std::move(item));
    }
}

std::string ReadText(const std::string& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return {};
    std::ostringstream bytes;
    bytes << stream.rdbuf();
    return stream.bad() ? std::string() : bytes.str();
}

} // namespace

LegacyPolicyModel LegacyPolicyAdapter::Adapt(const ppp::configurations::AppConfiguration& configuration,
    const LegacyPolicyAdapterInput& input) {
    LegacyPolicyModel model;
    model.canonical_routing = configuration.client.routing.configured;
    model.proxy_only = configuration.client.proxy_only;
    model.fake_ip_enabled = configuration.dns.fake_ip.enabled;
    model.fake_ip_range.assign(configuration.dns.fake_ip.range.data(), configuration.dns.fake_ip.range.size());
    model.geo_enabled = configuration.geo_rules.enabled;
    model.geo_generates_files = configuration.geo_rules.enabled &&
        (!configuration.geo_rules.output_bypass.empty() || !configuration.geo_rules.output_dns_rules.empty());
    model.dns_cache_enabled = configuration.udp.dns.cache;
    model.dns_intercept_unmatched = configuration.dns.intercept_unmatched;
    model.ecs_enabled = configuration.dns.ecs.enabled;
    model.ecs_override_ip.assign(configuration.dns.ecs.override_ip.data(), configuration.dns.ecs.override_ip.size());
    model.domestic_dns.assign(configuration.dns.servers.domestic.data(), configuration.dns.servers.domestic.size());
    model.foreign_dns.assign(configuration.dns.servers.foreign.data(), configuration.dns.servers.foreign.size());
    model.bypass_nic = input.bypass_nic;
    model.bypass_gateway = input.bypass_gateway;

    std::size_t order = 0;
    if (model.canonical_routing) {
        AddSources(model, LegacySourceRole::Bypass, configuration.client.routing.bypass, order);
        AddSources(model, LegacySourceRole::DnsRules, configuration.client.routing.dns_rules, order);
        AddRoutes(model, configuration.client.routing.routes, false);
        AddPeerRoutes(model, configuration.client.routing.peer_routes);
    } else {
        AddSources(model, LegacySourceRole::Bypass, input.cli_bypass, order);
        AddSources(model, LegacySourceRole::DnsRules, input.cli_dns_rules, order);
        AddSources(model, LegacySourceRole::DnsRules, configuration.client.routing.dns_rules, order);
        AddRoutes(model, configuration.client.routes, false);
        AddPeerRoutes(model, configuration.client.peer_routes);
    }

    std::vector<std::string> geoip;
    for (const auto& value : configuration.geo_rules.geoip) geoip.emplace_back(value.data(), value.size());
    std::vector<std::string> geosite;
    for (const auto& value : configuration.geo_rules.geosite) geosite.emplace_back(value.data(), value.size());
    AddSources(model, LegacySourceRole::GeoIp, geoip, order);
    AddSources(model, LegacySourceRole::GeoSite, geosite, order);

    for (const auto& source : model.sources) {
        if (source.role != LegacySourceRole::DnsRules) continue;
        using RuleMap = ppp::unordered_map<ppp::string, ppp::app::client::dns::Rule::Ptr>;
        RuleMap suffix, exact, regexp;
        ppp::string value(source.value.data(), source.value.size());
        const int loaded = source.kind == LegacySourceKind::File
            ? ppp::app::client::dns::Rule::LoadFile(value, suffix, exact, regexp)
            : ppp::app::client::dns::Rule::Load(value, suffix, exact, regexp);
        if (!loaded && suffix.empty() && exact.empty() && regexp.empty() && source.kind == LegacySourceKind::File) {
            model.issues.push_back({ "legacy_dns_rules_unavailable", source.original, 0,
                "The legacy DNS rules file could not be read or contained no rules." });
        }
        auto record = [&](const RuleMap& entries, LegacyDnsRule::PatternKind kind) {
            for (const auto& pair : entries) {
                if (!pair.second) continue;
                LegacyDnsRule item;
                item.source_kind = source.kind;
                item.source_order = source.order;
                item.pattern_kind = kind;
                item.pattern.assign(pair.second->Host.data(), pair.second->Host.size());
                item.provider.assign(pair.second->ProviderName.data(), pair.second->ProviderName.size());
                item.server = pair.second->Server.to_string();
                item.nic_or_domestic = pair.second->Nic;
                model.dns_rules.emplace_back(std::move(item));
            }
        };
        record(suffix, LegacyDnsRule::PatternKind::Suffix);
        record(exact, LegacyDnsRule::PatternKind::Exact);
        record(regexp, LegacyDnsRule::PatternKind::Regexp);
    }

    const std::string human_path(configuration.routing.rules.data(), configuration.routing.rules.size());
    if (!human_path.empty()) {
        ppp::string raw = ppp::io::File::RewritePath(configuration.routing.rules.data());
        ppp::string path = ppp::io::File::GetFullPath(raw.data());
        ppp::filesystem::error_code ec;
        const bool exists = !path.empty() && ppp::filesystem::fs::is_regular_file(path.data(), ec);
        model.sources.push_back({ LegacySourceRole::HumanRules,
            exists ? LegacySourceKind::File : LegacySourceKind::UnavailableFile,
            order++, human_path, path.empty() ? human_path : Std(path) });
        if (!exists) {
            model.issues.push_back({ "legacy_human_rules_unavailable", human_path, 0,
                "The legacy routing.rules field is a file path and does not exist." });
        } else {
            const auto content = ReadText(path.data());
            model.human_rules_text = content;
            if (content.empty()) {
                model.issues.push_back({ "legacy_human_rules_unavailable", Std(path), 0,
                    "The legacy routing.rules file is empty or unreadable." });
            } else {
                routing::HumanRoutingRules rules;
                if (rules.LoadText(content, path.data())) {
                    model.default_action = rules.DefaultAction();
                    model.domain_rules = rules.DomainRules();
                    model.ipv4_rules = rules.Ipv4Cidrs();
                    model.dns_providers = rules.DnsProviders();
                } else {
                    for (const auto& diagnostic : rules.Diagnostics()) {
                        model.issues.push_back({ "legacy_human_rules_invalid", diagnostic.file,
                            diagnostic.line, diagnostic.reason });
                    }
                }
            }
        }
    }

    if (model.default_action == routing::RoutingAction::Auto)
        model.differences.emplace_back("legacy default auto/native fallback has no v2 direct/proxy equivalent");
    if (model.geo_enabled || model.geo_generates_files)
        model.differences.emplace_back("legacy Geo generation or platform projection has side effects outside a v2 rules file");
    if (model.fake_ip_enabled)
        model.differences.emplace_back("legacy global Fake-IP mode and cache identity differ from policy-scoped Fake-IP");
    if (!model.dns_providers.empty())
        model.differences.emplace_back("legacy DNS provider rules, ECS, and NIC semantics are not equivalent to v2 resolver bindings");
    if (!model.dns_rules.empty())
        model.differences.emplace_back("legacy DNS rule overrides have not been translated to v2 resolver exceptions");
    if (model.dns_cache_enabled)
        model.differences.emplace_back("legacy DNS cache is global and does not partition entries by policy version or resolver");
    if (model.ecs_enabled || !model.ecs_override_ip.empty())
        model.differences.emplace_back("legacy ECS behavior is not represented by v2 policy resolver semantics");
    if ((!model.domestic_dns.empty() && model.domestic_dns != "doh.pub") ||
        (!model.foreign_dns.empty() && model.foreign_dns != "cloudflare"))
        model.differences.emplace_back("legacy global domestic/foreign DNS defaults must be reviewed when selecting v2 resolvers");
    if (!model.bypass_nic.empty() || !model.bypass_gateway.empty())
        model.differences.emplace_back("CLI NIC/gateway override changes legacy bypass routing and has no v2 host-rule equivalent");
    for (const auto& route : model.routes) {
        if (!route.nic.empty() || route.gateway != "0" || !route.peer.empty()) {
            model.differences.emplace_back("legacy NIC, gateway, or peer route projection cannot be represented by v2 host rules");
            break;
        }
    }
    return model;
}

} // namespace ppp::app::client::policy
