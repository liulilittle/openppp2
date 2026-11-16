#include "LegacyPolicyMigration.h"
#include <ppp/Filesystem.h>

#include "PolicyEvaluator.h"

#include <ppp/dns/DnsProviderCatalog.h>

#include <algorithm>
#include <set>
#include <tuple>
#include <sstream>

namespace ppp::app::client::policy {
namespace {
namespace routing = ppp::app::client::routing;

Json::String JsonString(const std::string& value) {
    return Json::String(value.data(), value.size());
}

const char* Action(routing::RoutingAction action) {
    switch (action) {
    case routing::RoutingAction::Direct: return "direct";
    case routing::RoutingAction::Proxy: return "proxy";
    default: return "reject";
    }
}

bool Same(PolicyAction next, routing::RoutingAction old) {
    return (next == PolicyAction::Direct && old == routing::RoutingAction::Direct) ||
        (next == PolicyAction::Proxy && old == routing::RoutingAction::Proxy);
}

std::string ResolverName(const std::string& configured, const char* fallback) {
    if (!configured.empty()) {
        const ppp::string value(configured.data(), configured.size());
        // Policy resolvers only use DoH/DoT, so plain-DNS-only providers cannot carry over.
        if (ppp::dns::DnsProviderCatalog::HasEncryptedEndpoint(value)) return configured;
    }
    return fallback;
}

std::string RuleValue(const routing::DomainRule& rule) {
    switch (rule.type) {
    case routing::DomainMatchType::Exact: return "=" + rule.domain;
    case routing::DomainMatchType::Subdomain: return "*." + rule.domain;
    case routing::DomainMatchType::Regexp: return "regexp:" + rule.domain;
    default: return rule.domain;
    }
}

using HostRuleKey = std::tuple<int, std::string, int>;

bool HostSourceKindsSupported(const LegacyPolicyModel& legacy, bool& routing_inputs_supported) {
    for (const auto& source : legacy.sources) {
        switch (source.role) {
        case LegacySourceRole::HumanRules:
            if (source.kind != LegacySourceKind::File) return false;
            break;
        case LegacySourceRole::DnsRules:
            break;
        case LegacySourceRole::Bypass:
        case LegacySourceRole::GeoIp:
        case LegacySourceRole::GeoSite:
            routing_inputs_supported = false;
            return false;
        }
        if (source.kind == LegacySourceKind::MissingFileInline ||
            source.kind == LegacySourceKind::UnavailableFile) {
            return false;
        }
    }
    return true;
}

bool HostRuleSetsMatch(const LegacyPolicyModel& legacy, const PolicySnapshot& snapshot) {
    std::set<HostRuleKey> expected;
    std::set<HostRuleKey> actual;
    auto action = [](routing::RoutingAction value) -> int {
        if (value == routing::RoutingAction::Direct) return static_cast<int>(PolicyAction::Direct);
        if (value == routing::RoutingAction::Proxy) return static_cast<int>(PolicyAction::Proxy);
        return -1;
    };
    auto policy_action = [](PolicyAction value) -> int {
        return value == PolicyAction::Direct || value == PolicyAction::Proxy
            ? static_cast<int>(value) : -1;
    };
    for (const auto& rule : legacy.domain_rules) {
        if (rule.origin != routing::RuleOrigin::Explicit || action(rule.action) < 0 ||
            rule.type == routing::DomainMatchType::Regexp) return false;
        int condition = rule.type == routing::DomainMatchType::Exact ? static_cast<int>(PolicyCondition::Exact) :
            rule.type == routing::DomainMatchType::Subdomain ? static_cast<int>(PolicyCondition::Subdomain) :
            static_cast<int>(PolicyCondition::Suffix);
        expected.emplace(condition, rule.domain, action(rule.action));
    }
    for (const auto& rule : legacy.ipv4_rules) {
        if (rule.origin != routing::RuleOrigin::Explicit || action(rule.action) < 0) return false;
        expected.emplace(static_cast<int>(PolicyCondition::Ipv4Cidr), rule.cidr, action(rule.action));
    }
    for (const auto& rule : snapshot.Rules()) {
        if (!rule.resolver.empty()) continue;
        if (rule.origin != PolicyOrigin::Explicit || policy_action(rule.action) < 0 ||
            (rule.condition != PolicyCondition::Exact && rule.condition != PolicyCondition::Suffix &&
             rule.condition != PolicyCondition::Subdomain && rule.condition != PolicyCondition::Ipv4Cidr)) return false;
        actual.emplace(static_cast<int>(rule.condition), rule.value, policy_action(rule.action));
    }
    return expected == actual;
}

void AddReason(Json::Value& report, const std::string& code, const std::string& message,
    const std::string& source = {}, std::size_t line = 0) {
    Json::Value item(Json::objectValue);
    item["code"] = JsonString(code);
    item["message"] = JsonString(message);
    item["source"] = JsonString(source);
    item["line"] = Json::UInt64(line);
    report["diagnostics"].append(std::move(item));
}

} // namespace

LegacyPolicyMigrationResult LegacyPolicyMigration::CreateDraft(const LegacyPolicyModel& legacy,
    const std::string& output_config_path, const std::string& runtime, const std::string& platform) {
    LegacyPolicyMigrationResult result;
    result.report["schema"] = 1;
    result.report["status"] = "draft";
    result.report["routing_equivalence"] = "unverified";
    result.report["host_routing_equivalence"] = "unverified";
    result.report["incomplete"] = true;
    result.report["diagnostics"] = Json::Value(Json::arrayValue);

    bool representable = legacy.issues.empty();
    bool routing_supported = legacy.issues.empty();
    bool routing_inputs_supported = legacy.routes.empty();
    const bool default_supported = legacy.default_action == routing::RoutingAction::Direct ||
        legacy.default_action == routing::RoutingAction::Proxy;
    if (!default_supported) {
        representable = false;
        AddReason(result.report, "E_MIGRATE_DEFAULT_AUTO",
            "Legacy default auto/native fallback has no v2 equivalent; the draft uses reject until an action is selected.");
    }
    for (const auto& issue : legacy.issues) {
        representable = false;
        AddReason(result.report, issue.code, issue.message, issue.source, issue.line);
    }
    std::string local_provider = ResolverName(legacy.domestic_dns, "doh.pub");
    std::string remote_provider = ResolverName(legacy.foreign_dns, "cloudflare");
    for (const auto& binding : legacy.dns_providers) {
        const auto value = ResolverName(binding.provider,
            binding.action == routing::RoutingAction::Direct ? "doh.pub" : "cloudflare");
        if (binding.action == routing::RoutingAction::Direct) local_provider = value;
        else if (binding.action == routing::RoutingAction::Proxy) remote_provider = value;
    }
    if (legacy.geo_enabled || legacy.geo_generates_files) {
        representable = false;
        AddReason(result.report, "E_MIGRATE_GEO_SIDE_EFFECT",
            "Geo-generated bypass/DNS files need an explicit materialized rule-set selection.");
    }
    auto known_provider = [](const std::string& provider) {
        if (provider.empty()) return true;
        const ppp::string value(provider.data(), provider.size());
        return ppp::dns::DnsProviderCatalog::HasProvider(value);
    };
    if (!known_provider(legacy.domestic_dns) || !known_provider(legacy.foreign_dns)) {
        representable = false;
        AddReason(result.report, "E_MIGRATE_DNS_PROVIDER",
            "A legacy DNS provider is not in the built-in catalog; select an explicit v2 resolver.");
    }
    auto plain_only = [](const std::string& provider) {
        if (provider.empty()) return false;
        const ppp::string value(provider.data(), provider.size());
        return ppp::dns::DnsProviderCatalog::HasProvider(value) &&
            !ppp::dns::DnsProviderCatalog::HasEncryptedEndpoint(value);
    };
    bool substituted = plain_only(legacy.domestic_dns) || plain_only(legacy.foreign_dns);
    for (const auto& binding : legacy.dns_providers) substituted = substituted || plain_only(binding.provider);
    if (substituted) {
        representable = false;
        AddReason(result.report, "E_MIGRATE_DNS_PROVIDER",
            "A legacy DNS provider offers only plain DNS; policy resolvers need DoH/DoT, so the draft uses doh.pub/cloudflare instead.");
    }
    for (const auto& binding : legacy.dns_providers) {
        if (!known_provider(binding.provider)) {
            representable = false;
            AddReason(result.report, "E_MIGRATE_DNS_PROVIDER",
                "A legacy rule selects an unknown DNS provider; select an explicit v2 resolver.",
                "legacy-routing.rules", binding.line);
        }
    }
    if (!legacy.routes.empty()) {
        representable = false;
        AddReason(result.report, "E_MIGRATE_ROUTE_PROJECTION",
            "Legacy route imports, NIC, gateway, or peer route projection cannot be represented by host rules.");
    }
    if (legacy.fake_ip_enabled || legacy.dns_cache_enabled || legacy.ecs_enabled ||
        !legacy.ecs_override_ip.empty() || !legacy.domestic_dns.empty() || !legacy.foreign_dns.empty()) {
        if (legacy.fake_ip_enabled || legacy.dns_cache_enabled || legacy.ecs_enabled || !legacy.ecs_override_ip.empty()) {
            representable = false;
            AddReason(result.report, "E_MIGRATE_DNS_RUNTIME",
                "Legacy Fake-IP, cache, or ECS behavior differs from policy-scoped v2 DNS.");
        }
    }
    for (const auto& source : legacy.sources) {
        if (source.role == LegacySourceRole::Bypass || source.role == LegacySourceRole::GeoIp ||
            source.role == LegacySourceRole::GeoSite || source.kind == LegacySourceKind::MissingFileInline ||
            source.kind == LegacySourceKind::UnavailableFile) {
            representable = false;
            AddReason(result.report, "E_MIGRATE_SOURCE_REVIEW",
                "Legacy source must be materialized and reviewed before it can be included in v2 semantics.", source.original);
        }
    }

    const auto fallback = default_supported ? Action(legacy.default_action) : "reject";
    std::ostringstream rules;
    rules << "default " << fallback << "\n"
        << "dns direct local\n"
        << "dns proxy remote\n";
    std::vector<std::string> direct, proxy, reject;
    for (const auto& rule : legacy.domain_rules) {
        if (rule.type == routing::DomainMatchType::Regexp || rule.origin != routing::RuleOrigin::Explicit ||
            (rule.action != routing::RoutingAction::Direct && rule.action != routing::RoutingAction::Proxy)) {
            routing_supported = false;
            if (rule.type == routing::DomainMatchType::Regexp)
                AddReason(result.report, "E_MIGRATE_REGEX_PRECEDENCE",
                    "Legacy regular-expression precedence depends on source order and overlapping matches.",
                    "legacy-routing.rules", rule.line);
            else
                AddReason(result.report, "E_MIGRATE_RULE_UNSUPPORTED",
                    "Only explicit direct/proxy host rules can be structurally compared.",
                    "legacy-routing.rules", rule.line);
        }
        auto& target = rule.action == routing::RoutingAction::Direct ? direct :
            rule.action == routing::RoutingAction::Proxy ? proxy : reject;
        target.push_back(RuleValue(rule));
    }
    for (const auto& rule : legacy.ipv4_rules) {
        if (rule.origin != routing::RuleOrigin::Explicit ||
            (rule.action != routing::RoutingAction::Direct && rule.action != routing::RoutingAction::Proxy)) {
            routing_supported = false;
            AddReason(result.report, "E_MIGRATE_RULE_UNSUPPORTED",
                "Only explicit direct/proxy IPv4 CIDR rules can be structurally compared.",
                "legacy-routing.rules", rule.line);
        }
        auto& target = rule.action == routing::RoutingAction::Direct ? direct :
            rule.action == routing::RoutingAction::Proxy ? proxy : reject;
        target.push_back(rule.cidr);
    }
    if (!direct.empty()) {
        rules << "[direct]\n";
        for (const auto& value : direct) rules << value << '\n';
    }
    if (!proxy.empty()) {
        rules << "[proxy]\n";
        for (const auto& value : proxy) rules << value << '\n';
    }
    if (!reject.empty()) {
        rules << "[reject]\n";
        for (const auto& value : reject) rules << value << '\n';
    }
    result.rules_text = rules.str();

    PolicySource source;
    source.config_path = ppp::filesystem::fs::absolute(output_config_path).lexically_normal().string();
    source.base_path = ppp::filesystem::fs::path(source.config_path).parent_path().string();
    source.rules_path = (ppp::filesystem::fs::path(source.base_path) / "routing.rules").string();
    source.rules_text = result.rules_text;
    source.dns_mode = "real";
    source.fake_ip_identity = "migration-draft";
    source.resolvers["local"] = { PolicyAction::Direct, { local_provider } };
    source.resolvers["remote"] = { PolicyAction::Proxy, { remote_provider } };
    auto compiled = PolicyCompiler::Compile(source);
    bool compiled_ok = compiled.Ok();
    for (const auto& diagnostic : compiled.diagnostics) {
        if (diagnostic.severity == "error") {
            compiled_ok = false;
            AddReason(result.report, diagnostic.code, diagnostic.message, diagnostic.file, diagnostic.line);
        }
    }

    bool source_kinds_supported = HostSourceKindsSupported(legacy, routing_inputs_supported) && legacy.routes.empty();
    if (!source_kinds_supported) {
        routing_supported = false;
        AddReason(result.report, "E_MIGRATE_HOST_SOURCE_UNSUPPORTED",
            "Host-routing equivalence requires only checked HumanRules sources and no legacy bypass or Geo projection.");
    }
    bool evaluator_match = compiled_ok && default_supported && routing_supported && source_kinds_supported &&
        HostRuleSetsMatch(legacy, *compiled.snapshot);
    if (evaluator_match && !legacy.human_rules_text.empty()) {
        routing::HumanRoutingRules old_rules;
        evaluator_match = old_rules.LoadText(legacy.human_rules_text, "legacy-routing.rules");
        std::vector<std::string> domains{"unmatched-migration-probe.invalid"};
        for (const auto& item : legacy.domain_rules) {
            if (item.type == routing::DomainMatchType::Exact) domains.push_back(item.domain);
            else if (item.type == routing::DomainMatchType::Regexp) continue;
            else {
                domains.push_back(item.domain);
                domains.emplace_back("probe." + item.domain);
                domains.emplace_back("deep.probe." + item.domain);
            }
        }
        for (const auto& domain : domains) {
            const auto before = old_rules.MatchDomain(domain);
            const auto after = PolicyEvaluator::Evaluate(*compiled.snapshot, domain).action;
            evaluator_match = evaluator_match && Same(after, before);
        }
        for (const auto& item : legacy.ipv4_rules) {
            const auto before = old_rules.MatchIpv4(item.network);
            boost::asio::ip::address_v4 address(item.network);
            const auto after = PolicyEvaluator::Evaluate(*compiled.snapshot, {}, address.to_string()).action;
            evaluator_match = evaluator_match && Same(after, before);
        }
    }
    if (compiled_ok && evaluator_match) {
        result.routing_equivalent = routing_inputs_supported;
        result.report["routing_equivalence"] = routing_inputs_supported ? "equivalent" : "partial";
        result.report["host_routing_equivalence"] = routing_inputs_supported ? "equivalent" : "partial";
        result.report["routing_equivalence_evidence"] = "complete normalized selector-set equality; only explicit exact/suffix/subdomain and IPv4 CIDR rules; legacy and v2 priorities agree for those classes; evaluator probes are regression evidence";
        if (!representable)
            AddReason(result.report, "W_MIGRATE_ROUTING_ONLY",
                "The legacy human host rules match the compiled v2 evaluator, while other routing/DNS inputs remain draft.");
    } else {
        result.report["routing_equivalence"] = "unverified";
        result.report["host_routing_equivalence"] = "unverified";
        result.report["routing_equivalence_evidence"] = "full selector-set, source, action, and priority preconditions were not satisfied; matching finite probes cannot establish equivalence";
        AddReason(result.report, "E_MIGRATE_EVALUATOR_DIFFERENCE",
            "Legacy and v2 host selectors could not be proven equivalent as complete sets.");
    }

    Json::Value policy(Json::objectValue);
    policy["version"] = 2;
    policy["rules"]["path"] = "routing.rules";
    policy["ipv6"] = "block";
    policy["dns"]["mode"] = "real";
    policy["dns"]["resolvers"]["local"]["via"] = "direct";
    policy["dns"]["resolvers"]["local"]["servers"].append(local_provider.c_str());
    policy["dns"]["resolvers"]["remote"]["via"] = "proxy";
    policy["dns"]["resolvers"]["remote"]["servers"].append(remote_provider.c_str());
    result.policy_config["client"]["policy"] = policy;
    result.report["resolver_selection"] = Json::Value(Json::objectValue);
    result.report["resolver_selection"]["local"] = JsonString(local_provider);
    result.report["resolver_selection"]["remote"] = JsonString(remote_provider);
    bool no_non_host_inputs = legacy.routes.empty() && !legacy.geo_enabled && !legacy.geo_generates_files &&
        legacy.bypass_nic.empty() && legacy.bypass_gateway.empty() && !legacy.proxy_only;
    for (const auto& source : legacy.sources) {
        if (source.role == LegacySourceRole::Bypass || source.role == LegacySourceRole::GeoIp ||
            source.role == LegacySourceRole::GeoSite || source.role == LegacySourceRole::DnsRules ||
            source.kind == LegacySourceKind::MissingFileInline || source.kind == LegacySourceKind::UnavailableFile)
            no_non_host_inputs = false;
    }
    const bool known_dns_defaults = legacy.domestic_dns == "doh.pub" &&
        legacy.foreign_dns == "cloudflare" && legacy.dns_intercept_unmatched &&
        legacy.dns_rules.empty() && legacy.dns_providers.empty();
    const bool runtime_known = (runtime == "tun" || runtime == "http" || runtime == "socks") &&
        (platform == "linux" || platform == "windows" || platform == "macos" ||
         platform == "android" || platform == "ios");
    // The adapter does not carry enough evidence to compare resolver cache policy,
    // actual DNS egress, or legacy IPv6/AAAA behavior with the v2 runtime.
    const bool whole_path_proven = false;
    result.complete = result.routing_equivalent && no_non_host_inputs && known_dns_defaults &&
        !legacy.fake_ip_enabled && !legacy.dns_cache_enabled && !legacy.ecs_enabled &&
        legacy.ecs_override_ip.empty() && runtime_known && legacy.issues.empty() && whole_path_proven;
    result.report["whole_policy_equivalence"] = result.complete ? "equivalent" : "draft";
    result.report["whole_equivalence_evidence"] = result.complete
        ? "host selector proof; built-in DNS defaults; cache, Fake-IP, ECS, Geo, routes, and unsupported sources absent; runtime/platform selected"
        : "host selectors may be proven, but the legacy model does not establish cache parity, actual DNS egress, or IPv6/AAAA behavior required for whole-policy equivalence";
    if (!known_dns_defaults)
        AddReason(result.report, "W_MIGRATE_DNS_EXIT_REVIEW",
            "DNS upstreams, interception, provider rules, or resolver exit differ from the built-in local/remote mapping.");
    if (runtime.empty() || platform.empty())
        AddReason(result.report, "W_MIGRATE_RUNTIME_SELECTION",
            "Select --runtime and --platform before whole-policy equivalence can be assessed.");
    else if (!runtime_known)
        AddReason(result.report, "E_MIGRATE_RUNTIME_UNSUPPORTED",
            "The selected runtime/platform pair is not in the supported equivalence matrix.");
    if (!legacy.dns_intercept_unmatched)
        AddReason(result.report, "W_MIGRATE_DNS_INTERCEPTION",
            "Legacy unmatched DNS requests bypass interception; the generated policy routes them through its configured resolver.");
    if (!legacy.dns_rules.empty() || !legacy.dns_providers.empty())
        AddReason(result.report, "W_MIGRATE_DNS_RULES",
            "Legacy DNS rules or provider bindings are not represented by the generated resolver policy.");
    if (!legacy.bypass_nic.empty() || !legacy.bypass_gateway.empty())
        AddReason(result.report, "W_MIGRATE_NIC_GATEWAY",
            "Legacy NIC or gateway selection changes the actual route and requires an explicit platform choice.");
    AddReason(result.report, "W_MIGRATE_DNS_CACHE_UNPROVEN",
        legacy.dns_cache_enabled
            ? "Legacy global DNS cache cannot be proven equivalent to v2 policy-scoped resolver caching."
            : "Legacy DNS caching is disabled, while the v2 resolver service caches responses.");
    AddReason(result.report, "W_MIGRATE_DNS_EXIT_UNPROVEN",
        "Provider names and NIC settings do not prove the actual legacy DNS transport or network egress; runtime evidence is unavailable.");
    AddReason(result.report, "W_MIGRATE_IPV6_AAAA",
        "Legacy IPv6/native fallback and AAAA handling cannot be proven equivalent to the v2 IPv6-block policy.");
    if (legacy.fake_ip_enabled)
        AddReason(result.report, "W_MIGRATE_FAKE_IP",
            "Legacy global Fake-IP mappings are not equivalent to policy-scoped Fake-IP state.");
    if (legacy.ecs_enabled || !legacy.ecs_override_ip.empty())
        AddReason(result.report, "W_MIGRATE_ECS",
            "Legacy ECS settings are not represented by the generated resolver policy.");
    result.report["incomplete"] = !result.complete;
    result.report["status"] = result.complete ? "equivalent" : "draft";
    result.report["runtime"] = JsonString(runtime);
    result.report["platform"] = JsonString(platform);
    result.policy_config["incomplete"] = !result.complete;
    return result;
}

} // namespace ppp::app::client::policy
