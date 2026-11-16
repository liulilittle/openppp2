#pragma once

#include <ppp/app/client/routing/HumanRoutingRules.h>
#include <ppp/app/client/dns/Rule.h>
#include <ppp/configurations/AppConfiguration.h>

#include <string>
#include <vector>

namespace ppp::app::client::policy {

enum class LegacySourceRole { Bypass, DnsRules, HumanRules, GeoIp, GeoSite };
enum class LegacySourceKind { Inline, File, MissingFileInline, UnavailableFile };

struct LegacyPolicySource final {
    LegacySourceRole role = LegacySourceRole::Bypass;
    LegacySourceKind kind = LegacySourceKind::Inline;
    std::size_t order = 0;
    std::string original;
    std::string value;
};

struct LegacyPolicyRoute final {
    std::string path;
    std::string nic;
    std::string gateway;
    std::string peer;
    bool peer_route = false;
};

struct LegacyPolicyAdapterInput final {
    std::vector<std::string> cli_bypass;
    std::vector<std::string> cli_dns_rules;
    std::string bypass_nic;
    std::string bypass_gateway;
};

struct LegacyPolicyIssue final {
    std::string code;
    std::string source;
    std::size_t line = 0;
    std::string message;
};

struct LegacyDnsRule final {
    enum class PatternKind { Suffix, Exact, Regexp };
    LegacySourceKind source_kind = LegacySourceKind::Inline;
    std::size_t source_order = 0;
    PatternKind pattern_kind = PatternKind::Suffix;
    std::string pattern;
    std::string provider;
    std::string server;
    bool nic_or_domestic = false;
};

struct LegacyPolicyModel final {
    bool canonical_routing = false;
    bool proxy_only = false;
    bool fake_ip_enabled = false;
    std::string fake_ip_range;
    bool geo_enabled = false;
    bool geo_generates_files = false;
    bool dns_cache_enabled = false;
    bool dns_intercept_unmatched = true;
    bool ecs_enabled = false;
    std::string ecs_override_ip;
    std::string domestic_dns;
    std::string foreign_dns;
    std::string bypass_nic;
    std::string bypass_gateway;
    std::vector<LegacyPolicySource> sources;
    std::vector<LegacyPolicyRoute> routes;
    std::vector<ppp::app::client::routing::DomainRule> domain_rules;
    std::vector<ppp::app::client::routing::Ipv4CidrRule> ipv4_rules;
    std::vector<ppp::app::client::routing::DnsProviderRule> dns_providers;
    std::string human_rules_text;
    std::vector<std::string> differences;
    std::vector<LegacyPolicyIssue> issues;
    std::vector<LegacyDnsRule> dns_rules;
    ppp::app::client::routing::RoutingAction default_action =
        ppp::app::client::routing::RoutingAction::Auto;
};

class LegacyPolicyAdapter final {
public:
    static LegacyPolicyModel Adapt(const ppp::configurations::AppConfiguration& configuration,
        const LegacyPolicyAdapterInput& input = {});
};

} // namespace ppp::app::client::policy
