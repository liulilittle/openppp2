#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace ppp::app::client::policy {

enum class PolicyAction { Direct, Proxy, Reject };
enum class PolicyOrigin { Explicit, RuleSet };
enum class PolicyCondition { Exact, Suffix, Subdomain, Keyword, Regexp, Ipv4Cidr };

struct PolicyDiagnostic {
    std::string code;
    std::string severity = "error";
    std::string path;
    std::string file;
    std::size_t line = 0;
    std::string original_line;
    std::string message;
};

struct PolicyRule {
    PolicyCondition condition = PolicyCondition::Suffix;
    std::string value;
    PolicyAction action = PolicyAction::Proxy;
    PolicyOrigin origin = PolicyOrigin::Explicit;
    std::string resolver;
    std::string file;
    std::size_t line = 0;
    std::string original_line;
    std::string source_name;
    std::size_t order = 0;
};

struct PolicyResolver {
    PolicyAction via = PolicyAction::Proxy;
    std::vector<std::string> servers;
    struct Server final {
        std::string uri;
        std::vector<std::string> addresses;
        std::vector<std::string> bootstrap;
    };
    std::vector<Server> server_specs;
    struct ServerRef final { bool structured = false; std::size_t index = 0; };
    std::vector<ServerRef> server_order;
};

struct PolicyRuleSet {
    std::string format;
    std::string path;
    std::string url;
    std::string tag;
    std::string sha256;
    // Exact checked source bytes, including binary dat payloads.
    std::string text;
    bool materialized = false;
};

struct PolicySource {
    int version = 2;
    std::string config_path;
    std::string base_path;
    std::string rules_path;
    std::string rules_text;
    std::string ipv6 = "block";
    std::string dns_mode = "auto";
    std::string fake_ip_range = "198.18.0.0/16";
    std::string fake_ip_storage = "./dns-fake-ip";
    std::string fake_ip_identity;
    bool tcp_domain_sniff = false;
    std::map<std::string, PolicyResolver> resolvers;
    std::map<std::string, PolicyRuleSet> rule_sets;
    bool updates_enabled = false;
    std::string updates_interval = "24h";
    PolicyAction updates_via = PolicyAction::Proxy;
    std::vector<std::string> updates_bootstrap;
    bool updates_allow_http = false;
};

} // namespace ppp::app::client::policy
