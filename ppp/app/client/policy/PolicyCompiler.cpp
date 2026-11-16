#include <ppp/app/client/policy/PolicyCompiler.h>
#include <ppp/app/client/policy/PolicyEvaluator.h>
#include <ppp/app/client/routing/GeoDataReader.h>
#include <boost/asio/ip/address.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <queue>
#include <regex>
#include <sstream>
#include <unordered_map>

namespace ppp::app::client::policy {
namespace {
constexpr std::size_t none = static_cast<std::size_t>(-1);
std::string Trim(std::string s) {
    const auto begin = s.find_first_not_of(" \t\r\n");
    return begin == std::string::npos ? "" : s.substr(begin, s.find_last_not_of(" \t\r\n") - begin + 1);
}
std::string Lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
bool Domain(std::string& s) {
    s = Lower(s);
    if (!s.empty() && s.back() == '.') s.pop_back();
    if (s.empty() || s.size() > 253) return false;
    if (s.find('.') != std::string::npos &&
        std::all_of(s.begin(), s.end(), [](unsigned char c) { return (c >= '0' && c <= '9') || c == '.'; })) return false;
    std::size_t label = 0;
    char previous = '.';
    for (unsigned char c : s) {
        if (c == '.') {
            if (!label || label > 63 || previous == '-') return false;
            label = 0;
        } else {
            if (!(std::isalnum(c) || c == '-') || c >= 128 || (!label && c == '-')) return false;
            ++label;
        }
        previous = static_cast<char>(c);
    }
    return label && label <= 63 && previous != '-';
}
bool Ip(const std::string& s, std::uint32_t& address) {
    if (s.empty() || s.back() == '.' || std::count(s.begin(), s.end(), '.') != 3) return false;
    std::istringstream in(s);
    address = 0;
    for (int i = 0; i < 4; ++i) {
        std::string part;
        if (!std::getline(in, part, '.') || part.empty() || part.size() > 3) return false;
        unsigned value = 0;
        for (char c : part) { if (c < '0' || c > '9') return false; value = value * 10 + unsigned(c - '0'); }
        if (value > 255) return false;
        address = (address << 8) | value;
    }
    return in.peek() == std::char_traits<char>::eof();
}
bool Cidr(const std::string& s, std::uint32_t& address, unsigned& prefix) {
    auto slash = s.find('/');
    if (!Ip(s.substr(0, slash), address)) return false;
    prefix = 32;
    if (slash != std::string::npos) {
        auto bits = s.substr(slash + 1);
        if (bits.empty() || bits.size() > 2) return false;
        prefix = 0;
        for (char c : bits) { if (c < '0' || c > '9') return false; prefix = prefix * 10 + unsigned(c - '0'); }
        if (prefix > 32) return false;
    }
    address &= prefix ? (0xffffffffu << (32 - prefix)) : 0;
    return true;
}
std::string CidrText(std::uint32_t ip, unsigned bits) {
    return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 255) + "." +
        std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255) + "/" + std::to_string(bits);
}
bool Action(const std::string& s, PolicyAction& action) {
    if (s == "direct") action = PolicyAction::Direct;
    else if (s == "proxy") action = PolicyAction::Proxy;
    else if (s == "reject") action = PolicyAction::Reject;
    else return false;
    return true;
}
struct Node { std::unordered_map<unsigned char, std::size_t> children; std::vector<std::size_t> rules; std::size_t failure = 0; };
struct PrefixNode { std::array<std::size_t, 2> children{{none, none}}; std::vector<std::size_t> rules; };
struct DomainIndex {
    std::unordered_map<std::string, std::vector<std::size_t>> exact;
    std::vector<Node> suffix{1}, keywords{1};
    std::vector<std::pair<std::size_t, std::regex>> regex;
};
std::size_t Insert(std::vector<Node>& nodes, const std::string& text) {
    std::size_t pos = 0;
    for (unsigned char c : text) {
        auto it = nodes[pos].children.find(c);
        if (it == nodes[pos].children.end()) {
            auto next = nodes.size(); nodes[pos].children[c] = next; nodes.emplace_back(); pos = next;
        } else pos = it->second;
    }
    return pos;
}
void Failures(std::vector<Node>& nodes) {
    std::queue<std::size_t> pending;
    for (const auto& edge : nodes[0].children) pending.push(edge.second);
    while (!pending.empty()) {
        auto pos = pending.front(); pending.pop();
        for (const auto& edge : nodes[pos].children) {
            auto failure = nodes[pos].failure;
            while (failure && !nodes[failure].children.count(edge.first)) failure = nodes[failure].failure;
            auto found = nodes[failure].children.find(edge.first);
            if (found != nodes[failure].children.end()) failure = found->second;
            nodes[edge.second].failure = failure;
            // Failure links share suffix matches without duplicating keyword output lists.
            pending.push(edge.second);
        }
    }
}
}

struct PolicySnapshot::Index {
    std::uint64_t version = 1;
    std::size_t skipped_ipv6 = 0;
    PolicyAction fallback = PolicyAction::Proxy;
    PolicyRule default_location;
    std::string dns_direct, dns_proxy;
    std::string dns_mode;
    std::string fake_ip_range;
    std::string fake_ip_storage;
    std::string fake_ip_identity;
    bool tcp_domain_sniff = false;
    std::map<std::string, PolicyResolver> resolvers;
    std::vector<PolicyRule> rules;
    DomainIndex domain, dns;
    std::vector<PrefixNode> prefixes{1};
};

namespace {
bool Better(const PolicySnapshot::Index& index, std::size_t a, std::size_t b) {
    if (b == none) return true;
    const auto& x = index.rules[a]; const auto& y = index.rules[b];
    if (x.origin != y.origin) return x.origin == PolicyOrigin::Explicit;
    auto rank = [](PolicyCondition c) {
        if (c == PolicyCondition::Exact) return 0;
        if (c == PolicyCondition::Suffix || c == PolicyCondition::Subdomain) return 1;
        if (c == PolicyCondition::Keyword) return 2;
        if (c == PolicyCondition::Regexp) return 3;
        return 0;
    };
    if (rank(x.condition) != rank(y.condition)) return rank(x.condition) < rank(y.condition);
    if (rank(x.condition) == 1) {
        if (x.value.size() != y.value.size()) return x.value.size() > y.value.size();
        if (x.condition != y.condition) return x.condition == PolicyCondition::Subdomain;
    }
    if (x.condition == PolicyCondition::Ipv4Cidr) {
        unsigned xp, yp; std::uint32_t ip;
        Cidr(x.value, ip, xp); Cidr(y.value, ip, yp);
        if (xp != yp) return xp > yp;
    }
    return x.order < y.order;
}
std::size_t MatchDomain(const PolicySnapshot::Index& index, const DomainIndex& lookup, std::string domain) {
    if (!Domain(domain)) return none;
    std::size_t best = none;
    auto consider = [&](const std::vector<std::size_t>& ids) { for (auto id : ids) if (Better(index, id, best)) best = id; };
    auto exact = lookup.exact.find(domain); if (exact != lookup.exact.end()) consider(exact->second);
    std::size_t pos = 0;
    for (std::size_t i = 0; i < domain.size(); ++i) {
        auto found = lookup.suffix[pos].children.find(domain[domain.size() - i - 1]);
        if (found == lookup.suffix[pos].children.end()) break;
        pos = found->second;
        if (i + 1 == domain.size() || domain[domain.size() - i - 2] == '.') {
            for (auto id : lookup.suffix[pos].rules) {
                if (index.rules[id].condition == PolicyCondition::Subdomain && i + 1 == domain.size()) continue;
                if (Better(index, id, best)) best = id;
            }
        }
    }
    pos = 0;
    for (unsigned char c : domain) {
        while (pos && !lookup.keywords[pos].children.count(c)) pos = lookup.keywords[pos].failure;
        auto next = lookup.keywords[pos].children.find(c);
        if (next != lookup.keywords[pos].children.end()) pos = next->second;
        for (auto output = pos; output; output = lookup.keywords[output].failure) consider(lookup.keywords[output].rules);
    }
    for (const auto& re : lookup.regex) {
        if (Better(index, re.first, best) && std::regex_search(domain, re.second)) best = re.first;
    }
    return best;
}
}

PolicySnapshot::PolicySnapshot(std::shared_ptr<const Index> index) : index_(std::move(index)) {}
std::uint64_t PolicySnapshot::Version() const noexcept { return index_->version; }
std::size_t PolicySnapshot::RuleCount() const noexcept { return index_->rules.size(); }
std::size_t PolicySnapshot::SkippedIpv6() const noexcept { return index_->skipped_ipv6; }
const std::vector<PolicyRule>& PolicySnapshot::Rules() const noexcept { return index_->rules; }
const std::map<std::string, PolicyResolver>& PolicySnapshot::Resolvers() const noexcept { return index_->resolvers; }
const std::string& PolicySnapshot::DnsMode() const noexcept { return index_->dns_mode; }
const std::string& PolicySnapshot::FakeIpRange() const noexcept { return index_->fake_ip_range; }
const std::string& PolicySnapshot::FakeIpStorage() const noexcept { return index_->fake_ip_storage; }
const std::string& PolicySnapshot::FakeIpIdentity() const noexcept { return index_->fake_ip_identity; }
bool PolicySnapshot::TcpDomainSniff() const noexcept { return index_->tcp_domain_sniff; }
const std::string& PolicySnapshot::DnsResolverForAction(PolicyAction action) const noexcept {
    static const std::string rejected;
    return action == PolicyAction::Direct ? index_->dns_direct :
        action == PolicyAction::Proxy ? index_->dns_proxy : rejected;
}

PolicyCompileResult PolicyCompiler::Compile(const PolicySource& source, std::uint64_t version) {
    PolicyCompileResult result;
    auto index = std::make_shared<PolicySnapshot::Index>();
    index->version = version; index->resolvers = source.resolvers;
    index->dns_mode = source.dns_mode;
    index->fake_ip_range = source.fake_ip_range;
    index->fake_ip_storage = source.fake_ip_storage;
    index->fake_ip_identity = source.fake_ip_identity;
    index->tcp_domain_sniff = source.tcp_domain_sniff;
    index->default_location.file = source.rules_path;
    index->default_location.source_name = "default";
    std::size_t order = 0;
    std::unordered_map<std::string, std::size_t> duplicates;
    auto diagnostic = [&](const PolicyRule& rule, const std::string& code, const std::string& message, const std::string& severity = "error") {
        PolicyDiagnostic d; d.code = code; d.severity = severity; d.file = rule.file; d.line = rule.line;
        d.original_line = rule.original_line; d.message = message; result.diagnostics.push_back(std::move(d));
    };
    auto add = [&](PolicyRule rule) {
        std::uint32_t ip = 0; unsigned prefix = 0;
        if (rule.condition == PolicyCondition::Ipv4Cidr) {
            if (!rule.resolver.empty()) { diagnostic(rule, "dns_ip_condition", "DNS exceptions cannot contain IP conditions"); return; }
            if (!Cidr(rule.value, ip, prefix)) { diagnostic(rule, "invalid_cidr", "Invalid IPv4 CIDR"); return; }
            rule.value = CidrText(ip, prefix);
        } else if (rule.condition == PolicyCondition::Regexp) {
            if (rule.value.empty()) { diagnostic(rule, "invalid_regex", "Empty regular expression"); return; }
        } else if (rule.condition == PolicyCondition::Keyword) {
            rule.value = Lower(rule.value);
            if (rule.value.empty() || std::any_of(rule.value.begin(), rule.value.end(), [](unsigned char c) { return c <= 32 || c >= 127; })) {
                diagnostic(rule, "invalid_keyword", "Keywords must be nonempty printable ASCII without whitespace"); return;
            }
        } else if (!Domain(rule.value)) { diagnostic(rule, "invalid_domain", "Domain must contain valid ASCII/Punycode labels"); return; }
        const std::string key = (rule.resolver.empty() ? "route:" : "dns:") + std::to_string(static_cast<int>(rule.condition)) + ":" + rule.value;
        auto prior = duplicates.find(key);
        if (prior != duplicates.end()) {
            const auto& first = index->rules[prior->second];
            if (first.origin == PolicyOrigin::Explicit && rule.origin == PolicyOrigin::Explicit) {
                bool same = first.resolver == rule.resolver && (!rule.resolver.empty() || first.action == rule.action);
                diagnostic(rule, same ? "duplicate_rule" : "conflicting_rule",
                    "Condition previously declared at " + first.file + ":" + std::to_string(first.line), same ? "warning" : "error");
                if (!same) diagnostic(first, "conflicting_rule", "Conflicting condition also declared at " + rule.file + ":" + std::to_string(rule.line));
                return;
            }
            diagnostic(rule, "shadowed_condition", "Same condition also supplied by " + first.source_name + " at " + first.file + ":" + std::to_string(first.line), "warning");
        }
        // Expanded set entries retain declaration order even when an index visits matches in a different order.
        rule.order = order++;
        const auto id = index->rules.size();
        DomainIndex& lookup = rule.resolver.empty() ? index->domain : index->dns;
        if (rule.condition == PolicyCondition::Regexp) {
            try { lookup.regex.emplace_back(id, std::regex(rule.value, std::regex::ECMAScript | std::regex::optimize | std::regex::icase)); }
            catch (const std::regex_error&) { diagnostic(rule, "invalid_regex", "Invalid ECMAScript regular expression"); return; }
        } else if (rule.condition == PolicyCondition::Exact) lookup.exact[rule.value].push_back(id);
        else if (rule.condition == PolicyCondition::Suffix || rule.condition == PolicyCondition::Subdomain) {
            std::string reverse(rule.value.rbegin(), rule.value.rend()); auto node = Insert(lookup.suffix, reverse); lookup.suffix[node].rules.push_back(id);
        } else if (rule.condition == PolicyCondition::Keyword) {
            auto node = Insert(lookup.keywords, rule.value); lookup.keywords[node].rules.push_back(id);
        } else {
            std::size_t node = 0;
            for (unsigned bit = 0; bit < prefix; ++bit) {
                unsigned branch = (ip >> (31 - bit)) & 1;
                if (index->prefixes[node].children[branch] == none) {
                    auto next = index->prefixes.size(); index->prefixes[node].children[branch] = next; index->prefixes.emplace_back();
                }
                node = index->prefixes[node].children[branch];
            }
            index->prefixes[node].rules.push_back(id);
        }
        if (prior == duplicates.end() || rule.origin == PolicyOrigin::Explicit) duplicates[key] = id;
        index->rules.push_back(std::move(rule));
    };
    auto condition = [&](PolicyRule rule, std::string text) {
        if (text.rfind("regexp:", 0) == 0) { rule.condition = PolicyCondition::Regexp; rule.value = text.substr(7); }
        else if (text.rfind("keyword:", 0) == 0) { rule.condition = PolicyCondition::Keyword; rule.value = text.substr(8); }
        else if (text.rfind("full:", 0) == 0) { rule.condition = PolicyCondition::Exact; rule.value = text.substr(5); }
        else if (!text.empty() && text.front() == '=') { rule.condition = PolicyCondition::Exact; rule.value = text.substr(1); }
        else if (text.rfind("*.", 0) == 0) { rule.condition = PolicyCondition::Subdomain; rule.value = text.substr(2); }
        else {
            std::uint32_t ip; unsigned prefix;
            if (text.find(':') != std::string::npos) { diagnostic(rule, "unsupported_ipv6", "IPv6 conditions and unknown condition prefixes are unsupported"); return; }
            if (!Cidr(text, ip, prefix) && text.find('.') != std::string::npos &&
                std::all_of(text.begin(), text.end(), [](char c) { return (c >= '0' && c <= '9') || c == '.' || c == '/'; })) {
                diagnostic(rule, "invalid_cidr", "Invalid numeric IPv4 condition"); return;
            }
            rule.condition = Cidr(text, ip, prefix) || text.find('/') != std::string::npos ? PolicyCondition::Ipv4Cidr : PolicyCondition::Suffix;
            rule.value = text;
        }
        add(std::move(rule));
    };
    bool has_default = false, has_section = false;
    PolicyAction action = PolicyAction::Proxy;
    std::string resolver;
    std::istringstream input(source.rules_text); std::string original; std::size_t line = 0;
    while (std::getline(input, original)) {
        ++line; std::string text = Trim(original);
        if (text.empty() || text[0] == '#' || text[0] == ';') continue;
        auto comment = text.find(" #"); if (comment != std::string::npos) text = Trim(text.substr(0, comment));
        PolicyRule rule; rule.file = source.rules_path; rule.line = line; rule.original_line = original;
        rule.action = action; rule.resolver = resolver; rule.source_name = "explicit"; rule.order = order++;
        if (text[0] == '[') {
            if (text.back() != ']') { diagnostic(rule, "invalid_section", "Malformed group header"); continue; }
            auto group = text.substr(1, text.size() - 2); resolver.clear();
            if (group.rfind("dns:", 0) == 0) {
                resolver = group.substr(4);
                if (!source.resolvers.count(resolver)) diagnostic(rule, "unknown_resolver", "DNS group references an undeclared resolver");
                has_section = true;
            } else has_section = Action(group, action);
            if (!has_section) diagnostic(rule, "invalid_section", "Unknown action group");
            continue;
        }
        if (text.rfind("default ", 0) == 0) {
            if (has_default || !Action(Trim(text.substr(8)), index->fallback)) diagnostic(rule, "invalid_default", "Exactly one default direct/proxy/reject directive is required");
            else index->default_location = rule;
            has_default = true; continue;
        }
        if (text.rfind("dns ", 0) == 0) {
            std::istringstream words(text); std::string command, via, name, extra; words >> command >> via >> name >> extra;
            auto* target = via == "direct" ? &index->dns_direct : via == "proxy" ? &index->dns_proxy : nullptr;
            if (!target || name.empty() || !extra.empty() || !target->empty() || !source.resolvers.count(name)) diagnostic(rule, "invalid_dns_binding", "DNS binding requires a declared resolver and a unique direct/proxy action");
            else *target = name;
            continue;
        }
        if (!has_section) { diagnostic(rule, "missing_section", "Condition requires an action or DNS group"); continue; }
        if (text == "lan") {
            for (const char* cidr : {"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32"}) condition(rule, cidr);
        } else if (text.rfind("set:", 0) == 0) {
            auto name = Trim(text.substr(4)); auto found = source.rule_sets.find(name);
            if (found == source.rule_sets.end()) { diagnostic(rule, "unknown_rule_set", "Reference to undeclared rule set"); continue; }
            const auto& set = found->second;
            rule.origin = PolicyOrigin::RuleSet; rule.source_name = name; rule.file = set.path;
            using namespace ppp::app::client::routing;
            if (set.format == "geoip-dat" || set.format == "geoip-text") {
                if (!rule.resolver.empty()) { diagnostic(rule, "dns_ip_condition", "DNS exceptions cannot reference IP rule sets"); continue; }
                auto data = set.materialized
                    ? (set.format == "geoip-dat" ? GeoDataReader::ReadGeoIpBytes(set.text, set.tag) : GeoDataReader::ReadGeoIpTextBytes(set.text))
                    : (set.format == "geoip-dat" ? GeoDataReader::ReadGeoIp(set.path, set.tag) : GeoDataReader::ReadGeoIpText(set.path));
                if (!data.Succeeded()) { diagnostic(rule, "rule_set_unavailable", "GeoIP source unavailable or malformed"); continue; }
                index->skipped_ipv6 += data.ipv6_entries;
                if (data.skipped) diagnostic(rule, "skipped_geo_entries", std::to_string(data.skipped) + " invalid GeoIP entries skipped", "warning");
                for (const auto& entry : data.entries) {
                    if (entry.address.size() != 4) continue;
                    auto item = rule; item.line = entry.line; item.original_line = entry.cidr; item.condition = PolicyCondition::Ipv4Cidr; item.value = entry.cidr; add(std::move(item));
                }
            } else if (set.format == "geosite-dat" || set.format == "geosite-text") {
                auto data = set.materialized
                    ? (set.format == "geosite-dat" ? GeoDataReader::ReadGeoSiteBytes(set.text, set.tag) : GeoDataReader::ReadGeoSiteTextBytes(set.text))
                    : (set.format == "geosite-dat" ? GeoDataReader::ReadGeoSite(set.path, set.tag) : GeoDataReader::ReadGeoSiteText(set.path));
                if (!data.Succeeded()) { diagnostic(rule, "rule_set_unavailable", "GeoSite source unavailable or malformed"); continue; }
                if (data.skipped) diagnostic(rule, "skipped_geo_entries", std::to_string(data.skipped) + " invalid GeoSite entries skipped", "warning");
                for (const auto& entry : data.entries) {
                    auto item = rule; item.line = entry.line; item.original_line = entry.value; item.value = entry.value;
                    item.condition = entry.type == GeoDataDomainType::Full ? PolicyCondition::Exact : entry.type == GeoDataDomainType::Domain ? PolicyCondition::Suffix : entry.type == GeoDataDomainType::Regex ? PolicyCondition::Regexp : PolicyCondition::Keyword;
                    add(std::move(item));
                }
            } else diagnostic(rule, "unsupported_rule_set_format", "Unsupported rule-set format");
        } else condition(rule, text);
    }
    PolicyRule location; location.file = source.rules_path;
    if (index->dns_direct.empty() || index->dns_proxy.empty()) diagnostic(location, "missing_dns_binding", "Both direct and proxy DNS bindings are required");
    if (source.version != 2) diagnostic(location, "unsupported_version", "Compiler accepts only policy version 2");
    if (std::any_of(result.diagnostics.begin(), result.diagnostics.end(), [](const auto& d) { return d.severity == "error"; })) return result;
    Failures(index->domain.keywords); Failures(index->dns.keywords);
    result.snapshot = std::shared_ptr<const PolicySnapshot>(new PolicySnapshot(index));
    return result;
}

PolicyDecision PolicyEvaluator::Evaluate(const PolicySnapshot& snapshot, const std::string& domain, const std::string& ipv4) {
    const auto& index = *snapshot.index_;
    PolicyDecision decision; decision.version = index.version; decision.action = index.fallback;
    decision.source = "default"; decision.file = index.default_location.file; decision.line = index.default_location.line;
    std::string normalized = domain;
    if (!domain.empty() && !Domain(normalized)) {
        decision.action = PolicyAction::Reject;
        decision.reason = "invalid_domain";
        return decision;
    }
    if (!ipv4.empty()) {
        boost::system::error_code error;
        const auto address = boost::asio::ip::make_address(ipv4, error);
        if (error || !address.is_v4()) {
            decision.action = PolicyAction::Reject;
            decision.reason = error ? "invalid_ipv4" : "unsupported_ipv6";
            return decision;
        }
    }
    auto best = MatchDomain(index, index.domain, domain);
    decision.reason = best == none ? "default" : "domain";
    if (best == none) {
        std::uint32_t address;
        if (Ip(ipv4, address)) {
            std::size_t node = 0;
            for (unsigned depth = 0; depth <= 32; ++depth) {
                for (auto id : index.prefixes[node].rules) if (Better(index, id, best)) best = id;
                if (depth == 32) break;
                auto next = index.prefixes[node].children[(address >> (31 - depth)) & 1];
                if (next == none) break;
                node = next;
            }
            if (best != none) decision.reason = "ipv4";
        } else {
            decision.needs_ip_resolution = Domain(normalized) && ipv4.empty();
            if (!ipv4.empty()) decision.reason = "invalid_ipv4";
            else if (decision.needs_ip_resolution) decision.reason = "needs_ip_resolution";
        }
    }
    if (best != none) {
        decision.action = index.rules[best].action; decision.matched = true;
        decision.rule_id = "r" + std::to_string(best + 1); decision.source = index.rules[best].source_name;
        decision.file = index.rules[best].file; decision.line = index.rules[best].line;
    }
    return decision;
}

PolicyDnsPlan PolicyEvaluator::PlanDns(const PolicySnapshot& snapshot, const std::string& domain) {
    const auto& index = *snapshot.index_;
    PolicyDnsPlan plan; plan.version = index.version;
    plan.source = "default"; plan.file = index.default_location.file; plan.line = index.default_location.line;
    std::string normalized = domain;
    if (!Domain(normalized)) {
        plan.action = PolicyAction::Reject;
        plan.rejected = true;
        return plan;
    }
    auto business = MatchDomain(index, index.domain, domain);
    plan.action = business == none ? index.fallback : index.rules[business].action;
    if (business != none) {
        plan.rule_id = "r" + std::to_string(business + 1);
        plan.source = index.rules[business].source_name;
        plan.file = index.rules[business].file; plan.line = index.rules[business].line;
        if (plan.action == PolicyAction::Reject) { plan.rejected = true; return plan; }
    }
    auto exception = MatchDomain(index, index.dns, domain);
    if (exception != none) {
        plan.resolver = index.rules[exception].resolver; plan.rule_id = "r" + std::to_string(exception + 1);
        plan.source = index.rules[exception].source_name;
        plan.file = index.rules[exception].file; plan.line = index.rules[exception].line;
    } else {
        if (plan.action == PolicyAction::Reject) { plan.rejected = true; return plan; }
        plan.resolver = plan.action == PolicyAction::Direct ? index.dns_direct : index.dns_proxy;
    }
    plan.via = index.resolvers.at(plan.resolver).via;
    return plan;
}

} // namespace ppp::app::client::policy
