#include <ppp/app/client/policy/PolicyCompiler.h>
#include <ppp/app/client/policy/PolicyEvaluator.h>

#include <array>
#include <iostream>
#include <sstream>
#include <stdexcept>

using namespace ppp::app::client::policy;
namespace {
void Require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
PolicySource Source(const std::string& rules) {
    PolicySource source;
    source.rules_path = "index-property.rules";
    source.rules_text = "default proxy\ndns direct local\ndns proxy remote\n" + rules;
    source.resolvers["local"] = {PolicyAction::Direct, {"udp://192.0.2.53:53"}};
    source.resolvers["remote"] = {PolicyAction::Proxy, {"tcp://198.51.100.53:53"}};
    return source;
}
std::shared_ptr<const PolicySnapshot> Compile(const PolicySource& source, std::uint64_t version = 17) {
    auto result = PolicyCompiler::Compile(source, version);
    for (const auto& diagnostic : result.diagnostics)
        if (diagnostic.severity == "error") std::cerr << diagnostic.code << ": " << diagnostic.message << '\n';
    Require(result.Ok(), "Valid property fixture failed to compile");
    return result.snapshot;
}
void Set(PolicySource& source, const std::string& name, const std::string& format, const std::string& text) {
    auto& set = source.rule_sets[name];
    set.path = name + ".fixture";
    set.format = format;
    set.text = text;
    set.materialized = true;
}
void Domains() {
    auto snapshot = Compile(Source(
        "[reject]\nregexp:test$\nkeyword:advert\n"
        "[direct]\nExample.Test.\n=LOGIN.example.test\n"
        "[proxy]\n*.example.test\n[reject]\nprivate.example.test\n"));
    struct Row { const char* domain; PolicyAction action; bool matched; std::size_t line; };
    const Row rows[] = {
        {"example.test", PolicyAction::Direct, true, 8},
        {"EXAMPLE.TEST.", PolicyAction::Direct, true, 8},
        {"login.example.test", PolicyAction::Direct, true, 9},
        {"LOGIN.EXAMPLE.TEST.", PolicyAction::Direct, true, 9},
        {"child.example.test", PolicyAction::Proxy, true, 11},
        {"deep.child.example.test.", PolicyAction::Proxy, true, 11},
        {"private.example.test", PolicyAction::Reject, true, 13},
        {"child.private.example.test", PolicyAction::Reject, true, 13},
        {"notexample.test", PolicyAction::Reject, true, 5},
        {"example.test.other", PolicyAction::Proxy, false, 1},
        {"advert.example.test", PolicyAction::Proxy, true, 11},
        {"advert.other.test", PolicyAction::Reject, true, 6},
        {"example..test", PolicyAction::Reject, false, 1},
        {"example.test..", PolicyAction::Reject, false, 1},
        {"-bad.example.test", PolicyAction::Reject, false, 1},
        {"bad-.example.test", PolicyAction::Reject, false, 1}
    };
    for (const auto& row : rows) {
        auto decision = PolicyEvaluator::Evaluate(*snapshot, row.domain);
        Require(decision.action == row.action && decision.matched == row.matched && decision.line == row.line,
            std::string("Domain boundary/priority/provenance: ") + row.domain);
        Require(decision.file == "index-property.rules" && decision.version == 17, "Domain provenance ownership");
    }
    auto reject_invalid = Compile(Source("[direct]\n0.0.0.0/0\n"));
    const std::vector<std::string> invalid_domains = {
        "example..test", "example.test..", ".example.test", "-bad.example.test", "bad-.example.test",
        "bad_label.test", "bad label.test", "https://example.test", "192.0.2.1",
        std::string(64, 'a') + ".test", "\xc3\xa9.test"
    };
    for (const auto& domain : invalid_domains) {
        for (const std::string ip : {"", "192.0.2.7"}) {
            const auto decision = PolicyEvaluator::Evaluate(*reject_invalid, domain, ip);
            Require(decision.action == PolicyAction::Reject && !decision.matched &&
                !decision.needs_ip_resolution && decision.reason == "invalid_domain",
                "Invalid domain must reject before default/IP routing: " + domain);
        }
        const auto dns = PolicyEvaluator::PlanDns(*reject_invalid, domain);
        Require(dns.rejected && dns.action == PolicyAction::Reject && dns.resolver.empty(),
            "Invalid domain must not select a DNS upstream: " + domain);
    }
    auto only_children = Compile(Source("[direct]\n*.root.test\n"));
    Require(!PolicyEvaluator::Evaluate(*only_children, "root.test").matched, "Subdomain excludes its root");
    Require(PolicyEvaluator::Evaluate(*only_children, "a.root.test").matched, "Subdomain includes children");

    auto source = Source("[reject]\nset:sites\nset:ips\n[direct]\nexample.test\n0.0.0.0/0\n");
    Set(source, "sites", "geosite-text", "full:exact.example.test\ndomain:example.test\n");
    Set(source, "ips", "geoip-text", "192.0.2.7/32\n");
    snapshot = Compile(source);
    Require(PolicyEvaluator::Evaluate(*snapshot, "exact.example.test").action == PolicyAction::Direct,
        "Explicit suffix precedes set exact");
    Require(PolicyEvaluator::Evaluate(*snapshot, "", "192.0.2.7").action == PolicyAction::Direct,
        "Explicit default prefix precedes set host prefix");
}
std::string Address(std::uint32_t ip) {
    return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 255) + "." +
        std::to_string((ip >> 8) & 255) + "." + std::to_string(ip & 255);
}
void Prefixes() {
    auto snapshot = Compile(Source(
        "[reject]\n203.0.113.7/0\n[direct]\n1.2.3.4/1\n"
        "[proxy]\n128.9.8.7/1\n[reject]\n192.0.2.5/31\n"
        "[direct]\n192.0.2.5/32\n"));
    struct Row { const char* ip; PolicyAction action; std::size_t line; };
    const Row rows[] = {
        {"0.0.0.0", PolicyAction::Direct, 7}, {"127.255.255.255", PolicyAction::Direct, 7},
        {"128.0.0.0", PolicyAction::Proxy, 9}, {"255.255.255.255", PolicyAction::Proxy, 9},
        {"192.0.2.3", PolicyAction::Proxy, 9}, {"192.0.2.4", PolicyAction::Reject, 11},
        {"192.0.2.5", PolicyAction::Direct, 13}, {"192.0.2.6", PolicyAction::Proxy, 9}
    };
    for (const auto& row : rows) {
        auto decision = PolicyEvaluator::Evaluate(*snapshot, "", row.ip);
        Require(decision.action == row.action && decision.line == row.line && decision.reason == "ipv4",
            std::string("IPv4 branch or prefix boundary: ") + row.ip);
    }
    const std::array<std::string, 5> canonical{{"0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "192.0.2.4/31", "192.0.2.5/32"}};
    Require(snapshot->Rules().size() == canonical.size(), "Prefix fixture rule count");
    for (std::size_t i = 0; i < canonical.size(); ++i)
        Require(snapshot->Rules()[i].value == canonical[i], "CIDR network canonicalization");
    auto all = Compile(Source("[reject]\n203.0.113.7/0\n"));
    Require(PolicyEvaluator::Evaluate(*all, "", "0.0.0.0").action == PolicyAction::Reject &&
        PolicyEvaluator::Evaluate(*all, "", "255.255.255.255").action == PolicyAction::Reject, "/0 stored on trie root");

    // Compare a seeded trie against interval division, without production CIDR parsing or matching.
    struct Interval { std::uint64_t start, size; PolicyAction action; std::size_t line; };
    std::vector<Interval> intervals;
    std::string rules;
    std::uint32_t seed = 0x9e3779b9u;
    auto next = [&]() { seed = seed * 1664525u + 1013904223u; return seed; };
    for (unsigned bits : {0u, 1u, 4u, 8u, 12u, 16u, 20u, 24u, 28u, 31u, 32u}) {
        auto address = next();
        auto size = std::uint64_t{1} << (32 - bits);
        auto start = (std::uint64_t(address) / size) * size;
        auto action = bits % 3 == 0 ? PolicyAction::Reject : PolicyAction::Direct;
        rules += action == PolicyAction::Reject ? "[reject]\n" : "[direct]\n";
        rules += Address(address) + "/" + std::to_string(bits) + "\n";
        intervals.push_back({start, size, action, 3 + intervals.size() * 2 + 2});
    }
    snapshot = Compile(Source(rules));
    auto check = [&](std::uint32_t address) {
        const Interval* expected = nullptr;
        for (const auto& candidate : intervals)
            if (address >= candidate.start && std::uint64_t(address) - candidate.start < candidate.size &&
                (!expected || candidate.size < expected->size)) expected = &candidate;
        auto decision = PolicyEvaluator::Evaluate(*snapshot, "", Address(address));
        Require(expected && decision.action == expected->action && decision.line == expected->line,
            "Seeded IPv4 interval oracle: " + Address(address));
    };
    for (const auto& interval : intervals) {
        check(static_cast<std::uint32_t>(interval.start));
        check(static_cast<std::uint32_t>(interval.start + interval.size - 1));
        if (interval.start) check(static_cast<std::uint32_t>(interval.start - 1));
        if (interval.start + interval.size < (std::uint64_t{1} << 32))
            check(static_cast<std::uint32_t>(interval.start + interval.size));
    }
    for (unsigned i = 0; i < 512; ++i) check(next());
}
void KeywordsAndSources() {
    auto source = Source("[reject]\nset:first\n[direct]\nset:second\n");
    Set(source, "first", "geosite-text", "plain:he\nplain:she\nplain:hers\nplain:his\nplain:aba\n");
    Set(source, "second", "geosite-text", "plain:he\nplain:ba\nplain:bc\n");
    auto snapshot = Compile(source);
    struct Keyword { const char* text; const char* source; std::size_t line; PolicyAction action; };
    const Keyword keywords[] = {
        {"he", "first", 1, PolicyAction::Reject}, {"she", "first", 2, PolicyAction::Reject},
        {"hers", "first", 3, PolicyAction::Reject}, {"his", "first", 4, PolicyAction::Reject},
        {"aba", "first", 5, PolicyAction::Reject}, {"he", "second", 1, PolicyAction::Direct},
        {"ba", "second", 2, PolicyAction::Direct}, {"bc", "second", 3, PolicyAction::Direct}
    };
    auto check = [&](const std::string& domain) {
        const Keyword* expected = nullptr;
        for (const auto& keyword : keywords) if (domain.find(keyword.text) != std::string::npos) { expected = &keyword; break; }
        auto decision = PolicyEvaluator::Evaluate(*snapshot, domain);
        Require(decision.matched == bool(expected), "Keyword oracle matched flag: " + domain);
        if (expected) Require(decision.action == expected->action && decision.source == expected->source &&
            decision.line == expected->line && decision.file == std::string(expected->source) + ".fixture",
            "Keyword failure links/order/provenance: " + domain + " got " + decision.source + ":" + std::to_string(decision.line));
    };
    for (const char* word : {"she", "ushers", "his", "hishers", "ababa", "bc", "bca", "xyz", "shxbc"})
        check(std::string(word) + ".test");
    std::uint32_t seed = 12345;
    const std::string alphabet = "abcehirs";
    for (unsigned n = 0; n < 384; ++n) {
        std::string word;
        for (unsigned i = 0; i < 24; ++i) {
            seed = seed * 1664525u + 1013904223u;
            word += alphabet[(seed >> 16) % alphabet.size()];
        }
        check(word + ".test");
    }
    auto dns_source = Source("[dns:local]\nkeyword:he\n[dns:remote]\nkeyword:she\n");
    auto dns = Compile(dns_source);
    Require(PolicyEvaluator::PlanDns(*dns, "ushers.test").resolver == "local", "DNS keyword index failure outputs use declaration order");
}
std::string Fingerprint(const PolicySnapshot& snapshot) {
    std::ostringstream result;
    for (const auto& rule : snapshot.Rules()) result << int(rule.condition) << ':' << rule.value << ':' <<
        int(rule.action) << ':' << int(rule.origin) << ':' << rule.resolver << ':' << rule.file << ':' <<
        rule.line << ':' << rule.original_line << ':' << rule.source_name << ':' << rule.order << '\n';
    return result.str();
}
void ImmutableSnapshots() {
    auto source = Source("[direct]\nexample.test\nkeyword:stable\n");
    auto retained = Compile(source, 123);
    const auto before = Fingerprint(*retained);
    source.rules_text = Source("[reject]\nexample.test\n").rules_text;
    auto replacement = Compile(source, 124);
    source.rules_text.clear(); source.resolvers.clear();
    for (unsigned n = 0; n < 128; ++n) {
        Require(PolicyEvaluator::Evaluate(*retained, "EXAMPLE.TEST.").action == PolicyAction::Direct,
            "Old snapshot remains independent of new snapshot and source");
        Require(PolicyEvaluator::Evaluate(*replacement, "example.test").action == PolicyAction::Reject,
            "New snapshot has independent action");
        Require(PolicyEvaluator::PlanDns(*retained, "stable.test").resolver == "local", "Snapshot owns DNS bindings");
        for (const char* invalid : {"[direct]\nregexp:[\n", "[direct]\n=conflict.test\n[reject]\n=conflict.test\n"}) {
            auto failed = PolicyCompiler::Compile(Source(invalid), 125);
            Require(!failed.Ok() && !failed.snapshot, "Compile failure publishes no partial snapshot");
            if (failed.Ok()) retained = failed.snapshot;
        }
    }
    Require(retained->Version() == 123 && Fingerprint(*retained) == before, "Queries and failed candidates cannot mutate snapshot");
}
}
int main() {
    try {
        Domains(); Prefixes(); KeywordsAndSources(); ImmutableSnapshots();
        std::cout << "policy index property tests passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    return 0;
}
