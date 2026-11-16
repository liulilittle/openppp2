#include <ppp/app/client/policy/LegacyPolicyMigration.h>
#include <ppp/app/client/policy/PolicyEvaluator.h>

#include <boost/asio/ip/address_v4.hpp>

#include <iostream>
#include <stdexcept>

using namespace ppp::app::client::policy;
namespace routing = ppp::app::client::routing;

namespace {

void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

LegacyPolicyModel Legacy(const std::string& text) {
    LegacyPolicyModel model;
    model.human_rules_text = text;
    routing::HumanRoutingRules rules;
    Require(rules.LoadText(text, "legacy-routing.rules"), "Legacy HumanRules must parse");
    model.default_action = rules.DefaultAction();
    model.domain_rules = rules.DomainRules();
    model.ipv4_rules = rules.Ipv4Cidrs();
    model.dns_providers = rules.DnsProviders();
    model.sources.push_back({LegacySourceRole::HumanRules, LegacySourceKind::File, 0,
        "legacy-routing.rules", "legacy-routing.rules"});
    return model;
}

std::shared_ptr<const PolicySnapshot> CompileDraft(const LegacyPolicyMigrationResult& migrated) {
    PolicySource source;
    source.config_path = "/tmp/migration/policy.json";
    source.base_path = "/tmp/migration";
    source.rules_path = "/tmp/migration/routing.rules";
    source.rules_text = migrated.rules_text;
    source.ipv6 = "block";
    source.dns_mode = "real";
    source.resolvers["local"] = {PolicyAction::Direct, {"doh.pub"}};
    source.resolvers["remote"] = {PolicyAction::Proxy, {"cloudflare"}};
    auto result = PolicyCompiler::Compile(source);
    if (!result.Ok()) {
        for (const auto& diagnostic : result.diagnostics)
            std::cerr << diagnostic.code << ": " << diagnostic.message << '\n';
        throw std::runtime_error("Generated migration rules must compile");
    }
    return result.snapshot;
}

bool HasDiagnostic(const Json::Value& report, const std::string& code) {
    for (const auto& item : report["diagnostics"])
        if (std::string(item["code"].asCString()) == code) return true;
    return false;
}

bool SameAction(PolicyAction next, routing::RoutingAction old) {
    return (next == PolicyAction::Direct && old == routing::RoutingAction::Direct) ||
        (next == PolicyAction::Proxy && old == routing::RoutingAction::Proxy);
}

void EquivalentHostRules() {
    const std::string text =
        "default direct\n"
        "[proxy]\n"
        "example.test\n"
        "*.child.example.test\n"
        "=login.example.test\n"
        "192.0.2.0/24\n"
        "[direct]\n"
        "*.example.test\n"
        "192.0.2.128/25\n";
    auto legacy = Legacy(text);
    auto migrated = LegacyPolicyMigration::CreateDraft(legacy, "/tmp/migration/policy.json");
    Require(migrated.routing_equivalent, "Supported host-rule structure must be provable");
    auto snapshot = CompileDraft(migrated);
    routing::HumanRoutingRules old;
    Require(old.LoadText(text, "legacy-routing.rules"), "Old evaluator setup");
    for (const auto& domain : {"example.test", "www.example.test", "login.example.test",
            "x.child.example.test", "unmatched.test"}) {
        Require(SameAction(PolicyEvaluator::Evaluate(*snapshot, domain).action, old.MatchDomain(domain)),
            "Legacy/v2 domain evaluators must agree");
    }
    for (const auto& ip : {"192.0.2.1", "192.0.2.129", "198.51.100.1"}) {
        const auto address = boost::asio::ip::make_address_v4(ip);
        Require(SameAction(PolicyEvaluator::Evaluate(*snapshot, {}, ip).action, old.MatchIpv4(address.to_uint())),
            "Legacy/v2 IPv4 evaluators must agree");
    }
    Require(!migrated.complete, "Runtime/platform and legacy DNS evidence are required for whole-policy proof");
    Require(HasDiagnostic(migrated.report, "W_MIGRATE_IPV6_AAAA"),
        "Draft must retain the unresolved IPv6/AAAA difference");
}

void AutoFailsClosedAndRemainsDraft() {
    auto migrated = LegacyPolicyMigration::CreateDraft(Legacy("default auto\n[direct]\nexample.test\n"),
        "/tmp/migration/policy.json");
    Require(!migrated.routing_equivalent && !migrated.complete, "Auto fallback cannot be represented as equivalent");
    Require(migrated.rules_text.find("default reject\n") == 0,
        "Unknown native fallback must not silently become proxy");
    Require(HasDiagnostic(migrated.report, "E_MIGRATE_DEFAULT_AUTO"), "Auto choice needs a concrete diagnostic");
}

void RegexOverlapIsStructuralCounterexample() {
    const std::string text =
        "default proxy\n"
        "[direct]\n"
        "regexp:^.*example\\.test$\n"
        "[proxy]\n"
        "example.test\n";
    auto legacy = Legacy(text);
    auto migrated = LegacyPolicyMigration::CreateDraft(legacy, "/tmp/migration/policy.json");
    Require(!migrated.routing_equivalent, "Regex precedence cannot be proven by finite probes");
    Require(HasDiagnostic(migrated.report, "E_MIGRATE_REGEX_PRECEDENCE"),
        "Regex priority difference needs a diagnostic");
    auto snapshot = CompileDraft(migrated);
    routing::HumanRoutingRules old;
    Require(old.LoadText(text, "legacy-routing.rules"), "Old regex evaluator setup");
    const std::string overlap = "child.example.test";
    Require(old.MatchDomain(overlap) == routing::RoutingAction::Direct,
        "Legacy regex precedes its overlapping suffix rule");
    Require(PolicyEvaluator::Evaluate(*snapshot, overlap).action == PolicyAction::Proxy,
        "v2 suffix priority differs from legacy regex priority");
}

void WholePolicyNeedsRuntimeEvidence() {
    auto legacy = Legacy("default direct\n[proxy]\nexample.test\n");
    legacy.domestic_dns = "doh.pub";
    legacy.foreign_dns = "cloudflare";
    legacy.dns_intercept_unmatched = true;
    auto migrated = LegacyPolicyMigration::CreateDraft(legacy, "/tmp/migration/policy.json", "socks", "linux");
    Require(migrated.routing_equivalent && !migrated.complete,
        "Host equivalence must not imply whole-policy equivalence without runtime evidence");
    Require(migrated.report["whole_policy_equivalence"].asString() == "draft",
        "Whole-policy status must remain draft while required evidence is unavailable");
    Require(HasDiagnostic(migrated.report, "W_MIGRATE_DNS_CACHE_UNPROVEN"),
        "DNS cache parity must be identified as unproven");
    Require(HasDiagnostic(migrated.report, "W_MIGRATE_DNS_EXIT_UNPROVEN"),
        "Actual DNS egress must be identified as unproven");
    Require(HasDiagnostic(migrated.report, "W_MIGRATE_IPV6_AAAA"),
        "IPv6 and AAAA behavior must be identified as unproven");
}

void PlainOnlyProviderIsSubstituted() {
    auto legacy = Legacy("default direct\n[proxy]\nexample.test\n");
    legacy.domestic_dns = "114";
    legacy.foreign_dns = "cloudflare";
    auto migrated = LegacyPolicyMigration::CreateDraft(legacy, "/tmp/migration/policy.json", "socks", "linux");
    Require(HasDiagnostic(migrated.report, "E_MIGRATE_DNS_PROVIDER"),
        "A plain-DNS-only provider must be reported as a migration difference");
    const auto& local = migrated.policy_config["client"]["policy"]["dns"]["resolvers"]["local"]["servers"];
    Require(local.size() == 1 && std::string(local[0].asCString()) == "doh.pub",
        "Policy resolvers must not keep a provider without DoH/DoT endpoints");
}

}

int main() {
    try {
        EquivalentHostRules();
        AutoFailsClosedAndRemainsDraft();
        RegexOverlapIsStructuralCounterexample();
        WholePolicyNeedsRuntimeEvidence();
        PlainOnlyProviderIsSubstituted();
        std::cout << "legacy policy migration tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
