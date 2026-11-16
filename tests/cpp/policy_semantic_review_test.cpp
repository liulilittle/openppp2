#include <ppp/app/client/policy/PolicyCompiler.h>
#include <ppp/app/client/policy/PolicyEvaluator.h>
#include <ppp/app/client/policy/PolicySourceLoader.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace ppp::app::client::policy;

namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
PolicySource Source(const std::string& body, const std::string& fallback = "proxy") {
    PolicySource source;
    source.rules_path = "semantic.rules";
    source.rules_text = "default " + fallback + "\ndns direct local\ndns proxy remote\n" + body;
    source.resolvers["local"] = {PolicyAction::Direct, {"udp://192.0.2.53:53"}};
    source.resolvers["remote"] = {PolicyAction::Proxy, {"tcp://198.51.100.53:53"}};
    return source;
}
void NumericDomainRules() {
    for (const auto& condition : {"=192.0.2.1", "full:192.0.2.1", "*.192.0.2.1", "=300.0.0.1"}) {
        auto result = PolicyCompiler::Compile(Source("[direct]\n" + std::string(condition) + "\n"));
        Require(!result.Ok(), "Numeric IPv4 literals must not compile as domain conditions");
    }
    for (const char control : {'\0', '\x01', '\x1f', '\x7f'}) {
        auto result = PolicyCompiler::Compile(Source("[direct]\nkeyword:a" + std::string(1, control) + "b\n"));
        Require(!result.Ok(), "Keyword ASCII control bytes must be rejected");
    }
}
void ProvenanceAndDns() {
    auto result = PolicyCompiler::Compile(Source(
        "[reject]\n=blocked.example\n[dns:local]\n=blocked.example\n=allowed.example\n", "reject"));
    Require(result.Ok(), "DNS exception fixture must compile");
    const auto& snapshot = *result.snapshot;
    auto blocked = PolicyEvaluator::PlanDns(snapshot, "blocked.example");
    Require(blocked.rejected && blocked.line == 5 && blocked.file == "semantic.rules", "Matched reject precedes DNS exception and retains business provenance");
    auto exception = PolicyEvaluator::PlanDns(snapshot, "allowed.example");
    Require(!exception.rejected && exception.resolver == "local" && exception.line == 8, "DNS exception precedes default rejection and retains exception provenance");
    auto fallback = PolicyEvaluator::PlanDns(snapshot, "unknown.example");
    Require(fallback.rejected && fallback.source == "default" && fallback.line == 1, "Default rejection retains default provenance");
    auto pending = PolicyEvaluator::Evaluate(snapshot, "unknown.example");
    Require(pending.needs_ip_resolution && !pending.matched && pending.line == 1, "Domain-only unmatched result must remain provisional");
    auto matched = PolicyEvaluator::Evaluate(snapshot, "blocked.example", "192.0.2.1");
    Require(matched.matched && !matched.needs_ip_resolution && matched.line == 5, "Domain decision must retain source line and override IPv4");
    auto ordinary = PolicyCompiler::Compile(Source(""));
    Require(ordinary.Ok(), "Invalid DNS input fixture must compile");
    for (const auto* invalid : {"", "bad..example", "bad_name.example", "192.0.2.1"}) {
        auto plan = PolicyEvaluator::PlanDns(*ordinary.snapshot, invalid);
        Require(plan.rejected && plan.resolver.empty(), "Invalid DNS domain cannot select a resolver");
    }
}
void ConflictLocations() {
    auto result = PolicyCompiler::Compile(Source("[direct]\n=conflict.example\n[proxy]\n=conflict.example\n"));
    Require(!result.Ok(), "Conflicting explicit conditions must fail");
    bool first = false, second = false;
    for (const auto& diagnostic : result.diagnostics) {
        if (diagnostic.code != "conflicting_rule") continue;
        first = first || diagnostic.line == 5;
        second = second || diagnostic.line == 7;
    }
    Require(first && second, "Conflict diagnostics must identify both declarations");
}
void BoundedRead() {
    const auto path = std::filesystem::temp_directory_path() / ("openppp-policy-limit-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".json");
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() { std::error_code error; std::filesystem::remove(path, error); }
    } cleanup{path};
    std::ofstream file(path, std::ios::binary);
    file.put(' '); file.close();
    Require(bool(file), "Size-limit fixture creation failed");
    std::filesystem::resize_file(path, 64u * 1024u * 1024u + 1u);
    auto result = PolicySourceLoader::LoadFile(path.string());
    Require(!result.Ok() && !result.diagnostics.empty() &&
        result.diagnostics.front().code == "E_POLICY_SOURCE_UNAVAILABLE", "Oversize files must fail at source loading before JSON parsing");
}
}

int main() {
    try {
        NumericDomainRules();
        ProvenanceAndDns();
        ConflictLocations();
        BoundedRead();
        std::cout << "policy semantic review tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
