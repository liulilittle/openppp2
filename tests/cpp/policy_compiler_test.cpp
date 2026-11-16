#include <ppp/app/client/policy/PolicyCompiler.h>
#include <ppp/app/client/policy/PolicyEvaluator.h>

#include <filesystem>
#include <chrono>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace ppp::app::client::policy;
namespace {
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
PolicySource Source(const std::string& body) {
    PolicySource source;
    source.rules_path = "test.rules";
    source.rules_text = "default proxy\ndns direct local\ndns proxy remote\n" + body;
    source.resolvers["local"] = {PolicyAction::Direct, {"udp://192.0.2.53:53"}};
    source.resolvers["remote"] = {PolicyAction::Proxy, {"tcp://198.51.100.53:53"}};
    return source;
}
std::shared_ptr<const PolicySnapshot> Compile(const PolicySource& source) {
    auto result = PolicyCompiler::Compile(source, 42);
    if (!result.Ok()) {
        for (const auto& d : result.diagnostics) std::cerr << d.code << ": " << d.message << '\n';
        throw std::runtime_error("Unexpected compile failure");
    }
    return result.snapshot;
}
bool Has(const PolicyCompileResult& result, const std::string& code) {
    for (const auto& d : result.diagnostics) if (d.code == code) return true;
    return false;
}
struct Files {
    std::filesystem::path root;
    Files() {
        root = std::filesystem::temp_directory_path() / ("openppp-policy-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directory(root);
    }
    ~Files() { std::error_code error; std::filesystem::remove_all(root, error); }
    std::string Write(const std::string& name, const std::string& text) {
        auto path = root / name;
        std::ofstream file(path, std::ios::binary); file << text; file.close();
        Require(bool(file), "Fixture write failed"); return path.string();
    }
};
void Priorities() {
    auto snapshot = Compile(Source(
        "[reject]\nregexp:example\\.test$\nkeyword:track\n"
        "[direct]\nexample.test\n=login.example.test\n192.0.2.0/24\n"
        "[proxy]\n*.example.test\n192.0.2.128/25\n"));
    auto eval = [&](const std::string& domain, const std::string& ip = "") { return PolicyEvaluator::Evaluate(*snapshot, domain, ip); };
    Require(eval("LOGIN.EXAMPLE.TEST.").action == PolicyAction::Direct, "Exact must win suffix and regex");
    Require(eval("example.test").action == PolicyAction::Direct, "Suffix must win regex (different from legacy)");
    Require(eval("www.example.test").action == PolicyAction::Proxy, "Subdomain tie must win suffix");
    Require(eval("notexample.test").action == PolicyAction::Reject, "Suffix must respect label boundary");
    Require(eval("track.other.test").action == PolicyAction::Reject, "Keyword index match");
    Require(eval("example.test", "192.0.2.200").action == PolicyAction::Direct, "Domain must win IP");
    Require(eval("elsewhere.test", "192.0.2.200").action == PolicyAction::Proxy, "IPv4 longest prefix");
    Require(eval("elsewhere.test", "192.0.2.1").action == PolicyAction::Direct, "IP fallback after unmatched domain");
    Require(eval("elsewhere.test").needs_ip_resolution, "Domain-only explain must require IP before final route");
    Require(eval("", "203.0.113.1").reason == "default", "Unmatched IP falls back");
    Require(eval("", "192.0.2.1.").reason == "invalid_ipv4" && eval("", "192.0.2.1.").action == PolicyAction::Reject, "Trailing-dot IP is rejected");
    Require(eval("bad..domain").reason == "invalid_domain" && eval("bad..domain").action == PolicyAction::Reject, "Invalid domain must fail closed");
    Require(eval("example.test", "2001:db8::1").action == PolicyAction::Reject, "Matched domain cannot override IPv6 block");
    Require(eval("example.test", "invalid-ip").action == PolicyAction::Reject, "Matched domain cannot override invalid IPv4 rejection");
    Require(snapshot->Version() == 42, "Version provenance");
    auto ordered = Compile(Source("[direct]\nregexp:^overlap\n[reject]\nregexp:overlap.*\n"));
    Require(PolicyEvaluator::Evaluate(*ordered, "overlap.test").action == PolicyAction::Direct, "Regex declaration order");
}
void Dns() {
    auto snapshot = Compile(Source("[direct]\nexample.test\n[reject]\n=deny.example.test\n[dns:remote]\n=example.test\n"));
    auto plan = PolicyEvaluator::PlanDns(*snapshot, "example.test");
    Require(plan.action == PolicyAction::Direct && plan.via == PolicyAction::Proxy && plan.resolver == "remote", "DNS exception can differ from route");
    Require(PolicyEvaluator::PlanDns(*snapshot, "child.example.test").resolver == "local", "DNS follows domain route");
    Require(PolicyEvaluator::PlanDns(*snapshot, "deny.example.test").rejected, "Business reject precedes DNS exception");
    Require(PolicyEvaluator::PlanDns(*snapshot, "unmatched.test").resolver == "remote", "DNS default resolver");
    auto rejected = Compile(Source("[direct]\n192.0.2.0/24\n"));
    Require(PolicyEvaluator::PlanDns(*rejected, "unmatched.test").resolver == "remote", "IP rules cannot influence DNS plan");
}
void ErrorsAndSnapshot() {
    for (const std::string body : {"[direct]\n=duplicate.test\n[proxy]\n=duplicate.test\n", "[direct]\n2001:db8::/32\n",
            "[direct]\nregexp:[\n", "[dns:local]\n192.0.2.0/24\n", "[direct]\nset:missing\n", "[auto]\nexample.test\n"}) {
        Require(!PolicyCompiler::Compile(Source(body)).Ok(), "Invalid condition must fail compilation");
    }
    auto duplicate = PolicyCompiler::Compile(Source("[direct]\n=duplicate.test\n=duplicate.test\n"));
    Require(duplicate.Ok() && duplicate.snapshot->RuleCount() == 1 && Has(duplicate, "duplicate_rule"), "Identical duplicate dedup warning");
    auto prior = duplicate.snapshot;
    auto candidate = PolicyCompiler::Compile(Source("[direct]\nregexp:[\n"));
    if (candidate.Ok()) prior = candidate.snapshot;
    Require(PolicyEvaluator::Evaluate(*prior, "duplicate.test").action == PolicyAction::Direct, "Failed candidate cannot replace prior immutable snapshot");
    auto source = Source("[direct]\nexample.test\n");
    auto stable = Compile(source); source.rules_text.clear(); source.resolvers.clear();
    Require(PolicyEvaluator::PlanDns(*stable, "example.test").resolver == "local", "Snapshot owns resolver configuration");
    auto no_default = Source(""); no_default.rules_text = "dns direct local\ndns proxy remote\n";
    Require(PolicyCompiler::Compile(no_default).Ok(), "Absent default uses proxy");
    Require(!PolicyCompiler::Compile(Source("[direct]\n300.0.0.1\n")).Ok(), "Invalid numeric IP cannot become domain");
}
void GeoAndSourcePriority() {
    Files files;
    auto source = Source("[proxy]\nset:first\nset:ips\n[reject]\nset:second\n[direct]\nexample.test\n192.0.0.0/16\n");
    source.rule_sets["first"] = {"geosite-text", files.Write("first.txt", "full:login.example.test\ndomain:tie.test\nplain:tracker\nregexp:^geo\\.\n"), "", "", "", ""};
    source.rule_sets["second"] = {"geosite-text", files.Write("second.txt", "domain:tie.test\ndomain:example.test\n"), "", "", "", ""};
    source.rule_sets["ips"] = {"geoip-text", files.Write("ip.txt", "192.0.2.0/24\n2001:db8::/32\n"), "", "", "", ""};
    auto compiled = PolicyCompiler::Compile(source);
    Require(compiled.Ok(), "Geo source compile");
    const auto& snapshot = *compiled.snapshot;
    Require(PolicyEvaluator::Evaluate(snapshot, "login.example.test").action == PolicyAction::Direct, "Explicit suffix wins set exact");
    Require(PolicyEvaluator::Evaluate(snapshot, "tie.test").action == PolicyAction::Proxy, "Set reference order resolves equal condition");
    Require(PolicyEvaluator::Evaluate(snapshot, "adtracker.test").action == PolicyAction::Proxy, "Geo Plain materializes keywords");
    Require(PolicyEvaluator::Evaluate(snapshot, "geo.test").action == PolicyAction::Proxy, "Geo regex materializes");
    Require(PolicyEvaluator::Evaluate(snapshot, "", "192.0.2.2").action == PolicyAction::Direct, "Explicit broad IP wins narrower set IP");
    Require(snapshot.SkippedIpv6() == 1, "Geo IPv6 skipped counter");
    Require(Has(compiled, "shadowed_condition"), "Set collision diagnostic");
    source.rules_text += "[reject]\nexample.test\n";
    Require(!PolicyCompiler::Compile(source).Ok(), "Explicit conflict detected even with earlier set duplicate");
    source = Source("[dns:local]\nset:ips\n");
    source.rule_sets["ips"] = {"geoip-text", files.Write("dns-ip.txt", "192.0.2.0/24\n"), "", "", "", ""};
    Require(Has(PolicyCompiler::Compile(source), "dns_ip_condition"), "DNS IP rule-set forbidden");
    source = Source("[direct]\nset:missing\n");
    source.rule_sets["missing"] = {"geoip-dat", (files.root / "missing.dat").string(), "", "test", "", ""};
    Require(Has(PolicyCompiler::Compile(source), "rule_set_unavailable"), "Unavailable Geo resource fails snapshot");
    auto lan = Compile(Source("[direct]\nlan\n"));
    Require(PolicyEvaluator::Evaluate(*lan, "", "10.1.2.3").action == PolicyAction::Direct, "Versioned LAN expansion");
}

void MaterializedSources() {
    Files files;
    auto source = Source("[direct]\nset:sites\nset:ips\n");
    auto& sites = source.rule_sets["sites"];
    sites.format = "geosite-text";
    sites.path = files.Write("sites.txt", "full:replacement.test\n");
    sites.text = "full:original.test\n";
    sites.materialized = true;
    auto& ips = source.rule_sets["ips"];
    ips.format = "geoip-text";
    ips.path = (files.root / "deleted.txt").string();
    ips.text = "192.0.2.0/24\n";
    ips.materialized = true;
    auto snapshot = Compile(source);
    Require(PolicyEvaluator::Evaluate(*snapshot, "original.test").action == PolicyAction::Direct,
        "Materialized GeoSite must use checked bytes despite replaced file");
    Require(PolicyEvaluator::Evaluate(*snapshot, "replacement.test", "203.0.113.1").action == PolicyAction::Proxy,
        "Replacement file content must not enter snapshot");
    Require(PolicyEvaluator::Evaluate(*snapshot, "", "192.0.2.7").action == PolicyAction::Direct,
        "Materialized GeoIP must compile despite missing file");
    sites.text.clear();
    ips.text.clear();
    snapshot = Compile(source);
    Require(snapshot->RuleCount() == 0, "Empty materialized source must not fall back to file");
}
}
int main() {
    try { Priorities(); Dns(); ErrorsAndSnapshot(); GeoAndSourcePriority(); MaterializedSources(); std::cout << "policy compiler tests passed\n"; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    return 0;
}
