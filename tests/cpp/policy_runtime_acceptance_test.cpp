#include <ppp/app/client/policy/PolicyRuntime.h>
#include <ppp/app/client/policy/PolicyTcpFlow.h>
#include <ppp/app/client/proxys/LocalProxyPolicyDestination.h>

#include <atomic>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace ppp::app::client::policy;
namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
PolicySource Source(PolicyAction action = PolicyAction::Direct) {
    PolicySource source;
    source.rules_path = "offline-acceptance.rules";
    source.rules_text = "default proxy\ndns direct local\ndns proxy remote\n";
    source.rules_text += action == PolicyAction::Direct ? "[direct]\n" : "[proxy]\n";
    source.rules_text += "=same.example.test\n192.0.2.0/24\n[reject]\n=blocked.example.test\n";
    source.rules_text += "[dns:remote]\n=same.example.test\n=blocked.example.test\n";
    source.resolvers["local"] = {PolicyAction::Direct, {"udp://192.0.2.53:53"}};
    source.resolvers["remote"] = {PolicyAction::Proxy, {"tcp://198.51.100.53:53"}};
    return source;
}
void PublicationAndRollback() {
    PolicyRuntime runtime;
    Require(!runtime.GetSnapshot(), "A new runtime must have no active policy");
    Require(runtime.Evaluate("same.example.test", "192.0.2.1").action == PolicyAction::Reject,
        "Uninitialized flow decision must fail closed");
    Require(runtime.PlanDns("same.example.test").rejected, "Uninitialized DNS must fail closed");
    auto first = runtime.Prepare(Source());
    Require(first.Ok() && !runtime.GetSnapshot(), "Preparation must not publish policy");
    Require(runtime.Commit(first), "Valid prepared policy must publish");
    auto active = runtime.GetSnapshot();
    auto stale = runtime.Prepare(Source(PolicyAction::Proxy));
    auto latest = runtime.Prepare(Source());
    Require(runtime.Commit(latest), "Latest candidate must publish");
    Require(!runtime.Commit(stale), "Delayed older candidate cannot overwrite newer policy");
    Require(!runtime.Commit(latest), "Published candidate cannot publish twice");
    auto bad_source = Source(); bad_source.rules_text += "[invalid]\nbroken\n";
    auto bad = runtime.Prepare(bad_source);
    auto retained = runtime.GetSnapshot();
    Require(!bad.Ok() && !runtime.Commit(bad), "Compilation failure must not publish");
    Require(runtime.GetSnapshot() == retained, "Failed compilation must preserve active policy identity");
    PolicyRuntime foreign;
    Require(!foreign.Commit(first), "Candidates must be bound to their creating runtime");
    auto altered = runtime.Prepare(Source()); altered.snapshot = first.snapshot;
    Require(!runtime.Commit(altered), "Public candidate fields cannot substitute another snapshot");
    Require(PolicyEvaluator::Evaluate(*active, "same.example.test").action == PolicyAction::Direct,
        "Retained reader snapshot remains valid across publication");
    Json::Value invalid(Json::objectValue);
    Require(!runtime.Prepare(invalid, "/tmp/offline-policy/config.json").Ok(),
        "Invalid full configuration must fail preparation");
    Require(runtime.GetSnapshot() == retained, "Source failure must retain active snapshot");
}
void RouteAndDnsSemantics() {
    PolicyRuntime runtime;
    Require(runtime.Commit(runtime.Prepare(Source())), "Semantic fixture must publish");
    auto snapshot = runtime.GetSnapshot();
    auto route = runtime.Evaluate("same.example.test", "198.51.100.8");
    Require(route.action == PolicyAction::Direct && route.matched && route.reason == "domain",
        "Preserved original domain must govern route before resolved IP");
    Require(route.version == snapshot->Version() && !route.rule_id.empty(),
        "Decision must retain policy version and rule identity");
    Require(runtime.Evaluate("blocked.example.test", "192.0.2.8").action == PolicyAction::Reject,
        "Domain reject cannot be overridden by direct destination IP");
    Require(runtime.Evaluate("unmatched.example.test", "192.0.2.8").action == PolicyAction::Direct,
        "Resolved IP must govern unmatched domain");
    Require(runtime.Evaluate("unmatched.example.test").needs_ip_resolution,
        "Unresolved unmatched domain must remain provisional");
    auto dns = runtime.PlanDns("same.example.test");
    Require(!dns.rejected && dns.action == PolicyAction::Direct && dns.via == PolicyAction::Proxy &&
        dns.resolver == "remote", "DNS exception must retain explicit exit independent of business route");
    Require(runtime.PlanDns("blocked.example.test").rejected, "DNS exception cannot bypass domain reject");
    Require(runtime.Evaluate("same.example.test", "2001:db8::1").action == PolicyAction::Reject,
        "Matched domain cannot bypass unsupported IPv6 destination");
    Require(runtime.Evaluate("same.example.test", "bad-ip").action == PolicyAction::Reject,
        "Matched domain cannot bypass malformed destination validation");
}
void ConcurrentPublication() {
    PolicyRuntime runtime;
    Require(runtime.Commit(runtime.Prepare(Source())), "Concurrent fixture must publish");
    std::atomic<bool> stop{false}, failed{false};
    std::vector<std::thread> readers;
    for (unsigned i = 0; i < 4; ++i) readers.emplace_back([&] {
        while (!stop.load()) {
            const auto snapshot = runtime.GetSnapshot();
            const auto route = PolicyEvaluator::Evaluate(*snapshot, "same.example.test", "192.0.2.7");
            const auto dns = PolicyEvaluator::PlanDns(*snapshot, "same.example.test");
            if (route.version != snapshot->Version() || dns.version != snapshot->Version() ||
                !route.matched || dns.resolver != "remote" || dns.rejected ||
                (route.action != PolicyAction::Direct && route.action != PolicyAction::Proxy)) failed = true;
        }
    });
    bool published = true;
    for (unsigned i = 0; i < 100; ++i) {
        auto candidate = runtime.Prepare(Source(i % 2 ? PolicyAction::Direct : PolicyAction::Proxy));
        published = runtime.Commit(candidate) && published;
    }
    stop = true;
    for (auto& reader : readers) reader.join();
    Require(published && !failed.load(), "Readers must observe complete immutable snapshots during publication");
}
void EntryPointAgreement() {
    PolicyRuntime runtime;
    Require(runtime.Commit(runtime.Prepare(Source())), "Entry point fixture must publish");
    const auto snapshot = runtime.GetSnapshot();
    unsigned resolutions = 0;
    const auto resolve = [&](const std::string& domain, boost::asio::ip::address& address) {
        ++resolutions;
        if (domain == "resolution-fails.example.test") return false;
        address = boost::asio::ip::make_address("192.0.2.8");
        return true;
    };
    const auto local = [&](const std::string& host, bool udp,
        ppp::app::client::proxys::LocalProxyPolicyDestination& target) {
        return ppp::app::client::proxys::ResolveLocalProxyPolicyDestination(snapshot, host, udp, resolve, target);
    };
    for (bool require_address : {false, true}) {
        ppp::app::client::proxys::LocalProxyPolicyDestination target;
        Require(local("same.example.test", require_address, target) &&
            target.action == PolicyAction::Direct && target.original_domain == "same.example.test",
            "HTTP/SOCKS local decision must preserve original direct-domain evidence");
        PolicyTcpFlowInput input;
        input.hostname = target.original_domain; input.ipv4 = target.address.to_string();
        auto tun = EvaluatePolicyTcpFlow(snapshot, input);
        Require(tun.disposition == PolicyTcpDisposition::Direct && tun.policy.action == target.action,
            "TUN TCP and local proxy must agree on domain action after resolution");
        input.direct_supported = false;
        Require(EvaluatePolicyTcpFlow(snapshot, input).disposition == PolicyTcpDisposition::Reject,
            "Unsupported direct cannot silently become proxy");
    }
    ppp::app::client::proxys::LocalProxyPolicyDestination blocked;
    const auto before_reject = resolutions;
    Require(!local("blocked.example.test", true, blocked) && resolutions == before_reject,
        "Reject must avoid resolver and every outgoing connection attempt");
    Require(!local("resolution-fails.example.test", false, blocked),
        "Failed resolution cannot fall back to a proxy action");
    Require(!local("2001:db8::1", false, blocked), "Local proxy must reject IPv6 literals");
    PolicyTcpFlowInput invalid;
    invalid.hostname = "same.example.test"; invalid.ipv4 = "invalid";
    Require(EvaluatePolicyTcpFlow(snapshot, invalid).disposition == PolicyTcpDisposition::Reject,
        "TUN matched domain cannot bypass malformed IP validation");
    invalid.ipv4 = "192.0.2.8"; invalid.is_fake_ip = true; invalid.is_resolved = false;
    Require(EvaluatePolicyTcpFlow(snapshot, invalid).disposition == PolicyTcpDisposition::Reject,
        "Unresolved Fake-IP cannot enter a route");
}
}
int main() {
    try {
        PublicationAndRollback(); RouteAndDnsSemantics(); ConcurrentPublication(); EntryPointAgreement();
        std::cout << "policy runtime acceptance tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
    return 0;
}
