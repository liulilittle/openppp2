#include <ppp/app/client/policy/PolicyTcpFlow.h>

#include <iostream>
#include <stdexcept>

using namespace ppp::app::client::policy;
namespace {
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
std::shared_ptr<const PolicySnapshot> Snapshot(const std::string& body, std::uint64_t version = 1) {
    PolicySource source;
    source.rules_path = "tun-tcp-test.rules";
    source.rules_text = "default reject\ndns direct local\ndns proxy remote\n" + body;
    source.resolvers["local"] = {PolicyAction::Direct, {"udp://192.0.2.53:53"}};
    source.resolvers["remote"] = {PolicyAction::Proxy, {"tcp://198.51.100.53:53"}};
    auto compiled = PolicyCompiler::Compile(source, version);
    Require(compiled.Ok(), "Test policy compilation");
    return compiled.snapshot;
}
void DecisionAndDomainEvidence() {
    auto snapshot = Snapshot("[proxy]\n192.0.2.0/24\n[direct]\n=direct.test\n[reject]\n=deny.test\n", 71);
    PolicyTcpFlowInput input;
    input.ipv4 = "192.0.2.5";
    auto result = EvaluatePolicyTcpFlow(snapshot, input);
    Require(result.disposition == PolicyTcpDisposition::Proxy, "IPv4 proxy does not use legacy bypass");
    input.hostname = "DIRECT.TEST.";
    result = EvaluatePolicyTcpFlow(snapshot, input);
    Require(result.disposition == PolicyTcpDisposition::Direct && result.policy.version == 71 &&
        result.policy.reason == "domain", "Sniffed/Fake-IP hostname wins conflicting IP policy");
    input.hostname = "deny.test";
    result = EvaluatePolicyTcpFlow(snapshot, input);
    Require(result.disposition == PolicyTcpDisposition::Reject && result.reason == "policy_reject",
        "Reject never downgrades to direct or proxy");
    input.hostname = "unmatched.test";
    Require(EvaluatePolicyTcpFlow(snapshot, input).disposition == PolicyTcpDisposition::Proxy,
        "Unmatched sniffed hostname uses IP policy");
    input.ipv4 = "203.0.113.9";
    Require(EvaluatePolicyTcpFlow(snapshot, input).disposition == PolicyTcpDisposition::Reject,
        "Unmatched sniff/unsupported sniff uses configured default");
    input.hostname = "direct.test";
    Require(EvaluatePolicyTcpFlow(snapshot, input).disposition == PolicyTcpDisposition::Direct,
        "Domain route overrides rejecting IP/default after sniff");
}
void FailClosedAndPlatform() {
    auto snapshot = Snapshot("[direct]\n=direct.test\n[proxy]\n=proxy.test\n");
    PolicyTcpFlowInput input;
    input.hostname = "proxy.test";
    input.ipv4 = "192.0.2.1";
    Require(EvaluatePolicyTcpFlow(nullptr, input).reason == "policy_unavailable",
        "Enabled policy with missing snapshot fails closed");
    input.ipv6 = true;
    Require(EvaluatePolicyTcpFlow(snapshot, input).reason == "unsupported_ipv6",
        "IPv6 rejects even with matching proxy domain");
    input.ipv6 = false;
    input.is_fake_ip = true;
    input.is_resolved = false;
    auto pending = EvaluatePolicyTcpFlow(snapshot, input);
    Require(pending.needs_dns_resolution && pending.disposition == PolicyTcpDisposition::Reject &&
        pending.reason == "needs_policy_resolution",
        "Known unresolved fake identity awaits policy DNS before transport");
    input.ipv4 = "invalid";
    Require(!EvaluatePolicyTcpFlow(snapshot, input).needs_dns_resolution,
        "Invalid Fake-IP identity address cannot initiate DNS");
    input.ipv4 = "192.0.2.1";
    input.hostname = "bad..test";
    Require(!EvaluatePolicyTcpFlow(snapshot, input).needs_dns_resolution,
        "Malformed fake identity cannot initiate DNS");
    input.hostname = "direct.test";
    input.direct_supported = false;
    Require(EvaluatePolicyTcpFlow(snapshot, input).reason == "unsupported_direct" &&
        !EvaluatePolicyTcpFlow(snapshot, input).needs_dns_resolution,
        "Unsupported direct fake identity fails before DNS");
    input.direct_supported = true;
    input.is_resolved = true;
    input.hostname.clear();
    Require(EvaluatePolicyTcpFlow(snapshot, input).reason == "unresolved_fake_ip",
        "Fake-IP must retain domain evidence");
    input.hostname = "proxy.test";
    input.direct_supported = false;
    Require(EvaluatePolicyTcpFlow(snapshot, input).disposition == PolicyTcpDisposition::Proxy,
        "Proxy remains usable when platform direct is unsupported");
    input.hostname = "direct.test";
    auto result = EvaluatePolicyTcpFlow(snapshot, input);
    Require(result.disposition == PolicyTcpDisposition::Reject && result.reason == "unsupported_direct",
        "iOS direct rejection cannot become proxy");
    input.direct_supported = true;
    Require(EvaluatePolicyTcpFlow(snapshot, input).disposition == PolicyTcpDisposition::Direct,
        "Resolved Fake-IP preserves direct domain policy");
    input.ipv4 = "invalid";
    Require(EvaluatePolicyTcpFlow(snapshot, input).disposition == PolicyTcpDisposition::Reject,
        "Malformed endpoint fails even when domain route matches");
    input.ipv4 = "2001:db8::1";
    Require(EvaluatePolicyTcpFlow(snapshot, input).reason == "unsupported_ipv6",
        "IPv6 endpoint cannot hide behind matching domain and incorrect IPv6 flag");
    input.is_fake_ip = false;
    input.hostname = "unmatched.test";
    input.ipv4 = "bad-ip";
    Require(EvaluatePolicyTcpFlow(snapshot, input).reason == "unresolved_destination",
        "Invalid IPv4 cannot become default proxy/direct");
    input.ipv4.clear();
    Require(EvaluatePolicyTcpFlow(snapshot, input).reason == "unresolved_destination",
        "Domain-only decision must resolve destination before forwarding");
}
void FlowPinsSnapshot() {
    auto current = Snapshot("[direct]\nexample.test\n", 3);
    const auto flow = current;
    current = Snapshot("[reject]\nexample.test\n", 4);
    PolicyTcpFlowInput input;
    input.hostname = "example.test";
    input.ipv4 = "192.0.2.6";
    auto old = EvaluatePolicyTcpFlow(flow, input);
    auto replacement = EvaluatePolicyTcpFlow(current, input);
    Require(old.disposition == PolicyTcpDisposition::Direct && old.policy.version == 3 &&
        replacement.disposition == PolicyTcpDisposition::Reject && replacement.policy.version == 4,
        "Accepted TCP flow keeps snapshot while later accepts observe replacement");
    input.is_fake_ip = true;
    input.is_resolved = false;
    Require(EvaluatePolicyTcpFlow(flow, input).needs_dns_resolution &&
        !EvaluatePolicyTcpFlow(current, input).needs_dns_resolution,
        "Pending fake identity uses old snapshot even when replacement rejects its domain");
    input.is_resolved = true;
    input.ipv4 = "203.0.113.9";
    Require(EvaluatePolicyTcpFlow(flow, input).disposition == PolicyTcpDisposition::Direct,
        "Policy DNS result resumes domain-first route under same snapshot");
}
}
int main() {
    try {
        DecisionAndDomainEvidence(); FailClosedAndPlatform(); FlowPinsSnapshot();
        std::cout << "policy TCP flow tests passed\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    return 0;
}
