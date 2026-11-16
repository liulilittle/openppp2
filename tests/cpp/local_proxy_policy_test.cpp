#include <ppp/app/client/proxys/LocalProxyPolicyDestination.h>

#include <iostream>
#include <stdexcept>

using namespace ppp::app::client;

namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
std::shared_ptr<const policy::PolicySnapshot> Compile(const std::string& rules, const std::string& fallback = "proxy") {
    policy::PolicySource source;
    source.rules_path = "test.rules";
    source.rules_text = "default " + fallback + "\ndns direct local\ndns proxy remote\n" + rules;
    source.resolvers["local"] = {policy::PolicyAction::Direct, {"udp://192.0.2.53:53"}};
    source.resolvers["remote"] = {policy::PolicyAction::Proxy, {"tcp://198.51.100.53:53"}};
    auto compiled = policy::PolicyCompiler::Compile(source);
    Require(compiled.Ok(), "Local proxy fixture must compile");
    return compiled.snapshot;
}
}

int main() {
    try {
        const auto client_relay = boost::asio::ip::udp::endpoint(
            boost::asio::ip::make_address("127.0.0.1"), 42000);
        const auto remote = boost::asio::ip::udp::endpoint(
            boost::asio::ip::make_address("1.1.1.1"), 53);
        const auto reply = proxys::MakeSocksUdpReplyEndpoints(client_relay, remote);
        Require(reply.source == remote && reply.destination == client_relay,
            "SOCKS UDP reply must encode the remote endpoint and send to the client relay");

        auto snapshot = Compile("[direct]\n=direct.example\n192.0.2.0/24\n[proxy]\n=proxy.example\n[reject]\n=blocked.example\n");
        proxys::LocalProxyPolicyDestination destination;
        int queries = 0;
        auto resolver = [&](const std::string& domain, boost::asio::ip::address& address) {
            ++queries;
            Require(domain == "direct.example" || domain == "pending.example" || domain == "proxy.example",
                "Resolver must receive the complete original domain");
            address = boost::asio::ip::make_address("192.0.2.9");
            return true;
        };
        Require(proxys::ResolveLocalProxyPolicyDestination(snapshot, "proxy.example", false, resolver, destination),
            "Matched TCP proxy must be routable without local DNS");
        Require(queries == 0 && destination.original_domain == "proxy.example" && destination.action == policy::PolicyAction::Proxy,
            "TCP proxy must preserve domain and skip direct DNS lookup");
        Require(!proxys::ResolveLocalProxyPolicyDestination(snapshot, "blocked.example", true, resolver, destination) && queries == 0,
            "Explicit reject must stop before DNS or UDP forwarding");
        Require(proxys::ResolveLocalProxyPolicyDestination(snapshot, "direct.example", false, resolver, destination),
            "Direct domain must resolve through selected DNS service");
        Require(queries == 1 && destination.action == policy::PolicyAction::Direct && destination.original_domain == "direct.example",
            "Direct resolution must preserve domain evidence");
        Require(proxys::ResolveLocalProxyPolicyDestination(snapshot, "pending.example", false, resolver, destination),
            "Unmatched domain must complete IPv4 phase");
        Require(queries == 2 && destination.action == policy::PolicyAction::Direct,
            "IPv4 specific rule must override provisional default");
        Require(proxys::ResolveLocalProxyPolicyDestination(snapshot, "proxy.example", true, resolver, destination),
            "SOCKS UDP domain must produce IP for tunnel transport");
        Require(queries == 3 && destination.action == policy::PolicyAction::Proxy && destination.original_domain == "proxy.example",
            "SOCKS UDP must retain domain route even when IPv4 prefers direct");
        auto exception_snapshot = Compile("[proxy]\n=proxy.example\n[dns:local]\n=proxy.example\n");
        int exception_queries = 0;
        auto exception_resolver = [&](const std::string& domain, boost::asio::ip::address& address) {
            ++exception_queries;
            auto plan = policy::PolicyEvaluator::PlanDns(*exception_snapshot, domain);
            Require(plan.resolver == "local" && plan.via == policy::PolicyAction::Direct,
                "TCP proxy DNS exception must select its dedicated direct resolver");
            address = boost::asio::ip::make_address("198.51.100.20");
            return true;
        };
        Require(proxys::ResolveLocalProxyPolicyDestination(exception_snapshot, "proxy.example", true, exception_resolver, destination),
            "TCP proxy must resolve numeric connection address with policy DNS");
        Require(exception_queries == 1 && destination.original_domain == "proxy.example" &&
            destination.address.to_string() == "198.51.100.20" && destination.action == policy::PolicyAction::Proxy,
            "DNS exit exception must not change proxy traffic exit or discard original domain");
        Require(!proxys::ResolveLocalProxyPolicyDestination(exception_snapshot, "proxy.example", true,
            [](const std::string&, boost::asio::ip::address&) { return false; }, destination),
            "Proxy DNS exception failure must prevent connection establishment");
        auto failing = [&](const std::string&, boost::asio::ip::address&) { ++queries; return false; };
        Require(!proxys::ResolveLocalProxyPolicyDestination(snapshot, "direct.example", false, failing, destination),
            "Failed direct DNS resolution must refuse rather than change exit");
        Require(!proxys::ResolveLocalProxyPolicyDestination(snapshot, "proxy.example", true, failing, destination),
            "Failed proxy DNS resolution must refuse rather than use system DNS");
        const int before = queries;
        Require(proxys::ResolveLocalProxyPolicyDestination(snapshot, "198.51.100.1", false, resolver, destination) &&
            destination.action == policy::PolicyAction::Proxy && queries == before, "IP proxy must avoid DNS");
        Require(!proxys::ResolveLocalProxyPolicyDestination(snapshot, "2001:db8::1", false, resolver, destination) && queries == before,
            "IPv6 proxy targets must fail before resolving or connecting");
        Require(!proxys::ResolveLocalProxyPolicyDestination(snapshot, "0.0.0.0", false, resolver, destination),
            "Unspecified numeric proxy targets must not reach transport");
        auto fake_snapshot = Compile("[reject]\n198.18.0.0/16\n=blocked.example\n[direct]\n=direct.example\n", "reject");
        const auto fake_address = boost::asio::ip::make_address("198.18.0.1");
        auto fake_plan = proxys::PlanLocalProxyUdpDestination(fake_snapshot, "pending.example", fake_address, true);
        Require(fake_plan.needs_ip_resolution && fake_plan.action == policy::PolicyAction::Reject,
            "Provisional default reject must defer IPv4 phase to manager DNS instead of matching fake prefix");
        auto numeric_plan = proxys::PlanLocalProxyUdpDestination(fake_snapshot, "pending.example", fake_address, false);
        Require(!numeric_plan.needs_ip_resolution && numeric_plan.action == policy::PolicyAction::Reject,
            "Ordinary numeric UDP must still evaluate numeric IPv4 rules");
        fake_plan = proxys::PlanLocalProxyUdpDestination(fake_snapshot, "blocked.example", fake_address, true);
        Require(!fake_plan.needs_ip_resolution && fake_plan.action == policy::PolicyAction::Reject,
            "Explicit fake domain reject must stop before manager DNS");
        fake_plan = proxys::PlanLocalProxyUdpDestination(fake_snapshot, "direct.example", fake_address, true);
        Require(!fake_plan.needs_ip_resolution && fake_plan.action == policy::PolicyAction::Direct,
            "Fake UDP domain decision must retain original domain action without local DNS");
        Require(!proxys::ResolveLocalProxyPolicyDestination(nullptr, "proxy.example", false, resolver, destination),
            "Unavailable policy must never use legacy bypass");
        const int before_invalid = queries;
        for (const auto& domain : {std::string("bad..example"), std::string("proxy.example\0other", 19), std::string()})
            Require(!proxys::ResolveLocalProxyPolicyDestination(snapshot, domain, true, resolver, destination),
                "Malformed domain must not reach DNS service");
        Require(queries == before_invalid, "Malformed domain must fail before resolving");
        auto ipv6_resolver = [](const std::string&, boost::asio::ip::address& address) {
            address = boost::asio::ip::make_address("2001:db8::1"); return true;
        };
        Require(!proxys::ResolveLocalProxyPolicyDestination(snapshot, "direct.example", false, ipv6_resolver, destination),
            "IPv6-only DNS response must not leak into direct transport");
        std::cout << "local proxy policy tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
