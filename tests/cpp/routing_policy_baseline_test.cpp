#include "support/policy_baseline.h"

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/ClientRoutingSources.h>
#include <ppp/app/client/routing/HumanRoutingRules.h>
#include <ppp/app/client/routing/TcpRoutingSelector.h>
#include <ppp/app/client/routing/UdpRoutingSelector.h>
#include <ppp/app/client/dns/DnsRedirectPlan.h>
#include <ppp/app/client/dns/HumanDnsQueryPolicy.h>

#include <iostream>

namespace routing = ppp::app::client::routing;
namespace dns = ppp::app::client::dns;
namespace baseline = policy_baseline;

namespace {
std::string FixturePath(const std::string& name) {
    baseline::Require(!name.empty() && name.find("..") == std::string::npos &&
        name.find('/') == std::string::npos && name.find('\\') == std::string::npos,
        "fixture filename must be local");
    return std::string(OPENPPP2_POLICY_FIXTURE_DIR) + "/" + name;
}

std::string ReadText(const std::string& name) {
    std::ifstream stream(FixturePath(name));
    baseline::Require(stream.is_open(), "cannot open rules fixture");
    std::ostringstream text;
    text << stream.rdbuf();
    return text.str();
}

routing::RoutingAction Action(const Json::Value& value) {
    const auto name = value.asString();
    if (name == "direct") return routing::RoutingAction::Direct;
    if (name == "proxy") return routing::RoutingAction::Proxy;
    baseline::Require(name == "auto", "invalid routing action");
    return routing::RoutingAction::Auto;
}

const char* ActionName(routing::RoutingAction action) {
    switch (action) {
    case routing::RoutingAction::Auto: return "auto";
    case routing::RoutingAction::Direct: return "direct";
    case routing::RoutingAction::Proxy: return "proxy";
    }
    throw std::runtime_error("unknown action");
}

void Overlay(Json::Value& target, const Json::Value& input) {
    for (const auto& key : input.getMemberNames()) {
        if (input[key].isObject() && target[key].isObject()) Overlay(target[key], input[key]);
        else target[key] = input[key];
    }
}

Json::Value Evaluate(const std::string& kind, const Json::Value& input) {
    Json::Value output(Json::objectValue);
    if (kind == "configuration") {
        ppp::configurations::AppConfiguration config;
        auto json = config.ToJson();
        Overlay(json, input["config"]);
        baseline::Require(config.Load(json), "AppConfiguration::Load failed");
        baseline::Require(config.Normalize(), "AppConfiguration::Normalize failed");
        auto serialized = config.ToJson();
        output["configured"] = config.client.routing.configured;
        output["proxy_only"] = config.client.proxy_only;
        output["rules"] = config.routing.rules.c_str();
        output["sniff"] = config.routing.tcp_domain_sniff;
        output["canonical"] = serialized["client"]["routing"];
        // The portable policy contract excludes the Linux-only interface name.
        // Platform adapter behavior is recorded separately in the baseline doc.
        for (auto& route : output["canonical"]["ip"]["routes"]) route.removeMember("nic");
        output["legacy_routes"] = static_cast<Json::UInt>(config.client.routes.size());
        output["legacy_peer_routes"] = static_cast<Json::UInt>(config.client.peer_routes.size());
        output["legacy_routes_emitted"] = serialized["client"].isMember("routes");
        ppp::configurations::AppConfiguration reloaded;
        baseline::Require(reloaded.Load(serialized), "configuration roundtrip failed");
        output["roundtrip"] = reloaded.ToJson()["client"]["routing"] == serialized["client"]["routing"];
        return output;
    }
    if (kind == "human") {
        routing::HumanRoutingRules rules;
        const bool loaded = input.isMember("file") ? rules.LoadFile(FixturePath(baseline::Text(input["file"].asString())))
            : rules.LoadText(baseline::Text(input["text"].asString()), "inline.rules");
        output["loaded"] = loaded;
        auto record_diagnostics = [&] {
            output["diagnostics"] = Json::Value(Json::arrayValue);
            for (const auto& diagnostic : rules.Diagnostics()) {
                Json::Value entry;
                entry["line"] = static_cast<Json::UInt>(diagnostic.line);
                entry["original_line"] = static_cast<Json::UInt>(diagnostic.original_line);
                output["diagnostics"].append(entry);
            }
        };
        record_diagnostics();
        if (!loaded) return output;
        if (input.get("geo", false).asBool()) {
            routing::HumanGeoDataSources sources;
            if (!input.get("missing_geo", false).asBool()) {
                sources.geoip.push_back(FixturePath("geoip.txt"));
                sources.geosite.push_back(FixturePath("geosite.txt"));
            }
            output["compiled"] = rules.CompileGeo(sources);
            record_diagnostics();
            const auto& stats = rules.GeoStats();
            output["geo_ipv4"] = static_cast<Json::UInt>(stats.ipv4_rules);
            output["geo_domains"] = static_cast<Json::UInt>(stats.domain_rules);
            output["ipv6_skipped"] = static_cast<Json::UInt>(stats.ipv6_skipped);
            output["unsupported_skipped"] = static_cast<Json::UInt>(stats.unsupported_skipped);
            output["source_skipped"] = static_cast<Json::UInt>(stats.source_skipped);
        }
        output["default"] = ActionName(rules.DefaultAction());
        output["domains"] = static_cast<Json::UInt>(rules.DomainRules().size());
        output["ipv4"] = static_cast<Json::UInt>(rules.Ipv4Cidrs().size());
        output["matches"] = Json::Value(Json::arrayValue);
        for (const auto& query : input["queries"]) {
            const bool ip = query.isMember("ip");
            const auto value = baseline::Text(query[ip ? "ip" : "domain"].asString());
            const auto match = ip ? rules.MatchIpv4Rule(value) : rules.MatchDomainRule(value);
            Json::Value result;
            result["valid"] = match.valid;
            result["matched"] = match.matched;
            result["action"] = ActionName(match.action);
            result["effective"] = ActionName(ip ? rules.MatchIpv4(value) : rules.MatchDomain(value));
            result["origin"] = match.matched ? (match.origin == routing::RuleOrigin::Geo ? "geo" : "explicit") : "none";
            output["matches"].append(result);
        }
        return output;
    }
    if (kind == "source") {
        const auto raw = input.isMember("file") ? "file://" + FixturePath(baseline::Text(input["file"].asString()))
            : baseline::Text(input["raw"].asString());
        const auto source = ppp::app::client::ParseClientRoutingSource(raw.c_str());
        output["kind"] = source.IsFile() ? "file" : "inline";
        if (source.IsInline()) output["value"] = source.value.c_str();
        else output["exists"] = ppp::io::File::Exists(source.value.c_str());
        return output;
    }
    if (kind == "legacy_dns") {
        ppp::unordered_map<ppp::string, dns::Rule::Ptr> suffix, full, regex;
        dns::Rule::Load(input.isMember("file") ? ReadText(baseline::Text(input["file"].asString())).c_str()
            : input["text"].asCString(), suffix, full, regex);
        if (input.isMember("append")) dns::Rule::Load(input["append"].asCString(), suffix, full, regex);
        output["entries"] = static_cast<Json::UInt>(suffix.size() + full.size() + regex.size());
        output["matches"] = Json::Value(Json::arrayValue);
        for (const auto& query : input["queries"]) {
            auto rule = dns::Rule::Get(query.asCString(), suffix, full, regex);
            Json::Value result;
            result["matched"] = !!rule;
            if (rule) {
                result["host"] = rule->Host.c_str();
                result["nic"] = rule->Nic;
                result["provider"] = rule->ProviderName.c_str();
                result["server"] = rule->Server.to_string().c_str();
            }
            output["matches"].append(result);
        }
        return output;
    }
    if (kind == "tcp") {
        routing::TcpRoutingSelectorInput request;
        request.action = Action(input["action"]);
        request.is_fake_ip = input.get("fake", false).asBool();
        request.is_resolved = input.get("resolved", true).asBool();
        request.direct_supported = input.get("direct_supported", true).asBool();
        switch (routing::TcpRoutingSelector::Select(request)) {
        case routing::TcpRoutingMode::Reject: output["mode"] = "reject"; break;
        case routing::TcpRoutingMode::ForceDirect: output["mode"] = "direct"; break;
        case routing::TcpRoutingMode::ForceProxy: output["mode"] = "proxy"; break;
        case routing::TcpRoutingMode::LegacyAuto: output["mode"] = "legacy_auto"; break;
        }
        return output;
    }
    if (kind == "udp") {
        routing::UdpRoutingSelectorInput request;
        request.action = Action(input["action"]);
        request.platform = input.get("android", false).asBool() ? routing::UdpRoutingPlatform::Android
            : routing::UdpRoutingPlatform::UnsupportedDirect;
        request.legacy_bypass = input.get("bypass", false).asBool();
        switch (routing::UdpRoutingSelector::Select(request)) {
        case routing::UdpRoutingMode::Reject: output["mode"] = "reject"; break;
        case routing::UdpRoutingMode::DirectSocket: output["mode"] = "direct"; break;
        case routing::UdpRoutingMode::Tunnel: output["mode"] = "tunnel"; break;
        }
        return output;
    }
    if (kind == "human_dns") {
        dns::HumanDnsQueryPolicyInput request;
        request.fake_ip_enabled = input.get("fake", false).asBool();
        request.strict_human_match = input.get("strict", false).asBool();
        request.is_a_query = input.get("a", true).asBool();
        request.hostname_fake_eligible = input.get("eligible", true).asBool();
        request.tcp_domain_sniff_enabled = input.get("sniff", false).asBool();
        switch (dns::HumanDnsQueryPolicy::DecideQuery(request)) {
        case dns::HumanDnsQueryMode::Continue: output["mode"] = "continue"; break;
        case dns::HumanDnsQueryMode::ResolveReal: output["mode"] = "real"; break;
        case dns::HumanDnsQueryMode::AttemptFake: output["mode"] = "attempt_fake"; break;
        case dns::HumanDnsQueryMode::Reject: output["mode"] = "reject"; break;
        }
        output["startup"] = dns::HumanDnsQueryPolicy::DecideStartup({request.fake_ip_enabled,
            input.get("domain_rules", true).asBool()}) == dns::HumanDnsStartupMode::FakeIp ? "fake" : "real";
        output["fake_result"] = dns::HumanDnsQueryPolicy::DecideFakeAttempt(
            input.get("allocated", true).asBool(), input.get("built", true).asBool()) ==
            dns::HumanDnsFakeAttemptResult::RespondFake ? "respond" : "reject";
        return output;
    }
    if (kind == "dns_plan") {
        dns::DnsRedirectPlanInput request;
        request.destination = boost::asio::ip::make_address("192.0.2.53");
        request.qtype = input.get("aaaa", false).asBool() ? dns::DnsQueryType::kAAAA : dns::DnsQueryType::kA;
        request.has_resolver = input.get("resolver", true).asBool();
        request.allow_ipv6_response = input.get("ipv6", true).asBool();
        request.intercept_unmatched = input.get("intercept", true).asBool();
        request.is_gateway_query = input.get("gateway", false).asBool();
        request.gateway_upstream_available = input.isMember("upstream");
        if (request.gateway_upstream_available) request.gateway_upstream = boost::asio::ip::make_address(input["upstream"].asCString());
        request.defer_same_destination_to_tunnel = input.get("defer", false).asBool();
        request.has_human_action = input.isMember("action");
        if (request.has_human_action) request.human_action = Action(input["action"]);
        request.human_provider = input.get("provider", "").asCString();
        if (input.isMember("rule_server") || input.isMember("rule_provider")) {
            request.rule = std::make_shared<dns::Rule>();
            request.rule->ProviderName = input.get("rule_provider", "").asCString();
            request.rule->Nic = input.get("nic", false).asBool();
            if (input.isMember("rule_server")) request.rule->Server = boost::asio::ip::make_address(input["rule_server"].asCString());
        }
        const auto result = dns::DnsRedirectPlan::Decide(request);
        switch (result.action) {
        case dns::DnsRouteAction::kBlockAAAA: output["action"] = "block_aaaa"; break;
        case dns::DnsRouteAction::kResolveProvider: output["action"] = "provider"; break;
        case dns::DnsRouteAction::kResolveUnmatched: output["action"] = "unmatched"; break;
        case dns::DnsRouteAction::kUdpRelay: output["action"] = "relay"; break;
        case dns::DnsRouteAction::kDeferToTunnel: output["action"] = "defer"; break;
        case dns::DnsRouteAction::kDrop: output["action"] = "drop"; break;
        }
        output["provider"] = result.provider_name.c_str();
        output["domestic"] = result.provider_domestic;
        output["target"] = result.udp_relay_target.to_string().c_str();
        return output;
    }
    throw std::runtime_error("unknown case kind: " + kind);
}

void SelfTest(const Json::Value& fixture) {
    // Comparator tests use the declared expectations, independently of production.
    auto report = baseline::Run(fixture, [](const std::string&, const Json::Value&) {
        return Json::Value(Json::objectValue);
    });
    for (Json::ArrayIndex i = 0; i < fixture["cases"].size(); ++i)
        report["results"][i]["output"] = fixture["cases"][i]["expected"];
    baseline::Require(baseline::Compare(fixture, report).empty(), "equal report rejected");
    auto differs = [&](Json::Value changed, const std::string& label) {
        baseline::Require(!baseline::Compare(fixture, changed).empty(), label + " not detected");
    };
    auto changed = report;
    changed["results"][0]["output"]["configured"] = !changed["results"][0]["output"]["configured"].asBool();
    differs(changed, "changed leaf");
    changed = report; changed["results"][0]["output"].removeMember("configured"); differs(changed, "missing field");
    changed = report; changed["results"][0]["output"]["extra"] = true; differs(changed, "extra field");
    changed = report; changed["results"].removeIndex(0, nullptr); differs(changed, "missing case");
    changed = report; auto extra = changed["results"][0]; extra["id"] = "extra";
    changed["results"].append(extra); differs(changed, "extra case");
    auto rejects = [](const std::function<void()>& run, const std::string& label) {
        bool rejected = false;
        try { run(); } catch (const std::runtime_error&) { rejected = true; }
        baseline::Require(rejected, label + " not rejected");
    };
    changed = report; changed["results"].append(changed["results"][0]);
    rejects([&] { baseline::Compare(fixture, changed); }, "duplicate report id");
    changed = report; changed["schema"] = 2;
    rejects([&] { baseline::Compare(fixture, changed); }, "report schema");
    changed = fixture; changed["schema"] = "1";
    rejects([&] { baseline::ValidateFixture(changed); }, "fixture schema");
    changed = fixture; changed["cases"].append(changed["cases"][0]);
    rejects([&] { baseline::ValidateFixture(changed); }, "duplicate fixture id");
    changed = report; changed["results"] = Json::Value(Json::arrayValue);
    rejects([&] { baseline::Compare(fixture, changed); }, "empty report");
    changed = report; changed["results"][0]["output"] = 1;
    rejects([&] { baseline::Compare(fixture, changed); }, "nonobject output");
    changed = report; changed["results"][0]["id"] = "";
    rejects([&] { baseline::Compare(fixture, changed); }, "empty id");
    changed = fixture; changed["cases"][0].removeMember("input");
    rejects([&] { baseline::ValidateFixture(changed); }, "missing input");
    rejects([&] { baseline::Run(fixture, [](const std::string&, const Json::Value&) {
        return Json::Value(1);
    }); }, "nonobject evaluator result");
    rejects([&] { baseline::ReadJson(FixturePath("invalid-duplicate.json")); }, "duplicate JSON key");
    rejects([&] { baseline::ReadJson(FixturePath("invalid-trailing.json")); }, "trailing JSON");
    changed = report;
    std::swap(changed["results"][0], changed["results"][1]);
    baseline::Require(baseline::Compare(fixture, changed).empty(), "report order changed meaning");
    std::vector<std::string> differences;
    Json::Value nested, actual;
    nested["array"][0]["leaf"] = true;
    actual["array"][0]["leaf"] = false;
    baseline::Diff(nested, actual, "nested", differences);
    baseline::Require(differences.size() == 1 && differences[0].find("/array/0/leaf") != std::string::npos,
        "nested array leaf not detected");
    differences.clear(); actual["array"].append(true);
    baseline::Diff(nested, actual, "nested", differences);
    baseline::Require(!differences.empty(), "array size change not detected");
    differences.clear(); actual["array"] = true;
    baseline::Diff(nested, actual, "nested", differences);
    baseline::Require(!differences.empty(), "type change not detected");
    differences.clear();
    baseline::Diff(Json::Value(1), Json::Value(Json::UInt(1)), "integer", differences);
    baseline::Require(differences.empty(), "integer signedness changed JSON meaning");
    baseline::Diff(Json::Value(-1), Json::Value(Json::UInt64(-1)), "integer", differences);
    baseline::Require(!differences.empty(), "different integer values not detected");
    differences.clear();
    baseline::Diff(Json::Value(1), Json::Value(1.0), "integer", differences);
    baseline::Require(!differences.empty(), "integer/real representation change not detected");
}
} // namespace

int main(int argc, char** argv) {
    try {
        const auto fixture = baseline::ReadJson(FixturePath("cases.json"));
        baseline::ValidateFixture(fixture);
        if (argc == 2 && std::string(argv[1]) == "--self-test") {
            SelfTest(fixture);
            std::cout << "baseline comparator self-tests passed\n";
            return 0;
        }
        baseline::Require(argc == 1 || (argc == 2 && std::string(argv[1]) == "--dump") ||
            (argc == 3 && std::string(argv[1]) == "--compare"),
            "usage: routing_policy_baseline_test [--dump | --compare report.json | --self-test]");
        const auto report = argc == 3 ? baseline::ReadJson(argv[2]) : baseline::Run(fixture, Evaluate);
        if (argc == 2) { std::cout << baseline::Encode(report) << '\n'; return 0; }
        const auto differences = baseline::Compare(fixture, report);
        for (const auto& difference : differences) std::cerr << difference << '\n';
        if (!differences.empty()) return 1;
        std::cout << fixture["cases"].size() << " offline baseline cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
