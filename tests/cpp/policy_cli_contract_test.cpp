#include <ppp/app/ApplicationPolicyCommand.h>
#include <ppp/app/client/policy/PolicySourceLoader.h>
#include <ppp/app/client/policy/PolicyStatusFile.h>
#include <ppp/app/client/policy/PolicyUpdateService.h>
#include <ppp/app/client/policy/DurablePolicyBundle.h>
#include <ppp/app/client/policy/LegacyPolicyAdapter.h>
#include <ppp/configurations/AppConfiguration.h>
#include <json/json.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace {
void Require(bool value, const std::string& message) {
    if (!value) throw std::runtime_error(message);
}

struct Result {
    std::optional<int> code;
    std::string output, error;
    Json::Value Report() const {
        Json::CharReaderBuilder reader;
        Json::Value report;
        Json::String errors;
        std::istringstream input(output);
        Require(Json::parseFromStream(reader, input, &report, &errors),
            "CLI output must be JSON (exit " + std::to_string(code.value_or(-1)) + "): " + std::string(errors.data(), errors.size()));
        Require(code.has_value(), "Policy command must be handled");
        Require(report["schema"].asInt() == 1, "Report schema must be 1");
        Require(report["exit_code"].asInt() == *code, "Report and process exit must agree");
        const auto status = report["status"].asString();
        Require(status == (*code == 0 ? "ok" : "error") ||
            (*code == 5 && status == "draft") || (*code == 0 && status == "equivalent"),
            "Report status must agree with command outcome");
        Require(report["plan_only"].asBool() && !report["runtime_installed"].asBool(), "Offline report must disclose plan-only behavior");
        Require(error.empty(), "JSON report must use stdout only");
        return report;
    }
};

Result Run(const std::vector<std::string>& args) {
    std::vector<const char*> pointers;
    for (const auto& arg : args) pointers.push_back(arg.c_str());
    std::ostringstream output, error;
    auto code = ppp::app::ApplicationPolicyCommand::Dispatch(
        static_cast<int>(pointers.size()), pointers.data(), output, error);
    return {code, output.str(), error.str()};
}

std::string ReadFile(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

struct Fixture {
    std::filesystem::path directory = std::filesystem::temp_directory_path() /
        ("openppp-policy-cli-contract-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Fixture() {
        Require(std::filesystem::create_directories(directory), "Fixture directory creation failed");
        Rules("default direct\ndns direct local\ndns proxy remote\n[proxy]\n192.0.2.0/24\n=proxy.example\n[dns:remote]\n=exception.example\n");
        Save(Config());
    }
    ~Fixture() { std::error_code ec; std::filesystem::remove_all(directory, ec); }
    void Write(const std::string& name, const std::string& text) {
        std::ofstream stream(directory / name, std::ios::binary);
        stream << text;
        Require(static_cast<bool>(stream), "Fixture write failed");
    }
    void Rules(const std::string& text) { Write("routing.rules", text); }
    Json::Value Config() const {
        Json::Value config;
        auto& policy = config["client"]["policy"];
        policy["version"] = 2;
        policy["rules"]["path"] = "routing.rules";
        policy["dns"]["resolvers"]["local"]["via"] = "direct";
        policy["dns"]["resolvers"]["local"]["servers"].append("udp://192.0.2.53:53");
        policy["dns"]["resolvers"]["remote"]["via"] = "proxy";
        policy["dns"]["resolvers"]["remote"]["servers"].append("tcp://198.51.100.53:53");
        return config;
    }
    void Save(const Json::Value& config) {
        Json::StreamWriterBuilder writer;
        auto text = Json::writeString(writer, config);
        Write("client.json", std::string(text.data(), text.size()));
    }
    std::vector<std::string> Args(const std::vector<std::string>& tail = {}, const std::string& command = "explain") const {
        std::vector<std::string> args = {"ppp", "policy", command, "--config", (directory / "client.json").string(),
            "--runtime", "tun", "--platform", "linux", "--json"};
        args.insert(args.end(), tail.begin(), tail.end());
        return args;
    }
};

void ErrorPair(const std::vector<std::string>& args, int code, const std::string& diagnostic = {}) {
    auto result = Run(args);
    Require(result.code == code, "Unexpected JSON exit code");
    auto report = result.Report();
    Require(!report["diagnostics"].empty(), "Error must have diagnostics");
    if (!diagnostic.empty()) Require(report["diagnostics"][0]["code"].asCString() == diagnostic, "Unexpected error code");
    auto text_args = args;
    text_args.erase(std::remove(text_args.begin(), text_args.end(), "--json"), text_args.end());
    auto text = Run(text_args);
    Require(text.code == code && text.output.empty(), "Text error must preserve exit and use stderr");
    Require(text.error.find(": error") != std::string::npos, "Text output must expose error status");
    for (const auto& item : report["diagnostics"])
        Require(text.error.find(item["code"].asCString()) != std::string::npos, "Text and JSON diagnostic codes must agree");
}

void ProvisionalAndProvenance() {
    Fixture fixture;
    auto pending = Run(fixture.Args({"--domain", "unmatched.example", "--network", "udp"}));
    Require(pending.code == 0, "Provisional default direct must not fail Linux UDP capability check");
    auto report = pending.Report();
    Require(report["route"]["provisional"].asBool() && report["route"]["needs_ip"].asBool(), "Unresolved domain must be provisional");
    Require(report["route"]["source"].asString() == "default" && report["route"]["line"].asUInt() == 1, "Default route provenance missing");
    auto direct = Run(fixture.Args({"--domain", "unmatched.example", "--ip", "198.51.100.1", "--network", "udp"}));
    Require(direct.code == 0 && direct.Report()["route"]["action"].asString() == "direct", "Resolved Linux direct UDP is supported by the shared flow path");
    auto unsupported = fixture.Args({"--domain", "unmatched.example", "--ip", "198.51.100.1", "--network", "udp"});
    std::replace(unsupported.begin(), unsupported.end(), std::string("linux"), std::string("ios"));
    ErrorPair(unsupported, 4, "E_POLICY_CAPABILITY_UNSUPPORTED");
    auto final = Run(fixture.Args({"--domain", "unmatched.example", "--ip", "192.0.2.9", "--network", "udp"}));
    Require(final.code == 0, "Resolved proxy IPv4 route must be supported");
    report = final.Report();
    Require(!report["route"]["provisional"].asBool() && report["route"]["action"].asString() == "proxy", "Resolved route must be final proxy");
    Require(report["route"]["line"].asUInt() == 5 && report["route"]["file"].asCString() == (fixture.directory / "routing.rules").string(), "IPv4 route file and line missing");
    report = Run(fixture.Args({"--domain", "proxy.example"})).Report();
    Require(report["route"]["line"].asUInt() == 6 && report["dns"]["line"].asUInt() == 6, "Business route DNS provenance must agree");
    report = Run(fixture.Args({"--domain", "exception.example"})).Report();
    Require(report["dns"]["line"].asUInt() == 8 && report["dns"]["file"].asCString() == (fixture.directory / "routing.rules").string(), "DNS override file and line missing");
    auto args = fixture.Args({"--domain", "unmatched.example", "--network", "udp"});
    args.erase(std::find(args.begin(), args.end(), "--json"));
    auto text = Run(args);
    Require(text.code == 0 && text.error.empty() && text.output.find("provisional default") != std::string::npos, "Text report must disclose provisional route");
}

void StrictArguments() {
    Fixture fixture;
    auto duplicate_json = Run(fixture.Args({"--domain", "proxy.example", "--json"}));
    Require(duplicate_json.code == 2 && duplicate_json.Report()["diagnostics"][0]["code"].asString() == "E_POLICY_ARGUMENT",
        "Duplicate JSON flag must fail even with an otherwise valid target");
    for (const auto& option : {"--config", "--runtime"}) {
        auto args = fixture.Args({"--domain", "proxy.example"});
        auto position = std::find(args.begin(), args.end(), option);
        args.erase(position, position + 2);
        ErrorPair(args, 2, "E_POLICY_ARGUMENT");
    }
    ErrorPair(fixture.Args({}, "update"), 2, "E_POLICY_ARGUMENT");
    for (const auto& tail : std::vector<std::vector<std::string>>{
        {"--json"}, {"--domain"}, {"--domain", "--ip", "192.0.2.1"},
        {"--runtime", "socks"}, {"--platform", "android"}, {"--unknown", "x"},
        {"--domain", ""}, {"--domain", "bad..example"}, {"--domain", "192.0.2.1"},
        {"--domain", "a.example", "--network", "icmp"},
        {"--domain", "a.example", "--port", "0"}, {"--domain", "a.example", "--port", "65536"},
        {"--domain", "a.example", "--port", "12x"}, {"--domain", "a.example", "--port", "-1"},
        {"--domain", "a.example", "--port", "+80"}, {"--domain", "a.example", "--port", "123456"},
        {"--ip", "192.0.2.999"}, {}})
        ErrorPair(fixture.Args(tail), 2, "E_POLICY_ARGUMENT");
    for (const auto& option : {"--domain", "--ip", "--network", "--port"})
        ErrorPair(fixture.Args({option, "unused"}, "check"), 2, "E_POLICY_ARGUMENT");
    for (const auto& change : {std::pair<std::string, std::string>{"tun", "invalid"}, {"linux", "invalid"}}) {
        auto args = fixture.Args({"--domain", "a.example"});
        std::replace(args.begin(), args.end(), change.first, change.second);
        ErrorPair(args, 2, "E_POLICY_ARGUMENT");
    }
    ErrorPair(fixture.Args({"--ip", "2001:db8::1"}), 4, "E_POLICY_IPV6_UNSUPPORTED");
    auto maximum = Run(fixture.Args({"--ip", "192.0.2.1", "--port", "65535"}));
    Require(maximum.code == 0 && maximum.Report()["port"].asUInt() == 65535, "Maximum valid port must survive parsing");
    auto minimum = Run(fixture.Args({"--ip", "192.0.2.1", "--port", "1"}));
    Require(minimum.code == 0 && minimum.Report()["port"].asUInt() == 1, "Minimum valid port must survive parsing");
    auto legacy = Run({"ppp", "--config", "unused.json"});
    Require(!legacy.code && legacy.output.empty() && legacy.error.empty(), "Legacy dispatch must remain unhandled");
}

void SourceErrorsAndPrivacy() {
    Fixture fixture;
    std::filesystem::remove(fixture.directory / "routing.rules");
    ErrorPair(fixture.Args({}, "check"), 3, "E_POLICY_SOURCE_UNAVAILABLE");
    fixture.Rules("default proxy\ndns direct local\ndns proxy remote\n[proxy]\nset:sample\n");
    auto config = fixture.Config();
    auto& set = config["client"]["policy"]["rule-sets"]["sample"];
    set["format"] = "geosite-dat";
    set["tag"] = "test";
    set["source"]["url"] = "https://example.test/sample.dat";
    fixture.Save(config);
    ErrorPair(fixture.Args({}, "check"), 3, "E_POLICY_SOURCE_UNAVAILABLE");
    set["source"].removeMember("url");
    set["source"]["path"] = "missing.dat";
    fixture.Save(config);
    ErrorPair(fixture.Args({}, "check"), 3, "E_POLICY_SOURCE_UNAVAILABLE");
    set["source"]["path"] = "corrupt.dat";
    fixture.Write("corrupt.dat", "invalid protobuf");
    fixture.Save(config);
    ErrorPair(fixture.Args({}, "check"), 3, "rule_set_unavailable");
    fixture.Write("client.json", "{\"password\":\"TEST_PRIVATE_CLI_MARKER\", broken}");
    ErrorPair(fixture.Args({}, "check"), 2, "E_POLICY_JSON");
    for (bool json : {false, true}) {
        auto args = fixture.Args({}, "check");
        if (!json) args.erase(std::find(args.begin(), args.end(), "--json"));
        auto result = Run(args);
        Require((result.output + result.error).find("TEST_PRIVATE_CLI_MARKER") == std::string::npos, "Malformed config diagnostics must not emit input snippets");
    }
}

void DefaultRejectDnsException() {
    Fixture fixture;
    fixture.Rules("default reject\ndns direct local\ndns proxy remote\n[reject]\n=blocked.example\n[dns:local]\n=allowed.example\n=blocked.example\n");
    auto allowed = Run(fixture.Args({"--domain", "allowed.example"})).Report();
    Require(!allowed["dns"]["rejected"].asBool() && allowed["dns"]["resolver"].asString() == "local" && allowed["dns"]["line"].asUInt() == 7, "DNS exception must override default reject");
    auto blocked = Run(fixture.Args({"--domain", "blocked.example"})).Report();
    Require(blocked["dns"]["rejected"].asBool() && blocked["dns"]["line"].asUInt() == 5, "Explicit reject must override DNS exception");
}

void StatusCommandReportsPreparedGeneration() {
    Fixture fixture;
    const auto loaded = ppp::app::client::policy::PolicySourceLoader::LoadFile(
        (fixture.directory / "client.json").string());
    Require(loaded.Ok(), "Status fixture policy must load");
    const auto identity = ppp::app::client::policy::PolicyUpdateService::ImmutableFingerprint(loaded.source);
    const auto store = fixture.directory / "store";
    const auto status_path = store / identity / "STATUS.json";
    std::filesystem::create_directories(status_path.parent_path());
    ppp::app::client::policy::PolicyStatusRecord record;
    record.identity = identity;
    Require(ppp::app::client::policy::GetCurrentProcessIdentity(record.pid, record.process_start, record.last_diagnostic),
        "Status fixture process identity must be available");
    record.last_diagnostic.clear();
    record.updated_at_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    record.session_generation = 19;
    record.active_version = 27;
    record.prepared_version = 28;
    record.prepared_digest = "prepared-test-digest";
    record.counters.dns_cache_hits = 77;
    record.counters.dns_timeout_attempts = 6;
    record.counters.fake_ip_pending = 2;
    record.counters.policy_proxy = 33;
    std::string write_error;
    Require(ppp::app::client::policy::WriteStatusAtomically(status_path.string(), identity, record, write_error),
        "Status fixture record must be written");

    auto result = Run({"ppp", "policy", "status", "--config", (fixture.directory / "client.json").string(),
        "--store", store.string(), "--json"});
    const auto report = result.Report();
    Require(result.code == 0 && report["runtime_state"].asString() == "online", "Status command must verify the live status owner");
    Require(report["session_generation"].asUInt64() == 19 && report["active_version"].asUInt64() == 27,
        "Status command must report the active runtime generation");
    Require(report["prepared_version"].asUInt64() == 28 && report["prepared_digest"].asString() == "prepared-test-digest",
        "Status command must report the prepared bundle");
    Require(!report["offline"].asBool(), "Status command must expose explicit offline state");
    Require(report["counters"]["dns_cache_hits"].asUInt64() == 77 &&
        report["counters"]["dns_timeout_attempts"].asUInt64() == 6 &&
        report["counters"]["fake_ip_pending"].asUInt64() == 2 &&
        report["counters"]["policy_proxy"].asUInt64() == 33,
        "Status command must expose aggregate counters without per-domain data");
}

void InitTemplatesValidateAndPreserveExistingFiles() {
    Fixture fixture;
    const auto out = fixture.directory / "generated";
    auto invalid = Run({"ppp", "policy", "init", "--out", out.string(), "--template", "unknown",
        "--runtime", "tun", "--json"});
    Require(invalid.code == 2 && invalid.Report()["diagnostics"][0]["code"].asString() == "E_POLICY_ARGUMENT",
        "Unknown init templates must be rejected");
    auto created = Run({"ppp", "policy", "init", "--out", out.string(), "--template", "direct-all",
        "--runtime", "socks", "--json"});
    Require(created.code == 0 && created.Report()["incomplete"].asBool(), "Init must create an explicitly incomplete template");
    auto checked = Run({"ppp", "policy", "check", "--config", (out / "policy.json").string(),
        "--runtime", "socks", "--platform", "linux", "--json"});
    Require(checked.code == 0, "Generated policy template must pass offline validation");
    const auto original = ReadFile(out / "policy.json");
    auto repeated = Run({"ppp", "policy", "init", "--out", out.string(), "--template", "proxy-all",
        "--runtime", "tun", "--json"});
    Require(repeated.code == 3 && ReadFile(out / "policy.json") == original,
        "Init must refuse existing output without replacing it");

    fixture.Write("geoip.txt", "198.51.100.0/24\n");
    fixture.Write("geosite.txt", "china.example\n");
    const auto split_out = fixture.directory / "split-cn";
    auto split = Run({"ppp", "policy", "init", "--out", split_out.string(), "--template", "split-cn",
        "--runtime", "tun", "--geoip", (fixture.directory / "geoip.txt").string(), "--geosite",
        (fixture.directory / "geosite.txt").string(), "--json"});
    Require(split.code == 0, "Split-CN init must accept explicit local geodata sources");
    Json::Value split_config;
    Json::CharReaderBuilder reader;
    Json::String parse_error;
    const auto split_bytes = ReadFile(split_out / "policy.json");
    std::istringstream split_input(split_bytes);
    Require(Json::parseFromStream(reader, split_input, &split_config, &parse_error),
        "Split-CN template must be valid JSON");
    for (const auto& name : {"geoip-cn", "geosite-cn"}) {
        const auto& set = split_config["client"]["policy"]["rule-sets"][name];
        Require(set["tag"].asCString() == std::string("cn"), "Split-CN rule-set must carry the cn tag");
    }
    Require(split_config["client"]["policy"]["rule-sets"]["geoip-cn"]["sha256"].asCString() ==
        ppp::app::client::policy::PolicySha256(ReadFile(fixture.directory / "geoip.txt")),
        "Split-CN local GeoIP source must be pinned");
    Require(split_config["client"]["policy"]["rule-sets"]["geosite-cn"]["sha256"].asCString() ==
        ppp::app::client::policy::PolicySha256(ReadFile(fixture.directory / "geosite.txt")),
        "Split-CN local GeoSite source must be pinned");
    auto split_check = Run({"ppp", "policy", "check", "--config", (split_out / "policy.json").string(),
        "--runtime", "tun", "--platform", "linux", "--json"});
    Require(split_check.code == 0, "Split-CN generated policy must pass offline validation");
}

void MigrationReportsRoutingEquivalenceAndReviewCases() {
    Fixture fixture;
    auto write_legacy_config = [&](const std::filesystem::path& rules_path) {
        Json::Value config;
        const auto path = rules_path.string();
        config["routing"]["rules"] = Json::String(path.data(), path.size());
        Json::StreamWriterBuilder writer;
        const auto bytes = Json::writeString(writer, config);
        fixture.Write("legacy.json", std::string(bytes.data(), bytes.size()));
    };
    fixture.Write("legacy.rules", "default proxy\n[direct]\n=local.example\n*.inside.example\n");
    write_legacy_config(fixture.directory / "legacy.rules");
    const auto output = fixture.directory / "migrated";
    auto migrated = Run({"ppp", "policy", "migrate", "--config", (fixture.directory / "legacy.json").string(),
        "--out", output.string(), "--json"});
    auto report = migrated.Report();
    Require(migrated.code == 5 && report["status"].asString() == "draft" &&
        report["migration"]["routing_equivalence"].asString() == "equivalent",
        "Human host rules must report routing equivalence while DNS review remains a draft: code=" +
        std::to_string(migrated.code.value_or(-1)) + ", status=" + report["status"].asCString() +
        ", routing=" + report["migration"]["routing_equivalence"].asCString());
    auto check = Run({"ppp", "policy", "check", "--config", (output / "policy.json").string(),
        "--runtime", "tun", "--platform", "linux", "--json"});
    Require(check.code == 0, "Migrated draft files must pass policy validation");

    fixture.Write("legacy.rules", "default auto\n=local.example\n");
    const auto auto_out = fixture.directory / "auto-migration";
    auto auto_result = Run({"ppp", "policy", "migrate", "--config", (fixture.directory / "legacy.json").string(),
        "--out", auto_out.string(), "--json"});
    Require(auto_result.code == 5 && auto_result.Report()["migration"]["routing_equivalence"].asString() != "equivalent",
        "Legacy Auto defaults must remain an explicit migration draft");
    fixture.Write("legacy.rules", "default proxy\nregexp:.*example\\.com proxy\n");
    const auto regex_out = fixture.directory / "regex-migration";
    auto regex_result = Run({"ppp", "policy", "migrate", "--config", (fixture.directory / "legacy.json").string(),
        "--out", regex_out.string(), "--json"});
    Require(regex_result.code == 5 && regex_result.Report()["migration"]["routing_equivalence"].asString() != "equivalent",
        "Regex precedence must remain an unproven migration draft");

    write_legacy_config(fixture.directory / "missing.rules");
    const auto missing_out = fixture.directory / "missing-migration";
    auto missing = Run({"ppp", "policy", "migrate", "--config", (fixture.directory / "legacy.json").string(),
        "--out", missing_out.string(), "--json"});
    Require(missing.code == 5 && !missing.Report()["migration"]["diagnostics"].empty(),
        "Missing legacy Human rules must be reported as a draft");
}

void LegacyAdapterReadsLoadedConfigurationAndPreservesLegacyRouting() {
    Fixture fixture;
    const std::string rules_text = "default proxy\n[direct]\n=service.example\n192.0.2.0/24\n";
    fixture.Write("legacy-routing.rules", rules_text);
    Json::Value legacy_json;
    const auto rules_path = (fixture.directory / "legacy-routing.rules").string();
    legacy_json["routing"]["rules"] = Json::String(rules_path.data(), rules_path.size());
    legacy_json["client"]["routes"].append(Json::Value(Json::objectValue));
    legacy_json["client"]["routes"][0]["ngw"] = "192.0.2.1";
    legacy_json["client"]["routes"][0]["path"] = "192.0.2.0/24";
    fixture.Save(legacy_json);

    ppp::configurations::AppConfiguration legacy_config;
    ppp::string config_path((fixture.directory / "client.json").string().c_str());
    Require(legacy_config.Load(config_path), "Real AppConfiguration loader must accept the legacy fixture");
    ppp::app::client::policy::LegacyPolicyAdapterInput cli;
    cli.cli_bypass = {"inline:198.51.100.0/24", "file://missing-legacy-source"};
    cli.cli_dns_rules = {"example.test/192.0.2.53/tun"};
    cli.bypass_nic = "test-nic";
    auto legacy = ppp::app::client::policy::LegacyPolicyAdapter::Adapt(legacy_config, cli);
    Require(!legacy.canonical_routing && legacy.default_action == ppp::app::client::routing::RoutingAction::Proxy &&
        legacy.domain_rules.size() == 1 && legacy.ipv4_rules.size() == 1 && legacy.routes.size() == 1,
        "Adapter must preserve the real legacy rules, route and default action (default=" +
            std::to_string(static_cast<int>(legacy.default_action)) + ", domains=" +
            std::to_string(legacy.domain_rules.size()) + ", IPv4=" +
            std::to_string(legacy.ipv4_rules.size()) + ", routes=" + std::to_string(legacy.routes.size()) + ")");
    Require(legacy.sources.size() >= 3 && legacy.sources[0].original == cli.cli_bypass[0] &&
        legacy.sources[1].kind == ppp::app::client::policy::LegacySourceKind::MissingFileInline &&
        legacy.sources[2].role == ppp::app::client::policy::LegacySourceRole::DnsRules &&
        legacy.bypass_nic == "test-nic",
        "Legacy CLI sources, order, missing-file behavior and bypass NIC must be represented");
    ppp::app::client::routing::HumanRoutingRules old_evaluator;
    Require(old_evaluator.LoadText(legacy.human_rules_text, "legacy-routing.rules"),
        "Old HumanRules evaluator must load the adapter's exact source bytes");
    Require(old_evaluator.MatchDomain("service.example") == ppp::app::client::routing::RoutingAction::Direct &&
        old_evaluator.MatchDomain("unmatched.example") == legacy.default_action,
        "Adapter model must retain the behavior of the existing legacy evaluator");

    Json::Value canonical_json = legacy_json;
    canonical_json["client"]["routing"]["ip"]["bypass"].append("inline:10.0.0.0/8");
    canonical_json["client"]["routing"]["dns"]["rules"].append("inline:corp.example/192.0.2.54/tun");
    fixture.Save(canonical_json);
    ppp::configurations::AppConfiguration canonical_config;
    Require(canonical_config.Load(config_path), "Real AppConfiguration loader must accept the canonical fixture");
    auto canonical = ppp::app::client::policy::LegacyPolicyAdapter::Adapt(canonical_config, cli);
    Require(canonical.canonical_routing && !canonical.sources.empty() &&
        canonical.sources[0].original == "inline:10.0.0.0/8" &&
        canonical.sources[0].original != cli.cli_bypass[0] && canonical.routes.empty(),
        "Canonical routing sources must win over CLI/legacy projections in the adapter model");
}

void ExportMaterializesVerifiedRemoteBundleWithoutQuerySecrets() {
    Fixture fixture;
    fixture.Rules("default proxy\ndns direct local\ndns proxy remote\n[direct]\nset:sample\n");
    auto config = fixture.Config();
    Json::Value structured_server;
    structured_server["uri"] = "https://dns.example.test/dns-query";
    structured_server["addresses"].append("192.0.2.54");
    structured_server["bootstrap"].append("udp://192.0.2.1:53");
    Json::Value mixed_servers(Json::arrayValue);
    mixed_servers.append("tcp://198.51.100.53:53");
    mixed_servers.append(structured_server);
    mixed_servers.append("cloudflare");
    config["client"]["policy"]["dns"]["resolvers"]["remote"]["servers"] = mixed_servers;
    auto& set = config["client"]["policy"]["rule-sets"]["sample"];
    set["format"] = "geosite-text";
    set["source"]["url"] = "https://example.test/rules?token=TEST_EXPORT_SECRET";
    fixture.Save(config);

    const auto loaded = ppp::app::client::policy::PolicySourceLoader::LoadFile(
        (fixture.directory / "client.json").string());
    Require(loaded.Ok() == false && loaded.source.rule_sets.size() == 1,
        "Remote declaration should be usable for durable export despite offline fetch diagnostic");
    const auto identity = ppp::app::client::policy::PolicyUpdateService::ImmutableFingerprint(loaded.source);
    ppp::app::client::policy::DurablePolicyBundle bundle;
    bundle.identity_fingerprint = identity;
    bundle.rules = ReadFile(fixture.directory / "routing.rules");
    bundle.rules_validated_at_ms = 1;
    ppp::app::client::policy::DurablePolicySource source;
    source.name = "sample";
    source.format = "geosite-text";
    const Json::String url_value = set["source"]["url"].asString();
    const std::string remote_url(url_value.data(), url_value.size());
    source.url_redacted = ppp::app::client::policy::RedactPolicySourceUrl(remote_url);
    source.url_fingerprint = ppp::app::client::policy::PolicySha256(remote_url);
    source.bytes = "remote.example\n";
    source.validated_at_ms = 1;
    bundle.rule_sets.emplace("sample", source);
    ppp::app::client::policy::FileDurablePolicyBundleStore store((fixture.directory / "store").string());
    std::string error;
    Require(store.Commit(bundle, error), "Verified remote test bundle must be committed");

    const auto export_parent = fixture.directory / "missing-parent" / "nested";
    const auto export_path = export_parent / "export.json";
    Require(!std::filesystem::exists(export_parent), "Export fixture parent must start missing");
    const auto export_args = std::vector<std::string>{"ppp", "policy", "export", "--config",
        (fixture.directory / "client.json").string(), "--store", (fixture.directory / "store").string(),
        "--out", export_path.string(), "--json"};
    auto exported = Run(export_args);
    Require(exported.code == 0, "Export must materialize a verified durable remote bundle");
    Require(std::filesystem::is_directory(export_parent),
        "Export must create missing parent directories before installing the bundle");
    const auto exported_bytes = ReadFile(export_path);
    Require(exported_bytes.find("TEST_EXPORT_SECRET") == std::string::npos,
        "Exported config must omit remote URL query credentials");
    Json::Value exported_config;
    Json::CharReaderBuilder reader;
    Json::String parse_error;
    std::istringstream exported_input(exported_bytes);
    Require(Json::parseFromStream(reader, exported_input, &exported_config, &parse_error),
        "Exported config must remain valid JSON");
    const auto& exported_servers = exported_config["client"]["policy"]["dns"]["resolvers"]["remote"]["servers"];
    Require(exported_servers.size() == 3 && exported_servers[0].isString() &&
        exported_servers[0].asString() == "tcp://198.51.100.53:53" &&
        exported_servers[1].isObject() && exported_servers[1]["uri"].asString() == "https://dns.example.test/dns-query" &&
        exported_servers[1]["addresses"][0].asString() == "192.0.2.54" &&
        exported_servers[1]["bootstrap"][0].asString() == "udp://192.0.2.1:53" &&
        exported_servers[2].isString() && exported_servers[2].asString() == "cloudflare",
        "Export must preserve mixed resolver server order and structured metadata");
    const auto exported_fake_ip_identity = exported_config["client"]["policy"]["dns"]["fake-ip"]["identity"].asString();
    Require(!exported_fake_ip_identity.empty() &&
        exported_config["policy_export"]["fake_ip_identity"].asString() == exported_fake_ip_identity,
        "Export metadata must match its relocated Fake-IP identity");
    auto repeated_export = Run(export_args);
    const auto repeated_report = repeated_export.Report();
    Require(repeated_export.code == 3 && repeated_report["diagnostics"][0]["code"].asString() == "E_POLICY_STORAGE" &&
        ReadFile(export_path) == exported_bytes,
        "Export must refuse existing output without changing the original file");
    auto check = Run({"ppp", "policy", "check", "--config", export_path.string(),
        "--runtime", "tun", "--platform", "linux", "--json"});
    Require(check.code == 0, "Exported materialized policy must pass offline validation");
    for (const auto& file : std::filesystem::recursive_directory_iterator(fixture.directory)) {
        const auto name = file.path().filename().string();
        if (name.rfind("export.json", 0) == 0)
            Require(ReadFile(file.path()).find("TEST_EXPORT_SECRET") == std::string::npos,
                "Export sidecars must not contain remote URL query credentials");
    }
}

void UpdateRefusesRuntimeOwnedStatusBeforePreparingBundle() {
    Fixture fixture;
    auto config = fixture.Config();
    config["client"]["policy"]["updates"]["via"] = "direct";
    config["client"]["policy"]["updates"]["enabled"] = true;
    fixture.Save(config);
    const auto loaded = ppp::app::client::policy::PolicySourceLoader::LoadFile(
        (fixture.directory / "client.json").string());
    Require(loaded.Ok(), "Direct update fixture must load");
    const auto identity = ppp::app::client::policy::PolicyUpdateService::ImmutableFingerprint(loaded.source);
    const auto store_root = fixture.directory / "store";
    const auto status_path = store_root / identity / "STATUS.json";
    ppp::app::client::policy::PolicyStatusWriterLease runtime_lease;
    std::string error;
    Require(runtime_lease.TryAcquire(status_path.string(), identity, error), "Runtime lease fixture must acquire");

    auto result = Run({"ppp", "policy", "update", "--config", (fixture.directory / "client.json").string(),
        "--store", store_root.string(), "--interface", "test-interface", "--json"});
    const auto report = result.Report();
    Require(result.code == 3 && report["diagnostics"][0]["code"].asString() == "E_POLICY_STATUS_OWNED",
        "Update must fail when an active runtime owns the status writer lease");
    const Json::String runtime_store_json = report["runtime_store_root"].asString();
    const std::string runtime_store(runtime_store_json.data(), runtime_store_json.size());
    Require(!report["runtime_store_compatible"].asBool() &&
        runtime_store != store_root.string(),
        "A custom update store must be identified as separate from the runtime store");
    ppp::app::client::policy::FileDurablePolicyBundleStore store(store_root.string());
    Require(!store.LoadCurrent(identity).found, "Lease conflict must happen before any durable bundle is prepared");
    Require(!std::filesystem::exists(status_path), "Lease conflict must not replace the runtime status record");
}
} // namespace

int main() {
    const char* stage = "startup";
    try {
        stage = "provisional route";
        ProvisionalAndProvenance();
        stage = "strict arguments";
        StrictArguments();
        stage = "source privacy";
        SourceErrorsAndPrivacy();
        stage = "DNS rejection";
        DefaultRejectDnsException();
        stage = "status output";
        StatusCommandReportsPreparedGeneration();
        stage = "init output";
        InitTemplatesValidateAndPreserveExistingFiles();
        stage = "migration output";
        MigrationReportsRoutingEquivalenceAndReviewCases();
        stage = "legacy adapter";
        LegacyAdapterReadsLoadedConfigurationAndPreservesLegacyRouting();
        stage = "export output";
        ExportMaterializesVerifiedRemoteBundleWithoutQuerySecrets();
        stage = "update lease";
        UpdateRefusesRuntimeOwnedStatusBeforePreparingBundle();
        std::cout << "policy CLI contract tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << stage << ": " << error.what() << '\n';
        return 1;
    }
}
