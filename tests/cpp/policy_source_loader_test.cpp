#include <ppp/app/client/policy/PolicySourceLoader.h>
#include <ppp/app/client/policy/PolicyCompiler.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace ppp::app::client::policy;
namespace fs = std::filesystem;

namespace {
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

bool Has(const PolicyLoadResult& result, const std::string& code, const std::string& path = {}) {
    for (const auto& item : result.diagnostics)
        if (item.code == code && (path.empty() || item.path == path)) return true;
    return false;
}

struct Fixture {
    fs::path dir = fs::temp_directory_path() / ("openppp2-policy-loader-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Fixture() { fs::create_directories(dir / "data"); }
    ~Fixture() { std::error_code ec; fs::remove_all(dir, ec); }
    void Write(const std::string& name, const std::string& text) {
        std::ofstream stream(dir / name, std::ios::binary);
        stream << text;
        Require(static_cast<bool>(stream), "fixture write failed");
    }
    std::string ConfigPath() const { return (dir / "client.json").string(); }
};

Json::Value Config() {
    Json::Value config;
    auto& policy = config["client"]["policy"];
    policy["version"] = 2;
    policy["rules"]["path"] = "data/routing.rules";
    policy["dns"]["mode"] = "auto";
    policy["dns"]["resolvers"]["local"]["via"] = "direct";
    policy["dns"]["resolvers"]["local"]["servers"].append("udp://192.0.2.53:53");
    policy["dns"]["resolvers"]["remote"]["via"] = "proxy";
    policy["dns"]["resolvers"]["remote"]["servers"].append("cloudflare");
    return config;
}
} // namespace

int main() {
    try {
        Fixture fixture;
        fixture.Write("data/routing.rules", "default proxy\ndns direct local\ndns proxy remote\n[direct]\nexample.test\n");
        fixture.Write("data/domains.txt", "example.test\n");
        auto config = Config();
        auto loaded = PolicySourceLoader::Load(config, fixture.ConfigPath());
        Require(loaded.Ok(), "valid config rejected");
        for (double version : {2.0, 2.5}) {
            auto invalid_version = Config();
            invalid_version["client"]["policy"]["version"] = version;
            Require(Has(PolicySourceLoader::Load(invalid_version, fixture.ConfigPath()), "E_POLICY_CONFIG", "client.policy.version"),
                "Floating-point schema version must be rejected");
        }
        auto unsigned_version = Config();
        unsigned_version["client"]["policy"]["version"] = Json::UInt(2);
        Require(PolicySourceLoader::Load(unsigned_version, fixture.ConfigPath()).Ok(), "Unsigned integer schema version 2 must be accepted");
        Require(loaded.source.rules_path == fs::weakly_canonical(fixture.dir / "data/routing.rules").string(), "relative path not configuration-relative");
        Require(loaded.source.rules_text.find("example.test") != std::string::npos, "rule contents missing");
        Require(loaded.source.resolvers.at("local").via == PolicyAction::Direct, "resolver via lost");
        Require(loaded.source.resolvers.at("remote").servers.front() == "cloudflare", "provider metadata lost");
        const fs::path default_storage(loaded.source.fake_ip_storage);
        Require(loaded.source.fake_ip_range == "198.18.0.0/16" &&
            default_storage == (fixture.dir / "dns-fake-ip").lexically_normal().string() &&
            loaded.source.fake_ip_identity.size() == 64, "Fake-IP durable defaults must resolve from the config location");
        auto fake = Config();
        fake["client"]["policy"]["dns"]["mode"] = "fake-ip";
        fake["client"]["policy"]["dns"]["fake-ip"]["range"] = "198.18.4.0/24";
        fake["client"]["policy"]["dns"]["fake-ip"]["storage"] = "state/fake-ip";
        fake["client"]["policy"]["dns"]["fake-ip"]["identity"] = "stable-client-01";
        const auto fake_loaded = PolicySourceLoader::Load(fake, fixture.ConfigPath());
        Require(fake_loaded.Ok() && fake_loaded.source.dns_mode == "fake-ip" &&
            fake_loaded.source.fake_ip_range == "198.18.4.0/24" &&
            fake_loaded.source.fake_ip_storage == (fixture.dir / "state/fake-ip").lexically_normal().string() &&
            fake_loaded.source.fake_ip_identity == "stable-client-01", "Fake-IP storage config must parse relative to the config file");
        const auto fake_snapshot = PolicyCompiler::Compile(fake_loaded.source);
        Require(fake_snapshot.Ok() && fake_snapshot.snapshot->DnsMode() == "fake-ip" &&
            fake_snapshot.snapshot->FakeIpIdentity() == "stable-client-01", "Fake-IP metadata must be pinned in the policy snapshot");
        for (const auto& mode : {"real", "fake-ip", "invalid"}) {
            auto mode_config = Config();
            mode_config["client"]["policy"]["dns"]["mode"] = mode;
            const auto mode_loaded = PolicySourceLoader::Load(mode_config, fixture.ConfigPath());
            Require((mode != std::string("invalid")) == mode_loaded.Ok(), "DNS mode must accept only auto, real, and fake-ip");
        }
        for (const auto& bad_range : {"not-an-ip", "198.18.0.0/33", "2001:db8::/32"}) {
            auto invalid_fake = Config();
            invalid_fake["client"]["policy"]["dns"]["fake-ip"]["range"] = bad_range;
            Require(!PolicySourceLoader::Load(invalid_fake, fixture.ConfigPath()).Ok(), "Invalid Fake-IP range accepted");
        }
        auto empty_storage = Config();
        empty_storage["client"]["policy"]["dns"]["mode"] = "fake-ip";
        empty_storage["client"]["policy"]["dns"]["fake-ip"]["storage"] = "";
        Require(!PolicySourceLoader::Load(empty_storage, fixture.ConfigPath()).Ok(), "Empty Fake-IP storage path accepted");
        Require(loaded.source.ipv6 == "block" && loaded.source.dns_mode == "auto" && !loaded.source.tcp_domain_sniff &&
            !loaded.source.updates_enabled && loaded.source.updates_interval == "24h" &&
            loaded.source.updates_via == PolicyAction::Proxy, "offline policy defaults changed");
        auto default_sniff = PolicyCompiler::Compile(loaded.source);
        Require(default_sniff.Ok() && !default_sniff.snapshot->TcpDomainSniff(), "TCP sniff must default to disabled");
        for (bool enabled : {true, false}) {
            auto sniff = Config();
            sniff["client"]["policy"]["tcp-domain-sniff"] = enabled;
            auto parsed = PolicySourceLoader::Load(sniff, fixture.ConfigPath());
            Require(parsed.Ok() && parsed.source.tcp_domain_sniff == enabled, "Explicit TCP sniff flag lost at loading");
            auto compiled = PolicyCompiler::Compile(parsed.source);
            Require(compiled.Ok() && compiled.snapshot->TcpDomainSniff() == enabled, "TCP sniff flag lost at compilation");
            parsed.source.tcp_domain_sniff = !enabled;
            Require(compiled.snapshot->TcpDomainSniff() == enabled, "TCP sniff snapshot metadata must remain immutable");
        }
        for (const auto& value : {Json::Value(), Json::Value(0), Json::Value(1), Json::Value("true"),
                Json::Value(Json::arrayValue), Json::Value(Json::objectValue)}) {
            auto sniff = Config();
            sniff["client"]["policy"]["tcp-domain-sniff"] = value;
            Require(Has(PolicySourceLoader::Load(sniff, fixture.ConfigPath()), "E_POLICY_CONFIG", "client.policy.tcp-domain-sniff"),
                "TCP sniff flag must reject non-boolean values");
        }
        const auto server_path = "client.policy.dns.resolvers.remote.servers[0]";
        for (const auto& endpoint : {"https://-invalid.test/dns-query", "https://invalid-.test/dns-query",
                "https://invalid..test/dns-query", "tls://invalid.test.", "tls://999.1.1.1",
                "https://invalid.test:0/dns-query", "https://invalid.test:/dns-query",
                "https://invalid.test:65536/dns-query", "udp://192.0.2.53/path",
                "udp://[2001:db8::53]:53", "https://[2001:db8::53]/dns-query",
                "https://user:TEST_PRIVATE_MARKER@example.test/dns-query", "https://example.test/dns%xx",
                "https://example.test/dns-query#fragment", "https://example.test\\dns-query",
                "https://example.test/<query>", "cloudflare?TEST_PRIVATE_MARKER"}) {
            auto invalid = Config();
            invalid["client"]["policy"]["dns"]["resolvers"]["remote"]["servers"][0] = endpoint;
            const auto rejected = PolicySourceLoader::Load(invalid, fixture.ConfigPath());
            Require(Has(rejected, "E_POLICY_CONFIG", server_path), "malformed DNS endpoint accepted");
            for (const auto& diagnostic : rejected.diagnostics)
                Require(diagnostic.message.find("TEST_PRIVATE_MARKER") == std::string::npos, "endpoint error leaked credentials");
        }
        for (const auto& endpoint : {"udp://192.0.2.53", "tcp://192.0.2.53:65535", "tls://192.0.2.53:853",
                "https://192.0.2.53/dns-query"}) {
            auto valid = Config();
            valid["client"]["policy"]["dns"]["resolvers"]["remote"]["servers"][0] = endpoint;
            Require(PolicySourceLoader::Load(valid, fixture.ConfigPath()).Ok(), "valid explicit DNS endpoint rejected");
        }
        // Policy resolvers use only DoH/DoT; providers that publish plain DNS alone are rejected.
        for (const auto& provider : {"114", "baidu"}) {
            auto plain = Config();
            plain["client"]["policy"]["dns"]["resolvers"]["remote"]["servers"][0] = provider;
            Require(Has(PolicySourceLoader::Load(plain, fixture.ConfigPath()), "E_POLICY_CONFIG", server_path),
                "provider without DoH/DoT endpoint accepted");
        }
        for (const auto& provider : {"doh.pub", "alidns", "tuna"}) {
            auto encrypted = Config();
            encrypted["client"]["policy"]["dns"]["resolvers"]["remote"]["servers"][0] = provider;
            Require(PolicySourceLoader::Load(encrypted, fixture.ConfigPath()).Ok(), "provider with DoH/DoT endpoint rejected");
        }
        {
            auto structured = Config();
            Json::Value server;
            server["uri"] = "https://dns.example.test/dns-query?key=test%20value";
            server["addresses"].append("192.0.2.53");
            server["bootstrap"].append("udp://192.0.2.1:53");
            structured["client"]["policy"]["dns"]["resolvers"]["remote"]["servers"][0] = server;
            const auto parsed = PolicySourceLoader::Load(structured, fixture.ConfigPath());
            Require(parsed.Ok() && parsed.source.resolvers.at("remote").server_specs.size() == 1 &&
                parsed.source.resolvers.at("remote").server_specs.front().uri == "https://dns.example.test/dns-query?key=test%20value" &&
                parsed.source.resolvers.at("remote").server_specs.front().addresses.front() == "192.0.2.53" &&
                parsed.source.resolvers.at("remote").server_specs.front().bootstrap.front() == "udp://192.0.2.1:53",
                "Structured hostname server metadata lost");
        }
        {
            auto mixed = Config();
            Json::Value server;
            server["uri"] = "tls://dns.example.test:853";
            server["addresses"].append("192.0.2.53");
            Json::Value servers(Json::arrayValue);
            servers.append(server);
            servers.append("cloudflare");
            mixed["client"]["policy"]["dns"]["resolvers"]["remote"]["servers"] = servers;
            const auto parsed = PolicySourceLoader::Load(mixed, fixture.ConfigPath());
            const auto& resolver = parsed.source.resolvers.at("remote");
            Require(parsed.Ok() && resolver.server_order.size() == 2 &&
                resolver.server_order[0].structured && !resolver.server_order[1].structured &&
                resolver.server_order[0].index == 0 && resolver.server_order[1].index == 0,
                "Mixed server forms must preserve ordered fallback references");
        }
        for (const auto& bad_bootstrap : {"udp://resolver.example.test:53", "tcp://192.0.2.1:53", "cloudflare", "udp://[2001:db8::1]:53"}) {
            Json::Value server;
            server["uri"] = "https://dns.example.test/dns-query";
            server["bootstrap"].append(bad_bootstrap);
            auto invalid = Config();
            invalid["client"]["policy"]["dns"]["resolvers"]["remote"]["servers"][0] = server;
            Require(Has(PolicySourceLoader::Load(invalid, fixture.ConfigPath()), "E_POLICY_CONFIG"), "Invalid explicit bootstrap resolver accepted");
        }
        {
            Json::Value server;
            server["uri"] = "https://dns.example.test/dns-query";
            auto invalid = Config();
            invalid["client"]["policy"]["dns"]["resolvers"]["remote"]["servers"][0] = server;
            Require(Has(PolicySourceLoader::Load(invalid, fixture.ConfigPath()), "E_POLICY_CONFIG"), "Hostname without addresses or bootstrap accepted");
        }
        auto oversized_host = Config();
        oversized_host["client"]["policy"]["dns"]["resolvers"]["remote"]["servers"][0] =
            ("https://" + std::string(64, 'a') + ".test/dns-query").c_str();
        Require(Has(PolicySourceLoader::Load(oversized_host, fixture.ConfigPath()), "E_POLICY_CONFIG", server_path), "overlong DNS label accepted");

        auto& set = config["client"]["policy"]["rule-sets"]["domains"];
        set["format"] = "geosite-text";
        set["source"]["path"] = "data/domains.txt";
        loaded = PolicySourceLoader::Load(config, fixture.ConfigPath());
        Require(loaded.Ok() && loaded.source.rule_sets.at("domains").text == "example.test\n", "local set not materialized");

        set["source"]["url"] = "https://example.test/domains.txt";
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_CONFIG", "client.policy.rule-sets.domains.source"), "path/url ambiguity accepted");
        set["source"].removeMember("path");
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_SOURCE_UNAVAILABLE"), "remote offline source accepted");
        for (const auto& url : {"https://", "https:///rules.txt", "https://-invalid.test/rules.txt",
                "https://example.test:99999/rules.txt", "https://example.test/%xx",
                "https://user:TEST_PRIVATE_MARKER@example.test/rules.txt", "https://example.test/rules.txt#fragment"}) {
            set["source"]["url"] = url;
            Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_CONFIG",
                "client.policy.rule-sets.domains.source.url"), "malformed source URL classified as offline availability");
        }
        for (const auto& url : {"https://example.test", "http://example.test:8080/rules.txt?version=test%20value"}) {
            set["source"]["url"] = url;
            loaded = PolicySourceLoader::Load(config, fixture.ConfigPath());
            Require(Has(loaded, "E_POLICY_SOURCE_UNAVAILABLE") && !Has(loaded, "E_POLICY_CONFIG"), "valid remote URL rejected as malformed");
        }
        set["source"]["url"] = "file:///not-a-source";
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_CONFIG"), "unsupported URL accepted");
        set["source"].removeMember("url");
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_CONFIG"), "missing source accepted");
        set["source"]["path"] = "data/domains.txt";
        set["format"] = "geosite-dat";
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_CONFIG", "client.policy.rule-sets.domains.tag"), "dat without tag accepted");
        set["tag"] = "test";
        set["sha256"] = "bad";
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_CONFIG", "client.policy.rule-sets.domains.sha256"), "invalid hash accepted");
        set["sha256"] = std::string(64, '0').c_str();
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_CONFIG", "client.policy.rule-sets.domains.sha256"), "mismatching valid digest accepted");
        fixture.Write("data/binary.dat", std::string("a\0b", 3));
        set["source"]["path"] = "data/binary.dat";
        set["sha256"] = "59B271AE1BBCB1D31D41929817F4B16FB439EB4F31520B5AD1D5CE98920A7138";
        loaded = PolicySourceLoader::Load(config, fixture.ConfigPath());
        Require(loaded.Ok() && loaded.source.rule_sets.at("domains").materialized &&
            loaded.source.rule_sets.at("domains").text == std::string("a\0b", 3), "binary source or uppercase digest corrupted");
        config = Config();

        for (const auto* field : {"routing", "geo-rules", "dns"}) {
            auto conflict = config;
            conflict[field] = Json::Value(Json::objectValue);
            Require(Has(PolicySourceLoader::Load(conflict, fixture.ConfigPath()), "E_POLICY_SOURCE_CONFLICT", field), "legacy root conflict missed");
        }
        auto conflict = config;
        conflict["client"]["routing"] = Json::Value(Json::objectValue);
        Require(Has(PolicySourceLoader::Load(conflict, fixture.ConfigPath()), "E_POLICY_SOURCE_CONFLICT", "client.routing"), "nested legacy conflict missed");
        conflict = Config();
        conflict["udp"]["dns"] = false;
        Require(Has(PolicySourceLoader::Load(conflict, fixture.ConfigPath()), "E_POLICY_SOURCE_CONFLICT", "udp.dns"), "explicit disabled legacy DNS conflict missed");
        config["server"]["peer-routing"]["enabled"] = true;
        config["client"]["routes"].append("192.0.2.0/24");
        Require(PolicySourceLoader::Load(config, fixture.ConfigPath()).Ok(), "non-policy network configuration conflicts");
        config["client"]["policy"]["rules"]["path"] = "file://missing.rules";
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_SOURCE_UNAVAILABLE"), "missing file interpreted as inline rules");
        config = Config();
        config["client"]["policy"]["rules"]["path"] = "data";
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_SOURCE_UNAVAILABLE"), "directory source accepted");
        config = Config();
        config["client"]["policy"]["unexpected"] = true;
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_CONFIG", "client.policy.unexpected"), "unknown policy field accepted");
        config = Config();
        config["client"]["policy"]["dns"]["resolvers"]["remote"]["via"] = "reject";
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_CONFIG"), "reject DNS via accepted");
        config = Config();
        config["client"]["policy"]["dns"]["resolvers"]["remote"]["servers"][0] = "unknown-provider";
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_CONFIG"), "unknown provider accepted");
        config["client"]["policy"]["dns"]["resolvers"]["remote"]["servers"][0] = "udp://192.0.2.53:99999";
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_CONFIG"), "invalid endpoint port accepted");
        config = Config();
        config["client"]["policy"]["ipv6"] = "direct";
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_CAPABILITY_UNSUPPORTED"), "IPv6 forwarding accepted");
        config = Config();
        config["client"]["policy"]["updates"]["interval"] = "0h";
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_CONFIG"), "zero update interval accepted");
        config["client"]["policy"]["updates"]["interval"] = "24h";
        Require(PolicySourceLoader::Load(config, fixture.ConfigPath()).Ok(), "valid update interval rejected");
        config["client"]["policy"]["version"] = 1;
        Require(Has(PolicySourceLoader::Load(config, fixture.ConfigPath()), "E_POLICY_CONFIG", "client.policy.version"), "wrong version accepted");
        Require(Has(PolicySourceLoader::Load(Config(), fixture.ConfigPath() + std::string("\0ignored", 8)), "E_POLICY_CONFIG", "$"), "NUL config path accepted");
        Require(Has(PolicySourceLoader::Load(Json::Value(), fixture.ConfigPath()), "E_POLICY_CONFIG", "client"), "null config accepted");
        for (const auto* field : {"rules", "dns", "rule-sets", "updates"}) {
            auto invalid = Config();
            invalid["client"]["policy"][field] = Json::Value(Json::arrayValue);
            Require(Has(PolicySourceLoader::Load(invalid, fixture.ConfigPath()), "E_POLICY_CONFIG",
                std::string("client.policy.") + field), "non-object policy field accepted");
        }

        fixture.Write("client.json", "");
        Require(Has(PolicySourceLoader::LoadFile(fixture.ConfigPath()), "E_POLICY_JSON"), "empty JSON accepted");
        fixture.Write("client.json", "{\"client\":{},\"client\":{\"policy\":{}}}");
        Require(Has(PolicySourceLoader::LoadFile(fixture.ConfigPath()), "E_POLICY_JSON"), "duplicate JSON keys accepted");
        fixture.Write("client.json", "{} trailing text");
        Require(Has(PolicySourceLoader::LoadFile(fixture.ConfigPath()), "E_POLICY_JSON"), "trailing JSON content accepted");
        fixture.Write("client.json", "{\"password\":\"TEST_PRIVATE_MARKER\", broken}");
        loaded = PolicySourceLoader::LoadFile(fixture.ConfigPath());
        Require(Has(loaded, "E_POLICY_JSON"), "malformed JSON accepted");
        for (const auto& diagnostic : loaded.diagnostics)
            Require(diagnostic.message.find("TEST_PRIVATE_MARKER") == std::string::npos, "JSON error leaked input");
        Json::StreamWriterBuilder writer;
        const auto json = Json::writeString(writer, Config());
        fixture.Write("client.json", std::string(json.data(), json.size()));
        Require(PolicySourceLoader::LoadFile(fixture.ConfigPath()).Ok(), "valid JSON file rejected");
        std::cout << "policy source loader tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
