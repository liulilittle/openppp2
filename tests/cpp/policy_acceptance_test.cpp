#include <ppp/app/client/policy/PolicySourceLoader.h>
#include <ppp/app/client/policy/PolicyCompiler.h>
#include <ppp/app/client/policy/PolicyEvaluator.h>
#include <openssl/sha.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace ppp::app::client::policy;
namespace {
void Require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
class Fixture {
public:
    std::filesystem::path root = std::filesystem::temp_directory_path() /
        ("openppp-policy-acceptance-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Fixture() { std::filesystem::create_directory(root); }
    ~Fixture() { std::error_code ec; std::filesystem::remove_all(root, ec); }
    void Write(const std::string& name, const std::string& bytes) const {
        std::ofstream stream(root / name, std::ios::binary); stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        stream.close(); Require(bool(stream), "Cannot write isolated fixture");
    }
    std::string ConfigPath() const { return (root / "config.json").string(); }
};
Json::Value Config() {
    Json::Value config;
    auto& policy = config["client"]["policy"];
    policy["version"] = 2; policy["rules"]["path"] = "routing.rules";
    policy["ipv6"] = "block"; policy["dns"]["mode"] = "auto";
    policy["dns"]["resolvers"]["local"]["via"] = "direct";
    policy["dns"]["resolvers"]["local"]["servers"].append("udp://192.0.2.53:53");
    policy["dns"]["resolvers"]["remote"]["via"] = "proxy";
    policy["dns"]["resolvers"]["remote"]["servers"].append("tcp://198.51.100.53:53");
    return config;
}
const std::string bindings = "default proxy\ndns direct local\ndns proxy remote\n";
void Set(Json::Value& config, const char* name, const char* format, const char* path) {
    auto& set = config["client"]["policy"]["rule-sets"][name];
    set["format"] = format; set["source"]["path"] = path;
}
std::shared_ptr<const PolicySnapshot> Compile(const PolicyLoadResult& loaded) {
    Require(loaded.Ok(), "Loader must accept isolated fixture");
    const auto compiled = PolicyCompiler::Compile(loaded.source, 17);
    if (!compiled.Ok()) for (const auto& d : compiled.diagnostics) std::cerr << d.code << ':' << d.message << '\n';
    Require(compiled.Ok(), "Compiler must accept loaded source"); return compiled.snapshot;
}
void PipelineSemantics() {
    Fixture files;
    files.Write("routing.rules", bindings +
        "[proxy]\nset:domains\nset:ips\n[direct]\nexample.test\n192.0.0.0/16\n"
        "[reject]\nregexp:example\\.test$\n=blocked.example.test\n[dns:remote]\n=example.test\n=blocked.example.test\n");
    files.Write("domains.txt", "full:login.example.test\ndomain:only-set.test\nplain:tracker\n");
    files.Write("ips.txt", "192.0.2.0/24\n2001:db8::/32\n");
    auto config = Config(); Set(config, "domains", "geosite-text", "domains.txt"); Set(config, "ips", "geoip-text", "ips.txt");
    const auto snapshot = Compile(PolicySourceLoader::Load(config, files.ConfigPath()));
    auto evaluate = [&](const std::string& domain, const std::string& ip = "") { return PolicyEvaluator::Evaluate(*snapshot, domain, ip); };
    Require(evaluate("login.example.test").action == PolicyAction::Direct, "Manual suffix overrides set exact");
    Require(evaluate("example.test").action == PolicyAction::Direct, "V2 suffix precedes regex, unlike legacy");
    Require(evaluate("only-set.test").action == PolicyAction::Proxy, "Named domain source materializes");
    Require(evaluate("tracker.other.test").action == PolicyAction::Proxy && evaluate("tracker.other.test").matched, "Geo Plain keyword materializes");
    Require(evaluate("blocked.example.test", "192.0.2.1").action == PolicyAction::Reject, "Matched domain reject precedes direct IP");
    Require(evaluate("other.test", "192.0.2.1").action == PolicyAction::Direct, "Manual broad prefix overrides narrower set");
    Require(evaluate("other.test").needs_ip_resolution, "Unmatched domain explain requires IP resolution");
    Require(snapshot->SkippedIpv6() == 1, "Geo IPv6 count remains visible");
    const auto dns = PolicyEvaluator::PlanDns(*snapshot, "example.test");
    Require(dns.action == PolicyAction::Direct && dns.via == PolicyAction::Proxy && dns.resolver == "remote", "DNS exception explains different business/DNS exit");
    Require(PolicyEvaluator::PlanDns(*snapshot, "blocked.example.test").rejected, "Reject wins independent DNS exception");
    Require(snapshot->Version() == 17, "Snapshot version follows compiler input");
}
void InvalidSources() {
    Fixture files; files.Write("routing.rules", bindings + "[direct]\nexample.test\n");
    auto config = Config(); Set(config, "absent", "geoip-text", "missing.txt");
    Require(!PolicySourceLoader::Load(config, files.ConfigPath()).Ok(), "Missing rule set fails loader");
    config = Config(); config["client"]["routing"] = Json::Value(Json::objectValue);
    Require(!PolicySourceLoader::Load(config, files.ConfigPath()).Ok(), "Explicit legacy source conflicts with v2");
    config = Config(); Set(config, "remote", "geosite-dat", "unused.dat");
    auto& remote = config["client"]["policy"]["rule-sets"]["remote"];
    remote["source"].removeMember("path"); remote["source"]["url"] = "https://rules.example.test/geosite.dat"; remote["tag"] = "test";
    Require(!PolicySourceLoader::Load(config, files.ConfigPath()).Ok(), "Offline loader never fetches remote-only sources");
    config = Config(); config["client"]["policy"]["rules"]["path"] = "not-present.rules";
    Require(!PolicySourceLoader::Load(config, files.ConfigPath()).Ok(), "Missing rules file never becomes inline input");
    config = Config(); files.Write("routing.rules", bindings + "[dns:local]\nset:ips\n");
    files.Write("ips.txt", "192.0.2.0/24\n"); Set(config, "ips", "geoip-text", "ips.txt");
    const auto loaded = PolicySourceLoader::Load(config, files.ConfigPath());
    Require(loaded.Ok() && !PolicyCompiler::Compile(loaded.source).Ok(), "DNS IP reference fails semantic compilation");
}
// Small independent protobuf writers encode the published Geo list schema, not evaluator output.
void Varint(std::string& bytes, unsigned value) {
    do { unsigned part = value & 127; value >>= 7; bytes.push_back(static_cast<char>(part | (value ? 128 : 0))); } while (value);
}
void Field(std::string& bytes, unsigned number, const std::string& value) {
    Varint(bytes, (number << 3) | 2); Varint(bytes, static_cast<unsigned>(value.size())); bytes += value;
}
void Integer(std::string& bytes, unsigned number, unsigned value) { Varint(bytes, number << 3); Varint(bytes, value); }
std::string GeoIp() {
    std::string cidr; Field(cidr, 1, std::string("\xc0\x00\x02\x00", 4)); Integer(cidr, 2, 24);
    std::string entry; Field(entry, 1, "TEST"); Field(entry, 2, cidr);
    std::string list; Field(list, 1, entry); return list;
}
std::string GeoSite() {
    std::string domain; Integer(domain, 1, 3); Field(domain, 2, "binary.example.test");
    std::string entry; Field(entry, 1, "TEST"); Field(entry, 2, domain);
    std::string list; Field(list, 1, entry); return list;
}
std::string Hash(const std::string& bytes) {
    unsigned char digest[SHA256_DIGEST_LENGTH]; SHA256(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), digest);
    std::string result; const char* alphabet = "0123456789abcdef";
    for (auto byte : digest) { result += alphabet[byte >> 4]; result += alphabet[byte & 15]; } return result;
}
void VerifiedMaterialization() {
    Fixture files;
    files.Write("routing.rules", bindings + "[direct]\nset:site\nset:ip\n");
    const auto ip = GeoIp(), site = GeoSite(); files.Write("ip.dat", ip); files.Write("site.dat", site);
    auto config = Config(); Set(config, "ip", "geoip-dat", "ip.dat"); Set(config, "site", "geosite-dat", "site.dat");
    auto& sets = config["client"]["policy"]["rule-sets"];
    sets["ip"]["tag"] = "TEST"; sets["site"]["tag"] = "TEST";
    sets["ip"]["sha256"] = Hash(ip).c_str(); sets["site"]["sha256"] = Hash(site).c_str();
    const auto loaded = PolicySourceLoader::Load(config, files.ConfigPath());
    Require(loaded.Ok(), "Valid binary sources with matching hashes load");
    Require(loaded.source.rule_sets.at("ip").text == ip, "Loader retains verified binary bytes");
    files.Write("ip.dat", "malformed replacement"); std::filesystem::remove(files.root / "site.dat");
    std::filesystem::remove(files.root / "routing.rules");
    const auto snapshot = Compile(loaded);
    Require(PolicyEvaluator::Evaluate(*snapshot, "binary.example.test").action == PolicyAction::Direct, "Deleted GeoSite file must not alter checked bytes");
    Require(PolicyEvaluator::Evaluate(*snapshot, "", "192.0.2.7").action == PolicyAction::Direct, "Overwritten GeoIP must not alter checked bytes");
    auto mismatched = Config(); files.Write("routing.rules", bindings + "[direct]\nset:ip\n"); Set(mismatched, "ip", "geoip-dat", "ip.dat");
    mismatched["client"]["policy"]["rule-sets"]["ip"]["tag"] = "TEST";
    mismatched["client"]["policy"]["rule-sets"]["ip"]["sha256"] = Hash(ip).c_str();
    Require(!PolicySourceLoader::Load(mismatched, files.ConfigPath()).Ok(), "Changed bytes fail SHA-256 loading");
}
}
int main() {
    try { PipelineSemantics(); InvalidSources(); VerifiedMaterialization(); std::cout << "policy acceptance tests passed\n"; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    return 0;
}
