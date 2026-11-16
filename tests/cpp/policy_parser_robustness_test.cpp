#include <ppp/app/client/policy/PolicyCompiler.h>
#include <ppp/app/client/policy/PolicyEvaluator.h>
#include <ppp/app/client/routing/GeoDataReader.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace ppp::app::client::policy;
using namespace ppp::app::client::routing;
namespace {
void Require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
PolicySource Source(const std::string& body) {
    PolicySource source;
    source.rules_path = "robustness.rules";
    source.rules_text = "default proxy\ndns direct local\ndns proxy remote\n" + body;
    source.resolvers["local"] = {PolicyAction::Direct, {"udp://192.0.2.53:53"}};
    source.resolvers["remote"] = {PolicyAction::Proxy, {"tcp://198.51.100.53:53"}};
    return source;
}
std::string Field(unsigned char tag, const std::string& body) {
    Require(body.size() < 128, "Fixture length must fit one protobuf byte");
    return std::string(1, static_cast<char>(tag)) +
        std::string(1, static_cast<char>(body.size())) + body;
}
void ProtobufBoundaries() {
    static_assert(noexcept(GeoDataReader::ReadGeoIpBytes({}, {})));
    static_assert(noexcept(GeoDataReader::ReadGeoSiteBytes({}, {})));
    static_assert(noexcept(GeoDataReader::ReadGeoIpTextBytes({})));
    static_assert(noexcept(GeoDataReader::ReadGeoSiteTextBytes({})));
    const auto cidr = Field(0x0a, std::string("\xc0\x00\x02\x09", 4)) + std::string("\x10\x18", 2);
    const auto ip = Field(0x0a, Field(0x0a, "TEST") + Field(0x12, cidr));
    const auto domain = std::string("\x08\x03", 2) + Field(0x12, "fixture.test");
    const auto site = Field(0x0a, Field(0x0a, "TEST") + Field(0x12, domain));
    auto valid_ip = GeoDataReader::ReadGeoIpBytes(ip, "test");
    auto valid_site = GeoDataReader::ReadGeoSiteBytes(site, "test");
    Require(valid_ip.Succeeded() && valid_ip.entries.size() == 1 &&
        valid_ip.entries[0].cidr == "192.0.2.0/24", "GeoIP canonical fixture");
    Require(valid_site.Succeeded() && valid_site.entries.size() == 1 &&
        valid_site.entries[0].value == "fixture.test", "GeoSite fixture");
    // Each fixture is a single outer length-delimited record, so every nonempty
    // strict prefix must fail rather than expose partial selected entries.
    for (std::size_t n = 1; n < ip.size(); ++n) {
        auto result = GeoDataReader::ReadGeoIpBytes(std::string_view(ip.data(), n), "test");
        Require(result.status == GeoDataReadStatus::Malformed && result.entries.empty(), "Truncated GeoIP accepted");
    }
    for (std::size_t n = 1; n < site.size(); ++n) {
        auto result = GeoDataReader::ReadGeoSiteBytes(std::string_view(site.data(), n), "test");
        Require(result.status == GeoDataReadStatus::Malformed && result.entries.empty(), "Truncated GeoSite accepted");
    }
    std::vector<std::string> malformed = {
        std::string("\x00", 1), std::string("\x0f", 1), std::string("\x0a\x80", 2),
        std::string("\x0a\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02", 11),
        std::string("\x0a\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01", 11),
        std::string(11, static_cast<char>(0x80))
    };
    for (const auto& bytes : malformed) {
        auto a = GeoDataReader::ReadGeoIpBytes(bytes, "test");
        auto b = GeoDataReader::ReadGeoSiteBytes(bytes, "test");
        Require(a.status == GeoDataReadStatus::Malformed && a.entries.empty(), "Malformed GeoIP varint accepted");
        Require(b.status == GeoDataReadStatus::Malformed && b.entries.empty(), "Malformed GeoSite varint accepted");
        for (const auto& format : {"geoip-dat", "geosite-dat"}) {
            auto source = Source("[direct]\nset:broken\n");
            auto& set = source.rule_sets["broken"];
            set.format = format;
            set.path = "not-opened.dat";
            set.tag = "test";
            set.text = bytes;
            set.materialized = true;
            Require(!PolicyCompiler::Compile(source).Ok(), "Malformed Geo bytes produced policy snapshot");
        }
    }
    // Bounded mutation corpus checks memory safety and deterministic structured
    // outcomes; mutated valid records are intentionally allowed to parse.
    for (const auto& original : {ip, site}) {
        for (std::size_t pos = 0; pos < original.size(); ++pos) {
            for (unsigned char byte : {0u, 1u, 127u, 128u, 255u}) {
                auto mutated = original;
                mutated[pos] = static_cast<char>(byte);
                auto a = GeoDataReader::ReadGeoIpBytes(mutated, "test");
                auto b = GeoDataReader::ReadGeoIpBytes(mutated, "test");
                auto c = GeoDataReader::ReadGeoSiteBytes(mutated, "test");
                auto d = GeoDataReader::ReadGeoSiteBytes(mutated, "test");
                Require(a.status == b.status && a.entries.size() == b.entries.size() && a.diagnostic == b.diagnostic,
                    "GeoIP parse is nondeterministic");
                Require(c.status == d.status && c.entries.size() == d.entries.size() && c.diagnostic == d.diagnostic,
                    "GeoSite parse is nondeterministic");
            }
        }
    }
}
void SyntaxFailuresRetainSnapshot() {
    auto initial = PolicyCompiler::Compile(Source("[direct]\n=stable.test\n"), 77);
    Require(initial.Ok(), "Initial snapshot failed");
    auto active = initial.snapshot;
    const std::vector<std::string> bad = {
        "[direct", "[unknown]\nexample.test", "[direct]\n=", "[direct]\n=bad..test",
        "[direct]\n=" + std::string(64, 'a') + ".test",
        "[direct]\n=" + std::string(65536, 'a'),
        "[direct]\nregexp:[", "[direct]\nregexp:(", "[direct]\nregexp:*",
        "[direct]\n192.0.2.0/33", "[direct]\n192.0.2.0/-1", "[direct]\n192.0.2.0/",
        "[direct]\n192.0.2.0/24/1", "[direct]\n256.0.2.1", "[direct]\n192.0.2.1.",
        "[direct]\n=bad" + std::string(1, '\0') + ".test",
        "[direct]\n=bad" + std::string(1, static_cast<char>(0xff)) + ".test",
        "[dns:missing]\nexample.test", "default auto", "dns proxy remote extra"
    };
    for (const auto& body : bad) {
        auto candidate = PolicyCompiler::Compile(Source(body), 78);
        Require(!candidate.Ok() && !candidate.diagnostics.empty(), "Malformed rule produced snapshot");
        if (candidate.Ok()) active = candidate.snapshot;
        Require(active == initial.snapshot && active->Version() == 77 &&
            PolicyEvaluator::Evaluate(*active, "stable.test").action == PolicyAction::Direct,
            "Failed candidate displaced retained snapshot");
    }
    auto boundaries = PolicyCompiler::Compile(Source("[direct]\n0.0.0.0/0\n192.0.2.9/32\n"));
    Require(boundaries.Ok(), "Valid /0 and /32 boundaries rejected");
    Require(PolicyEvaluator::Evaluate(*boundaries.snapshot, "", "203.0.113.8").action == PolicyAction::Direct,
        "Zero prefix failed to match");
}
void ByteCorpus() {
    for (unsigned byte = 0; byte < 256; ++byte) {
        std::string input(1, static_cast<char>(byte));
        (void)GeoDataReader::ReadGeoIpBytes(input, "test");
        (void)GeoDataReader::ReadGeoSiteBytes(input, "test");
        (void)GeoDataReader::ReadGeoIpTextBytes(input);
        (void)GeoDataReader::ReadGeoSiteTextBytes(input);
        auto a = PolicyCompiler::Compile(Source("[direct]\n=" + input + ".test\n"));
        auto b = PolicyCompiler::Compile(Source("[direct]\n=" + input + ".test\n"));
        Require(a.Ok() == b.Ok() && a.diagnostics.size() == b.diagnostics.size(), "Compiler byte outcome changed");
    }
    auto ip = GeoDataReader::ReadGeoIpTextBytes("192.0.2.9/24\n300.0.0.1/24\n192.0.2.0/33\n");
    Require(ip.Succeeded() && ip.entries.size() == 1 && ip.skipped == 2 &&
        ip.entries[0].cidr == "192.0.2.0/24", "Text CIDR skip contract");
}
}
int main() {
    try {
        ProtobufBoundaries(); SyntaxFailuresRetainSnapshot(); ByteCorpus();
        std::cout << "policy parser robustness tests passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
    return 0;
}
