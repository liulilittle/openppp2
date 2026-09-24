#define BOOST_TEST_MODULE human_routing_rules_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/routing/HumanRoutingRules.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <initializer_list>
#include <string>
#include <vector>

namespace routing = ppp::app::client::routing;

namespace {

using Bytes = std::vector<std::uint8_t>;

int ActionValue(routing::RoutingAction action) {
    return static_cast<int>(action);
}

int OriginValue(routing::RuleOrigin origin) {
    return static_cast<int>(origin);
}

int MatchTypeValue(routing::DomainMatchType type) {
    return static_cast<int>(type);
}

void ExpectLoadFailure(const std::string& text) {
    routing::HumanRoutingRules rules;
    BOOST_TEST(!rules.LoadText(text, "invalid.rules"));
    BOOST_TEST(!rules.Diagnostics().empty());
    BOOST_TEST(rules.Diagnostics().front().file == "invalid.rules");
}

void AppendVarint(Bytes& bytes, std::uint64_t value) {
    do {
        std::uint8_t byte = static_cast<std::uint8_t>(value & 0x7fu);
        value >>= 7u;
        if (value != 0) {
            byte |= 0x80u;
        }
        bytes.push_back(byte);
    } while (value != 0);
}

void AppendField(Bytes& message, std::uint32_t field, const Bytes& value) {
    AppendVarint(message, (static_cast<std::uint64_t>(field) << 3u) | 2u);
    AppendVarint(message, value.size());
    message.insert(message.end(), value.begin(), value.end());
}

void AppendString(Bytes& message, std::uint32_t field, const std::string& value) {
    AppendField(message, field, Bytes(value.begin(), value.end()));
}

void AppendVarintField(Bytes& message, std::uint32_t field, std::uint64_t value) {
    AppendVarint(message, static_cast<std::uint64_t>(field) << 3u);
    AppendVarint(message, value);
}

Bytes MakeCidr(std::initializer_list<std::uint8_t> address, std::uint8_t prefix) {
    Bytes cidr;
    AppendField(cidr, 1, Bytes(address));
    AppendVarintField(cidr, 2, prefix);
    return cidr;
}

Bytes MakeGeoIpDat(const std::string& country, const std::vector<Bytes>& cidrs) {
    Bytes entry;
    AppendString(entry, 1, country);
    for (const Bytes& cidr : cidrs) {
        AppendField(entry, 2, cidr);
    }
    Bytes list;
    AppendField(list, 1, entry);
    return list;
}

Bytes MakeDomain(std::uint8_t type, const std::string& value) {
    Bytes domain;
    AppendVarintField(domain, 1, type);
    AppendString(domain, 2, value);
    return domain;
}

Bytes MakeGeoSiteDat(const std::string& country, const std::vector<Bytes>& domains) {
    Bytes entry;
    AppendString(entry, 1, country);
    for (const Bytes& domain : domains) {
        AppendField(entry, 2, domain);
    }
    Bytes list;
    AppendField(list, 1, entry);
    return list;
}

class FixtureFile final {
public:
    explicit FixtureFile(const Bytes& bytes) : path_(NextPath()) {
        std::ofstream output(path_, std::ios::binary);
        BOOST_REQUIRE(output.good());
        output.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
        BOOST_REQUIRE(output.good());
    }

    explicit FixtureFile(const std::string& text) : path_(NextPath()) {
        std::ofstream output(path_, std::ios::binary);
        BOOST_REQUIRE(output.good());
        output << text;
        BOOST_REQUIRE(output.good());
    }

    ~FixtureFile() {
        std::remove(path_.c_str());
    }

    const std::string& path() const noexcept { return path_; }

private:
    static std::string NextPath() {
        static std::atomic_uint sequence{0};
        return "human-routing-geo-" + std::to_string(++sequence) + ".fixture";
    }

    std::string path_;
};

routing::HumanGeoDataSources DatSources(
    const FixtureFile& geoip,
    const FixtureFile& geosite) {
    routing::HumanGeoDataSources sources;
    sources.geoip_dat = geoip.path();
    sources.geosite_dat = geosite.path();
    return sources;
}

} // namespace

BOOST_AUTO_TEST_CASE(parses_confirmed_format_and_exposes_model) {
    const std::string text = R"RULES(
# routing policy
default proxy

dns direct doh.pub
dns proxy cloudflare

[direct]
lan
geo:cn
qq.com
baidu.com
192.168.0.0/16
10.20.30.40

[proxy]
google.com
youtube.com
=api.example.cn
8.8.8.8
)RULES";

    routing::HumanRoutingRules rules;
    BOOST_REQUIRE(rules.LoadText(text, "sample.rules"));
    BOOST_TEST(rules.Diagnostics().empty());
    BOOST_TEST(ActionValue(rules.DefaultAction()) == ActionValue(routing::RoutingAction::Proxy));

    BOOST_REQUIRE_EQUAL(rules.DnsProviders().size(), 2u);
    BOOST_TEST(ActionValue(rules.DnsProviders()[0].action) == ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(rules.DnsProviders()[0].provider == "doh.pub");
    BOOST_TEST(ActionValue(rules.DnsProviders()[1].action) == ActionValue(routing::RoutingAction::Proxy));
    BOOST_TEST(rules.DnsProviders()[1].provider == "cloudflare");

    BOOST_REQUIRE_EQUAL(rules.GeoDeclarations().size(), 1u);
    BOOST_TEST(rules.GeoDeclarations()[0].country == "cn");
    BOOST_TEST(rules.GeoDeclarations()[0].includes_geoip);
    BOOST_TEST(rules.GeoDeclarations()[0].includes_geosite);

    BOOST_TEST(ActionValue(rules.MatchDomain("qq.com")) == ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchDomain("www.QQ.com.")) == ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchDomain("google.com")) == ActionValue(routing::RoutingAction::Proxy));
    BOOST_TEST(ActionValue(rules.MatchDomain("api.example.cn")) == ActionValue(routing::RoutingAction::Proxy));
    BOOST_TEST(ActionValue(rules.MatchIpv4("10.20.30.40")) == ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchIpv4("8.8.8.8")) == ActionValue(routing::RoutingAction::Proxy));
    BOOST_TEST(ActionValue(rules.MatchIpv4("203.0.113.1")) == ActionValue(routing::RoutingAction::Proxy));
}

BOOST_AUTO_TEST_CASE(domain_priority_is_deterministic_and_not_line_ordered) {
    const std::string text = R"RULES(
default auto
[proxy]
*.example.com
=api.example.com
[direct]
example.com
very.example.com
=login.very.example.com
)RULES";

    routing::HumanRoutingRules rules;
    BOOST_REQUIRE(rules.LoadText(text));

    BOOST_TEST(ActionValue(rules.MatchDomain("example.com")) == ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchDomain("www.example.com")) == ActionValue(routing::RoutingAction::Proxy));
    BOOST_TEST(ActionValue(rules.MatchDomain("api.example.com")) == ActionValue(routing::RoutingAction::Proxy));
    BOOST_TEST(ActionValue(rules.MatchDomain("very.example.com")) == ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchDomain("x.very.example.com")) == ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchDomain("login.very.example.com")) == ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchDomain("other.test")) == ActionValue(routing::RoutingAction::Auto));
}

BOOST_AUTO_TEST_CASE(cidr_longest_prefix_and_single_ip_win) {
    const std::string text = R"RULES(
default proxy
[direct]
10.0.0.0/8
10.20.30.40
[proxy]
10.20.0.0/16
)RULES";

    routing::HumanRoutingRules rules;
    BOOST_REQUIRE(rules.LoadText(text));

    BOOST_TEST(ActionValue(rules.MatchIpv4("10.1.2.3")) == ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchIpv4("10.20.1.2")) == ActionValue(routing::RoutingAction::Proxy));
    BOOST_TEST(ActionValue(rules.MatchIpv4("10.20.30.40")) == ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchIpv4(0x0a141e28u)) == ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchIpv4("11.0.0.1")) == ActionValue(routing::RoutingAction::Proxy));
    BOOST_TEST(ActionValue(rules.MatchIpv4("not-an-ip")) == ActionValue(routing::RoutingAction::Auto));
}

BOOST_AUTO_TEST_CASE(lan_expands_required_local_ipv4_ranges) {
    routing::HumanRoutingRules rules;
    BOOST_REQUIRE(rules.LoadText("default proxy\n[direct]\nlan\n"));

    const char* local_addresses[] = {
        "10.1.2.3",       // RFC1918
        "172.31.255.1",   // RFC1918
        "192.168.10.20",  // RFC1918
        "127.0.0.1",      // loopback
        "169.254.20.30",  // link-local
        "100.100.20.30",  // CGNAT
    };
    for (const char* address : local_addresses) {
        BOOST_TEST(ActionValue(rules.MatchIpv4(address)) == ActionValue(routing::RoutingAction::Direct));
    }
    BOOST_TEST(ActionValue(rules.MatchIpv4("100.128.0.1")) == ActionValue(routing::RoutingAction::Proxy));
    BOOST_REQUIRE_EQUAL(rules.Ipv4Cidrs().size(), 6u);
    for (const auto& cidr : rules.Ipv4Cidrs()) {
        BOOST_TEST(cidr.from_lan);
    }
}

BOOST_AUTO_TEST_CASE(same_action_duplicates_are_stably_deduplicated) {
    const std::string text = R"RULES(
default direct
default direct
dns direct doh.pub
dns direct DOH.PUB
[direct]
Example.com
example.com.
10.20.30.40
10.20.30.40/32
geo:cn
geo:CN
)RULES";

    routing::HumanRoutingRules rules;
    BOOST_REQUIRE(rules.LoadText(text));
    BOOST_REQUIRE_EQUAL(rules.DomainRules().size(), 1u);
    BOOST_REQUIRE_EQUAL(rules.Ipv4Cidrs().size(), 1u);
    BOOST_REQUIRE_EQUAL(rules.GeoDeclarations().size(), 1u);
    BOOST_REQUIRE_EQUAL(rules.DnsProviders().size(), 1u);
    BOOST_TEST(rules.DomainRules()[0].line == 7u);
    BOOST_TEST(rules.Ipv4Cidrs()[0].line == 9u);
}

BOOST_AUTO_TEST_CASE(conflicts_report_current_and_original_lines) {
    routing::HumanRoutingRules rules;
    BOOST_TEST(!rules.LoadText(
        "[direct]\nexample.com\n[proxy]\nexample.com\n",
        "conflict.rules"));

    BOOST_REQUIRE_EQUAL(rules.Diagnostics().size(), 1u);
    const auto& diagnostic = rules.Diagnostics().front();
    BOOST_TEST(diagnostic.file == "conflict.rules");
    BOOST_TEST(diagnostic.line == 4u);
    BOOST_TEST(diagnostic.original_line == 2u);
    BOOST_TEST(diagnostic.reason.find("conflicting actions") != std::string::npos);
    BOOST_TEST(rules.DomainRules().empty());
}

BOOST_AUTO_TEST_CASE(canonical_cidr_and_lan_conflicts_are_rejected) {
    routing::HumanRoutingRules rules;
    BOOST_TEST(!rules.LoadText(
        "[direct]\nlan\n[proxy]\n192.168.12.34/16\n",
        "lan-conflict.rules"));
    BOOST_REQUIRE_EQUAL(rules.Diagnostics().size(), 1u);
    BOOST_TEST(rules.Diagnostics()[0].line == 4u);
    BOOST_TEST(rules.Diagnostics()[0].original_line == 2u);
}

BOOST_AUTO_TEST_CASE(safe_inline_comments_are_supported) {
    routing::HumanRoutingRules rules;
    BOOST_REQUIRE(rules.LoadText(
        "default proxy # fallback\n"
        "dns direct doh.pub # domestic\n"
        "[direct] # local\n"
        "example.com # suffix\n"));
    BOOST_TEST(ActionValue(rules.MatchDomain("sub.example.com")) == ActionValue(routing::RoutingAction::Direct));

    ExpectLoadFailure("[direct]\nexample.com#not-a-comment\n");
}

BOOST_AUTO_TEST_CASE(strict_syntax_errors_are_rejected) {
    const std::string invalid_inputs[] = {
        "example.com\n",
        "[unknown]\nexample.com\n",
        "[direct extra]\nexample.com\n",
        "default maybe\n",
        "dns auto doh.pub\n",
        "dns direct unknown-provider\n",
        "unknown directive\n",
        "[direct]\nbad_domain.example\n",
        "[direct]\n1.2.3.4/33\n",
        "[direct]\n2001:db8::1\n",
        "[direct]\nexample.com extra\n",
    };

    for (const std::string& input : invalid_inputs) {
        ExpectLoadFailure(input);
    }
}

BOOST_AUTO_TEST_CASE(file_loading_preserves_filename_in_diagnostics) {
    const std::string path = "human-routing-rules-invalid.fixture";
    {
        std::ofstream output(path, std::ios::binary);
        BOOST_REQUIRE(output.good());
        output << "[direct]\ninvalid_domain\n";
    }

    routing::HumanRoutingRules rules;
    BOOST_TEST(!rules.LoadFile(path));
    BOOST_REQUIRE(!rules.Diagnostics().empty());
    BOOST_TEST(rules.Diagnostics().front().file == path);
    std::remove(path.c_str());
}

BOOST_AUTO_TEST_CASE(compile_geo_combines_dat_and_text_with_precedence_and_provenance) {
    FixtureFile geoip(MakeGeoIpDat("CN", {
        MakeCidr({ 10, 20, 99, 7 }, 16),
        MakeCidr({ 198, 51, 100, 99 }, 24),
        MakeCidr({
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        }, 32),
    }));
    FixtureFile geosite(MakeGeoSiteDat("CN", {
        MakeDomain(0, "unsupported-keyword"),
        MakeDomain(2, "domain.only.cn"),
        MakeDomain(3, "full.only.cn"),
        MakeDomain(1, "^api[0-9]+\\.geo\\.cn$"),
        MakeDomain(2, "explicit.example.cn"),
    }));
    FixtureFile geoip_text(
        "203.0.113.99/24\n"
        "not-a-cidr\n"
        "2001:db8:ffff::1/48\n");
    FixtureFile geosite_text(
        "domain:supplement.example\n"
        "domain:\n"
        "plain:ignored-text-keyword\n");

    routing::HumanRoutingRules rules;
    BOOST_REQUIRE(rules.LoadText(
        "default proxy\n"
        "[proxy]\n"
        "explicit.example.cn\n"
        "10.20.0.0/16\n"
        "[direct]\n"
        "geo:cn\n",
        "human-production.rules"));
    routing::HumanGeoDataSources sources = DatSources(geoip, geosite);
    sources.geoip.push_back(geoip_text.path());
    sources.geosite.push_back(geosite_text.path());
    BOOST_REQUIRE(rules.CompileGeo(sources));

    BOOST_TEST(rules.GeoCompiled());
    BOOST_TEST(rules.GeoStats().ipv4_rules == 3u);
    BOOST_TEST(rules.GeoStats().domain_rules == 5u);
    BOOST_TEST(rules.GeoStats().ipv6_skipped == 2u);
    BOOST_TEST(rules.GeoStats().unsupported_skipped == 2u);
    BOOST_TEST(rules.GeoStats().source_skipped == 2u);
    BOOST_TEST(ActionValue(rules.MatchIpv4("10.20.30.40")) ==
        ActionValue(routing::RoutingAction::Proxy));
    BOOST_TEST(ActionValue(rules.MatchIpv4("198.51.100.8")) ==
        ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchIpv4("203.0.113.8")) ==
        ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchDomain("explicit.example.cn")) ==
        ActionValue(routing::RoutingAction::Proxy));
    BOOST_TEST(ActionValue(rules.MatchDomain("www.domain.only.cn")) ==
        ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchDomain("full.only.cn")) ==
        ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchDomain("www.full.only.cn")) ==
        ActionValue(routing::RoutingAction::Proxy));
    BOOST_TEST(ActionValue(rules.MatchDomain("api42.geo.cn")) ==
        ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchDomain("www.supplement.example")) ==
        ActionValue(routing::RoutingAction::Direct));

    const auto geo_cidr = std::find_if(rules.Ipv4Cidrs().begin(), rules.Ipv4Cidrs().end(),
        [](const routing::Ipv4CidrRule& rule) {
            return rule.cidr == "198.51.100.0/24";
        });
    BOOST_REQUIRE(geo_cidr != rules.Ipv4Cidrs().end());
    BOOST_TEST(OriginValue(geo_cidr->origin) == OriginValue(routing::RuleOrigin::Geo));
    BOOST_TEST(geo_cidr->country == "cn");
    BOOST_TEST(geo_cidr->path == geoip.path());
    BOOST_TEST(geo_cidr->line == 6u);

    const auto exact = std::find_if(rules.DomainRules().begin(), rules.DomainRules().end(),
        [](const routing::DomainRule& rule) {
            return rule.domain == "full.only.cn";
        });
    BOOST_REQUIRE(exact != rules.DomainRules().end());
    BOOST_TEST(MatchTypeValue(exact->type) == MatchTypeValue(routing::DomainMatchType::Exact));
    BOOST_TEST(OriginValue(exact->origin) == OriginValue(routing::RuleOrigin::Geo));
    BOOST_TEST(exact->country == "cn");
    BOOST_TEST(exact->path == geosite.path());
    BOOST_TEST(exact->line == 6u);
}

BOOST_AUTO_TEST_CASE(compile_geo_selector_missing_is_fatal_with_human_context) {
    FixtureFile geoip(MakeGeoIpDat("US", {
        MakeCidr({ 192, 0, 2, 1 }, 24),
    }));
    FixtureFile geosite(MakeGeoSiteDat("CN", {
        MakeDomain(2, "example.cn"),
    }));
    routing::HumanRoutingRules rules;
    BOOST_REQUIRE(rules.LoadText("[direct]\ngeo:cn\n", "routing/human.rules"));

    BOOST_TEST(!rules.CompileGeo(DatSources(geoip, geosite)));
    BOOST_TEST(!rules.GeoCompiled());
    BOOST_REQUIRE_EQUAL(rules.Diagnostics().size(), 1u);
    const routing::RoutingDiagnostic& diagnostic = rules.Diagnostics().front();
    BOOST_TEST(diagnostic.file == "routing/human.rules");
    BOOST_TEST(diagnostic.line == 2u);
    BOOST_TEST(diagnostic.reason.find("country=cn") != std::string::npos);
    BOOST_TEST(diagnostic.reason.find(geoip.path()) != std::string::npos);
    BOOST_TEST(diagnostic.reason.find("selector") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(compile_geo_truncated_dat_is_fatal) {
    FixtureFile geoip(Bytes{ 0x0a, 0x06, 0x0a, 0x02, 'C', 'N' });
    FixtureFile geosite(MakeGeoSiteDat("CN", {
        MakeDomain(2, "example.cn"),
    }));
    routing::HumanRoutingRules rules;
    BOOST_REQUIRE(rules.LoadText("[direct]\ngeo:cn\n", "truncated-human.rules"));

    BOOST_TEST(!rules.CompileGeo(DatSources(geoip, geosite)));
    BOOST_REQUIRE_EQUAL(rules.Diagnostics().size(), 1u);
    BOOST_TEST(rules.Diagnostics()[0].file == "truncated-human.rules");
    BOOST_TEST(rules.Diagnostics()[0].line == 2u);
    BOOST_TEST(rules.Diagnostics()[0].reason.find(geoip.path()) != std::string::npos);
    BOOST_TEST(rules.Diagnostics()[0].reason.find("truncated") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(compile_geo_requires_both_geoip_and_geosite_categories) {
    FixtureFile geoip_text("192.0.2.0/24\n");
    routing::HumanRoutingRules rules;
    BOOST_REQUIRE(rules.LoadText("[direct]\ngeo:cn\n", "missing-category.rules"));
    routing::HumanGeoDataSources sources;
    sources.geoip.push_back(geoip_text.path());

    BOOST_TEST(!rules.CompileGeo(sources));
    BOOST_REQUIRE_EQUAL(rules.Diagnostics().size(), 1u);
    BOOST_TEST(rules.Diagnostics()[0].file == "missing-category.rules");
    BOOST_TEST(rules.Diagnostics()[0].line == 2u);
    BOOST_TEST(rules.Diagnostics()[0].reason.find("GeoSite category") != std::string::npos);
    BOOST_TEST(rules.Diagnostics()[0].reason.find("path='<none>'") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(failed_recompile_removes_geo_rules_but_retains_explicit_rules) {
    FixtureFile valid_geoip(MakeGeoIpDat("CN", {
        MakeCidr({ 198, 51, 100, 3 }, 24),
    }));
    FixtureFile valid_geosite(MakeGeoSiteDat("CN", {
        MakeDomain(2, "geo-only.cn"),
    }));
    FixtureFile malformed_geoip(Bytes{ 0x0f });

    routing::HumanRoutingRules rules;
    BOOST_REQUIRE(rules.LoadText(
        "default proxy\n"
        "[direct]\n"
        "explicit.example\n"
        "192.0.2.0/24\n"
        "geo:cn\n",
        "rollback.rules"));
    BOOST_REQUIRE(rules.CompileGeo(DatSources(valid_geoip, valid_geosite)));
    BOOST_TEST(ActionValue(rules.MatchDomain("geo-only.cn")) ==
        ActionValue(routing::RoutingAction::Direct));

    BOOST_TEST(!rules.CompileGeo(DatSources(malformed_geoip, valid_geosite)));
    BOOST_TEST(!rules.GeoCompiled());
    BOOST_TEST(ActionValue(rules.MatchDomain("geo-only.cn")) ==
        ActionValue(routing::RoutingAction::Proxy));
    BOOST_TEST(ActionValue(rules.MatchDomain("explicit.example")) ==
        ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchIpv4("192.0.2.10")) ==
        ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(ActionValue(rules.MatchIpv4("198.51.100.10")) ==
        ActionValue(routing::RoutingAction::Proxy));
    BOOST_TEST(std::count_if(rules.DomainRules().begin(), rules.DomainRules().end(),
        [](const routing::DomainRule& rule) {
            return rule.origin == routing::RuleOrigin::Geo;
        }) == 0u);
    BOOST_TEST(std::count_if(rules.Ipv4Cidrs().begin(), rules.Ipv4Cidrs().end(),
        [](const routing::Ipv4CidrRule& rule) {
            return rule.origin == routing::RuleOrigin::Geo;
        }) == 0u);
}

BOOST_AUTO_TEST_CASE(structured_match_distinguishes_match_default_and_invalid_input) {
    routing::HumanRoutingRules rules;
    BOOST_REQUIRE(rules.LoadText(
        "default proxy\n"
        "[direct]\n"
        "example.com\n"
        "192.0.2.0/24\n"));

    const routing::RoutingMatch domain = rules.MatchDomainRule("www.example.com");
    BOOST_TEST(domain.valid);
    BOOST_TEST(domain.matched);
    BOOST_TEST(ActionValue(domain.action) == ActionValue(routing::RoutingAction::Direct));
    BOOST_TEST(domain.line == 3u);

    const routing::RoutingMatch missing_domain = rules.MatchDomainRule("unmatched.test");
    BOOST_TEST(missing_domain.valid);
    BOOST_TEST(!missing_domain.matched);
    BOOST_TEST(ActionValue(missing_domain.action) == ActionValue(routing::RoutingAction::Auto));
    BOOST_TEST(ActionValue(rules.MatchDomain("unmatched.test")) ==
        ActionValue(routing::RoutingAction::Proxy));

    const routing::RoutingMatch ipv4 = rules.MatchIpv4Rule("192.0.2.25");
    BOOST_TEST(ipv4.valid);
    BOOST_TEST(ipv4.matched);
    BOOST_TEST(ActionValue(ipv4.action) == ActionValue(routing::RoutingAction::Direct));

    const routing::RoutingMatch missing_ipv4 = rules.MatchIpv4Rule("198.51.100.7");
    BOOST_TEST(missing_ipv4.valid);
    BOOST_TEST(!missing_ipv4.matched);
    BOOST_TEST(ActionValue(missing_ipv4.action) == ActionValue(routing::RoutingAction::Auto));

    const routing::RoutingMatch invalid_ipv4 = rules.MatchIpv4Rule("not-an-ip");
    BOOST_TEST(!invalid_ipv4.valid);
    BOOST_TEST(!invalid_ipv4.matched);
}
