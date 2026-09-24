#define BOOST_TEST_MODULE geo_data_reader_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/routing/GeoDataReader.h>

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

Bytes MakeCidr(Bytes address, std::uint8_t prefix) {
    Bytes cidr;
    AppendField(cidr, 1, address);
    AppendVarintField(cidr, 2, prefix);
    return cidr;
}

Bytes MakeGeoIpEntry(const std::string& country, const std::vector<Bytes>& cidrs) {
    Bytes entry;
    AppendString(entry, 1, country);
    for (const Bytes& cidr : cidrs) {
        AppendField(entry, 2, cidr);
    }
    return entry;
}

Bytes MakeGeoIpList(const std::string& country, const std::vector<Bytes>& cidrs) {
    Bytes list;
    AppendField(list, 1, MakeGeoIpEntry(country, cidrs));
    return list;
}

Bytes MakeDomain(routing::GeoDataDomainType type, const std::string& value) {
    Bytes domain;
    AppendVarintField(domain, 1, static_cast<std::uint8_t>(type));
    AppendString(domain, 2, value);
    return domain;
}

Bytes MakeGeoSiteList(
    const std::string& country,
    const std::vector<Bytes>& domains) {
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
        return "geo-data-reader-" + std::to_string(++sequence) + ".fixture";
    }

    std::string path_;
};

int StatusValue(routing::GeoDataReadStatus status) {
    return static_cast<int>(status);
}

int DomainTypeValue(routing::GeoDataDomainType type) {
    return static_cast<int>(type);
}

} // namespace

BOOST_AUTO_TEST_CASE(geoip_dat_selects_category_and_canonicalizes_ipv4_and_ipv6) {
    const Bytes ipv6 = {
        0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
        0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
    };
    Bytes list;
    AppendField(list, 1, MakeGeoIpEntry("US", { MakeCidr({ 203, 0, 113, 9 }, 24) }));
    AppendField(list, 1, MakeGeoIpEntry("CN", {
        MakeCidr({ 10, 20, 30, 40 }, 16),
        MakeCidr(ipv6, 48),
        MakeCidr({ 1, 2, 3, 4, 5 }, 20),
    }));
    FixtureFile fixture(list);

    const routing::GeoIpReadResult result =
        routing::GeoDataReader::ReadGeoIp(fixture.path(), "geoip:CN");
    BOOST_REQUIRE(result.Succeeded());
    BOOST_TEST(result.diagnostic.empty());
    BOOST_REQUIRE_EQUAL(result.entries.size(), 2u);
    BOOST_TEST(result.entries[0].cidr == "10.20.0.0/16");
    BOOST_TEST(result.entries[1].cidr == "2001:db8:1234::/48");
    BOOST_TEST(result.entries[1].address.size() == 16u);
    BOOST_TEST(result.ipv4_entries == 1u);
    BOOST_TEST(result.ipv6_entries == 1u);
    BOOST_TEST(result.skipped == 1u);
}

BOOST_AUTO_TEST_CASE(geoip_dat_reports_missing_selector_and_malformed_inputs) {
    FixtureFile valid(MakeGeoIpList("US", { MakeCidr({ 192, 0, 2, 1 }, 24) }));
    const routing::GeoIpReadResult missing =
        routing::GeoDataReader::ReadGeoIp(valid.path(), "cn");
    BOOST_TEST(StatusValue(missing.status) ==
        StatusValue(routing::GeoDataReadStatus::SelectorMissing));
    BOOST_TEST(missing.entries.empty());
    BOOST_TEST(missing.diagnostic.find("cn") != std::string::npos);

    FixtureFile truncated(Bytes{ 0x0a, 0x05, 0x0a, 0x02, 'C' });
    const routing::GeoIpReadResult truncated_result =
        routing::GeoDataReader::ReadGeoIp(truncated.path(), "cn");
    BOOST_TEST(StatusValue(truncated_result.status) ==
        StatusValue(routing::GeoDataReadStatus::Malformed));
    BOOST_TEST(truncated_result.entries.empty());
    BOOST_TEST(truncated_result.diagnostic.find("truncated") != std::string::npos);

    FixtureFile malformed(Bytes{ 0x0f });
    const routing::GeoIpReadResult malformed_result =
        routing::GeoDataReader::ReadGeoIp(malformed.path(), "cn");
    BOOST_TEST(StatusValue(malformed_result.status) ==
        StatusValue(routing::GeoDataReadStatus::Malformed));
    BOOST_TEST(malformed_result.diagnostic.find("wire type") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(geosite_dat_preserves_plain_regex_domain_full_order) {
    FixtureFile fixture(MakeGeoSiteList("CN", {
        MakeDomain(routing::GeoDataDomainType::Plain, "keyword"),
        MakeDomain(routing::GeoDataDomainType::Regex, "^api\\.example\\.cn$"),
        MakeDomain(routing::GeoDataDomainType::Domain, "example.cn"),
        MakeDomain(routing::GeoDataDomainType::Full, "login.example.cn"),
    }));

    const routing::GeoSiteReadResult result =
        routing::GeoDataReader::ReadGeoSite(fixture.path(), "geosite:cn");
    BOOST_REQUIRE(result.Succeeded());
    BOOST_REQUIRE_EQUAL(result.entries.size(), 4u);
    const routing::GeoDataDomainType expected_types[] = {
        routing::GeoDataDomainType::Plain,
        routing::GeoDataDomainType::Regex,
        routing::GeoDataDomainType::Domain,
        routing::GeoDataDomainType::Full,
    };
    const char* expected_values[] = {
        "keyword", "^api\\.example\\.cn$", "example.cn", "login.example.cn",
    };
    for (std::size_t index = 0; index < result.entries.size(); ++index) {
        BOOST_TEST(DomainTypeValue(result.entries[index].type) ==
            DomainTypeValue(expected_types[index]));
        BOOST_TEST(result.entries[index].value == expected_values[index]);
    }
}

BOOST_AUTO_TEST_CASE(geosite_dat_reports_missing_selector_and_nested_malformed_data) {
    FixtureFile valid(MakeGeoSiteList("US", {
        MakeDomain(routing::GeoDataDomainType::Domain, "example.com"),
    }));
    const routing::GeoSiteReadResult missing =
        routing::GeoDataReader::ReadGeoSite(valid.path(), "cn");
    BOOST_TEST(StatusValue(missing.status) ==
        StatusValue(routing::GeoDataReadStatus::SelectorMissing));

    Bytes bad_domain;
    AppendVarintField(bad_domain, 1, 2);
    bad_domain.push_back(0x12);
    bad_domain.push_back(0x04);
    bad_domain.push_back('b');
    Bytes entry;
    AppendString(entry, 1, "CN");
    AppendField(entry, 2, bad_domain);
    Bytes list;
    AppendField(list, 1, entry);
    FixtureFile malformed(list);

    const routing::GeoSiteReadResult result =
        routing::GeoDataReader::ReadGeoSite(malformed.path(), "cn");
    BOOST_TEST(StatusValue(result.status) ==
        StatusValue(routing::GeoDataReadStatus::Malformed));
    BOOST_TEST(result.entries.empty());
    BOOST_TEST(result.diagnostic.find("truncated") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(text_sources_parse_types_lines_counts_and_canonical_addresses) {
    FixtureFile geoip(
        "# addresses\n"
        "10.20.30.40/16\n"
        "geoip:2001:db8:abcd:1234::1/48\n"
        "not-an-address\n");
    const routing::GeoIpReadResult ip_result =
        routing::GeoDataReader::ReadGeoIpText(geoip.path());
    BOOST_REQUIRE(ip_result.Succeeded());
    BOOST_REQUIRE_EQUAL(ip_result.entries.size(), 2u);
    BOOST_TEST(ip_result.entries[0].cidr == "10.20.0.0/16");
    BOOST_TEST(ip_result.entries[0].line == 2u);
    BOOST_TEST(ip_result.entries[1].cidr == "2001:db8:abcd::/48");
    BOOST_TEST(ip_result.entries[1].line == 3u);
    BOOST_TEST(ip_result.ipv4_entries == 1u);
    BOOST_TEST(ip_result.ipv6_entries == 1u);
    BOOST_TEST(ip_result.skipped == 1u);

    FixtureFile geosite(
        "plain:word\n"
        "regexp:^api\\.example$\n"
        "domain:.Example.COM\n"
        "full:login.example.com\n"
        "plain: # malformed\n");
    const routing::GeoSiteReadResult site_result =
        routing::GeoDataReader::ReadGeoSiteText(geosite.path());
    BOOST_REQUIRE(site_result.Succeeded());
    BOOST_REQUIRE_EQUAL(site_result.entries.size(), 4u);
    BOOST_TEST(site_result.entries[0].line == 1u);
    BOOST_TEST(DomainTypeValue(site_result.entries[0].type) ==
        DomainTypeValue(routing::GeoDataDomainType::Plain));
    BOOST_TEST(DomainTypeValue(site_result.entries[1].type) ==
        DomainTypeValue(routing::GeoDataDomainType::Regex));
    BOOST_TEST(DomainTypeValue(site_result.entries[2].type) ==
        DomainTypeValue(routing::GeoDataDomainType::Domain));
    BOOST_TEST(site_result.entries[2].value == "Example.COM");
    BOOST_TEST(DomainTypeValue(site_result.entries[3].type) ==
        DomainTypeValue(routing::GeoDataDomainType::Full));
    BOOST_TEST(site_result.skipped == 1u);
}

BOOST_AUTO_TEST_CASE(binary_and_text_readers_report_missing_files) {
    const std::string missing = "geo-data-reader-definitely-missing.fixture";
    const routing::GeoIpReadResult dat_ip =
        routing::GeoDataReader::ReadGeoIp(missing, "cn");
    const routing::GeoSiteReadResult dat_site =
        routing::GeoDataReader::ReadGeoSite(missing, "cn");
    const routing::GeoIpReadResult text_ip =
        routing::GeoDataReader::ReadGeoIpText(missing);
    const routing::GeoSiteReadResult text_site =
        routing::GeoDataReader::ReadGeoSiteText(missing);

    BOOST_TEST(StatusValue(dat_ip.status) ==
        StatusValue(routing::GeoDataReadStatus::FileMissing));
    BOOST_TEST(StatusValue(dat_site.status) ==
        StatusValue(routing::GeoDataReadStatus::FileMissing));
    BOOST_TEST(StatusValue(text_ip.status) ==
        StatusValue(routing::GeoDataReadStatus::FileMissing));
    BOOST_TEST(StatusValue(text_site.status) ==
        StatusValue(routing::GeoDataReadStatus::FileMissing));
}
