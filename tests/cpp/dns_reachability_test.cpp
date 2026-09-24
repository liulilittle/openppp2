#define BOOST_TEST_MODULE dns_reachability_test
#include <boost/test/included/unit_test.hpp>

#include <unordered_map>
#include <unordered_set>

#include <ppp/app/client/dns/DnsReachability.h>
#include <ppp/app/client/dns/DnsReachabilityParse.h>
#include <ppp/app/client/dns/Rule.h>
#include <ppp/configurations/DnsServerEntry.h>
#include <ppp/dns/DnsResolver.h>

namespace client_dns = ppp::app::client::dns;
namespace app_config = ppp::configurations;

namespace {

boost::asio::ip::address MakeAddress(const char* text) {
    boost::system::error_code ec;
    boost::asio::ip::address address = boost::asio::ip::make_address(text, ec);
    BOOST_REQUIRE(!ec);
    return address;
}

app_config::DnsServerEntry MakeConfigEntry(
    const char* protocol,
    const char* address,
    const char* url = "",
    const char* hostname = "",
    ppp::vector<ppp::string> bootstrap = {}) {

    app_config::DnsServerEntry entry;
    entry.protocol = protocol;
    entry.address = address;
    entry.url = url;
    entry.hostname = hostname;
    entry.bootstrap = std::move(bootstrap);
    return entry;
}

std::unordered_set<uint32_t> CollectIps(const ppp::function<void(const ppp::function<void(uint32_t)>&)>& run) {
    std::unordered_set<uint32_t> ips;
    run([&ips](uint32_t ip) noexcept {
        ips.insert(ip);
    });
    return ips;
}

}  // namespace

BOOST_AUTO_TEST_CASE(parse_reachability_ipv4_accepts_plain_address) {
    uint32_t ip = 0;
    BOOST_TEST(client_dns::ParseReachabilityIpv4("1.1.1.1", ip));
    BOOST_TEST(ip == htonl(0x01010101u));
}

BOOST_AUTO_TEST_CASE(parse_reachability_ipv4_accepts_host_port) {
    uint32_t ip = 0;
    BOOST_TEST(client_dns::ParseReachabilityIpv4("9.9.9.9:53", ip));
    BOOST_TEST(ip == htonl(0x09090909u));
}

BOOST_AUTO_TEST_CASE(parse_reachability_ipv4_rejects_loopback) {
    uint32_t ip = 0;
    BOOST_TEST(!client_dns::ParseReachabilityIpv4("127.0.0.1", ip));
}

BOOST_AUTO_TEST_CASE(parse_reachability_ipv4_rejects_multicast) {
    uint32_t ip = 0;
    BOOST_TEST(!client_dns::ParseReachabilityIpv4("224.0.0.1", ip));
}

BOOST_AUTO_TEST_CASE(build_resolver_entries_maps_protocols) {
    ppp::vector<app_config::DnsServerEntry> config_entries;
    config_entries.push_back(MakeConfigEntry("doh", "1.1.1.1:443", "https://example/dns-query", "example"));
    config_entries.push_back(MakeConfigEntry("dot", "1.1.1.1:853", "", "dot.example"));
    config_entries.push_back(MakeConfigEntry("doq", "1.1.1.1:853"));
    config_entries.push_back(MakeConfigEntry("tcp", "8.8.8.8:53"));
    config_entries.push_back(MakeConfigEntry("udp", "9.9.9.9:53"));
    config_entries.push_back(MakeConfigEntry("DoH", "1.0.0.1:443"));

    const ppp::vector<ppp::dns::ServerEntry> entries =
        client_dns::DnsReachability::BuildResolverEntries(config_entries);

    BOOST_REQUIRE_EQUAL(entries.size(), 6u);
    BOOST_TEST(static_cast<int>(entries[0].protocol) == static_cast<int>(ppp::dns::Protocol::DoH));
    BOOST_TEST(entries[0].url == "https://example/dns-query");
    BOOST_TEST(entries[0].hostname == "example");
    BOOST_TEST(static_cast<int>(entries[1].protocol) == static_cast<int>(ppp::dns::Protocol::DoT));
    BOOST_TEST(static_cast<int>(entries[2].protocol) == static_cast<int>(ppp::dns::Protocol::DoT));
    BOOST_TEST(static_cast<int>(entries[3].protocol) == static_cast<int>(ppp::dns::Protocol::TCP));
    BOOST_TEST(static_cast<int>(entries[4].protocol) == static_cast<int>(ppp::dns::Protocol::UDP));
    BOOST_TEST(static_cast<int>(entries[5].protocol) == static_cast<int>(ppp::dns::Protocol::DoH));
}

BOOST_AUTO_TEST_CASE(build_resolver_entries_parses_bootstrap_ips) {
    ppp::vector<app_config::DnsServerEntry> config_entries;
    config_entries.push_back(MakeConfigEntry(
        "udp", "1.1.1.1:53", "", "", { "8.8.8.8", "invalid-host", "127.0.0.1" }));

    const ppp::vector<ppp::dns::ServerEntry> entries =
        client_dns::DnsReachability::BuildResolverEntries(config_entries);

    BOOST_REQUIRE_EQUAL(entries.size(), 1u);
    BOOST_REQUIRE_EQUAL(entries[0].bootstrap_ips.size(), 1u);
    BOOST_TEST(entries[0].bootstrap_ips[0] == MakeAddress("8.8.8.8"));
}

BOOST_AUTO_TEST_CASE(collect_provider_ips_cloudflare_contains_public_ipv4) {
    std::unordered_set<uint32_t> ips;
    client_dns::DnsReachability::CollectProviderIps("cloudflare", [&ips](uint32_t ip) noexcept {
        ips.insert(ip);
    });

    BOOST_TEST(!ips.empty());
    BOOST_TEST(ips.count(htonl(0x01010101u)) > 0);
}

BOOST_AUTO_TEST_CASE(collect_server_entry_ips_literal_and_provider) {
    ppp::vector<app_config::DnsServerEntry> entries;
    entries.push_back(MakeConfigEntry("udp", "1.2.3.4:53"));
    entries.push_back(MakeConfigEntry("udp", "cloudflare"));
    entries.push_back(MakeConfigEntry("udp", "203.0.113.10:53", "", "", { "198.51.100.20" }));

    const auto ips = CollectIps([&entries](const ppp::function<void(uint32_t)>& add_ip) noexcept {
        client_dns::DnsReachability::CollectServerEntryIps(entries, add_ip);
    });

    BOOST_TEST(ips.count(htonl(0x01020304u)) > 0);
    BOOST_TEST(ips.count(htonl(0x01010101u)) > 0);
    BOOST_TEST(ips.count(htonl(0xcb00710au)) > 0);
    BOOST_TEST(ips.count(htonl(0xc6336414u)) > 0);
}

BOOST_AUTO_TEST_CASE(collect_rule_table_ips_splits_nic_and_tunnel) {
    ppp::unordered_map<ppp::string, client_dns::Rule::Ptr> rules;

    auto nic_rule = ppp::make_shared_object<client_dns::Rule>();
    nic_rule->Server = MakeAddress("1.0.0.1");
    nic_rule->Nic = true;
    rules.emplace("nic.example", nic_rule);

    auto tunnel_rule = ppp::make_shared_object<client_dns::Rule>();
    tunnel_rule->Server = MakeAddress("8.8.4.4");
    tunnel_rule->Nic = false;
    rules.emplace("tunnel.example", tunnel_rule);

    auto provider_rule = ppp::make_shared_object<client_dns::Rule>();
    provider_rule->ProviderName = "cloudflare";
    rules.emplace("provider-tunnel.example", provider_rule);

    auto provider_nic_rule = ppp::make_shared_object<client_dns::Rule>();
    provider_nic_rule->ProviderName = "cloudflare";
    provider_nic_rule->Nic = true;
    rules.emplace("provider-nic.example", provider_nic_rule);

    std::unordered_set<uint32_t> nic_ips;
    std::unordered_set<uint32_t> tunnel_ips;
    client_dns::DnsReachability::CollectRuleTableReachabilityIps(
        rules,
        [&tunnel_ips](uint32_t ip) noexcept { tunnel_ips.insert(ip); },
        [&nic_ips](uint32_t ip) noexcept { nic_ips.insert(ip); });

    BOOST_TEST(nic_ips.count(htonl(0x01000001u)) > 0);
    BOOST_TEST(tunnel_ips.count(htonl(0x08080404u)) > 0);
    BOOST_TEST(nic_ips.count(htonl(0x01010101u)) > 0);
    BOOST_TEST(tunnel_ips.count(htonl(0x01010101u)) > 0);
}

BOOST_AUTO_TEST_CASE(collect_provider_ips_unknown_is_noop) {
    bool called = false;
    client_dns::DnsReachability::CollectProviderIps("not-a-provider", [&called](uint32_t) noexcept {
        called = true;
    });
    BOOST_TEST(!called);
}
