#include "DnsReachability.h"

#include "DnsReachabilityParse.h"
#include <ppp/app/client/dns/Rule.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/dns/DnsProviderCatalog.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                static ppp::dns::ServerEntry DnsServerEntryToResolverEntry(
                    const ppp::configurations::DnsServerEntry& ce) noexcept {

                    ppp::dns::ServerEntry se;
                    ppp::string proto = ce.protocol;
                    for (auto& c : proto) {
                        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    }
                    if (proto == "doh") {
                        se.protocol = ppp::dns::Protocol::DoH;
                    }
                    else if (proto == "dot" || proto == "doq") {
                        se.protocol = ppp::dns::Protocol::DoT;
                    }
                    else if (proto == "tcp") {
                        se.protocol = ppp::dns::Protocol::TCP;
                    }
                    else {
                        se.protocol = ppp::dns::Protocol::UDP;
                    }
                    se.url = ce.url;
                    se.hostname = ce.hostname;
                    se.address = ce.address;
                    for (const auto& b : ce.bootstrap) {
                        boost::system::error_code ec;
                        boost::asio::ip::address addr = boost::asio::ip::make_address(b, ec);
                        if (!ec && !addr.is_unspecified() && !addr.is_loopback()) {
                            se.bootstrap_ips.push_back(addr);
                        }
                    }
                    return se;
                }

                ppp::vector<ppp::dns::ServerEntry> DnsReachability::BuildResolverEntries(
                    const ppp::vector<ppp::configurations::DnsServerEntry>& config_entries) noexcept {

                    ppp::vector<ppp::dns::ServerEntry> result;
                    result.reserve(config_entries.size());
                    for (const auto& ce : config_entries) {
                        result.emplace_back(DnsServerEntryToResolverEntry(ce));
                    }
                    return result;
                }

                bool DnsReachability::ParseReachabilityIpv4(const ppp::string& address, uint32_t& ipnet) noexcept {
                    return dns::ParseReachabilityIpv4(address, ipnet);
                }

                void DnsReachability::CollectProviderIps(
                    const ppp::string& provider_name,
                    const ppp::function<void(uint32_t)>& add_ip) noexcept {

                    if (provider_name.empty() || !add_ip) {
                        return;
                    }

                    const ppp::vector<ppp::dns::ServerEntry>* provider =
                        ppp::dns::DnsProviderCatalog::GetProvider(provider_name);
                    if (NULLPTR == provider) {
                        return;
                    }

                    for (const ppp::dns::ServerEntry& entry : *provider) {
                        uint32_t ip = ppp::net::IPEndPoint::AnyAddress;
                        if (dns::ParseReachabilityIpv4(entry.address, ip)) {
                            add_ip(ip);
                        }
                        for (const boost::asio::ip::address& bootstrap : entry.bootstrap_ips) {
                            if (bootstrap.is_v4() && !bootstrap.is_unspecified() &&
                                !bootstrap.is_loopback() && !bootstrap.is_multicast()) {
                                add_ip(htonl(bootstrap.to_v4().to_uint()));
                            }
                        }
                    }
                }

                void DnsReachability::CollectServerEntryIps(
                    const ppp::vector<ppp::configurations::DnsServerEntry>& entries,
                    const ppp::function<void(uint32_t)>& add_ip) noexcept {

                    if (!add_ip) {
                        return;
                    }

                    for (const auto& entry : entries) {
                        if (!entry.address.empty() && ppp::dns::DnsProviderCatalog::HasProvider(entry.address)) {
                            CollectProviderIps(entry.address, add_ip);
                        }
                        else {
                            uint32_t ip = ppp::net::IPEndPoint::AnyAddress;
                            if (dns::ParseReachabilityIpv4(entry.address, ip)) {
                                add_ip(ip);
                            }
                        }

                        for (const ppp::string& bootstrap : entry.bootstrap) {
                            uint32_t ip = ppp::net::IPEndPoint::AnyAddress;
                            if (dns::ParseReachabilityIpv4(bootstrap, ip)) {
                                add_ip(ip);
                            }
                        }
                    }
                }

                void DnsReachability::CollectInterceptReachabilityIps(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                    const ppp::function<void(uint32_t)>& add_ip) noexcept {

                    if (NULLPTR == configuration || !add_ip) {
                        return;
                    }

                    CollectProviderIps(configuration->dns.servers.foreign, add_ip);
                    CollectProviderIps(configuration->dns.servers.domestic, add_ip);
                    CollectProviderIps("cloudflare", add_ip);
                    CollectServerEntryIps(configuration->dns.servers.foreign_entries, add_ip);
                    CollectServerEntryIps(configuration->dns.servers.domestic_entries, add_ip);
                }

                void DnsReachability::CollectRuleTableReachabilityIps(
                    const ppp::unordered_map<ppp::string, Rule::Ptr>& rules,
                    const ppp::function<void(uint32_t)>& add_tunnel_ip,
                    const ppp::function<void(uint32_t)>& add_nic_ip) noexcept {

                    for (const auto& pair : rules) {
                        const Rule::Ptr& rule = pair.second;
                        if (NULLPTR == rule) {
                            continue;
                        }

                        if (!rule->ProviderName.empty()) {
                            CollectProviderIps(
                                rule->ProviderName,
                                rule->Nic ? add_nic_ip : add_tunnel_ip);
                            continue;
                        }

                        if (!rule->Server.is_v4()) {
                            continue;
                        }

                        uint32_t ip = htonl(rule->Server.to_v4().to_uint());
                        if (rule->Nic) {
                            if (add_nic_ip) {
                                add_nic_ip(ip);
                            }
                        }
                        else if (add_tunnel_ip) {
                            add_tunnel_ip(ip);
                        }
                    }
                }

            }
        }
    }
}
