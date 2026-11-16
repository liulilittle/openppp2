#include <ppp/dns/DnsProviderCatalog.h>

namespace ppp {
    namespace dns {

        namespace {

            ppp::string TrimCopy(const ppp::string& text) {
                std::size_t begin = 0;
                while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin]))) {
                    ++begin;
                }
                std::size_t end = text.size();
                while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1]))) {
                    --end;
                }
                return text.substr(begin, end - begin);
            }

            ppp::string NormalizeProviderName(const ppp::string& name) noexcept {
                ppp::string normalized = TrimCopy(name);
                for (auto& ch : normalized) {
                    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
                }
                return normalized;
            }

            ServerEntry MakeEntry(
                Protocol protocol,
                const char* address,
                const char* hostname = NULLPTR,
                const char* url = NULLPTR) noexcept {

                ServerEntry entry;
                entry.protocol = protocol;
                if (NULLPTR != address) {
                    entry.address = address;
                }
                if (NULLPTR != hostname) {
                    entry.hostname = hostname;
                }
                if (NULLPTR != url) {
                    entry.url = url;
                }
                return entry;
            }

            const ppp::unordered_map<ppp::string, ppp::vector<ServerEntry> >& Providers() noexcept {
                static const ppp::unordered_map<ppp::string, ppp::vector<ServerEntry> > providers = {
                    { "doh.pub", {
                        // DNSPod serves DoH/DoT on 1.12.12.12 and 120.53.53.53; 119.29.29.29 is plain DNS only.
                        MakeEntry(Protocol::DoH, "1.12.12.12:443", "doh.pub", "https://doh.pub/dns-query"),
                        MakeEntry(Protocol::DoH, "120.53.53.53:443", "doh.pub", "https://doh.pub/dns-query"),
                        MakeEntry(Protocol::DoT, "1.12.12.12:853", "dot.pub"),
                        MakeEntry(Protocol::TCP, "119.29.29.29:53"),
                        MakeEntry(Protocol::UDP, "119.29.29.29:53") } },
                    { "alidns", {
                        MakeEntry(Protocol::DoH, "223.5.5.5:443", "dns.alidns.com", "https://dns.alidns.com/dns-query"),
                        MakeEntry(Protocol::DoT, "223.5.5.5:853", "dns.alidns.com"),
                        MakeEntry(Protocol::TCP, "223.5.5.5:53"),
                        MakeEntry(Protocol::UDP, "223.5.5.5:53") } },
                    // Baidu and 114 publish no DoH/DoT service; plain DNS only.
                    { "baidu", {
                        MakeEntry(Protocol::TCP, "180.76.76.76:53"),
                        MakeEntry(Protocol::UDP, "180.76.76.76:53") } },
                    { "360", {
                        MakeEntry(Protocol::DoH, "101.226.4.6:443", "doh.360.cn", "https://doh.360.cn/dns-query"),
                        MakeEntry(Protocol::DoT, "101.226.4.6:853", "dns.360.cn"),
                        MakeEntry(Protocol::TCP, "101.226.4.6:53"),
                        MakeEntry(Protocol::UDP, "101.226.4.6:53") } },
                    { "114", {
                        MakeEntry(Protocol::TCP, "114.114.114.114:53"),
                        MakeEntry(Protocol::UDP, "114.114.114.114:53") } },
                    // doh.tuna.tsinghua.edu.cn does not exist; TUNA only ever published DoT here.
                    { "tuna", {
                        MakeEntry(Protocol::DoT, "101.6.6.6:853", "dns.tuna.tsinghua.edu.cn"),
                        MakeEntry(Protocol::TCP, "101.6.6.6:53"),
                        MakeEntry(Protocol::UDP, "101.6.6.6:53") } },
                    { "cloudflare", {
                        MakeEntry(Protocol::DoH, "1.1.1.1:443", "cloudflare-dns.com", "https://cloudflare-dns.com/dns-query"),
                        MakeEntry(Protocol::DoT, "1.1.1.1:853", "cloudflare-dns.com"),
                        MakeEntry(Protocol::TCP, "1.1.1.1:53"),
                        MakeEntry(Protocol::UDP, "1.1.1.1:53") } },
                    { "google", {
                        MakeEntry(Protocol::DoH, "8.8.8.8:443", "dns.google", "https://dns.google/dns-query"),
                        MakeEntry(Protocol::DoT, "8.8.8.8:853", "dns.google"),
                        MakeEntry(Protocol::TCP, "8.8.8.8:53"),
                        MakeEntry(Protocol::UDP, "8.8.8.8:53") } },
                    { "quad9", {
                        MakeEntry(Protocol::DoH, "9.9.9.9:443", "dns.quad9.net", "https://dns.quad9.net/dns-query"),
                        MakeEntry(Protocol::DoT, "9.9.9.9:853", "dns.quad9.net"),
                        MakeEntry(Protocol::TCP, "9.9.9.9:53"),
                        MakeEntry(Protocol::UDP, "9.9.9.9:53") } },
                    { "adguard", {
                        MakeEntry(Protocol::DoH, "94.140.14.14:443", "dns.adguard.com", "https://dns.adguard.com/dns-query"),
                        MakeEntry(Protocol::DoT, "94.140.14.14:853", "dns.adguard.com"),
                        MakeEntry(Protocol::TCP, "94.140.14.14:53"),
                        MakeEntry(Protocol::UDP, "94.140.14.14:53") } },
                    { "nextdns", {
                        MakeEntry(Protocol::DoH, "45.90.28.0:443", "dns.nextdns.io", "https://dns.nextdns.io/dns-query"),
                        MakeEntry(Protocol::DoT, "45.90.28.0:853", "dns.nextdns.io"),
                        MakeEntry(Protocol::TCP, "45.90.28.0:53"),
                        MakeEntry(Protocol::UDP, "45.90.28.0:53") } },
                    { "mullvad", {
                        MakeEntry(Protocol::DoH, "194.242.2.2:443", "dns.mullvad.net", "https://dns.mullvad.net/dns-query"),
                        MakeEntry(Protocol::DoT, "194.242.2.2:853", "dns.mullvad.net"),
                        MakeEntry(Protocol::TCP, "194.242.2.2:53"),
                        MakeEntry(Protocol::UDP, "194.242.2.2:53") } },
                };
                return providers;
            }

        }

        bool DnsProviderCatalog::HasProvider(const ppp::string& name) noexcept {
            return NULLPTR != GetProvider(name);
        }

        bool DnsProviderCatalog::HasEncryptedEndpoint(const ppp::string& name) noexcept {
            const ppp::vector<ServerEntry>* provider = GetProvider(name);
            if (NULLPTR == provider) {
                return false;
            }
            for (const ServerEntry& entry : *provider) {
                if (entry.protocol == Protocol::DoH || entry.protocol == Protocol::DoT) {
                    return true;
                }
            }
            return false;
        }

        const ppp::vector<ServerEntry>* DnsProviderCatalog::GetProvider(const ppp::string& name) noexcept {
            const ppp::string key = NormalizeProviderName(name);
            const auto& providers = Providers();
            const auto tail = providers.find(key);
            return tail == providers.end() ? NULLPTR : &tail->second;
        }

    }
}
