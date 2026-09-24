#include <ppp/app/client/routing/HumanRoutingRules.h>

#include <ppp/app/client/routing/GeoDataReader.h>
#include <ppp/dns/DnsProviderCatalog.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <exception>
#include <fstream>
#include <limits>
#include <sstream>
#include <unordered_map>
#include <utility>

namespace ppp::app::client::routing {
namespace {

    std::string Trim(const std::string& value) {
        std::size_t begin = 0;
        while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin]))) {
            ++begin;
        }

        std::size_t end = value.size();
        while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
            --end;
        }
        return value.substr(begin, end - begin);
    }

    std::string ToLowerAscii(std::string value) {
        for (char& ch : value) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        return value;
    }

    std::string StripSafeComment(const std::string& line) {
        for (std::size_t i = 0; i < line.size(); ++i) {
            if (line[i] == '#' && (i == 0 || std::isspace(static_cast<unsigned char>(line[i - 1])))) {
                return line.substr(0, i);
            }
        }
        return line;
    }

    std::vector<std::string> SplitWhitespace(const std::string& line) {
        std::istringstream stream(line);
        std::vector<std::string> tokens;
        std::string token;
        while (stream >> token) {
            tokens.emplace_back(std::move(token));
        }
        return tokens;
    }

    bool ParseAction(const std::string& token, RoutingAction& action) noexcept {
        const std::string normalized = ToLowerAscii(token);
        if (normalized == "auto") {
            action = RoutingAction::Auto;
            return true;
        }
        if (normalized == "direct") {
            action = RoutingAction::Direct;
            return true;
        }
        if (normalized == "proxy") {
            action = RoutingAction::Proxy;
            return true;
        }
        return false;
    }

    const char* ActionName(RoutingAction action) noexcept {
        switch (action) {
        case RoutingAction::Direct:
            return "direct";
        case RoutingAction::Proxy:
            return "proxy";
        default:
            return "auto";
        }
    }

    bool ParseIpv4(const std::string& text, std::uint32_t& address) noexcept {
        if (text.empty()) {
            return false;
        }

        std::uint32_t result = 0;
        std::size_t offset = 0;
        for (int octet_index = 0; octet_index < 4; ++octet_index) {
            const std::size_t separator = text.find('.', offset);
            const std::size_t end = separator == std::string::npos ? text.size() : separator;
            if (end == offset || (octet_index < 3 && separator == std::string::npos) ||
                (octet_index == 3 && separator != std::string::npos)) {
                return false;
            }

            unsigned int octet = 0;
            for (std::size_t i = offset; i < end; ++i) {
                const unsigned char ch = static_cast<unsigned char>(text[i]);
                if (!std::isdigit(ch)) {
                    return false;
                }
                octet = octet * 10u + static_cast<unsigned int>(ch - '0');
                if (octet > 255u) {
                    return false;
                }
            }

            result = (result << 8u) | octet;
            offset = end + 1;
        }

        address = result;
        return true;
    }

    std::uint32_t PrefixMask(std::uint8_t prefix_length) noexcept {
        if (prefix_length == 0) {
            return 0;
        }
        return std::numeric_limits<std::uint32_t>::max() << (32u - prefix_length);
    }

    std::string Ipv4ToString(std::uint32_t address) {
        return std::to_string((address >> 24u) & 0xffu) + "." +
            std::to_string((address >> 16u) & 0xffu) + "." +
            std::to_string((address >> 8u) & 0xffu) + "." +
            std::to_string(address & 0xffu);
    }

    bool ParseCidr(const std::string& text, std::uint32_t& network, std::uint8_t& prefix_length) noexcept {
        const std::size_t slash = text.find('/');
        if (slash != std::string::npos && text.find('/', slash + 1) != std::string::npos) {
            return false;
        }

        const std::string address_text = slash == std::string::npos ? text : text.substr(0, slash);
        std::uint32_t address = 0;
        if (!ParseIpv4(address_text, address)) {
            return false;
        }

        unsigned int prefix = 32;
        if (slash != std::string::npos) {
            const std::string prefix_text = text.substr(slash + 1);
            if (prefix_text.empty()) {
                return false;
            }
            prefix = 0;
            for (char raw_ch : prefix_text) {
                const unsigned char ch = static_cast<unsigned char>(raw_ch);
                if (!std::isdigit(ch)) {
                    return false;
                }
                prefix = prefix * 10u + static_cast<unsigned int>(ch - '0');
                if (prefix > 32u) {
                    return false;
                }
            }
        }

        prefix_length = static_cast<std::uint8_t>(prefix);
        network = address & PrefixMask(prefix_length);
        return true;
    }

    std::string GeoSourceContext(const GeoDeclaration& declaration, const std::string& path,
                                 const std::string& detail) {
        std::string reason = "geo compile failed: country=" + declaration.country +
            " path='" + path + "' selector='" + declaration.country + "'";
        if (!detail.empty()) {
            reason += ": " + detail;
        }
        return reason;
    }

    bool LooksLikeIpv4OrCidr(const std::string& value) noexcept {
        if (value.find('/') != std::string::npos) {
            return true;
        }
        return !value.empty() && std::all_of(value.begin(), value.end(), [](char raw_ch) {
            const unsigned char ch = static_cast<unsigned char>(raw_ch);
            return std::isdigit(ch) || ch == '.';
        });
    }

    bool NormalizeDomain(const std::string& input, std::string& domain) noexcept {
        domain = ToLowerAscii(input);
        if (!domain.empty() && domain.back() == '.') {
            domain.pop_back();
        }
        if (domain.empty() || domain.size() > 253 || domain.front() == '.' || domain.back() == '.') {
            return false;
        }

        std::size_t label_begin = 0;
        while (label_begin < domain.size()) {
            const std::size_t dot = domain.find('.', label_begin);
            const std::size_t label_end = dot == std::string::npos ? domain.size() : dot;
            const std::size_t label_length = label_end - label_begin;
            if (label_length == 0 || label_length > 63 || domain[label_begin] == '-' || domain[label_end - 1] == '-') {
                return false;
            }
            for (std::size_t i = label_begin; i < label_end; ++i) {
                const unsigned char ch = static_cast<unsigned char>(domain[i]);
                if (!std::isalnum(ch) && ch != '-') {
                    return false;
                }
            }
            if (dot == std::string::npos) {
                break;
            }
            label_begin = dot + 1;
        }
        return true;
    }

    bool IsSubdomainOf(const std::string& candidate, const std::string& suffix) noexcept {
        return candidate.size() > suffix.size() &&
            candidate.compare(candidate.size() - suffix.size(), suffix.size(), suffix) == 0 &&
            candidate[candidate.size() - suffix.size() - 1] == '.';
    }

    std::string DomainRuleKey(DomainMatchType type, const std::string& domain) {
        return std::to_string(static_cast<int>(type)) + ":" + domain;
    }

    std::string CidrRuleKey(std::uint32_t network, std::uint8_t prefix_length) {
        return std::to_string(network) + "/" + std::to_string(prefix_length);
    }

    struct SeenRule final {
        RoutingAction action = RoutingAction::Auto;
        std::size_t line = 0;
    };

    constexpr std::array<const char*, 6> kLanCidrs = {
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
    };

} // namespace

    void HumanRoutingRules::ClearModel() noexcept {
        default_action_ = RoutingAction::Auto;
        geo_compiled_ = false;
        geo_stats_ = GeoCompileStats{};
        dns_providers_.clear();
        geo_declarations_.clear();
        domain_rules_.clear();
        ipv4_cidrs_.clear();
        domain_regexps_.clear();
    }

    void HumanRoutingRules::ClearGeoRules() noexcept {
        domain_rules_.erase(std::remove_if(domain_rules_.begin(), domain_rules_.end(),
            [](const DomainRule& rule) { return rule.origin == RuleOrigin::Geo; }), domain_rules_.end());
        ipv4_cidrs_.erase(std::remove_if(ipv4_cidrs_.begin(), ipv4_cidrs_.end(),
            [](const Ipv4CidrRule& rule) { return rule.origin == RuleOrigin::Geo; }), ipv4_cidrs_.end());
        domain_regexps_.erase(std::remove_if(domain_regexps_.begin(), domain_regexps_.end(),
            [this](const CompiledDomainRegexp& regexp) { return regexp.rule_index >= domain_rules_.size(); }),
            domain_regexps_.end());
        geo_compiled_ = false;
        geo_stats_ = GeoCompileStats{};
    }

    bool HumanRoutingRules::LoadText(std::string_view text_view, std::string_view file_view) noexcept {
        const std::string text(text_view);
        const std::string file(file_view);
        ClearModel();
        source_file_ = file;
        diagnostics_.clear();

        RoutingAction section_action = RoutingAction::Auto;
        bool has_section = false;
        bool has_default = false;
        std::size_t default_line = 0;
        std::unordered_map<std::string, SeenRule> seen_domains;
        std::unordered_map<std::string, SeenRule> seen_cidrs;
        std::unordered_map<std::string, SeenRule> seen_geo;
        std::unordered_map<std::string, SeenRule> seen_dns;

        auto add_error = [this, &file](std::size_t line, std::size_t original_line, std::string reason) {
            diagnostics_.push_back(RoutingDiagnostic{ file, line, original_line, std::move(reason) });
        };

        auto add_cidr = [&](std::uint32_t network, std::uint8_t prefix_length, RoutingAction action,
                            bool from_lan, std::size_t line) {
            const std::string key = CidrRuleKey(network, prefix_length);
            const auto existing = seen_cidrs.find(key);
            if (existing != seen_cidrs.end()) {
                if (existing->second.action != action) {
                    add_error(line, existing->second.line,
                        "equivalent IPv4 CIDR has conflicting actions (" +
                        std::string(ActionName(existing->second.action)) + " vs " + ActionName(action) + ")");
                }
                return;
            }

            seen_cidrs.emplace(key, SeenRule{ action, line });
            ipv4_cidrs_.push_back(Ipv4CidrRule{
                action,
                network,
                prefix_length,
                Ipv4ToString(network) + "/" + std::to_string(prefix_length),
                from_lan,
                line,
                RuleOrigin::Explicit,
                {},
                {},
            });
        };

        std::istringstream input(text);
        std::string raw_line;
        std::size_t line_number = 0;
        while (std::getline(input, raw_line)) {
            ++line_number;
            if (!raw_line.empty() && raw_line.back() == '\r') {
                raw_line.pop_back();
            }

            const std::string line = Trim(StripSafeComment(raw_line));
            if (line.empty()) {
                continue;
            }

            if (line.front() == '[') {
                if (line.back() != ']' || line.find(']') != line.size() - 1) {
                    add_error(line_number, 0, "invalid section header");
                    has_section = false;
                    continue;
                }

                const std::string section = ToLowerAscii(Trim(line.substr(1, line.size() - 2)));
                if (section == "direct") {
                    section_action = RoutingAction::Direct;
                    has_section = true;
                }
                elif(section == "proxy") {
                    section_action = RoutingAction::Proxy;
                    has_section = true;
                }
                else {
                    add_error(line_number, 0, "unknown section '" + section + "'");
                    has_section = false;
                }
                continue;
            }

            const std::vector<std::string> tokens = SplitWhitespace(line);
            if (!tokens.empty() && ToLowerAscii(tokens[0]) == "default") {
                RoutingAction action = RoutingAction::Auto;
                if (tokens.size() != 2 || !ParseAction(tokens[1], action)) {
                    add_error(line_number, 0, "invalid default directive; expected 'default auto|direct|proxy'");
                    continue;
                }
                if (has_default && default_action_ != action) {
                    add_error(line_number, default_line, "default action conflicts with the earlier directive");
                    continue;
                }
                if (!has_default) {
                    default_action_ = action;
                    default_line = line_number;
                    has_default = true;
                }
                continue;
            }

            if (!tokens.empty() && ToLowerAscii(tokens[0]) == "dns") {
                RoutingAction action = RoutingAction::Auto;
                if (tokens.size() != 3 || !ParseAction(tokens[1], action) || action == RoutingAction::Auto) {
                    add_error(line_number, 0, "invalid dns directive; expected 'dns direct|proxy <provider>'");
                    continue;
                }

                const std::string provider = ToLowerAscii(tokens[2]);
                const ppp::string provider_name(provider.data(), provider.size());
                if (!ppp::dns::DnsProviderCatalog::HasProvider(provider_name)) {
                    add_error(line_number, 0, "unknown DNS provider '" + provider + "'");
                    continue;
                }

                const std::string key = ActionName(action);
                const auto existing = seen_dns.find(key);
                if (existing != seen_dns.end()) {
                    const auto provider_rule = std::find_if(dns_providers_.begin(), dns_providers_.end(),
                        [action](const DnsProviderRule& rule) { return rule.action == action; });
                    if (provider_rule != dns_providers_.end() && provider_rule->provider != provider) {
                        add_error(line_number, existing->second.line,
                            "DNS action already uses provider '" + provider_rule->provider + "'");
                    }
                    continue;
                }

                seen_dns.emplace(key, SeenRule{ action, line_number });
                dns_providers_.push_back(DnsProviderRule{ action, provider, line_number });
                continue;
            }

            if (!tokens.empty()) {
                const std::string keyword = ToLowerAscii(tokens[0]);
                if (keyword.find('=') == std::string::npos && tokens.size() > 1) {
                    add_error(line_number, 0, "unknown directive '" + keyword + "'");
                    continue;
                }
            }

            if (!has_section) {
                add_error(line_number, 0, "rule entry appears outside a direct or proxy section");
                continue;
            }
            if (tokens.size() != 1) {
                add_error(line_number, 0, "rule entry must contain exactly one value");
                continue;
            }

            const std::string raw_entry = tokens[0];
            const std::string entry = ToLowerAscii(raw_entry);
            if (entry == "lan") {
                for (const char* cidr : kLanCidrs) {
                    std::uint32_t network = 0;
                    std::uint8_t prefix_length = 0;
                    ParseCidr(cidr, network, prefix_length);
                    add_cidr(network, prefix_length, section_action, true, line_number);
                }
                continue;
            }

            if (entry.compare(0, 4, "geo:") == 0) {
                const std::string country = entry.substr(4);
                if (country.size() != 2 || !std::isalpha(static_cast<unsigned char>(country[0])) ||
                    !std::isalpha(static_cast<unsigned char>(country[1]))) {
                    add_error(line_number, 0, "invalid geo declaration; expected 'geo:<two-letter-country>'");
                    continue;
                }

                const auto existing = seen_geo.find(country);
                if (existing != seen_geo.end()) {
                    if (existing->second.action != section_action) {
                        add_error(line_number, existing->second.line,
                            "equivalent geo declaration has conflicting actions (" +
                            std::string(ActionName(existing->second.action)) + " vs " + ActionName(section_action) + ")");
                    }
                    continue;
                }

                seen_geo.emplace(country, SeenRule{ section_action, line_number });
                geo_declarations_.push_back(GeoDeclaration{
                    section_action, country, true, true, line_number,
                });
                continue;
            }

            if (LooksLikeIpv4OrCidr(entry)) {
                std::uint32_t network = 0;
                std::uint8_t prefix_length = 0;
                if (!ParseCidr(entry, network, prefix_length)) {
                    add_error(line_number, 0, "invalid IPv4 address or CIDR '" + entry + "'");
                    continue;
                }
                add_cidr(network, prefix_length, section_action, false, line_number);
                continue;
            }

            DomainMatchType type = DomainMatchType::Suffix;
            std::string domain_token = entry;
            if (!domain_token.empty() && domain_token.front() == '=') {
                type = DomainMatchType::Exact;
                domain_token.erase(domain_token.begin());
            }
            elif(domain_token.compare(0, 2, "*.") == 0) {
                type = DomainMatchType::Subdomain;
                domain_token.erase(0, 2);
            }
            elif(domain_token.compare(0, 7, "regexp:") == 0) {
                type = DomainMatchType::Regexp;
                domain_token = raw_entry.substr(7);
            }

            std::string domain;
            std::regex compiled_regexp;
            if (type == DomainMatchType::Regexp) {
                if (domain_token.empty()) {
                    add_error(line_number, 0, "invalid regexp domain rule: pattern is empty");
                    continue;
                }
                try {
                    compiled_regexp = std::regex(domain_token,
                        std::regex::ECMAScript | std::regex::optimize | std::regex::icase);
                }
                catch (const std::regex_error& error) {
                    add_error(line_number, 0, "invalid regexp domain rule '" + domain_token + "': " + error.what());
                    continue;
                }
                domain = std::move(domain_token);
            }
            elif(!NormalizeDomain(domain_token, domain)) {
                add_error(line_number, 0, "invalid domain rule '" + entry + "'");
                continue;
            }

            const std::string key = DomainRuleKey(type, domain);
            const auto existing = seen_domains.find(key);
            if (existing != seen_domains.end()) {
                if (existing->second.action != section_action) {
                    add_error(line_number, existing->second.line,
                        "equivalent domain rule has conflicting actions (" +
                        std::string(ActionName(existing->second.action)) + " vs " + ActionName(section_action) + ")");
                }
                continue;
            }

            seen_domains.emplace(key, SeenRule{ section_action, line_number });
            const std::size_t rule_index = domain_rules_.size();
            domain_rules_.push_back(DomainRule{
                section_action, type, std::move(domain), line_number, RuleOrigin::Explicit, {}, {},
            });
            if (type == DomainMatchType::Regexp) {
                domain_regexps_.push_back(CompiledDomainRegexp{ rule_index, std::move(compiled_regexp) });
            }
        }

        if (!diagnostics_.empty()) {
            ClearModel();
            return false;
        }
        return true;
    }

    bool HumanRoutingRules::LoadFile(std::string_view path_view) noexcept {
        const std::string path(path_view);
        ClearModel();
        diagnostics_.clear();
        if (path.empty()) {
            diagnostics_.push_back(RoutingDiagnostic{ path, 0, 0, "routing rules file path is empty" });
            return false;
        }

        std::ifstream stream(path, std::ios::binary);
        if (!stream) {
            diagnostics_.push_back(RoutingDiagnostic{ path, 0, 0, "unable to open routing rules file" });
            return false;
        }

        std::ostringstream contents;
        contents << stream.rdbuf();
        if (stream.bad()) {
            diagnostics_.push_back(RoutingDiagnostic{ path, 0, 0, "unable to read routing rules file" });
            return false;
        }
        return LoadText(contents.str(), path);
    }

    bool HumanRoutingRules::CompileGeo(const HumanGeoDataSources& sources) noexcept {
        ClearGeoRules();
        diagnostics_.clear();

        const GeoDeclaration* current_declaration = nullptr;
        std::string current_path;
        auto fail = [this](const GeoDeclaration& declaration, const std::string& path,
                           const std::string& detail) {
            diagnostics_.push_back(RoutingDiagnostic{
                source_file_, declaration.line, 0, GeoSourceContext(declaration, path, detail),
            });
            ClearGeoRules();
            return false;
        };

        try {
            auto add_ipv4 = [this](const GeoDeclaration& declaration, const std::string& path,
                                   std::uint32_t network, std::uint8_t prefix_length) {
                network &= PrefixMask(prefix_length);
                ipv4_cidrs_.push_back(Ipv4CidrRule{
                    declaration.action,
                    network,
                    prefix_length,
                    Ipv4ToString(network) + "/" + std::to_string(prefix_length),
                    false,
                    declaration.line,
                    RuleOrigin::Geo,
                    declaration.country,
                    path,
                });
                ++geo_stats_.ipv4_rules;
            };

            auto add_domain = [this](const GeoDeclaration& declaration, const std::string& path,
                                     DomainMatchType type, std::string value, std::string& error) {
                std::regex compiled_regexp;
                if (type == DomainMatchType::Regexp) {
                    if (value.empty()) {
                        error = "regexp pattern is empty";
                        return false;
                    }
                    try {
                        compiled_regexp = std::regex(value,
                            std::regex::ECMAScript | std::regex::optimize | std::regex::icase);
                    }
                    catch (const std::regex_error& exception) {
                        error = "invalid regexp '" + value + "': " + exception.what();
                        return false;
                    }
                }
                else {
                    std::string normalized;
                    if (!NormalizeDomain(value, normalized)) {
                        error = "invalid domain '" + value + "'";
                        return false;
                    }
                    value = std::move(normalized);
                }

                const std::size_t rule_index = domain_rules_.size();
                domain_rules_.push_back(DomainRule{
                    declaration.action,
                    type,
                    std::move(value),
                    declaration.line,
                    RuleOrigin::Geo,
                    declaration.country,
                    path,
                });
                if (type == DomainMatchType::Regexp) {
                    domain_regexps_.push_back(CompiledDomainRegexp{ rule_index, std::move(compiled_regexp) });
                }
                ++geo_stats_.domain_rules;
                return true;
            };

            for (const GeoDeclaration& declaration : geo_declarations_) {
                current_declaration = &declaration;

                if (sources.geoip_dat.empty() && sources.geoip.empty()) {
                    return fail(declaration, "<none>", "GeoIP category has no usable source");
                }
                if (sources.geosite_dat.empty() && sources.geosite.empty()) {
                    return fail(declaration, "<none>", "GeoSite category has no usable source");
                }

                if (!sources.geoip_dat.empty()) {
                    current_path = sources.geoip_dat;
                    const GeoIpReadResult result = GeoDataReader::ReadGeoIp(
                        current_path, declaration.country);
                    if (!result.Succeeded()) {
                        return fail(declaration, current_path, result.diagnostic.empty()
                            ? "unable to read GeoIP dat" : result.diagnostic);
                    }
                    geo_stats_.source_skipped += result.skipped;

                    for (const GeoDataCidr& cidr : result.entries) {
                        if (cidr.address.size() == 16) {
                            ++geo_stats_.ipv6_skipped;
                            continue;
                        }
                        if (cidr.address.size() != 4 || cidr.prefix_length > 32) {
                            return fail(declaration, current_path, "malformed address in GeoIP dat");
                        }
                        const std::uint32_t address =
                            (static_cast<std::uint32_t>(cidr.address[0]) << 24u) |
                            (static_cast<std::uint32_t>(cidr.address[1]) << 16u) |
                            (static_cast<std::uint32_t>(cidr.address[2]) << 8u) |
                            static_cast<std::uint32_t>(cidr.address[3]);
                        add_ipv4(declaration, current_path, address, cidr.prefix_length);
                    }
                }

                for (const std::string& path : sources.geoip) {
                    current_path = path;
                    const GeoIpReadResult result = GeoDataReader::ReadGeoIpText(path);
                    if (!result.Succeeded()) {
                        return fail(declaration, path, result.diagnostic.empty()
                            ? "unable to read GeoIP text source" : result.diagnostic);
                    }
                    geo_stats_.source_skipped += result.skipped;
                    for (const GeoDataCidr& cidr : result.entries) {
                        if (cidr.address.size() == 16) {
                            ++geo_stats_.ipv6_skipped;
                            continue;
                        }
                        if (cidr.address.size() != 4 || cidr.prefix_length > 32) {
                            ++geo_stats_.source_skipped;
                            continue;
                        }
                        const std::uint32_t address =
                            (static_cast<std::uint32_t>(cidr.address[0]) << 24u) |
                            (static_cast<std::uint32_t>(cidr.address[1]) << 16u) |
                            (static_cast<std::uint32_t>(cidr.address[2]) << 8u) |
                            static_cast<std::uint32_t>(cidr.address[3]);
                        add_ipv4(declaration, path, address, cidr.prefix_length);
                    }
                }

                if (!sources.geosite_dat.empty()) {
                    current_path = sources.geosite_dat;
                    const GeoSiteReadResult result = GeoDataReader::ReadGeoSite(
                        current_path, declaration.country);
                    if (!result.Succeeded()) {
                        return fail(declaration, current_path, result.diagnostic.empty()
                            ? "unable to read GeoSite dat" : result.diagnostic);
                    }
                    geo_stats_.source_skipped += result.skipped;

                    for (const GeoDataDomain& domain : result.entries) {
                        DomainMatchType type = DomainMatchType::Suffix;
                        switch (domain.type) {
                        case GeoDataDomainType::Plain:
                            ++geo_stats_.unsupported_skipped;
                            continue;
                        case GeoDataDomainType::Regex:
                            type = DomainMatchType::Regexp;
                            break;
                        case GeoDataDomainType::Domain:
                            type = DomainMatchType::Suffix;
                            break;
                        case GeoDataDomainType::Full:
                            type = DomainMatchType::Exact;
                            break;
                        default:
                            ++geo_stats_.unsupported_skipped;
                            continue;
                        }
                        std::string error;
                        if (!add_domain(declaration, current_path, type, domain.value, error)) {
                            return fail(declaration, current_path, error);
                        }
                    }
                }

                for (const std::string& path : sources.geosite) {
                    current_path = path;
                    const GeoSiteReadResult result = GeoDataReader::ReadGeoSiteText(path);
                    if (!result.Succeeded()) {
                        return fail(declaration, path, result.diagnostic.empty()
                            ? "unable to read GeoSite text source" : result.diagnostic);
                    }
                    geo_stats_.source_skipped += result.skipped;
                    for (const GeoDataDomain& domain : result.entries) {
                        DomainMatchType type = DomainMatchType::Suffix;
                        switch (domain.type) {
                        case GeoDataDomainType::Plain:
                            ++geo_stats_.unsupported_skipped;
                            continue;
                        case GeoDataDomainType::Regex:
                            type = DomainMatchType::Regexp;
                            break;
                        case GeoDataDomainType::Domain:
                            type = DomainMatchType::Suffix;
                            break;
                        case GeoDataDomainType::Full:
                            type = DomainMatchType::Exact;
                            break;
                        default:
                            ++geo_stats_.unsupported_skipped;
                            continue;
                        }
                        std::string error;
                        if (!add_domain(declaration, path, type, domain.value, error)) {
                            ++geo_stats_.source_skipped;
                        }
                    }
                }
            }

            geo_compiled_ = true;
            return true;
        }
        catch (const std::exception& exception) {
            if (current_declaration != nullptr) {
                return fail(*current_declaration, current_path, exception.what());
            }
            ClearGeoRules();
            diagnostics_.push_back(RoutingDiagnostic{
                source_file_, 0, 0, std::string("geo compile failed: ") + exception.what(),
            });
            return false;
        }
        catch (...) {
            if (current_declaration != nullptr) {
                return fail(*current_declaration, current_path, "unknown error");
            }
            ClearGeoRules();
            diagnostics_.push_back(RoutingDiagnostic{
                source_file_, 0, 0, "geo compile failed: unknown error",
            });
            return false;
        }
    }

    RoutingMatch HumanRoutingRules::MatchDomainRule(std::string_view input_view) const noexcept {
        const std::string input(input_view);
        std::string domain;
        if (!NormalizeDomain(Trim(input), domain)) {
            return {};
        }

        auto match_origin = [this, &domain](RuleOrigin origin) -> const DomainRule* {
            for (const DomainRule& rule : domain_rules_) {
                if (rule.origin == origin && rule.type == DomainMatchType::Exact && rule.domain == domain) {
                    return &rule;
                }
            }

            for (const CompiledDomainRegexp& regexp : domain_regexps_) {
                if (regexp.rule_index >= domain_rules_.size()) {
                    continue;
                }
                const DomainRule& rule = domain_rules_[regexp.rule_index];
                if (rule.origin != origin) {
                    continue;
                }
                try {
                    if (std::regex_search(domain, regexp.expression)) {
                        return &rule;
                    }
                }
                catch (const std::regex_error&) {
                }
            }

            const DomainRule* best = nullptr;
            for (const DomainRule& rule : domain_rules_) {
                if (rule.origin != origin) {
                    continue;
                }
                bool matches = false;
                if (rule.type == DomainMatchType::Suffix) {
                    matches = domain == rule.domain || IsSubdomainOf(domain, rule.domain);
                }
                elif(rule.type == DomainMatchType::Subdomain) {
                    matches = IsSubdomainOf(domain, rule.domain);
                }
                if (!matches) {
                    continue;
                }
                if (nullptr == best || rule.domain.size() > best->domain.size() ||
                    (rule.domain.size() == best->domain.size() &&
                     rule.type == DomainMatchType::Subdomain && best->type == DomainMatchType::Suffix)) {
                    best = &rule;
                }
            }
            return best;
        };

        for (RuleOrigin origin : { RuleOrigin::Explicit, RuleOrigin::Geo }) {
            if (const DomainRule* rule = match_origin(origin)) {
                return RoutingMatch{ rule->action, true, true, rule->origin, rule->line };
            }
        }
        RoutingMatch result;
        result.valid = true;
        return result;
    }

    RoutingMatch HumanRoutingRules::MatchIpv4Rule(std::string_view input_view) const noexcept {
        const std::string input(input_view);
        std::uint32_t address = 0;
        if (!ParseIpv4(Trim(input), address)) {
            return {};
        }
        return MatchIpv4Rule(address);
    }

    RoutingMatch HumanRoutingRules::MatchIpv4Rule(std::uint32_t address) const noexcept {
        for (RuleOrigin origin : { RuleOrigin::Explicit, RuleOrigin::Geo }) {
            const Ipv4CidrRule* best = nullptr;
            for (const Ipv4CidrRule& rule : ipv4_cidrs_) {
                if (rule.origin != origin || (address & PrefixMask(rule.prefix_length)) != rule.network) {
                    continue;
                }
                if (nullptr == best || rule.prefix_length > best->prefix_length) {
                    best = &rule;
                }
            }
            if (best != nullptr) {
                return RoutingMatch{ best->action, true, true, best->origin, best->line };
            }
        }
        RoutingMatch result;
        result.valid = true;
        return result;
    }

    RoutingAction HumanRoutingRules::MatchDomain(std::string_view domain) const noexcept {
        const RoutingMatch match = MatchDomainRule(domain);
        if (!match.valid) {
            return RoutingAction::Auto;
        }
        return match.matched ? match.action : default_action_;
    }

    RoutingAction HumanRoutingRules::MatchIpv4(std::string_view address) const noexcept {
        const RoutingMatch match = MatchIpv4Rule(address);
        if (!match.valid) {
            return RoutingAction::Auto;
        }
        return match.matched ? match.action : default_action_;
    }

    RoutingAction HumanRoutingRules::MatchIpv4(std::uint32_t address) const noexcept {
        const RoutingMatch match = MatchIpv4Rule(address);
        return match.matched ? match.action : default_action_;
    }

} // namespace ppp::app::client::routing
