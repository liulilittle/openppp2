#pragma once

#include <cstddef>
#include <cstdint>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

namespace ppp::app::client::routing {

    enum class RoutingAction {
        Auto,
        Direct,
        Proxy,
    };

    enum class RuleOrigin {
        Explicit,
        Geo,
    };

    enum class DomainMatchType {
        Suffix,
        Exact,
        Subdomain,
        Regexp,
    };

    struct RoutingDiagnostic final {
        std::string file;
        std::size_t line = 0;
        std::size_t original_line = 0;
        std::string reason;
    };

    struct RoutingMatch final {
        RoutingAction action = RoutingAction::Auto;
        bool valid = false;
        bool matched = false;
        RuleOrigin origin = RuleOrigin::Explicit;
        std::size_t line = 0;
    };

    struct DnsProviderRule final {
        RoutingAction action = RoutingAction::Auto;
        std::string provider;
        std::size_t line = 0;
    };

    struct GeoDeclaration final {
        RoutingAction action = RoutingAction::Auto;
        std::string country;
        bool includes_geoip = true;
        bool includes_geosite = true;
        std::size_t line = 0;
    };

    struct DomainRule final {
        RoutingAction action = RoutingAction::Auto;
        DomainMatchType type = DomainMatchType::Suffix;
        std::string domain;
        std::size_t line = 0;
        RuleOrigin origin = RuleOrigin::Explicit;
        std::string country;
        std::string path;
    };

    struct Ipv4CidrRule final {
        RoutingAction action = RoutingAction::Auto;
        std::uint32_t network = 0; // Host byte order.
        std::uint8_t prefix_length = 0;
        std::string cidr;
        bool from_lan = false;
        std::size_t line = 0;
        RuleOrigin origin = RuleOrigin::Explicit;
        std::string country;
        std::string path;
    };

    struct HumanGeoDataSources final {
        std::string geoip_dat;
        std::string geosite_dat;
        std::vector<std::string> geoip;
        std::vector<std::string> geosite;
    };

    struct GeoCompileStats final {
        std::size_t ipv4_rules = 0;
        std::size_t domain_rules = 0;
        std::size_t ipv6_skipped = 0;
        std::size_t unsupported_skipped = 0;
        std::size_t source_skipped = 0;
    };

    class HumanRoutingRules final {
    public:
        bool LoadText(std::string_view text, std::string_view file = "<text>") noexcept;
        bool LoadFile(std::string_view path) noexcept;
        bool CompileGeo(const HumanGeoDataSources& sources) noexcept;

        RoutingMatch MatchDomainRule(std::string_view domain) const noexcept;
        RoutingMatch MatchIpv4Rule(std::string_view address) const noexcept;
        RoutingMatch MatchIpv4Rule(std::uint32_t address) const noexcept;

        RoutingAction MatchDomain(std::string_view domain) const noexcept;
        RoutingAction MatchIpv4(std::string_view address) const noexcept;
        RoutingAction MatchIpv4(std::uint32_t address) const noexcept;

        RoutingAction DefaultAction() const noexcept { return default_action_; }
        bool IsCompiled() const noexcept { return geo_compiled_; }
        bool GeoCompiled() const noexcept { return geo_compiled_; }
        const GeoCompileStats& GeoStats() const noexcept { return geo_stats_; }
        const std::vector<DnsProviderRule>& DnsProviders() const noexcept { return dns_providers_; }
        const std::vector<GeoDeclaration>& GeoDeclarations() const noexcept { return geo_declarations_; }
        bool HasDomainRules() const noexcept { return !domain_rules_.empty(); }
        const std::vector<DomainRule>& DomainRules() const noexcept { return domain_rules_; }
        const std::vector<Ipv4CidrRule>& Ipv4Cidrs() const noexcept { return ipv4_cidrs_; }
        const std::vector<RoutingDiagnostic>& Diagnostics() const noexcept { return diagnostics_; }

    private:
        struct CompiledDomainRegexp final {
            std::size_t rule_index = 0;
            std::regex expression;
        };

        void ClearModel() noexcept;
        void ClearGeoRules() noexcept;

    private:
        RoutingAction default_action_ = RoutingAction::Auto;
        bool geo_compiled_ = false;
        std::string source_file_ = "<text>";
        GeoCompileStats geo_stats_;
        std::vector<DnsProviderRule> dns_providers_;
        std::vector<GeoDeclaration> geo_declarations_;
        std::vector<DomainRule> domain_rules_;
        std::vector<Ipv4CidrRule> ipv4_cidrs_;
        std::vector<CompiledDomainRegexp> domain_regexps_;
        std::vector<RoutingDiagnostic> diagnostics_;
    };

} // namespace ppp::app::client::routing
