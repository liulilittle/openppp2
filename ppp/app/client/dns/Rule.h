#pragma once

/**
 * @file Rule.h
 * @brief DNS rule declarations for host-to-server resolution routing.
 *
 * @details Defines `ppp::app::client::dns::Rule`, the data structure and matching
 *          engine used to route DNS queries for specific host patterns to custom
 *          upstream DNS servers (or through the local NIC rather than the VPN).
 *
 *          Three rule categories are supported, evaluated in priority order:
 *          -# **Full-host** (`full_rules`): exact, case-sensitive hostname match.
 *          -# **Regular expression** (`regexp_rules`): ECMAScript-compatible pattern.
 *          -# **Relative / suffix** (`rules`): domain-suffix walk-up matching.
 *
 * @author  OPENPPP2 Team
 * @license GPL-3.0
 */

#include <ppp/stdafx.h>

namespace ppp
{
    namespace app
    {
        namespace client
        {
            namespace dns
            {
                /**
                 * @brief Stores one DNS routing rule entry.
                 *
                 * @details Each `Rule` maps a host-matching pattern to either a legacy
                 *          upstream DNS server address or a built-in provider name.
                 *          For legacy IP rules, `Nic = true` means physical NIC and
                 *          `Nic = false` means VPN tunnel. For provider rules,
                 *          `Nic = true` means domestic/ECS-eligible semantics and
                 *          `Nic = false` means foreign/no-ECS semantics.
                 *
                 *          Rule entries are normally created and owned by the DNS policy's
                 *          three-tier lookup tables.
                 */
                struct Rule final
                {
                public:
                    /**
                     * @brief Host pattern stored for this rule.
                     *
                     * @details Interpretation depends on which map this rule belongs to:
                     *          - In `full_rules`   — exact hostname string.
                     *          - In `regexp_rules` — ECMAScript regular-expression pattern.
                     *          - In `rules`        — domain-suffix string (e.g. `"example.com"`).
                     */
                    ppp::string                         Host;

                    /**
                     * @brief Legacy path selector, or provider domestic selector.
                     *
                     * @details For IP-based rules, `Nic = true` bypasses the VPN via the
                     *          physical NIC and `Nic = false` forwards through the tunnel.
                     *          For provider rules, `Nic = true` marks the query domestic
                     *          (ECS eligible) and `Nic = false` marks it foreign.
                     */
                    bool                                Nic = false;

                    /**
                     * @brief Upstream DNS server address for queries matching this rule.
                     *
                     * @details May be an IPv4 or IPv6 address.  Ignored when `Nic` is true
                     *          (the host resolver is used instead).
                     *
                     * @note    When `ProviderName` is non-empty this field is left
                     *          default-constructed and the rule routes through
                     *          `DnsResolver` instead of direct UDP forwarding.
                     */
                    boost::asio::ip::address            Server;

                    /**
                     * @brief Built-in DNS provider short name (e.g. "doh.pub", "cloudflare").
                     *
                     * @details When non-empty, DNS queries matching this rule are resolved
                     *          through `ppp::dns::DnsResolver::ResolveAsync()` using
                     *          multi-protocol upstream servers (DoH / DoT / TCP / UDP)
                     *          instead of the legacy single-IP UDP forwarding path.
                     *
                     *          The `Nic` flag is repurposed as the "domestic" selector:
                     *          `Nic == true`  → domestic provider group,
                     *          `Nic == false` → foreign provider group.
                     *
                     *          An empty `ProviderName` means the rule uses the legacy
                     *          `Server` IP + UDP forwarding path (fully backward compatible).
                     */
                    ppp::string                         ProviderName;

                public:
                    /** @brief Convenience alias for a reference-counted `Rule` pointer. */
                    typedef std::shared_ptr<Rule>       Ptr;

                public:
                    /**
                     * @brief Finds the best matching rule for a host string across all three tiers.
                     *
                     * @details Evaluation order:
                     *          1. Exact full-host lookup in `full_rules`.
                     *          2. Regular-expression scan of `regexp_rules`.
                     *          3. Domain-suffix walk-up in `rules`.
                     *
                     * @param s            Input host string to match (e.g. `"www.example.com"`).
                     * @param rules        Relative/suffix-domain rule map (tier 3).
                     * @param full_rules   Full exact-host rule map (tier 1).
                     * @param regexp_rules Regular-expression rule map (tier 2).
                     * @return Shared pointer to the first matched `Rule`, or null when no rule matches.
                     * @note This function is `noexcept`; regex errors are swallowed and treated as
                     *       no-match.
                     */
                    static Rule::Ptr                    Get(const ppp::string& s, ppp::unordered_map<ppp::string, Ptr>& rules, ppp::unordered_map<ppp::string, Ptr>& full_rules, ppp::unordered_map<ppp::string, Ptr>& regexp_rules) noexcept;

                    /**
                     * @brief Parses rule text and inserts entries into the three rule maps.
                     *
                     * @details Each line in `s` is expected to follow the format:
                     *          `[!][host-pattern] [dns-server] [nic]`
                     *          Lines that do not conform are silently ignored.
                     *
                     * @param s            Rule text content (newline-delimited).
                     * @param rules        Relative/suffix-domain rule map (receives tier-3 entries).
                     * @param full_rules   Full exact-host rule map (receives tier-1 entries).
                     * @param regexp_rules Regular-expression rule map (receives tier-2 entries).
                     * @return Number of new entries inserted into the relative (`rules`) map.
                     * @note Invalid lines are ignored without error propagation.
                     */
                    static int                          Load(const ppp::string& s, ppp::unordered_map<ppp::string, Ptr>& rules, ppp::unordered_map<ppp::string, Ptr>& full_rules, ppp::unordered_map<ppp::string, Ptr>& regexp_rules) noexcept;

                    /**
                     * @brief Reads a rule file from disk and inserts entries into the three rule maps.
                     *
                     * @details Delegates file reading to platform I/O helpers, then calls `Load()`
                     *          with the file content.
                     *
                     * @param path         Absolute or relative path to the rule text file.
                     * @param rules        Relative/suffix-domain rule map (receives tier-3 entries).
                     * @param full_rules   Full exact-host rule map (receives tier-1 entries).
                     * @param regexp_rules Regular-expression rule map (receives tier-2 entries).
                     * @return Number of entries loaded from the file; 0 if the path is invalid or
                     *         the file is empty or unreadable.
                     * @note Returns 0 without propagating file I/O errors.
                     */
                    static int                          LoadFile(const ppp::string& path, ppp::unordered_map<ppp::string, Ptr>& rules, ppp::unordered_map<ppp::string, Ptr>& full_rules, ppp::unordered_map<ppp::string, Ptr>& regexp_rules) noexcept;
                
                private:
                    /**
                     * @brief Scans `regexp_rules` and returns the first entry whose pattern matches `s`.
                     *
                     * @details Uses ECMAScript regex semantics.  Each map key is compiled as a
                     *          regular expression and tested against `s`.  The first key whose
                     *          regex matches is returned.
                     *
                     * @param s     Host string to test against each regex pattern.
                     * @param rules Regex rule map (key = regex pattern, value = Rule).
                     * @return Matched `Rule` pointer, or null when no pattern matches.
                     * @note Regex compilation or match errors are swallowed and treated as no-match.
                     */
                    static Rule::Ptr                    GetWithRegExp(const ppp::string& s, const ppp::unordered_map<ppp::string, Ptr>& rules) noexcept;

                    /**
                     * @brief Walks up the domain hierarchy of `s` looking for a suffix match in `rules`.
                     *
                     * @details For `"a.b.example.com"` the walk order is:
                     *          `"a.b.example.com"` → `"b.example.com"` → `"example.com"` → `"com"`.
                     *          The first key present in `rules` terminates the search.
                     *
                     * @param s     Host string to walk.
                     * @param rules Suffix-domain rule map.
                     * @return Matched `Rule` pointer, or null when no suffix is found.
                     * @note Matching is delegated to firewall domain-suffix helpers.
                     */
                    static Rule::Ptr                    GetWithRelativePath(const ppp::string& s, const ppp::unordered_map<ppp::string, Ptr>& rules) noexcept;

                    /**
                     * @brief Performs a direct hash-map lookup for `s` in `rules`.
                     *
                     * @details The lookup is case-sensitive and O(1) on average.
                     *
                     * @param s     Host string to look up exactly.
                     * @param rules Exact-host rule map.
                     * @return Matched `Rule` pointer, or null when the key is absent.
                     */
                    static Rule::Ptr                    GetWithAbsoluteHost(const ppp::string& s, const ppp::unordered_map<ppp::string, Ptr>& rules) noexcept;
                };
            }
        }
    }
}
