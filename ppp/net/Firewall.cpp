#include <ppp/io/File.h>
#include <ppp/net/Firewall.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file Firewall.cpp
 * @brief Implements firewall rule parsing and runtime matching for ports, domains, and IP segments.
 */

using ppp::collections::Dictionary;
using ppp::io::File;
using ppp::net::Ipep;
using ppp::net::IPEndPoint;

namespace ppp
{
    namespace net
    {
        /**
         * @brief Builds a 32-bit mask from a CIDR prefix.
         * @param prefix Prefix length in bits.
         * @param Unused type selector for overload resolution.
         * @return The computed IPv4 mask.
         */
        static UInt32 FirewallPrefixMask(int prefix, UInt32) noexcept
        {
            return prefix ? ~0u << (32 - prefix) : 0u;
        }

        /**
         * @brief Builds a 128-bit mask from a CIDR prefix.
         * @param prefix Prefix length in bits.
         * @param Unused type selector for overload resolution.
         * @return The computed IPv6-compatible mask.
         */
        static Int128 FirewallPrefixMask(int prefix, Int128) noexcept
        {
            return PrefixMask128(prefix);
        }

        /**
         * @brief Adds a protocol-agnostic blocked port rule.
         * @param port Target port.
         * @return true if inserted; otherwise false.
         */
        bool Firewall::DropNetworkPort(int port) noexcept
        {
            if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                return false;
            }

            SynchronizedObjectScope scope(syncobj_);
            bool inserted = ports_.emplace(port).second;

            ppp::diagnostics::SetLastErrorCode(inserted ? ppp::diagnostics::ErrorCode::Success : ppp::diagnostics::ErrorCode::FirewallDropPortAlreadyExists);
            return inserted;
        }

        /**
         * @brief Adds a protocol-specific blocked port rule.
         * @param port Target port.
         * @param tcp_or_udp true for TCP, false for UDP.
         * @return true if inserted; otherwise false.
         */
        bool Firewall::DropNetworkPort(int port, bool tcp_or_udp) noexcept
        {
            if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                return false;
            }

            SynchronizedObjectScope scope(syncobj_);
            bool inserted = false;
            if (tcp_or_udp)
            {
                inserted = ports_tcp_.emplace(port).second;
            }
            else
            {
                inserted = ports_udp_.emplace(port).second;
            }
            ppp::diagnostics::SetLastErrorCode(inserted ? ppp::diagnostics::ErrorCode::Success : ppp::diagnostics::ErrorCode::FirewallDropPortProtocolAlreadyExists);
            return inserted;
        }

        /**
         * @brief Adds a blocked IPv4/IPv6 network segment rule.
         * @param ip Address used to compute network base.
         * @param prefix CIDR prefix.
         * @return true if rule table changed; otherwise false.
         */
        bool Firewall::DropNetworkSegment(const boost::asio::ip::address& ip, int prefix) noexcept
        {
            /**
             * @brief Inserts or tightens a stored segment rule.
             * @details If the key already exists, the smaller prefix is kept to preserve the stricter range.
             */
            auto set_network_segments = [](NetworkSegmentTable& m, Int128 k, int prefix) noexcept -> bool
                {
                    auto tail = m.find(k);
                    auto endl = m.end();
                    if (tail == endl)
                    {
                        return m.emplace(k, prefix).second;
                    }
                    else
                    {
                        int& now = tail->second;
                        if (prefix < now)
                        {
                            now = prefix;
                            return true;
                        }
                        else
                        {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FirewallDropSegmentAlreadyExists);
                            return false;
                        }
                    }
                };

            if (ip.is_v4())
            {
                if (prefix < 0 || prefix > 32)
                {
                    prefix = 32;
                }

                UInt32 __mask = prefix ? ~0u << (32 - prefix) : 0L;
                UInt32 __ip = ip.to_v4().to_uint();
                UInt32 __networkIP = __ip & __mask;

                SynchronizedObjectScope scope(syncobj_);
                return set_network_segments(network_segments_, __networkIP, prefix);
            }
            elif(ip.is_v6())
            {
                if (prefix < 0 || prefix > 128)
                {
                    prefix = 128;
                }

                Int128 __mask = PrefixMask128(prefix);
                boost::asio::ip::address_v6::bytes_type bytes = ip.to_v6().to_bytes();
                Int128 network_ip = 0;
                std::memcpy(&network_ip, bytes.data(), sizeof(network_ip));
                Int128 __ip = Ipep::NetworkToHostOrder(network_ip);
                Int128 __networkIP = __ip & __mask;

                SynchronizedObjectScope scope(syncobj_);
                return set_network_segments(network_segments_, __networkIP, prefix);
            }
            else
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return false;
            }
        }

        /**
         * @brief Adds a blocked domain rule after normalization.
         * @param host Host or domain input.
         * @return true if inserted; otherwise false.
         */
        bool Firewall::DropNetworkDomains(const ppp::string& host) noexcept
        {
            if (host.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsAddressInvalid);
                return false;
            }

            ppp::string host_lower = LTrim(RTrim(ToLower(host)));
            if (host_lower.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsAddressInvalid);
                return false;
            }
            else
            {
                SynchronizedObjectScope scope(syncobj_);
                bool inserted = network_domains_.emplace(host_lower).second;
                ppp::diagnostics::SetLastErrorCode(inserted ? ppp::diagnostics::ErrorCode::Success : ppp::diagnostics::ErrorCode::FirewallDropDomainAlreadyExists);
                return inserted;
            }
        }

        /** @brief Clears all configured firewall rules. */
        void Firewall::Clear() noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            ports_.clear();
            ports_tcp_.clear();
            ports_udp_.clear();
            network_domains_.clear();
            network_segments_.clear();
        }

        /**
         * @brief Tests whether a port is blocked by global or protocol-specific rules.
         * @param port Target port.
         * @param tcp_or_udp true for TCP lookup, false for UDP lookup.
         * @return true if blocked; otherwise false.
         */
        bool Firewall::IsDropNetworkPort(int port, bool tcp_or_udp) noexcept
        {
            if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                return false;
            }

            SharedSynchronizedObjectScope scope(syncobj_);
            ppp::unordered_set<int>* lists[] =
            {
                &ports_,
                tcp_or_udp ? &ports_tcp_ : &ports_udp_
            };
            for (auto* list : lists)
            {
                auto tail = list->find(port);
                auto endl = list->end();
                if (tail != endl)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
                    return true;
                }
            }
            return false;
        }

        template <typename T>
        /**
         * @brief Checks whether an IP belongs to any blocked segment.
         * @tparam T Address integer type (UInt32 for IPv4, Int128 for IPv6).
         * @param ip Original address value (unused, kept for call-site symmetry).
         * @param __ip Address as integer in host order.
         * @param max_prefix Maximum prefix length for the address family.
         * @param network_segments Segment table containing network base to prefix mappings.
         * @return true if any configured segment matches; otherwise false.
         */
        static bool Firewall_IsDropNetworkSegment(const boost::asio::ip::address& ip, T __ip, int max_prefix, Firewall::NetworkSegmentTable& network_segments) noexcept
        {
            static constexpr int MIN_PREFIX_VALUE = ppp::net::native::MIN_PREFIX_VALUE;
            if (network_segments.empty())
            {
                return false;
            }

            for (int prefix = max_prefix; prefix >= MIN_PREFIX_VALUE; prefix--)
            {
                T __mask = FirewallPrefixMask(prefix, T{});
                T __networkIP = __ip & __mask;

                auto tail = network_segments.find(__networkIP);
                auto endl = network_segments.end();
                if (tail == endl)
                {
                    continue;
                }

                if (prefix >= tail->second)
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * @brief Tests whether an IP matches a blocked CIDR segment.
         * @param ip IPv4 or IPv6 address.
         * @return true if blocked; otherwise false.
         */
        bool Firewall::IsDropNetworkSegment(const boost::asio::ip::address& ip) noexcept
        {
            if (ip.is_v4())
            {
                UInt32 __ip = ip.to_v4().to_uint();
                {
                    SharedSynchronizedObjectScope scope(syncobj_);
                    bool blocked = Firewall_IsDropNetworkSegment<UInt32>(ip, __ip, 32, network_segments_);
                    if (blocked) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
                    }
                    return blocked;
                }
            }
            elif(ip.is_v6())
            {
                boost::asio::ip::address_v6::bytes_type __bytes_ip = ip.to_v6().to_bytes();
                {
                    Int128 network_ip = 0;
                    std::memcpy(&network_ip, __bytes_ip.data(), sizeof(network_ip));
                    Int128 __ip = Ipep::NetworkToHostOrder(network_ip);
                    {
                        SharedSynchronizedObjectScope scope(syncobj_);
                        bool blocked = Firewall_IsDropNetworkSegment<Int128>(ip, __ip, 128, network_segments_);
                        if (blocked) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
                        }
                        return blocked;
                    }
                }
            }
            else
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return false;
            }
        }

        /**
         * @brief Tests whether a host is blocked by domain or IP rules.
         * @param host Host or address string.
         * @return true if blocked; otherwise false.
         *
         * @note TOCTOU FIX (MEDIUM-1): The previous implementation acquired and
         *       released syncobj_ on every individual call inside the `contains`
         *       lambda, so another writer thread could modify network_domains_
         *       between calls â breaking atomicity of the suffix-walk evaluation.
         *       Fix: take a single snapshot copy of network_domains_ under one lock
         *       acquisition, then run all matching against the immutable local copy.
         */
        bool Firewall::IsDropNetworkDomains(const ppp::string& host) noexcept
        {
            if (host.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsAddressInvalid);
                return false;
            }

            ppp::string host_lower = LTrim(RTrim(ToLower(host)));
            if (host_lower.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsAddressInvalid);
                return false;
            }

            boost::system::error_code ec;
            boost::asio::ip::address ip = StringToAddress(host_lower.data(), ec);
            if (ec == boost::system::errc::success)
            {
                return IsDropNetworkSegment(ip);
            }

            // Take a snapshot of the domain table under a single shared-lock acquisition so
            // the entire suffix-walk evaluation is performed against a consistent view.
            NetworkDomainsTable domains_snapshot;
            {
                SharedSynchronizedObjectScope scope(syncobj_);
                try
                {
                    domains_snapshot = network_domains_;
                }
                catch (const std::bad_alloc&)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FirewallDomainSnapshotCopyOutOfMemory);
                    return false; // Cannot snapshot; fail-safe
                }
            }

            auto contains = [&domains_snapshot](const ppp::string& s) noexcept
                {
                    auto tail = domains_snapshot.find(s);
                    auto endl = domains_snapshot.end();
                    return tail != endl;
                };
            bool blocked = IsSameNetworkDomains(host_lower, contains);
            if (blocked) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
            }

            return blocked;
        }

        /**
         * @brief Performs exact and suffix-based domain matching.
         * @param host Normalized host name.
         * @param contains Callback used to test candidate domain keys.
         * @return true if any candidate matches; otherwise false.
         */
        bool Firewall::IsSameNetworkDomains(const ppp::string& host, const ppp::function<bool(const ppp::string& s)>& contains) noexcept
        {
            if (host.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsAddressInvalid);
                return false;
            }

            /**
             * @brief Match the same hostname view that downstream C-string DNS resolution uses.
             * @note Protocol hostnames are length-delimited and may contain embedded NUL bytes,
             *       while the resolver consumes a C string and stops at the first NUL.
             */
            ppp::string cstr_host = host.c_str();
            if (cstr_host.size() != host.size())
            {
                return IsSameNetworkDomains(cstr_host, contains);
            }

            /** @brief Fast path for exact domain match. */
            if (contains(host))
            {
                return true;
            }

            /** @brief Split host labels to evaluate suffix-based domain matches. */
            ppp::vector<ppp::string> lables;
            if (Tokenize<ppp::string>(host, lables, ".") < 1)
            {
                return false;
            }

            std::size_t label_size = lables.size();
            if (label_size < 2)
            {
                return false;
            }

            for (ppp::string& i : lables)
            {
                i = LTrim(RTrim(i));
                if (i.empty())
                {
                    return true;
                }
            }

            for (std::size_t i = 1, l = label_size - 1; i < l; i++)
            {
                ppp::string next;
                /** @brief Rebuild suffix candidate from current label to the end. */
                for (std::size_t j = i; j < label_size; j++)
                {
                    const ppp::string& label = lables[j];
                    if (next.empty())
                    {
                        next = label;
                    }
                    else
                    {
                        next += '.';
                        next.append(label);
                    }
                }

                if (!next.empty() && contains(next))
                {
                    return true;
                }
            }

            return contains(*lables.rbegin());
        }

        /**
         * @brief Parses and inserts an IP/CIDR drop command payload.
         * @param fw Target firewall.
         * @param line Rule payload text.
         * @return true if a rule is accepted; otherwise false.
         */
        static bool LoadWithRulesDropIP(Firewall* fw, ppp::string& line) noexcept
        {
            boost::system::error_code ec;
            boost::asio::ip::address ip = StringToAddress(line.data(), ec);
            if (ec == boost::system::errc::success)
            {
                if (ip.is_v4())
                {
                    return fw->DropNetworkSegment(ip, 32);
                }
                elif(ip.is_v6())
                {
                    return fw->DropNetworkSegment(ip, 128);
                }
                else
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }
            }

            std::size_t slash_index = line.find('/');
            if (slash_index == ppp::string::npos)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FirewallRuleDropIpMissingSlash);
                return false;
            }

            /** @brief Parse CIDR address and prefix from `address/prefix`. */
            ppp::string host = line.substr(0, slash_index);
            host = LTrim<ppp::string>(RTrim<ppp::string>(host));
            if (host.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FirewallRuleDropIpHostEmpty);
                return false;
            }

            ip = StringToAddress(host.data(), ec);
            if (ec)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return false;
            }

            ppp::string cidr = line.substr(slash_index + 1);
            cidr = LTrim<ppp::string>(RTrim<ppp::string>(cidr));

            /** @brief An explicit slash requires a valid numeric prefix; empty or out-of-range values are rejected. */
            if (cidr.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkMaskInvalid);
                return false;
            }

            /**
             * @brief Use strtol to properly validate numeric conversion.
             * @note atoi cannot distinguish between 0 and conversion error.
             */
            char* endptr = NULLPTR;
            long parsed = strtol(cidr.data(), &endptr, 10);
            if (NULLPTR == endptr || endptr == cidr.data() || *endptr != '\x0' || parsed < 0 || parsed > 128)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkMaskInvalid);
                return false;
            }

            int prefix = static_cast<int>(parsed);
            if (ip.is_v4())
            {
                if (prefix > 32)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkMaskInvalid);
                    return false;
                }
            }
            elif(ip.is_v6())
            {
                /** @brief v6 prefix already bounded to 0..128 above. */
            }
            else
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return false;
            }

            return fw->DropNetworkSegment(ip, prefix);
        }

        /**
         * @brief Parses and inserts a port drop command payload.
         * @param fw Target firewall.
         * @param line Rule payload text.
         * @return true if a rule is accepted; otherwise false.
         */
        static bool LoadWithRulesDropPort(Firewall* fw, ppp::string& line) noexcept
        {
            /**
             * @brief Validate port number using strtol.
             * @note Port must be in range [1, 65535].
             */
            char* endptr = NULLPTR;
            long parsed_port = strtol(line.data(), &endptr, 10);
            if (NULLPTR == endptr || endptr == line.data() || (*endptr != '\x0' && *endptr != '/') || parsed_port <= ppp::net::IPEndPoint::MinPort || parsed_port > ppp::net::IPEndPoint::MaxPort)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                return false;
            }

            int32_t network_port = static_cast<int32_t>(parsed_port);

            std::size_t slash_index = line.find('/');
            if (slash_index != ppp::string::npos)
            {
                ppp::string protocol = LTrim<ppp::string>(RTrim<ppp::string>(line.substr(slash_index + 1)));
                if (protocol.size() > 0)
                {
                    protocol = ToLower<ppp::string>(protocol);
                    if (protocol == "tcp")
                    {
                        return fw->DropNetworkPort(network_port, true);
                    }
                    elif(protocol == "udp")
                    {
                        return fw->DropNetworkPort(network_port, false);
                    }
                }
            }

            return fw->DropNetworkPort(network_port);
        }

        /**
         * @brief Parses and inserts a domain drop command payload.
         * @param fw Target firewall.
         * @param line Rule payload text.
         * @return true if a rule is accepted; otherwise false.
         */
        static bool LoadWithRulesDropDns(Firewall* fw, ppp::string& line) noexcept
        {
            return fw->DropNetworkDomains(line);
        }

        /**
         * @brief Loads rule text from a file path and parses it.
         * @param path Rule file path.
         * @return true if at least one rule is loaded; otherwise false.
         */
        bool Firewall::LoadWithFile(const ppp::string& path) noexcept
        {
            if (path.empty())
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallLoadFileInputPathEmpty);
            }

            ppp::string file_path = File::GetFullPath(File::RewritePath(path.data()).data());
            if (file_path.empty())
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallLoadFileFullPathEmpty);
            }

            ppp::string rules = File::ReadAllText(file_path.data());
            return LoadWithRules(rules);
        }

        /**
         * @brief Parses rule text and inserts accepted drop commands.
         * @param rules Multiline rule configuration.
         * @return true if at least one rule is loaded; otherwise false.
         */
        bool Firewall::LoadWithRules(const ppp::string& rules) noexcept
        {
            typedef bool(*DropProc)(Firewall* fw, ppp::string& line);

            if (rules.empty())
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FirewallLoadRulesInputEmpty);
            }

            ppp::vector<ppp::string> lines;
            if (ppp::Tokenize<ppp::string>(rules, lines, "\r\n") < 1)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FirewallLoadRulesTokenizeFailed);
                return false;
            }

            if (lines.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FirewallLoadRulesNoLines);
                return false;
            }

            struct
            {
                /** @brief Command keyword after `drop` (ip/port/dns). */
                ppp::string drop_command;
                /** @brief Parsing and insertion routine for the command payload. */
                DropProc drop_proc;
            }
            drop_commands[] =
            {
                { "ip", LoadWithRulesDropIP },
                { "port", LoadWithRulesDropPort },
                { "dns", LoadWithRulesDropDns },
            };

            bool any = false;
            ppp::string drop_headers = "drop";
            for (ppp::string& line : lines)
            {
                /** @brief Strip trailing inline comments before command parsing. */
                std::size_t index = line.find('#');
                if (index != ppp::string::npos)
                {
                    line = line.substr(0, index);
                }

                line = LTrim<ppp::string>(RTrim<ppp::string>(line));
                if (line.size() < drop_headers.size() + 1)
                {
                    continue;
                }

                line = ToLower<ppp::string>(line);
                if (memcmp(line.data(), drop_headers.data(), drop_headers.size()) != 0)
                {
                    continue;
                }

                char ch = line[drop_headers.size()];
                if (ch != ' ' && ch != '\t')
                {
                    continue;
                }

                line = LTrim<ppp::string>(RTrim<ppp::string>(line.substr(drop_headers.size() + 1)));
                if (line.empty())
                {
                    continue;
                }

                for (auto& i : drop_commands)
                {
                    ppp::string& drop_command = i.drop_command;
                    if (line.size() < drop_command.size() + 1)
                    {
                        continue;
                    }

                    if (memcmp(line.data(), drop_command.data(), drop_command.size()) != 0)
                    {
                        continue;
                    }

                    line = LTrim<ppp::string>(RTrim<ppp::string>(line.substr(drop_command.size() + 1)));
                    if (line.empty())
                    {
                        break;
                    }

                    /** @brief Record whether at least one rule is accepted successfully. */
                    any |= i.drop_proc(this, line);
                }
            }
            return any;
        }
    }
}
