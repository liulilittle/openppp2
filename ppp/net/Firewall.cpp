#include <ppp/io/File.h>
#include <ppp/net/Firewall.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/collections/Dictionary.h>

using ppp::collections::Dictionary;
using ppp::io::File;
using ppp::net::Ipep;
using ppp::net::IPEndPoint;

namespace ppp
{
    namespace net
    {
        bool Firewall::DropNetworkPort(int port) noexcept
        {
            if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort)
            {
                return false;
            }

            SynchronizedObjectScope scope(syncobj_);
            return ports_.emplace(port).second;
        }

        bool Firewall::DropNetworkPort(int port, bool tcp_or_udp) noexcept
        {
            if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort)
            {
                return false;
            }

            SynchronizedObjectScope scope(syncobj_);
            if (tcp_or_udp)
            {
                return ports_tcp_.emplace(port).second;
            }
            else
            {
                return ports_udp_.emplace(port).second;
            }
        }

        bool Firewall::DropNetworkSegment(const boost::asio::ip::address& ip, int prefix) noexcept
        {
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

                UInt32 __mask = prefix ? -1 << (32 - prefix) : 0L;
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

                Int128 __mask = prefix ? Int128(-1) << (128 - prefix) : 0L;
                Int128 __ip = Ipep::NetworkToHostOrder(*(Int128*)ip.to_v6().to_bytes().data());
                Int128 __networkIP = __ip & __mask;

                SynchronizedObjectScope scope(syncobj_);
                return set_network_segments(network_segments_, __networkIP, prefix);
            }
            else
            {
                return false;
            }
        }

        bool Firewall::DropNetworkDomains(const ppp::string& host) noexcept
        {
            if (host.empty())
            {
                return false;
            }

            ppp::string host_lower = LTrim(RTrim(ToLower(host)));
            if (host.empty())
            {
                return false;
            }
            else
            {
                SynchronizedObjectScope scope(syncobj_);
                return network_domains_.emplace(host_lower).second;
            }
        }

        void Firewall::Clear() noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            ports_.clear();
            ports_tcp_.clear();
            ports_udp_.clear();
            network_domains_.clear();
            network_segments_.clear();
        }

        bool Firewall::IsDropNetworkPort(int port, bool tcp_or_udp) noexcept
        {
            if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort)
            {
                return false;
            }

            SynchronizedObjectScope scope(syncobj_);
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
                    return true;
                }
            }
            return false;
        }

        template <typename T>
        static bool Firewall_IsDropNetworkSegment(const boost::asio::ip::address& ip, T __ip, int max_prefix, Firewall::NetworkSegmentTable& network_segments) noexcept
        {
            static constexpr int MIN_PREFIX_VALUE = ppp::net::native::MIN_PREFIX_VALUE;
            if (network_segments.empty())
            {
                return false;
            }

            for (int prefix = max_prefix; prefix >= MIN_PREFIX_VALUE; prefix--)
            {
                T __mask = prefix ? -1 << (max_prefix - prefix) : 0L;
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

        bool Firewall::IsDropNetworkSegment(const boost::asio::ip::address& ip) noexcept
        {
            if (ip.is_v4())
            {
                UInt32 __ip = ip.to_v4().to_uint();
                {
                    SynchronizedObjectScope scope(syncobj_);
                    return Firewall_IsDropNetworkSegment<UInt32>(ip, __ip, 32, network_segments_);
                }
            }
            elif(ip.is_v6())
            {
                boost::asio::ip::address_v6::bytes_type __bytes_ip = ip.to_v6().to_bytes();
                {
                    Int128 __ip = Ipep::NetworkToHostOrder(*(Int128*)__bytes_ip.data());
                    {
                        SynchronizedObjectScope scope(syncobj_);
                        return Firewall_IsDropNetworkSegment<Int128>(ip, __ip, 128, network_segments_);
                    }
                }
            }
            else
            {
                return false;
            }
        }

        bool Firewall::IsDropNetworkDomains(const ppp::string& host) noexcept
        {
            if (host.empty())
            {
                return false;
            }

            ppp::string host_lower = LTrim(RTrim(ToLower(host)));
            if (host_lower.empty())
            {
                return false;
            }

            boost::system::error_code ec;
            boost::asio::ip::address ip = StringToAddress(host_lower.data(), ec);
            if (ec == boost::system::errc::success)
            {
                return IsDropNetworkSegment(ip);
            }

            auto contains = [this](const ppp::string& s) noexcept
                {
                    SynchronizedObjectScope scope(syncobj_);
                    auto tail = network_domains_.find(s);
                    auto endl = network_domains_.end();
                    return tail != endl;
                };
            return IsSameNetworkDomains(host_lower, contains);
        }

        bool Firewall::IsSameNetworkDomains(const ppp::string& host, const ppp::function<bool(const ppp::string& s)>& contains) noexcept
        {
            if (host.empty())
            {
                return false;
            }
            
            // Direct hit
            if (contains(host))
            {
                return true;
            }

            // Segment hit
            ppp::vector<ppp::string> lables;
            if (Tokenize<ppp::string>(host, lables, ".") < 1)
            {
                return true;
            }

            if (lables.empty() || lables.size() < 2) 
            {
                return true;
            }

            for (ppp::string& i : lables) 
            {
                i = LTrim(RTrim(i));
                if (i.empty()) 
                {
                    return true;
                }
            }

            for (std::size_t i = 1, l = lables.size() - 1; i < l; i++)
            {
                ppp::string next;
                for (std::size_t j = i; j < lables.size(); j++) 
                {
                    ppp::string label = lables[j];
                    if (next.empty()) 
                    {
                        next += label;
                    }
                    else
                    {
                        next += "." + label;
                    }
                }

                next = next.data();
                if (!next.empty() && contains(next))
                {
                    return true;
                }
            }
            return false;
        }

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
                    return false;
                }
            }

            std::size_t slash_index = line.find('/');
            if (slash_index == ppp::string::npos)
            {
                return false;
            }

            ppp::string host = line.substr(0, slash_index);
            host = LTrim<ppp::string>(RTrim<ppp::string>(host));
            if (host.empty())
            {
                return false;
            }

            ip = StringToAddress(host.data(), ec);
            if (ec)
            {
                return false;
            }

            ppp::string cidr = line.substr(slash_index + 1);
            cidr = LTrim<ppp::string>(RTrim<ppp::string>(cidr));

            int prefix = -1;
            if (cidr.size() > 0)
            {
                prefix = atoi(cidr.data());
            }

            if (ip.is_v4())
            {
                if (prefix < 0 || prefix > 32)
                {
                    prefix = 32;
                }
            }
            elif(ip.is_v6())
            {
                if (prefix < 0 || prefix > 128)
                {
                    prefix = 128;
                }
            }
            else
            {
                return false;
            }

            return fw->DropNetworkSegment(ip, prefix);
        }

        static bool LoadWithRulesDropPort(Firewall* fw, ppp::string& line) noexcept
        {
            int32_t network_port = atoi(line.data());
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

        static bool LoadWithRulesDropDns(Firewall* fw, ppp::string& line) noexcept
        {
            return fw->DropNetworkDomains(line);
        }

        bool Firewall::LoadWithFile(const ppp::string& path) noexcept
        {
            if (path.empty())
            {
                return false;
            }

            ppp::string file_path = File::GetFullPath(File::RewritePath(path.data()).data());
            if (file_path.empty())
            {
                return false;
            }

            ppp::string rules = File::ReadAllText(file_path.data());
            return LoadWithRules(rules);
        }

        bool Firewall::LoadWithRules(const ppp::string& rules) noexcept
        {
            typedef bool(*DropProc)(Firewall* fw, ppp::string& line);

            if (rules.empty())
            {
                return false;
            }

            ppp::vector<ppp::string> lines;
            if (ppp::Tokenize<ppp::string>(rules, lines, "\r\n") < 1)
            {
                return false;
            }

            if (lines.empty())
            {
                return false;
            }

            struct
            {
                ppp::string drop_command;
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

                    any |= i.drop_proc(this, line);
                }
            }
            return any;
        }
    }
}