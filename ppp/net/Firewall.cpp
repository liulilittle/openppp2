#include <ppp/net/Firewall.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/collections/Dictionary.h>

using ppp::collections::Dictionary;
using ppp::net::Ipep;
using ppp::net::IPEndPoint;

namespace ppp
{
    namespace net
    {
        bool Firewall::DropNetworkPort(int port) noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            return Dictionary::ContainsKey(ports_, port);
        }

        bool Firewall::DropNetworkPort(int port, bool tcp_or_udp) noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            if (tcp_or_udp)
            {
                return Dictionary::ContainsKey(ports_tcp_, port);
            }
            else
            {
                return Dictionary::ContainsKey(ports_udp_, port);
            }
        }

        bool Firewall::DropNetworkSegment(const boost::asio::ip::address& ip, int prefix) noexcept
        {
            if (prefix < 0 || prefix > 32)
            {
                prefix = 32;
            }

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
                Int32 __mask = prefix ? -1 << (32 - prefix) : 0L;
                Int32 __ip = ip.to_v4().to_uint();
                Int32 __networkIP = __ip & __mask;

                SynchronizedObjectScope scope(syncobj_);
                return set_network_segments(network_segments_, __networkIP, prefix);
            }
            elif(ip.is_v6())
            {
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
                auto r = network_domains_.emplace(host_lower);
                return r.second;
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
                Int32 __ip = ip.to_v4().to_uint();
                {
                    SynchronizedObjectScope scope(syncobj_);
                    return Firewall_IsDropNetworkSegment<Int32>(ip, __ip, 32, network_segments_);
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
            if (host.empty())
            {
                return false;
            }

            auto contains = [this](const ppp::string& s) noexcept
                {
                    SynchronizedObjectScope scope(syncobj_);
                    auto tail = network_domains_.find(s);
                    auto endl = network_domains_.end();
                    return tail != endl;
                };

            // Direct hit
            if (contains(host_lower))
            {
                return true;
            }
            else
            {
                boost::system::error_code ec;
                boost::asio::ip::address ip = boost::asio::ip::address::from_string(host_lower.data(), ec);
                if (ec == boost::system::errc::success)
                {
                    return IsDropNetworkSegment(ip);
                }
            }

            // Segment hit
            ppp::vector<ppp::string> lables;
            if (Tokenize<ppp::string>(host_lower, lables, ".") < 1)
            {
                return true;
            }

            if (lables.empty() || lables.size() < 2) 
            {
                return true;
            }

            for (ppp::string& i : lables) 
            {
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
                    if (next.empty()) 
                    {
                        next += lables[j];
                    }
                    else
                    {
                        next += "." + lables[j];
                    }
                }

                if (next.size() > 0 && contains(next))
                {
                    return true;
                }
            }
            return false;
        }
    }
}