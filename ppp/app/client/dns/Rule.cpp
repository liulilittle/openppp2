#include <ppp/app/client/dns/Rule.h>
#include <ppp/io/File.h>
#include <ppp/net/Firewall.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>

namespace ppp
{
    namespace app
    {
        namespace client
        {
            namespace dns
            {
                int Rule::LoadFile(const ppp::string& path, ppp::unordered_map<ppp::string, Ptr>& rules) noexcept
                {
                    if (path.empty())
                    {
                        return 0;
                    }

                    ppp::string s = ppp::io::File::ReadAllText(
                        ppp::io::File::GetFullPath(
                            ppp::io::File::RewritePath(path.data()).data()).data());
                    return Load(s, rules);
                }

                int Rule::Load(const ppp::string& s, ppp::unordered_map<ppp::string, Ptr>& rules) noexcept
                {
                    if (s.empty())
                    {
                        return 0;
                    }

                    ppp::vector<ppp::string> lines;
                    Tokenize<ppp::string>(s, lines, "\r\n");

                    if (lines.empty())
                    {
                        return 0;
                    }

                    std::size_t length = rules.size();
                    ppp::unordered_set<ppp::string> sets;

                    for (std::size_t i = 0, line_count = lines.size(); i < line_count; i++)
                    {
                        ppp::string line = lines[i];
                        std::size_t index = line.find('#');
                        if (index != ppp::string::npos) 
                        {
                            if (index == 0) 
                            {
                                continue;
                            }

                            line = line.substr(0, index);
                        }

                        line = RTrim(LTrim(line));
                        if (line.empty())
                        {
                            continue;
                        }

                        ppp::vector<ppp::string> segments;
                        Tokenize<ppp::string>(line, segments, "/");

                        std::size_t segment_size = segments.size();
                        if (segment_size < 2)
                        {
                            continue;
                        }

                        for (std::size_t j = 0; j < segment_size; j++)
                        {
                            segments[j] = RTrim(LTrim(segments[j]));
                        }

                        if (segments[0].empty() || segments[1].empty())
                        {
                            continue;
                        }

                        segments[0] = ToLower<ppp::string>(segments[0].data());
                        if (!ppp::net::Ipep::IsDomainAddress(segments[0]))
                        {
                            continue;
                        }

                        boost::system::error_code ec;
                        boost::asio::ip::address address = StringToAddress(segments[1].data(), ec);
                        if (ec)
                        {
                            continue;
                        }
                        elif(ppp::net::IPEndPoint::IsInvalid(address))
                        {
                            continue;
                        }

                        bool nic = true;
                        if (segment_size > 2)
                        {
                            ppp::string& nic_type = segments[2];
                            if (!nic_type.empty())
                            {
                                char nic_ch = tolower(nic_type[0]);
                                if (nic_ch == 't' || nic_ch == 'v' || nic_ch == 'f' || nic_ch == 'c')
                                {
                                    nic = false;
                                }
                            }
                        }

                        Ptr rule = make_shared_object<Rule>(Rule{ segments[0], nic, address });
                        if (NULL == rule)
                        {
                            break;
                        }

                        rules[segments[0]] = rule;
                    }
                    return rules.size() - length;
                }

                Rule::Ptr Rule::Get(const ppp::string& s, const ppp::unordered_map<ppp::string, Ptr>& rules) noexcept
                {
                    if (s.empty() || rules.empty())
                    {
                        return NULL;
                    }

                    ppp::string host_lower = LTrim(RTrim(ToLower(s)));
                    if (host_lower.empty())
                    {
                        return NULL;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::address ip = StringToAddress(host_lower.data(), ec);
                    if (ec == boost::system::errc::success)
                    {
                        return NULL;
                    }

                    Ptr rule;
                    auto contains = [&rule, &rules](const ppp::string& s) noexcept
                        {
                            auto tail = rules.find(s);
                            auto endl = rules.end();
                            if (tail == endl)
                            {
                                return false;
                            }
                            else
                            {
                                rule = tail->second;
                                return true;
                            }
                        };

                    if (ppp::net::Firewall::IsSameNetworkDomains(host_lower, contains))
                    {
                        return rule;
                    }
                    else
                    {
                        return NULL;
                    }
                }
            }
        }
    }
}