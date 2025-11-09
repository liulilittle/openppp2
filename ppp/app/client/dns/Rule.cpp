#include <ppp/app/client/dns/Rule.h>
#include <ppp/io/File.h>
#include <ppp/net/Firewall.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>

#include <boost/regex.h>
#include <boost/regex.hpp>

namespace ppp
{
    namespace app
    {
        namespace client
        {
            namespace dns
            {
                int Rule::LoadFile(const ppp::string& path, ppp::unordered_map<ppp::string, Ptr>& rules, ppp::unordered_map<ppp::string, Ptr>& full_rules, ppp::unordered_map<ppp::string, Ptr>& regexp_rules) noexcept
                {
                    if (path.empty())
                    {
                        return 0;
                    }

                    ppp::string full_path = ppp::io::File::GetFullPath(
                        ppp::io::File::RewritePath(path.data()).data());
                    if (full_path.empty())
                    {
                        return 0;
                    }

                    ppp::string texts = ppp::io::File::ReadAllText(full_path.data());
                    return Load(texts, rules, full_rules, regexp_rules);
                }

                int Rule::Load(const ppp::string& s, ppp::unordered_map<ppp::string, Ptr>& rules, ppp::unordered_map<ppp::string, Ptr>& full_rules, ppp::unordered_map<ppp::string, Ptr>& regexp_rules) noexcept
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
                            segments[j] = ATrim<ppp::string>(segments[j]);
                        }
                        
                        ppp::string& host = segments[0];
                        if (host.empty() || segments[1].empty())
                        {
                            continue;
                        }
                       
                        std::size_t host_size = host.size();
                        bool regexp = host_size >= 7 && memcmp(host.data(), "regexp:", 7) == 0;
                        bool full = false;
                        if (regexp) 
                        {
                            boost::regex pattern;
                            host = host.substr(7);

                            try 
                            {
                                int err = pattern.set_expression(host.data(), host.data() + host.size(), boost::regex_constants::icase | boost::regex_constants::perl);
                                if (err != boost::regex_constants::error_ok)
                                {
                                    continue;
                                }
                            }
                            catch (const boost::exception&) 
                            {
                                continue;
                            }
                            catch (const std::exception&) 
                            {
                                continue;
                            }
                        }
                        elif((full = host_size >= 5 && memcmp(host.data(), "full:", 5) == 0))
                        {
                            host = ToLower<ppp::string>(host.substr(5));
                        }
                        else 
                        {
                            host = ToLower<ppp::string>(host);
                        }

                        boost::system::error_code ec;
                        boost::asio::ip::address address = StringToAddress(segments[1], ec);
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
                    
                        Ptr rule = make_shared_object<Rule>(Rule{ host, nic, address });
                        if (NULL == rule)
                        {
                            break;
                        }
                        elif(regexp)
                        {
                            regexp_rules[host] = rule;
                        }
                        elif(full) 
                        {
                            full_rules[host] = rule;
                        }
                        else 
                        {
                            rules[host] = rule;
                        }
                    }

                    return rules.size() - length;
                }

                Rule::Ptr Rule::Get(const ppp::string& s, ppp::unordered_map<ppp::string, Ptr>& rules, ppp::unordered_map<ppp::string, Ptr>& full_rules, ppp::unordered_map<ppp::string, Ptr>& regexp_rules) noexcept 
                {
                    if (s.empty())
                    {
                        return NULL;
                    }

                    if (rules.empty() && full_rules.empty() && regexp_rules.empty())
                    {
                        return NULL;
                    }

                    ppp::string host_lower = ATrim(s);
                    if (host_lower.empty())
                    {
                        return NULL;
                    }

                    boost::system::error_code ec;
                    host_lower = ToLower(s);

                    boost::asio::ip::address ip = StringToAddress(host_lower, ec);
                    if (ec == boost::system::errc::success)
                    {
                        return NULL;
                    }

                    Rule::Ptr rule = GetWithAbsoluteHost(host_lower, full_rules);
                    if (NULL != rule) 
                    {
                        return rule;
                    }

                    rule = GetWithRegExp(host_lower, regexp_rules);
                    if (NULL != rule) 
                    {
                        return rule;
                    }

                    return GetWithRelativePath(host_lower, rules);
                }

                Rule::Ptr Rule::GetWithAbsoluteHost(const ppp::string& s, const ppp::unordered_map<ppp::string, Ptr>& rules) noexcept
                {
                    auto tail = rules.find(s);
                    auto endl = rules.end();
                    return tail != endl ? tail->second : NULL;
                }

                Rule::Ptr Rule::GetWithRegExp(const ppp::string& s, const ppp::unordered_map<ppp::string, Ptr>& rules) noexcept
                {
                    using boost_sregex_iterator = boost::regex_iterator<ppp::string::const_iterator>;

                    /* R"(^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{5}\.googlevideo\.com$)" */
                    // https://onecompiler.com/cpp/43kcdykv8
                    // https://regex101.com/r/aOnyJr/1

                    for (auto&& [r, rule] : rules)
                    {
                        boost::regex pattern;

                        try 
                        {
                            int err = pattern.set_expression(r.data(), r.data() + r.size(), boost::regex_constants::icase | boost::regex_constants::perl);
                            if (err != boost::regex_constants::error_ok)
                            {
                                continue;
                            }

                            if (boost::regex_search(s.begin(), s.end(), pattern)) 
                            {
                                return rule;
                            }
                        }
                        catch (const boost::exception&) 
                        {
                            continue;
                        }
                        catch (const std::exception&) 
                        {
                            continue;
                        }
                    }

                    return NULL;
                }

                Rule::Ptr Rule::GetWithRelativePath(const ppp::string& s, const ppp::unordered_map<ppp::string, Ptr>& rules) noexcept
                {
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

                    if (ppp::net::Firewall::IsSameNetworkDomains(s, contains))
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