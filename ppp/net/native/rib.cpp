#include <stdio.h>
#include <stdint.h>

#include <ppp/diagnostics/Error.h>
#include <ppp/io/File.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>

/**
 * @file rib.cpp
 * @brief RouteInformationTable / ForwardInformationTable (RIB/FIB) implementations.
 *
 * Split out of checksum.cpp (Phase 2 P2-a) so that translation unit is no longer a
 * packet-parsing + checksum + routing-table grab-bag; declarations stay in rib.h.
 */

namespace ppp
{
    namespace net
    {
        namespace native
        {
            /** @brief Loads CIDR routes from file and inserts them with a shared gateway. */
            bool RouteInformationTable::AddAllRoutesByIPList(const ppp::string& path, uint32_t gw) noexcept
            {
                if (path.empty())
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FilePathInvalid);
                    return false;
                }

                if (!ppp::io::File::Exists(path.data()))
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::FileStatFailed);
                    return false;
                }

                ppp::string cidrs = ppp::io::File::ReadAllText(path.data());
                if (cidrs.empty())
                {
                    return true;
                }

                return AddAllRoutes(cidrs, gw);
            }

            /** @brief Parses multiple CIDR lines and inserts each route entry. */
            bool RouteInformationTable::AddAllRoutes(const ppp::string& cidrs, uint32_t gw) noexcept
            {
                if (cidrs.empty())
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteTableAddAllRoutesInputEmpty);
                    return false;
                }

                ppp::vector<ppp::string> lines;
                if (Tokenize<ppp::string>(cidrs, lines, "\r\n") < 1)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteTableAddAllRoutesTokenizeFailed);
                    return false;
                }

                bool any = false;
                for (ppp::string& line : lines)
                {
                    std::size_t comment = line.find('#');
                    if (comment != ppp::string::npos)
                    {
                        line = line.substr(0, comment);
                    }

                    line = ATrim<ppp::string>(line);
                    if (line.empty())
                    {
                        continue;
                    }

                    ppp::vector<ppp::string> routes;
                    if (Tokenize<ppp::string>(line, routes, ",; \t") < 1)
                    {
                        continue;
                    }

                    for (ppp::string& route : routes)
                    {
                        route = ATrim<ppp::string>(route);
                        if (route.empty())
                        {
                            continue;
                        }

                        any |= AddRoute(route, gw);
                    }
                }
                return any;
            }

            /** @brief Parses one CIDR string and inserts an IPv4 route entry. */
            bool RouteInformationTable::AddRoute(const ppp::string& cidr, uint32_t gw) noexcept
            {
                if (cidr.empty())
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteTableAddRouteInputEmpty);
                    return false;
                }

                std::string host;
                int prefix = -1;
                bool prefix_f = false;

                std::size_t i = cidr.find('/');
                if (i == ppp::string::npos)
                {
                    host = cidr;
                }
                else
                {
                    if (i == 0)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteTableAddRouteMissingHostBeforeSlash);
                        return false;
                    }

                    host = cidr.substr(0, i);
                    prefix_f = true;

                    char* endptr = NULLPTR;
                    long parsed_prefix = strtol(cidr.data() + (i + 1), &endptr, 10);
                    if (NULLPTR == endptr || endptr == (cidr.data() + (i + 1)) || *endptr != '\x0') {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteTableAddRouteInvalidPrefix);
                        return false;
                    }

                    prefix = static_cast<int>(parsed_prefix);
                }

                boost::system::error_code ec;
                boost::asio::ip::address ip = StringToAddress(host, ec);
                if (ec)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }

                if (ip.is_v4())
                {
                    if (!prefix_f)
                    {
                        prefix = 32;
                    }
                    elif(prefix < 0 || prefix > 32)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkMaskInvalid);
                        return false;
                    }
                }
                else
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressFamilyMismatch);
                    return false;
                }

                boost::asio::ip::address_v4 in = ip.to_v4();
                return AddRoute(htonl(in.to_uint()), prefix, gw);
            }

            /** @brief Inserts or updates route entry identified by destination/prefix. */
            bool RouteInformationTable::AddRoute(uint32_t ip, int prefix, uint32_t gw) noexcept
            {
                if (prefix < MIN_PREFIX_VALUE || prefix > MAX_PREFIX_VALUE)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkMaskInvalid);
                    return false;
                }

                if (IPEndPoint::NoneAddress == ip)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }

                if (IPEndPoint::AnyAddress == gw || IPEndPoint::NoneAddress == gw)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkGatewayInvalid);
                    return false;
                }

                uint32_t mask = IPEndPoint::PrefixToNetmask(prefix);
                if ((ip & mask) != ip)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }

                RouteEntries& entries = routes[ip];
                auto tail = std::find_if(entries.begin(), entries.end(),
                    [prefix](RouteEntry& route) noexcept -> bool
                    {
                        return route.Prefix == prefix;
                    });
                if (tail != entries.end())
                {
                    tail->NextHop = gw;
                }
                else
                {
                    RouteEntry entry;
                    entry.NextHop = gw;
                    entry.Destination = ip;
                    entry.Prefix = prefix;
                    entries.emplace_back(entry);
                }
                return true;
            }

            /** @brief Deletes all route entries under one destination key. */
            bool RouteInformationTable::DeleteRoute(uint32_t ip) noexcept
            {
                auto tail = routes.find(ip);
                auto endl = routes.end();
                if (tail == endl)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                    return false;
                }

                routes.erase(tail);
                return true;
            }

            /** @brief Deletes route entries matching destination and gateway. */
            bool RouteInformationTable::DeleteRoute(uint32_t ip, uint32_t gw) noexcept
            {
                auto tail = routes.find(ip);
                auto endl = routes.end();
                if (tail == endl)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                    return false;
                }

                ppp::vector<int> prefixes;
                auto& entries = tail->second;
                for (auto&& route : entries)
                {
                    if (route.NextHop == gw)
                    {
                        prefixes.emplace_back(route.Prefix);
                    }
                }

                for (int prefix : prefixes)
                {
                    DeleteRoute(ip, prefix, gw);
                }

                if (0 < prefixes.size())
                {
                    return true;
                }

                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                return false;
            }

            /** @brief Deletes one route entry matching destination/prefix/gateway. */
            bool RouteInformationTable::DeleteRoute(uint32_t ip, int prefix, uint32_t gw) noexcept
            {
                auto tail = routes.find(ip);
                auto endl = routes.end();
                if (tail == endl)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                    return false;
                }

                auto& entries = tail->second;
                auto entry_tail = std::find_if(entries.begin(), entries.end(),
                    [prefix, gw](RouteEntry& route) noexcept -> bool
                    {
                        return route.Prefix == prefix && route.NextHop == gw;
                    });

                if (entry_tail == entries.end())
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                    return false;
                }

                entries.erase(entry_tail);
                if (entries.empty())
                {
                    routes.erase(tail);
                }
                return true;
            }

            /** @brief Returns mutable access to route entries table. */
            RouteEntriesTable& RouteInformationTable::GetAllRoutes() noexcept
            {
                return routes;
            }

            /** @brief Removes all route entries from RIB. */
            void RouteInformationTable::Clear() noexcept
            {
                routes.clear();
            }

            /** @brief Builds forwarding table snapshot from route-information table. */
            ForwardInformationTable::ForwardInformationTable(RouteInformationTable& rib) noexcept
            {
                Fill(rib);
            }

            /** @brief Performs next-hop lookup using default prefix bounds. */
            uint32_t ForwardInformationTable::GetNextHop(uint32_t ip, RouteEntriesTable& routes) noexcept
            {
                return GetNextHop(ip, MIN_PREFIX_VALUE, MAX_PREFIX_VALUE, routes);
            }

            /**
             * @brief Performs longest-prefix-match lookup in the provided route table.
             * @return Next-hop IPv4 address in network order, or `IPEndPoint::NoneAddress`.
             */
            uint32_t ForwardInformationTable::GetNextHop(uint32_t ip, int min_prefix_value, int max_prefix_value, RouteEntriesTable& routes) noexcept
            {
                for (int prefix = max_prefix_value; prefix >= min_prefix_value; prefix--)
                {
                    uint32_t mask = IPEndPoint::PrefixToNetmask(prefix);
                    uint32_t dest = ip & mask;
                    auto tail = routes.find(dest);
                    auto endl = routes.end();
                    if (tail == endl)
                    {
                        continue;
                    }

                    for (auto&& entry : tail->second)
                    {
                        if (prefix >= entry.Prefix)
                        {
                            return entry.NextHop;
                        }
                    }
                }

                return IPEndPoint::NoneAddress;
            }

            /** @brief Performs next-hop lookup against internal forwarding table. */
            uint32_t ForwardInformationTable::GetNextHop(uint32_t ip) noexcept
            {
                return GetNextHop(ip, routes);
            }

            /** @brief Returns mutable access to forwarding route table. */
            RouteEntriesTable& ForwardInformationTable::GetAllRoutes() noexcept
            {
                return routes;
            }

            /** @brief Copies routes from RIB and sorts each bucket by prefix descending. */
            void ForwardInformationTable::Fill(RouteInformationTable& rib) noexcept
            {
                routes = rib.GetAllRoutes();
                for (auto&& kv : routes)
                {
                    auto& entries = kv.second;
                    std::sort(entries.begin(), entries.end(),
                        [](RouteEntry& x, RouteEntry& y) noexcept
                        {
                            return x.Prefix > y.Prefix;
                        });
                }
            }

            /** @brief Removes all forwarding entries. */
            void ForwardInformationTable::Clear() noexcept
            {
                routes.clear();
            }
        }
    }
}
