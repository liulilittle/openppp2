#include <ppp/net/IPEndPoint.h>
#include <windows/ppp/win32/network/Router.h>

typedef ppp::net::IPEndPoint IPEndPoint;

namespace ppp
{
    namespace win32
    {
        namespace network
        {
            template <typename Loop>
            static int Router_DeleteRoute(const std::shared_ptr<MIB_IPFORWARDTABLE>& table, Loop&& loop) noexcept
            {
                if (NULL == table)
                {
                    return -1;
                }

                int events = 0;
                for (DWORD dwNumEntries = 0; dwNumEntries < table->dwNumEntries; dwNumEntries++)
                {
                    MIB_IPFORWARDROW& route = table->table[dwNumEntries];
                    if (loop(route))
                    {
                        if (Router::Delete(route))
                        {
                            events++;
                        }
                    }
                }
                return events;
            }

            bool Router::GetBestRoute(uint32_t destination, uint32_t source, MIB_IPFORWARDROW& route) noexcept
            {
                int err = ::GetBestRoute(destination, source, &route);
                return err == NO_ERROR;
            }

            bool Router::GetBestRoute(uint32_t destination, MIB_IPFORWARDROW& route) noexcept
            {
                return GetBestRoute(destination, 0, route);
            }

            int Router::GetBestInterface(uint32_t ip) noexcept
            {
                DWORD dwBestIfIndex = 0;
                int err = ::GetBestInterface(ip, &dwBestIfIndex);
                if (err != NO_ERROR)
                {
                    return -1;
                }

                return dwBestIfIndex;
            }

            int Router::Delete(const std::shared_ptr<MIB_IPFORWARDTABLE>& table, uint32_t destination, uint32_t mask, uint32_t gw, int interface_index) noexcept
            {
                return Router_DeleteRoute(table,
                    [&](MIB_IPFORWARDROW& route) noexcept
                    {
                        return route.dwForwardDest == destination && route.dwForwardMask == mask && route.dwForwardNextHop == gw && (int)route.dwForwardIfIndex == interface_index;
                    });
            }

            int Router::Delete(const std::shared_ptr<MIB_IPFORWARDTABLE>& table, uint32_t destination, uint32_t mask, uint32_t gw) noexcept
            {
                return Router_DeleteRoute(table,
                    [&](MIB_IPFORWARDROW& route) noexcept
                    {
                        return route.dwForwardDest == destination && route.dwForwardMask == mask && route.dwForwardNextHop == gw;
                    });
            }

            int Router::Delete(const std::shared_ptr<MIB_IPFORWARDTABLE>& table, uint32_t destination, uint32_t gw) noexcept
            {
                return Router_DeleteRoute(table,
                    [&](MIB_IPFORWARDROW& route) noexcept
                    {
                        return route.dwForwardDest == destination && route.dwForwardNextHop == gw;
                    });
            }

            int Router::Delete(const std::shared_ptr<MIB_IPFORWARDTABLE>& table, uint32_t destination) noexcept
            {
                return Router_DeleteRoute(table,
                    [&](MIB_IPFORWARDROW& route) noexcept
                    {
                        return route.dwForwardDest == destination;
                    });
            }

            int Router::Delete(const std::shared_ptr<MIB_IPFORWARDTABLE>& table, uint32_t destination, int interface_index) noexcept
            {
                return Router_DeleteRoute(table,
                    [&](MIB_IPFORWARDROW& route) noexcept
                    {
                        return route.dwForwardDest == destination && (int)route.dwForwardIfIndex == interface_index;
                    });
            }

            bool Router::Delete(MIB_IPFORWARDROW& route) noexcept
            {
                int err = ::DeleteIpForwardEntry(&route);
                return err == NO_ERROR;
            }

            std::shared_ptr<MIB_IPFORWARDTABLE> Router::GetIpForwardTable() noexcept
            {
                PMIB_IPFORWARDTABLE pRouteTable = NULL;
                DWORD dwSize = 0;
                DWORD dwErr = ::GetIpForwardTable(pRouteTable, &dwSize, true);
                if (dwErr == ERROR_INSUFFICIENT_BUFFER)
                {
                    pRouteTable = (PMIB_IPFORWARDTABLE)Malloc(dwSize);
                    if (NULL == pRouteTable)
                    {
                        return NULL;
                    }

                    dwErr = ::GetIpForwardTable(pRouteTable, &dwSize, true);
                }

                std::shared_ptr<MIB_IPFORWARDTABLE> pRouteTablePtr(pRouteTable,
                    [](MIB_IPFORWARDTABLE* p) noexcept
                    {
                        Mfree(p);
                    });;
                if (dwErr != ERROR_SUCCESS)
                {
                    pRouteTablePtr.reset();
                }

                return pRouteTablePtr;
            }

            bool Router::Add(uint32_t destination, uint32_t gw, int metric) noexcept
            {
                return Add(destination, IPEndPoint::NoneAddress, gw, metric);
            }

            bool Router::Add(uint32_t destination, uint32_t mask, uint32_t gw, int metric) noexcept
            {
                int interface_index = GetBestInterface(gw);
                return Add(destination, mask, gw, metric, interface_index);
            }

            bool Router::Add(uint32_t destination, uint32_t mask, uint32_t gw, int metric, int interface_index) noexcept
            {
                if (interface_index < 0)
                {
                    return false;
                }

                if (metric < 1)
                {
                    metric = 1;
                }

                MIB_IPFORWARDROW route;
                memset(&route, 0, sizeof(MIB_IPFORWARDROW));

                route.dwForwardDest = destination;
                route.dwForwardMask = mask;
                route.dwForwardPolicy = 0;
                route.dwForwardNextHop = gw;
                route.dwForwardIfIndex = interface_index;
                route.dwForwardType = MIB_IPROUTE_TYPE_DIRECT;
                route.dwForwardProto = MIB_IPPROTO_NETMGMT;
                route.dwForwardAge = 0;
                route.dwForwardNextHopAS = 0;
                route.dwForwardMetric1 = metric;
                route.dwForwardMetric2 = -1;
                route.dwForwardMetric3 = -1;
                route.dwForwardMetric4 = -1;
                route.dwForwardMetric5 = -1;

                MIB_IPINTERFACE_ROW mib{};
                mib.Family = AF_INET;
                mib.InterfaceIndex = interface_index;

                int err = ::GetIpInterfaceEntry(&mib);
                if (err != NO_ERROR)
                {
                    return false;
                }
                elif((int64_t)metric < (int64_t)mib.Metric)
                {
                    route.dwForwardMetric1 = mib.Metric;
                }

                return Router::Add(route);
            }

            bool Router::Add(MIB_IPFORWARDROW& route) noexcept
            {
                int err = ::CreateIpForwardEntry(&route);
                return err == NO_ERROR;
            }
        }
    }
}