#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/IPEndPoint.h>

namespace ppp
{
    namespace net
    {
        namespace native
        {
            typedef struct
            {
                uint32_t                                                Destination;
                int                                                     Prefix;
                uint32_t                                                NextHop;
            }                                                           RouteEntry;

            typedef ppp::vector<RouteEntry>                             RouteEntries;
            typedef ppp::unordered_map<uint32_t, RouteEntries>          RouteEntriesTable;

            static constexpr int                                        MIN_PREFIX_VALUE = 0;
            static constexpr int                                        MAX_PREFIX_VALUE = 32;
            static constexpr int                                        MAX_PREFIX_VALUE_V4 = MAX_PREFIX_VALUE;
            static constexpr int                                        MAX_PREFIX_VALUE_V6 = 128;

            // RIB
            class RouteInformationTable
            {
            public:
                bool                                                    AddRoute(uint32_t ip, int prefix, uint32_t gw) noexcept;
                bool                                                    AddRoute(const ppp::string& cidr, uint32_t gw) noexcept;
                bool                                                    AddAllRoutes(const ppp::string& cidrs, uint32_t gw) noexcept;
                bool                                                    AddAllRoutesByIPList(const ppp::string& path, uint32_t gw) noexcept;
                bool                                                    IsAvailable() noexcept { return routes.begin() != routes.end(); }

            public:
                bool                                                    DeleteRoute(uint32_t ip) noexcept;
                bool                                                    DeleteRoute(uint32_t ip, uint32_t gw) noexcept;
                bool                                                    DeleteRoute(uint32_t ip, int prefix, uint32_t gw) noexcept;

            public:
                RouteEntriesTable&                                      GetAllRoutes() noexcept;
                void                                                    Clear() noexcept;

            private:
                RouteEntriesTable                                       routes;
            };

            // FIB
            class ForwardInformationTable
            {
            public:
                ForwardInformationTable() noexcept = default;
                ForwardInformationTable(RouteInformationTable& rib) noexcept;

            public:
                uint32_t                                                GetNextHop(uint32_t ip) noexcept;
                static uint32_t                                         GetNextHop(uint32_t ip, RouteEntriesTable& routes) noexcept;
                static uint32_t                                         GetNextHop(uint32_t ip, int min_prefix_value, int max_prefix_value, RouteEntriesTable& routes) noexcept;
                void                                                    Fill(RouteInformationTable& rib) noexcept;
                void                                                    Clear() noexcept;
                RouteEntriesTable&                                      GetAllRoutes() noexcept;
                bool                                                    IsAvailable() noexcept { return routes.begin() != routes.end(); }

            private:
                RouteEntriesTable                                       routes;
            };
        }
    }
}