#include <linux/ppp/tap/TapLinux.h>

namespace linux_route_platform_test {

    int route_add_error = 0;
    bool route_query_succeeded = false;
    bool exact_route_exists = false;
    int exact_route_probes = 0;
    int route_deletes = 0;

    void ConfigureRouteAdd(
        int error,
        bool query_succeeded,
        bool exact_exists) noexcept {
        route_add_error = error;
        route_query_succeeded = query_succeeded;
        exact_route_exists = exact_exists;
        exact_route_probes = 0;
        route_deletes = 0;
    }

    int ExactRouteProbes() noexcept {
        return exact_route_probes;
    }

    int RouteDeletes() noexcept {
        return route_deletes;
    }

}

namespace ppp {
    namespace tap {

        std::shared_ptr<ppp::net::native::RouteInformationTable>
        TapLinux::FindAllDefaultGatewayRoutes(const ppp::unordered_set<uint32_t>&) noexcept {
            return NULLPTR;
        }

        bool TapLinux::TryFindAllDefaultGatewayRoutes(
            const ppp::unordered_set<uint32_t>&,
            std::shared_ptr<ppp::net::native::RouteInformationTable>& routes) noexcept {
            routes.reset();
            return false;
        }

        bool TapLinux::AddAllRoutes(
            const ppp::function<ppp::string(ppp::net::native::RouteEntry&)>&,
            std::shared_ptr<ppp::net::native::RouteInformationTable>) noexcept {
            return false;
        }

        bool TapLinux::DeleteAllRoutes(
            const ppp::function<ppp::string(ppp::net::native::RouteEntry&)>&,
            std::shared_ptr<ppp::net::native::RouteInformationTable>) noexcept {
            return false;
        }

        bool TapLinux::AddRoute(
            const ppp::string&,
            UInt32,
            int,
            UInt32) noexcept {
            return false;
        }

        TapLinux::RouteMutationResult TapLinux::AddRouteStatus(
            const ppp::string&,
            UInt32,
            int,
            UInt32) noexcept {
            if (linux_route_platform_test::route_add_error == EEXIST) {
                ++linux_route_platform_test::exact_route_probes;
            }
            return ClassifyRouteAddResult(
                linux_route_platform_test::route_add_error,
                linux_route_platform_test::route_query_succeeded,
                linux_route_platform_test::exact_route_exists);
        }

        bool TapLinux::DeleteRoute(
            const ppp::string&,
            UInt32,
            int,
            UInt32) noexcept {
            ++linux_route_platform_test::route_deletes;
            return false;
        }

    }
}

namespace ppp {
    namespace net {
        namespace native {

            bool RouteInformationTable::AddRoute(
                uint32_t ip,
                int prefix,
                uint32_t gw) noexcept {
                RouteEntry entry;
                entry.Destination = ip;
                entry.Prefix = prefix;
                entry.NextHop = gw;
                routes[ip].emplace_back(entry);
                return true;
            }

            RouteEntriesTable& RouteInformationTable::GetAllRoutes() noexcept {
                return routes;
            }

        }
    }
}
