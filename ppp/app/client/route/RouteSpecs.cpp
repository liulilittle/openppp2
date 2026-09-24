#include <ppp/stdafx.h>
#include <ppp/app/client/route/RouteSpecs.h>
#include <ppp/net/native/rib.h>

#include <map>
#include <set>

namespace ppp::app::client::route {

std::vector<RouteSpec> BuildRouteSpecs(
    const std::shared_ptr<ppp::net::native::RouteInformationTable>& rib) noexcept {
    std::vector<RouteSpec> specs;
    if (NULLPTR == rib) {
        return specs;
    }

    for (const auto& pair : rib->GetAllRoutes()) {
        for (const ppp::net::native::RouteEntry& entry : pair.second) {
            specs.push_back(RouteSpec{
                entry.Destination,
                entry.NextHop,
                entry.Prefix,
                {},
            });
        }
    }
    std::sort(specs.begin(), specs.end(), [](const RouteSpec& left,
        const RouteSpec& right) noexcept {
        return std::tie(
            left.network,
            left.gateway,
            left.prefix,
            left.interface_name) < std::tie(
            right.network,
            right.gateway,
            right.prefix,
            right.interface_name);
    });
    return specs;
}

RouteSpec ResolveRouteSpec(
    const RoutePlanInput& input,
    RouteSpec route) noexcept {
    if (!route.interface_name.empty()) {
        return route;
    }
    if (route.gateway == input.tap_gateway) {
        route.interface_name = input.tap_interface.name;
        return route;
    }
    const auto nic = input.nics.find(route.gateway);
    route.interface_name = nic != input.nics.end() && !nic->second.empty()
        ? nic->second
        : input.underlying_interface.name;
    return route;
}

DnsRouteSpecPlan BuildDnsRouteSpecs(const RoutePlanInput& input) noexcept {
    DnsRouteSpecPlan plan;

    auto collect = [&plan](const RouteInterfaceSnapshot& interface, int bucket) noexcept {
        if (interface.name.empty()) {
            return;
        }

        uint32_t values[2] = { 0, 0 };
        const boost::asio::ip::address addresses[] = {
            interface.ip,
            interface.submask,
        };
        for (int i = 0; i < arraysizeof(addresses); ++i) {
            if (addresses[i].is_v4()) {
                values[i] = addresses[i].to_v4().to_uint();
            }
        }

        const uint32_t network = values[0] & values[1];
        for (const boost::asio::ip::address& address : interface.dns) {
            if (!address.is_v4() || address.is_multicast() || address.is_loopback() ||
                address.is_unspecified() ||
                address.to_v4() == boost::asio::ip::address_v4::broadcast()) {
                continue;
            }

            const uint32_t ip = address.to_v4().to_uint();
            if ((ip & values[1]) != network) {
                plan.servers[static_cast<size_t>(bucket)].emplace(htonl(ip));
            }
        }
    };

    collect(input.tap_interface, 0);
    collect(input.underlying_interface, 1);
    plan.servers[0].insert(input.tunnel_dns.begin(), input.tunnel_dns.end());
    plan.servers[1].insert(input.underlying_dns.begin(), input.underlying_dns.end());
    for (uint32_t ip : plan.servers[0]) {
        plan.servers[1].erase(ip);
    }

    auto append_unique = [&plan](RouteSpec route) {
        const auto duplicate = [&route](const RouteSpec& value) noexcept {
            return value.network == route.network &&
                value.gateway == route.gateway &&
                value.prefix == route.prefix &&
                value.interface_name == route.interface_name;
        };
        if (std::find_if(plan.routes.begin(), plan.routes.end(), duplicate) ==
            plan.routes.end()) {
            plan.routes.emplace_back(std::move(route));
        }
    };

    if (input.has_fake_ip_route) {
        append_unique(RouteSpec{
            input.fake_ip_route.network,
            input.tap_gateway,
            input.fake_ip_route.prefix,
            {},
        });
    }

    std::vector<uint32_t> tunnel(plan.servers[0].begin(), plan.servers[0].end());
    std::sort(tunnel.begin(), tunnel.end());
    for (uint32_t ip : tunnel) {
        append_unique(RouteSpec{ ip, input.tap_gateway, 32, {} });
    }

    const boost::asio::ip::address& gateway = input.underlying_interface.gateway;
    if (gateway.is_v4()) {
        const uint32_t next_hop = htonl(gateway.to_v4().to_uint());
        std::vector<uint32_t> underlying(
            plan.servers[1].begin(), plan.servers[1].end());
        std::sort(underlying.begin(), underlying.end());
        for (uint32_t ip : underlying) {
            append_unique(RouteSpec{ ip, next_hop, 32, {} });
        }
    }

    return plan;
}

std::vector<RouteSpec> MergeRouteSpecs(
    const std::vector<RouteSpec>& legacy,
    const std::vector<RouteSpec>& human,
    const std::vector<RouteSpec>& dns_and_fake) noexcept {
    using RouteKey = std::pair<uint32_t, int>;

    std::map<RouteKey, RouteSpec> merged;
    std::set<RouteKey> protected_legacy_hosts;
    for (const RouteSpec& route : legacy) {
        const RouteKey key(route.network, route.prefix);
        merged[key] = route;
        if (route.prefix == 32) {
            protected_legacy_hosts.emplace(key);
        }
    }

    auto overlay = [&merged, &protected_legacy_hosts](
        const std::vector<RouteSpec>& routes) {
        for (const RouteSpec& route : routes) {
            const RouteKey key(route.network, route.prefix);
            // The legacy RIB does not retain remote-route provenance, so every
            // pre-existing /32 is protected conservatively. The cost is that a
            // human /32 cannot override an ordinary legacy host route either.
            if (route.prefix == 32 &&
                protected_legacy_hosts.find(key) != protected_legacy_hosts.end()) {
                continue;
            }
            merged[key] = route;
        }
    };
    overlay(human);
    overlay(dns_and_fake);

    std::vector<RouteSpec> routes;
    routes.reserve(merged.size());
    for (const auto& item : merged) {
        routes.emplace_back(item.second);
    }
    std::sort(routes.begin(), routes.end(),
        [](const RouteSpec& left, const RouteSpec& right) noexcept {
            return std::make_tuple(ntohl(left.network), left.prefix,
                       ntohl(left.gateway), left.interface_name) <
                std::make_tuple(ntohl(right.network), right.prefix,
                       ntohl(right.gateway), right.interface_name);
        });
    return routes;
}

}
