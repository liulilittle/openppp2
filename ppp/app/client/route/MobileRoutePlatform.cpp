#include <ppp/stdafx.h>
#include <ppp/app/client/route/MobileRoutePlatform.h>

namespace ppp::app::client::route {

std::vector<RouteSpec> BuildMobileRouteSpecs(const MobileRoutePlan& plan) noexcept {
    std::vector<RouteSpec> routes;
    routes.reserve(1 + plan.tunnel_dns.size() + plan.underlying_dns.size());

    RouteSpec subnet;
    subnet.network = plan.tap_network;
    subnet.gateway = plan.tap_gateway;
    subnet.prefix = plan.tap_prefix;
    routes.emplace_back(subnet);

    std::vector<uint32_t> tunnel_dns(plan.tunnel_dns.begin(), plan.tunnel_dns.end());
    std::vector<uint32_t> underlying_dns(
        plan.underlying_dns.begin(), plan.underlying_dns.end());
    std::sort(tunnel_dns.begin(), tunnel_dns.end());
    std::sort(underlying_dns.begin(), underlying_dns.end());

    for (uint32_t ip : tunnel_dns) {
        routes.push_back(RouteSpec{ ip, plan.tap_gateway, 32, {} });
    }
    for (uint32_t ip : underlying_dns) {
        if (plan.tunnel_dns.find(ip) == plan.tunnel_dns.end()) {
            routes.push_back(RouteSpec{ ip, plan.loopback_gateway, 32, {} });
        }
    }
    return routes;
}

MobileRoutePlatform::MobileRoutePlatform(AddOperation add) noexcept
    : add_(std::move(add)) {
}

bool MobileRoutePlatform::ApplyAll(const std::vector<RouteSpec>& routes) noexcept {
    if (!add_) {
        return false;
    }
    for (const RouteSpec& route : routes) {
        if (!add_(route)) {
            return false;
        }
    }
    return true;
}

}
