#pragma once

#include <array>
#include <memory>
#include <unordered_set>
#include <vector>

#include <ppp/app/client/route/IRoutePlatform.h>
#include <ppp/app/client/route/RoutePlanInput.h>
#include <ppp/net/native/rib_fwd.h>

namespace ppp::app::client::route {

std::vector<RouteSpec> BuildRouteSpecs(
    const std::shared_ptr<ppp::net::native::RouteInformationTable>& rib) noexcept;

RouteSpec ResolveRouteSpec(
    const RoutePlanInput& input,
    RouteSpec route) noexcept;

struct DnsRouteSpecPlan final {
    std::vector<RouteSpec> routes;
    std::array<std::unordered_set<uint32_t>, 3> servers;
};

DnsRouteSpecPlan BuildDnsRouteSpecs(const RoutePlanInput& input) noexcept;

std::vector<RouteSpec> MergeRouteSpecs(
    const std::vector<RouteSpec>& legacy,
    const std::vector<RouteSpec>& human,
    const std::vector<RouteSpec>& dns_and_fake) noexcept;

}
