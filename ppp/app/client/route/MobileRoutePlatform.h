#pragma once

#include <cstdint>
#include <functional>
#include <unordered_set>
#include <vector>

#include <ppp/app/client/route/IRoutePlatform.h>

namespace ppp::app::client::route {

struct MobileRoutePlan final {
    uint32_t tap_network = 0;
    int tap_prefix = 0;
    uint32_t tap_gateway = 0;
    uint32_t loopback_gateway = 0;
    std::unordered_set<uint32_t> tunnel_dns;
    std::unordered_set<uint32_t> underlying_dns;
};

std::vector<RouteSpec> BuildMobileRouteSpecs(const MobileRoutePlan& plan) noexcept;

class MobileRoutePlatform final {
public:
    using AddOperation = std::function<bool(const RouteSpec&)>;

    explicit MobileRoutePlatform(AddOperation add) noexcept;
    bool ApplyAll(const std::vector<RouteSpec>& routes) noexcept;

private:
    AddOperation add_;
};

}
