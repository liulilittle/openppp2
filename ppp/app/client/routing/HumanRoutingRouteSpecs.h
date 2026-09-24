#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <ppp/app/client/route/IRoutePlatform.h>
#include <ppp/app/client/route/RoutePlanInput.h>

namespace ppp::app::client::routing {

enum class HumanRoutingRouteEnvironment {
    Desktop,
    Mobile,
};

enum class HumanRoutingRouteErrorCode {
    InvalidAction,
    InvalidSource,
    InvalidPrefix,
    NonCanonicalNetwork,
    MissingGateway,
    MissingInterface,
};

struct HumanRoutingRouteError final {
    HumanRoutingRouteErrorCode code = HumanRoutingRouteErrorCode::InvalidAction;
    std::size_t rule_index = 0;
    RuleOrigin origin = RuleOrigin::Explicit;
    RoutingAction action = RoutingAction::Auto;
    std::uint32_t network = 0; // Host byte order.
    std::uint8_t prefix_length = 0;
    std::size_t line = 0;
    std::string reason;
};

struct HumanRoutingRouteSpecPlan final {
    std::vector<route::RouteSpec> routes;
    std::size_t invalid_count = 0;
    std::vector<HumanRoutingRouteError> errors;
};

HumanRoutingRouteSpecPlan BuildHumanRoutingRouteSpecs(
    const route::RoutePlanInput& input,
    HumanRoutingRouteEnvironment environment =
        HumanRoutingRouteEnvironment::Desktop) noexcept;

} // namespace ppp::app::client::routing
