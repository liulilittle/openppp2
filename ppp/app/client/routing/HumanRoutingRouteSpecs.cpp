#include <ppp/stdafx.h>
#include <ppp/app/client/routing/HumanRoutingRouteSpecs.h>
#include <ppp/net/IPEndPoint.h>

#include <limits>
#include <map>

namespace ppp::app::client::routing {
namespace {

    using RuleKey = std::pair<std::uint32_t, std::uint8_t>;

    struct SelectedRule final {
        const Ipv4CidrRule* rule = nullptr;
        std::size_t index = 0;
    };

    std::uint32_t PrefixMask(std::uint8_t prefix_length) noexcept {
        return prefix_length == 0
            ? 0
            : std::numeric_limits<std::uint32_t>::max() << (32u - prefix_length);
    }

    bool IsKnownOrigin(RuleOrigin origin) noexcept {
        return origin == RuleOrigin::Explicit || origin == RuleOrigin::Geo;
    }

    bool IsGatewayPresent(std::uint32_t gateway) noexcept {
        return gateway != ppp::net::IPEndPoint::AnyAddress &&
            gateway != ppp::net::IPEndPoint::NoneAddress;
    }

    bool IsDesktopDirectGatewayPresent(const boost::asio::ip::address& gateway) noexcept {
        return gateway.is_v4() && !gateway.is_unspecified() &&
            !gateway.is_loopback() && !gateway.is_multicast() &&
            gateway.to_v4() != boost::asio::ip::address_v4::broadcast();
    }

    void AddError(
        HumanRoutingRouteSpecPlan& plan,
        HumanRoutingRouteErrorCode code,
        std::size_t index,
        const Ipv4CidrRule& rule,
        const char* reason) {
        plan.errors.push_back(HumanRoutingRouteError{
            code,
            index,
            rule.origin,
            rule.action,
            rule.network,
            rule.prefix_length,
            rule.line,
            reason,
        });
    }

} // namespace

HumanRoutingRouteSpecPlan BuildHumanRoutingRouteSpecs(
    const route::RoutePlanInput& input,
    HumanRoutingRouteEnvironment environment) noexcept {
    HumanRoutingRouteSpecPlan plan;
    std::map<RuleKey, SelectedRule> selected;

    for (std::size_t index = 0; index < input.human_ipv4_rules.size(); ++index) {
        const Ipv4CidrRule& rule = input.human_ipv4_rules[index];
        if (rule.action != RoutingAction::Direct &&
            rule.action != RoutingAction::Proxy) {
            AddError(plan, HumanRoutingRouteErrorCode::InvalidAction,
                index, rule, "human IPv4 route action must be direct or proxy");
            continue;
        }
        if (!IsKnownOrigin(rule.origin)) {
            AddError(plan, HumanRoutingRouteErrorCode::InvalidSource,
                index, rule, "human IPv4 route origin must be explicit or geo");
            continue;
        }
        if (rule.prefix_length > 32) {
            AddError(plan, HumanRoutingRouteErrorCode::InvalidPrefix,
                index, rule, "human IPv4 route prefix is outside 0..32");
            continue;
        }
        if ((rule.network & PrefixMask(rule.prefix_length)) != rule.network) {
            AddError(plan, HumanRoutingRouteErrorCode::NonCanonicalNetwork,
                index, rule, "human IPv4 route network is not prefix-aligned");
            continue;
        }

        const RuleKey key(rule.network, rule.prefix_length);
        const auto existing = selected.find(key);
        if (existing == selected.end()) {
            selected.emplace(key, SelectedRule{ &rule, index });
        }
        else if (existing->second.rule->origin == RuleOrigin::Geo &&
            rule.origin == RuleOrigin::Explicit) {
            existing->second = SelectedRule{ &rule, index };
        }
    }

    std::vector<const Ipv4CidrRule*> explicit_rules;
    explicit_rules.reserve(selected.size());
    for (const auto& item : selected) {
        if (item.second.rule->origin == RuleOrigin::Explicit) {
            explicit_rules.emplace_back(item.second.rule);
        }
    }

    for (const auto& item : selected) {
        const Ipv4CidrRule& rule = *item.second.rule;
        if (rule.origin == RuleOrigin::Geo) {
            const bool covered_by_explicit = std::any_of(
                explicit_rules.begin(), explicit_rules.end(),
                [&rule](const Ipv4CidrRule* explicit_rule) noexcept {
                    return explicit_rule->prefix_length < rule.prefix_length &&
                        (rule.network & PrefixMask(explicit_rule->prefix_length)) ==
                            explicit_rule->network;
                });
            if (covered_by_explicit) {
                continue;
            }
        }

        route::RouteSpec route_spec;
        route_spec.network = htonl(rule.network);
        route_spec.prefix = rule.prefix_length;

        if (rule.action == RoutingAction::Proxy) {
            if (!IsGatewayPresent(input.tap_gateway)) {
                AddError(plan, HumanRoutingRouteErrorCode::MissingGateway,
                    item.second.index, rule, "proxy human IPv4 routes require a tap gateway");
                continue;
            }
            route_spec.gateway = input.tap_gateway;
            if (environment == HumanRoutingRouteEnvironment::Desktop) {
                if (input.tap_interface.name.empty()) {
                    AddError(plan, HumanRoutingRouteErrorCode::MissingInterface,
                        item.second.index, rule, "proxy human IPv4 routes require a tap interface");
                    continue;
                }
                route_spec.interface_name = input.tap_interface.name;
            }
        }
        else if (environment == HumanRoutingRouteEnvironment::Mobile) {
            route_spec.gateway = ppp::net::IPEndPoint::LoopbackAddress;
        }
        else {
            if (!IsDesktopDirectGatewayPresent(input.underlying_interface.gateway)) {
                AddError(plan, HumanRoutingRouteErrorCode::MissingGateway,
                    item.second.index, rule,
                    "direct human IPv4 routes require an underlying IPv4 gateway");
                continue;
            }
            if (input.underlying_interface.name.empty()) {
                AddError(plan, HumanRoutingRouteErrorCode::MissingInterface,
                    item.second.index, rule,
                    "direct human IPv4 routes require an underlying interface");
                continue;
            }
            route_spec.gateway = htonl(
                input.underlying_interface.gateway.to_v4().to_uint());
            route_spec.interface_name = input.underlying_interface.name;
        }
        plan.routes.emplace_back(std::move(route_spec));
    }

    std::sort(plan.routes.begin(), plan.routes.end(),
        [](const route::RouteSpec& left, const route::RouteSpec& right) noexcept {
            return std::make_tuple(ntohl(left.network), left.prefix,
                       ntohl(left.gateway), left.interface_name) <
                std::make_tuple(ntohl(right.network), right.prefix,
                       ntohl(right.gateway), right.interface_name);
        });
    plan.invalid_count = plan.errors.size();
    return plan;
}

} // namespace ppp::app::client::routing
