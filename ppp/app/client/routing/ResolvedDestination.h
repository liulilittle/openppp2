#pragma once

#include <string>

#include <ppp/app/client/routing/HumanRoutingRules.h>
#include <ppp/net/IPEndPoint.h>

namespace ppp::app::client::routing {

    struct ResolvedDestination final {
        ppp::net::IPEndPoint original_endpoint;
        ppp::net::IPEndPoint connect_endpoint;
        std::string hostname;
        RoutingAction action = RoutingAction::Auto;
        bool is_fake_ip = false;
        bool is_resolved = true;
    };

} // namespace ppp::app::client::routing
