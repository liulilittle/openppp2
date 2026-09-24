#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <boost/asio/ip/address.hpp>

#include <ppp/app/client/route/IRoutePlatform.h>
#include <ppp/app/client/routing/HumanRoutingRules.h>

namespace ppp::app::client::route {

struct RouteInterfaceSnapshot final {
    std::string name;
    int index = -1;
    boost::asio::ip::address ip;
    boost::asio::ip::address gateway;
    boost::asio::ip::address submask;
    std::vector<boost::asio::ip::address> dns;
};

struct RouteSource final {
    std::string path;
    uint32_t gateway = 0;
};

struct RoutePlanInput final {
    uint32_t tap_ip = 0;
    uint32_t tap_gateway = 0;
    uint32_t tap_submask = 0;
    bool tap_hosted = false;
    bool tap_promiscuous = false;
    RouteInterfaceSnapshot tap_interface;
    RouteInterfaceSnapshot underlying_interface;
    std::unordered_map<uint32_t, std::string> nics;
    std::vector<RouteSource> route_sources;
    std::string bypass_ip_list;
    std::unordered_set<uint32_t> tunnel_dns;
    std::unordered_set<uint32_t> underlying_dns;
    std::vector<routing::Ipv4CidrRule> human_ipv4_rules;
    bool has_fake_ip_route = false;
    RouteSpec fake_ip_route;
};

}
