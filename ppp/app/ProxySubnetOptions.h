#pragma once

#include <cstdint>
#include <unordered_map>

namespace ppp::app {
    struct ProxySubnetOptions final {
        bool subnet = true;
        bool internet = true;
        std::unordered_map<uint16_t, uint16_t> forwards;
    };

    ProxySubnetOptions ParseProxySubnetOptions(int argc, const char* argv[]) noexcept;

    inline bool ProxyDestinationAllowed(bool internet, bool virtual_subnet) noexcept {
        return internet || virtual_subnet;
    }
}
