#pragma once

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

#include <ppp/app/client/route/IRoutePlatform.h>

namespace ppp::app::client::route {

// A compact, versioned route-spec encoding used as the durable journal
// payload for routes created by OpenPPP2.  It has no platform pointers or
// process-local addresses.  The payload alone is not ownership proof: a
// platform-specific identity/CAS check is still required before replay.
inline bool SerializeRouteSpecForJournal(
    const RouteSpec& route, std::string& output) noexcept {
    if (route.prefix < 0 || route.prefix > 32 ||
        route.interface_name.size() > std::numeric_limits<uint16_t>::max()) {
        return false;
    }
    try {
        output.clear();
        output.append("OPP2RT1", 7);
        const auto u32 = [&output](uint32_t value) {
            for (unsigned shift = 0; shift < 32; shift += 8) {
                output.push_back(static_cast<char>((value >> shift) & 0xffu));
            }
        };
        u32(route.network);
        u32(route.gateway);
        u32(static_cast<uint32_t>(route.prefix));
        const uint16_t size = static_cast<uint16_t>(route.interface_name.size());
        output.push_back(static_cast<char>(size & 0xffu));
        output.push_back(static_cast<char>(size >> 8));
        output.append(route.interface_name);
        return true;
    }
    catch (...) {
        output.clear();
        return false;
    }
}

inline std::optional<RouteSpec> DeserializeRouteSpecForJournal(
    std::string_view input) noexcept {
    if (input.size() < 7 + 12 + 2 || input.substr(0, 7) != "OPP2RT1") {
        return std::nullopt;
    }
    try {
        size_t offset = 7;
        const auto u32 = [&input, &offset](uint32_t& value) noexcept {
            if (input.size() - offset < 4) return false;
            value = static_cast<uint32_t>(static_cast<unsigned char>(input[offset])) |
                (static_cast<uint32_t>(static_cast<unsigned char>(input[offset + 1])) << 8) |
                (static_cast<uint32_t>(static_cast<unsigned char>(input[offset + 2])) << 16) |
                (static_cast<uint32_t>(static_cast<unsigned char>(input[offset + 3])) << 24);
            offset += 4;
            return true;
        };
        RouteSpec route;
        uint32_t prefix = 0;
        if (!u32(route.network) || !u32(route.gateway) || !u32(prefix) ||
            prefix > 32 || input.size() - offset < 2) {
            return std::nullopt;
        }
        const uint16_t size = static_cast<uint16_t>(
            static_cast<unsigned char>(input[offset]) |
            (static_cast<uint16_t>(static_cast<unsigned char>(input[offset + 1])) << 8));
        offset += 2;
        if (input.size() - offset != size) return std::nullopt;
        route.prefix = static_cast<int>(prefix);
        route.interface_name.assign(input.data() + offset, size);
        return route;
    }
    catch (...) {
        return std::nullopt;
    }
}

} // namespace ppp::app::client::route
