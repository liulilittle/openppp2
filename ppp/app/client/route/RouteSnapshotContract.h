#pragma once

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <ppp/app/client/route/IRoutePlatform.h>

namespace ppp::app::client::route {

// This is deliberately independent of IRouteSnapshot.  IRouteSnapshot is an
// in-process polymorphic object; this record is the stable representation a
// future recovery worker can persist and validate after a restart.
enum class RouteSnapshotPlatform : uint8_t {
    Linux = 1,
    Darwin = 2,
};

struct RouteSnapshotIdentity final {
    uint32_t interface_index = 0;
    std::string interface_name;
    // Linux uses the interface hardware address.  Darwin uses the link-layer
    // address when available.  It is kept as text so the record is portable.
    std::string link_identity;

    bool Complete() const noexcept {
        return interface_index != 0 && !interface_name.empty() &&
            !link_identity.empty();
    }
};

struct RouteSnapshotRecord final {
    static constexpr uint8_t kVersion = 1;

    uint8_t version = kVersion;
    RouteSnapshotPlatform platform = RouteSnapshotPlatform::Linux;
    RouteSpec route;
    RouteSnapshotIdentity identity;

    bool Complete() const noexcept {
        return version == kVersion &&
            (platform == RouteSnapshotPlatform::Linux ||
                platform == RouteSnapshotPlatform::Darwin) &&
            route.prefix >= 0 && route.prefix <= 32 &&
            route.interface_name == identity.interface_name &&
            identity.Complete();
    }
};

inline bool SameRouteSnapshotIdentity(
    const RouteSnapshotIdentity& left,
    const RouteSnapshotIdentity& right) noexcept {
    return left.interface_index == right.interface_index &&
        left.interface_name == right.interface_name &&
        left.link_identity == right.link_identity;
}

inline bool SameRouteSnapshotRoute(
    const RouteSnapshotRecord& left,
    const RouteSnapshotRecord& right) noexcept {
    return left.platform == right.platform &&
        SameRouteSnapshotIdentity(left.identity, right.identity) &&
        left.route.network == right.route.network &&
        left.route.gateway == right.route.gateway &&
        left.route.prefix == right.route.prefix &&
        left.route.interface_name == right.route.interface_name;
}

namespace route_snapshot_detail {

inline void AppendU32(std::string& output, uint32_t value) {
    output.push_back(static_cast<char>(value & 0xffu));
    output.push_back(static_cast<char>((value >> 8) & 0xffu));
    output.push_back(static_cast<char>((value >> 16) & 0xffu));
    output.push_back(static_cast<char>((value >> 24) & 0xffu));
}

inline bool ReadU32(std::string_view input, size_t& offset, uint32_t& value) noexcept {
    if (offset > input.size() || input.size() - offset < 4) {
        return false;
    }
    const auto at = [&input](size_t index) noexcept {
        return static_cast<uint32_t>(static_cast<unsigned char>(input[index]));
    };
    value = at(offset) | (at(offset + 1) << 8) |
        (at(offset + 2) << 16) | (at(offset + 3) << 24);
    offset += 4;
    return true;
}

inline bool AppendString(std::string& output, const std::string& value) {
    if (value.size() > std::numeric_limits<uint16_t>::max()) {
        return false;
    }
    const uint16_t length = static_cast<uint16_t>(value.size());
    output.push_back(static_cast<char>(length & 0xffu));
    output.push_back(static_cast<char>((length >> 8) & 0xffu));
    output.append(value);
    return true;
}

inline bool ReadString(
    std::string_view input,
    size_t& offset,
    std::string& value) {
    if (offset > input.size() || input.size() - offset < 2) {
        return false;
    }
    const uint16_t length = static_cast<uint16_t>(
        static_cast<unsigned char>(input[offset])) |
        static_cast<uint16_t>(static_cast<unsigned char>(input[offset + 1])) << 8;
    offset += 2;
    if (input.size() - offset < length) {
        return false;
    }
    value.assign(input.data() + offset, length);
    offset += length;
    return true;
}

} // namespace route_snapshot_detail

// Wire format (little-endian, fixed magic, length-prefixed UTF-8 strings):
// magic[6]="OPP2RS", version[1], platform[1], reserved[2],
// network[4], gateway[4], prefix[4], ifindex[4], then name/link strings.
inline bool SerializeRouteSnapshot(
    const RouteSnapshotRecord& record,
    std::string& output) noexcept {
    if (!record.Complete()) {
        return false;
    }
    try {
        output.clear();
        output.reserve(32 + record.identity.interface_name.size() +
            record.identity.link_identity.size());
        output.append("OPP2RS", 6);
        output.push_back(static_cast<char>(record.version));
        output.push_back(static_cast<char>(record.platform));
        output.push_back('\0');
        output.push_back('\0');
        route_snapshot_detail::AppendU32(output, record.route.network);
        route_snapshot_detail::AppendU32(output, record.route.gateway);
        route_snapshot_detail::AppendU32(
            output, static_cast<uint32_t>(record.route.prefix));
        route_snapshot_detail::AppendU32(
            output, record.identity.interface_index);
        return route_snapshot_detail::AppendString(
                output, record.identity.interface_name) &&
            route_snapshot_detail::AppendString(
                output, record.identity.link_identity);
    }
    catch (...) {
        output.clear();
        return false;
    }
}

inline std::optional<RouteSnapshotRecord> DeserializeRouteSnapshot(
    std::string_view input) noexcept {
    constexpr size_t kFixedSize = 6 + 1 + 1 + 2 + 4 * 4 + 2 + 2;
    if (input.size() < kFixedSize || input.substr(0, 6) != "OPP2RS") {
        return std::nullopt;
    }
    try {
        size_t offset = 6;
        RouteSnapshotRecord record;
        record.version = static_cast<uint8_t>(input[offset++]);
        const uint8_t platform = static_cast<uint8_t>(input[offset++]);
        if (record.version != RouteSnapshotRecord::kVersion ||
            (platform != static_cast<uint8_t>(RouteSnapshotPlatform::Linux) &&
                platform != static_cast<uint8_t>(RouteSnapshotPlatform::Darwin))) {
            return std::nullopt;
        }
        record.platform = static_cast<RouteSnapshotPlatform>(platform);
        // Reserved bytes must be zero so future versions cannot silently be
        // interpreted as version 1 records.
        if (input[offset++] != '\0' || input[offset++] != '\0') {
            return std::nullopt;
        }
        uint32_t prefix = 0;
        if (!route_snapshot_detail::ReadU32(input, offset, record.route.network) ||
            !route_snapshot_detail::ReadU32(input, offset, record.route.gateway) ||
            !route_snapshot_detail::ReadU32(input, offset, prefix) ||
            !route_snapshot_detail::ReadU32(
                input, offset, record.identity.interface_index) ||
            !route_snapshot_detail::ReadString(
                input, offset, record.identity.interface_name) ||
            !route_snapshot_detail::ReadString(
                input, offset, record.identity.link_identity) ||
            offset != input.size() || prefix > 32) {
            return std::nullopt;
        }
        record.route.prefix = static_cast<int>(prefix);
        record.route.interface_name = record.identity.interface_name;
        return record.Complete() ? std::optional<RouteSnapshotRecord>(
            std::move(record)) : std::nullopt;
    }
    catch (...) {
        return std::nullopt;
    }
}

} // namespace ppp::app::client::route
