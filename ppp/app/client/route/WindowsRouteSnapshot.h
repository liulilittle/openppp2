#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace ppp::app::client::route {

// The route journal must never persist a platform struct verbatim.  Windows
// may add padding or change the layout of MIB_IPFORWARDROW, so snapshots use
// this explicitly versioned, endian-independent representation instead.
inline constexpr std::uint32_t WindowsRouteSnapshotSchemaVersion = 1;

enum class WindowsRouteSnapshotKind : std::uint8_t {
    RouteRow = 1,
    Gateway = 2,
};

struct WindowsRouteRowSnapshot final {
    std::uint32_t destination = 0;
    std::uint32_t mask = 0;
    std::uint32_t policy = 0;
    std::uint32_t next_hop = 0;
    std::uint32_t interface_index = 0;
    std::uint32_t type = 0;
    std::uint32_t proto = 0;
    std::uint32_t age = 0;
    std::uint32_t next_hop_as = 0;
    std::uint32_t metric1 = 0;
    std::uint32_t metric2 = 0;
    std::uint32_t metric3 = 0;
    std::uint32_t metric4 = 0;
    std::uint32_t metric5 = 0;

    // InterfaceIndex can be reused after an adapter is removed.  These
    // optional stable identifiers are therefore part of the compare key when
    // present.  An empty value means that the caller has no value to verify.
    std::string interface_luid;
    std::string interface_guid;
};

struct WindowsGatewaySnapshotData final {
    std::uint32_t interface_index = 0;
    std::string interface_luid;
    std::string interface_guid;
    std::string gateway;
};

// A canonical binary format is used so the journal does not depend on a JSON
// implementation.  Integers are unsigned big-endian values.  The header is:
//   "OPRS" (4 bytes), schema version (u32), kind (u8), reserved (3 bytes)
// followed by the fields for the selected kind and length-prefixed strings.
bool SerializeWindowsRouteSnapshot(
    const WindowsRouteRowSnapshot& snapshot,
    std::string& serialized) noexcept;
bool SerializeWindowsGatewaySnapshot(
    const WindowsGatewaySnapshotData& snapshot,
    std::string& serialized) noexcept;

bool DeserializeWindowsRouteSnapshot(
    std::string_view serialized,
    WindowsRouteRowSnapshot& snapshot) noexcept;
bool DeserializeWindowsGatewaySnapshot(
    std::string_view serialized,
    WindowsGatewaySnapshotData& snapshot) noexcept;

bool SameWindowsRouteSnapshot(
    const WindowsRouteRowSnapshot& left,
    const WindowsRouteRowSnapshot& right) noexcept;
bool SameWindowsGatewaySnapshot(
    const WindowsGatewaySnapshotData& left,
    const WindowsGatewaySnapshotData& right) noexcept;

// Verifies an actual row/value against a snapshot without applying any
// mutation.  Callers should treat false as a conflict and retain recovery
// state for a later retry.
bool VerifyWindowsRouteSnapshot(
    const WindowsRouteRowSnapshot& expected,
    const WindowsRouteRowSnapshot& actual) noexcept;
bool VerifyWindowsGatewaySnapshot(
    const WindowsGatewaySnapshotData& expected,
    const WindowsGatewaySnapshotData& actual) noexcept;

} // namespace ppp::app::client::route
