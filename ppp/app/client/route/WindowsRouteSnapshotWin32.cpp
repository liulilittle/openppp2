#include <ppp/stdafx.h>
#include <windows/ppp/win32/network/WindowsRouteSnapshotWin32.h>

#if defined(_WIN32)

#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/win32/network/Router.h>

namespace ppp::app::client::route {
namespace {

void FillInterfaceIdentity(
    std::uint32_t interface_index,
    std::string& luid,
    std::string& guid) noexcept {
    auto adapter = ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(
        static_cast<int>(interface_index));
    if (!adapter) {
        return;
    }
    luid = adapter->InterfaceLuid;
    guid = adapter->Guid;
}

bool SameWindowsRouteIdentity(
    const MIB_IPFORWARDROW& row,
    const WindowsRouteRowSnapshot& expected) noexcept {
    return row.dwForwardDest == expected.destination &&
        row.dwForwardMask == expected.mask &&
        row.dwForwardPolicy == expected.policy &&
        row.dwForwardNextHop == expected.next_hop &&
        row.dwForwardIfIndex == expected.interface_index;
}

} // namespace

WindowsRouteRowSnapshot CaptureWindowsRouteRowSnapshot(
    const MIB_IPFORWARDROW& row) noexcept {
    WindowsRouteRowSnapshot snapshot;
    snapshot.destination = row.dwForwardDest;
    snapshot.mask = row.dwForwardMask;
    snapshot.policy = row.dwForwardPolicy;
    snapshot.next_hop = row.dwForwardNextHop;
    snapshot.interface_index = row.dwForwardIfIndex;
    snapshot.type = row.dwForwardType;
    snapshot.proto = row.dwForwardProto;
    snapshot.age = row.dwForwardAge;
    snapshot.next_hop_as = row.dwForwardNextHopAS;
    snapshot.metric1 = row.dwForwardMetric1;
    snapshot.metric2 = row.dwForwardMetric2;
    snapshot.metric3 = row.dwForwardMetric3;
    snapshot.metric4 = row.dwForwardMetric4;
    snapshot.metric5 = row.dwForwardMetric5;
    FillInterfaceIdentity(
        snapshot.interface_index,
        snapshot.interface_luid,
        snapshot.interface_guid);
    return snapshot;
}

WindowsGatewaySnapshotData CaptureWindowsGatewaySnapshotData(
    std::uint32_t interface_index,
    const std::string& gateway) noexcept {
    WindowsGatewaySnapshotData snapshot;
    snapshot.interface_index = interface_index;
    snapshot.gateway = gateway;
    FillInterfaceIdentity(
        snapshot.interface_index,
        snapshot.interface_luid,
        snapshot.interface_guid);
    return snapshot;
}

bool VerifyWindowsRouteSnapshot(
    const MIB_IPFORWARDROW& actual,
    const WindowsRouteRowSnapshot& expected) noexcept {
    return VerifyWindowsRouteSnapshot(
        expected, CaptureWindowsRouteRowSnapshot(actual));
}

WindowsRouteSnapshotLiveStatus VerifyWindowsRouteSnapshotLive(
    const WindowsRouteRowSnapshot& expected) noexcept {
    auto table = ppp::win32::network::Router::GetIpForwardTable();
    if (!table) {
        return WindowsRouteSnapshotLiveStatus::Unavailable;
    }

    bool identity_found = false;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_IPFORWARDROW& row = table->table[i];
        if (!SameWindowsRouteIdentity(row, expected)) {
            continue;
        }
        identity_found = true;
        if (VerifyWindowsRouteSnapshot(row, expected)) {
            return WindowsRouteSnapshotLiveStatus::Match;
        }
    }
    return identity_found
        ? WindowsRouteSnapshotLiveStatus::Conflict
        : WindowsRouteSnapshotLiveStatus::Missing;
}

WindowsRouteSnapshotLiveStatus VerifyWindowsGatewaySnapshotLive(
    const WindowsGatewaySnapshotData& expected) noexcept {
    auto adapter = ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(
        static_cast<int>(expected.interface_index));
    if (!adapter) {
        return WindowsRouteSnapshotLiveStatus::Missing;
    }

    WindowsGatewaySnapshotData actual;
    actual.interface_index = static_cast<std::uint32_t>(adapter->InterfaceIndex);
    actual.interface_luid = adapter->InterfaceLuid;
    actual.interface_guid = adapter->Guid;
    // The gateway snapshot identifies one gateway.  Report Match when that
    // exact value is still present and Conflict when the adapter changed.
    for (const ppp::string& gateway : adapter->DefaultIPGateway) {
        if (_stricmp(gateway.data(), expected.gateway.data()) == 0) {
            actual.gateway = gateway;
            if (VerifyWindowsGatewaySnapshot(expected, actual)) {
                return WindowsRouteSnapshotLiveStatus::Match;
            }
            return WindowsRouteSnapshotLiveStatus::Conflict;
        }
    }
    return WindowsRouteSnapshotLiveStatus::Conflict;
}

} // namespace ppp::app::client::route

#endif // defined(_WIN32)
