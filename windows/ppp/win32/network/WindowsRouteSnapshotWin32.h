#pragma once

#include <ppp/app/client/route/WindowsRouteSnapshot.h>

 #if defined(_WIN32)
 #include <Windows.h>
 #include <Iphlpapi.h>

namespace ppp::app::client::route {

WindowsRouteRowSnapshot CaptureWindowsRouteRowSnapshot(
    const MIB_IPFORWARDROW& row) noexcept;
WindowsGatewaySnapshotData CaptureWindowsGatewaySnapshotData(
    std::uint32_t interface_index,
    const std::string& gateway) noexcept;

bool VerifyWindowsRouteSnapshot(
    const MIB_IPFORWARDROW& actual,
    const WindowsRouteRowSnapshot& expected) noexcept;

enum class WindowsRouteSnapshotLiveStatus : std::uint8_t {
    Unavailable,
    Missing,
    Match,
    Conflict,
};

WindowsRouteSnapshotLiveStatus VerifyWindowsRouteSnapshotLive(
    const WindowsRouteRowSnapshot& expected) noexcept;
WindowsRouteSnapshotLiveStatus VerifyWindowsGatewaySnapshotLive(
    const WindowsGatewaySnapshotData& expected) noexcept;

} // namespace ppp::app::client::route

#endif // defined(_WIN32)
