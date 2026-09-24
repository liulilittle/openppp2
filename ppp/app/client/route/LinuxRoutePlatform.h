#pragma once

#include <functional>
#include <string>
#include <unordered_map>

#include <ppp/app/client/route/IRoutePlatform.h>
#include <ppp/app/client/route/RouteState.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace route {

                struct LinuxRouteOperations final {
                    std::function<bool(
                        uint32_t gateway,
                        RouteInformationTablePtr& routes)> capture_defaults;
                    std::function<RouteAddResult(const RouteSpec& route)> add;
                    std::function<bool(const RouteSpec& route)> remove;
                };

                std::string SelectLinuxInterface(
                    uint32_t next_hop,
                    uint32_t tap_gateway,
                    const std::string& tap_interface,
                    const std::string& underlying_interface,
                    const std::unordered_map<uint32_t, std::string>& nics) noexcept;

                class LinuxRoutePlatform final : public IRoutePlatform {
                public:
                    LinuxRoutePlatform(
                        uint32_t tap_gateway,
                        std::string tap_interface,
                        std::string underlying_interface,
                        std::unordered_map<uint32_t, std::string> nics,
                        bool promiscuous) noexcept;

                    LinuxRoutePlatform(
                        uint32_t tap_gateway,
                        std::string tap_interface,
                        std::string underlying_interface,
                        std::unordered_map<uint32_t, std::string> nics,
                        bool promiscuous,
                        LinuxRouteOperations operations) noexcept;

                    DefaultRouteCapture CaptureDefaults() noexcept override;
                    bool RemoveDefault(const RouteSnapshotPtr& route) noexcept override;
                    RouteAddResult Add(const RouteSpec& route) noexcept override;
                    bool Delete(const RouteSpec& route) noexcept override;
                    bool RestoreDefault(const RouteSnapshotPtr& route) noexcept override;
                    bool SameDefault(
                        const RouteSnapshotPtr& left,
                        const RouteSnapshotPtr& right) noexcept override;

                private:
                    static LinuxRouteOperations CreateSystemOperations() noexcept;
                    RouteSpec Resolve(RouteSpec route) const noexcept;

                    uint32_t tap_gateway_ = 0;
                    std::string tap_interface_;
                    std::string underlying_interface_;
                    std::unordered_map<uint32_t, std::string> nics_;
                    bool promiscuous_ = false;
                    LinuxRouteOperations operations_;
                };

            }
        }
    }
}
