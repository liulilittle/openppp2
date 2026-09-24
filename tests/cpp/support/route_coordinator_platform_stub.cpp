#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/io/File.h>
#include <ppp/net/native/rib.h>

namespace ppp {

bool SetThreadName(const char*) noexcept {
    return true;
}

uint64_t GetTickCount() noexcept {
    const auto now = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count());
}

void Sleep(int milliseconds) noexcept {
    if (milliseconds > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    }
}

}

namespace ppp::io {

ppp::string File::RewritePath(const char* path) noexcept {
    return path == nullptr ? ppp::string() : ppp::string(path);
}

ppp::string File::GetFullPath(const char* path) noexcept {
    return path == nullptr ? ppp::string() : ppp::string(path);
}

bool File::Exists(const char*) noexcept {
    return false;
}

}

namespace ppp::net::native {

RouteEntriesTable& RouteInformationTable::GetAllRoutes() noexcept {
    return routes;
}

bool RouteInformationTable::AddRoute(uint32_t, int, uint32_t) noexcept {
    return true;
}

bool RouteInformationTable::AddAllRoutes(const ppp::string&, uint32_t) noexcept {
    return true;
}

bool RouteInformationTable::AddAllRoutesByIPList(
    const ppp::string&, uint32_t) noexcept {
    return true;
}

}

namespace ppp::app::client::route {

namespace {

class StubRoutePlatform final : public IRoutePlatform {
public:
    DefaultRouteCapture CaptureDefaults() noexcept override {
        return std::vector<RouteSnapshotPtr>();
    }
    bool RemoveDefault(const RouteSnapshotPtr&) noexcept override { return true; }
    RouteAddResult Add(const RouteSpec&) noexcept override {
        return RouteAddResult::Created;
    }
    bool Delete(const RouteSpec&) noexcept override { return true; }
    bool RestoreDefault(const RouteSnapshotPtr&) noexcept override { return true; }
    bool SameDefault(const RouteSnapshotPtr& left,
        const RouteSnapshotPtr& right) noexcept override {
        return left == right;
    }
};

}

std::unique_ptr<IRoutePlatform> RouteCoordinator::NewPlatform(
    const RoutePlanInput&) noexcept {
    return std::make_unique<StubRoutePlatform>();
}

}
