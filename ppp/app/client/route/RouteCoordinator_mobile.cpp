#include <ppp/stdafx.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/route/MobileRoutePlatform.h>
#include <ppp/app/client/route/RouteSpecs.h>
#include <ppp/app/client/route/RouteState.h>
#include <ppp/app/client/routing/HumanRoutingRouteSpecs.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/io/File.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>

#if defined(_ANDROID) || defined(_IPHONE) || defined(OPENPPP2_ROUTE_TEST_MOBILE)

#if defined(_ANDROID)
#include <android/log.h>

static bool AndroidDnsRedirectTraceEnabled() noexcept {
#ifdef NDEBUG
    return false;
#else
    return true;
#endif
}

#define ANDROID_DNS_REDIRECT_TRACE(...) \
    do { \
        if (AndroidDnsRedirectTraceEnabled()) { \
            __android_log_print(ANDROID_LOG_INFO, "openppp2", __VA_ARGS__); \
        } \
    } while (0)
#endif

using ppp::net::IPEndPoint;
using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {

            bool route::RouteCoordinator::AddAllRoute(const route::RoutePlanInput& input) noexcept {
                using RouteInformationTable = ppp::net::native::RouteInformationTable;
                using RouteInformationTablePtr = std::shared_ptr<RouteInformationTable>;

                std::lock_guard<std::mutex> operation_lock(operation_mutex_);
                if (stopped_.load(std::memory_order_acquire)) {
                    return false;
                }

                RouteInformationTablePtr rib = make_shared_object<RouteInformationTable>();
                if (NULLPTR == rib)  {
                    return false;
                }

                uint32_t cidr = ntohl(input.tap_submask);
                cidr = cidr & ntohl(input.tap_ip);
                cidr = htonl(cidr);

                if (!input.bypass_ip_list.empty()) {
                    const ppp::string bypass_ip_list(input.bypass_ip_list.begin(), input.bypass_ip_list.end());
                    bool bypass_loaded = rib->AddAllRoutes(bypass_ip_list, IPEndPoint::LoopbackAddress);
#if defined(_ANDROID)
                    ANDROID_DNS_REDIRECT_TRACE("bypass_ip_list load len=%d ok=%d",
                        (int)bypass_ip_list.size(), bypass_loaded ? 1 : 0);
#endif
                    ppp::telemetry::Log(Level::kDebug, "client", "bypass list updated");
                }

                // Static client route sources are native policy routes on mobile.
                // They are intentionally kept in the in-process RIB/FIB; this
                // path never calls the platform route installer.
                for (const route::RouteSource& source : input.route_sources) {
                    ppp::string path(source.path.begin(), source.path.end());
                    path = ppp::LTrim(ppp::RTrim(path));
                    if (path.size() >= 7 &&
                        ppp::ToLower<ppp::string>(path.substr(0, 7)) == "file://") {
                        path = ppp::LTrim(ppp::RTrim(path.substr(7)));
                    }
                    if (path.empty()) {
                        continue;
                    }

                    ppp::string rewritten = ppp::io::File::RewritePath(path.data());
                    ppp::string fullpath = ppp::io::File::GetFullPath(rewritten.data());
                    if (fullpath.empty() || !ppp::io::File::Exists(fullpath.data())) {
                        ppp::telemetry::Log(Level::kDebug, "client",
                            "mobile route source unavailable: %s", path.data());
                        continue;
                    }

                    const uint32_t gateway = source.gateway != IPEndPoint::AnyAddress
                        ? source.gateway : input.tap_gateway;
                    if (gateway == IPEndPoint::AnyAddress ||
                        gateway == IPEndPoint::NoneAddress) {
                        continue;
                    }
                    rib->AddAllRoutesByIPList(fullpath, gateway);
                }

                route::MobileRoutePlan plan;
                plan.tap_network = cidr;
                plan.tap_prefix = IPEndPoint::NetmaskToPrefix(input.tap_submask);
                plan.tap_gateway = input.tap_gateway;
                plan.loopback_gateway = IPEndPoint::LoopbackAddress;
                plan.tunnel_dns = input.tunnel_dns;
                plan.underlying_dns = input.underlying_dns;

                const routing::HumanRoutingRouteSpecPlan human_plan =
                    routing::BuildHumanRoutingRouteSpecs(
                        input,
                        routing::HumanRoutingRouteEnvironment::Mobile);
                if (human_plan.invalid_count != 0) {
                    return false;
                }
                const std::vector<route::RouteSpec> specs = route::MergeRouteSpecs(
                    route::BuildRouteSpecs(rib),
                    human_plan.routes,
                    route::BuildMobileRouteSpecs(plan));
                route::MobileRoutePlatform platform(
                    [rib](const route::RouteSpec& spec) noexcept {
                        return rib->AddRoute(spec.network, spec.prefix, spec.gateway);
                    });
                if (!platform.ApplyAll(specs)) {
                    return false;
                }
                state_.ReplaceRib(std::move(rib));
                state_.MarkApplied(true);
                return true;
            }

        }
    }
}

#endif
