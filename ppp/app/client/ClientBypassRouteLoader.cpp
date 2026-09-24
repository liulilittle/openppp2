#include <ppp/app/client/ClientBypassRouteLoader.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/io/File.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Socket.h>
#include <ppp/net/http/HttpClient.h>

#include <algorithm>

#if defined(_WIN32)
#include <winsock2.h>
#include <iphlpapi.h>
#endif

using ppp::net::IPEndPoint;
using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {

            void ClientBypassRouteLoader::Bind(VEthernetNetworkSwitcher* owner) noexcept {
                owner_ = owner;
            }

#if defined(_ANDROID) || defined(_IPHONE)
            void ClientBypassRouteLoader::SetBypassIpList(ppp::string&& bypass_ip_list) noexcept {
                owner_->bypass_ip_list_ = std::move(bypass_ip_list);
            }
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
            bool ClientBypassRouteLoader::AddLoadIPList(
                const ppp::string& path,
#if defined(_LINUX)
                const ppp::string& nic,
#endif
                const boost::asio::ip::address& gw,
                const ppp::string& url) noexcept {

                using File = ppp::io::File;

                if (IsRouteListPathEmpty(path)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
                }

                ppp::string fullpath = File::RewritePath(path.data());
                if (fullpath.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
                }

                fullpath = File::GetFullPath(path.data());
                if (fullpath.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
                }

                bool vbgp_url = ppp::net::http::HttpClient::VerifyUri(url, NULLPTR, NULLPTR, NULLPTR, NULLPTR);
                if (!vbgp_url && !File::Exists(fullpath.data())) {
                    if (ppp::diagnostics::ErrorCode::FileNotFound == ppp::diagnostics::GetLastErrorCode()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RouteListFileNotFound);
                    }

                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigRouteLoadFailed);
                    }

                    return false;
                }

                uint32_t ngw = IPEndPoint::AnyAddress;
                if (
#if defined(_LINUX)
                    !nic.empty() &&
#endif
                    gw.is_v4() && !IPEndPoint::IsInvalid(gw)) {
                    ngw = htonl(gw.to_v4().to_uint());
                }

                auto ribs = owner_->ribs_;
                if (NULLPTR == ribs) {
                    ribs = make_shared_object<VEthernetNetworkSwitcher::LoadIPListFileVector>();
                    owner_->ribs_ = ribs;
                }

                if (NULLPTR == ribs) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                }

                auto tail = std::find_if(ribs->begin(), ribs->end(),
                    [&fullpath](const std::pair<ppp::string, uint32_t>& i) noexcept {
                        return i.first == fullpath;
                    });
                if (tail != ribs->end()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RouteListRegistrationDuplicate);
                }

                if (vbgp_url) {
                    auto vbgp = owner_->vbgp_;
                    if (NULLPTR == vbgp) {
                        vbgp = make_shared_object<VEthernetNetworkSwitcher::RouteIPListTable>();
                        if (NULLPTR == vbgp) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VbgpRouteTableAllocFailed);
                        }

                        owner_->vbgp_ = vbgp;
                    }

                    vbgp->emplace(std::make_pair(fullpath, url));
                }

#if defined(_LINUX)
                if (ngw != IPEndPoint::AnyAddress) {
                    owner_->route_coordinator_->AddNic(
                        ngw,
                        std::string(nic.begin(), nic.end()));
                }
#endif

                ribs->emplace_back(std::make_pair(fullpath, ngw));
                source_order_.emplace_back(SourceOrder{ false, ribs->size() - 1 });
                return true;
            }

            bool ClientBypassRouteLoader::AddLoadIPListText(
                const ppp::string& text,
#if defined(_LINUX)
                const ppp::string& nic,
#endif
                const boost::asio::ip::address& gw) noexcept {
                if (text.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
                }

                uint32_t ngw = IPEndPoint::AnyAddress;
                if (
#if defined(_LINUX)
                    !nic.empty() &&
#endif
                    gw.is_v4() && !IPEndPoint::IsInvalid(gw)) {
                    ngw = htonl(gw.to_v4().to_uint());
                }

#if defined(_LINUX)
                if (ngw != IPEndPoint::AnyAddress) {
                    owner_->route_coordinator_->AddNic(
                        ngw,
                        std::string(nic.begin(), nic.end()));
                }
#endif

                text_sources_.emplace_back(TextSource{ text, ngw });
                source_order_.emplace_back(SourceOrder{ true, text_sources_.size() - 1 });
                return true;
            }

            bool ClientBypassRouteLoader::LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept {
                owner_->route_coordinator_->ReplaceRib(NULLPTR);
                owner_->route_coordinator_->ReplaceFib(NULLPTR);

                auto ribs = std::move(owner_->ribs_);
                auto text_sources = std::move(text_sources_);
                auto source_order = std::move(source_order_);
                bool any = false;
                if (gw.is_v4()) {
                    boost::asio::ip::address_v4 in = gw.to_v4();
                    if (uint32_t next_hop = htonl(in.to_uint()); !IPEndPoint::IsInvalid(in)) {
                        if (NULLPTR != ribs || !text_sources.empty()) {
                            auto rib = make_shared_object<VEthernetNetworkSwitcher::RouteInformationTable>();
                            if (NULLPTR != rib) {
                                for (const SourceOrder& source : source_order) {
                                    if (source.text) {
                                        if (source.index >= text_sources.size()) {
                                            continue;
                                        }
                                        const TextSource& text = text_sources[source.index];
                                        const uint32_t ngw = text.ngw != IPEndPoint::AnyAddress ? text.ngw : next_hop;
                                        any |= rib->AddAllRoutes(text.text, ngw);
                                    }
                                    else {
                                        if (NULLPTR == ribs || source.index >= ribs->size()) {
                                            continue;
                                        }
                                        const auto& file = (*ribs)[source.index];
                                        const uint32_t ngw = file.second != IPEndPoint::AnyAddress ? file.second : next_hop;
                                        any |= rib->AddAllRoutesByIPList(file.first, ngw);
                                    }
                                }

                                if (any) {
                                    owner_->route_coordinator_->ReplaceRib(rib);
                                    ppp::telemetry::Log(Level::kDebug, "client", "bypass list updated");
                                }
                            }
                        }
                    }
                }

                owner_->ribs_.reset();
                text_sources_.clear();
                source_order_.clear();
                return any;
            }
#endif

            bool ClientBypassRouteLoader::IsBypassIpAddress(const boost::asio::ip::address& ip) noexcept {
                if (RejectsBypassBeforeTapLookup(ip)) {
                    return false;
                }

                if (IPEndPoint::IsInvalid(ip)) {
                    return false;
                }

                auto tap = owner_->GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                uint32_t nip = htonl(ip.to_v4().to_uint());
                if (owner_->ProxyOnly(NULLPTR)) {
                    auto fib = owner_->GetFib();
                    if (NULLPTR == fib) {
                        return false;
                    }

                    const uint32_t ngw = fib->GetNextHop(nip);
                    return ngw != IPEndPoint::NoneAddress && ngw != tap->GatewayServer;
                }

#if defined(_ANDROID) || defined(_IPHONE)
                if (auto fib = owner_->GetFib(); NULLPTR != fib) {
                    uint32_t ngw = fib->GetNextHop(nip);
                    return ngw != IPEndPoint::NoneAddress && ngw != tap->GatewayServer;
                }

                return false;
#elif defined(_WIN32)
                DWORD dwInterfaceIndex;
                if (!::GetBestInterface((IPAddr)nip, &dwInterfaceIndex)) {
                    return false;
                }

                return dwInterfaceIndex != (DWORD)tap->GetInterfaceIndex();
#else
                return ppp::net::Socket::GetBestInterfaceIP(nip) != tap->IPAddress;
#endif
            }

        }
    }
}
