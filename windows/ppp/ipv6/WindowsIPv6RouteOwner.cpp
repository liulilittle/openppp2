#include <windows/ppp/ipv6/WindowsIPv6RouteOwner.h>

#include <ppp/diagnostics/Telemetry.h>
#include <ppp/diagnostics/TelemetryFwd.h>

#include <algorithm>
#include <cstring>

namespace ppp::win32::ipv6 {

    namespace {
        bool IsUnsafeExternalAddress(const boost::asio::ip::address_v6& address) noexcept {
            return address.is_unspecified() || address.is_multicast() ||
                address.is_loopback() || address.is_link_local();
        }
    }

    NETIO_STATUS WindowsIPv6RouteApi::GetBestRoute2(
        const NET_LUID* interface_luid,
        NET_IFINDEX interface_index,
        const SOCKADDR_INET* destination,
        MIB_IPFORWARD_ROW2* best_route,
        SOCKADDR_INET* best_source) noexcept {
        NET_LUID mutable_luid{};
        NET_LUID* mutable_luid_ptr = nullptr;
        if (interface_luid != nullptr) {
            mutable_luid = *interface_luid;
            mutable_luid_ptr = &mutable_luid;
        }
        return ::GetBestRoute2(mutable_luid_ptr, interface_index, nullptr,
            destination, 0, best_route, best_source);
    }

    NETIO_STATUS WindowsIPv6RouteApi::GetIpForwardEntry2(MIB_IPFORWARD_ROW2* row) noexcept {
        return ::GetIpForwardEntry2(row);
    }

    NETIO_STATUS WindowsIPv6RouteApi::CreateIpForwardEntry2(
        const MIB_IPFORWARD_ROW2* row) noexcept {
        return ::CreateIpForwardEntry2(row);
    }

    NETIO_STATUS WindowsIPv6RouteApi::DeleteIpForwardEntry2(
        const MIB_IPFORWARD_ROW2* row) noexcept {
        return ::DeleteIpForwardEntry2(row);
    }

    NETIO_STATUS WindowsIPv6RouteApi::GetIfEntry2(MIB_IF_ROW2* row) noexcept {
        return ::GetIfEntry2(row);
    }

    WindowsIPv6RouteOwner::WindowsIPv6RouteOwner(
        std::unique_ptr<IWindowsIPv6RouteApi> api) noexcept
        : api_(api ? std::move(api) : std::make_unique<WindowsIPv6RouteApi>())
        , transaction_(*this) {
    }

    WindowsIPv6RouteOwner::~WindowsIPv6RouteOwner() noexcept {
        Stop();
    }

    void WindowsIPv6RouteOwner::Diagnostic(
        const char* action,
        const char* detail) const noexcept {
        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "windows_ipv6_route",
            "route-only best-effort IPv6 %s: %s", action, detail);
    }

    bool WindowsIPv6RouteOwner::BindInterfaces(
        int tap_interface_index,
        int physical_interface_index) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tap_interface_index < 0 || physical_interface_index < 0 ||
            tap_interface_index == physical_interface_index) {
            Diagnostic("bind skipped", "invalid or identical interface index");
            return false;
        }

        MIB_IF_ROW2 tap{};
        tap.InterfaceIndex = static_cast<NET_IFINDEX>(tap_interface_index);
        MIB_IF_ROW2 physical{};
        physical.InterfaceIndex = static_cast<NET_IFINDEX>(physical_interface_index);
        if (api_->GetIfEntry2(&tap) != NO_ERROR ||
            api_->GetIfEntry2(&physical) != NO_ERROR ||
            tap.InterfaceLuid.Value == 0 || physical.InterfaceLuid.Value == 0 ||
            tap.InterfaceLuid.Value == physical.InterfaceLuid.Value ||
            physical.Type == IF_TYPE_SOFTWARE_LOOPBACK) {
            Diagnostic("bind failed", "stable TAP/physical identity unavailable");
            return false;
        }

        tap_interface_ = tap;
        physical_interface_ = physical;
        bound_ = true;
        Diagnostic("bound", "retained TAP and physical LUID/index identities");
        return true;
    }

    WindowsIPv6RouteOwner::RouteIdentity WindowsIPv6RouteOwner::ToIdentity(
        const MIB_IPFORWARD_ROW2& row,
        RouteKind kind) noexcept {
        RouteIdentity identity;
        identity.Kind = kind;
        if (row.DestinationPrefix.Prefix.si_family == AF_INET6) {
            std::memcpy(identity.Destination.data(),
                &row.DestinationPrefix.Prefix.Ipv6.sin6_addr,
                identity.Destination.size());
        }
        identity.PrefixLength = row.DestinationPrefix.PrefixLength;
        identity.InterfaceLuid = row.InterfaceLuid.Value;
        identity.InterfaceIndex = row.InterfaceIndex;
        if (row.NextHop.si_family == AF_INET6) {
            std::memcpy(identity.NextHop.data(), &row.NextHop.Ipv6.sin6_addr,
                identity.NextHop.size());
            identity.NextHopScopeId = row.NextHop.Ipv6.sin6_scope_id;
        }
        identity.Metric = row.Metric;
        identity.Protocol = static_cast<std::uint32_t>(row.Protocol);
        identity.Origin = static_cast<std::uint32_t>(row.Origin);
        identity.SitePrefixLength = row.SitePrefixLength;
        identity.Loopback = row.Loopback == TRUE;
        identity.AutoconfigureAddress = row.AutoconfigureAddress == TRUE;
        identity.Publish = row.Publish == TRUE;
        identity.Immortal = row.Immortal == TRUE;
        return identity;
    }

    MIB_IPFORWARD_ROW2 WindowsIPv6RouteOwner::ToRow(
        const RouteIdentity& route) noexcept {
        MIB_IPFORWARD_ROW2 row;
        ::InitializeIpForwardEntry(&row);
        row.InterfaceLuid.Value = route.InterfaceLuid;
        row.InterfaceIndex = route.InterfaceIndex;
        row.DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
        std::memcpy(&row.DestinationPrefix.Prefix.Ipv6.sin6_addr,
            route.Destination.data(), route.Destination.size());
        row.DestinationPrefix.PrefixLength = route.PrefixLength;
        row.NextHop.Ipv6.sin6_family = AF_INET6;
        std::memcpy(&row.NextHop.Ipv6.sin6_addr,
            route.NextHop.data(), route.NextHop.size());
        row.NextHop.Ipv6.sin6_scope_id = route.NextHopScopeId;
        row.Metric = route.Metric;
        row.Protocol = static_cast<NL_ROUTE_PROTOCOL>(route.Protocol);
        row.Origin = static_cast<NL_ROUTE_ORIGIN>(route.Origin);
        row.SitePrefixLength = route.SitePrefixLength;
        row.Loopback = route.Loopback ? TRUE : FALSE;
        row.AutoconfigureAddress = route.AutoconfigureAddress ? TRUE : FALSE;
        row.Publish = route.Publish ? TRUE : FALSE;
        row.Immortal = route.Immortal ? TRUE : FALSE;
        row.ValidLifetime = 0xffffffffUL;
        row.PreferredLifetime = 0xffffffffUL;
        return row;
    }

    bool WindowsIPv6RouteOwner::IsExactRouteRowMatch(
        const MIB_IPFORWARD_ROW2& existing,
        const MIB_IPFORWARD_ROW2& expected,
        RouteKind kind) noexcept {
        if (existing.DestinationPrefix.Prefix.si_family != AF_INET6 ||
            expected.DestinationPrefix.Prefix.si_family != AF_INET6 ||
            existing.NextHop.si_family != AF_INET6 ||
            expected.NextHop.si_family != AF_INET6) {
            return false;
        }
        return ppp::ipv6::route_transaction::IsExactRouteMatch(
            ToIdentity(existing, kind), ToIdentity(expected, kind));
    }

    WindowsIPv6RouteOwner::OwnershipMutation WindowsIPv6RouteOwner::Create(
        const RouteIdentity& route) noexcept {
        MIB_IPFORWARD_ROW2 expected = ToRow(route);
        const NETIO_STATUS status = api_->CreateIpForwardEntry2(&expected);
        if (status == NO_ERROR) {
            RouteRecord record;
            record.Row = expected;
            record.Created = true;
            records_.emplace_back(record);
            return OwnershipMutation::Changed;
        }
        if (status != ERROR_OBJECT_ALREADY_EXISTS) {
            Diagnostic("create failed", "IP Helper route create returned an error");
            return OwnershipMutation::Failed;
        }

        MIB_IPFORWARD_ROW2 existing = expected;
        if (api_->GetIpForwardEntry2(&existing) != NO_ERROR ||
            !IsExactRouteRowMatch(existing, expected, route.Kind)) {
            Diagnostic("create conflict", "pre-existing route was not exact-equivalent");
            return OwnershipMutation::Failed;
        }
        return OwnershipMutation::Unchanged;
    }

    bool WindowsIPv6RouteOwner::RevalidateInterface(
        const MIB_IPFORWARD_ROW2& row) noexcept {
        MIB_IF_ROW2 current{};
        current.InterfaceIndex = row.InterfaceIndex;
        return api_->GetIfEntry2(&current) == NO_ERROR &&
            current.InterfaceIndex == row.InterfaceIndex &&
            current.InterfaceLuid.Value == row.InterfaceLuid.Value;
    }

    bool WindowsIPv6RouteOwner::Delete(const RouteIdentity& route) noexcept {
        auto record = std::find_if(records_.begin(), records_.end(),
            [&route](const RouteRecord& candidate) noexcept {
                return candidate.Created &&
                    ppp::ipv6::route_transaction::IsExactRouteMatch(
                        ToIdentity(candidate.Row, route.Kind), route);
            });
        if (record == records_.end()) {
            Diagnostic("cleanup pending", "owned route record was unavailable");
            return false;
        }
        if (!RevalidateInterface(record->Row)) {
            record->CleanupPending = true;
            Diagnostic("cleanup pending", "interface LUID/index changed");
            return false;
        }

        MIB_IPFORWARD_ROW2 existing = record->Row;
        const NETIO_STATUS query_status = api_->GetIpForwardEntry2(&existing);
        if (query_status == ERROR_NOT_FOUND) {
            records_.erase(record);
            return true;
        }
        if (query_status != NO_ERROR ||
            !IsExactRouteRowMatch(existing, record->Row, route.Kind)) {
            record->CleanupPending = true;
            Diagnostic("cleanup refused", "exact route revalidation failed");
            return false;
        }

        const NETIO_STATUS delete_status = api_->DeleteIpForwardEntry2(&existing);
        if (delete_status == NO_ERROR || delete_status == ERROR_NOT_FOUND) {
            records_.erase(record);
            return true;
        }
        record->CleanupPending = true;
        Diagnostic("cleanup pending", "IP Helper exact route delete failed");
        return false;
    }

    bool WindowsIPv6RouteOwner::StageEgressEndpoint(
        const boost::asio::ip::tcp::endpoint& endpoint,
        bool proven_external) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!bound_) {
            Diagnostic("egress stage skipped", "owner is not bound");
            return false;
        }
        if (!proven_external || endpoint.address().is_unspecified() ||
            endpoint.address().is_multicast() || endpoint.address().is_loopback()) {
            transaction_.RollbackStagedPin();
            Diagnostic("egress rejected", "candidate is not a proven external endpoint");
            return false;
        }
        if (endpoint.address().is_v4()) {
            return transaction_.StageNoPin();
        }
        if (!endpoint.address().is_v6() ||
            IsUnsafeExternalAddress(endpoint.address().to_v6())) {
            transaction_.RollbackStagedPin();
            Diagnostic("egress rejected", "unsafe IPv6 endpoint category");
            return false;
        }

        SOCKADDR_INET destination{};
        destination.Ipv6.sin6_family = AF_INET6;
        const auto bytes = endpoint.address().to_v6().to_bytes();
        std::memcpy(&destination.Ipv6.sin6_addr, bytes.data(), bytes.size());
        destination.Ipv6.sin6_scope_id =
            static_cast<ULONG>(endpoint.address().to_v6().scope_id());

        MIB_IPFORWARD_ROW2 best_route;
        SOCKADDR_INET best_source{};
        if (api_->GetBestRoute2(&physical_interface_.InterfaceLuid,
                physical_interface_.InterfaceIndex, &destination,
                &best_route, &best_source) != NO_ERROR ||
            best_route.InterfaceLuid.Value != physical_interface_.InterfaceLuid.Value ||
            best_route.InterfaceIndex != physical_interface_.InterfaceIndex ||
            best_route.InterfaceLuid.Value == tap_interface_.InterfaceLuid.Value) {
            transaction_.RollbackStagedPin();
            Diagnostic("egress rejected", "constrained physical GetBestRoute2 failed");
            return false;
        }

        best_route.DestinationPrefix.Prefix = destination;
        best_route.DestinationPrefix.PrefixLength = 128;
        best_route.Protocol = MIB_IPPROTO_NETMGMT;
        best_route.Origin = NlroManual;
        best_route.Loopback = FALSE;
        best_route.AutoconfigureAddress = FALSE;
        best_route.Publish = FALSE;
        best_route.Immortal = TRUE;
        const RouteIdentity pin = ToIdentity(best_route, RouteKind::EgressPin);
        if (!transaction_.StagePin(pin)) {
            Diagnostic("egress stage failed", "physical /128 pin could not be owned or verified");
            return false;
        }
        return true;
    }

    bool WindowsIPv6RouteOwner::BuildPair(
        const boost::asio::ip::address_v6* gateway,
        RouteIdentity& lower,
        RouteIdentity& upper) const noexcept {
        if (!bound_) {
            return false;
        }
        lower.Kind = RouteKind::LowerHalf;
        lower.PrefixLength = 1;
        lower.InterfaceLuid = tap_interface_.InterfaceLuid.Value;
        lower.InterfaceIndex = tap_interface_.InterfaceIndex;
        lower.Protocol = static_cast<std::uint32_t>(MIB_IPPROTO_NETMGMT);
        lower.Origin = static_cast<std::uint32_t>(NlroManual);
        lower.Immortal = true;
        upper = lower;
        upper.Kind = RouteKind::UpperHalf;
        upper.Destination[0] = 0x80;

        if (gateway != nullptr) {
            if (gateway->is_unspecified() || gateway->is_multicast() || gateway->is_loopback()) {
                return false;
            }
            lower.NextHop = gateway->to_bytes();
            lower.NextHopScopeId = static_cast<std::uint32_t>(gateway->scope_id());
            if (gateway->is_link_local() && lower.NextHopScopeId == 0) {
                lower.NextHopScopeId = tap_interface_.InterfaceIndex;
            }
            upper.NextHop = lower.NextHop;
            upper.NextHopScopeId = lower.NextHopScopeId;
        }
        return true;
    }

    bool WindowsIPv6RouteOwner::EnsureSinkMode() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!transaction_.HasEgress()) {
            Diagnostic("sink skipped", "no proven external egress is staged or committed");
            return false;
        }

        RouteIdentity lower;
        RouteIdentity upper;
        if (!BuildPair(nullptr, lower, upper) ||
            !transaction_.EnsureSinkMode(lower, upper)) {
            Diagnostic("sink failed", "split TAP takeover pair unavailable");
            return false;
        }
        return true;
    }

    bool WindowsIPv6RouteOwner::ActivateManagedMode(
        const boost::asio::ip::address& gateway,
        bool nat_mode) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (transaction_.Mode() == ppp::ipv6::route_transaction::PairMode::None ||
            !transaction_.HasEgress()) {
            Diagnostic("managed activation skipped", "route-only sink is not active");
            return false;
        }

        RouteIdentity lower;
        RouteIdentity upper;
        boost::asio::ip::address_v6 gateway_v6;
        const boost::asio::ip::address_v6* next_hop = nullptr;
        if (!nat_mode) {
            if (!gateway.is_v6()) {
                Diagnostic("managed activation failed", "GUA gateway is missing");
                return false;
            }
            gateway_v6 = gateway.to_v6();
            next_hop = &gateway_v6;
        }
        if (!BuildPair(next_hop, lower, upper) ||
            !transaction_.ActivateManagedMode(lower, upper)) {
            Diagnostic("managed activation failed", "target split pair unavailable");
            return false;
        }
        return true;
    }

    bool WindowsIPv6RouteOwner::CommitStagedPin() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!transaction_.HasStagedPin()) {
            return true;
        }
        const bool result = transaction_.CommitStagedPin();
        if (!result) {
            Diagnostic("pin commit pending", "retired pin cleanup requires retry");
        }
        return result;
    }

    bool WindowsIPv6RouteOwner::RollbackStagedPin() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        const bool result = transaction_.RollbackStagedPin();
        if (!result) {
            Diagnostic("pin rollback pending", "staged pin cleanup requires retry");
        }
        return result;
    }

    bool WindowsIPv6RouteOwner::Stop() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        const bool result = transaction_.Stop();
        if (!result || !records_.empty()) {
            Diagnostic("stop incomplete", "exact owned route cleanup remains pending");
            return false;
        }
        bound_ = false;
        tap_interface_ = MIB_IF_ROW2{};
        physical_interface_ = MIB_IF_ROW2{};
        return true;
    }

    bool WindowsIPv6RouteOwner::HasActiveTakeover() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return transaction_.Mode() != ppp::ipv6::route_transaction::PairMode::None;
    }

    bool WindowsIPv6RouteOwner::HasPendingCleanup() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return transaction_.HasPendingCleanup() || !records_.empty();
    }
}
