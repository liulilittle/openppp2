#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <netioapi.h>
#include <iphlpapi.h>

#include <ppp/ipv6/IPv6RouteTransaction.h>

#include <boost/asio/ip/tcp.hpp>

#include <memory>
#include <mutex>
#include <vector>

namespace ppp::win32::ipv6 {

    class IWindowsIPv6RouteApi {
    public:
        virtual ~IWindowsIPv6RouteApi() noexcept = default;
        virtual NETIO_STATUS GetBestRoute2(
            const NET_LUID* interface_luid,
            NET_IFINDEX interface_index,
            const SOCKADDR_INET* destination,
            MIB_IPFORWARD_ROW2* best_route,
            SOCKADDR_INET* best_source) noexcept = 0;
        virtual NETIO_STATUS GetIpForwardEntry2(MIB_IPFORWARD_ROW2* row) noexcept = 0;
        virtual NETIO_STATUS CreateIpForwardEntry2(const MIB_IPFORWARD_ROW2* row) noexcept = 0;
        virtual NETIO_STATUS DeleteIpForwardEntry2(const MIB_IPFORWARD_ROW2* row) noexcept = 0;
        virtual NETIO_STATUS GetIfEntry2(MIB_IF_ROW2* row) noexcept = 0;
    };

    class WindowsIPv6RouteApi final : public IWindowsIPv6RouteApi {
    public:
        NETIO_STATUS GetBestRoute2(
            const NET_LUID* interface_luid,
            NET_IFINDEX interface_index,
            const SOCKADDR_INET* destination,
            MIB_IPFORWARD_ROW2* best_route,
            SOCKADDR_INET* best_source) noexcept override;
        NETIO_STATUS GetIpForwardEntry2(MIB_IPFORWARD_ROW2* row) noexcept override;
        NETIO_STATUS CreateIpForwardEntry2(const MIB_IPFORWARD_ROW2* row) noexcept override;
        NETIO_STATUS DeleteIpForwardEntry2(const MIB_IPFORWARD_ROW2* row) noexcept override;
        NETIO_STATUS GetIfEntry2(MIB_IF_ROW2* row) noexcept override;
    };

    class WindowsIPv6RouteOwner final : private ppp::ipv6::route_transaction::IRouteMutator {
    public:
        struct RouteRecord {
            MIB_IPFORWARD_ROW2 Row{};
            bool Created = false;
            bool CleanupPending = false;
        };

        explicit WindowsIPv6RouteOwner(
            std::unique_ptr<IWindowsIPv6RouteApi> api = nullptr) noexcept;
        ~WindowsIPv6RouteOwner() noexcept;

        bool BindInterfaces(int tap_interface_index, int physical_interface_index) noexcept;
        bool StageEgressEndpoint(
            const boost::asio::ip::tcp::endpoint& endpoint,
            bool proven_external) noexcept;
        bool EnsureSinkMode() noexcept;
        bool ActivateManagedMode(
            const boost::asio::ip::address& gateway,
            bool nat_mode) noexcept;
        bool CommitStagedPin() noexcept;
        bool RollbackStagedPin() noexcept;
        bool Stop() noexcept;
        bool HasActiveTakeover() const noexcept;
        bool HasPendingCleanup() const noexcept;

    private:
        using OwnershipMutation = ppp::ipv6::client_policy::OwnershipMutation;
        using RouteIdentity = ppp::ipv6::route_transaction::RouteIdentity;
        using RouteKind = ppp::ipv6::route_transaction::RouteKind;

        OwnershipMutation Create(const RouteIdentity& route) noexcept override;
        bool Delete(const RouteIdentity& route) noexcept override;

        bool BuildPair(
            const boost::asio::ip::address_v6* gateway,
            RouteIdentity& lower,
            RouteIdentity& upper) const noexcept;
        static MIB_IPFORWARD_ROW2 ToRow(const RouteIdentity& route) noexcept;
        static RouteIdentity ToIdentity(
            const MIB_IPFORWARD_ROW2& row,
            RouteKind kind) noexcept;
        static bool IsExactRouteRowMatch(
            const MIB_IPFORWARD_ROW2& existing,
            const MIB_IPFORWARD_ROW2& expected,
            RouteKind kind) noexcept;
        bool RevalidateInterface(const MIB_IPFORWARD_ROW2& row) noexcept;
        void Diagnostic(const char* action, const char* detail) const noexcept;

        std::unique_ptr<IWindowsIPv6RouteApi> api_;
        ppp::ipv6::route_transaction::IPv6RouteTransaction transaction_;
        mutable std::mutex mutex_;
        MIB_IF_ROW2 tap_interface_{};
        MIB_IF_ROW2 physical_interface_{};
        bool bound_ = false;
        std::vector<RouteRecord> records_;
    };
}
