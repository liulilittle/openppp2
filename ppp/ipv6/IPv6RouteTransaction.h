#pragma once

#include <ppp/ipv6/IPv6ClientPolicy.h>

#include <array>
#include <cstdint>
#include <vector>

namespace ppp::ipv6::route_transaction {

    enum class RouteKind : std::uint8_t {
        EgressPin,
        LowerHalf,
        UpperHalf,
    };

    enum class PairMode : std::uint8_t {
        None,
        Sink,
        Managed,
    };

    struct RouteIdentity {
        RouteKind Kind = RouteKind::EgressPin;
        std::array<std::uint8_t, 16> Destination{};
        std::uint8_t PrefixLength = 0;
        std::uint64_t InterfaceLuid = 0;
        std::uint32_t InterfaceIndex = 0;
        std::array<std::uint8_t, 16> NextHop{};
        std::uint32_t NextHopScopeId = 0;
        std::uint32_t Metric = 0;
        std::uint32_t Protocol = 0;
        std::uint32_t Origin = 0;
        std::uint8_t SitePrefixLength = 0;
        bool Loopback = false;
        bool AutoconfigureAddress = false;
        bool Publish = false;
        bool Immortal = false;
    };

    bool IsExactRouteMatch(const RouteIdentity& existing, const RouteIdentity& expected) noexcept;

    class IRouteMutator {
    public:
        virtual ~IRouteMutator() noexcept = default;
        virtual client_policy::OwnershipMutation Create(const RouteIdentity& route) noexcept = 0;
        virtual bool Delete(const RouteIdentity& route) noexcept = 0;
    };

    class IPv6RouteTransaction final {
    public:
        explicit IPv6RouteTransaction(IRouteMutator& mutator) noexcept;

        bool StagePin(const RouteIdentity& pin) noexcept;
        bool StageNoPin() noexcept;
        bool CommitStagedPin() noexcept;
        bool RollbackStagedPin() noexcept;

        bool EnsureSinkMode(const RouteIdentity& lower, const RouteIdentity& upper) noexcept;
        bool ActivateManagedMode(const RouteIdentity& lower, const RouteIdentity& upper) noexcept;
        bool Stop() noexcept;

        PairMode Mode() const noexcept { return mode_; }
        bool HasStagedPin() const noexcept { return staged_pin_.Present; }
        bool HasEgress() const noexcept { return staged_pin_.Present || committed_pin_.Present; }
        bool HasPendingCleanup() const noexcept;

    private:
        struct RouteSlot {
            RouteIdentity Identity;
            bool Present = false;
            bool Owned = false;
        };

        bool ApplyPair(PairMode mode, const RouteIdentity& lower, const RouteIdentity& upper) noexcept;
        bool DeleteSlot(RouteSlot& slot) noexcept;
        bool RetryPending(RouteKind kind) noexcept;
        void QueueOwned(RouteSlot& slot) noexcept;

        IRouteMutator& mutator_;
        PairMode mode_ = PairMode::None;
        RouteSlot lower_;
        RouteSlot upper_;
        RouteSlot staged_pin_;
        RouteSlot committed_pin_;
        std::vector<RouteSlot> pending_cleanup_;
    };
}
