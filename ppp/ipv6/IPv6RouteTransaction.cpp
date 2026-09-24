#include <ppp/ipv6/IPv6RouteTransaction.h>

#include <algorithm>

namespace ppp::ipv6::route_transaction {

    bool IsExactRouteMatch(const RouteIdentity& existing, const RouteIdentity& expected) noexcept {
        return existing.Kind == expected.Kind &&
            existing.Destination == expected.Destination &&
            existing.PrefixLength == expected.PrefixLength &&
            existing.InterfaceLuid == expected.InterfaceLuid &&
            existing.InterfaceIndex == expected.InterfaceIndex &&
            existing.NextHop == expected.NextHop &&
            existing.NextHopScopeId == expected.NextHopScopeId &&
            existing.Metric == expected.Metric &&
            existing.Protocol == expected.Protocol &&
            existing.Origin == expected.Origin &&
            existing.SitePrefixLength == expected.SitePrefixLength &&
            existing.Loopback == expected.Loopback &&
            existing.AutoconfigureAddress == expected.AutoconfigureAddress &&
            existing.Publish == expected.Publish &&
            existing.Immortal == expected.Immortal;
    }

    IPv6RouteTransaction::IPv6RouteTransaction(IRouteMutator& mutator) noexcept
        : mutator_(mutator) {
    }

    bool IPv6RouteTransaction::DeleteSlot(RouteSlot& slot) noexcept {
        if (!slot.Present || !slot.Owned) {
            slot = RouteSlot();
            return true;
        }
        if (!mutator_.Delete(slot.Identity)) {
            return false;
        }
        slot = RouteSlot();
        return true;
    }

    void IPv6RouteTransaction::QueueOwned(RouteSlot& slot) noexcept {
        if (slot.Present && slot.Owned) {
            pending_cleanup_.emplace_back(slot);
        }
        slot = RouteSlot();
    }

    bool IPv6RouteTransaction::RetryPending(RouteKind kind) noexcept {
        bool clean = true;
        for (auto it = pending_cleanup_.begin(); it != pending_cleanup_.end();) {
            if (it->Identity.Kind != kind) {
                ++it;
                continue;
            }
            if (mutator_.Delete(it->Identity)) {
                it = pending_cleanup_.erase(it);
            }
            else {
                clean = false;
                ++it;
            }
        }
        return clean;
    }

    bool IPv6RouteTransaction::StagePin(const RouteIdentity& pin) noexcept {
        if (pin.Kind != RouteKind::EgressPin || !RollbackStagedPin()) {
            return false;
        }

        const auto mutation = mutator_.Create(pin);
        if (mutation == client_policy::OwnershipMutation::Failed) {
            return false;
        }
        staged_pin_.Identity = pin;
        staged_pin_.Present = true;
        staged_pin_.Owned = mutation == client_policy::OwnershipMutation::Changed;
        return true;
    }

    bool IPv6RouteTransaction::StageNoPin() noexcept {
        if (!RollbackStagedPin()) {
            return false;
        }
        staged_pin_.Present = true;
        staged_pin_.Owned = false;
        staged_pin_.Identity = RouteIdentity();
        staged_pin_.Identity.Kind = RouteKind::EgressPin;
        return true;
    }

    bool IPv6RouteTransaction::CommitStagedPin() noexcept {
        if (!staged_pin_.Present) {
            return false;
        }

        if (committed_pin_.Present &&
            IsExactRouteMatch(committed_pin_.Identity, staged_pin_.Identity)) {
            if (staged_pin_.Owned) {
                QueueOwned(staged_pin_);
            }
            else {
                staged_pin_ = RouteSlot();
            }
            RetryPending(RouteKind::EgressPin);
            return true;
        }

        QueueOwned(committed_pin_);
        committed_pin_ = staged_pin_;
        staged_pin_ = RouteSlot();
        RetryPending(RouteKind::EgressPin);
        return true;
    }

    bool IPv6RouteTransaction::RollbackStagedPin() noexcept {
        return DeleteSlot(staged_pin_);
    }

    bool IPv6RouteTransaction::EnsureSinkMode(
        const RouteIdentity& lower,
        const RouteIdentity& upper) noexcept {
        return ApplyPair(PairMode::Sink, lower, upper);
    }

    bool IPv6RouteTransaction::ActivateManagedMode(
        const RouteIdentity& lower,
        const RouteIdentity& upper) noexcept {
        return ApplyPair(PairMode::Managed, lower, upper);
    }

    bool IPv6RouteTransaction::ApplyPair(
        PairMode mode,
        const RouteIdentity& lower,
        const RouteIdentity& upper) noexcept {
        if (lower.Kind != RouteKind::LowerHalf || upper.Kind != RouteKind::UpperHalf) {
            return false;
        }
        if (lower_.Present && upper_.Present &&
            IsExactRouteMatch(lower_.Identity, lower) &&
            IsExactRouteMatch(upper_.Identity, upper)) {
            mode_ = mode;
            return true;
        }

        RouteSlot next_lower;
        next_lower.Identity = lower;
        const auto lower_result = mutator_.Create(lower);
        if (lower_result == client_policy::OwnershipMutation::Failed) {
            return false;
        }
        next_lower.Present = true;
        next_lower.Owned = lower_result == client_policy::OwnershipMutation::Changed;

        RouteSlot next_upper;
        next_upper.Identity = upper;
        const auto upper_result = mutator_.Create(upper);
        if (upper_result == client_policy::OwnershipMutation::Failed) {
            if (!DeleteSlot(next_lower)) {
                QueueOwned(next_lower);
            }
            return false;
        }
        next_upper.Present = true;
        next_upper.Owned = upper_result == client_policy::OwnershipMutation::Changed;

        QueueOwned(upper_);
        QueueOwned(lower_);
        lower_ = next_lower;
        upper_ = next_upper;
        mode_ = mode;
        RetryPending(RouteKind::UpperHalf);
        RetryPending(RouteKind::LowerHalf);
        return true;
    }

    bool IPv6RouteTransaction::Stop() noexcept {
        bool clean = true;
        clean = DeleteSlot(upper_) && clean;
        clean = DeleteSlot(lower_) && clean;
        clean = RetryPending(RouteKind::UpperHalf) && clean;
        clean = RetryPending(RouteKind::LowerHalf) && clean;
        mode_ = PairMode::None;

        clean = DeleteSlot(staged_pin_) && clean;
        clean = RetryPending(RouteKind::EgressPin) && clean;
        clean = DeleteSlot(committed_pin_) && clean;
        clean = RetryPending(RouteKind::EgressPin) && clean;
        return clean && pending_cleanup_.empty();
    }

    bool IPv6RouteTransaction::HasPendingCleanup() const noexcept {
        if (!pending_cleanup_.empty()) {
            return true;
        }
        return (lower_.Present && lower_.Owned) ||
            (upper_.Present && upper_.Owned) ||
            (staged_pin_.Present && staged_pin_.Owned) ||
            (committed_pin_.Present && committed_pin_.Owned);
    }
}
