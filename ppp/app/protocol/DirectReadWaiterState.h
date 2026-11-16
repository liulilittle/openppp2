#pragma once

#include <ppp/app/runtime/XtcpFirstLegHooks.h>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <utility>

namespace ppp::app::protocol {

/**
 * @brief Matches one direct-read completion to the coroutine waiting for it.
 * @tparam Waiter Wakeup handle returned to the completer; must be default
 *         constructible (empty) and contextually convertible to bool. Production
 *         uses YieldContext::Anchor so a handed-out waiter can only resume the
 *         suspension it was armed for.
 */
template <class Waiter>
class BasicDirectReadWaiterState final {
public:
    enum class Outcome : std::uint8_t {
        Pending,
        Accepted,
        Terminal,
        Rejected,
    };

    Outcome Register(const client::xtcp::XtcpDirectReadReservation& reservation,
        const Waiter& waiter) noexcept {
        if (invalidated_ || !reservation.IsValid() || !waiter || expected_ ||
            reservation.token <= retired_token_) {
            return Outcome::Rejected;
        }
        expected_ = reservation;
        waiter_ = waiter;
        if (pending_) {
            if (pending_->IsSame(reservation)) {
                outcome_ = pending_outcome_;
                pending_.reset();
                pending_outcome_ = Outcome::Pending;
                waiter_ = Waiter{};
            }
            else if (pending_->token > reservation.token) {
                expected_.reset();
                waiter_ = Waiter{};
                return Outcome::Rejected;
            }
            else {
                pending_.reset();
                pending_outcome_ = Outcome::Pending;
            }
        }
        return outcome_;
    }

    Waiter Complete(
        const client::xtcp::XtcpDirectReadReservation& reservation,
        client::xtcp::XtcpDirectCompletion completion) noexcept {
        if (invalidated_ || !reservation.IsValid() || reservation.token <= retired_token_) {
            return Waiter{};
        }
        const Outcome outcome = completion == client::xtcp::XtcpDirectCompletion::Accepted
            ? Outcome::Accepted : Outcome::Terminal;
        if (expected_) {
            if (!expected_->IsSame(reservation) || outcome_ != Outcome::Pending) {
                return Waiter{};
            }
            outcome_ = outcome;
            return std::exchange(waiter_, Waiter{});
        }
        if (!pending_ || reservation.token > pending_->token) {
            pending_ = reservation;
            pending_outcome_ = outcome;
        }
        return Waiter{};
    }

    Outcome Consume(const client::xtcp::XtcpDirectReadReservation& reservation) noexcept {
        if (!expected_ || !expected_->IsSame(reservation)) {
            return Outcome::Rejected;
        }
        const Outcome result = outcome_;
        if (result == Outcome::Pending) {
            return Outcome::Pending;
        }
        retired_token_ = std::max(retired_token_, reservation.token);
        expected_.reset();
        waiter_ = Waiter{};
        outcome_ = Outcome::Pending;
        return result;
    }

    Waiter Invalidate() noexcept {
        invalidated_ = true;
        pending_.reset();
        pending_outcome_ = Outcome::Pending;
        outcome_ = Outcome::Terminal;
        return std::exchange(waiter_, Waiter{});
    }

    void Reset() noexcept {
        invalidated_ = false;
        expected_.reset();
        pending_.reset();
        waiter_ = Waiter{};
        outcome_ = Outcome::Pending;
        pending_outcome_ = Outcome::Pending;
        retired_token_ = 0;
    }

private:
    bool invalidated_ = false;
    std::uint64_t retired_token_ = 0;
    std::optional<client::xtcp::XtcpDirectReadReservation> expected_;
    std::optional<client::xtcp::XtcpDirectReadReservation> pending_;
    Waiter waiter_{};
    Outcome outcome_ = Outcome::Pending;
    Outcome pending_outcome_ = Outcome::Pending;
};

} // namespace ppp::app::protocol
