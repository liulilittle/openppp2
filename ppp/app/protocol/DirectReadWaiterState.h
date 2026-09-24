#pragma once

#include <ppp/app/runtime/XtcpFirstLegHooks.h>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <utility>

namespace ppp::coroutines { class YieldContext; }

namespace ppp::app::protocol {

class DirectReadWaiterState final {
public:
    enum class Outcome : std::uint8_t {
        Pending,
        Accepted,
        Terminal,
        Rejected,
    };

    Outcome Register(const client::xtcp::XtcpDirectReadReservation& reservation,
        ppp::coroutines::YieldContext* waiter) noexcept {
        if (invalidated_ || !reservation.IsValid() || waiter == nullptr || expected_ ||
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
                waiter_ = nullptr;
            }
            else if (pending_->token > reservation.token) {
                expected_.reset();
                waiter_ = nullptr;
                return Outcome::Rejected;
            }
            else {
                pending_.reset();
                pending_outcome_ = Outcome::Pending;
            }
        }
        return outcome_;
    }

    ppp::coroutines::YieldContext* Complete(
        const client::xtcp::XtcpDirectReadReservation& reservation,
        client::xtcp::XtcpDirectCompletion completion) noexcept {
        if (invalidated_ || !reservation.IsValid() || reservation.token <= retired_token_) {
            return nullptr;
        }
        const Outcome outcome = completion == client::xtcp::XtcpDirectCompletion::Accepted
            ? Outcome::Accepted : Outcome::Terminal;
        if (expected_) {
            if (!expected_->IsSame(reservation) || outcome_ != Outcome::Pending) {
                return nullptr;
            }
            outcome_ = outcome;
            return std::exchange(waiter_, nullptr);
        }
        if (!pending_ || reservation.token > pending_->token) {
            pending_ = reservation;
            pending_outcome_ = outcome;
        }
        return nullptr;
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
        waiter_ = nullptr;
        outcome_ = Outcome::Pending;
        return result;
    }

    ppp::coroutines::YieldContext* Invalidate() noexcept {
        invalidated_ = true;
        pending_.reset();
        pending_outcome_ = Outcome::Pending;
        outcome_ = Outcome::Terminal;
        return std::exchange(waiter_, nullptr);
    }

    void Reset() noexcept {
        invalidated_ = false;
        expected_.reset();
        pending_.reset();
        waiter_ = nullptr;
        outcome_ = Outcome::Pending;
        pending_outcome_ = Outcome::Pending;
        retired_token_ = 0;
    }

private:
    bool invalidated_ = false;
    std::uint64_t retired_token_ = 0;
    std::optional<client::xtcp::XtcpDirectReadReservation> expected_;
    std::optional<client::xtcp::XtcpDirectReadReservation> pending_;
    ppp::coroutines::YieldContext* waiter_ = nullptr;
    Outcome outcome_ = Outcome::Pending;
    Outcome pending_outcome_ = Outcome::Pending;
};

} // namespace ppp::app::protocol
