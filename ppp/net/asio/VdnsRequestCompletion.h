#pragma once

#include <atomic>
#include <cstdint>
#include <utility>

namespace ppp::net::asio::vdns {

enum class VdnsRequestCompletionState : std::uint8_t {
    Pending,
    Finished,
    TimedOut,
    Cancelled
};

/**
 * @brief Single-winner arbitration shared by vdns response, timeout, and cancel paths.
 */
class VdnsRequestCompletion final {
public:
    using State = VdnsRequestCompletionState;

    /**
     * @brief Atomically claims completion and runs the winning cleanup action.
     * @return True only for the caller that changed Pending to a terminal state.
     */
    template <typename TAction>
    bool TryComplete(State terminal_state, TAction&& action) noexcept(noexcept(std::forward<TAction>(action)())) {
        State expected = State::Pending;
        if (terminal_state == State::Pending ||
            !state_.compare_exchange_strong(
                expected,
                terminal_state,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            return false;
        }

        std::forward<TAction>(action)();
        return true;
    }

    /** @return True while no terminal path has won. */
    bool IsPending() const noexcept {
        return GetState() == State::Pending;
    }

    /** @return Current request completion state. */
    State GetState() const noexcept {
        return state_.load(std::memory_order_acquire);
    }

private:
    std::atomic<State> state_{State::Pending};
};

}
