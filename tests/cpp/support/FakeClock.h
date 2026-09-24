#pragma once

/**
 * @file FakeClock.h
 * @brief Deterministic clock for VMUX testing — no real sleep, no wall-clock
 *        drift, fully controllable by the test harness.
 * @license GPL-3.0
 *
 * Used in conjunction with MuxRetransmitBuffer, MuxAckTracker, and other
 * strand-affine components that take a tick/time parameter. The clock
 * advances only when the test calls advance().
 */

#include <cstdint>
#include <cstddef>

namespace ppp::test {

/** Monotonic fake clock. All values are in milliseconds. */
class FakeClock final {
public:
    FakeClock() noexcept = default;

    /** Current tick in milliseconds. */
    std::uint64_t now() const noexcept { return tick_; }

    /** Advance the clock by @p ms milliseconds (must be > 0). */
    void advance(std::uint64_t ms) noexcept { tick_ += ms; }

    /** Reset to epoch. */
    void reset() noexcept { tick_ = 0; }

private:
    std::uint64_t tick_ = 0;
};

} // namespace ppp::test
