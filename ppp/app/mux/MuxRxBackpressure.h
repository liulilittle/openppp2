#pragma once

/**
 * @file MuxRxBackpressure.h
 * @brief Receive-side reorder budget and head-of-line gap clock for vmux.
 * @license GPL-3.0
 *
 * Carriers are reliable byte streams, so a reorder buffer that keeps growing
 * means one carrier lags the others, not that frames are lost. Instead of
 * tearing the session down when a byte cap is crossed, the receiver treats the
 * cap as soft: it keeps buffering up to a hard bound but stops reading the
 * carrier that just delivered an out-of-order frame. TCP flow control on that
 * carrier then pushes back on the sender until the lagging frame arrives and
 * the buffer drains. Only the hard bound (memory safety) rejects.
 *
 * Header-only and free of vmux state so the policy is unit-testable.
 */

#include <cstddef>
#include <cstdint>
#include <limits>

namespace ppp::app::mux {

/** Verdict for buffering one out-of-order frame. */
enum class MuxReorderAdmit {
    Accept,          ///< Within the soft cap.
    AcceptAndPause,  ///< Over the soft cap, within the hard cap: buffer and pause the delivering carrier.
    Reject,          ///< Over the hard cap: caller applies its terminal policy.
};

/** Hard bound derived from a soft cap (saturating); factor < 1 is treated as 1. */
inline std::size_t MuxReorderHardCap(std::size_t soft_cap, std::size_t hard_factor) noexcept {
    const std::size_t factor = hard_factor < 1 ? 1 : hard_factor;
    if (soft_cap > std::numeric_limits<std::size_t>::max() / factor) {
        return std::numeric_limits<std::size_t>::max();
    }
    return soft_cap * factor;
}

/**
 * Classify buffering @p incoming bytes on top of @p buffered.
 * @param soft_cap 0 means unlimited (always Accept).
 */
inline MuxReorderAdmit AdmitReorderBytes(
    std::size_t buffered,
    std::size_t incoming,
    std::size_t soft_cap,
    std::size_t hard_factor) noexcept {
    if (soft_cap == 0) {
        return MuxReorderAdmit::Accept;
    }
    const std::size_t total = (incoming > std::numeric_limits<std::size_t>::max() - buffered)
        ? std::numeric_limits<std::size_t>::max()
        : buffered + incoming;
    if (total <= soft_cap) {
        return MuxReorderAdmit::Accept;
    }
    return total <= MuxReorderHardCap(soft_cap, hard_factor)
        ? MuxReorderAdmit::AcceptAndPause
        : MuxReorderAdmit::Reject;
}

/** Hysteresis: resume paused carriers once the buffer is back to half the soft cap. */
inline bool MuxReorderShouldResume(std::size_t buffered, std::size_t soft_cap) noexcept {
    return soft_cap == 0 || buffered <= soft_cap / 2;
}

/**
 * Liveness guard: pausing every live carrier would also block the one that
 * carries the missing frame, so the receiver must release all pauses instead.
 */
inline bool MuxPauseWouldStallAll(std::size_t paused, std::size_t live) noexcept {
    return live == 0 || paused >= live;
}

/**
 * Head-of-line gap clock (0 = no gap).
 *
 * The gap timeout must measure how long delivery has been stalled, not how
 * long the reorder buffer has been non-empty: under sustained multi-carrier
 * load the buffer is almost never empty even though every gap closes quickly.
 */
inline std::uint64_t MuxGapClockOnBuffered(std::uint64_t since, std::uint64_t now) noexcept {
    return since == 0 ? now : since;
}

/** In-order delivery is progress: restart the clock if frames remain buffered. */
inline std::uint64_t MuxGapClockAfterAdvance(std::uint64_t now, bool still_buffered) noexcept {
    return still_buffered ? now : 0;
}

inline bool MuxGapExpired(std::uint64_t since, std::uint64_t now, std::uint64_t timeout) noexcept {
    return since != 0 && now >= since && (now - since) > timeout;
}

} // namespace ppp::app::mux
