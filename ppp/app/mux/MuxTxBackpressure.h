#pragma once

/**
 * @file MuxTxBackpressure.h
 * @brief Send-side retransmit-buffer window for vmux.
 * @license GPL-3.0
 *
 * Every reliably-sent frame stays in the retransmit buffer until the peer
 * ACKs it, so unacked bytes ~= BDP + carrier kernel send buffers. Treating the
 * buffer cap as a terminal limit tore the session down whenever a fast,
 * high-RTT path simply had more than the cap in flight. Instead the cap is a
 * send window checked before a frame leaves the DRR queue: a frame that would
 * cross it stays queued (its flow is parked) until an ACK releases bytes. The
 * retransmit buffer itself only rejects past a hard bound (window * factor),
 * which only frames that bypass the window (e.g. the turbo SYN) can approach.
 *
 * Header-only and free of vmux state so the policy is unit-testable.
 */

#include <cstddef>
#include <cstdint>
#include <limits>

namespace ppp::app::mux {

/** Verdict for sending one frame against the retransmit window. */
enum class MuxTxAdmit {
    Send,         ///< Fits both windows (or is not tracked).
    HoldSession,  ///< Would cross the session-wide window: keep it queued.
    HoldFlow,     ///< Would cross this flow's window: keep it queued.
};

/** Hard bound derived from a window (saturating); factor < 1 is treated as 1. */
inline std::size_t MuxTxHardCap(std::size_t window, std::size_t hard_factor) noexcept {
    const std::size_t factor = hard_factor < 1 ? 1 : hard_factor;
    if (window > std::numeric_limits<std::size_t>::max() / factor) {
        return std::numeric_limits<std::size_t>::max();
    }
    return window * factor;
}

/**
 * True when @p incoming more bytes fit a window that already holds
 * @p inflight. A window of 0 is unlimited, and an empty window always admits
 * one frame so a frame larger than the window cannot wedge the sender.
 */
inline bool MuxTxFitsWindow(std::size_t inflight, std::size_t incoming, std::size_t window) noexcept {
    if (window == 0 || inflight == 0) {
        return true;
    }
    return incoming <= window && inflight <= window - incoming;
}

/**
 * Classify sending a frame that would add @p incoming tracked bytes.
 * @param incoming 0 for frames the retransmit buffer will not track (always Send).
 * @param flow_window 0 when there is no per-flow window (compat ordering).
 */
inline MuxTxAdmit AdmitTxFrame(
    std::size_t session_inflight,
    std::size_t flow_inflight,
    std::size_t incoming,
    std::size_t session_window,
    std::size_t flow_window) noexcept {
    if (incoming == 0) {
        return MuxTxAdmit::Send;
    }
    if (!MuxTxFitsWindow(flow_inflight, incoming, flow_window)) {
        return MuxTxAdmit::HoldFlow;
    }
    if (!MuxTxFitsWindow(session_inflight, incoming, session_window)) {
        return MuxTxAdmit::HoldSession;
    }
    return MuxTxAdmit::Send;
}

/**
 * True when tracking @p incoming more bytes on top of @p inflight would cross
 * the hard bound (window * factor): the caller applies its terminal policy.
 * A window of 0 is unlimited.
 */
inline bool MuxTxOverHardCap(
    std::size_t inflight,
    std::size_t incoming,
    std::size_t window,
    std::size_t hard_factor) noexcept {
    if (window == 0) {
        return false;
    }
    const std::size_t hard = MuxTxHardCap(window, hard_factor);
    return incoming > hard || inflight > hard - incoming;
}

/**
 * Acceleration completes a push before it is written so the stream's read
 * pump can run ahead of the carrier. Re-couple it (complete only once the
 * frame is written) when the session queue reaches its high-water, when the
 * flow is parked on the retransmit window, or when the flow's own queue is
 * half way to its cap: one outstanding read per stream then bounds the queue
 * well below the cap, so a healthy stream never overflows it.
 */
inline bool MuxTxShouldCoupleCompletion(
    std::size_t session_frames,
    std::size_t session_high_water,
    bool flow_parked,
    std::size_t flow_frames,
    std::size_t flow_bytes,
    std::size_t flow_max_frames,
    std::size_t flow_max_bytes) noexcept {
    if (session_high_water > 0 && session_frames >= session_high_water) {
        return true;
    }
    if (flow_parked) {
        return true;
    }
    if (flow_max_frames > 0 && flow_frames >= flow_max_frames / 2) {
        return true;
    }
    return flow_max_bytes > 0 && flow_bytes >= flow_max_bytes / 2;
}

/** Per-carrier load snapshot used to choose where the next frame goes. */
struct MuxLinkLoad {
    std::size_t   queued_bytes = 0;  ///< Bytes handed to the carrier and not yet written.
    std::uint64_t srtt_ms = 0;       ///< Smoothed RTT; meaningful only when has_rtt.
    bool          has_rtt = false;
    bool          has_credit = false; ///< Room for this frame under the per-carrier byte budget.
};

/**
 * Pick the carrier for the next frame: among those with credit, the one with
 * the fewest bytes in flight (a backlogged carrier is a slow one, whatever its
 * local write completions say); ties go to list order unless one carrier's SRTT
 * is lower by more than kMuxRttTieMarginMs.
 * @return index into @p links, or -1 when none has credit.
 */
/** SRTT advantage (ms) a carrier needs to win a tie on bytes in flight. */
static constexpr std::uint64_t kMuxRttTieMarginMs = 10;

template <typename Links>
inline int MuxPickLeastLoaded(const Links& links) noexcept {
    int best = -1;
    for (int i = 0; i < static_cast<int>(links.size()); ++i) {
        const MuxLinkLoad& l = links[i];
        if (!l.has_credit) {
            continue;
        }
        if (best < 0) {
            best = i;
            continue;
        }
        const MuxLinkLoad& b = links[best];
        if (l.queued_bytes != b.queued_bytes) {
            if (l.queued_bytes < b.queued_bytes) {
                best = i;
            }
        }
        else if (l.has_rtt && b.has_rtt && l.srtt_ms + kMuxRttTieMarginMs < b.srtt_ms) {
            // Only a clearly faster carrier beats list order: callers rotate the
            // list so equally loaded carriers take turns, and a hair-thin SRTT
            // edge would otherwise pin every idle frame to one carrier.
            best = i;
        }
    }
    return best;
}

/**
 * Send a push straight from its read buffer only when the read filled at
 * least half of it (and is not tiny): the retransmit window counts frame
 * length, so a mostly empty max-size buffer would let real memory exceed the
 * window. Smaller reads are copied into an exact-size frame instead.
 */
inline bool MuxPushIsZeroCopy(int payload, int buffer, int min_payload) noexcept {
    return payload >= min_payload && payload > 0 && payload * 2 >= buffer;
}

/** Receiver-side XON/XOFF decision for one stream. */
enum class MuxFlowControlAction { None, SendXon, SendXoff };

/**
 * Hysteresis: stop the peer at the threshold, resume it once the backlog is
 * down to half (resuming only at zero made throughput a sawtooth: the pipe
 * drained completely before the peer sent again).
 */
inline MuxFlowControlAction MuxFlowControlNext(bool peer_running, std::int64_t backlog, std::int64_t threshold) noexcept {
    if (threshold < 1) {
        return MuxFlowControlAction::None;
    }
    if (peer_running) {
        return backlog >= threshold ? MuxFlowControlAction::SendXoff : MuxFlowControlAction::None;
    }
    return backlog <= threshold / 2 ? MuxFlowControlAction::SendXon : MuxFlowControlAction::None;
}

/**
 * Per-connection XON/XOFF (cmd_acceleration) ordering. Control frames are
 * unordered under flow_v2 and may take different carriers, so an XON can
 * overtake the XOFF sent before it and leave the stream stopped forever.
 * Senders stamp each frame with a monotonic version; a receiver applies a
 * versioned frame only if it is newer than the last one it applied
 * (wrap-safe). Unversioned frames (older peers) are always applied.
 */
inline bool MuxFlowControlIsFresh(bool have_last, std::uint32_t last, std::uint32_t version) noexcept {
    if (!have_last) {
        return true;
    }
    return static_cast<std::int32_t>(version - last) > 0;
}

} // namespace ppp::app::mux
