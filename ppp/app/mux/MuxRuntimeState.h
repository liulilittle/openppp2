#pragma once

#include <cstdint>
#include <string>
#include <utility>

namespace ppp::app::mux {

struct MuxRuntimeState final {
    std::string requested_mode;      ///< User/config preset: compat|flow|balance|stripe
    std::string effective_mode;      ///< Negotiated preset after capability intersection
    std::string receiver_ordering;   ///< compat|flow_v2
    std::string scheduler;           ///< competition|round_robin (derived from effective_mode)
    std::string pool_policy;         ///< fixed|adaptive (derived from effective_mode + turbo)
    bool turbo = false;              ///< flow turbo active (adaptive pool / best-link SYN)
    bool reliability = false;        ///< reliability sub-protocol agreed (ACK + retransmission)
    bool fec = false;                ///< XOR parity FEC agreed (implies reliability)
    std::uint16_t active_links = 0;
    std::string fallback_reason;
};

inline const char* MuxSchedulerName(const std::string& mode) noexcept {
    return mode == "stripe" ? "round_robin" : "competition";
}

inline const char* MuxPoolPolicyName(const std::string& mode, bool turbo) noexcept {
    return (mode == "flow" && turbo) ? "adaptive" : "fixed";
}

inline void FillMuxPresentation(MuxRuntimeState& state) noexcept {
    state.scheduler = MuxSchedulerName(state.effective_mode);
    state.pool_policy = MuxPoolPolicyName(state.effective_mode, state.turbo);
}

inline bool IsMuxLinkActive(bool handshake_complete, bool retiring) noexcept {
    return handshake_complete && !retiring;
}

/** True when the preset needs negotiated per-flow DSN ordering. */
inline bool ModeRequiresFlowV2(const std::string& mode, bool turbo) noexcept {
    return mode == "balance" || mode == "stripe" || (mode == "flow" && turbo);
}

/**
 * Negotiate effective preset + receiver ordering + reliability capabilities.
 * @param local_supports_flow_v2 Implementation capability (independent of current preset).
 * @param peer_supports_flow_v2 Peer advertised capability bit.
 * @param turbo Local turbo request (only meaningful with flow preset).
 * @param local_reliability Local reliability sub-protocol enabled (config).
 * @param peer_reliability Peer advertised reliability capability bit.
 * @param local_fec Local FEC enabled (config); requires reliability to take effect.
 * @param peer_fec Peer advertised FEC capability bit.
 */
inline MuxRuntimeState NegotiateMuxRuntimeState(
    std::string requested_mode,
    bool local_supports_flow_v2,
    bool peer_supports_flow_v2,
    std::uint16_t active_links = 0,
    bool turbo = false,
    bool local_reliability = false,
    bool peer_reliability = false,
    bool local_fec = false,
    bool peer_fec = false) {
    MuxRuntimeState state;
    state.requested_mode = std::move(requested_mode);
    state.effective_mode = state.requested_mode;
    state.active_links = active_links;
    state.turbo = turbo && state.requested_mode == "flow";
    // Reliability is orthogonal to the scheduler preset and receiver ordering:
    // it runs in both compat and flow_v2 modes, so it never forces a fallback.
    state.reliability = local_reliability && peer_reliability;
    state.fec = state.reliability && local_fec && peer_fec;

    const bool known = state.requested_mode == "compat" ||
        state.requested_mode == "flow" ||
        state.requested_mode == "balance" ||
        state.requested_mode == "stripe";
    if (!known) {
        state.effective_mode = "compat";
        state.receiver_ordering = "compat";
        state.turbo = false;
        state.fallback_reason = "unsupported_requested_mode";
        FillMuxPresentation(state);
        return state;
    }

    const bool requires_flow_v2 = ModeRequiresFlowV2(state.requested_mode, state.turbo);
    if (requires_flow_v2 && (!local_supports_flow_v2 || !peer_supports_flow_v2)) {
        // balance/stripe cannot run without flow_v2; fall back the whole preset.
        // flow without turbo does not require flow_v2, so it is not handled here.
        if (state.requested_mode == "balance" || state.requested_mode == "stripe") {
            state.effective_mode = "compat";
            state.receiver_ordering = "compat";
            state.turbo = false;
            state.fallback_reason = local_supports_flow_v2
                ? "peer_missing_flow_v2"
                : "local_missing_flow_v2";
            FillMuxPresentation(state);
            return state;
        }
    }

    // flow keeps its preset even if ordering stays compat (old peer or no turbo).
    const bool uses_flow_v2 = ModeRequiresFlowV2(state.effective_mode, state.turbo) &&
        local_supports_flow_v2 && peer_supports_flow_v2;
    state.receiver_ordering = uses_flow_v2 ? "flow_v2" : "compat";
    if (state.requested_mode == "flow" && state.turbo && !uses_flow_v2 &&
        state.fallback_reason.empty() && (!local_supports_flow_v2 || !peer_supports_flow_v2)) {
        state.fallback_reason = local_supports_flow_v2
            ? "peer_missing_flow_v2"
            : "local_missing_flow_v2";
        // Keep effective_mode=flow; turbo features that need flow_v2 degrade safely.
    }

    FillMuxPresentation(state);
    return state;
}

/** Apply the capabilities selected by the peer's authoritative handshake reply. */
inline MuxRuntimeState ApplyAgreedMuxRuntimeState(
    std::string requested_mode,
    bool agreed_flow_v2,
    std::uint16_t active_links = 0,
    bool turbo = false,
    bool agreed_reliability = false,
    bool agreed_fec = false) {
    const bool known = requested_mode == "compat" ||
        requested_mode == "flow" ||
        requested_mode == "balance" ||
        requested_mode == "stripe";
    if (!known || !agreed_flow_v2) {
        MuxRuntimeState state = NegotiateMuxRuntimeState(
            std::move(requested_mode), true, false, active_links, turbo);
        // Ordering fell back, but the peer's authoritative reliability result
        // still applies (reliability runs in compat mode too).
        state.reliability = agreed_reliability;
        state.fec = agreed_reliability && agreed_fec;
        return state;
    }

    MuxRuntimeState state;
    state.requested_mode = std::move(requested_mode);
    state.effective_mode = state.requested_mode;
    state.receiver_ordering = "flow_v2";
    state.active_links = active_links;
    state.turbo = turbo && state.requested_mode == "flow";
    state.reliability = agreed_reliability;
    state.fec = agreed_reliability && agreed_fec;
    FillMuxPresentation(state);
    return state;
}

} // namespace ppp::app::mux
