#pragma once

#include <ppp/p2p/P2PAuthenticatedProbeAck.h>
#include <ppp/p2p/P2PState.h>

namespace ppp::p2p {

class P2PControlStateMachine final {
public:
    P2PState State() const noexcept { return state_; }
    P2PFallbackReason FallbackReason() const noexcept { return fallback_reason_; }
    const char* EffectivePath() const noexcept { return EffectivePathFor(state_); }

    static const char* EffectivePathFor(P2PState state) noexcept {
        return state == P2PState::Direct ? "direct" : "relay";
    }

    static bool CanForwardDataFor(P2PState state) noexcept {
        return state == P2PState::Direct;
    }

    bool MarkEligible() noexcept {
        if (state_ != P2PState::Relay && state_ != P2PState::Unavailable &&
            state_ != P2PState::Failed) return false;
        fallback_reason_ = P2PFallbackReason::None;
        state_ = P2PState::Eligible;
        return true;
    }

    bool AcceptOffer() noexcept {
        return Move(P2PState::Eligible, P2PState::Probing);
    }

    bool AcceptProbeAck(bool) noexcept { return false; }

    bool AcceptProbeAck(P2PAuthenticatedProbeAck&& ack) noexcept {
        if (state_ != P2PState::Probing) return false;
        if (!ack.Consume()) return false;
        return Move(P2PState::Probing, P2PState::Direct);
    }

    bool MarkSuspect() noexcept {
        return Move(P2PState::Direct, P2PState::Suspect);
    }

    bool AcceptRecoveryAck(bool) noexcept { return false; }

    bool AcceptRecoveryAck(P2PAuthenticatedProbeAck&& ack) noexcept {
        if (state_ != P2PState::Suspect) return false;
        if (!ack.Consume()) return false;
        return Move(P2PState::Suspect, P2PState::Direct);
    }

    bool RecoverFromAuthenticatedData() noexcept {
        return Move(P2PState::Suspect, P2PState::Direct);
    }

    bool BeginFallback(P2PFallbackReason reason) noexcept {
        if (reason == P2PFallbackReason::None) return false;
        if (state_ != P2PState::Eligible && state_ != P2PState::Probing &&
            state_ != P2PState::Direct && state_ != P2PState::Suspect) return false;
        fallback_reason_ = reason;
        state_ = P2PState::FallingBack;
        return true;
    }

    bool CompleteFallback(bool prerequisites_available) noexcept {
        if (state_ != P2PState::FallingBack) return false;
        state_ = prerequisites_available ? P2PState::Relay : P2PState::Unavailable;
        return true;
    }

    bool Disable() noexcept {
        if (state_ == P2PState::Disabled) return false;
        if (state_ == P2PState::Eligible || state_ == P2PState::Probing ||
            state_ == P2PState::Direct || state_ == P2PState::Suspect) {
            return false;
        }
        state_ = P2PState::Disabled;
        return true;
    }

private:
    bool Move(P2PState from, P2PState to) noexcept {
        if (state_ != from) return false;
        state_ = to;
        return true;
    }

    P2PState state_ = P2PState::Relay;
    P2PFallbackReason fallback_reason_ = P2PFallbackReason::None;
};

}
