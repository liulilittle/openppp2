#pragma once

#include <ppp/p2p/P2PControlStateMachine.h>

#include <cstdint>
#include <mutex>
#include <optional>

namespace ppp::p2p {

class P2PDirectActivationCoordinator final {
public:
    bool Begin(std::uint64_t generation) noexcept;
    bool StageAuthenticatedAck(P2PAuthenticatedProbeAck&& ack,
        std::uint64_t generation) noexcept;
    bool Activate(bool data_channel_ready, std::uint64_t generation) noexcept;
    bool MarkSuspect(std::uint64_t generation) noexcept;
    bool AcceptRecoveryAck(P2PAuthenticatedProbeAck&& ack,
        std::uint64_t generation) noexcept;
    bool RecoverFromAuthenticatedData(std::uint64_t generation) noexcept;
    bool Fallback(P2PFallbackReason reason, bool relay_prerequisites_available,
        std::uint64_t generation) noexcept;
    bool Reset(std::uint64_t generation) noexcept;

    P2PState State() const noexcept;
    const char* EffectivePath() const noexcept;
    bool HasPendingAck() const noexcept;

private:
    mutable std::mutex mutex_;
    P2PControlStateMachine state_machine_;
    std::optional<P2PAuthenticatedProbeAck> pending_ack_;
    std::uint64_t generation_ = 0;
};

}
