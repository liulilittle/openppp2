#include <ppp/stdafx.h>
#include <ppp/p2p/P2PDirectActivationCoordinator.h>

namespace ppp::p2p {

bool P2PDirectActivationCoordinator::Begin(std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation < generation_) return false;

    generation_ = generation;
    pending_ack_.reset();
    state_machine_ = {};
    return state_machine_.MarkEligible() && state_machine_.AcceptOffer();
}

bool P2PDirectActivationCoordinator::StageAuthenticatedAck(
    P2PAuthenticatedProbeAck&& ack, std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation != generation_ || state_machine_.State() != P2PState::Probing ||
        pending_ack_) return false;

    pending_ack_.emplace(std::move(ack));
    return true;
}

bool P2PDirectActivationCoordinator::Activate(
    bool data_channel_ready, std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!data_channel_ready || generation != generation_ || !pending_ack_) return false;

    auto ack = std::move(*pending_ack_);
    pending_ack_.reset();
    return state_machine_.AcceptProbeAck(std::move(ack));
}

bool P2PDirectActivationCoordinator::MarkSuspect(
    std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation != generation_) return false;
    return state_machine_.MarkSuspect();
}

bool P2PDirectActivationCoordinator::AcceptRecoveryAck(
    P2PAuthenticatedProbeAck&& ack, std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation != generation_) return false;
    return state_machine_.AcceptRecoveryAck(std::move(ack));
}

bool P2PDirectActivationCoordinator::RecoverFromAuthenticatedData(
    std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation != generation_) return false;
    return state_machine_.RecoverFromAuthenticatedData();
}

bool P2PDirectActivationCoordinator::Fallback(P2PFallbackReason reason,
    bool relay_prerequisites_available, std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation != generation_) return false;

    pending_ack_.reset();
    return state_machine_.BeginFallback(reason) &&
        state_machine_.CompleteFallback(relay_prerequisites_available);
}

bool P2PDirectActivationCoordinator::Reset(std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation < generation_) return false;

    generation_ = generation;
    pending_ack_.reset();
    state_machine_ = {};
    return true;
}

P2PState P2PDirectActivationCoordinator::State() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_machine_.State();
}

const char* P2PDirectActivationCoordinator::EffectivePath() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_machine_.EffectivePath();
}

bool P2PDirectActivationCoordinator::HasPendingAck() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_ack_.has_value();
}

}
