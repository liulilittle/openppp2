#pragma once

#include <ppp/app/runtime/RuntimeReadiness.h>
#include <ppp/app/runtime/RuntimeSnapshotPublisher.h>
#include <ppp/app/runtime/RuntimeStopCoordinator.h>
#include <ppp/app/mux/MuxRuntimeState.h>

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <utility>

namespace ppp::app::runtime {

class RuntimeLifecycle final {
public:
    using Listener = RuntimeSnapshotPublisher::Listener;

    std::uint64_t Begin(RuntimeSnapshot seed, std::uint64_t now) noexcept {
        RuntimeSnapshot snapshot;
        {
            std::lock_guard<std::mutex> scope(mutex_);
            const std::uint64_t generation = ++generation_;
            stop_coordinator_.BeginGeneration(generation);
            readiness_ = RuntimeReadiness();
            requested_phase_ = RuntimePhase::Starting;

            snapshot = std::move(seed);
            snapshot.generation = generation;
            snapshot.monotonic_ms = NextTimestamp(now);
            snapshot.phase = RuntimePhase::Starting;
            snapshot.connected_monotonic_ms = 0;
            current_ = snapshot;
        }
        publisher_.Publish(snapshot);
        return snapshot.generation;
    }

    bool Transition(
        std::uint64_t generation,
        RuntimePhase phase,
        std::uint64_t now) noexcept {
        RuntimeSnapshot snapshot;
        {
            std::lock_guard<std::mutex> scope(mutex_);
            if (generation == 0 || generation != generation_ ||
                stop_coordinator_.IsStopping(generation) ||
                stop_coordinator_.IsCompleted(generation)) {
                return false;
            }
            requested_phase_ = phase;
            current_.phase = GateConnectedPhase(phase, readiness_);
            current_.monotonic_ms = NextTimestamp(now);
            StampConnectedAt();
            snapshot = current_;
        }
        return publisher_.Publish(std::move(snapshot));
    }

    bool UpdateReadiness(
        std::uint64_t generation,
        RuntimeReadiness readiness,
        std::uint64_t now) noexcept {
        RuntimeSnapshot snapshot;
        {
            std::lock_guard<std::mutex> scope(mutex_);
            if (generation == 0 || generation != generation_ ||
                stop_coordinator_.IsStopping(generation) ||
                stop_coordinator_.IsCompleted(generation)) {
                return false;
            }
            readiness_ = readiness;
            if (requested_phase_ == RuntimePhase::Connected &&
                current_.phase != RuntimePhase::Stopping &&
                current_.phase != RuntimePhase::Idle &&
                current_.phase != RuntimePhase::Failed) {
                current_.phase = GateConnectedPhase(requested_phase_, readiness_);
            }
            current_.monotonic_ms = NextTimestamp(now);
            StampConnectedAt();
            snapshot = current_;
        }
        return publisher_.Publish(std::move(snapshot));
    }

    bool UpdateMuxState(
        std::uint64_t generation,
        const ppp::app::mux::MuxRuntimeState& state,
        std::uint64_t now) noexcept {
        RuntimeSnapshot snapshot;
        {
            std::lock_guard<std::mutex> scope(mutex_);
            if (generation == 0 || generation != generation_ ||
                stop_coordinator_.IsStopping(generation) ||
                stop_coordinator_.IsCompleted(generation)) {
                return false;
            }
            if (current_.requested_mux_mode == state.requested_mode &&
                current_.effective_mux_mode == state.effective_mode &&
                current_.mux_receiver_ordering == state.receiver_ordering &&
                current_.mux_scheduler == state.scheduler &&
                current_.mux_pool_policy == state.pool_policy &&
                current_.mux_turbo == state.turbo &&
                current_.mux_active_links == state.active_links &&
                current_.mux_fallback_reason == state.fallback_reason) {
                return true;
            }
            current_.requested_mux_mode = state.requested_mode;
            current_.effective_mux_mode = state.effective_mode;
            current_.mux_receiver_ordering = state.receiver_ordering;
            current_.mux_scheduler = state.scheduler;
            current_.mux_pool_policy = state.pool_policy;
            current_.mux_turbo = state.turbo;
            current_.mux_active_links = state.active_links;
            current_.mux_fallback_reason = state.fallback_reason;
            current_.monotonic_ms = NextTimestamp(now);
            snapshot = current_;
        }
        return publisher_.Publish(std::move(snapshot));
    }

    bool UpdateP2PState(
        std::uint64_t generation,
        ppp::p2p::P2PState state,
        std::uint64_t now) noexcept {
        RuntimeSnapshot snapshot;
        {
            std::lock_guard<std::mutex> scope(mutex_);
            if (generation == 0 || generation != generation_ ||
                stop_coordinator_.IsStopping(generation) ||
                stop_coordinator_.IsCompleted(generation)) {
                return false;
            }
            if (current_.p2p_state == state) {
                return true;
            }
            current_.p2p_state = state;
            current_.monotonic_ms = NextTimestamp(now);
            snapshot = current_;
        }
        return publisher_.Publish(std::move(snapshot));
    }

    bool UpdateTraffic(
        std::uint64_t generation,
        const RuntimeTraffic& traffic,
        std::uint64_t now) noexcept {
        RuntimeSnapshot snapshot;
        {
            std::lock_guard<std::mutex> scope(mutex_);
            if (generation == 0 || generation != generation_ ||
                stop_coordinator_.IsStopping(generation) ||
                stop_coordinator_.IsCompleted(generation)) {
                return false;
            }
            if (current_.traffic.rx_bytes == traffic.rx_bytes &&
                current_.traffic.tx_bytes == traffic.tx_bytes) {
                return true;
            }
            current_.traffic = traffic;
            current_.monotonic_ms = NextTimestamp(now);
            snapshot = current_;
        }
        return publisher_.Publish(std::move(snapshot));
    }

    bool TryBeginStop(std::uint64_t generation, std::uint64_t now) noexcept {
        RuntimeSnapshot snapshot;
        {
            std::lock_guard<std::mutex> scope(mutex_);
            if (generation == 0 || generation != generation_ ||
                !stop_coordinator_.TryBeginStop(generation)) {
                return false;
            }
            requested_phase_ = RuntimePhase::Stopping;
            current_.phase = RuntimePhase::Stopping;
            if (current_.p2p_state == ppp::p2p::P2PState::Eligible ||
                current_.p2p_state == ppp::p2p::P2PState::Probing ||
                current_.p2p_state == ppp::p2p::P2PState::Direct ||
                current_.p2p_state == ppp::p2p::P2PState::Suspect) {
                current_.p2p_state = ppp::p2p::P2PState::FallingBack;
            }
            current_.monotonic_ms = NextTimestamp(now);
            StampConnectedAt();
            snapshot = current_;
        }
        return publisher_.Publish(std::move(snapshot));
    }

    bool CompleteStop(
        std::uint64_t generation,
        bool success,
        RuntimeError error,
        std::uint64_t now) noexcept {
        RuntimeSnapshot snapshot;
        {
            std::lock_guard<std::mutex> scope(mutex_);
            if (generation == 0 || generation != generation_ ||
                !stop_coordinator_.IsStopping(generation)) {
                return false;
            }
            stop_coordinator_.CompleteStop(generation, success);
            requested_phase_ = success ? RuntimePhase::Idle : RuntimePhase::Failed;
            current_.phase = requested_phase_;
            current_.mux_active_links = 0;
            current_.p2p_state = ppp::p2p::P2PState::Disabled;
            current_.last_error = success ? RuntimeError() : std::move(error);
            current_.monotonic_ms = NextTimestamp(now);
            StampConnectedAt();
            snapshot = current_;
        }
        return publisher_.Publish(std::move(snapshot));
    }

    RuntimeSnapshot GetSnapshot() const noexcept {
        return publisher_.GetLatest();
    }

    std::uint64_t Subscribe(Listener listener) noexcept {
        return publisher_.Subscribe(std::move(listener));
    }

    void Unsubscribe(std::uint64_t token) noexcept {
        publisher_.Unsubscribe(token);
    }

private:
    // Records when the session entered Connected so consumers can render an
    // elapsed time that survives their own process being restarted. Leaving
    // Connected clears it, so a reconnect starts a new interval.
    void StampConnectedAt() noexcept {
        if (current_.phase != RuntimePhase::Connected) {
            current_.connected_monotonic_ms = 0;
        }
        else if (current_.connected_monotonic_ms == 0) {
            current_.connected_monotonic_ms = current_.monotonic_ms;
        }
    }

    std::uint64_t NextTimestamp(std::uint64_t now) noexcept {
        const std::uint64_t minimum = current_.monotonic_ms + 1;
        return std::max(now, minimum);
    }

    mutable std::mutex mutex_;
    RuntimeSnapshotPublisher publisher_;
    RuntimeStopCoordinator stop_coordinator_;
    RuntimeSnapshot current_;
    RuntimeReadiness readiness_;
    RuntimePhase requested_phase_ = RuntimePhase::Idle;
    std::uint64_t generation_ = 0;
};

}
