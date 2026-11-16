#pragma once

#include <array>
#include <cstdint>
#include <limits>

namespace ppp::p2p {

// Serialized by the server's pair-table lock; no client clock is trusted.
struct P2PV2ServerCoordination {
    using Hash = std::array<std::uint8_t, 32>;
    std::uint64_t Generation = 0, StartedAt = 0, LastOfferAt = 0;
    std::uint64_t CurrentExpiresAt = 0, PendingExpiresAt = 0;
    Hash CurrentHash{}, PendingHash{};
    bool Generating = false, InitiatorActive = false, ResponderActive = false;

    void ClearPending() noexcept {
        Generating = false;
        PendingHash = {};
        StartedAt = PendingExpiresAt = 0;
        InitiatorActive = ResponderActive = false;
    }
    bool ExpirePending(std::uint64_t now) noexcept {
        if ((Generating && now >= StartedAt && now - StartedAt >= 10000) ||
            (PendingExpiresAt && now >= PendingExpiresAt)) {
            ClearPending();
            return true;
        }
        return false;
    }
    bool Begin(std::uint64_t now, std::uint64_t generation,
        bool explicit_renew = false) noexcept {
        if (!generation || generation <= Generation || Generating || PendingHash != Hash{} ||
            (Generation && (now < LastOfferAt ||
                (!explicit_renew && now - LastOfferAt < 10000u)))) return false;
        Generation = generation;
        Generating = true;
        StartedAt = LastOfferAt = now;
        InitiatorActive = ResponderActive = false;
        return true;
    }
    bool Complete(std::uint64_t generation, const Hash& hash, std::uint64_t now) noexcept {
        if (!Generating || Generation != generation || now < StartedAt ||
            now - StartedAt >= 10000 || hash == Hash{}) return false;
        Generating = false;
        PendingHash = hash;
        StartedAt = now;
        PendingExpiresAt = Deadline(now);
        return true;
    }
    bool CanSend(std::uint64_t generation, const Hash& hash, std::uint64_t now) const noexcept {
        return Generation == generation && PendingHash == hash && hash != Hash{} &&
            PendingExpiresAt && now < PendingExpiresAt;
    }
    bool Cancel(const Hash& predecessor, const Hash& pending) noexcept {
        if (CurrentHash != predecessor || pending == Hash{} || PendingHash != pending ||
            InitiatorActive || ResponderActive) return false;
        ClearPending();
        return true;
    }
    // 0 = rejected, 1 = waiting for peer, 2 = current (also idempotent).
    unsigned Activate(const Hash& hash, bool initiator, std::uint64_t now) noexcept {
        if (hash == Hash{}) return 0;
        if (CurrentHash == hash) return CurrentExpiresAt && now < CurrentExpiresAt ? 2 : 0;
        if (PendingHash != hash || !PendingExpiresAt || now >= PendingExpiresAt) return 0;
        (initiator ? InitiatorActive : ResponderActive) = true;
        if (!InitiatorActive || !ResponderActive) return 1;
        CurrentHash = PendingHash;
        // Reports may be delayed; this is a conservative upper bound for recovery.
        CurrentExpiresAt = Deadline(now);
        ClearPending();
        return 2;
    }
    bool MatchesPredecessor(const Hash& hash, std::uint64_t now) noexcept {
        if (hash == Hash{} && CurrentExpiresAt && now >= CurrentExpiresAt) {
            CurrentHash = {};
            CurrentExpiresAt = 0;
        }
        return CurrentHash == hash;
    }
    // An authenticated client may have discarded its local channel while the
    // server still holds the previous key (for example after relay-first).
    // Clear the server-side predecessor so the next renew can converge
    // immediately instead of waiting for the 60-second key expiry.
    void ResetForExplicitRenew() noexcept {
        CurrentHash = {};
        CurrentExpiresAt = 0;
        ClearPending();
    }
    bool PrepareOffer(std::uint64_t now, bool explicit_renew) noexcept {
        // Explicit renew already authenticated its predecessor under this lock.
        if (explicit_renew) return true;
        if (CurrentHash != Hash{} && now < CurrentExpiresAt) return false;
        MatchesPredecessor({}, now);
        return true;
    }
private:
    static std::uint64_t Deadline(std::uint64_t now) noexcept {
        const auto max = std::numeric_limits<std::uint64_t>::max();
        return now > max - 60000 ? max : now + 60000;
    }
};

}
