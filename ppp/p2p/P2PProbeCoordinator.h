#pragma once

#include <ppp/p2p/P2PControlPacket.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace ppp::p2p {

enum class P2PProbeRole : std::uint8_t {
    Controlling,
    Controlled,
};

// Controls which candidate family is attempted first. RelayFirst deliberately
// keeps a peer on the authenticated relay path and suppresses direct probes.
enum class P2PPeerPriority : std::uint8_t {
    IPv4First,
    IPv6First,
    RelayFirst,
};

constexpr const char* P2PPeerPriorityName(P2PPeerPriority priority) noexcept {
    switch (priority) {
    case P2PPeerPriority::IPv4First: return "ipv4-first";
    case P2PPeerPriority::IPv6First: return "ipv6-first";
    case P2PPeerPriority::RelayFirst: return "relay-first";
    }
    return "ipv6-first";
}

constexpr bool ParseP2PPeerPriority(const char* value,
    P2PPeerPriority& output) noexcept {
    if (!value) return false;
    const auto equal = [](const char* a, const char* b) {
        while (*a && *b && *a == *b) { ++a; ++b; }
        return *a == *b;
    };
    if (equal(value, "ipv4-first")) {
        output = P2PPeerPriority::IPv4First;
        return true;
    }
    if (equal(value, "ipv6-first")) {
        output = P2PPeerPriority::IPv6First;
        return true;
    }
    if (equal(value, "relay-first")) {
        output = P2PPeerPriority::RelayFirst;
        return true;
    }
    return false;
}

struct P2PProbeCandidatePair {
    P2PCandidateEndpoint local;
    P2PCandidateEndpoint peer;

    friend bool operator==(const P2PProbeCandidatePair& a,
        const P2PProbeCandidatePair& b) noexcept {
        return a.local == b.local && a.peer == b.peer;
    }
};

struct P2PProbeTask {
    P2PProbeCandidatePair pair;
    std::size_t pair_index = 0;
    // The channel, not this scheduler, owns authenticated transaction IDs,
    // sequences, nonces and keys. Rounds are scheduling metadata only.
    std::uint8_t round = 0;
};

struct P2PProbeBatch {
    std::array<P2PProbeTask, 4> tasks{};
    std::size_t size = 0;
};

struct P2PProbeSnapshot {
    bool active = false;
    bool timed_out = false;
    P2PProbeRole role = P2PProbeRole::Controlling;
    std::uint64_t generation = 0;
    std::uint64_t deadline_ms = 0;
    std::size_t pair_count = 0;
    std::uint8_t emitted_rounds = 0;
    std::optional<std::size_t> nominated_pair;
    std::optional<std::size_t> acknowledged_pair;
    std::array<bool, 4> acknowledged_pairs{};
};

// A bounded, key-free scheduler. The owning channel/strand serializes calls.
// Nomination and ACK methods must only receive events authenticated by the
// v2 channel; they do not validate packets or create authentication proofs.
class P2PProbeCoordinator final {
public:
    static constexpr std::size_t MaxPairs = 4;
    static constexpr std::uint64_t RetryIntervalMs = 2000;
    static constexpr std::uint64_t ProbeWindowMs = 4000;
    static constexpr std::uint64_t SetupWindowMs = 10000;

    void SetPriority(P2PPeerPriority priority) noexcept;
    P2PPeerPriority Priority() const noexcept { return priority_; }

    bool Begin(P2PProbeRole role,
        const std::vector<P2PCandidateEndpoint>& local_candidates,
        const std::vector<P2PCandidateEndpoint>& peer_candidates,
        std::uint64_t now_ms,
        std::uint64_t generation) noexcept;

    // Both peers prime NAT filters with the original two-round budget. An
    // authenticated controlling-peer Commit narrows the controlled peer to
    // one pair without resetting its send budget, transactions or deadline.
    bool NominateResponderPair(const P2PProbeCandidatePair& pair,
        std::uint64_t now_ms,
        std::uint64_t generation) noexcept;

    P2PProbeBatch Poll(std::uint64_t now_ms,
        std::uint64_t generation) noexcept;
    bool OnAuthenticatedAck(std::size_t pair_index,
        std::uint64_t now_ms,
        std::uint64_t generation) noexcept;
    std::optional<std::size_t> FindPair(
        const P2PProbeCandidatePair& pair) const noexcept;
    std::optional<P2PProbeCandidatePair> Pair(
        std::size_t pair_index) const noexcept;
    P2PProbeSnapshot Snapshot() const noexcept;
    bool Cancel(std::uint64_t generation) noexcept;

private:
    bool active_ = false;
    bool timed_out_ = false;
    bool probing_started_ = false;
    bool cancelled_ = true;
    P2PProbeRole role_ = P2PProbeRole::Controlling;
    std::uint64_t generation_ = 0;
    std::uint64_t started_at_ms_ = 0;
    std::uint64_t setup_deadline_ms_ = 0;
    std::uint64_t deadline_ms_ = 0;
    std::array<P2PProbeCandidatePair, MaxPairs> pairs_{};
    std::size_t pair_count_ = 0;
    std::uint8_t emitted_rounds_ = 0;
    std::optional<std::size_t> nominated_pair_;
    std::optional<std::size_t> acknowledged_pair_;
    std::array<bool, MaxPairs> acknowledged_pairs_{};
    P2PPeerPriority priority_ = P2PPeerPriority::IPv6First;
};

}
