#pragma once

#include <boost/asio/ip/address.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace ppp::p2p {

struct P2PIngressLimiterSnapshot {
    std::size_t source_entries = 0;
    std::size_t session_entries = 0;
};

// Apply the source bucket before posting/allocating unauthenticated work, then
// the session bucket on its owning strand. Both operations are thread safe.
// The caller exempts normal data only from the authenticated chosen endpoint;
// the limiter itself never treats a claimed packet type as authentication.
class P2PIngressLimiter final {
public:
    using SessionId = std::array<std::uint8_t, 16>;
    static constexpr std::size_t MaxEntries = 256;
    static constexpr std::uint64_t IdleExpiryMs = 60000;
    static constexpr std::uint32_t SourcePacketsPerSecond = 4;
    static constexpr std::uint32_t SourceBurst = 8;
    static constexpr std::uint32_t SessionPacketsPerSecond = 8;
    static constexpr std::uint32_t SessionBurst = 16;

    bool AllowSource(const boost::asio::ip::address& source,
        std::uint64_t now_ms) noexcept;
    bool AllowSession(const SessionId& session,
        std::uint64_t now_ms) noexcept;
    void Clear() noexcept;
    P2PIngressLimiterSnapshot Snapshot() const noexcept;

private:
    using Key = std::array<std::uint8_t, 16>;
    struct Entry {
        Key key{};
        std::uint64_t refill_at_ms = 0;
        std::uint64_t seen_at_ms = 0;
        // Integer millitokens make a packet cost exactly 1000 units.
        std::uint32_t tokens = 0;
        bool used = false;
    };
    using Table = std::array<Entry, MaxEntries>;

    bool AllowLocked(Table& table, const Key& key,
        std::uint32_t packets_per_second,
        std::uint32_t burst,
        std::uint64_t now_ms) noexcept;

    mutable std::mutex mutex_;
    Table sources_{};
    Table sessions_{};
};

}
