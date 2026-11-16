#include <ppp/p2p/P2PIngressLimiter.h>

#include <algorithm>

namespace ppp::p2p {

bool P2PIngressLimiter::AllowSource(const boost::asio::ip::address& source,
    std::uint64_t now_ms) noexcept {
    if (source.is_unspecified()) return false;
    Key key{};
    if (source.is_v4()) {
        const auto bytes = source.to_v4().to_bytes();
        key[10] = 0xff;
        key[11] = 0xff;
        std::copy(bytes.begin(), bytes.end(), key.begin() + 12);
    }
    else {
        key = source.to_v6().to_bytes();
        // IPv4 and IPv4-mapped IPv6 share one source budget. Scope IDs are
        // deliberately excluded: an address cannot gain a budget per scope.
        if (source.to_v6().is_v4_mapped() &&
            std::all_of(key.begin() + 12, key.end(),
                [](std::uint8_t byte) noexcept { return byte == 0; })) {
            return false;
        }
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return AllowLocked(sources_, key,
        SourcePacketsPerSecond, SourceBurst, now_ms);
}

bool P2PIngressLimiter::AllowSession(const SessionId& session,
    std::uint64_t now_ms) noexcept {
    if (std::all_of(session.begin(), session.end(),
        [](std::uint8_t byte) noexcept { return byte == 0; })) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    return AllowLocked(sessions_, session,
        SessionPacketsPerSecond, SessionBurst, now_ms);
}

bool P2PIngressLimiter::AllowLocked(Table& table, const Key& key,
    std::uint32_t packets_per_second,
    std::uint32_t burst,
    std::uint64_t now_ms) noexcept {
    Entry* matching = nullptr;
    Entry* vacant = nullptr;
    for (auto& entry : table) {
        if (entry.used && now_ms >= entry.seen_at_ms &&
            now_ms - entry.seen_at_ms >= IdleExpiryMs) {
            entry = {};
        }
        if (entry.used && entry.key == key) matching = &entry;
        else if (!entry.used && !vacant) vacant = &entry;
    }
    if (!matching) {
        // Never evict an active source/session to admit unknown flood keys.
        if (!vacant) return false;
        *vacant = {key, now_ms, now_ms, burst * 1000, true};
        matching = vacant;
    }
    Entry& entry = *matching;
    const auto elapsed = now_ms >= entry.refill_at_ms
        ? now_ms - entry.refill_at_ms : 0;
    // Cap elapsed before multiplication, preventing overflow at large ticks.
    const std::uint64_t capacity = burst * 1000;
    const auto refill = std::min<std::uint64_t>(elapsed,
        (capacity + packets_per_second - 1) / packets_per_second) *
        packets_per_second;
    entry.tokens = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(capacity, entry.tokens + refill));
    entry.refill_at_ms = std::max(entry.refill_at_ms, now_ms);
    entry.seen_at_ms = std::max(entry.seen_at_ms, now_ms);
    if (entry.tokens < 1000) return false;
    entry.tokens -= 1000;
    return true;
}

void P2PIngressLimiter::Clear() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    sources_ = {};
    sessions_ = {};
}

P2PIngressLimiterSnapshot P2PIngressLimiter::Snapshot() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    P2PIngressLimiterSnapshot snapshot;
    for (const auto& entry : sources_) snapshot.source_entries += entry.used;
    for (const auto& entry : sessions_) snapshot.session_entries += entry.used;
    return snapshot;
}

}
