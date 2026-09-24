#pragma once

/**
 * @file MuxRetransmitBuffer.h
 * @brief Sender-side retransmission buffer for the vmux reliability
 *        sub-protocol (QUIC-style ACK + fast retransmit + PTO).
 * @license GPL-3.0
 *
 * Retains a shared_ptr copy of every reliably-sent frame until the peer's ACK
 * covers it, so a lost frame can be re-sent on another live carrier link with
 * its ORIGINAL sequence number (the receiver deduplicates). Keyed by
 * (connection_id, sequence); under ordering_compat the caller uses
 * connection_id 0 because the sequence space is already session-global.
 *
 * Bounded: a session-wide byte cap (Track fails when exceeded; the caller
 * degrades to fail_flow / session rebuild) and per-frame attempt accounting
 * (the caller tears down when attempts are exhausted).
 *
 * Not thread-safe: strand-affine by design, like the rest of vmux state.
 */

#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <unordered_map>
#include <vector>

#include <ppp/app/mux/MuxAckTracker.h>

namespace ppp::app::mux {

/** One retained outbound frame awaiting peer acknowledgment. */
struct MuxRtxEntry final {
    std::shared_ptr<std::uint8_t> buffer;         ///< Full vmux frame (header + payload).
    int                           length = 0;     ///< Frame length in bytes.
    std::uint64_t                 first_sent_tick = 0; ///< Tick of the first transmission.
    std::uint64_t                 last_sent_tick = 0;  ///< Tick of the most recent (re)transmission.
    std::uint32_t                 attempts = 0;   ///< Retransmissions already performed.
    std::uint32_t                 fast_rtx_mark = 0;   ///< largest-acked value at the last fast retransmit (dedup).
    std::uint16_t                 orig_link_id = 0;  ///< Carrier link the frame was FIRST sent on (for per-link RTT attribution).
    std::uint16_t                 last_link_id = 0;  ///< Carrier link the frame was most recently (re)sent on (for per-link PTO).
    std::list<std::uint64_t>::iterator order;     ///< Position in the insertion-ordered list (stable iterator).
};

class MuxRetransmitBuffer final {
public:
    /** Pack (connection_id, sequence) into one ordering key. */
    static constexpr std::uint64_t Key(std::uint32_t connection_id, std::uint32_t sequence) noexcept {
        return (static_cast<std::uint64_t>(connection_id) << 32) | sequence;
    }

    static constexpr std::uint32_t KeyCid(std::uint64_t key) noexcept {
        return static_cast<std::uint32_t>(key >> 32);
    }

    /**
     * Retain one freshly-sent frame.
     * @return false when the byte cap would be exceeded (caller degrades).
     */
    bool Track(
        std::uint32_t connection_id,
        std::uint32_t sequence,
        const std::shared_ptr<std::uint8_t>& buffer,
        int length,
        std::uint64_t now,
        std::size_t byte_cap,
        std::uint16_t link_id = 0) {
        const std::uint64_t key = Key(connection_id, sequence);
        if (entries_.find(key) != entries_.end()) {
            return true; // Already tracked (defensive; sends are unique per key).
        }
        if (byte_cap > 0 && bytes_ + static_cast<std::size_t>(length) > byte_cap) {
            return false;
        }

        order_.emplace_back(key);
        MuxRtxEntry entry;
        entry.buffer = buffer;
        entry.length = length;
        entry.first_sent_tick = now;
        entry.last_sent_tick = now;
        entry.orig_link_id = link_id;
        entry.last_link_id = link_id;
        entry.order = (--order_.end());
        entries_.emplace(key, std::move(entry));
        bytes_ += static_cast<std::size_t>(length);
        return true;
    }

    /**
     * Release every entry of @p connection_id covered by the ACK ranges and
     * collect fast-retransmit candidates: entries whose sequence sits at least
     * @p fast_threshold below @p largest (approximating "N later frames were
     * acked above the hole", the QUIC dup-ACK rule) AND whose first_sent_tick
     * is at least @p fast_time_threshold ago (QUIC time threshold ≈ SRTT/4).
     * A candidate is reported at most once per advancing @p largest.
     * @return RTT sample in ms from the first newly-acked entry that was never
     *         retransmitted (Karn's rule); 0 when no usable sample exists.
     */
    std::uint64_t Ack(
        std::uint32_t connection_id,
        std::uint32_t largest,
        const std::vector<MuxAckRange>& ranges,
        std::uint64_t now,
        std::uint32_t fast_threshold,
        std::uint64_t fast_time_threshold,
        std::vector<std::uint64_t>& fast_candidates,
        std::uint16_t* out_link_id = nullptr) {
        std::uint64_t rtt_sample = 0;
        if (nullptr != out_link_id) {
            *out_link_id = 0;
        }

        // Collect keys first: erasing while iterating the map is fine, but the
        // candidate scan below walks the whole map anyway, so do one pass.
        std::vector<std::uint64_t> acked;
        for (auto it = entries_.begin(); it != entries_.end(); ++it) {
            if (KeyCid(it->first) != connection_id) {
                continue;
            }
            const std::uint32_t seq = static_cast<std::uint32_t>(it->first & 0xFFFFFFFFu);
            for (const MuxAckRange& range : ranges) {
                if (seq >= range.start && seq <= range.end) {
                    acked.push_back(it->first);
                    break;
                }
            }
        }

        for (std::uint64_t key : acked) {
            auto it = entries_.find(key);
            if (it == entries_.end()) {
                continue;
            }
            if (rtt_sample == 0 && it->second.attempts == 0 && now >= it->second.first_sent_tick) {
                rtt_sample = now - it->second.first_sent_tick;
                if (nullptr != out_link_id) {
                    *out_link_id = it->second.orig_link_id;
                }
            }
            bytes_ -= static_cast<std::size_t>(it->second.length);
            order_.erase(it->second.order);
            entries_.erase(it);
        }

        // Fast-retransmit candidates: unacked entries of this space with at
        // least fast_threshold acked sequences above them.
        for (auto& kv : entries_) {
            if (KeyCid(kv.first) != connection_id) {
                continue;
            }
            const std::uint32_t seq = static_cast<std::uint32_t>(kv.first & 0xFFFFFFFFu);
            if (!(largest > seq)) {
                continue;
            }
            if (static_cast<std::uint32_t>(largest - seq) < fast_threshold) {
                continue;
            }
            MuxRtxEntry& entry = kv.second;
            if (entry.fast_rtx_mark == largest) {
                continue; // Already fast-retransmitted for this largest.
            }
            // Time threshold (QUIC ≈ SRTT/4): skip entries that were sent
            // too recently — the gap might just be normal reordering on a
            // heterogeneous multi-path link. 0 disables the time gate.
            if (fast_time_threshold > 0 && now >= entry.first_sent_tick &&
                (now - entry.first_sent_tick) < fast_time_threshold) {
                continue;
            }
            entry.fast_rtx_mark = largest;
            fast_candidates.push_back(kv.first);
        }

        return rtt_sample;
    }

    /**
     * Collect keys whose last (re)transmission is older than the per-entry
     * exponential-backoff PTO, oldest first, bounded by @p max_count.
     *
     * Each entry's timeout is  base_pto << min(attempts, 5)  using saturating
     * shift-left (so it never overflows to zero), then clamped to @p pto_max.
     * This prevents the 8 retransmissions from firing in a flat 8*PTO burst
     * and instead follows the QUIC/RFC 6298 exponential backoff principle.
     */
    void CollectExpired(std::uint64_t now, std::uint64_t base_pto,
        std::uint64_t pto_max, std::size_t max_count,
        std::vector<std::uint64_t>& expired) const {
        for (const auto& kv : entries_) {
            if (expired.size() >= max_count) {
                break;
            }
            const MuxRtxEntry& entry = kv.second;
            if (now < entry.last_sent_tick) {
                continue;
            }
            // Saturating shift-left: base_pto << shift, clamped to UINT64_MAX.
            const std::uint32_t shift = entry.attempts > 5 ? 5 : entry.attempts;
            std::uint64_t effective = base_pto;
            for (std::uint32_t s = 0; s < shift; ++s) {
                if (effective > (UINT64_MAX >> 1)) {
                    effective = UINT64_MAX;
                    break;
                }
                effective <<= 1;
            }
            if (effective > pto_max) {
                effective = pto_max;
            }
            if ((now - entry.last_sent_tick) >= effective) {
                expired.push_back(kv.first);
            }
        }
    }

    MuxRtxEntry* Find(std::uint64_t key) noexcept {
        auto it = entries_.find(key);
        return it == entries_.end() ? nullptr : &it->second;
    }

    /** Account one retransmission of @p key on @p link_id. */
    void MarkRetransmitted(std::uint64_t key, std::uint64_t now,
        std::uint16_t link_id = 0) noexcept {
        MuxRtxEntry* entry = Find(key);
        if (nullptr != entry) {
            entry->attempts++;
            entry->last_sent_tick = now;
            entry->last_link_id = link_id;
        }
    }

    /** Drop every entry of one connection space (flow reset / flow release). */
    void EraseCid(std::uint32_t connection_id) {
        for (auto it = entries_.begin(); it != entries_.end();) {
            if (KeyCid(it->first) == connection_id) {
                bytes_ -= static_cast<std::size_t>(it->second.length);
                order_.erase(it->second.order);
                it = entries_.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    void Clear() noexcept {
        entries_.clear();
        order_.clear();
        bytes_ = 0;
    }

    std::size_t size() const noexcept { return entries_.size(); }
    std::size_t bytes() const noexcept { return bytes_; }

private:
    // std::list iterators are stable across insert/erase, so each entry can
    // store its position for O(1) removal from the insertion-ordered list.
    std::list<std::uint64_t>                                       order_;
    std::unordered_map<std::uint64_t, MuxRtxEntry>                 entries_;
    std::size_t                                                    bytes_ = 0;
};

} // namespace ppp::app::mux
