#pragma once

/**
 * @file MuxAckTracker.h
 * @brief QUIC-style received-sequence range tracking and ACK frame wire codec
 *        for the vmux reliability sub-protocol.
 * @license GPL-3.0
 *
 * One tracker instance covers ONE sequence space: the single global space under
 * ordering_compat (keyed with connection_id 0 on the wire), or one per-flow DSN
 * space under flow_v2. Ranges are inclusive [start, end], stored ascending,
 * merged on insert, and hard-capped so a malicious or flaky peer cannot make
 * the ACK state grow without bound.
 *
 * Sequence wrap: the vmux sequence space is 32-bit. Trackers use plain uint32
 * ordering; a backwards jump past half the sequence space is treated as a wrap
 * and resets the tracker (the sender then falls back to PTO once). This keeps
 * the structure O(ranges) with no circular-order corner cases.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

namespace ppp::app::mux {

/** Inclusive received-sequence range [start, end]. */
struct MuxAckRange final {
    std::uint32_t start = 0;
    std::uint32_t end   = 0;
};

/** Received-sequence range set for one sequence space. */
class MuxAckTracker final {
public:
    /**
     * Record one received sequence number, merging adjacent/overlapping ranges.
     * @param seq Received sequence (0 is valid: flow_v2 control placeholder).
     * @param max_ranges Hard cap; when merging cannot stay below it, the oldest
     *        (lowest) ranges are dropped — they are the ones most likely already
     *        covered by an earlier ACK, and the sender re-covers them via PTO.
     */
    void Add(std::uint32_t seq, std::size_t max_ranges) {
        if (!ranges_.empty()) {
            const std::uint32_t front = ranges_.front().start;
            // Wrap heuristic: a sequence more than half the space behind the
            // oldest tracked value means the counter wrapped; restart tracking.
            if (static_cast<std::uint32_t>(front - seq) > 0x80000000u && seq < front) {
                ranges_.clear();
            }
        }

        // A range and seq are disjoint-below when the range ends more than one
        // below seq; disjoint-above when it starts more than one above seq.
        // Anything else overlaps or is adjacent and must be merged.
        auto disjoint_below = [seq](const MuxAckRange& r) noexcept {
            return r.end < seq && (seq - r.end) > 1;
        };
        auto disjoint_above = [seq](const MuxAckRange& r) noexcept {
            return r.start > seq && (r.start - seq) > 1;
        };

        // Find the first range not strictly below seq (linear: ranges are few,
        // capped by max_ranges).
        std::size_t i = 0;
        const std::size_t n = ranges_.size();
        while (i < n && disjoint_below(ranges_[i])) {
            ++i;
        }

        if (i < n && !disjoint_above(ranges_[i])) {
            // Overlapping or adjacent: merge into ranges_[i].
            if (seq < ranges_[i].start) {
                ranges_[i].start = seq;
            }
            if (seq > ranges_[i].end) {
                ranges_[i].end = seq;
            }
            // Absorb following ranges that now overlap or touch.
            while (i + 1 < ranges_.size() &&
                   !(ranges_[i + 1].start > ranges_[i].end && (ranges_[i + 1].start - ranges_[i].end) > 1)) {
                if (ranges_[i + 1].end > ranges_[i].end) {
                    ranges_[i].end = ranges_[i + 1].end;
                }
                ranges_.erase(ranges_.begin() + (i + 1));
            }
        }
        else {
            ranges_.insert(ranges_.begin() + i, MuxAckRange{ seq, seq });
        }

        if (max_ranges > 0) {
            while (ranges_.size() > max_ranges) {
                ranges_.erase(ranges_.begin()); // Drop oldest; PTO re-covers.
            }
        }
    }

    bool empty() const noexcept { return ranges_.empty(); }
    void Clear() noexcept { ranges_.clear(); }
    std::size_t size() const noexcept { return ranges_.size(); }

    /** Highest tracked sequence; 0 when empty. */
    std::uint32_t largest() const noexcept {
        return ranges_.empty() ? 0 : ranges_.back().end;
    }

    const std::vector<MuxAckRange>& ranges() const noexcept { return ranges_; }

private:
    std::vector<MuxAckRange> ranges_;
};

/** One decoded ACK block: ranges for one sequence space (connection_id). */
struct MuxAckBlock final {
    std::uint32_t              connection_id = 0; ///< 0 = compat global space.
    std::uint32_t              largest = 0;
    std::vector<MuxAckRange>   ranges;
};

/**
 * ACK frame payload wire format (all integers big-endian):
 *   block_count(1)
 *   per block: connection_id(4) largest(4) range_count(1) { start(4) end(4) }*
 */

/** Maximum wire size of an ACK payload with the given block/range caps. */
inline std::size_t MuxAckFrameMaxSize(std::size_t max_blocks, std::size_t max_ranges) noexcept {
    return 1 + max_blocks * (9 + max_ranges * 8);
}

/**
 * Encode ACK blocks into @p out.
 * @return Payload length, or 0 when @p cap is insufficient (caller must not send).
 */
inline std::size_t EncodeMuxAckFrame(
    const MuxAckBlock* blocks,
    std::size_t block_count,
    std::uint8_t* out,
    std::size_t cap,
    std::size_t max_ranges_per_block) noexcept {
    if (nullptr == out || block_count > 255) {
        return 0;
    }

    std::size_t need = 1;
    for (std::size_t b = 0; b < block_count; ++b) {
        const std::size_t range_count = blocks[b].ranges.size() < max_ranges_per_block
            ? blocks[b].ranges.size()
            : max_ranges_per_block;
        need += 9 + range_count * 8;
    }
    if (cap < need) {
        return 0;
    }

    std::uint8_t* w = out;
    *w++ = static_cast<std::uint8_t>(block_count);
    for (std::size_t b = 0; b < block_count; ++b) {
        const MuxAckBlock& block = blocks[b];
        const std::uint32_t cid = block.connection_id;
        const std::uint32_t largest = block.largest;
        *w++ = static_cast<std::uint8_t>((cid >> 24) & 0xFF);
        *w++ = static_cast<std::uint8_t>((cid >> 16) & 0xFF);
        *w++ = static_cast<std::uint8_t>((cid >> 8) & 0xFF);
        *w++ = static_cast<std::uint8_t>(cid & 0xFF);
        *w++ = static_cast<std::uint8_t>((largest >> 24) & 0xFF);
        *w++ = static_cast<std::uint8_t>((largest >> 16) & 0xFF);
        *w++ = static_cast<std::uint8_t>((largest >> 8) & 0xFF);
        *w++ = static_cast<std::uint8_t>(largest & 0xFF);

        const std::vector<MuxAckRange>& ranges = block.ranges;
        std::size_t range_count = ranges.size() < max_ranges_per_block
            ? ranges.size()
            : max_ranges_per_block;
        // Send the NEWEST ranges when capped: they carry the loss signal.
        const std::size_t first = ranges.size() - range_count;
        *w++ = static_cast<std::uint8_t>(range_count);
        for (std::size_t r = first; r < ranges.size(); ++r) {
            const std::uint32_t start = ranges[r].start;
            const std::uint32_t end = ranges[r].end;
            *w++ = static_cast<std::uint8_t>((start >> 24) & 0xFF);
            *w++ = static_cast<std::uint8_t>((start >> 16) & 0xFF);
            *w++ = static_cast<std::uint8_t>((start >> 8) & 0xFF);
            *w++ = static_cast<std::uint8_t>(start & 0xFF);
            *w++ = static_cast<std::uint8_t>((end >> 24) & 0xFF);
            *w++ = static_cast<std::uint8_t>((end >> 16) & 0xFF);
            *w++ = static_cast<std::uint8_t>((end >> 8) & 0xFF);
            *w++ = static_cast<std::uint8_t>(end & 0xFF);
        }
    }

    return static_cast<std::size_t>(w - out);
}

/**
 * Decode an ACK payload. Strictly bounds-checked; rejects truncated or
 * inconsistent input (range_count overflow, start > end, end > largest).
 * @param max_blocks Cap on decoded blocks (DoS bound).
 * @param max_ranges Cap on decoded ranges per block (DoS bound).
 * @return true when the payload is well-formed.
 */
inline bool DecodeMuxAckFrame(
    const std::uint8_t* p,
    std::size_t len,
    std::size_t max_blocks,
    std::size_t max_ranges,
    std::vector<MuxAckBlock>& out) noexcept {
    out.clear();
    if (nullptr == p || len < 1) {
        return false;
    }

    const std::uint8_t block_count = *p++;
    --len;
    if (block_count == 0 || block_count > max_blocks) {
        return false;
    }

    out.reserve(block_count);
    for (std::size_t b = 0; b < block_count; ++b) {
        if (len < 9) {
            out.clear();
            return false;
        }

        MuxAckBlock block;
        block.connection_id =
            (static_cast<std::uint32_t>(p[0]) << 24) |
            (static_cast<std::uint32_t>(p[1]) << 16) |
            (static_cast<std::uint32_t>(p[2]) << 8) |
            static_cast<std::uint32_t>(p[3]);
        block.largest =
            (static_cast<std::uint32_t>(p[4]) << 24) |
            (static_cast<std::uint32_t>(p[5]) << 16) |
            (static_cast<std::uint32_t>(p[6]) << 8) |
            static_cast<std::uint32_t>(p[7]);
        const std::uint8_t range_count = p[8];
        p += 9;
        len -= 9;

        if (range_count == 0 || range_count > max_ranges || len < static_cast<std::size_t>(range_count) * 8) {
            out.clear();
            return false;
        }

        block.ranges.reserve(range_count);
        for (std::size_t r = 0; r < range_count; ++r) {
            MuxAckRange range;
            range.start =
                (static_cast<std::uint32_t>(p[0]) << 24) |
                (static_cast<std::uint32_t>(p[1]) << 16) |
                (static_cast<std::uint32_t>(p[2]) << 8) |
                static_cast<std::uint32_t>(p[3]);
            range.end =
                (static_cast<std::uint32_t>(p[4]) << 24) |
                (static_cast<std::uint32_t>(p[5]) << 16) |
                (static_cast<std::uint32_t>(p[6]) << 8) |
                static_cast<std::uint32_t>(p[7]);
            p += 8;
            len -= 8;

            if (range.start > range.end || range.end > block.largest) {
                out.clear();
                return false;
            }
            block.ranges.push_back(range);
        }

        out.push_back(std::move(block));
    }

    if (len != 0) {
        out.clear();
        return false; // Trailing garbage: malformed.
    }

    return true;
}

} // namespace ppp::app::mux
