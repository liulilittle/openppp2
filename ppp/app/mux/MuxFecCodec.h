#pragma once

/**
 * @file MuxFecCodec.h
 * @brief XOR parity forward-error-correction codec for the vmux reliability
 *        sub-protocol.
 * @license GPL-3.0
 *
 * The sender groups every K reliable data frames and emits one cmd_fec parity
 * frame listing the covered (connection_id, sequence) pairs explicitly, so
 * grouping survives cross-link reordering and both ordering modes. The parity
 * block is the bytewise XOR of all covered frames, each prefixed with its
 * 2-byte big-endian length and zero-padded to the longest block. The receiver
 * can recover exactly ONE missing frame per group; two or more losses are left
 * to ACK-driven retransmission.
 *
 * Pure functions / ASIO-free value types: unit-testable in isolation.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

namespace ppp::app::mux {

/** (connection_id, sequence) identity of one FEC-covered frame. */
struct MuxFecFrameId final {
    std::uint32_t connection_id = 0;
    std::uint32_t sequence = 0;
};

/** Encode-side group accumulator: XORs frames as they are sent. */
class MuxFecEncoder final {
public:
    void Reset(std::uint64_t now) noexcept {
        entries_.clear();
        parity_.clear();
        first_add_tick_ = now;
    }

    /**
     * Fold one sent frame into the running parity.
     * @param frame Full vmux frame (header + payload).
     * @param length Frame length; caller guarantees it is within the FEC size limit.
     */
    void Add(std::uint32_t connection_id, std::uint32_t sequence,
        const std::uint8_t* frame, int length) {
        if (entries_.empty()) {
            parity_.assign(static_cast<std::size_t>(length) + 2, 0);
        }
        else if (parity_.size() < static_cast<std::size_t>(length) + 2) {
            parity_.resize(static_cast<std::size_t>(length) + 2, 0);
        }

        // Block layout: length(2, big-endian) || frame bytes; zero-padded to parity size.
        parity_[0] ^= static_cast<std::uint8_t>((static_cast<std::uint32_t>(length) >> 8) & 0xFF);
        parity_[1] ^= static_cast<std::uint8_t>(static_cast<std::uint32_t>(length) & 0xFF);
        for (int i = 0; i < length; ++i) {
            parity_[2 + i] ^= frame[i];
        }

        entries_.push_back(MuxFecFrameId{ connection_id, sequence });
    }

    int count() const noexcept { return static_cast<int>(entries_.size()); }
    std::uint64_t first_add_tick() const noexcept { return first_add_tick_; }
    const std::vector<MuxFecFrameId>& entries() const noexcept { return entries_; }

    /** Maximum wire size of a group payload with the current parity length. */
    std::size_t MaxPayloadSize() const noexcept {
        return 1 + entries_.size() * 8 + 2 + parity_.size();
    }

    /**
     * Serialize the group as a cmd_fec payload:
     *   count(1) | { connection_id(4) sequence(4) }*count | parity_len(2) | parity
     * @return Payload length, or 0 when @p cap is insufficient or the group is
     *         empty / too large for the 1-byte count field.
     */
    int Build(std::uint8_t* out, int cap) const {
        if (entries_.empty() || entries_.size() > 255 || parity_.size() > 0xFFFF) {
            return 0;
        }
        const std::size_t need = MaxPayloadSize();
        if (cap < 0 || static_cast<std::size_t>(cap) < need) {
            return 0;
        }

        std::uint8_t* w = out;
        *w++ = static_cast<std::uint8_t>(entries_.size());
        for (const MuxFecFrameId& id : entries_) {
            *w++ = static_cast<std::uint8_t>((id.connection_id >> 24) & 0xFF);
            *w++ = static_cast<std::uint8_t>((id.connection_id >> 16) & 0xFF);
            *w++ = static_cast<std::uint8_t>((id.connection_id >> 8) & 0xFF);
            *w++ = static_cast<std::uint8_t>(id.connection_id & 0xFF);
            *w++ = static_cast<std::uint8_t>((id.sequence >> 24) & 0xFF);
            *w++ = static_cast<std::uint8_t>((id.sequence >> 16) & 0xFF);
            *w++ = static_cast<std::uint8_t>((id.sequence >> 8) & 0xFF);
            *w++ = static_cast<std::uint8_t>(id.sequence & 0xFF);
        }
        const std::size_t parity_len = parity_.size();
        *w++ = static_cast<std::uint8_t>((parity_len >> 8) & 0xFF);
        *w++ = static_cast<std::uint8_t>(parity_len & 0xFF);
        std::memcpy(w, parity_.data(), parity_len);
        w += parity_len;

        return static_cast<int>(w - out);
    }

private:
    std::vector<MuxFecFrameId> entries_;
    std::vector<std::uint8_t>  parity_;     ///< Running XOR block (2-byte length prefix + frame bytes, zero-padded).
    std::uint64_t              first_add_tick_ = 0;
};

/** Decoded view of one received cmd_fec payload. */
struct MuxFecFrameView final {
    std::vector<MuxFecFrameId> entries;
    std::vector<std::uint8_t>  parity;      ///< Copied parity block (outlives the receive buffer).
};

/**
 * Parse a cmd_fec payload. Strictly bounds-checked.
 * @param max_count Cap on covered entries (DoS bound).
 * @return true when well-formed.
 */
inline bool ParseMuxFecFrame(const std::uint8_t* p, int len, int max_count, MuxFecFrameView& out) {
    out.entries.clear();
    out.parity.clear();
    if (nullptr == p || len < 1) {
        return false;
    }

    const std::uint8_t count = *p++;
    --len;
    if (count == 0 || count > max_count || len < static_cast<int>(count) * 8 + 2) {
        return false;
    }

    out.entries.reserve(count);
    for (int i = 0; i < count; ++i) {
        MuxFecFrameId id;
        id.connection_id =
            (static_cast<std::uint32_t>(p[0]) << 24) |
            (static_cast<std::uint32_t>(p[1]) << 16) |
            (static_cast<std::uint32_t>(p[2]) << 8) |
            static_cast<std::uint32_t>(p[3]);
        id.sequence =
            (static_cast<std::uint32_t>(p[4]) << 24) |
            (static_cast<std::uint32_t>(p[5]) << 16) |
            (static_cast<std::uint32_t>(p[6]) << 8) |
            static_cast<std::uint32_t>(p[7]);
        out.entries.push_back(id);
        p += 8;
        len -= 8;
    }

    const std::size_t parity_len = (static_cast<std::size_t>(p[0]) << 8) | p[1];
    p += 2;
    len -= 2;
    if (parity_len < 3 || static_cast<int>(parity_len) != len) {
        return false; // 2-byte length prefix + at least 1 frame byte; no trailing garbage.
    }

    out.parity.assign(p, p + parity_len);
    return true;
}

/**
 * Recover the single missing frame of a group.
 * @param view Parsed parity frame (entries + parity block).
 * @param present Frame bytes aligned with view.entries; nullptr marks the
 *        (single) missing slot. Exactly one slot may be null.
 * @param present_lengths Lengths aligned with @p present.
 * @param missing_index Index of the missing entry.
 * @param out Output buffer for the recovered full vmux frame.
 * @param cap Output capacity.
 * @return Recovered frame length, or 0 on inconsistency (bad inputs, recovered
 *         block length exceeds the parity block or @p cap).
 */
inline int MuxFecRecover(
    const MuxFecFrameView& view,
    const std::uint8_t* const* present,
    const int* present_lengths,
    int missing_index,
    std::uint8_t* out,
    int cap) noexcept {
    const int count = static_cast<int>(view.entries.size());
    const int parity_len = static_cast<int>(view.parity.size());
    if (nullptr == out || missing_index < 0 || missing_index >= count || parity_len < 3) {
        return 0;
    }

    // recovered = parity XOR (all present blocks), zero-padding short blocks.
    std::vector<std::uint8_t> recovered(view.parity.begin(), view.parity.end());
    for (int i = 0; i < count; ++i) {
        if (i == missing_index) {
            continue;
        }
        const std::uint8_t* frame = present[i];
        const int length = present_lengths[i];
        if (nullptr == frame || length < 0 || length + 2 > parity_len) {
            return 0;
        }
        recovered[0] ^= static_cast<std::uint8_t>((static_cast<std::uint32_t>(length) >> 8) & 0xFF);
        recovered[1] ^= static_cast<std::uint8_t>(static_cast<std::uint32_t>(length) & 0xFF);
        for (int b = 0; b < length; ++b) {
            recovered[2 + b] ^= frame[b];
        }
    }

    const int recovered_length = (static_cast<int>(recovered[0]) << 8) | recovered[1];
    if (recovered_length <= 0 || recovered_length + 2 > parity_len || recovered_length > cap) {
        return 0;
    }

    std::memcpy(out, recovered.data() + 2, static_cast<std::size_t>(recovered_length));
    return recovered_length;
}

} // namespace ppp::app::mux
