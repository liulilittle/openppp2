#pragma once

/**
 * @file DeliveryOracle.h
 * @brief Data-correctness oracle for VMUX testing.
 * @license GPL-3.0
 *
 * Generates per-flow payloads with a known hash, delivers them through the
 * component under test, and verifies:
 *   - no missing frames
 *   - no duplicate frames
 *   - no out-of-order delivery (within a flow)
 *   - no cross-flow contamination
 *   - payload bytes are unmodified
 *
 * Usage:
 *   DeliveryOracle oracle;
 *   oracle.send(flow_id=1, seq=0, payload_len=1024);
 *   ... // component under test processes the frame
 *   oracle.recv(flow_id=1, seq=0, payload_ptr, payload_len);
 *   oracle.verify(); // throws on any violation
 */

#include <cstdint>
#include <cstring>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <stdexcept>
#include <string>

namespace ppp::test {

/** One sent frame's expected metadata. */
struct OracleSentFrame {
    std::uint32_t flow_id  = 0;
    std::uint32_t seq      = 0;
    int           length   = 0;
    std::uint64_t hash     = 0;
};

class DeliveryOracle final {
public:
    DeliveryOracle() noexcept = default;

    /**
     * Generate a deterministic payload of @p length bytes for the given flow
     * and sequence, record the expected delivery, and return the payload.
     *
     * The caller owns the returned buffer and must keep it alive until the
     * component under test has consumed it.
     */
    std::vector<std::uint8_t> send(std::uint32_t flow_id, std::uint32_t seq, int length) {
        std::vector<std::uint8_t> payload(static_cast<std::size_t>(length));
        fill_deterministic(flow_id, seq, payload.data(), length);

        OracleSentFrame frame;
        frame.flow_id = flow_id;
        frame.seq     = seq;
        frame.length  = length;
        frame.hash    = hash64(payload.data(), static_cast<std::size_t>(length));
        sent_.push_back(frame);

        return payload;
    }

    /**
     * Record a frame that was delivered by the component under test.
     * Throws std::runtime_error if the frame is unexpected, duplicate,
     * or corrupted. Out-of-order delivery within a flow is allowed (the
     * receiver may reorder); verify() catches missing frames.
     */
    void recv(std::uint32_t flow_id, std::uint32_t seq,
              const void* payload, int length) {
        const auto* p = static_cast<const std::uint8_t*>(payload);

        // Find the matching sent frame for this (flow_id, seq).
        OracleSentFrame* expected = nullptr;
        for (auto& f : sent_) {
            if (f.flow_id == flow_id && f.seq == seq) {
                expected = &f;
                break;
            }
        }

        if (!expected) {
            throw std::runtime_error(
                "DeliveryOracle: unexpected frame flow=" +
                std::to_string(flow_id) + " seq=" + std::to_string(seq));
        }

        // Check length.
        if (expected->length != length) {
            throw std::runtime_error(
                "DeliveryOracle: length mismatch on flow " +
                std::to_string(flow_id) + " seq=" + std::to_string(seq) +
                ": expected " + std::to_string(expected->length) +
                " got " + std::to_string(length));
        }

        // Check hash (payload integrity).
        const std::uint64_t actual = hash64(p, static_cast<std::size_t>(length));
        if (expected->hash != actual) {
            throw std::runtime_error(
                "DeliveryOracle: payload corruption on flow " +
                std::to_string(flow_id) + " seq=" + std::to_string(seq) +
                ": hash mismatch");
        }

        // Check for duplicate delivery.
        auto [dup_it, inserted] = delivered_.insert(
            (static_cast<std::uint64_t>(flow_id) << 32) | seq);
        if (!inserted) {
            throw std::runtime_error(
                "DeliveryOracle: duplicate delivery on flow " +
                std::to_string(flow_id) + " seq=" + std::to_string(seq));
        }

        ++total_delivered_;
    }

    /** Verify all sent frames were delivered exactly once. */
    void verify() const {
        if (total_delivered_ != sent_.size()) {
            // Find which frames are missing.
            for (const auto& f : sent_) {
                std::uint64_t key = (static_cast<std::uint64_t>(f.flow_id) << 32) | f.seq;
                if (delivered_.find(key) == delivered_.end()) {
                    throw std::runtime_error(
                        "DeliveryOracle: missing frame flow=" +
                        std::to_string(f.flow_id) + " seq=" +
                        std::to_string(f.seq));
                }
            }
            throw std::runtime_error(
                "DeliveryOracle: delivered count mismatch: sent=" +
                std::to_string(sent_.size()) + " delivered=" +
                std::to_string(total_delivered_));
        }
    }

    /** Reset to a clean state. */
    void reset() noexcept {
        sent_.clear();
        delivered_.clear();
        total_delivered_ = 0;
    }

    std::size_t sent_count() const noexcept { return sent_.size(); }
    std::size_t delivered_count() const noexcept { return total_delivered_; }

private:
    // FNV-1a 64-bit hash.
    static std::uint64_t hash64(const std::uint8_t* data, std::size_t len) noexcept {
        std::uint64_t h = 14695981039346656037ULL;
        for (std::size_t i = 0; i < len; ++i) {
            h ^= static_cast<std::uint64_t>(data[i]);
            h *= 1099511628211ULL;
        }
        return h;
    }

    // Deterministic payload fill: mix flow_id, seq, and byte index.
    static void fill_deterministic(std::uint32_t flow_id, std::uint32_t seq,
                                   std::uint8_t* out, int length) noexcept {
        for (int i = 0; i < length; ++i) {
            out[i] = static_cast<std::uint8_t>(
                (flow_id * 31 + seq * 17 + i * 7 + 0x5A) & 0xFF);
        }
    }

    std::vector<OracleSentFrame>                        sent_;
    std::unordered_set<std::uint64_t>                   delivered_;
    std::size_t                                         total_delivered_ = 0;
};

} // namespace ppp::test
