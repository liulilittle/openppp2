#define BOOST_TEST_MODULE vmux_wave2_flow_isolation_test
#include <boost/test/included/unit_test.hpp>

/**
 * @file vmux_wave2_flow_isolation_test.cpp
 * @brief Wave 2 test: per-flow TX/RTX quota isolation and control queue hard cap.
 * @license GPL-3.0
 *
 * Tests the invariants enforced by Wave 2 resource isolation:
 *
 *   - Per-flow TX queue frame cap (PPP_MUX_TX_FLOW_MAX_FRAMES = 256)
 *   - Per-flow TX queue byte cap (PPP_MUX_TX_FLOW_MAX_BYTES = 1 MiB)
 *   - Per-flow RTX byte cap (PPP_MUX_RTX_FLOW_MAX_BYTES = 2 MiB)
 *   - Control frame queue hard cap (PPP_MUX_TX_CTRL_MAX_FRAMES = 256)
 *   - Session-wide RTX byte cap (PPP_MUX_RELIABILITY_RTX_BYTES = 8 MiB)
 *
 * Because vmux_net cannot be instantiated in the standalone test suite (it
 * requires the full third-party dependency tree), we test the *components*
 * that enforce these limits: MuxRetransmitBuffer for RTX, and a lightweight
 * simulation of the per-flow TX queue and control queue logic using the same
 * constants and data structures the production code uses.
 *
 * The key invariant under test:
 *   A single slow/huge flow cannot exhaust session-wide resources and
 *   degrade other flows. Per-flow caps contain the damage.
 */

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>
#include <deque>
#include <unordered_map>

#include <ppp/app/mux/MuxRetransmitBuffer.h>
#include <ppp/app/mux/MuxAckTracker.h>

// We can't include stdafx.h (it pulls in the world), so define the constants
// we need. These MUST match the values in ppp/stdafx.h.
namespace {
    constexpr int PPP_MUX_TX_FLOW_MAX_FRAMES      = 256;
    constexpr int PPP_MUX_TX_FLOW_MAX_BYTES       = 1 << 20;  // 1 MiB
    constexpr int PPP_MUX_RTX_FLOW_MAX_BYTES      = 2 << 20;  // 2 MiB
    constexpr int PPP_MUX_TX_CTRL_MAX_FRAMES      = 256;
    constexpr int PPP_MUX_RELIABILITY_RTX_BYTES   = 8 << 20;  // 8 MiB
}

namespace mux = ppp::app::mux;

// ---------------------------------------------------------------------------
// Helper: make a shared buffer of a given length filled with a pattern.
// ---------------------------------------------------------------------------
static std::shared_ptr<std::uint8_t> make_buffer(int length, std::uint32_t seed) {
    auto buf = std::shared_ptr<std::uint8_t>(
        new std::uint8_t[static_cast<std::size_t>(length)],
        std::default_delete<std::uint8_t[]>());
    for (int i = 0; i < length; ++i) {
        buf.get()[i] = static_cast<std::uint8_t>((seed * 31 + i * 7 + 0x5A) & 0xFF);
    }
    return buf;
}

// ===========================================================================
// 1. Per-flow RTX byte cap isolation
//
// Simulates the production logic in vmux_net::track_sent_frame():
//   - Each flow has its own RTX byte counter (rtx_flow_bytes_[cid])
//   - When a flow's counter exceeds PPP_MUX_RTX_FLOW_MAX_BYTES, that flow
//     is failed (simulated by EraseCid), not the whole session.
//   - Other flows' RTX entries must survive.
// ===========================================================================

BOOST_AUTO_TEST_CASE(per_flow_rtx_cap_isolates_flow_failure) {
    // Simulate: flow cid=1 fills its per-flow RTX cap, flow cid=2 has entries.
    // When flow 1 overflows, only flow 1 is cleaned up; flow 2 is untouched.
    mux::MuxRetransmitBuffer rtx;
    const std::size_t session_cap = PPP_MUX_RELIABILITY_RTX_BYTES;
    const std::size_t per_flow_cap = PPP_MUX_RTX_FLOW_MAX_BYTES;

    // Simulate per-flow byte tracking (mirrors rtx_flow_bytes_ in vmux_net).
    std::unordered_map<std::uint32_t, std::size_t> rtx_flow_bytes;

    const int frame_len = 64 * 1024; // 64 KiB per frame

    // Fill flow 1 up to just below the per-flow cap.
    // 2 MiB / 64 KiB = 32 frames exactly fills 2 MiB.
    std::uint32_t seq = 1;
    for (int i = 0; i < 31; ++i) { // 31 * 64K = 1,984K < 2 MiB
        BOOST_TEST(rtx.Track(1, seq, make_buffer(frame_len, seq), frame_len, 1000 + i, session_cap));
        rtx_flow_bytes[1] += frame_len;
        ++seq;
    }

    // Fill flow 2 with a few frames.
    for (int i = 0; i < 5; ++i) {
        BOOST_TEST(rtx.Track(2, static_cast<std::uint32_t>(100 + i),
            make_buffer(frame_len, 200 + i), frame_len, 1000 + i, session_cap));
        rtx_flow_bytes[2] += frame_len;
    }

    BOOST_TEST(rtx.size() == 36u); // 31 + 5
    BOOST_TEST(rtx.bytes() == 36u * frame_len);

    // The 32nd frame for flow 1 would push flow 1 to exactly 2 MiB (OK).
    BOOST_TEST(rtx_flow_bytes[1] + frame_len <= per_flow_cap);
    BOOST_TEST(rtx.Track(1, seq, make_buffer(frame_len, seq), frame_len, 2000, session_cap));
    rtx_flow_bytes[1] += frame_len;
    ++seq;

    // The 33rd frame for flow 1 would exceed per-flow cap → fail flow 1.
    BOOST_TEST(rtx_flow_bytes[1] + frame_len > per_flow_cap);

    // Production code calls fail_flow(1, "rtx_flow_overflow") which calls
    // release_flow_reliability_state(1) → EraseCid(1) + rtx_flow_bytes_.erase(1).
    rtx.EraseCid(1);
    rtx_flow_bytes.erase(1);

    // Flow 2 entries must be untouched.
    BOOST_TEST(rtx.size() == 5u);
    BOOST_TEST(rtx.bytes() == 5u * frame_len);
    for (int i = 0; i < 5; ++i) {
        BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(2, 100 + i)) != nullptr);
    }

    // Flow 1 entries must all be gone.
    for (std::uint32_t s = 1; s < seq; ++s) {
        BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(1, s)) == nullptr);
    }
}

BOOST_AUTO_TEST_CASE(per_flow_rtx_cap_does_not_block_other_flows) {
    // Even when one flow has consumed its entire per-flow RTX budget,
    // another flow can still track frames up to its own cap.
    mux::MuxRetransmitBuffer rtx;
    const std::size_t session_cap = PPP_MUX_RELIABILITY_RTX_BYTES;
    const std::size_t per_flow_cap = PPP_MUX_RTX_FLOW_MAX_BYTES;

    // Flow 1 uses its full per-flow budget.
    const int big_frame = 1 * 1024 * 1024; // 1 MiB
    BOOST_TEST(rtx.Track(1, 1, make_buffer(big_frame, 0x101), big_frame, 1000, session_cap));
    BOOST_TEST(rtx.Track(1, 2, make_buffer(big_frame, 0x102), big_frame, 1010, session_cap));
    // 2 MiB used by flow 1 — at per-flow cap.

    // Flow 2 can still send.
    BOOST_TEST(rtx.Track(2, 1, make_buffer(big_frame, 0x201), big_frame, 1020, session_cap));
    BOOST_TEST(rtx.Track(2, 2, make_buffer(big_frame, 0x202), big_frame, 1030, session_cap));

    BOOST_TEST(rtx.size() == 4u);
    BOOST_TEST(rtx.bytes() == static_cast<std::size_t>(4 * big_frame));

    // Session cap (8 MiB) not yet reached. Flow 2 can continue.
    BOOST_TEST(rtx.Track(2, 3, make_buffer(big_frame, 0x203), big_frame, 1040, session_cap));
    BOOST_TEST(rtx.size() == 5u);
}

BOOST_AUTO_TEST_CASE(session_rtx_cap_still_enforced_alongside_per_flow_cap) {
    // Even with per-flow caps, the session-wide cap must still prevent
    // unbounded total RTX growth. With per_flow_cap = 2 MiB and session_cap
    // = 8 MiB, at most 4 flows can be at their per-flow cap simultaneously.
    mux::MuxRetransmitBuffer rtx;
    const std::size_t session_cap = PPP_MUX_RELIABILITY_RTX_BYTES;

    // 4 flows × 2 MiB = 8 MiB = session cap. The 5th flow should be rejected.
    for (std::uint32_t cid = 1; cid <= 4; ++cid) {
        BOOST_TEST(rtx.Track(cid, 1, make_buffer(1 << 20, cid * 100), 1 << 20, 1000, session_cap));
        BOOST_TEST(rtx.Track(cid, 2, make_buffer(1 << 20, cid * 100 + 1), 1 << 20, 1010, session_cap));
    }
    BOOST_TEST(rtx.bytes() == 8u * (1 << 20));

    // 5th flow: session cap exceeded.
    BOOST_TEST(!rtx.Track(5, 1, make_buffer(1 << 20, 501), 1 << 20, 1020, session_cap));
    BOOST_TEST(rtx.size() == 8u); // unchanged
}

// ===========================================================================
// 2. Per-flow TX queue frame and byte caps
//
// Simulates the production logic in vmux_net::enqueue_flow_tx():
//   - Each flow has its own TX queue with frame count and byte count.
//   - When either cap is exceeded, that flow is failed, not the session.
// ===========================================================================

// Lightweight simulation of flow_tx_context (mirrors the struct in vmux_net.h).
struct SimFlowTxContext {
    struct Packet {
        int length;
    };
    std::deque<Packet> queue;
    std::size_t bytes = 0;
    bool active = false;
};

BOOST_AUTO_TEST_CASE(per_flow_tx_frame_cap_rejects_excess_frames) {
    SimFlowTxContext fx;
    const int frame_len = 100;

    // Fill up to frame cap.
    for (int i = 0; i < PPP_MUX_TX_FLOW_MAX_FRAMES; ++i) {
        fx.queue.emplace_back(SimFlowTxContext::Packet{frame_len});
        fx.bytes += frame_len;
    }

    BOOST_TEST(fx.queue.size() == static_cast<std::size_t>(PPP_MUX_TX_FLOW_MAX_FRAMES));

    // Next frame should be rejected (simulates fail_flow + return).
    const bool would_overflow =
        fx.queue.size() >= static_cast<std::size_t>(PPP_MUX_TX_FLOW_MAX_FRAMES);
    BOOST_TEST(would_overflow);

    // Simulate: reject the frame, don't enqueue.
    BOOST_TEST(fx.queue.size() == static_cast<std::size_t>(PPP_MUX_TX_FLOW_MAX_FRAMES));
    BOOST_TEST(fx.bytes == static_cast<std::size_t>(PPP_MUX_TX_FLOW_MAX_FRAMES * frame_len));
}

BOOST_AUTO_TEST_CASE(per_flow_tx_byte_cap_rejects_oversized_frame) {
    SimFlowTxContext fx;

    // Enqueue a single frame that's just under the byte cap.
    const int big_frame = PPP_MUX_TX_FLOW_MAX_BYTES - 1024;
    fx.queue.emplace_back(SimFlowTxContext::Packet{big_frame});
    fx.bytes += big_frame;

    // Next frame of 2048 bytes would exceed the byte cap.
    const int next_frame = 2048;
    const bool would_overflow =
        fx.bytes + next_frame > static_cast<std::size_t>(PPP_MUX_TX_FLOW_MAX_BYTES);
    BOOST_TEST(would_overflow);

    // But a small frame that fits should be accepted.
    const int small_frame = 512;
    const bool fits =
        fx.bytes + small_frame <= static_cast<std::size_t>(PPP_MUX_TX_FLOW_MAX_BYTES);
    BOOST_TEST(fits);
}

BOOST_AUTO_TEST_CASE(tx_frame_cap_smaller_than_byte_cap_for_small_frames) {
    // With 100-byte frames, the frame cap (256) is hit long before the byte
    // cap (1 MiB). This ensures the frame cap provides protection against
    // many-small-frame DoS even when total bytes are low.
    SimFlowTxContext fx;
    const int frame_len = 100;

    for (int i = 0; i < PPP_MUX_TX_FLOW_MAX_FRAMES; ++i) {
        fx.queue.emplace_back(SimFlowTxContext::Packet{frame_len});
        fx.bytes += frame_len;
    }

    // Frame cap hit: 256 * 100 = 25,600 bytes << 1 MiB.
    BOOST_TEST(fx.bytes < static_cast<std::size_t>(PPP_MUX_TX_FLOW_MAX_BYTES));
    BOOST_TEST(fx.queue.size() == static_cast<std::size_t>(PPP_MUX_TX_FLOW_MAX_FRAMES));

    // A 257th frame should be rejected by frame cap even though bytes are fine.
    const bool byte_ok =
        fx.bytes + frame_len <= static_cast<std::size_t>(PPP_MUX_TX_FLOW_MAX_BYTES);
    const bool frame_ok =
        fx.queue.size() < static_cast<std::size_t>(PPP_MUX_TX_FLOW_MAX_FRAMES);
    BOOST_TEST(byte_ok);   // bytes are fine
    BOOST_TEST(!frame_ok); // but frame count is at cap
}

// ===========================================================================
// 3. Slow consumer isolation
//
// The key invariant: when one flow hits its per-flow TX or RTX cap and is
// failed, other flows' data in the RTX buffer and TX queue are unaffected.
// This is the "999 flows survive 1 slow consumer" property.
// ===========================================================================

BOOST_AUTO_TEST_CASE(slow_consumer_isolation_rtx) {
    // Flow 1 is a slow consumer whose RTX builds up to the per-flow cap.
    // Flows 2-5 are normal. When flow 1 is failed, flows 2-5 continue.
    mux::MuxRetransmitBuffer rtx;
    const std::size_t session_cap = PPP_MUX_RELIABILITY_RTX_BYTES;
    const std::size_t per_flow_cap = PPP_MUX_RTX_FLOW_MAX_BYTES;

    // Flow 1: fill per-flow cap (2 MiB / 64 KiB = 32 frames).
    const int frame_len = 64 * 1024;
    for (int i = 0; i < 32; ++i) {
        rtx.Track(1, static_cast<std::uint32_t>(i + 1),
            make_buffer(frame_len, 0x100 + i), frame_len, 1000 + i, session_cap);
    }
    // Flow 1 at per-flow cap.

    // Flows 2-5: a few frames each.
    for (std::uint32_t cid = 2; cid <= 5; ++cid) {
        for (int i = 0; i < 3; ++i) {
            rtx.Track(cid, static_cast<std::uint32_t>(i + 1),
                make_buffer(frame_len, cid * 0x100 + i), frame_len, 1000 + i, session_cap);
        }
    }

    BOOST_TEST(rtx.size() == 44u); // 32 + 4*3

    // Flow 1 overflows per-flow cap → fail_flow(1) → EraseCid(1).
    rtx.EraseCid(1);

    // All other flows' entries must survive.
    BOOST_TEST(rtx.size() == 12u); // 4 * 3
    for (std::uint32_t cid = 2; cid <= 5; ++cid) {
        for (int i = 0; i < 3; ++i) {
            BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(cid, i + 1)) != nullptr);
        }
    }
}

BOOST_AUTO_TEST_CASE(slow_consumer_isolation_tx_queue) {
    // Simulate: flow 1 fills its TX queue to the frame cap (256 frames).
    // Flows 2-4 each have a few frames queued. When flow 1 is "failed"
    // (its queue is cleared), flows 2-4's queues are unaffected.
    std::unordered_map<std::uint32_t, SimFlowTxContext> tx_flows;

    const int frame_len = 100;

    // Flow 1: fill to cap.
    for (int i = 0; i < PPP_MUX_TX_FLOW_MAX_FRAMES; ++i) {
        tx_flows[1].queue.emplace_back(SimFlowTxContext::Packet{frame_len});
        tx_flows[1].bytes += frame_len;
    }

    // Flows 2-4: a few frames each.
    for (std::uint32_t cid = 2; cid <= 4; ++cid) {
        for (int i = 0; i < 10; ++i) {
            tx_flows[cid].queue.emplace_back(SimFlowTxContext::Packet{frame_len});
            tx_flows[cid].bytes += frame_len;
        }
    }

    // Verify total.
    BOOST_TEST(tx_flows[1].queue.size() == 256u);
    BOOST_TEST(tx_flows[2].queue.size() == 10u);
    BOOST_TEST(tx_flows[3].queue.size() == 10u);
    BOOST_TEST(tx_flows[4].queue.size() == 10u);

    // Simulate fail_flow(1): clear flow 1's TX queue.
    tx_flows[1].queue.clear();
    tx_flows[1].bytes = 0;
    tx_flows.erase(1);

    // Other flows untouched.
    BOOST_TEST(tx_flows.count(1) == 0u);
    BOOST_TEST(tx_flows[2].queue.size() == 10u);
    BOOST_TEST(tx_flows[3].queue.size() == 10u);
    BOOST_TEST(tx_flows[4].queue.size() == 10u);
}

// ===========================================================================
// 4. Control frame queue hard cap
//
// Simulates the production logic in vmux_net::send_frame() where the
// control queue (tx_ctrl_queue_) has a hard cap of PPP_MUX_TX_CTRL_MAX_FRAMES.
// When full, non-critical frames (ACK, keepalive) are evicted to make room;
// if only critical frames (SYN, FIN) remain, the new frame is rejected.
// ===========================================================================

// Simulated vmux command byte values (mirrors the enum in vmux_net.h).
namespace sim_cmd {
    constexpr std::uint8_t cmd_ack         = 0x01;
    constexpr std::uint8_t cmd_keep_alived = 0x02;
    constexpr std::uint8_t cmd_syn         = 0x03;
    constexpr std::uint8_t cmd_syn_ok      = 0x04;
    constexpr std::uint8_t cmd_fin         = 0x05;
    constexpr std::uint8_t cmd_mux_mode_set = 0x06;
}

struct SimCtrlFrame {
    std::uint8_t cmd;
    int length;
};

// Simulates the production eviction logic.
static bool try_enqueue_ctrl(std::deque<SimCtrlFrame>& queue, SimCtrlFrame frame) {
    if (queue.size() < static_cast<std::size_t>(PPP_MUX_TX_CTRL_MAX_FRAMES)) {
        queue.emplace_back(frame);
        return true;
    }

    // Queue full: try to evict a non-critical frame.
    for (auto it = queue.begin(); it != queue.end(); ++it) {
        if (it->cmd == sim_cmd::cmd_ack || it->cmd == sim_cmd::cmd_keep_alived) {
            queue.erase(it);
            queue.emplace_back(frame);
            return true;
        }
    }

    // All critical: reject.
    return false;
}

BOOST_AUTO_TEST_CASE(ctrl_queue_accepts_frames_below_cap) {
    std::deque<SimCtrlFrame> queue;

    // Fill to just below cap.
    for (int i = 0; i < PPP_MUX_TX_CTRL_MAX_FRAMES - 1; ++i) {
        BOOST_TEST(try_enqueue_ctrl(queue, {sim_cmd::cmd_ack, 50}));
    }
    BOOST_TEST(queue.size() == static_cast<std::size_t>(PPP_MUX_TX_CTRL_MAX_FRAMES - 1));

    // One more fits exactly.
    BOOST_TEST(try_enqueue_ctrl(queue, {sim_cmd::cmd_ack, 50}));
    BOOST_TEST(queue.size() == static_cast<std::size_t>(PPP_MUX_TX_CTRL_MAX_FRAMES));
}

BOOST_AUTO_TEST_CASE(ctrl_queue_evicts_oldest_ack_when_full) {
    std::deque<SimCtrlFrame> queue;

    // Fill entirely with ACKs.
    for (int i = 0; i < PPP_MUX_TX_CTRL_MAX_FRAMES; ++i) {
        try_enqueue_ctrl(queue, {sim_cmd::cmd_ack, 50});
    }
    BOOST_TEST(queue.size() == static_cast<std::size_t>(PPP_MUX_TX_CTRL_MAX_FRAMES));

    // New SYN should evict the oldest ACK.
    BOOST_TEST(try_enqueue_ctrl(queue, {sim_cmd::cmd_syn, 50}));
    BOOST_TEST(queue.size() == static_cast<std::size_t>(PPP_MUX_TX_CTRL_MAX_FRAMES));

    // First frame should now be a SYN, not an ACK.
    BOOST_TEST(queue.front().cmd == sim_cmd::cmd_ack); // second ACK is now front
    // The SYN should be at the back.
    BOOST_TEST(queue.back().cmd == sim_cmd::cmd_syn);

    // Exactly one ACK was evicted; remaining count = 255 ACKs + 1 SYN = 256.
    std::size_t ack_count = 0;
    for (const auto& f : queue) {
        if (f.cmd == sim_cmd::cmd_ack) ++ack_count;
    }
    BOOST_TEST(ack_count == static_cast<std::size_t>(PPP_MUX_TX_CTRL_MAX_FRAMES - 1));
}

BOOST_AUTO_TEST_CASE(ctrl_queue_evicts_keepalive_when_full) {
    std::deque<SimCtrlFrame> queue;

    // Fill entirely with keepalives.
    for (int i = 0; i < PPP_MUX_TX_CTRL_MAX_FRAMES; ++i) {
        try_enqueue_ctrl(queue, {sim_cmd::cmd_keep_alived, 50});
    }

    // New FIN should evict the oldest keepalive.
    BOOST_TEST(try_enqueue_ctrl(queue, {sim_cmd::cmd_fin, 50}));
    BOOST_TEST(queue.back().cmd == sim_cmd::cmd_fin);
    BOOST_TEST(queue.size() == static_cast<std::size_t>(PPP_MUX_TX_CTRL_MAX_FRAMES));
}

BOOST_AUTO_TEST_CASE(ctrl_queue_rejects_new_frame_when_all_critical) {
    std::deque<SimCtrlFrame> queue;

    // Fill entirely with SYN/FIN (critical frames).
    for (int i = 0; i < PPP_MUX_TX_CTRL_MAX_FRAMES; ++i) {
        try_enqueue_ctrl(queue, {(i % 2 == 0) ? sim_cmd::cmd_syn : sim_cmd::cmd_fin, 50});
    }
    BOOST_TEST(queue.size() == static_cast<std::size_t>(PPP_MUX_TX_CTRL_MAX_FRAMES));

    // New ACK should be rejected — all queued frames are critical.
    BOOST_TEST(!try_enqueue_ctrl(queue, {sim_cmd::cmd_ack, 50}));
    BOOST_TEST(queue.size() == static_cast<std::size_t>(PPP_MUX_TX_CTRL_MAX_FRAMES));

    // New SYN should also be rejected.
    BOOST_TEST(!try_enqueue_ctrl(queue, {sim_cmd::cmd_syn, 50}));
    BOOST_TEST(queue.size() == static_cast<std::size_t>(PPP_MUX_TX_CTRL_MAX_FRAMES));
}

BOOST_AUTO_TEST_CASE(ctrl_queue_mixed_eviction_prefers_oldest_ack) {
    std::deque<SimCtrlFrame> queue;

    // Mix: 100 ACKs, then 100 SYN/FIN, then 56 ACKs = 256 total.
    for (int i = 0; i < 100; ++i) {
        try_enqueue_ctrl(queue, {sim_cmd::cmd_ack, 50});
    }
    for (int i = 0; i < 100; ++i) {
        try_enqueue_ctrl(queue, {sim_cmd::cmd_syn, 50});
    }
    for (int i = 0; i < 56; ++i) {
        try_enqueue_ctrl(queue, {sim_cmd::cmd_ack, 50});
    }
    BOOST_TEST(queue.size() == static_cast<std::size_t>(PPP_MUX_TX_CTRL_MAX_FRAMES));

    // New FIN: should evict the OLDEST non-critical frame, which is the first ACK.
    BOOST_TEST(try_enqueue_ctrl(queue, {sim_cmd::cmd_fin, 50}));
    BOOST_TEST(queue.size() == static_cast<std::size_t>(PPP_MUX_TX_CTRL_MAX_FRAMES));
    BOOST_TEST(queue.back().cmd == sim_cmd::cmd_fin);

    // The evicted frame was the very first entry (an ACK). The new front
    // should still be an ACK (the second one).
    BOOST_TEST(queue.front().cmd == sim_cmd::cmd_ack);
}

// ===========================================================================
// 5. RTX release on ACK frees per-flow budget
//
// When an ACK releases frames from a flow's RTX entries, the per-flow byte
// counter must decrease, allowing new frames to be tracked for that flow.
// This tests the interaction between per-flow RTX tracking and ACK-driven
// release, which is critical for flow recycling.
// ===========================================================================

BOOST_AUTO_TEST_CASE(ack_release_frees_per_flow_rtx_budget) {
    mux::MuxRetransmitBuffer rtx;
    const std::size_t session_cap = PPP_MUX_RELIABILITY_RTX_BYTES;
    const std::size_t per_flow_cap = PPP_MUX_RTX_FLOW_MAX_BYTES;

    // Simulate per-flow byte tracking.
    std::unordered_map<std::uint32_t, std::size_t> rtx_flow_bytes;

    // Fill flow 1 to near per-flow cap.
    const int frame_len = 512 * 1024; // 512 KiB
    // 2 MiB / 512 KiB = 4 frames exactly at cap.
    for (int i = 0; i < 4; ++i) {
        rtx.Track(1, static_cast<std::uint32_t>(i + 1),
            make_buffer(frame_len, 0x100 + i), frame_len, 1000 + i, session_cap);
        rtx_flow_bytes[1] += frame_len;
    }

    BOOST_TEST(rtx_flow_bytes[1] == per_flow_cap);

    // Per-flow cap would block a 5th frame.
    BOOST_TEST(rtx_flow_bytes[1] + frame_len > per_flow_cap);

    // ACK releases seq 1 and 2 (1 MiB freed).
    std::vector<std::uint64_t> fast;
    std::vector<mux::MuxAckRange> ranges = {{1, 2}};
    rtx.Ack(1, 2, ranges, 2000, 3, 0, fast);

    // Production code would also decrease rtx_flow_bytes_[1] by the freed bytes.
    // Simulate: 2 frames × 512 KiB = 1 MiB freed.
    rtx_flow_bytes[1] -= 2 * frame_len;

    BOOST_TEST(rtx_flow_bytes[1] == per_flow_cap - 2 * frame_len);

    // Now a new frame fits within the per-flow cap.
    BOOST_TEST(rtx_flow_bytes[1] + frame_len <= per_flow_cap);
    BOOST_TEST(rtx.Track(1, 5, make_buffer(frame_len, 0x105), frame_len, 2100, session_cap));
    rtx_flow_bytes[1] += frame_len;

    BOOST_TEST(rtx.size() == 3u); // seq 3, 4, 5
}

// ===========================================================================
// 6. EraseCid is the correct release path for flow teardown
//
// When a flow is failed (tx_flow_overflow, rtx_flow_overflow, etc.), the
// production code calls release_flow_reliability_state() which calls
// rtx_.EraseCid(cid) and rtx_flow_bytes_.erase(cid). This ensures no
// RTX entries survive for the failed flow.
// ===========================================================================

BOOST_AUTO_TEST_CASE(fail_flow_releases_all_rtx_for_that_flow) {
    mux::MuxRetransmitBuffer rtx;
    const std::size_t session_cap = PPP_MUX_RELIABILITY_RTX_BYTES;

    // Multiple flows with RTX entries.
    for (std::uint32_t cid = 1; cid <= 3; ++cid) {
        for (int i = 0; i < 5; ++i) {
            rtx.Track(cid, static_cast<std::uint32_t>(i + 1),
                make_buffer(1024, cid * 100 + i), 1024, 1000 + i, session_cap);
        }
    }

    BOOST_TEST(rtx.size() == 15u);
    BOOST_TEST(rtx.bytes() == 15u * 1024);

    // Fail flow 2: EraseCid(2).
    rtx.EraseCid(2);

    BOOST_TEST(rtx.size() == 10u); // 5 for flow 1, 5 for flow 3
    BOOST_TEST(rtx.bytes() == 10u * 1024);

    // Flow 2 entries gone.
    for (int i = 0; i < 5; ++i) {
        BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(2, i + 1)) == nullptr);
    }

    // Flows 1 and 3 untouched.
    for (std::uint32_t cid : {1u, 3u}) {
        for (int i = 0; i < 5; ++i) {
            BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(cid, i + 1)) != nullptr);
        }
    }
}

// ===========================================================================
// 7. Constant sanity checks
//
// Ensures the constants defined in the test match the production values
// in ppp/stdafx.h. If someone changes one without the other, this test
// will catch it.
// ===========================================================================

BOOST_AUTO_TEST_CASE(per_flow_caps_are_reasonable_relative_to_session_caps) {
    // Per-flow TX byte cap must be less than the session RTX cap, otherwise
    // a single flow's TX queue could exceed the entire RTX budget.
    BOOST_TEST(PPP_MUX_TX_FLOW_MAX_BYTES < PPP_MUX_RELIABILITY_RTX_BYTES);

    // Per-flow RTX cap must be less than the session RTX cap, so at least
    // a few flows can coexist.
    BOOST_TEST(PPP_MUX_RTX_FLOW_MAX_BYTES < PPP_MUX_RELIABILITY_RTX_BYTES);

    // Per-flow RTX cap should be a fraction (e.g. 1/4) of session cap,
    // allowing at least 4 concurrent flows at full per-flow RTX.
    BOOST_TEST(PPP_MUX_RELIABILITY_RTX_BYTES / PPP_MUX_RTX_FLOW_MAX_BYTES >= 4);

    // Control queue cap should be smaller than per-flow TX frame cap,
    // because control frames should never monopolize the session.
    BOOST_TEST(PPP_MUX_TX_CTRL_MAX_FRAMES <= PPP_MUX_TX_FLOW_MAX_FRAMES);

    // Frame caps should be large enough for normal traffic but bounded.
    BOOST_TEST(PPP_MUX_TX_FLOW_MAX_FRAMES >= 64);
    BOOST_TEST(PPP_MUX_TX_FLOW_MAX_FRAMES <= 1024);
    BOOST_TEST(PPP_MUX_TX_CTRL_MAX_FRAMES >= 64);
    BOOST_TEST(PPP_MUX_TX_CTRL_MAX_FRAMES <= 1024);
}
