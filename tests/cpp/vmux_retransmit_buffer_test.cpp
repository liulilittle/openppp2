#define BOOST_TEST_MODULE vmux_retransmit_buffer_test
#include <boost/test/included/unit_test.hpp>

#include <cstdint>
#include <memory>
#include <vector>

#include <ppp/app/mux/MuxRetransmitBuffer.h>

namespace mux = ppp::app::mux;

namespace {
    std::shared_ptr<std::uint8_t> make_frame(int value) {
        auto buffer = std::make_shared<std::uint8_t>(static_cast<std::uint8_t>(value));
        return buffer;
    }
}

BOOST_AUTO_TEST_CASE(track_retain_and_release_on_ack) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(7, 1, make_frame(1), 100, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(7, 2, make_frame(2), 100, 1010, 1 << 20));
    BOOST_TEST(rtx.size() == 2u);
    BOOST_TEST(rtx.bytes() == 200u);

    std::vector<std::uint64_t> fast;
    std::vector<mux::MuxAckRange> ranges = { {1, 1} };
    const std::uint64_t sample = rtx.Ack(7, 1, ranges, 1100, 3, 0, fast);

    BOOST_TEST(sample == 100u); // 1100 - 1000, entry never retransmitted.
    BOOST_TEST(rtx.size() == 1u);
    BOOST_TEST(rtx.bytes() == 100u);
    BOOST_TEST(fast.empty());
}

BOOST_AUTO_TEST_CASE(track_refuses_to_exceed_the_byte_cap) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 400, 1000, 500));
    BOOST_TEST(!rtx.Track(0, 2, make_frame(2), 400, 1000, 500));
    BOOST_TEST(rtx.size() == 1u);
    BOOST_TEST(rtx.bytes() == 400u);
}

BOOST_AUTO_TEST_CASE(fast_retransmit_candidates_follow_the_distance_rule) {
    mux::MuxRetransmitBuffer rtx;
    for (std::uint32_t seq = 1; seq <= 6; ++seq) {
        BOOST_TEST(rtx.Track(3, seq, make_frame((int)seq), 10, 1000, 1 << 20));
    }

    // ACK covers 4..6 with largest 6: seq 1..3 sit at least 3 below largest.
    std::vector<std::uint64_t> fast;
    std::vector<mux::MuxAckRange> ranges = { {4, 6} };
    rtx.Ack(3, 6, ranges, 2000, 3, 0, fast);

    BOOST_TEST(rtx.size() == 3u); // 4..6 released.
    BOOST_REQUIRE_EQUAL(fast.size(), 3u);
    for (std::uint64_t key : fast) {
        const std::uint32_t seq = static_cast<std::uint32_t>(key & 0xFFFFFFFFu);
        BOOST_TEST(seq <= 3u);
    }

    // Same largest again: no duplicate candidates (fast_rtx_mark dedup).
    std::vector<std::uint64_t> fast_again;
    std::vector<mux::MuxAckRange> ranges_again = { {7, 7} };
    rtx.Track(3, 7, make_frame(7), 10, 1000, 1 << 20);
    rtx.Ack(3, 6, ranges_again, 2100, 3, 0, fast_again); // largest unchanged at 6
    BOOST_TEST(fast_again.empty());
}

BOOST_AUTO_TEST_CASE(no_rtt_sample_from_retransmitted_frames) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20));
    rtx.MarkRetransmitted(mux::MuxRetransmitBuffer::Key(0, 1), 1500);

    std::vector<std::uint64_t> fast;
    std::vector<mux::MuxAckRange> ranges = { {1, 1} };
    const std::uint64_t sample = rtx.Ack(0, 1, ranges, 2000, 3, 0, fast);
    BOOST_TEST(sample == 0u); // Karn's rule: retransmitted frames give no sample.
}

BOOST_AUTO_TEST_CASE(collect_expired_respects_pto_and_count_bound) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(0, 2, make_frame(2), 10, 1500, 1 << 20));
    BOOST_TEST(rtx.Track(0, 3, make_frame(3), 10, 1900, 1 << 20));

    std::vector<std::uint64_t> expired;
    rtx.CollectExpired(2000, 400, 60000, 32, expired); // entries idle >= 400ms: seq 1 and 2
    BOOST_REQUIRE_EQUAL(expired.size(), 2u);

    std::vector<std::uint64_t> bounded;
    rtx.CollectExpired(2000, 400, 60000, 1, bounded);
    BOOST_REQUIRE_EQUAL(bounded.size(), 1u);

    std::vector<std::uint64_t> none;
    rtx.CollectExpired(1100, 400, 60000, 32, none);
    BOOST_TEST(none.empty());
}

BOOST_AUTO_TEST_CASE(erase_cid_drops_only_that_space) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(1, 1, make_frame(1), 10, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(2, 1, make_frame(2), 20, 1000, 1 << 20));

    rtx.EraseCid(1);
    BOOST_TEST(rtx.size() == 1u);
    BOOST_TEST(rtx.bytes() == 20u);
    BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(2, 1)) != nullptr);

    rtx.Clear();
    BOOST_TEST(rtx.size() == 0u);
    BOOST_TEST(rtx.bytes() == 0u);
}

BOOST_AUTO_TEST_CASE(duplicate_track_is_a_noop) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 5, make_frame(5), 10, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(0, 5, make_frame(5), 10, 2000, 1 << 20));
    BOOST_TEST(rtx.size() == 1u);
    BOOST_TEST(rtx.bytes() == 10u);
}

BOOST_AUTO_TEST_CASE(take_link_inflight_returns_only_that_carriers_unacked_frames) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20, /*link_id=*/3));
    BOOST_TEST(rtx.Track(0, 2, make_frame(2), 10, 1001, 1 << 20, /*link_id=*/4));
    BOOST_TEST(rtx.Track(0, 3, make_frame(3), 10, 1002, 1 << 20, /*link_id=*/3));
    BOOST_TEST(rtx.Track(0, 4, make_frame(4), 10, 1003, 1 << 20, /*link_id=*/3));

    // seq 3 was acked; seq 4 was already re-sent on carrier 4.
    std::vector<std::uint64_t> fast;
    std::vector<mux::MuxAckRange> ranges = { {3, 3} };
    rtx.Ack(0, 3, ranges, 1100, 1000, 0, fast);
    rtx.MarkRetransmitted(mux::MuxRetransmitBuffer::Key(0, 4), 1101, 4);

    std::vector<std::uint64_t> lost;
    rtx.TakeLinkInflight(3, lost);
    BOOST_REQUIRE_EQUAL(lost.size(), 1u);
    BOOST_TEST(lost[0] == mux::MuxRetransmitBuffer::Key(0, 1));

    // Orphaned: the dead carrier's id no longer owns it, so a carrier that later
    // reuses id 3 cannot re-claim it, and a re-send is not suppressed by the
    // "already sent this tick" guard.
    const mux::MuxRtxEntry* entry = rtx.Find(lost[0]);
    BOOST_REQUIRE(entry != nullptr);
    BOOST_TEST(entry->last_link_id == 0u);
    BOOST_TEST(entry->last_sent_tick == 0u);
    std::vector<std::uint64_t> again;
    rtx.TakeLinkInflight(3, again);
    BOOST_TEST(again.empty());
}

BOOST_AUTO_TEST_CASE(take_link_inflight_preserves_send_order_and_ignores_unknown_link) {
    mux::MuxRetransmitBuffer rtx;
    for (std::uint32_t seq = 10; seq < 15; ++seq) {
        BOOST_TEST(rtx.Track(7, seq, make_frame((int)seq), 10, 1000 + seq, 1 << 20, /*link_id=*/2));
    }

    std::vector<std::uint64_t> none;
    rtx.TakeLinkInflight(0, none);
    BOOST_TEST(none.empty());

    std::vector<std::uint64_t> lost;
    rtx.TakeLinkInflight(2, lost);
    BOOST_REQUIRE_EQUAL(lost.size(), 5u);
    for (std::size_t i = 0; i < lost.size(); ++i) {
        BOOST_TEST(lost[i] == mux::MuxRetransmitBuffer::Key(7, (std::uint32_t)(10 + i)));
    }
}

BOOST_AUTO_TEST_CASE(cid_bytes_follow_track_ack_and_erase) {
    // The per-flow send window reads CidBytes(): it must shrink on ACK, or a
    // long-lived flow_v2 flow would hit its 2 MiB budget after 2 MiB total
    // sent and be failed even though nothing is outstanding.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(7, 1, make_frame(1), 100, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(7, 2, make_frame(2), 100, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(9, 1, make_frame(3), 50, 1000, 1 << 20));
    BOOST_TEST(rtx.CidBytes(7) == 200u);
    BOOST_TEST(rtx.CidBytes(9) == 50u);
    BOOST_TEST(rtx.CidBytes(42) == 0u);

    std::vector<std::uint64_t> fast;
    std::vector<mux::MuxAckRange> ranges = { {1, 2} };
    rtx.Ack(7, 2, ranges, 1100, 3, 0, fast);
    BOOST_TEST(rtx.CidBytes(7) == 0u);
    BOOST_TEST(rtx.CidBytes(9) == 50u);
    BOOST_TEST(rtx.bytes() == 50u);

    BOOST_TEST(rtx.Track(7, 3, make_frame(4), 100, 1200, 1 << 20));
    rtx.EraseCid(9);
    BOOST_TEST(rtx.CidBytes(9) == 0u);
    BOOST_TEST(rtx.CidBytes(7) == 100u);

    rtx.Clear();
    BOOST_TEST(rtx.CidBytes(7) == 0u);
}
