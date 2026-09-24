#define BOOST_TEST_MODULE p2p_replay_window_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PReplayWindow.h>
#include <limits>
#include <type_traits>

using ppp::p2p::P2PReplayWindow;
using ppp::p2p::REPLAY_WINDOW_SIZE;

static_assert(std::is_same<decltype(P2PReplayWindow::base_), uint64_t>::value,
              "Replay base must retain the extended uint64 sequence");

// Aim: first packet on an empty window is accepted and immediately marked duplicate.
BOOST_AUTO_TEST_CASE(replay_empty_window_accepts_first) {
    P2PReplayWindow window;
    BOOST_TEST(!window.initialized_);
    BOOST_TEST(!window.IsDuplicate(42));
    BOOST_TEST(window.Accept(42));
    BOOST_TEST(window.initialized_);
    BOOST_TEST(window.IsDuplicate(42));
}

// Aim: sequence zero is a valid first packet but cannot be accepted twice.
BOOST_AUTO_TEST_CASE(replay_rejects_duplicate_zero) {
    P2PReplayWindow window;
    BOOST_TEST(!window.IsDuplicate(0));
    BOOST_REQUIRE(window.Accept(0));
    BOOST_TEST(window.IsDuplicate(0));
    BOOST_TEST(!window.Accept(0));
}

// Aim: Reset restores the empty state even when the prior base was zero.
BOOST_AUTO_TEST_CASE(replay_reset_after_zero_accepts_zero_once_again) {
    P2PReplayWindow window;
    BOOST_REQUIRE(window.Accept(0));
    window.Reset();
    BOOST_TEST(!window.initialized_);
    BOOST_TEST(!window.IsDuplicate(0));
    BOOST_REQUIRE(window.Accept(0));
    BOOST_TEST(!window.Accept(0));
}

// Aim: uint32 sequence rollover advances the uint64 extended base.
BOOST_AUTO_TEST_CASE(replay_accepts_zero_after_uint32_max) {
    P2PReplayWindow window;
    const uint32_t max_sequence = std::numeric_limits<uint32_t>::max();
    BOOST_REQUIRE(window.Accept(max_sequence));
    BOOST_REQUIRE(window.Accept(0));
    BOOST_TEST(window.base_ == static_cast<uint64_t>(max_sequence) + 1u);
    BOOST_TEST(!window.Accept(max_sequence));
    BOOST_TEST(!window.Accept(0));
}

// Aim: re-sending the same sequence inside the window is rejected.
BOOST_AUTO_TEST_CASE(replay_rejects_duplicate_inside_window) {
    P2PReplayWindow window;
    BOOST_REQUIRE(window.Accept(100));
    BOOST_TEST(!window.Accept(100));
    BOOST_TEST(window.IsDuplicate(100));
}

// Aim: sequences older than REPLAY_WINDOW_SIZE are treated as duplicates (drop).
BOOST_AUTO_TEST_CASE(replay_rejects_seq_older_than_window) {
    P2PReplayWindow window;
    BOOST_REQUIRE(window.Accept(5000));
    const uint32_t stale = 5000 - static_cast<uint32_t>(REPLAY_WINDOW_SIZE);
    BOOST_TEST(window.IsDuplicate(stale));
    BOOST_TEST(!window.Accept(stale));
}

// Aim: the oldest sequence still represented by the bitmap is accepted once.
BOOST_AUTO_TEST_CASE(replay_accepts_window_size_minus_one_behind) {
    P2PReplayWindow window;
    const uint32_t base = 5000;
    const uint32_t oldest_in_window =
        base - static_cast<uint32_t>(REPLAY_WINDOW_SIZE - 1);
    BOOST_REQUIRE(window.Accept(base));
    BOOST_TEST(!window.IsDuplicate(oldest_in_window));
    BOOST_REQUIRE(window.Accept(oldest_in_window));
    BOOST_TEST(window.IsDuplicate(oldest_in_window));
    BOOST_TEST(!window.Accept(oldest_in_window));
}

// Aim: a jump beyond the bitmap clears history without allowing old packets back in.
BOOST_AUTO_TEST_CASE(replay_far_ahead_resets_window_and_rejects_old_base) {
    P2PReplayWindow window;
    const uint32_t first = 100;
    const uint32_t far_ahead =
        first + static_cast<uint32_t>(REPLAY_WINDOW_SIZE) + 17u;
    BOOST_REQUIRE(window.Accept(first));
    BOOST_REQUIRE(window.Accept(first - 1u));
    BOOST_REQUIRE(window.Accept(far_ahead));
    BOOST_TEST(window.base_ == far_ahead);
    BOOST_TEST(!window.Accept(first));
    BOOST_TEST(!window.Accept(far_ahead));
    BOOST_REQUIRE(window.Accept(far_ahead - 1u));
    BOOST_TEST(!window.Accept(far_ahead - 1u));
}

// Aim: packets reordered around uint32 rollover remain bounded and single-use.
BOOST_AUTO_TEST_CASE(replay_accepts_reordered_sequences_across_uint32_wrap_once) {
    P2PReplayWindow window;
    const uint32_t max_sequence = std::numeric_limits<uint32_t>::max();
    BOOST_REQUIRE(window.Accept(max_sequence - 1u));
    BOOST_REQUIRE(window.Accept(1));
    BOOST_REQUIRE(window.Accept(max_sequence));
    BOOST_REQUIRE(window.Accept(0));
    BOOST_TEST(!window.Accept(max_sequence));
    BOOST_TEST(!window.Accept(0));
}

// Aim: the ambiguous serial-number half range fails closed as stale.
BOOST_AUTO_TEST_CASE(replay_rejects_ambiguous_half_range_jump) {
    P2PReplayWindow window;
    BOOST_REQUIRE(window.Accept(7));
    BOOST_TEST(window.IsDuplicate(7u + P2PReplayWindow::SequenceHalfRange));
    BOOST_TEST(!window.Accept(7u + P2PReplayWindow::SequenceHalfRange));
}

// Aim: accepting newer sequences advances base; in-window older seqs stay duplicate.
BOOST_AUTO_TEST_CASE(replay_advances_base_on_newer_seq) {
    P2PReplayWindow window;
    BOOST_REQUIRE(window.Accept(10));
    BOOST_REQUIRE(window.Accept(20));
    BOOST_TEST(window.IsDuplicate(20));
    BOOST_TEST(!window.IsDuplicate(21));
    BOOST_TEST(window.IsDuplicate(10));
}

// Aim: Accept() refuses stale sequences (negative path for replay protection).
BOOST_AUTO_TEST_CASE(replay_does_not_accept_stale_seq) {
    P2PReplayWindow window;
    BOOST_REQUIRE(window.Accept(5000));
    const uint32_t stale = 5000 - static_cast<uint32_t>(REPLAY_WINDOW_SIZE);
    BOOST_TEST(!window.Accept(stale));
}
