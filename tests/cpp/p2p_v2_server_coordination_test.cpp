#define BOOST_TEST_MODULE p2p_v2_server_coordination_test
#include <boost/test/included/unit_test.hpp>
#include <ppp/p2p/P2PV2ServerCoordination.h>

using State = ppp::p2p::P2PV2ServerCoordination;
namespace {
State::Hash Hash(unsigned value) { State::Hash hash{}; hash[0] = static_cast<std::uint8_t>(value); return hash; }
void Pending(State& state, std::uint64_t now = 0, std::uint64_t generation = 1) {
    BOOST_REQUIRE(state.Begin(now, generation));
    BOOST_REQUIRE(state.Complete(generation, Hash(1), now + 10));
}
}

BOOST_AUTO_TEST_CASE(generation_and_send_are_bound_to_live_pending_offer) {
    State state;
    Pending(state);
    BOOST_TEST(state.CanSend(1, Hash(1), 10));
    BOOST_TEST(!state.CanSend(2, Hash(1), 10));
    BOOST_TEST(!state.CanSend(1, Hash(2), 10));
    BOOST_TEST(!state.CanSend(1, Hash(1), 60010));
    BOOST_REQUIRE(state.Cancel({}, Hash(1)));
    BOOST_TEST(!state.CanSend(1, Hash(1), 11));
    BOOST_TEST(!state.Complete(1, Hash(1), 12));
}
BOOST_AUTO_TEST_CASE(simultaneous_renew_coalesces_and_does_not_restart_budget) {
    State state;
    BOOST_REQUIRE(state.Begin(0, 1));
    BOOST_TEST(!state.Begin(1, 2));
    BOOST_TEST(!state.ExpirePending(9999));
    BOOST_TEST(state.ExpirePending(10000));
    BOOST_TEST(!state.Complete(1, Hash(1), 10000));
    BOOST_REQUIRE(state.Begin(10000, 2));
    BOOST_TEST(!state.Complete(1, Hash(1), 10001));
    BOOST_REQUIRE(state.Complete(2, Hash(2), 10001));
    BOOST_TEST(!state.Begin(20000, 3));
}
BOOST_AUTO_TEST_CASE(cancel_cannot_race_bilateral_activation) {
    State state;
    Pending(state);
    BOOST_TEST(state.Activate(Hash(2), true, 11) == 0u);
    BOOST_TEST(state.Activate(Hash(1), true, 11) == 1u);
    BOOST_TEST(state.Activate(Hash(1), true, 12) == 1u);
    BOOST_TEST(!state.Cancel({}, Hash(1)));
    BOOST_TEST(state.Activate(Hash(1), false, 13) == 2u);
    BOOST_TEST(state.Activate(Hash(1), false, 14) == 2u);
    BOOST_TEST(!state.CanSend(1, Hash(1), 14));
    BOOST_TEST(state.CurrentExpiresAt == 60013u);
}
BOOST_AUTO_TEST_CASE(zero_predecessor_recovers_only_after_conservative_hard_expiry) {
    State state;
    Pending(state);
    BOOST_REQUIRE(state.Activate(Hash(1), true, 11) == 1u);
    BOOST_REQUIRE(state.Activate(Hash(1), false, 12) == 2u);
    BOOST_TEST(!state.MatchesPredecessor({}, 60011));
    BOOST_TEST(state.MatchesPredecessor({}, 60012));
    BOOST_TEST(state.Activate(Hash(1), true, 60012) == 0u);
    BOOST_REQUIRE(state.Begin(60012, 2));
    BOOST_REQUIRE(state.Complete(2, Hash(2), 60013));
}
BOOST_AUTO_TEST_CASE(refresh_failure_preserves_current_and_late_reports_are_rejected) {
    State state;
    Pending(state);
    BOOST_REQUIRE(state.Activate(Hash(1), true, 11) == 1u);
    BOOST_REQUIRE(state.Activate(Hash(1), false, 12) == 2u);
    BOOST_REQUIRE(state.Begin(40000, 2));
    BOOST_REQUIRE(state.Complete(2, Hash(2), 40001));
    BOOST_TEST(!state.Cancel(Hash(3), Hash(2)));
    BOOST_REQUIRE(state.Cancel(Hash(1), Hash(2)));
    BOOST_TEST(state.MatchesPredecessor(Hash(1), 40002));
    BOOST_TEST(state.Activate(Hash(2), true, 40002) == 0u);
}
BOOST_AUTO_TEST_CASE(expired_partial_activation_and_backwards_clock_do_not_extend_state) {
    State state;
    BOOST_REQUIRE(state.Begin(100, 1));
    BOOST_TEST(!state.Complete(1, Hash(1), 99));
    BOOST_REQUIRE(state.Complete(1, Hash(1), 101));
    BOOST_TEST(state.Activate(Hash(1), true, 102) == 1u);
    BOOST_TEST(state.Activate(Hash(1), false, 60101) == 0u);
    BOOST_TEST(state.ExpirePending(60101));
    BOOST_TEST(state.MatchesPredecessor({}, 60101));
}
BOOST_AUTO_TEST_CASE(explicit_renew_preserves_authenticated_predecessor_after_server_expiry) {
    State state;
    Pending(state);
    BOOST_REQUIRE(state.Activate(Hash(1), true, 11) == 1u);
    BOOST_REQUIRE(state.Activate(Hash(1), false, 12) == 2u);
    BOOST_TEST(!state.PrepareOffer(60011, false));
    BOOST_REQUIRE(state.MatchesPredecessor(Hash(1), 60012));
    BOOST_REQUIRE(state.PrepareOffer(60012, true));
    BOOST_TEST(state.CurrentHash == Hash(1), boost::test_tools::per_element());
    BOOST_REQUIRE(state.Begin(60012, 2));
    BOOST_TEST(state.CurrentHash == Hash(1), boost::test_tools::per_element());
    state.ClearPending();
    BOOST_REQUIRE(state.PrepareOffer(60013, false));
    BOOST_TEST(state.CurrentHash == State::Hash{}, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(explicit_renew_can_restart_before_offer_throttle) {
    State state;
    Pending(state);
    BOOST_REQUIRE(state.Activate(Hash(1), true, 11) == 1u);
    BOOST_REQUIRE(state.Activate(Hash(1), false, 12) == 2u);
    BOOST_TEST(!state.Begin(100, 2));
    BOOST_REQUIRE(state.Begin(100, 2, true));
}

BOOST_AUTO_TEST_CASE(explicit_zero_predecessor_clears_stale_current) {
    State state;
    Pending(state);
    BOOST_REQUIRE(state.Activate(Hash(1), true, 11) == 1u);
    BOOST_REQUIRE(state.Activate(Hash(1), false, 12) == 2u);
    state.ResetForExplicitRenew();
    BOOST_TEST(state.CurrentHash == State::Hash{}, boost::test_tools::per_element());
    BOOST_TEST(state.CurrentExpiresAt == 0u);
    BOOST_REQUIRE(state.Begin(100, 2, true));
}
