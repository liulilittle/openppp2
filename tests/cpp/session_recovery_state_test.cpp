#define BOOST_TEST_MODULE session_recovery_state_test
#include <boost/test/included/unit_test.hpp>

#include <limits>

#include <ppp/app/server/SessionRecoveryState.h>

using ppp::app::server::SessionRecoveryState;

static int StateValue(SessionRecoveryState::State state) noexcept {
    return static_cast<int>(state);
}

BOOST_AUTO_TEST_CASE(new_session_is_active_with_first_generation) {
    SessionRecoveryState state;
    BOOST_TEST(StateValue(state.GetState()) == StateValue(SessionRecoveryState::State::Active));
    BOOST_TEST(state.GetGeneration() == 1u);
    BOOST_TEST(state.GetDeadline() == 0u);
    BOOST_TEST(!state.ReserveResume(1, 100, 1));
}

BOOST_AUTO_TEST_CASE(reserve_and_commit_advance_generation) {
    SessionRecoveryState state;
    BOOST_TEST(state.Suspend(1, 100, 50));
    BOOST_TEST(state.IsSuspended(149));
    BOOST_TEST(state.ReserveResume(1, 149, 7));
    BOOST_TEST(state.HasResumeReservation());
    BOOST_TEST(!state.ReserveResume(1, 149, 8));
    BOOST_TEST(state.CanCommitResume(1, 149, 7));
    BOOST_TEST(state.CommitResume(1, 149, 7));
    BOOST_TEST(StateValue(state.GetState()) == StateValue(SessionRecoveryState::State::Active));
    BOOST_TEST(state.GetGeneration() == 2u);
    BOOST_TEST(state.GetDeadline() == 0u);
    BOOST_TEST(!state.HasResumeReservation());
}

BOOST_AUTO_TEST_CASE(commit_then_runs_non_failing_publication_boundary) {
    SessionRecoveryState state;
    BOOST_REQUIRE(state.Suspend(1, 100, 50));
    BOOST_REQUIRE(state.ReserveResume(1, 120, 7));

    bool published = false;
    bool observed_active = false;
    bool observed_generation = false;
    bool observed_reservation_cleared = false;
    BOOST_REQUIRE(ppp::app::server::CommitSessionResumeAndPublish(
        state, 1, 120, 7,
        [&](std::uint64_t generation) noexcept {
            observed_active = state.GetState() == SessionRecoveryState::State::Active;
            observed_generation = generation == 2 && state.GetGeneration() == 2;
            observed_reservation_cleared = !state.HasResumeReservation();
            published = true;
        }));
    BOOST_TEST(published);
    BOOST_TEST(observed_active);
    BOOST_TEST(observed_generation);
    BOOST_TEST(observed_reservation_cleared);

    SessionRecoveryState rejected;
    BOOST_REQUIRE(rejected.Suspend(1, 100, 50));
    BOOST_REQUIRE(rejected.ReserveResume(1, 120, 9));
    bool rejected_publication = false;
    BOOST_TEST(!ppp::app::server::CommitSessionResumeAndPublish(
        rejected, 1, 120, 8,
        [&](std::uint64_t) noexcept { rejected_publication = true; }));
    BOOST_TEST(!rejected_publication);
    BOOST_TEST(rejected.GetGeneration() == 1u);
    BOOST_TEST(rejected.IsSuspended(120));
    BOOST_TEST(rejected.HasResumeReservation());
}

BOOST_AUTO_TEST_CASE(committed_reservation_survives_original_deadline_for_publish) {
    SessionRecoveryState state;
    BOOST_REQUIRE(state.Suspend(1, 100, 50));
    BOOST_REQUIRE(state.ReserveResume(1, 149, 7));
    // Commit validates at the original deadline edge; publish happens after it.
    BOOST_REQUIRE(state.MarkResumeCommitted(7, 149, 10));
    BOOST_TEST(state.GetDeadline() == 159u);
    BOOST_TEST(state.CanCommitResume(1, 155, 7));
    BOOST_TEST(state.CommitResume(1, 155, 7));
    BOOST_TEST(StateValue(state.GetState()) == StateValue(SessionRecoveryState::State::Active));
}

BOOST_AUTO_TEST_CASE(mark_committed_extends_only_and_requires_matching_token) {
    SessionRecoveryState state;
    BOOST_REQUIRE(state.Suspend(1, 100, 500));
    BOOST_REQUIRE(state.ReserveResume(1, 100, 7));
    BOOST_TEST(!state.MarkResumeCommitted(8, 100, 10));
    // A shorter publish grace must not shorten the existing deadline.
    BOOST_REQUIRE(state.MarkResumeCommitted(7, 100, 10));
    BOOST_TEST(state.GetDeadline() == 600u);
}

BOOST_AUTO_TEST_CASE(cancel_requires_matching_nonzero_token) {
    SessionRecoveryState state;
    BOOST_TEST(state.Suspend(1, 100, 50));
    BOOST_TEST(!state.ReserveResume(1, 120, 0));
    BOOST_TEST(state.ReserveResume(1, 120, 7));
    BOOST_TEST(!state.CommitResume(1, 120, 8));
    BOOST_TEST(!state.CancelResume(0));
    BOOST_TEST(!state.CancelResume(8));
    BOOST_TEST(state.HasResumeReservation());
    BOOST_TEST(state.CancelResume(7));
    BOOST_TEST(!state.HasResumeReservation());
    BOOST_TEST(state.IsSuspended(120));
    BOOST_TEST(state.ReserveResume(1, 120, 9));
}

BOOST_AUTO_TEST_CASE(deadline_is_exclusive_and_expiry_clears_reservation) {
    SessionRecoveryState state;
    BOOST_TEST(state.Suspend(1, 100, 50));
    BOOST_TEST(state.ReserveResume(1, 149, 7));
    BOOST_TEST(!state.CanCommitResume(1, 150, 7));
    BOOST_TEST(state.IsExpired(150));
    BOOST_TEST(StateValue(state.GetState()) == StateValue(SessionRecoveryState::State::Expired));
    BOOST_TEST(!state.HasResumeReservation());
    BOOST_TEST(!state.CommitResume(1, 149, 7));
    BOOST_TEST(!state.CancelResume(7));
}

BOOST_AUTO_TEST_CASE(stale_generation_cannot_change_state) {
    SessionRecoveryState state;
    BOOST_TEST(!state.Suspend(2, 100, 50));
    BOOST_TEST(state.Suspend(1, 100, 50));
    BOOST_TEST(!state.ReserveResume(2, 120, 7));
    BOOST_TEST(state.ReserveResume(1, 120, 7));
    BOOST_TEST(!state.CanCommitResume(2, 120, 7));
    BOOST_TEST(!state.CommitResume(2, 120, 7));
    BOOST_TEST(state.GetGeneration() == 1u);
}

BOOST_AUTO_TEST_CASE(deadline_addition_saturates) {
    const std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
    SessionRecoveryState state;
    BOOST_TEST(state.Suspend(1, maximum - 5, 10));
    BOOST_TEST(state.GetDeadline() == maximum);
    BOOST_TEST(state.IsSuspended(maximum - 1));
    BOOST_TEST(state.IsExpired(maximum));
}
