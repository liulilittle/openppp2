#define BOOST_TEST_MODULE runtime_stop_coordinator_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/runtime/RuntimeStopCoordinator.h>

using ppp::app::runtime::RuntimeStopCoordinator;

BOOST_AUTO_TEST_CASE(stop_is_rejected_before_generation_activation) {
    RuntimeStopCoordinator stop;
    BOOST_TEST(!stop.TryBeginStop(0));
    BOOST_TEST(!stop.TryBeginStop(1));
    BOOST_TEST(!stop.BeginGeneration(0));
}

BOOST_AUTO_TEST_CASE(stop_is_claimed_once_per_generation) {
    RuntimeStopCoordinator stop;
    BOOST_REQUIRE(stop.BeginGeneration(7));

    BOOST_TEST(stop.TryBeginStop(7));
    BOOST_TEST(!stop.TryBeginStop(7));
    BOOST_TEST(stop.IsStopping(7));

    stop.CompleteStop(7, true);
    BOOST_TEST(!stop.IsStopping(7));
    BOOST_TEST(stop.IsCompleted(7));
    BOOST_TEST(stop.WasCleanupSuccessful(7));
    BOOST_TEST(!stop.TryBeginStop(7));
}

BOOST_AUTO_TEST_CASE(duplicate_generation_cannot_reopen_completed_stop) {
    RuntimeStopCoordinator stop;
    BOOST_REQUIRE(stop.BeginGeneration(7));
    BOOST_REQUIRE(stop.TryBeginStop(7));
    stop.CompleteStop(7, true);

    BOOST_TEST(!stop.BeginGeneration(7));
    BOOST_TEST(stop.IsCompleted(7));
    BOOST_TEST(!stop.TryBeginStop(7));
}

BOOST_AUTO_TEST_CASE(old_generation_cannot_stop_new_session) {
    RuntimeStopCoordinator stop;
    BOOST_REQUIRE(stop.BeginGeneration(7));
    BOOST_REQUIRE(stop.TryBeginStop(7));
    stop.CompleteStop(7, true);

    BOOST_REQUIRE(stop.BeginGeneration(8));
    BOOST_TEST(!stop.TryBeginStop(7));
    BOOST_TEST(stop.TryBeginStop(8));
}

BOOST_AUTO_TEST_CASE(stale_completion_does_not_complete_current_generation) {
    RuntimeStopCoordinator stop;
    BOOST_REQUIRE(stop.BeginGeneration(8));
    BOOST_REQUIRE(stop.TryBeginStop(8));

    stop.CompleteStop(7, true);
    BOOST_TEST(stop.IsStopping(8));
    BOOST_TEST(!stop.IsCompleted(8));

    stop.CompleteStop(8, false);
    BOOST_TEST(stop.IsCompleted(8));
    BOOST_TEST(!stop.WasCleanupSuccessful(8));
}
