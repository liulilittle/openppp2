#define BOOST_TEST_MODULE client_connection_teardown_state_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/ClientConnectionTeardown.h>

namespace client = ppp::app::client;

BOOST_AUTO_TEST_CASE(committed_dns_restore_survives_a_failed_route_cleanup) {
    client::ClientTeardownRouteState state;

    const client::ClientTeardownRouteActions first =
        state.CompleteAttempt(true, false);
    BOOST_TEST(first.restore_dns);
    BOOST_TEST(!first.release_network_state);
    state.MarkDnsRestoreResult(true);

    const client::ClientTeardownRouteActions retry =
        state.CompleteAttempt(false, true);
    BOOST_TEST(!retry.restore_dns);
    BOOST_TEST(retry.release_network_state);

    const client::ClientTeardownRouteActions already_complete =
        state.CompleteAttempt(false, true);
    BOOST_TEST(!already_complete.restore_dns);
    BOOST_TEST(already_complete.release_network_state);
}

BOOST_AUTO_TEST_CASE(uncommitted_default_rollback_does_not_arm_dns_restore) {
    client::ClientTeardownRouteState state;

    const client::ClientTeardownRouteActions first =
        state.CompleteAttempt(false, false);
    BOOST_TEST(!first.restore_dns);
    BOOST_TEST(!first.release_network_state);

    const client::ClientTeardownRouteActions retry =
        state.CompleteAttempt(false, true);
    BOOST_TEST(!retry.restore_dns);
    BOOST_TEST(retry.release_network_state);
}

BOOST_AUTO_TEST_CASE(failed_dns_restore_is_retained_for_a_later_attempt) {
    client::ClientTeardownRouteState state;

    const client::ClientTeardownRouteActions first =
        state.CompleteAttempt(true, false);
    BOOST_TEST(first.restore_dns);
    state.MarkDnsRestoreResult(false);

    const client::ClientTeardownRouteActions route_complete =
        state.CompleteAttempt(false, true);
    BOOST_TEST(route_complete.restore_dns);
    BOOST_TEST(!route_complete.release_network_state);

    state.MarkDnsRestoreResult(true);
    const client::ClientTeardownRouteActions restored =
        state.CompleteAttempt(false, true);
    BOOST_TEST(!restored.restore_dns);
    BOOST_TEST(restored.release_network_state);
}

BOOST_AUTO_TEST_CASE(route_retry_does_not_rearm_a_completed_dns_restore) {
    client::ClientTeardownRouteState state;

    const client::ClientTeardownRouteActions first =
        state.CompleteAttempt(true, false);
    BOOST_TEST(first.restore_dns);
    state.MarkDnsRestoreResult(true);

    const client::ClientTeardownRouteActions route_retry =
        state.CompleteAttempt(true, false);
    BOOST_TEST(!route_retry.restore_dns);
    BOOST_TEST(!route_retry.release_network_state);

    const client::ClientTeardownRouteActions completed =
        state.CompleteAttempt(false, true);
    BOOST_TEST(completed.release_network_state);

    const client::ClientTeardownRouteActions next_connection =
        state.CompleteAttempt(true, false);
    BOOST_TEST(next_connection.restore_dns);
}
