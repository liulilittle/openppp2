#define BOOST_TEST_MODULE client_reconnection_policy_test
#include <boost/test/included/unit_test.hpp>

#include <limits>

#include <ppp/app/client/ClientReconnectionPolicy.h>

using ppp::app::client::ClientReconnectionPolicy;

BOOST_AUTO_TEST_CASE(exponential_delay_caps_without_overflow) {
    ClientReconnectionPolicy policy(100, 800, 0);
    BOOST_TEST(policy.OnFailure(0) == 100u);
    BOOST_TEST(policy.OnFailure(0) == 200u);
    BOOST_TEST(policy.OnFailure(0) == 400u);
    BOOST_TEST(policy.OnFailure(0) == 800u);
    BOOST_TEST(policy.OnFailure(0) == 800u);
}

BOOST_AUTO_TEST_CASE(jitter_obeys_deterministic_bounds) {
    ClientReconnectionPolicy low(100, 1000, 20);
    ClientReconnectionPolicy high(100, 1000, 20);
    BOOST_TEST(low.OnFailure(0) == 80u);
    BOOST_TEST(high.OnFailure(40) == 120u);

    ClientReconnectionPolicy capped_low(1000, 1000, 20);
    ClientReconnectionPolicy capped_mid(1000, 1000, 20);
    ClientReconnectionPolicy capped_high(1000, 1000, 20);
    BOOST_TEST(capped_low.OnFailure(0) == 800u);
    BOOST_TEST(capped_mid.OnFailure(200) == 1000u);
    BOOST_TEST(capped_high.OnFailure(400) == 1200u);
}

BOOST_AUTO_TEST_CASE(reset_restarts_at_base_delay) {
    ClientReconnectionPolicy policy(50, 400, 0);
    BOOST_TEST(policy.OnFailure(0) == 50u);
    BOOST_TEST(policy.OnFailure(0) == 100u);
    policy.Reset();
    BOOST_TEST(policy.GetAttempt() == 0u);
    BOOST_TEST(policy.OnFailure(0) == 50u);
}

BOOST_AUTO_TEST_CASE(attempt_counter_saturates) {
    const std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
    ClientReconnectionPolicy policy(1, 1024, 0, maximum);
    BOOST_TEST(policy.OnFailure(0) == 1024u);
    BOOST_TEST(policy.GetAttempt() == maximum);
}
