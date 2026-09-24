#define BOOST_TEST_MODULE vmux_link_churn_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/mux/MuxLinkDrainState.h>

namespace mux = ppp::app::mux;

BOOST_AUTO_TEST_CASE(retiring_link_waits_for_inflight_write) {
    mux::MuxLinkDrainState link;

    const auto write = link.BeginWrite();
    BOOST_REQUIRE(write);
    link.BeginRetire();

    BOOST_TEST(link.retiring());
    BOOST_TEST(!link.accepting_writes());
    BOOST_TEST(!link.reapable());
    BOOST_TEST(link.inflight() == 1u);
    BOOST_TEST(!link.BeginWrite());

    BOOST_TEST(link.CompleteWrite(write));
    BOOST_TEST(link.reapable());
}

BOOST_AUTO_TEST_CASE(rejected_write_submission_rolls_back_before_retire) {
    mux::MuxLinkDrainState link;

    const auto write = link.BeginWrite();
    BOOST_REQUIRE(write);
    BOOST_TEST(link.AbortWrite(write));
    link.BeginRetire();

    BOOST_TEST(link.inflight() == 0u);
    BOOST_TEST(link.reapable());

    // A defensive duplicate rollback must not underflow the counter.
    BOOST_TEST(!link.AbortWrite(write));
    BOOST_TEST(link.inflight() == 0u);
}

BOOST_AUTO_TEST_CASE(copied_ticket_is_consumed_exactly_once) {
    mux::MuxLinkDrainState link;
    const auto write_a = link.BeginWrite();
    const auto write_a_copy = write_a;
    const auto write_b = link.BeginWrite();
    BOOST_REQUIRE(write_a);
    BOOST_REQUIRE(write_b);
    BOOST_TEST(link.inflight() == 2u);

    BOOST_TEST(link.CompleteWrite(write_a));
    BOOST_TEST(!link.CompleteWrite(write_a_copy));
    BOOST_TEST(link.inflight() == 1u);
    BOOST_TEST(link.CompleteWrite(write_b));
    BOOST_TEST(link.inflight() == 0u);
}

BOOST_AUTO_TEST_CASE(grow_shrink_churn_drains_one_hundred_links) {
    for (int cycle = 0; cycle < 100; ++cycle) {
        mux::MuxLinkDrainState link;
        const auto first = link.BeginWrite();
        const auto second = link.BeginWrite();
        BOOST_REQUIRE(first);
        BOOST_REQUIRE(second);

        link.BeginRetire();
        BOOST_TEST(link.CompleteWrite(first));
        BOOST_TEST(!link.reapable());
        BOOST_TEST(link.CompleteWrite(second));
        BOOST_TEST(link.reapable());

        // Late or duplicate completions cannot underflow the counter.
        BOOST_TEST(!link.CompleteWrite(second));
        BOOST_TEST(link.inflight() == 0u);
    }
}
