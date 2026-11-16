#define BOOST_TEST_MODULE vmux_rx_queue_limit_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/mux/MuxRxQueueLimit.h>

namespace mux = ppp::app::mux;

BOOST_AUTO_TEST_CASE(under_cap_is_accepted) {
    BOOST_TEST(!mux::MuxRxQueueOverflows(10, 1000, 100, 1 << 20));
}

BOOST_AUTO_TEST_CASE(byte_cap_is_twice_soft_threshold) {
    BOOST_TEST(mux::MuxRxQueueHardMaxBytes(1000) == 2000);
    BOOST_TEST(!mux::MuxRxQueueOverflows(1, 1900, 100, 1000));
    BOOST_TEST(mux::MuxRxQueueOverflows(1, 1901, 100, 1000));
}

BOOST_AUTO_TEST_CASE(flow_control_off_still_has_cap) {
    BOOST_TEST(mux::MuxRxQueueHardMaxBytes(0) == mux::kMuxRxQueueHardMaxBytesNoFc);
    BOOST_TEST(mux::MuxRxQueueOverflows(1, mux::kMuxRxQueueHardMaxBytesNoFc, 1, 0));
}

BOOST_AUTO_TEST_CASE(packet_count_cap) {
    BOOST_TEST(!mux::MuxRxQueueOverflows(mux::kMuxRxQueueHardMaxPackets - 1, 0, 1, 1 << 30));
    BOOST_TEST(mux::MuxRxQueueOverflows(mux::kMuxRxQueueHardMaxPackets, 0, 1, 1 << 30));
}

BOOST_AUTO_TEST_CASE(empty_push_is_noop) {
    BOOST_TEST(mux::MuxIsNoopPush(0));
    BOOST_TEST(mux::MuxIsNoopPush(-1));
    BOOST_TEST(!mux::MuxIsNoopPush(1));
}
