#define BOOST_TEST_MODULE vmux_flow_context_admission_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/mux/MuxFlowContextAdmission.h>

namespace mux = ppp::app::mux;

static unsigned as_u(mux::FlowContextAdmission v) {
    return static_cast<unsigned>(v);
}

BOOST_AUTO_TEST_CASE(zero_connection_id_is_rejected) {
    BOOST_TEST(
        as_u(mux::AdmitFlowContext(0, false, true, 0, 8)) ==
        as_u(mux::FlowContextAdmission::RejectZero));
}

BOOST_AUTO_TEST_CASE(already_tracked_flow_is_allowed) {
    BOOST_TEST(
        as_u(mux::AdmitFlowContext(7, true, false, 3, 8)) ==
        as_u(mux::FlowContextAdmission::AllowExisting));
}

BOOST_AUTO_TEST_CASE(unknown_connection_id_is_rejected_before_create) {
    BOOST_TEST(
        as_u(mux::AdmitFlowContext(99, false, false, 0, 8)) ==
        as_u(mux::FlowContextAdmission::RejectUnknown));
}

BOOST_AUTO_TEST_CASE(known_socket_under_cap_may_create) {
    BOOST_TEST(
        as_u(mux::AdmitFlowContext(3, false, true, 2, 8)) ==
        as_u(mux::FlowContextAdmission::AllowCreate));
}

BOOST_AUTO_TEST_CASE(context_cap_blocks_new_fake_or_extra_flows) {
    BOOST_TEST(
        as_u(mux::AdmitFlowContext(4, false, true, 8, 8)) ==
        as_u(mux::FlowContextAdmission::RejectCap));
}

BOOST_AUTO_TEST_CASE(zero_cap_means_unbounded_create_for_known_socket) {
    // Cap 0 is treated as "no additional limit" by the admission helper; the
    // runtime still latches PPP_MUX_FLOW_MAX_CONTEXTS before calling this.
    BOOST_TEST(
        as_u(mux::AdmitFlowContext(5, false, true, 1000, 0)) ==
        as_u(mux::FlowContextAdmission::AllowCreate));
}
