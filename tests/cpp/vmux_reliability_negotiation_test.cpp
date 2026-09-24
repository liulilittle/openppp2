#define BOOST_TEST_MODULE vmux_reliability_negotiation_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/mux/MuxRuntimeState.h>

namespace mux = ppp::app::mux;

BOOST_AUTO_TEST_CASE(reliability_requires_both_ends) {
    const auto both = mux::NegotiateMuxRuntimeState(
        "compat", true, true, 2, false,
        /*local_reliability=*/true, /*peer_reliability=*/true);
    BOOST_TEST(both.reliability);
    BOOST_TEST(!both.fec);

    const auto peer_missing = mux::NegotiateMuxRuntimeState(
        "compat", true, true, 2, false,
        /*local_reliability=*/true, /*peer_reliability=*/false);
    BOOST_TEST(!peer_missing.reliability);

    const auto local_off = mux::NegotiateMuxRuntimeState(
        "compat", true, true, 2, false,
        /*local_reliability=*/false, /*peer_reliability=*/true);
    BOOST_TEST(!local_off.reliability);
}

BOOST_AUTO_TEST_CASE(fec_requires_reliability_and_both_ends) {
    const auto full = mux::NegotiateMuxRuntimeState(
        "balance", true, true, 2, false,
        /*local_reliability=*/true, /*peer_reliability=*/true,
        /*local_fec=*/true, /*peer_fec=*/true);
    BOOST_TEST(full.reliability);
    BOOST_TEST(full.fec);

    // FEC advertised without reliability never takes effect.
    const auto fec_without_reliability = mux::NegotiateMuxRuntimeState(
        "balance", true, true, 2, false,
        /*local_reliability=*/false, /*peer_reliability=*/true,
        /*local_fec=*/true, /*peer_fec=*/true);
    BOOST_TEST(!fec_without_reliability.reliability);
    BOOST_TEST(!fec_without_reliability.fec);
}

BOOST_AUTO_TEST_CASE(reliability_survives_ordering_fallback) {
    // balance without peer flow_v2 falls the whole preset back to compat, but
    // reliability is orthogonal to ordering and must stay negotiated.
    const auto state = mux::NegotiateMuxRuntimeState(
        "balance", true, false, 2, false,
        /*local_reliability=*/true, /*peer_reliability=*/true);

    BOOST_TEST(state.effective_mode == "compat");
    BOOST_TEST(state.receiver_ordering == "compat");
    BOOST_TEST(state.reliability);
}

BOOST_AUTO_TEST_CASE(agreed_result_applies_reliability_even_in_compat) {
    // Server fell back to compat ordering but agreed reliability: the client
    // must still enable it (compat mode ACKs the global sequence space).
    const auto client = mux::ApplyAgreedMuxRuntimeState(
        "balance", /*agreed_flow_v2=*/false, 2, false,
        /*agreed_reliability=*/true, /*agreed_fec=*/false);

    BOOST_TEST(client.effective_mode == "compat");
    BOOST_TEST(client.receiver_ordering == "compat");
    BOOST_TEST(client.reliability);
    BOOST_TEST(!client.fec);
}

BOOST_AUTO_TEST_CASE(agreed_fec_implies_agreed_reliability) {
    const auto client = mux::ApplyAgreedMuxRuntimeState(
        "flow", /*agreed_flow_v2=*/true, 1, true,
        /*agreed_reliability=*/true, /*agreed_fec=*/true);

    BOOST_TEST(client.receiver_ordering == "flow_v2");
    BOOST_TEST(client.reliability);
    BOOST_TEST(client.fec);

    // Defensive: fec without reliability is clamped off.
    const auto inconsistent = mux::ApplyAgreedMuxRuntimeState(
        "flow", /*agreed_flow_v2=*/true, 1, false,
        /*agreed_reliability=*/false, /*agreed_fec=*/true);
    BOOST_TEST(!inconsistent.reliability);
    BOOST_TEST(!inconsistent.fec);
}

BOOST_AUTO_TEST_CASE(default_arguments_keep_legacy_behavior) {
    // Existing callers (no reliability arguments) negotiate neither.
    const auto state = mux::NegotiateMuxRuntimeState("balance", true, true, 3);
    BOOST_TEST(!state.reliability);
    BOOST_TEST(!state.fec);

    const auto agreed = mux::ApplyAgreedMuxRuntimeState("compat", true, 1);
    BOOST_TEST(!agreed.reliability);
    BOOST_TEST(!agreed.fec);
}
