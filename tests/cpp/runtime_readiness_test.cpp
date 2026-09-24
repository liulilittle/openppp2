#define BOOST_TEST_MODULE runtime_readiness_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/runtime/RuntimeReadiness.h>

using ppp::app::runtime::GateConnectedPhase;
using ppp::app::runtime::BuildClientRuntimeReadiness;
using ppp::app::runtime::BuildServerRuntimeReadiness;
using ppp::app::runtime::ClientRuntimeReadinessFacts;
using ppp::app::runtime::RuntimePhase;
using ppp::app::runtime::RuntimeReadiness;

BOOST_AUTO_TEST_CASE(connected_requires_every_readiness_fact) {
    RuntimeReadiness readiness;
    readiness.session = true;
    readiness.adapter = true;
    readiness.route = true;
    readiness.dns = true;

    BOOST_TEST(!readiness.IsFullyReady());
    BOOST_TEST(static_cast<int>(GateConnectedPhase(RuntimePhase::Connected, readiness)) ==
               static_cast<int>(RuntimePhase::ApplyingPolicy));

    readiness.policy = true;
    BOOST_TEST(readiness.IsFullyReady());
    BOOST_TEST(static_cast<int>(GateConnectedPhase(RuntimePhase::Connected, readiness)) ==
               static_cast<int>(RuntimePhase::Connected));
}

BOOST_AUTO_TEST_CASE(non_connected_phases_are_not_rewritten) {
    const RuntimeReadiness readiness;
    BOOST_TEST(static_cast<int>(GateConnectedPhase(RuntimePhase::Reconnecting, readiness)) ==
               static_cast<int>(RuntimePhase::Reconnecting));
    BOOST_TEST(static_cast<int>(GateConnectedPhase(RuntimePhase::Failed, readiness)) ==
               static_cast<int>(RuntimePhase::Failed));
}

BOOST_AUTO_TEST_CASE(client_requires_open_adapter_and_committed_host_policy) {
    ClientRuntimeReadinessFacts facts;
    facts.session_established = true;
    facts.adapter_open = false;
    facts.route_applied = false;
    facts.dns_configured = true;
    facts.dns_session_active = true;
    facts.policy_negotiated = true;

    RuntimeReadiness readiness = BuildClientRuntimeReadiness(facts);
    BOOST_TEST(!readiness.adapter);
    BOOST_TEST(!readiness.route);
    BOOST_TEST(!readiness.IsFullyReady());

    facts.adapter_open = true;
    facts.route_required = false;
    readiness = BuildClientRuntimeReadiness(facts);
    BOOST_TEST(readiness.route);
    BOOST_TEST(readiness.IsFullyReady());
}

BOOST_AUTO_TEST_CASE(client_requires_active_dns_when_dns_policy_is_required) {
    ClientRuntimeReadinessFacts facts;
    facts.session_established = true;
    facts.adapter_open = true;
    facts.route_applied = true;
    facts.dns_configured = true;
    facts.dns_session_active = false;
    facts.policy_negotiated = true;

    RuntimeReadiness readiness = BuildClientRuntimeReadiness(facts);
    BOOST_TEST(!readiness.dns);
    BOOST_TEST(!readiness.IsFullyReady());

    facts.dns_required = false;
    readiness = BuildClientRuntimeReadiness(facts);
    BOOST_TEST(readiness.dns);
    BOOST_TEST(readiness.IsFullyReady());
}

BOOST_AUTO_TEST_CASE(server_readiness_is_derived_from_active_runtime_state) {
    BOOST_TEST(!BuildServerRuntimeReadiness(false).IsFullyReady());
    BOOST_TEST(BuildServerRuntimeReadiness(true).IsFullyReady());
}
