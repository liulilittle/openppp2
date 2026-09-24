#define BOOST_TEST_MODULE p2p_control_state_machine_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PControlStateMachine.h>

using namespace ppp::p2p;

BOOST_AUTO_TEST_CASE(follows_the_bounded_probe_and_fallback_lifecycle) {
    P2PControlStateMachine machine;
    BOOST_TEST(static_cast<int>(machine.State()) == static_cast<int>(P2PState::Relay));
    BOOST_REQUIRE(machine.MarkEligible());
    BOOST_TEST(static_cast<int>(machine.State()) == static_cast<int>(P2PState::Eligible));
    BOOST_REQUIRE(machine.AcceptOffer());
    BOOST_TEST(static_cast<int>(machine.State()) == static_cast<int>(P2PState::Probing));
    BOOST_TEST(std::string(machine.EffectivePath()) == "relay");
    BOOST_REQUIRE(machine.BeginFallback(P2PFallbackReason::Timeout));
    BOOST_TEST(static_cast<int>(machine.State()) == static_cast<int>(P2PState::FallingBack));
    BOOST_REQUIRE(machine.CompleteFallback(true));
    BOOST_TEST(static_cast<int>(machine.State()) == static_cast<int>(P2PState::Relay));
}

BOOST_AUTO_TEST_CASE(unauthenticated_ack_never_enters_direct) {
    P2PControlStateMachine machine;
    BOOST_REQUIRE(machine.MarkEligible());
    BOOST_REQUIRE(machine.AcceptOffer());
    BOOST_TEST(!machine.AcceptProbeAck(false));
    BOOST_TEST(static_cast<int>(machine.State()) == static_cast<int>(P2PState::Probing));
    BOOST_TEST(std::string(machine.EffectivePath()) == "relay");
}

BOOST_AUTO_TEST_CASE(bare_authenticated_claim_never_enters_direct) {
    P2PControlStateMachine machine;
    BOOST_REQUIRE(machine.MarkEligible());
    BOOST_REQUIRE(machine.AcceptOffer());
    BOOST_TEST(!machine.AcceptProbeAck(true));
    BOOST_TEST(static_cast<int>(machine.State()) == static_cast<int>(P2PState::Probing));
    BOOST_TEST(std::string(machine.EffectivePath()) == "relay");
}

BOOST_AUTO_TEST_CASE(relay_path_is_invariant_for_every_non_direct_state) {
    for (const auto state : {P2PState::Disabled, P2PState::Unavailable,
             P2PState::Relay, P2PState::Eligible, P2PState::Probing,
             P2PState::Suspect, P2PState::FallingBack, P2PState::Failed}) {
        BOOST_TEST(std::string(P2PControlStateMachine::EffectivePathFor(state)) == "relay");
    }
    BOOST_TEST(std::string(P2PControlStateMachine::EffectivePathFor(P2PState::Direct)) == "direct");
}

BOOST_AUTO_TEST_CASE(data_forwarding_is_allowed_only_in_direct) {
    for (const auto state : {P2PState::Disabled, P2PState::Unavailable,
             P2PState::Relay, P2PState::Eligible, P2PState::Probing,
             P2PState::Suspect, P2PState::FallingBack, P2PState::Failed}) {
        BOOST_TEST(!P2PControlStateMachine::CanForwardDataFor(state));
    }
    BOOST_TEST(P2PControlStateMachine::CanForwardDataFor(P2PState::Direct));
}

BOOST_AUTO_TEST_CASE(rejects_out_of_order_transitions) {
    P2PControlStateMachine machine;
    BOOST_TEST(!machine.AcceptOffer());
    BOOST_TEST(!machine.AcceptProbeAck(true));
    BOOST_TEST(!machine.MarkSuspect());
    BOOST_TEST(!machine.CompleteFallback(true));
    BOOST_TEST(static_cast<int>(machine.State()) == static_cast<int>(P2PState::Relay));
}

BOOST_AUTO_TEST_CASE(fallback_can_end_unavailable_or_disabled_without_losing_relay_path) {
    P2PControlStateMachine machine;
    BOOST_REQUIRE(machine.MarkEligible());
    BOOST_REQUIRE(machine.BeginFallback(P2PFallbackReason::AuthenticationFailure));
    BOOST_REQUIRE(machine.CompleteFallback(false));
    BOOST_TEST(static_cast<int>(machine.State()) == static_cast<int>(P2PState::Unavailable));
    BOOST_TEST(std::string(machine.EffectivePath()) == "relay");
    BOOST_REQUIRE(machine.Disable());
    BOOST_TEST(static_cast<int>(machine.State()) == static_cast<int>(P2PState::Disabled));
    BOOST_TEST(std::string(machine.EffectivePath()) == "relay");
}

BOOST_AUTO_TEST_CASE(falling_back_can_complete_directly_to_disabled) {
    P2PControlStateMachine machine;
    BOOST_REQUIRE(machine.MarkEligible());
    BOOST_REQUIRE(machine.BeginFallback(P2PFallbackReason::SocketError));
    BOOST_REQUIRE(machine.Disable());
    BOOST_TEST(static_cast<int>(machine.State()) == static_cast<int>(P2PState::Disabled));
    BOOST_TEST(std::string(machine.EffectivePath()) == "relay");
}

BOOST_AUTO_TEST_CASE(probing_failures_record_reason_and_fall_back_to_relay) {
    for (const auto reason : {P2PFallbackReason::Timeout,
             P2PFallbackReason::AuthenticationFailure}) {
        P2PControlStateMachine machine;
        BOOST_REQUIRE(machine.MarkEligible());
        BOOST_REQUIRE(machine.AcceptOffer());
        BOOST_REQUIRE(machine.BeginFallback(reason));
        BOOST_TEST(static_cast<int>(machine.State()) ==
            static_cast<int>(P2PState::FallingBack));
        BOOST_TEST(static_cast<int>(machine.FallbackReason()) ==
            static_cast<int>(reason));
        BOOST_TEST(std::string(machine.EffectivePath()) == "relay");
        BOOST_REQUIRE(machine.CompleteFallback(true));
        BOOST_TEST(static_cast<int>(machine.State()) ==
            static_cast<int>(P2PState::Relay));
        BOOST_TEST(static_cast<int>(machine.FallbackReason()) ==
            static_cast<int>(reason));
        BOOST_REQUIRE(machine.MarkEligible());
        BOOST_TEST(static_cast<int>(machine.FallbackReason()) ==
            static_cast<int>(P2PFallbackReason::None));
    }
}

BOOST_AUTO_TEST_CASE(fallback_rejects_missing_reason) {
    P2PControlStateMachine machine;
    BOOST_REQUIRE(machine.MarkEligible());
    BOOST_TEST(!machine.BeginFallback(P2PFallbackReason::None));
    BOOST_TEST(static_cast<int>(machine.State()) == static_cast<int>(P2PState::Eligible));
}

BOOST_AUTO_TEST_CASE(authenticated_recovery_returns_direct_from_suspect) {
    P2PControlStateMachine machine;
    BOOST_REQUIRE(machine.MarkEligible());
    BOOST_REQUIRE(machine.AcceptOffer());
    auto first = detail::P2PAuthenticatedProbeAckFactory::Create();
    BOOST_REQUIRE(machine.AcceptProbeAck(std::move(first)));
    BOOST_REQUIRE(machine.MarkSuspect());
    BOOST_TEST(static_cast<int>(machine.State()) ==
        static_cast<int>(P2PState::Suspect));
    BOOST_TEST(std::string(machine.EffectivePath()) == "relay");
    BOOST_TEST(!machine.AcceptRecoveryAck(false));
    BOOST_TEST(!machine.AcceptRecoveryAck(true));
    auto recovery = detail::P2PAuthenticatedProbeAckFactory::Create();
    BOOST_REQUIRE(machine.AcceptRecoveryAck(std::move(recovery)));
    BOOST_TEST(static_cast<int>(machine.State()) ==
        static_cast<int>(P2PState::Direct));
    BOOST_TEST(std::string(machine.EffectivePath()) == "direct");
    BOOST_TEST(P2PControlStateMachine::CanForwardDataFor(machine.State()));
}
