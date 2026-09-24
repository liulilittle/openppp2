#define BOOST_TEST_MODULE p2p_offer_token_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2POfferToken.h>
#include <ppp/p2p/P2PControlStateMachine.h>
#include <ppp/p2p/P2PDirectActivationCoordinator.h>
#include <ppp/p2p/P2PKeyDerivation.h>

#include <array>
#include <stdexcept>

using namespace ppp::p2p;

namespace {
template <std::size_t N>
std::array<std::uint8_t, N> Bytes(std::uint8_t seed) {
    std::array<std::uint8_t, N> value{};
    for (std::size_t i = 0; i < N; ++i) value[i] = seed + i;
    return value;
}

P2PCandidateEndpoint Endpoint(std::uint8_t seed, std::uint16_t port) {
    P2PCandidateEndpoint endpoint;
    endpoint.address_family = 6;
    endpoint.address = Bytes<16>(seed);
    endpoint.port = port;
    return endpoint;
}

P2POfferBinding Binding() {
    P2POfferBinding binding;
    binding.version = 1;
    binding.offer_id = Bytes<16>(1);
    binding.initiator_session_id = Bytes<16>(20);
    binding.responder_session_id = Bytes<16>(40);
    binding.initiator_peer_id = Bytes<16>(60);
    binding.responder_peer_id = Bytes<16>(80);
    binding.connection_epoch = Bytes<16>(100);
    binding.message_type = P2PControlType::Probe;
    binding.offer_hash = Bytes<32>(180);
    binding.sender_role = 0;
    binding.receiver_role = 1;
    binding.direction = 0;
    binding.sequence = 7;
    binding.nonce = BuildP2PV1Nonce(Bytes<8>(200), binding.sequence);
    binding.source = Endpoint(120, 4000);
    binding.destination = Endpoint(140, 5000);
    binding.ttl_seconds = 30;
    return binding;
}

P2POfferBinding ProbeAckBinding(const P2POfferBinding& probe) {
    auto binding = probe;
    binding.message_type = P2PControlType::ProbeAck;
    binding.sender_role = 1;
    binding.receiver_role = 0;
    binding.direction = 1;
    binding.source = Endpoint(140, 5000);
    binding.destination = Endpoint(120, 4000);
    binding.sequence = 8;
    binding.nonce = BuildP2PV1Nonce(Bytes<8>(210), binding.sequence);
    if (!CreateP2PProbeTranscriptHash(probe, binding.probe_transcript_hash)) {
        throw std::runtime_error("failed to hash probe transcript");
    }
    return binding;
}

bool ValidateOnce(const std::array<std::uint8_t, 32>& key,
                  const P2POfferBinding& received,
                  const P2POfferBinding& current,
                  const P2PCandidateEndpoint& source,
                  const P2PCandidateEndpoint& destination,
                  std::uint64_t elapsed,
                  const P2POfferToken& token) {
    P2PReplayWindow replay;
    return ValidateP2POfferToken(key, received, current, source, destination,
        elapsed, token, Bytes<8>(200), replay);
}
}

BOOST_AUTO_TEST_CASE(accepts_only_an_unexpired_fully_bound_token) {
    const auto key = Bytes<32>(9);
    const auto binding = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, binding, token));
    BOOST_TEST(ValidateOnce(key, binding, binding,
        binding.source, binding.destination, 29'999, token));
    BOOST_TEST(!ValidateOnce(key, binding, binding,
        binding.source, binding.destination, 30'000, token));
}

BOOST_AUTO_TEST_CASE(rejects_ttl_outside_one_through_thirty) {
    const auto key = Bytes<32>(9);
    auto binding = Binding();
    P2POfferToken token{};
    binding.ttl_seconds = 0;
    BOOST_TEST(!CreateP2POfferToken(key, binding, token));
    binding.ttl_seconds = 31;
    BOOST_TEST(!CreateP2POfferToken(key, binding, token));
}

BOOST_AUTO_TEST_CASE(token_api_rejects_noncanonical_ipv4_candidates) {
    const auto key = Bytes<32>(9);
    auto binding = Binding();
    binding.source.address_family = 4;
    binding.source.address = {};
    binding.source.address[12] = 192;
    binding.source.address[13] = 0;
    binding.source.address[14] = 2;
    binding.source.address[15] = 1;
    P2POfferToken token{};
    BOOST_TEST(!CreateP2POfferToken(key, binding, token));

    binding.source.address[10] = 0xff;
    binding.source.address[11] = 0xff;
    BOOST_TEST(CreateP2POfferToken(key, binding, token));
}

BOOST_AUTO_TEST_CASE(rejects_wrong_peer_both_sessions_direction_and_candidate) {
    const auto key = Bytes<32>(9);
    const auto received = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, received, token));

    auto expected = received;
    expected.initiator_peer_id[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, received, expected,
        received.source, received.destination, 0, token));
    expected = received;
    expected.initiator_session_id[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, received, expected,
        received.source, received.destination, 0, token));
    expected = received;
    expected.responder_session_id[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, received, expected,
        received.source, received.destination, 0, token));
    expected = received;
    expected.direction = 1;
    BOOST_TEST(!ValidateOnce(key, received, expected,
        received.source, received.destination, 0, token));
    expected = received;
    expected.destination.port++;
    BOOST_TEST(!ValidateOnce(key, received, expected,
        received.source, received.destination, 0, token));
}

BOOST_AUTO_TEST_CASE(rejects_old_epoch_after_restart_and_wrong_offer) {
    const auto key = Bytes<32>(9);
    const auto received = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, received, token));
    auto current = received;
    current.connection_epoch[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, received, current,
        received.source, received.destination, 0, token));
    current = received;
    current.offer_id[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, received, current,
        received.source, received.destination, 0, token));
}

BOOST_AUTO_TEST_CASE(rejects_spoofed_observed_endpoints) {
    const auto key = Bytes<32>(9);
    const auto binding = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, binding, token));
    auto spoofed = binding.source;
    spoofed.port++;
    BOOST_TEST(!ValidateOnce(key, binding, binding,
        spoofed, binding.destination, 0, token));
    spoofed = binding.destination;
    spoofed.address[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, binding, binding,
        binding.source, spoofed, 0, token));
}

BOOST_AUTO_TEST_CASE(rejects_tampered_token) {
    const auto key = Bytes<32>(9);
    const auto binding = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, binding, token));
    token[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, binding, binding,
        binding.source, binding.destination, 0, token));
}

BOOST_AUTO_TEST_CASE(control_hmac_covers_every_dynamic_control_field) {
    const auto key = Bytes<32>(9);
    const auto original = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, original, token));

    auto changed = original;
    changed.message_type = P2PControlType::ProbeAck;
    BOOST_TEST(!ValidateOnce(key, changed, changed, changed.source, changed.destination, 0, token));
    changed = original;
    changed.offer_hash[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, changed, changed, changed.source, changed.destination, 0, token));
    changed = original;
    std::swap(changed.sender_role, changed.receiver_role);
    changed.direction = changed.sender_role;
    BOOST_TEST(!ValidateOnce(key, changed, changed, changed.source, changed.destination, 0, token));
    changed = original;
    changed.sequence++;
    changed.nonce = BuildP2PV1Nonce(Bytes<8>(200), changed.sequence);
    BOOST_TEST(!ValidateOnce(key, changed, changed, changed.source, changed.destination, 0, token));
    changed = original;
    changed.nonce[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, changed, changed, changed.source, changed.destination, 0, token));
}

BOOST_AUTO_TEST_CASE(control_hmac_uses_the_exact_protocol_transcript) {
    const auto key = Bytes<32>(9);
    const auto original = Binding();
    auto same_transcript = original;
    same_transcript.offer_id[0] ^= 1;
    same_transcript.initiator_session_id[0] ^= 1;
    same_transcript.responder_session_id[0] ^= 1;
    same_transcript.initiator_peer_id[0] ^= 1;
    same_transcript.responder_peer_id[0] ^= 1;

    P2POfferToken original_token{};
    P2POfferToken same_transcript_token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, original, original_token));
    BOOST_REQUIRE(CreateP2POfferToken(key, same_transcript, same_transcript_token));
    BOOST_TEST(original_token == same_transcript_token);
}

BOOST_AUTO_TEST_CASE(validates_nonce_and_hmac_before_consuming_replay_window) {
    const auto key = Bytes<32>(9);
    const auto binding = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, binding, token));
    P2PReplayWindow replay;
    auto tampered = token;
    tampered[0] ^= 1;
    BOOST_TEST(!ValidateP2POfferToken(key, binding, binding,
        binding.source, binding.destination, 0, tampered, Bytes<8>(200), replay));
    BOOST_TEST(ValidateP2POfferToken(key, binding, binding,
        binding.source, binding.destination, 0, token, Bytes<8>(200), replay));
    BOOST_TEST(!ValidateP2POfferToken(key, binding, binding,
        binding.source, binding.destination, 0, token, Bytes<8>(200), replay));

    P2PReplayWindow nonce_replay;
    BOOST_TEST(!ValidateP2POfferToken(key, binding, binding,
        binding.source, binding.destination, 0, token, Bytes<8>(201), nonce_replay));
    BOOST_TEST(ValidateP2POfferToken(key, binding, binding,
        binding.source, binding.destination, 0, token, Bytes<8>(200), nonce_replay));
}

BOOST_AUTO_TEST_CASE(stale_authenticated_sequence_is_rejected_by_validator) {
    const auto key = Bytes<32>(9);
    auto newest = Binding();
    newest.sequence = 2000;
    newest.nonce = BuildP2PV1Nonce(Bytes<8>(200), newest.sequence);
    P2POfferToken newest_token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, newest, newest_token));

    P2PReplayWindow replay;
    BOOST_REQUIRE(ValidateP2POfferToken(key, newest, newest,
        newest.source, newest.destination, 0, newest_token, Bytes<8>(200), replay));

    auto stale = newest;
    stale.sequence = newest.sequence - REPLAY_WINDOW_SIZE;
    stale.nonce = BuildP2PV1Nonce(Bytes<8>(200), stale.sequence);
    P2POfferToken stale_token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, stale, stale_token));
    BOOST_TEST(!ValidateP2POfferToken(key, stale, stale,
        stale.source, stale.destination, 0, stale_token, Bytes<8>(200), replay));
}

BOOST_AUTO_TEST_CASE(only_a_validated_probe_ack_can_enter_direct) {
    const auto key = Bytes<32>(9);
    const auto probe = Binding();
    const auto ack = ProbeAckBinding(probe);
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, ack, token));

    P2PReplayWindow replay;
    auto proof = AuthenticateP2PProbeAck(key, ack, probe,
        ack.source, ack.destination, 0, token, Bytes<8>(210), replay);
    BOOST_REQUIRE(proof.has_value());

    P2PControlStateMachine machine;
    BOOST_REQUIRE(machine.MarkEligible());
    BOOST_REQUIRE(machine.AcceptOffer());
    BOOST_REQUIRE(machine.AcceptProbeAck(std::move(*proof)));
    BOOST_TEST(static_cast<int>(machine.State()) == static_cast<int>(P2PState::Direct));
    BOOST_TEST(std::string(machine.EffectivePath()) == "direct");
}

BOOST_AUTO_TEST_CASE(validated_probe_ack_proof_is_consumed_once) {
    const auto key = Bytes<32>(9);
    const auto probe = Binding();
    const auto ack = ProbeAckBinding(probe);
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, ack, token));
    P2PReplayWindow replay;
    auto proof = AuthenticateP2PProbeAck(key, ack, probe,
        ack.source, ack.destination, 0, token, Bytes<8>(210), replay);
    BOOST_REQUIRE(proof.has_value());

    P2PControlStateMachine first;
    BOOST_REQUIRE(first.MarkEligible());
    BOOST_REQUIRE(first.AcceptOffer());
    BOOST_REQUIRE(first.AcceptProbeAck(std::move(*proof)));

    P2PControlStateMachine second;
    BOOST_REQUIRE(second.MarkEligible());
    BOOST_REQUIRE(second.AcceptOffer());
    BOOST_TEST(!second.AcceptProbeAck(std::move(*proof)));
    BOOST_TEST(static_cast<int>(second.State()) == static_cast<int>(P2PState::Probing));
}

BOOST_AUTO_TEST_CASE(out_of_order_state_does_not_consume_probe_ack_proof) {
    const auto key = Bytes<32>(9);
    const auto probe = Binding();
    const auto ack = ProbeAckBinding(probe);
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, ack, token));
    P2PReplayWindow replay;
    auto proof = AuthenticateP2PProbeAck(key, ack, probe,
        ack.source, ack.destination, 0, token, Bytes<8>(210), replay);
    BOOST_REQUIRE(proof.has_value());

    P2PControlStateMachine machine;
    BOOST_TEST(!machine.AcceptProbeAck(std::move(*proof)));
    BOOST_REQUIRE(machine.MarkEligible());
    BOOST_REQUIRE(machine.AcceptOffer());
    BOOST_TEST(machine.AcceptProbeAck(std::move(*proof)));
}

BOOST_AUTO_TEST_CASE(probe_ack_is_bound_to_probe_transcript_and_single_use_sequence) {
    const auto key = Bytes<32>(9);
    const auto probe = Binding();
    const auto ack = ProbeAckBinding(probe);

    P2PReplayWindow replay;
    auto wrong_transcript = ack;
    wrong_transcript.probe_transcript_hash[0] ^= 1;
    P2POfferToken wrong_token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, wrong_transcript, wrong_token));
    BOOST_TEST(!AuthenticateP2PProbeAck(key, wrong_transcript, probe,
        ack.source, ack.destination, 0, wrong_token, Bytes<8>(210), replay).has_value());

    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, ack, token));
    BOOST_REQUIRE(AuthenticateP2PProbeAck(key, ack, probe,
        ack.source, ack.destination, 0, token, Bytes<8>(210), replay).has_value());
    BOOST_TEST(!AuthenticateP2PProbeAck(key, ack, probe,
        ack.source, ack.destination, 0, token, Bytes<8>(210), replay).has_value());
}

BOOST_AUTO_TEST_CASE(probe_ack_rejects_an_unrelated_outstanding_probe) {
    const auto key = Bytes<32>(9);
    const auto probe = Binding();
    const auto ack = ProbeAckBinding(probe);
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, ack, token));

    auto unrelated = probe;
    unrelated.sequence++;
    unrelated.nonce = BuildP2PV1Nonce(Bytes<8>(200), unrelated.sequence);
    P2PReplayWindow replay;
    BOOST_TEST(!AuthenticateP2PProbeAck(key, ack, unrelated,
        ack.source, ack.destination, 0, token, Bytes<8>(210), replay).has_value());
}

BOOST_AUTO_TEST_CASE(a_probe_never_produces_a_probe_ack_proof) {
    const auto key = Bytes<32>(9);
    const auto probe = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, probe, token));
    P2PReplayWindow replay;
    BOOST_TEST(!AuthenticateP2PProbeAck(key, probe, probe,
        probe.source, probe.destination, 0, token, Bytes<8>(200), replay).has_value());
}

BOOST_AUTO_TEST_CASE(non_ack_control_rejects_probe_transcript_hash) {
    const auto key = Bytes<32>(9);
    auto probe = Binding();
    probe.probe_transcript_hash = Bytes<32>(220);
    P2POfferToken token{};
    BOOST_TEST(!CreateP2POfferToken(key, probe, token));
}

BOOST_AUTO_TEST_CASE(direct_socket_and_suspect_migration_failures_fall_back) {
    const auto key = Bytes<32>(9);
    const auto probe = Binding();
    const auto ack = ProbeAckBinding(probe);
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, ack, token));

    P2PReplayWindow socket_replay;
    auto socket_proof = AuthenticateP2PProbeAck(key, ack, probe,
        ack.source, ack.destination, 0, token, Bytes<8>(210), socket_replay);
    BOOST_REQUIRE(socket_proof.has_value());
    P2PControlStateMachine socket_machine;
    BOOST_REQUIRE(socket_machine.MarkEligible());
    BOOST_REQUIRE(socket_machine.AcceptOffer());
    BOOST_REQUIRE(socket_machine.AcceptProbeAck(std::move(*socket_proof)));
    BOOST_REQUIRE(socket_machine.BeginFallback(P2PFallbackReason::SocketError));
    BOOST_TEST(std::string(socket_machine.EffectivePath()) == "relay");

    P2PReplayWindow migration_replay;
    auto migration_proof = AuthenticateP2PProbeAck(key, ack, probe,
        ack.source, ack.destination, 0, token, Bytes<8>(210), migration_replay);
    BOOST_REQUIRE(migration_proof.has_value());
    P2PControlStateMachine migration_machine;
    BOOST_REQUIRE(migration_machine.MarkEligible());
    BOOST_REQUIRE(migration_machine.AcceptOffer());
    BOOST_REQUIRE(migration_machine.AcceptProbeAck(std::move(*migration_proof)));
    BOOST_REQUIRE(migration_machine.MarkSuspect());
    BOOST_REQUIRE(migration_machine.BeginFallback(P2PFallbackReason::MigrationFailure));
    BOOST_TEST(std::string(migration_machine.EffectivePath()) == "relay");
}

BOOST_AUTO_TEST_CASE(direct_activation_requires_proof_and_ready_data_channel) {
    const auto key = Bytes<32>(9);
    const auto probe = Binding();
    const auto ack = ProbeAckBinding(probe);
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, ack, token));
    P2PReplayWindow replay;
    auto proof = AuthenticateP2PProbeAck(key, ack, probe,
        ack.source, ack.destination, 0, token, Bytes<8>(210), replay);
    BOOST_REQUIRE(proof.has_value());

    P2PDirectActivationCoordinator coordinator;
    BOOST_REQUIRE(coordinator.Begin(7));
    BOOST_TEST(static_cast<int>(coordinator.State()) ==
        static_cast<int>(P2PState::Probing));
    BOOST_REQUIRE(coordinator.StageAuthenticatedAck(std::move(*proof), 7));
    BOOST_TEST(coordinator.HasPendingAck());
    BOOST_TEST(!coordinator.Activate(false, 7));
    BOOST_TEST(!coordinator.Activate(true, 6));
    BOOST_TEST(std::string(coordinator.EffectivePath()) == "relay");
    BOOST_REQUIRE(coordinator.Activate(true, 7));
    BOOST_TEST(static_cast<int>(coordinator.State()) ==
        static_cast<int>(P2PState::Direct));
    BOOST_TEST(std::string(coordinator.EffectivePath()) == "direct");
}

BOOST_AUTO_TEST_CASE(fallback_and_generation_reset_discard_pending_proof) {
    const auto key = Bytes<32>(9);
    const auto probe = Binding();
    const auto ack = ProbeAckBinding(probe);
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, ack, token));
    P2PReplayWindow replay;
    auto proof = AuthenticateP2PProbeAck(key, ack, probe,
        ack.source, ack.destination, 0, token, Bytes<8>(210), replay);
    BOOST_REQUIRE(proof.has_value());

    P2PDirectActivationCoordinator coordinator;
    BOOST_REQUIRE(coordinator.Begin(7));
    BOOST_REQUIRE(coordinator.StageAuthenticatedAck(std::move(*proof), 7));
    BOOST_REQUIRE(coordinator.Fallback(
        P2PFallbackReason::SocketError, true, 7));
    BOOST_TEST(!coordinator.HasPendingAck());
    BOOST_TEST(std::string(coordinator.EffectivePath()) == "relay");
    BOOST_TEST(!coordinator.Activate(true, 7));
    BOOST_REQUIRE(coordinator.Reset(8));
    BOOST_TEST(!coordinator.Begin(7));
}

BOOST_AUTO_TEST_CASE(suspect_recovery_requires_authenticated_ack) {
    const auto key = Bytes<32>(9);
    const auto probe = Binding();
    const auto ack = ProbeAckBinding(probe);
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, ack, token));
    P2PReplayWindow replay;
    auto activate_proof = AuthenticateP2PProbeAck(key, ack, probe,
        ack.source, ack.destination, 0, token, Bytes<8>(210), replay);
    BOOST_REQUIRE(activate_proof.has_value());

    P2PDirectActivationCoordinator coordinator;
    BOOST_REQUIRE(coordinator.Begin(7));
    BOOST_REQUIRE(coordinator.StageAuthenticatedAck(
        std::move(*activate_proof), 7));
    BOOST_REQUIRE(coordinator.Activate(true, 7));
    BOOST_REQUIRE(coordinator.MarkSuspect(7));
    BOOST_TEST(static_cast<int>(coordinator.State()) ==
        static_cast<int>(P2PState::Suspect));
    BOOST_TEST(std::string(coordinator.EffectivePath()) == "relay");
    BOOST_TEST(!coordinator.MarkSuspect(6));
    BOOST_TEST(!coordinator.AcceptRecoveryAck(
        detail::P2PAuthenticatedProbeAckFactory::Create(), 6));
    BOOST_REQUIRE(coordinator.AcceptRecoveryAck(
        detail::P2PAuthenticatedProbeAckFactory::Create(), 7));
    BOOST_TEST(static_cast<int>(coordinator.State()) ==
        static_cast<int>(P2PState::Direct));
    BOOST_TEST(std::string(coordinator.EffectivePath()) == "direct");
}
