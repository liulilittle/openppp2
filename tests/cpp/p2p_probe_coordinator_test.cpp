#define BOOST_TEST_MODULE p2p_probe_coordinator_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PProbeCoordinator.h>

#include <limits>

using namespace ppp::p2p;

namespace {

P2PCandidateEndpoint Candidate(std::uint8_t host, std::uint16_t port = 4000) {
    P2PCandidateEndpoint endpoint;
    endpoint.address_family = 4;
    endpoint.address[10] = endpoint.address[11] = 0xff;
    endpoint.address[12] = 192;
    endpoint.address[14] = 2;
    endpoint.address[15] = host;
    endpoint.port = port;
    return endpoint;
}

P2PCandidateEndpoint Candidate6(std::uint8_t host, std::uint16_t port = 4000) {
    P2PCandidateEndpoint endpoint;
    endpoint.address_family = 6;
    endpoint.address[0] = 0x20;
    endpoint.address[1] = 0x01;
    endpoint.address[15] = host;
    endpoint.port = port;
    return endpoint;
}

const std::vector<P2PCandidateEndpoint> Local{Candidate(1), Candidate(2)};
const std::vector<P2PCandidateEndpoint> Peer{Candidate(3), Candidate(4)};

}

BOOST_AUTO_TEST_CASE(controlling_probes_four_pairs_in_two_bounded_rounds) {
    P2PProbeCoordinator coordinator;
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlling, Local, Peer, 1000, 7));
    auto first = coordinator.Poll(1000, 7);
    BOOST_REQUIRE_EQUAL(first.size, 4u);
    for (std::size_t index = 0; index < first.size; ++index) {
        BOOST_TEST(first.tasks[index].pair_index == index);
        BOOST_TEST(first.tasks[index].round == 1u);
        BOOST_CHECK(first.tasks[index].pair.local == Local[index / 2]);
        BOOST_CHECK(first.tasks[index].pair.peer == Peer[index % 2]);
    }
    BOOST_TEST(coordinator.Poll(1000, 7).size == 0u);
    BOOST_TEST(coordinator.Poll(2999, 7).size == 0u);
    const auto second = coordinator.Poll(3000, 7);
    BOOST_REQUIRE_EQUAL(second.size, 4u);
    for (const auto& task : second.tasks) BOOST_TEST(task.round == 2u);
    BOOST_TEST(coordinator.Poll(4999, 7).size == 0u);
    BOOST_TEST(coordinator.Poll(5000, 7).size == 0u);
    BOOST_TEST(coordinator.Snapshot().timed_out);
    BOOST_TEST(!coordinator.Snapshot().active);
}

BOOST_AUTO_TEST_CASE(priority_controls_candidate_family_order) {
    const std::vector<P2PCandidateEndpoint> locals{Candidate(1), Candidate6(1)};
    const std::vector<P2PCandidateEndpoint> peers{Candidate(2), Candidate6(2)};
    P2PProbeCoordinator coordinator;

    coordinator.SetPriority(P2PPeerPriority::IPv4First);
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlling, locals, peers, 1000, 7));
    auto batch = coordinator.Poll(1000, 7);
    BOOST_REQUIRE_EQUAL(batch.size, 2u);
    BOOST_TEST(batch.tasks[0].pair.local.address_family == 4);
    BOOST_TEST(batch.tasks[1].pair.local.address_family == 6);

    coordinator.SetPriority(P2PPeerPriority::IPv6First);
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlling, locals, peers, 2000, 8));
    batch = coordinator.Poll(2000, 8);
    BOOST_REQUIRE_EQUAL(batch.size, 2u);
    BOOST_TEST(batch.tasks[0].pair.local.address_family == 6);
    BOOST_TEST(batch.tasks[1].pair.local.address_family == 4);
}

BOOST_AUTO_TEST_CASE(relay_first_suppresses_direct_probe_batches) {
    P2PProbeCoordinator coordinator;
    coordinator.SetPriority(P2PPeerPriority::RelayFirst);
    BOOST_TEST(!coordinator.Begin(P2PProbeRole::Controlling, Local, Peer, 1000, 7));
    BOOST_TEST(static_cast<int>(coordinator.Priority()) ==
        static_cast<int>(P2PPeerPriority::RelayFirst));
    BOOST_TEST(coordinator.Poll(1000, 7).size == 0u);
    BOOST_TEST(coordinator.Snapshot().pair_count == 0u);

    coordinator.SetPriority(P2PPeerPriority::IPv4First);
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlling, Local, Peer, 2000, 8));
    BOOST_TEST(coordinator.Poll(2000, 8).size == 4u);
}

BOOST_AUTO_TEST_CASE(validated_ack_stops_all_other_pairs_and_rejects_late_acks) {
    P2PProbeCoordinator coordinator;
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlling, Local, Peer, 1000, 7));
    BOOST_TEST(!coordinator.OnAuthenticatedAck(2, 1001, 7)); // Nothing sent yet.
    BOOST_TEST(coordinator.Poll(1001, 7).size == 4u);
    BOOST_TEST(!coordinator.OnAuthenticatedAck(4, 1001, 7));
    BOOST_TEST(!coordinator.OnAuthenticatedAck(2, 1001, 6));
    BOOST_REQUIRE(coordinator.OnAuthenticatedAck(2, 1001, 7));
    BOOST_REQUIRE(coordinator.Snapshot().acknowledged_pair.has_value());
    BOOST_TEST(*coordinator.Snapshot().acknowledged_pair == 2u);
    BOOST_TEST(coordinator.Poll(3000, 7).size == 0u);
    BOOST_TEST(!coordinator.OnAuthenticatedAck(1, 3000, 7));
    BOOST_TEST(!coordinator.Snapshot().timed_out);
}

BOOST_AUTO_TEST_CASE(controlled_primes_all_pairs_then_preserves_budget_for_nomination) {
    P2PProbeCoordinator coordinator;
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlled, Local, Peer, 1000, 7));
    BOOST_TEST(coordinator.Poll(1000, 7).size == 4u);
    BOOST_TEST(coordinator.OnAuthenticatedAck(0, 1001, 7));
    BOOST_TEST(coordinator.Snapshot().active);
    BOOST_TEST(!coordinator.Snapshot().acknowledged_pair.has_value());
    const P2PProbeCandidatePair chosen{Local[1], Peer[1]};
    BOOST_REQUIRE(coordinator.NominateResponderPair(chosen, 1500, 7));
    BOOST_TEST(coordinator.Snapshot().deadline_ms == 5000u);
    BOOST_TEST(coordinator.Poll(1500, 7).size == 0u);
    BOOST_TEST(!coordinator.OnAuthenticatedAck(0, 1501, 7));
    BOOST_TEST(!coordinator.NominateResponderPair({Local[0], Peer[0]}, 1501, 7));
    BOOST_REQUIRE(coordinator.NominateResponderPair(chosen, 2500, 7));
    BOOST_TEST(coordinator.Snapshot().deadline_ms == 5000u);
    BOOST_TEST(coordinator.Poll(2999, 7).size == 0u);
    auto second = coordinator.Poll(3000, 7);
    BOOST_REQUIRE_EQUAL(second.size, 1u);
    BOOST_CHECK(second.tasks[0].pair == chosen);
    BOOST_TEST(second.tasks[0].round == 2u);
    BOOST_TEST(coordinator.OnAuthenticatedAck(3, 3001, 7));
}

BOOST_AUTO_TEST_CASE(cached_ack_can_complete_late_nomination_without_new_probes) {
    P2PProbeCoordinator coordinator;
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlled, Local, Peer, 1000, 7));
    BOOST_TEST(coordinator.Poll(1000, 7).size == 4u);
    BOOST_REQUIRE(coordinator.OnAuthenticatedAck(0, 1001, 7));
    BOOST_TEST(coordinator.Poll(5000, 7).size == 0u);
    BOOST_TEST(coordinator.Snapshot().timed_out);
    BOOST_TEST(!coordinator.NominateResponderPair({Local[1], Peer[1]}, 10000, 7));
    BOOST_REQUIRE(coordinator.NominateResponderPair({Local[0], Peer[0]}, 10000, 7));
    BOOST_TEST(coordinator.Snapshot().deadline_ms == 5000u);
    BOOST_TEST(coordinator.Poll(10000, 7).size == 0u);
    BOOST_TEST(!coordinator.Snapshot().timed_out);
    BOOST_REQUIRE(coordinator.Snapshot().acknowledged_pair.has_value());
    BOOST_TEST(*coordinator.Snapshot().acknowledged_pair == 0u);
    BOOST_TEST(!coordinator.NominateResponderPair({Local[0], Peer[0]}, 11000, 7));
}

BOOST_AUTO_TEST_CASE(controlled_without_nomination_times_out_at_setup_boundary) {
    P2PProbeCoordinator coordinator;
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlled, Local, Peer, 1000, 7));
    BOOST_TEST(coordinator.Poll(1000, 7).size == 4u);
    BOOST_TEST(coordinator.Poll(4999, 7).size == 4u);
    BOOST_TEST(coordinator.Snapshot().active);
    BOOST_TEST(coordinator.Poll(5000, 7).size == 0u);
    BOOST_TEST(coordinator.Snapshot().timed_out);
}

BOOST_AUTO_TEST_CASE(stale_generation_poll_ack_and_cancel_cannot_touch_new_attempt) {
    P2PProbeCoordinator coordinator;
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlling, Local, Peer, 1000, 7));
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlling, Local, Peer, 2000, 8));
    BOOST_TEST(coordinator.Poll(2000, 7).size == 0u);
    BOOST_TEST(!coordinator.Cancel(7));
    BOOST_TEST(!coordinator.OnAuthenticatedAck(0, 2000, 7));
    BOOST_TEST(coordinator.Snapshot().active);
    BOOST_TEST(coordinator.Poll(2000, 8).size == 4u);
    BOOST_TEST(coordinator.Cancel(8));
    BOOST_TEST(coordinator.Cancel(8));
    BOOST_TEST(coordinator.Poll(2000, 8).size == 0u);
    BOOST_TEST(coordinator.Snapshot().pair_count == 0u);
}

BOOST_AUTO_TEST_CASE(candidate_duplicates_and_large_inputs_never_raise_pair_cap) {
    P2PProbeCoordinator coordinator;
    std::vector<P2PCandidateEndpoint> locals{Local[0], Local[0], Local[1], Candidate(5)};
    std::vector<P2PCandidateEndpoint> peers{Peer[0], Peer[0], Peer[1], Candidate(6)};
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlling, locals, peers, 1000, 7));
    const auto batch = coordinator.Poll(1000, 7);
    BOOST_REQUIRE_EQUAL(batch.size, P2PProbeCoordinator::MaxPairs);
    for (std::size_t left = 0; left < batch.size; ++left) {
        for (std::size_t right = left + 1; right < batch.size; ++right) {
            BOOST_CHECK(!(batch.tasks[left].pair == batch.tasks[right].pair));
        }
    }
    BOOST_TEST(!coordinator.Pair(4).has_value());
}

BOOST_AUTO_TEST_CASE(delayed_poll_skips_missed_round_instead_of_bursting_both) {
    P2PProbeCoordinator coordinator;
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlling, Local, Peer, 1000, 7));
    const auto batch = coordinator.Poll(3000, 7);
    BOOST_REQUIRE_EQUAL(batch.size, 4u);
    for (const auto& task : batch.tasks) BOOST_TEST(task.round == 2u);
    BOOST_TEST(coordinator.Poll(3000, 7).size == 0u);
}

BOOST_AUTO_TEST_CASE(malformed_or_incompatible_candidates_fail_atomically) {
    P2PProbeCoordinator coordinator;
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlling, Local, Peer, 1000, 7));
    auto invalid = Local;
    invalid[0].port = 0;
    BOOST_TEST(!coordinator.Begin(P2PProbeRole::Controlling, invalid, Peer, 2000, 8));
    BOOST_TEST(!coordinator.Begin(P2PProbeRole::Controlling, {}, Peer, 2000, 8));
    P2PCandidateEndpoint ipv6;
    ipv6.address_family = 6;
    ipv6.address[0] = 0x20;
    ipv6.address[1] = 1;
    ipv6.port = 4000;
    BOOST_TEST(!coordinator.Begin(P2PProbeRole::Controlling, {ipv6}, Peer, 2000, 8));
    BOOST_TEST(coordinator.Snapshot().generation == 7u);
    BOOST_TEST(coordinator.Poll(1000, 7).size == 4u);
}

BOOST_AUTO_TEST_CASE(deadline_overflow_and_backward_ticks_fail_closed) {
    P2PProbeCoordinator coordinator;
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    BOOST_TEST(!coordinator.Begin(P2PProbeRole::Controlling,
        Local, Peer, maximum - 1, 7));
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlled,
        Local, Peer, maximum - 10000, 7));
    BOOST_TEST(coordinator.Poll(maximum - 10001, 7).size == 0u);
    BOOST_TEST(coordinator.Poll(maximum - 10000, 7).size == 4u);
    BOOST_REQUIRE(coordinator.OnAuthenticatedAck(0, maximum - 9999, 7));
    BOOST_REQUIRE(coordinator.NominateResponderPair(
        {Local[0], Peer[0]}, maximum - 1000, 7));
    BOOST_TEST(coordinator.Snapshot().deadline_ms == maximum - 6000);
    BOOST_TEST(coordinator.Poll(maximum, 7).size == 0u);
    BOOST_TEST(!coordinator.Snapshot().timed_out);
}

BOOST_AUTO_TEST_CASE(nomination_never_restarts_two_used_rounds_or_cancelled_priming) {
    P2PProbeCoordinator coordinator;
    BOOST_REQUIRE(coordinator.Begin(P2PProbeRole::Controlled, Local, Peer, 1000, 7));
    BOOST_TEST(coordinator.Poll(1000, 7).size == 4u);
    BOOST_TEST(coordinator.Poll(3000, 7).size == 4u);
    BOOST_REQUIRE(coordinator.NominateResponderPair({Local[1], Peer[1]}, 3999, 7));
    BOOST_TEST(coordinator.Poll(3999, 7).size == 0u);
    BOOST_TEST(coordinator.Poll(5000, 7).size == 0u);
    BOOST_TEST(coordinator.Snapshot().timed_out);
    BOOST_TEST(!coordinator.OnAuthenticatedAck(3, 5001, 7));
    BOOST_TEST(coordinator.Cancel(7));
    BOOST_TEST(!coordinator.NominateResponderPair({Local[1], Peer[1]}, 5001, 7));
}
