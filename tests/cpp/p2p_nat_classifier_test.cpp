#define BOOST_TEST_MODULE p2p_nat_classifier_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PNatClassifier.h>

using namespace ppp::p2p;

namespace {

boost::asio::ip::udp::endpoint Endpoint(const char* address, uint16_t port) {
    return {boost::asio::ip::make_address(address), port};
}

void ObserveSymmetricNat(P2PNatClassifier& classifier, uint32_t peer,
                         const char* source_address, uint16_t source_port,
                         uint64_t now_ms) {
    classifier.Observe(peer, Endpoint(source_address, source_port),
        Endpoint("198.51.100.1", 5000), now_ms);
    classifier.Observe(peer, Endpoint(source_address, source_port + 1),
        Endpoint("198.51.100.2", 5000), now_ms + 1);
}

} // namespace

BOOST_AUTO_TEST_CASE(symmetric_peers_are_not_offered_hole_punching) {
    P2PNatClassifier classifier;
    ObserveSymmetricNat(classifier, 1, "203.0.113.1", 4000, 1000);
    ObserveSymmetricNat(classifier, 2, "203.0.113.2", 6000, 1000);

    const auto first = classifier.Classify(1, 1002);
    const auto second = classifier.Classify(2, 1002);
    BOOST_REQUIRE(static_cast<int>(first.type) ==
        static_cast<int>(P2PNatType::Symmetric));
    BOOST_REQUIRE(static_cast<int>(second.type) ==
        static_cast<int>(P2PNatType::Symmetric));
    BOOST_TEST(!P2PNatClassifier::ShouldAttemptPunch(first, second));
}

BOOST_AUTO_TEST_CASE(udp_blocked_on_either_side_disables_hole_punching) {
    P2PNatClassification blocked;
    blocked.type = P2PNatType::UdpBlocked;
    blocked.confidence = 1;
    blocked.stale = false;

    P2PNatClassification unknown;
    BOOST_TEST(!P2PNatClassifier::ShouldAttemptPunch(blocked, unknown));
    BOOST_TEST(!P2PNatClassifier::ShouldAttemptPunch(unknown, blocked));
}

BOOST_AUTO_TEST_CASE(unknown_nat_remains_eligible_for_bounded_probing) {
    P2PNatClassification unknown;
    BOOST_TEST(P2PNatClassifier::ShouldAttemptPunch(unknown, unknown));
}

BOOST_AUTO_TEST_CASE(single_udp_destination_is_insufficient_to_classify_nat) {
    P2PNatClassifier classifier;
    classifier.Observe(1, Endpoint("203.0.113.1", 4000),
        Endpoint("198.51.100.1", 5000), 1000);

    const auto classification = classifier.Classify(1, 1001);
    BOOST_TEST(static_cast<int>(classification.type) ==
        static_cast<int>(P2PNatType::Unknown));
    BOOST_TEST(classification.confidence == 1);
    BOOST_TEST(!classification.stale);
}

BOOST_AUTO_TEST_CASE(stable_mapping_across_two_udp_destinations_is_full_cone) {
    P2PNatClassifier classifier;
    classifier.Observe(1, Endpoint("203.0.113.1", 4000),
        Endpoint("198.51.100.1", 5000), 1000);
    classifier.Observe(1, Endpoint("203.0.113.1", 4000),
        Endpoint("198.51.100.2", 5000), 1001);

    const auto classification = classifier.Classify(1, 1002);
    BOOST_TEST(static_cast<int>(classification.type) ==
        static_cast<int>(P2PNatType::FullCone));
    BOOST_TEST(classification.confidence == 2);
}
