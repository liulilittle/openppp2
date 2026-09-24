#include <ppp/p2p/P2PControlDatagram.h>

#include <utility>

namespace ppp::p2p {

namespace {

bool SerializeControl(
    const P2PControlPacket& packet,
    std::vector<std::uint8_t>& output) noexcept {
    std::vector<std::uint8_t> datagram;
    if (!SerializeP2PControlPacket(packet, datagram)) return false;
    output.swap(datagram);
    return true;
}

} // namespace

bool CreateAuthenticatedProbeDatagram(
    P2PClientOfferSession& session,
    const P2PCandidateEndpoint& source,
    const P2PCandidateEndpoint& destination,
    std::uint64_t now_ms,
    std::uint64_t generation,
    std::vector<std::uint8_t>& output) noexcept {
    P2PControlPacket probe;
    return session.CreateAuthenticatedProbe(
            source, destination, now_ms, generation, probe) &&
        SerializeControl(probe, output);
}

bool CreateAuthenticatedMigrateChallengeDatagram(
    P2PClientOfferSession& session,
    const P2PCandidateEndpoint& source,
    const P2PCandidateEndpoint& destination,
    std::uint64_t now_ms,
    std::uint64_t generation,
    std::vector<std::uint8_t>& output) noexcept {
    P2PControlPacket challenge;
    return session.CreateAuthenticatedMigrateChallenge(
            source, destination, now_ms, generation, challenge) &&
        SerializeControl(challenge, output);
}

bool HandleAuthenticatedControlDatagram(
    P2PClientOfferSession& session,
    const std::vector<std::uint8_t>& datagram,
    const P2PCandidateEndpoint& observed_source,
    const P2PCandidateEndpoint& observed_destination,
    std::uint64_t now_ms,
    std::uint64_t generation,
    P2PControlDatagramResult& output) noexcept {
    P2PControlPacket packet;
    if (!ParseP2PControlPacket(datagram, packet)) {
        return false;
    }

    P2PControlDatagramResult result;
    if (packet.type == P2PControlType::Probe) {
        P2PControlPacket ack;
        if (!session.CreateAuthenticatedProbeAck(
                packet, observed_source, observed_destination,
                now_ms, generation, ack) ||
            !SerializeControl(ack, result.reply)) {
            return false;
        }
        result.action = P2PControlDatagramAction::Reply;
    }
    else if (packet.type == P2PControlType::ProbeAck) {
        auto proof = session.AuthenticateProbeAck(
            packet, observed_source, observed_destination,
            now_ms, generation);
        if (!proof) return false;
        result.action = P2PControlDatagramAction::AuthenticatedAck;
        result.authenticated_ack.emplace(std::move(*proof));
    }
    else if (packet.type == P2PControlType::MigrateChallenge) {
        P2PControlPacket ack;
        if (!session.CreateAuthenticatedMigrateAck(
                packet, observed_source, observed_destination,
                now_ms, generation, ack) ||
            !SerializeControl(ack, result.reply)) {
            return false;
        }
        result.action = P2PControlDatagramAction::Reply;
    }
    else if (packet.type == P2PControlType::MigrateAck) {
        auto proof = session.AuthenticateMigrateAck(
            packet, observed_source, observed_destination,
            now_ms, generation);
        if (!proof) return false;
        result.action = P2PControlDatagramAction::AuthenticatedMigrateAck;
        result.authenticated_ack.emplace(std::move(*proof));
    }
    else {
        return false;
    }

    output = std::move(result);
    return true;
}

}
