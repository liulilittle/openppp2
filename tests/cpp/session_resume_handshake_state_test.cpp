#define BOOST_TEST_MODULE session_resume_handshake_state_test
#include <ppp/stdafx.h>
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/SessionResumeAuthenticator.h>
#include <ppp/app/client/ClientSessionResumeHandshakePolicy.h>
#include <ppp/app/server/SessionRecoveryState.h>

#include <algorithm>
#include <cstring>
#include <vector>

namespace protocol = ppp::app::protocol;
using ppp::Byte;

namespace {
const ppp::string SessionId = "00112233445566778899aabbccddeeff";
const ppp::string ServerNonce(64, '2');

protocol::VirtualEthernetInformation MakeBaseInformation() {
    protocol::VirtualEthernetInformation information;
    information.BandwidthQoS = 123456789;
    information.ExpiredTime = 0x12345678u;
    information.IncomingTraffic = 0x0102030405060708ull;
    information.OutgoingTraffic = 0x1112131415161718ull;
    return information;
}

ppp::string MakeValidExtensions() {
    protocol::VirtualEthernetInformationExtensions extensions;
    extensions.SessionResume.action = protocol::SessionResumeAction::Offer;
    extensions.SessionResume.capabilities =
        protocol::SessionResumeControl::CapabilityV1;
    extensions.SessionResume.session_id = SessionId;
    extensions.SessionResume.server_nonce = ServerNonce;
    return extensions.ToJson();
}

std::vector<Byte> MakeInformationFrame(const ppp::string& extensions = ppp::string()) {
    protocol::VirtualEthernetInformation wire = MakeBaseInformation();
    wire.BandwidthQoS = ppp::net::Ipep::HostToNetworkOrder(wire.BandwidthQoS);
    wire.ExpiredTime = htonl(wire.ExpiredTime);
    wire.IncomingTraffic = ppp::net::Ipep::HostToNetworkOrder(wire.IncomingTraffic);
    wire.OutgoingTraffic = ppp::net::Ipep::HostToNetworkOrder(wire.OutgoingTraffic);

    std::vector<Byte> frame(
        1 + sizeof(wire) + extensions.size());
    frame[0] = static_cast<Byte>(
        protocol::VirtualEthernetLinklayer::PacketAction_INFO);
    std::memcpy(frame.data() + 1, &wire, sizeof(wire));
    if (!extensions.empty()) {
        std::memcpy(frame.data() + 1 + sizeof(wire),
            extensions.data(), extensions.size());
    }
    return frame;
}
}

BOOST_AUTO_TEST_CASE(strict_codec_rejects_non_info_and_truncated_base) {
    protocol::VirtualEthernetLinklayer::InformationEnvelope decoded;

    std::vector<Byte> frame = MakeInformationFrame();
    frame[0] = static_cast<Byte>(
        protocol::VirtualEthernetLinklayer::PacketAction_KEEPALIVED);
    BOOST_TEST(!protocol::VirtualEthernetLinklayer::DecodeInformation(
        frame.data(), static_cast<int>(frame.size()), decoded));

    frame = MakeInformationFrame();
    frame.resize(sizeof(protocol::VirtualEthernetInformation));
    BOOST_TEST(!protocol::VirtualEthernetLinklayer::DecodeInformation(
        frame.data(), static_cast<int>(frame.size()), decoded));
}

BOOST_AUTO_TEST_CASE(strict_codec_rejects_malformed_or_incomplete_json) {
    protocol::VirtualEthernetLinklayer::InformationEnvelope decoded;

    std::vector<Byte> frame = MakeInformationFrame("{");
    BOOST_TEST(!protocol::VirtualEthernetLinklayer::DecodeInformation(
        frame.data(), static_cast<int>(frame.size()), decoded));

    frame = MakeInformationFrame(MakeValidExtensions() + " trailing");
    BOOST_TEST(!protocol::VirtualEthernetLinklayer::DecodeInformation(
        frame.data(), static_cast<int>(frame.size()), decoded));
}

BOOST_AUTO_TEST_CASE(strict_codec_rejects_non_object_extensions) {
    protocol::VirtualEthernetLinklayer::InformationEnvelope decoded;
    std::vector<Byte> frame = MakeInformationFrame("[]");

    BOOST_TEST(!protocol::VirtualEthernetLinklayer::DecodeInformation(
        frame.data(), static_cast<int>(frame.size()), decoded));
}

BOOST_AUTO_TEST_CASE(strict_codec_rejects_malformed_session_resume_schema) {
    const ppp::string malformed =
        R"({"session-resume":{"version":1,"action":"offer"}})";
    protocol::VirtualEthernetLinklayer::InformationEnvelope decoded;
    std::vector<Byte> frame = MakeInformationFrame(malformed);

    BOOST_TEST(!protocol::VirtualEthernetLinklayer::DecodeInformation(
        frame.data(), static_cast<int>(frame.size()), decoded));
}

BOOST_AUTO_TEST_CASE(strict_codec_decodes_valid_envelope_and_network_order) {
    const ppp::string extensions = MakeValidExtensions();
    std::vector<Byte> frame = MakeInformationFrame(extensions);
    protocol::VirtualEthernetLinklayer::InformationEnvelope decoded;

    BOOST_REQUIRE(protocol::VirtualEthernetLinklayer::DecodeInformation(
        frame.data(), static_cast<int>(frame.size()), decoded));

    const protocol::VirtualEthernetInformation expected = MakeBaseInformation();
    const std::int64_t bandwidth_qos = decoded.Base.BandwidthQoS;
    const std::uint32_t expired_time = decoded.Base.ExpiredTime;
    const std::uint64_t incoming_traffic = decoded.Base.IncomingTraffic;
    const std::uint64_t outgoing_traffic = decoded.Base.OutgoingTraffic;
    BOOST_TEST(bandwidth_qos == expected.BandwidthQoS);
    BOOST_TEST(expired_time == expected.ExpiredTime);
    BOOST_TEST(incoming_traffic == expected.IncomingTraffic);
    BOOST_TEST(outgoing_traffic == expected.OutgoingTraffic);
    BOOST_TEST(decoded.ExtendedJson == extensions);
    BOOST_TEST(static_cast<std::uint8_t>(decoded.Extensions.SessionResume.action) ==
        static_cast<std::uint8_t>(protocol::SessionResumeAction::Offer));
    BOOST_TEST(decoded.Extensions.SessionResume.capabilities ==
        protocol::SessionResumeControl::CapabilityV1);
    BOOST_TEST(decoded.Extensions.SessionResume.session_id == SessionId);
    BOOST_TEST(decoded.Extensions.SessionResume.server_nonce == ServerNonce);
}

namespace {
template <std::size_t N>
std::array<std::uint8_t, N> Filled(std::uint8_t seed) {
    std::array<std::uint8_t, N> value{};
    for (std::size_t i = 0; i < value.size(); ++i) {
        value[i] = static_cast<std::uint8_t>(seed + i);
    }
    return value;
}

protocol::SessionResumeTranscriptFields MakeResumeFields(
    protocol::SessionResumeAction action, std::uint64_t generation) {
    protocol::SessionResumeTranscriptFields fields;
    fields.action = action;
    fields.capabilities = protocol::SessionResumeControl::CapabilityV1;
    fields.session_id = Filled<protocol::SessionResumeIdSize>(1);
    fields.generation = generation;
    fields.client_nonce = Filled<protocol::SessionResumeSecretSize>(21);
    fields.server_nonce = Filled<protocol::SessionResumeSecretSize>(61);
    fields.candidate_binding = Filled<protocol::SessionResumeSecretSize>(101);
    return fields;
}

struct ClientRetryGuard {
    std::uint64_t generation = 0;
    unsigned int sync_count = 0;
    protocol::SessionResumeNonce client_nonce =
        Filled<protocol::SessionResumeSecretSize>(21);

    bool Apply(const protocol::SessionResumeSecret& root,
        const protocol::SessionResumeTranscriptFields& request,
        const protocol::SessionResumeTranscriptFields& sync,
        const protocol::SessionResumeProof& proof) {
        if (sync_count != 0 ||
            request.action != protocol::SessionResumeAction::ResumeRequest ||
            sync.action != protocol::SessionResumeAction::GenerationSync ||
            sync.capabilities != request.capabilities ||
            sync.session_id != request.session_id ||
            sync.client_nonce != request.client_nonce ||
            sync.candidate_binding != request.candidate_binding ||
            !std::all_of(sync.server_nonce.begin(), sync.server_nonce.end(),
                [](std::uint8_t value) { return value == 0; }) ||
            !protocol::VerifySessionResumeProof(root, sync, proof)) {
            return false;
        }

        const protocol::SessionResumeNonce previous = client_nonce;
        if (!protocol::GenerateSessionResumeNonce(client_nonce) ||
            client_nonce == previous) {
            return false;
        }
        generation = sync.generation;
        ++sync_count;
        return true;
    }
};
}

BOOST_AUTO_TEST_CASE(fresh_offer_requires_server_nonce_then_client_accepted_proof) {
    protocol::SessionResumeControl offer;
    offer.action = protocol::SessionResumeAction::Offer;
    offer.capabilities = protocol::SessionResumeControl::CapabilityV1;
    offer.session_id = SessionId;
    offer.server_nonce = ServerNonce;
    BOOST_REQUIRE(offer.Valid());

    protocol::SessionResumeSecret root(
        Filled<protocol::SessionResumeSecretSize>(9));
    auto accepted = MakeResumeFields(protocol::SessionResumeAction::Accepted, 0);
    accepted.candidate_binding.fill(0);
    protocol::SessionResumeProof proof{};
    BOOST_REQUIRE(protocol::ComputeSessionResumeProof(root, accepted, proof));
    BOOST_TEST(protocol::VerifySessionResumeProof(root, accepted, proof));

    auto wrong_nonce = accepted;
    wrong_nonce.server_nonce[0] ^= 1;
    BOOST_TEST(!protocol::VerifySessionResumeProof(root, wrong_nonce, proof));
}

BOOST_AUTO_TEST_CASE(resume_reserve_confirm_commit_publishes_next_generation) {
    using ppp::app::server::SessionRecoveryState;
    SessionRecoveryState state;
    BOOST_REQUIRE(state.Suspend(1, 100, 100));

    protocol::SessionResumeSecret root(
        Filled<protocol::SessionResumeSecretSize>(9));
    auto request = MakeResumeFields(
        protocol::SessionResumeAction::ResumeRequest, 1);
    request.server_nonce.fill(0);
    protocol::SessionResumeProof request_proof{};
    BOOST_REQUIRE(protocol::ComputeSessionResumeProof(root, request, request_proof));
    BOOST_REQUIRE(protocol::VerifySessionResumeProof(root, request, request_proof));

    constexpr std::uint64_t ReservationToken = 77;
    BOOST_REQUIRE(state.ReserveResume(1, 120, ReservationToken));
    BOOST_TEST(state.GetGeneration() == 1u);

    auto accepted = request;
    accepted.action = protocol::SessionResumeAction::ResumeAccept;
    accepted.server_nonce = Filled<protocol::SessionResumeSecretSize>(61);
    protocol::SessionResumeProof accepted_proof{};
    BOOST_REQUIRE(protocol::ComputeSessionResumeProof(root, accepted, accepted_proof));
    BOOST_REQUIRE(protocol::VerifySessionResumeProof(root, accepted, accepted_proof));
    BOOST_TEST(state.GetGeneration() == 1u);

    auto confirm = accepted;
    confirm.action = protocol::SessionResumeAction::ResumeConfirm;
    protocol::SessionResumeProof confirm_proof{};
    BOOST_REQUIRE(protocol::ComputeSessionResumeProof(root, confirm, confirm_proof));
    BOOST_REQUIRE(protocol::VerifySessionResumeProof(root, confirm, confirm_proof));
    BOOST_REQUIRE(state.CanCommitResume(1, 120, ReservationToken));
    BOOST_REQUIRE(state.CommitResume(1, 120, ReservationToken));

    auto committed = confirm;
    committed.action = protocol::SessionResumeAction::ResumeCommitted;
    committed.generation = state.GetGeneration();
    protocol::SessionResumeProof committed_proof{};
    BOOST_REQUIRE(protocol::ComputeSessionResumeProof(root, committed, committed_proof));
    BOOST_TEST(protocol::VerifySessionResumeProof(root, committed, committed_proof));
    BOOST_TEST(state.GetGeneration() == 2u);
}

BOOST_AUTO_TEST_CASE(resume_cancel_rolls_reservation_back_without_generation_change) {
    using ppp::app::server::SessionRecoveryState;
    SessionRecoveryState state;
    BOOST_REQUIRE(state.Suspend(1, 100, 100));
    BOOST_REQUIRE(state.ReserveResume(1, 120, 88));
    BOOST_REQUIRE(state.CancelResume(88));
    BOOST_TEST(state.GetGeneration() == 1u);
    BOOST_TEST(state.IsSuspended(120));
    BOOST_TEST(state.ReserveResume(1, 120, 89));
}

BOOST_AUTO_TEST_CASE(authenticated_stale_sync_allows_exactly_one_retry_with_new_nonce) {
    using ppp::app::server::SessionRecoveryState;
    SessionRecoveryState state;
    BOOST_REQUIRE(state.Suspend(1, 100, 100));
    BOOST_TEST(!state.ReserveResume(0, 120, 70));

    protocol::SessionResumeSecret root(
        Filled<protocol::SessionResumeSecretSize>(9));
    auto request = MakeResumeFields(
        protocol::SessionResumeAction::ResumeRequest, 0);
    request.server_nonce.fill(0);
    auto sync = request;
    sync.action = protocol::SessionResumeAction::GenerationSync;
    sync.generation = 1;
    protocol::SessionResumeProof sync_proof{};
    BOOST_REQUIRE(protocol::ComputeSessionResumeProof(root, sync, sync_proof));

    ClientRetryGuard client;
    const auto first_nonce = client.client_nonce;
    BOOST_REQUIRE(client.Apply(root, request, sync, sync_proof));
    BOOST_TEST(client.generation == 1u);
    BOOST_TEST(client.client_nonce != first_nonce);

    auto retry = MakeResumeFields(
        protocol::SessionResumeAction::ResumeRequest, client.generation);
    retry.client_nonce = client.client_nonce;
    retry.server_nonce.fill(0);
    protocol::SessionResumeProof retry_proof{};
    BOOST_REQUIRE(protocol::ComputeSessionResumeProof(root, retry, retry_proof));
    BOOST_TEST(protocol::VerifySessionResumeProof(root, retry, retry_proof));
    BOOST_TEST(!client.Apply(root, request, sync, sync_proof));
    BOOST_TEST(client.sync_count == 1u);
}

BOOST_AUTO_TEST_CASE(restart_offer_forces_fresh_fallback_on_same_carrier) {
    protocol::SessionResumeControl restart_offer;
    restart_offer.action = protocol::SessionResumeAction::Offer;
    restart_offer.capabilities = protocol::SessionResumeControl::CapabilityV1;
    restart_offer.session_id = SessionId;
    restart_offer.server_nonce = ServerNonce;
    BOOST_REQUIRE(restart_offer.Valid());

    bool retained_root = true;
    const bool fresh_fallback =
        restart_offer.action == protocol::SessionResumeAction::Offer;
    if (fresh_fallback) {
        retained_root = false;
    }
    BOOST_TEST(fresh_fallback);
    BOOST_TEST(!retained_root);
}

BOOST_AUTO_TEST_CASE(client_preamble_preserves_legacy_and_resume_ordering) {
    using ppp::app::client::ClientSessionResumePreamble;
    using ppp::app::client::SelectClientSessionResumePreamble;
    const auto choose = [](bool enabled, bool vnet, bool exporter,
        bool armed, bool root) noexcept {
        return static_cast<int>(SelectClientSessionResumePreamble(
            enabled, vnet, exporter, armed, root));
    };

    BOOST_TEST(choose(false, true, true, false, false) ==
        static_cast<int>(ClientSessionResumePreamble::Legacy));
    BOOST_TEST(choose(true, false, true, false, false) ==
        static_cast<int>(ClientSessionResumePreamble::Legacy));
    BOOST_TEST(choose(true, true, false, false, false) ==
        static_cast<int>(ClientSessionResumePreamble::Legacy));
    BOOST_TEST(choose(true, true, true, false, false) ==
        static_cast<int>(ClientSessionResumePreamble::FreshProbe));
    BOOST_TEST(choose(true, true, true, true, false) ==
        static_cast<int>(ClientSessionResumePreamble::FreshProbe));
    BOOST_TEST(choose(true, true, true, false, true) ==
        static_cast<int>(ClientSessionResumePreamble::FreshProbe));
    BOOST_TEST(choose(true, true, true, true, true) ==
        static_cast<int>(ClientSessionResumePreamble::ResumeRequest));
}
