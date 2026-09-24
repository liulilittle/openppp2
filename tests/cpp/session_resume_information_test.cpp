#define BOOST_TEST_MODULE session_resume_information_test
#include <ppp/stdafx.h>
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/protocol/VirtualEthernetInformation.h>

#include <array>
#include <limits>

namespace protocol = ppp::app::protocol;

namespace {
const ppp::string SessionId = "00112233445566778899aabbccddeeff";
const ppp::string ClientNonce(64, '1');
const ppp::string ServerNonce(64, '2');
const ppp::string CandidateBinding(64, '3');
const ppp::string Proof(64, '4');

protocol::SessionResumeControl MakeControl(protocol::SessionResumeAction action) {
    protocol::SessionResumeControl control;
    control.action = action;
    if (action == protocol::SessionResumeAction::Reject) {
        control.reason = "session-missing";
        return control;
    }

    control.capabilities = protocol::SessionResumeControl::CapabilityV1;
    control.session_id = SessionId;
    if (action != protocol::SessionResumeAction::ResumeRequest &&
        action != protocol::SessionResumeAction::GenerationSync) {
        control.server_nonce = ServerNonce;
    }
    if (action == protocol::SessionResumeAction::Offer) {
        return control;
    }

    control.client_nonce = ClientNonce;
    if (action == protocol::SessionResumeAction::Accepted) {
        control.proof = Proof;
    }
    else {
        control.generation = 18446744073709551615ull;
        control.candidate_binding = CandidateBinding;
        control.proof = Proof;
    }
    return control;
}

Json::Value MakeJson(protocol::SessionResumeAction action) {
    Json::Value json;
    MakeControl(action).ToJson(json);
    return json;
}

void ExpectInvalid(const Json::Value& session_resume) {
    Json::Value extensions;
    extensions["IPv6StatusMessage"] = "preserved-sibling";
    extensions["session-resume"] = session_resume;

    protocol::VirtualEthernetInformationExtensions parsed;
    parsed.SessionResume = MakeControl(protocol::SessionResumeAction::Offer);
    BOOST_TEST(!protocol::VirtualEthernetInformationExtensions::FromJson(
        parsed, extensions));
    BOOST_TEST(!parsed.SessionResume.HasAny());
}
}

BOOST_AUTO_TEST_CASE(all_v1_actions_round_trip_with_canonical_wire_types) {
    const std::array<protocol::SessionResumeAction, 8> actions = {{
        protocol::SessionResumeAction::Offer,
        protocol::SessionResumeAction::Accepted,
        protocol::SessionResumeAction::ResumeRequest,
        protocol::SessionResumeAction::GenerationSync,
        protocol::SessionResumeAction::ResumeAccept,
        protocol::SessionResumeAction::ResumeConfirm,
        protocol::SessionResumeAction::ResumeCommitted,
        protocol::SessionResumeAction::Reject,
    }};

    for (const auto action : actions) {
        protocol::VirtualEthernetInformationExtensions extensions;
        extensions.SessionResume = MakeControl(action);

        Json::Value json;
        extensions.ToJson(json);
        BOOST_REQUIRE(json["session-resume"].isObject());
        const Json::Value& wire = json["session-resume"];
        BOOST_TEST(wire["version"].asUInt() == 1u);
        BOOST_TEST(wire["action"].asString() ==
            protocol::SessionResumeControl::ActionToString(action));

        const bool resume_action = action == protocol::SessionResumeAction::ResumeRequest ||
            action == protocol::SessionResumeAction::GenerationSync ||
            action == protocol::SessionResumeAction::ResumeAccept ||
            action == protocol::SessionResumeAction::ResumeConfirm ||
            action == protocol::SessionResumeAction::ResumeCommitted;
        if (resume_action) {
            BOOST_TEST(wire["generation"].isString());
            BOOST_TEST(wire["generation"].asString() == "18446744073709551615");
        }

        protocol::VirtualEthernetInformationExtensions parsed;
        BOOST_REQUIRE(protocol::VirtualEthernetInformationExtensions::FromJson(
            parsed, json));
        BOOST_TEST(static_cast<std::uint8_t>(parsed.SessionResume.action) ==
            static_cast<std::uint8_t>(action));
        BOOST_TEST(parsed.SessionResume.version == 1u);
        BOOST_TEST(parsed.SessionResume.reason == extensions.SessionResume.reason);
        if (action != protocol::SessionResumeAction::Reject) {
            BOOST_TEST(parsed.SessionResume.session_id == SessionId);
            const bool omits_server_nonce =
                action == protocol::SessionResumeAction::ResumeRequest ||
                action == protocol::SessionResumeAction::GenerationSync;
            BOOST_TEST(wire.isMember("server-nonce") == !omits_server_nonce);
            BOOST_TEST(parsed.SessionResume.server_nonce ==
                (omits_server_nonce ? ppp::string() : ServerNonce));
        }
        if (action != protocol::SessionResumeAction::Offer &&
            action != protocol::SessionResumeAction::Reject) {
            BOOST_TEST(parsed.SessionResume.client_nonce == ClientNonce);
        }
        if (resume_action) {
            BOOST_TEST(parsed.SessionResume.generation ==
                std::numeric_limits<std::uint64_t>::max());
            BOOST_TEST(parsed.SessionResume.candidate_binding == CandidateBinding);
            BOOST_TEST(parsed.SessionResume.proof == Proof);
        }
    }
}

BOOST_AUTO_TEST_CASE(unknown_fields_are_additively_compatible) {
    Json::Value extensions;
    extensions["future-sibling"] = "ignored";
    extensions["session-resume"] = MakeJson(
        protocol::SessionResumeAction::ResumeRequest);
    extensions["session-resume"]["future-control-field"] = Json::Value(Json::objectValue);

    protocol::VirtualEthernetInformationExtensions parsed;
    BOOST_REQUIRE(protocol::VirtualEthernetInformationExtensions::FromJson(
        parsed, extensions));
    BOOST_TEST(static_cast<std::uint8_t>(parsed.SessionResume.action) ==
        static_cast<std::uint8_t>(protocol::SessionResumeAction::ResumeRequest));
}

BOOST_AUTO_TEST_CASE(absent_control_does_not_invalidate_other_extensions) {
    protocol::VirtualEthernetInformationExtensions parsed;
    Json::Value empty(Json::objectValue);
    BOOST_REQUIRE(protocol::VirtualEthernetInformationExtensions::FromJson(
        parsed, empty));
    BOOST_TEST(!parsed.HasAny());

    Json::Value extensions;
    extensions["IPv6StatusMessage"] = "legacy-extension";
    BOOST_REQUIRE(protocol::VirtualEthernetInformationExtensions::FromJson(
        parsed, extensions));
    BOOST_TEST(parsed.IPv6StatusMessage == "legacy-extension");
    BOOST_TEST(!parsed.SessionResume.HasAny());

    Json::Value unknown_only;
    unknown_only["future-sibling"] = true;
    BOOST_REQUIRE(protocol::VirtualEthernetInformationExtensions::FromJson(
        parsed, unknown_only));
    BOOST_TEST(!parsed.HasAny());
}

BOOST_AUTO_TEST_CASE(reject_accepts_bare_or_complete_authenticated_form) {
    Json::Value bare = MakeJson(protocol::SessionResumeAction::Reject);
    protocol::SessionResumeControl parsed;
    BOOST_REQUIRE(protocol::SessionResumeControl::FromJson(parsed, bare));

    Json::Value authenticated = MakeJson(
        protocol::SessionResumeAction::ResumeAccept);
    authenticated["action"] = "reject";
    authenticated["reason"] = "stale-generation";
    BOOST_REQUIRE(protocol::SessionResumeControl::FromJson(parsed, authenticated));
    BOOST_TEST(parsed.generation == std::numeric_limits<std::uint64_t>::max());
}

BOOST_AUTO_TEST_CASE(strictly_rejects_wrong_types_versions_and_ranges) {
    Json::Value valid = MakeJson(protocol::SessionResumeAction::ResumeRequest);

    Json::Value malformed = valid;
    malformed.removeMember("version");
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["version"] = 2;
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["version"] = "1";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["version"] = 1.0;
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["action"] = "future-action";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["capabilities"] = "1";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["capabilities"] = 2;
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["capabilities"] = 1.0;
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["capabilities"] = Json::UInt64(
        static_cast<Json::UInt64>(std::numeric_limits<std::uint32_t>::max()) + 1);
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["generation"] = Json::UInt64(7);
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["generation"] = "07";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["generation"] = "18446744073709551616";
    ExpectInvalid(malformed);
}

BOOST_AUTO_TEST_CASE(strictly_rejects_noncanonical_hex_and_reason_tokens) {
    Json::Value valid = MakeJson(protocol::SessionResumeAction::ResumeRequest);

    Json::Value malformed = valid;
    malformed["session-id"] = "00112233445566778899AABBCCDDEEFF";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["session-id"] = SessionId.substr(1);
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["client-nonce"] = ppp::string(63, '1');
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["server-nonce"] = ppp::string(64, 'A');
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["candidate-binding"] = Json::UInt(3);
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["proof"] = ppp::string(65, '4');
    ExpectInvalid(malformed);

    malformed = MakeJson(protocol::SessionResumeAction::Reject);
    malformed["reason"] = ppp::string(
        protocol::SessionResumeControl::MaximumReasonLength + 1, 'a');
    ExpectInvalid(malformed);
    malformed = MakeJson(protocol::SessionResumeAction::Reject);
    malformed["reason"] = "contains space";
    ExpectInvalid(malformed);
}

BOOST_AUTO_TEST_CASE(strictly_rejects_invalid_action_field_combinations) {
    Json::Value malformed = MakeJson(protocol::SessionResumeAction::Offer);
    malformed["proof"] = Proof;
    ExpectInvalid(malformed);

    malformed = MakeJson(protocol::SessionResumeAction::Offer);
    malformed.removeMember("server-nonce");
    ExpectInvalid(malformed);

    malformed = MakeJson(protocol::SessionResumeAction::Offer);
    malformed["client-nonce"] = ClientNonce;
    ExpectInvalid(malformed);

    malformed = MakeJson(protocol::SessionResumeAction::Accepted);
    malformed.removeMember("server-nonce");
    ExpectInvalid(malformed);

    malformed = MakeJson(protocol::SessionResumeAction::ResumeConfirm);
    malformed.removeMember("generation");
    ExpectInvalid(malformed);

    malformed = MakeJson(protocol::SessionResumeAction::Reject);
    malformed.removeMember("reason");
    ExpectInvalid(malformed);

    malformed = MakeJson(protocol::SessionResumeAction::Reject);
    malformed["session-id"] = SessionId;
    ExpectInvalid(malformed);

    ExpectInvalid(Json::Value("not-an-object"));
}

BOOST_AUTO_TEST_CASE(serializer_never_emits_noncanonical_controls) {
    protocol::VirtualEthernetInformationExtensions extensions;
    extensions.SessionResume = MakeControl(protocol::SessionResumeAction::Offer);
    extensions.SessionResume.session_id[0] = 'A';
    Json::Value json;
    extensions.ToJson(json);
    BOOST_TEST(!json.isMember("session-resume"));

    extensions.SessionResume = MakeControl(protocol::SessionResumeAction::Accepted);
    extensions.SessionResume.generation = 1;
    json = Json::Value();
    extensions.ToJson(json);
    BOOST_TEST(!json.isMember("session-resume"));

    extensions.SessionResume = MakeControl(protocol::SessionResumeAction::ResumeRequest);
    extensions.SessionResume.version = 2;
    json = Json::Value();
    extensions.ToJson(json);
    BOOST_TEST(!json.isMember("session-resume"));
}
