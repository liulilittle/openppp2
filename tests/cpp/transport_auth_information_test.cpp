#define BOOST_TEST_MODULE transport_auth_information_test
#include <ppp/stdafx.h>
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/protocol/VirtualEthernetInformation.h>

namespace protocol = ppp::app::protocol;

namespace {
const ppp::string Method = "noise-psk-v1";
const ppp::string KeyId = "primary.key_1";
const ppp::string Token = "00112233445566778899aabbccddeeff";
const ppp::string Message = "0011aaff";
const ppp::string Proof(64, 'a');

protocol::TransportAuthControl MakeAdvertise(bool with_message = false) {
    protocol::TransportAuthControl control;
    control.action = protocol::TransportAuthAction::Advertise;
    control.methods = {"tls-exporter-v1", Method};
    control.token = Token;
    if (with_message) {
        control.method = Method;
        control.key_id = KeyId;
        control.sequence = 1;
        control.message = Message;
    }
    return control;
}

protocol::TransportAuthControl MakeSelect() {
    protocol::TransportAuthControl control;
    control.action = protocol::TransportAuthAction::Select;
    control.method = Method;
    control.key_id = KeyId;
    control.token = Token;
    control.sequence = 2;
    control.message = Message;
    return control;
}

protocol::TransportAuthControl MakeSuccess(bool with_proof) {
    protocol::TransportAuthControl control;
    control.action = protocol::TransportAuthAction::Success;
    control.method = Method;
    control.key_id = KeyId;
    control.token = Token;
    if (with_proof) {
        control.proof = Proof;
    }
    return control;
}

protocol::TransportAuthControl MakeReject(bool with_token = false) {
    protocol::TransportAuthControl control;
    control.action = protocol::TransportAuthAction::Reject;
    control.reason = "authentication-failed";
    if (with_token) {
        control.token = Token;
    }
    return control;
}

Json::Value ToJson(const protocol::TransportAuthControl& control) {
    Json::Value json;
    control.ToJson(json);
    return json;
}

void ExpectInvalid(const Json::Value& transport_auth) {
    Json::Value extensions;
    extensions["IPv6StatusMessage"] = "cleared-on-failure";
    extensions["transport-auth"] = transport_auth;

    protocol::VirtualEthernetInformationExtensions parsed;
    parsed.TransportAuth = MakeAdvertise();
    BOOST_TEST(!protocol::VirtualEthernetInformationExtensions::FromJson(
        parsed, extensions));
    BOOST_TEST(!parsed.TransportAuth.HasAny());
}

protocol::SessionResumeControl MakeSessionResumeOffer() {
    protocol::SessionResumeControl control;
    control.action = protocol::SessionResumeAction::Offer;
    control.capabilities = protocol::SessionResumeControl::CapabilityV1;
    control.session_id = "00112233445566778899aabbccddeeff";
    control.server_nonce = ppp::string(64, 'b');
    return control;
}
}

BOOST_AUTO_TEST_CASE(all_action_forms_round_trip) {
    const protocol::TransportAuthControl controls[] = {
        MakeAdvertise(false),
        MakeAdvertise(true),
        MakeSelect(),
        MakeSuccess(true),
        MakeSuccess(false),
        MakeReject(false),
        MakeReject(true),
    };

    for (const protocol::TransportAuthControl& control : controls) {
        BOOST_REQUIRE(control.Valid());
        protocol::VirtualEthernetInformationExtensions extensions;
        extensions.TransportAuth = control;
        BOOST_TEST(extensions.HasAny());

        Json::Value wire;
        extensions.ToJson(wire);
        BOOST_REQUIRE(wire["transport-auth"].isObject());
        BOOST_TEST(wire["transport-auth"]["version"].asUInt() == 1u);
        BOOST_TEST(wire["transport-auth"]["action"].asString() ==
            protocol::TransportAuthControl::ActionToString(control.action));

        protocol::VirtualEthernetInformationExtensions parsed;
        BOOST_REQUIRE(protocol::VirtualEthernetInformationExtensions::FromJson(
            parsed, wire));
        BOOST_TEST(static_cast<unsigned>(parsed.TransportAuth.action) ==
            static_cast<unsigned>(control.action));
        BOOST_TEST(parsed.TransportAuth.method == control.method);
        BOOST_TEST(parsed.TransportAuth.methods == control.methods,
            boost::test_tools::per_element());
        BOOST_TEST(parsed.TransportAuth.key_id == control.key_id);
        BOOST_TEST(parsed.TransportAuth.token == control.token);
        BOOST_TEST(parsed.TransportAuth.sequence == control.sequence);
        BOOST_TEST(parsed.TransportAuth.message == control.message);
        BOOST_TEST(parsed.TransportAuth.proof == control.proof);
        BOOST_TEST(parsed.TransportAuth.reason == control.reason);
    }
}

BOOST_AUTO_TEST_CASE(transport_auth_and_session_resume_are_independent_siblings) {
    protocol::VirtualEthernetInformationExtensions extensions;
    extensions.TransportAuth = MakeAdvertise();
    extensions.SessionResume = MakeSessionResumeOffer();

    Json::Value wire;
    extensions.ToJson(wire);
    BOOST_REQUIRE(wire["transport-auth"].isObject());
    BOOST_REQUIRE(wire["session-resume"].isObject());

    protocol::VirtualEthernetInformationExtensions parsed;
    BOOST_REQUIRE(protocol::VirtualEthernetInformationExtensions::FromJson(parsed, wire));
    BOOST_TEST(parsed.TransportAuth.Valid());
    BOOST_TEST(parsed.SessionResume.Valid());
    BOOST_TEST(parsed.SessionResume.session_id ==
        extensions.SessionResume.session_id);
}

BOOST_AUTO_TEST_CASE(unknown_siblings_remain_ignored_but_unknown_control_fields_fail) {
    Json::Value extensions;
    extensions["future-sibling"] = Json::Value(Json::objectValue);
    extensions["transport-auth"] = ToJson(MakeAdvertise());

    protocol::VirtualEthernetInformationExtensions parsed;
    BOOST_REQUIRE(protocol::VirtualEthernetInformationExtensions::FromJson(
        parsed, extensions));
    BOOST_TEST(parsed.TransportAuth.Valid());

    Json::Value malformed = extensions["transport-auth"];
    malformed["future-control-field"] = true;
    ExpectInvalid(malformed);

    Json::Value unknown_only;
    unknown_only["future-sibling"] = true;
    BOOST_REQUIRE(protocol::VirtualEthernetInformationExtensions::FromJson(
        parsed, unknown_only));
    BOOST_TEST(!parsed.HasAny());
}

BOOST_AUTO_TEST_CASE(rejects_missing_wrong_type_and_unsupported_discriminators) {
    Json::Value valid = ToJson(MakeAdvertise());
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
    malformed.removeMember("action");
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["action"] = "future-action";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["action"] = 1;
    ExpectInvalid(malformed);
    ExpectInvalid(Json::Value("not-an-object"));
}

BOOST_AUTO_TEST_CASE(rejects_invalid_methods_arrays_tokens_and_duplicates) {
    Json::Value valid = ToJson(MakeAdvertise());
    Json::Value malformed = valid;
    malformed["methods"] = "noise-psk-v1";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["methods"] = Json::Value(Json::arrayValue);
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["methods"].append("extra-one");
    malformed["methods"].append("extra-two");
    malformed["methods"].append("extra-three");
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["methods"].append(Method);
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["methods"][0] = "TLS-exporter-v1";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["methods"][0] = ppp::string(
        protocol::TransportAuthControl::MaximumMethodLength + 1, 'a');
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["methods"][0] = "bad_method";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["methods"][0] = Json::UInt(1);
    ExpectInvalid(malformed);
}

BOOST_AUTO_TEST_CASE(rejects_invalid_method_and_key_id_tokens) {
    Json::Value valid = ToJson(MakeSelect());
    Json::Value malformed = valid;
    malformed["method"] = "Noise-psk-v1";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["method"] = ppp::string(
        protocol::TransportAuthControl::MaximumMethodLength + 1, 'a');
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["method"] = Json::UInt(1);
    ExpectInvalid(malformed);

    malformed = valid;
    malformed["key-id"] = "_leading";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["key-id"] = "Upper";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["key-id"] = "contains/slash";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["key-id"] = ppp::string(
        protocol::TransportAuthControl::MaximumKeyIdLength + 1, 'a');
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["key-id"] = Json::UInt(1);
    ExpectInvalid(malformed);
}

BOOST_AUTO_TEST_CASE(requires_fixed_canonical_attempt_tokens) {
    Json::Value required[] = {
        ToJson(MakeAdvertise(false)),
        ToJson(MakeAdvertise(true)),
        ToJson(MakeSelect()),
        ToJson(MakeSuccess(true)),
        ToJson(MakeSuccess(false)),
    };
    for (Json::Value valid : required) {
        valid.removeMember("token");
        ExpectInvalid(valid);
    }

    Json::Value malformed = ToJson(MakeSelect());
    malformed["token"] = "";
    ExpectInvalid(malformed);
    malformed = ToJson(MakeSelect());
    malformed["token"] = "00112233445566778899aabbccddeef";
    ExpectInvalid(malformed);
    malformed = ToJson(MakeSelect());
    malformed["token"] = "00112233445566778899AABBCCDDEEFF";
    ExpectInvalid(malformed);
    malformed = ToJson(MakeSelect());
    malformed["token"] = ppp::string(64, 'a');
    ExpectInvalid(malformed);
    malformed = ToJson(MakeSelect());
    malformed["token"] = ppp::string(
        protocol::TransportAuthControl::MaximumTokenSize + 1, 'a');
    ExpectInvalid(malformed);
    malformed = ToJson(MakeSelect());
    malformed["token"] = Json::UInt(1);
    ExpectInvalid(malformed);

    malformed = ToJson(MakeReject());
    malformed["token"] = "ABCDEF";
    ExpectInvalid(malformed);
}

BOOST_AUTO_TEST_CASE(rejects_sequence_errors_and_noncanonical_messages) {
    Json::Value valid = ToJson(MakeSelect());
    Json::Value malformed = valid;
    malformed["sequence"] = 1;
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["sequence"] = "2";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["sequence"] = 2.0;
    ExpectInvalid(malformed);
    malformed = valid;
    malformed.removeMember("sequence");
    ExpectInvalid(malformed);

    malformed = valid;
    malformed["message"] = "";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["message"] = "0";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["message"] = "AA";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["message"] = "gg";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["message"] = ppp::string(
        (protocol::TransportAuthControl::MaximumMessageBytes + 1) * 2, 'a');
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["message"] = Json::UInt(1);
    ExpectInvalid(malformed);
}

BOOST_AUTO_TEST_CASE(rejects_noncanonical_proofs_and_reason_tokens) {
    Json::Value valid = ToJson(MakeSuccess(true));
    Json::Value malformed = valid;
    malformed["proof"] = ppp::string(63, 'a');
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["proof"] = ppp::string(64, 'A');
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["proof"] = Json::UInt(1);
    ExpectInvalid(malformed);

    valid = ToJson(MakeReject());
    malformed = valid;
    malformed["reason"] = "";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["reason"] = "contains space";
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["reason"] = ppp::string(
        protocol::TransportAuthControl::MaximumReasonLength + 1, 'a');
    ExpectInvalid(malformed);
    malformed = valid;
    malformed["reason"] = Json::UInt(1);
    ExpectInvalid(malformed);
}

BOOST_AUTO_TEST_CASE(rejects_invalid_action_field_combinations) {
    Json::Value malformed = ToJson(MakeAdvertise());
    malformed["key-id"] = KeyId;
    ExpectInvalid(malformed);

    malformed = ToJson(MakeAdvertise(true));
    malformed["sequence"] = 2;
    ExpectInvalid(malformed);
    malformed = ToJson(MakeAdvertise(true));
    malformed["method"] = "unadvertised-v1";
    ExpectInvalid(malformed);

    malformed = ToJson(MakeSelect());
    malformed["methods"] = ToJson(MakeAdvertise())["methods"];
    ExpectInvalid(malformed);
    malformed = ToJson(MakeSelect());
    malformed["proof"] = Proof;
    ExpectInvalid(malformed);

    malformed = ToJson(MakeSuccess(false));
    malformed["sequence"] = 2;
    ExpectInvalid(malformed);
    malformed = ToJson(MakeSuccess(false));
    malformed["message"] = Message;
    ExpectInvalid(malformed);
    malformed = ToJson(MakeSuccess(false));
    malformed.removeMember("key-id");
    ExpectInvalid(malformed);

    malformed = ToJson(MakeReject());
    malformed["method"] = Method;
    ExpectInvalid(malformed);
    malformed = ToJson(MakeReject());
    malformed.removeMember("reason");
    ExpectInvalid(malformed);
}

BOOST_AUTO_TEST_CASE(clear_and_serializer_do_not_emit_invalid_controls) {
    protocol::VirtualEthernetInformationExtensions extensions;
    extensions.TransportAuth = MakeAdvertise();
    extensions.Clear();
    BOOST_TEST(extensions.TransportAuth.token.empty());
    BOOST_TEST(!extensions.TransportAuth.HasAny());
    BOOST_TEST(!extensions.HasAny());

    extensions.TransportAuth.token = Token;
    BOOST_TEST(extensions.TransportAuth.HasAny());
    extensions.TransportAuth.Clear();

    extensions.TransportAuth = MakeSelect();
    extensions.TransportAuth.message[0] = 'A';
    Json::Value wire;
    extensions.ToJson(wire);
    BOOST_TEST(!wire.isMember("transport-auth"));

    extensions.TransportAuth = MakeSuccess(true);
    extensions.TransportAuth.version = 2;
    wire = Json::Value();
    extensions.ToJson(wire);
    BOOST_TEST(!wire.isMember("transport-auth"));
}
