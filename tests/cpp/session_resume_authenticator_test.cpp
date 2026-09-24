#define BOOST_TEST_MODULE session_resume_authenticator_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/protocol/SessionResumeAuthenticator.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

namespace protocol = ppp::app::protocol;

namespace {
template <std::size_t N>
std::array<std::uint8_t, N> Filled(std::uint8_t start) {
    std::array<std::uint8_t, N> value{};
    for (std::size_t i = 0; i < N; ++i) {
        value[i] = static_cast<std::uint8_t>(start + i);
    }
    return value;
}

protocol::SessionResumeTranscriptFields MakeFields(
    protocol::SessionResumeAction action = protocol::SessionResumeAction::ResumeAccept) {
    protocol::SessionResumeTranscriptFields fields;
    fields.action = action;
    fields.capabilities = protocol::SessionResumeControl::CapabilityV1;
    fields.session_id = Filled<protocol::SessionResumeIdSize>(1);
    fields.generation = 0x0102030405060708ull;
    fields.client_nonce = Filled<protocol::SessionResumeSecretSize>(21);
    if (action != protocol::SessionResumeAction::ResumeRequest &&
        action != protocol::SessionResumeAction::GenerationSync) {
        fields.server_nonce = Filled<protocol::SessionResumeSecretSize>(61);
    }
    fields.candidate_binding = Filled<protocol::SessionResumeSecretSize>(101);
    return fields;
}

bool IsAllZero(const protocol::SessionResumeBytes32& value) {
    return std::all_of(value.begin(), value.end(),
        [](std::uint8_t byte) { return byte == 0; });
}
}

BOOST_AUTO_TEST_CASE(exporter_derivations_use_distinct_labels_and_session_context) {
    const auto session_id = Filled<protocol::SessionResumeIdSize>(7);
    std::vector<std::string> labels;
    std::vector<protocol::SessionResumeId> contexts;
    const protocol::SessionResumeExporter exporter =
        [&labels, &contexts](const char* label, const std::uint8_t* context,
            std::size_t context_length, std::uint8_t* output,
            std::size_t output_length) {
            if (!label || context_length != protocol::SessionResumeIdSize ||
                output_length != protocol::SessionResumeSecretSize) {
                return false;
            }
            labels.emplace_back(label);
            protocol::SessionResumeId copied_context{};
            std::copy(context, context + context_length, copied_context.begin());
            contexts.push_back(copied_context);
            const std::uint8_t domain = labels.back() ==
                protocol::SessionResumeRootExporterLabel ? 0x31 : 0x92;
            for (std::size_t i = 0; i < output_length; ++i) {
                output[i] = static_cast<std::uint8_t>(domain + i + context[i % context_length]);
            }
            return true;
        };

    protocol::SessionResumeSecret retained_root;
    protocol::SessionResumeCandidateBinding candidate{};
    BOOST_REQUIRE(protocol::DeriveSessionResumeRetainedRoot(
        exporter, session_id, retained_root));
    protocol::SessionResumeBytes32 retained_snapshot{};
    std::copy(retained_root.data(), retained_root.data() + retained_root.size(),
        retained_snapshot.begin());

    BOOST_REQUIRE(protocol::DeriveSessionResumeCandidateBinding(
        exporter, session_id, candidate));
    protocol::SessionResumeBytes32 retained_after_candidate{};
    std::copy(retained_root.data(), retained_root.data() + retained_root.size(),
        retained_after_candidate.begin());

    BOOST_REQUIRE(labels.size() == 2u);
    BOOST_TEST(labels[0] == "EXPORTER-OPENPPP2-L3-ROAMING-ROOT-v1");
    BOOST_TEST(labels[1] == "EXPORTER-OPENPPP2-L3-ROAMING-CANDIDATE-v1");
    BOOST_TEST(contexts[0] == session_id);
    BOOST_TEST(contexts[1] == session_id);
    BOOST_TEST(candidate != retained_snapshot);
    BOOST_TEST(retained_after_candidate == retained_snapshot);
    BOOST_TEST(!protocol::DeriveSessionResumeRetainedRoot(
        exporter, session_id, retained_root));
    protocol::SessionResumeBytes32 retained_after_rederive{};
    std::copy(retained_root.data(), retained_root.data() + retained_root.size(),
        retained_after_rederive.begin());
    BOOST_TEST(retained_after_rederive == retained_snapshot);
}

BOOST_AUTO_TEST_CASE(canonical_transcript_has_fixed_width_and_big_endian_layout) {
    const auto fields = MakeFields(protocol::SessionResumeAction::ResumeRequest);
    protocol::SessionResumeTranscript first{};
    protocol::SessionResumeTranscript second{};
    BOOST_REQUIRE(protocol::BuildSessionResumeTranscript(fields, first));
    BOOST_REQUIRE(protocol::BuildSessionResumeTranscript(fields, second));
    BOOST_TEST(first == second);
    BOOST_TEST(first.size() == 150u);

    const std::array<std::uint8_t, 24> domain = {{
        'o', 'p', 'e', 'n', 'p', 'p', 'p', '2', '-', 'l', '3', '-',
        'r', 'o', 'a', 'm', 'i', 'n', 'g', '-', 'v', '1', 0, 0,
    }};
    BOOST_TEST(std::equal(domain.begin(), domain.end(), first.begin()));
    BOOST_TEST(first[24] == 1u);
    BOOST_TEST(first[25] ==
        static_cast<std::uint8_t>(protocol::SessionResumeAction::ResumeRequest));
    BOOST_TEST(first[26] == 0u);
    BOOST_TEST(first[29] == 1u);
    BOOST_TEST(std::equal(fields.session_id.begin(), fields.session_id.end(),
        first.begin() + 30));
    BOOST_TEST(first[46] == 1u);
    BOOST_TEST(first[53] == 8u);
    BOOST_TEST(std::equal(fields.client_nonce.begin(), fields.client_nonce.end(),
        first.begin() + 54));
    BOOST_TEST(std::all_of(first.begin() + 86, first.begin() + 118,
        [](std::uint8_t value) { return value == 0; }));
    BOOST_TEST(std::equal(fields.candidate_binding.begin(),
        fields.candidate_binding.end(), first.begin() + 118));
}

BOOST_AUTO_TEST_CASE(transcript_enforces_action_specific_zero_placeholders) {
    protocol::SessionResumeTranscript transcript{};

    auto offer = MakeFields();
    offer.action = protocol::SessionResumeAction::Offer;
    offer.generation = 0;
    offer.client_nonce.fill(0);
    offer.candidate_binding.fill(0);
    BOOST_REQUIRE(protocol::BuildSessionResumeTranscript(offer, transcript));
    BOOST_TEST(transcript[25] == 1u);
    offer.generation = 1;
    BOOST_TEST(!protocol::BuildSessionResumeTranscript(offer, transcript));

    auto accepted = MakeFields();
    accepted.action = protocol::SessionResumeAction::Accepted;
    accepted.generation = 0;
    accepted.candidate_binding.fill(0);
    BOOST_REQUIRE(protocol::BuildSessionResumeTranscript(accepted, transcript));
    BOOST_TEST(transcript[25] == 2u);
    accepted.candidate_binding[0] = 1;
    BOOST_TEST(!protocol::BuildSessionResumeTranscript(accepted, transcript));

    const std::array<protocol::SessionResumeAction, 5> resume_actions = {{
        protocol::SessionResumeAction::ResumeRequest,
        protocol::SessionResumeAction::GenerationSync,
        protocol::SessionResumeAction::ResumeAccept,
        protocol::SessionResumeAction::ResumeConfirm,
        protocol::SessionResumeAction::ResumeCommitted,
    }};
    std::uint8_t expected_code = 3;
    for (const auto action : resume_actions) {
        const auto resume = MakeFields(action);
        BOOST_REQUIRE(protocol::BuildSessionResumeTranscript(resume, transcript));
        BOOST_TEST(transcript[25] == expected_code++);
    }

    auto authenticated_reject = MakeFields();
    authenticated_reject.action = protocol::SessionResumeAction::Reject;
    BOOST_REQUIRE(protocol::BuildSessionResumeTranscript(
        authenticated_reject, transcript));
    BOOST_TEST(transcript[25] == 8u);

    protocol::SessionResumeTranscriptFields bare_reject;
    bare_reject.action = protocol::SessionResumeAction::Reject;
    BOOST_REQUIRE(protocol::BuildSessionResumeTranscript(bare_reject, transcript));
    bare_reject.client_nonce[0] = 1;
    BOOST_TEST(!protocol::BuildSessionResumeTranscript(bare_reject, transcript));

    auto invalid = MakeFields();
    invalid.action = protocol::SessionResumeAction::None;
    BOOST_TEST(!protocol::BuildSessionResumeTranscript(invalid, transcript));
    invalid = MakeFields();
    invalid.capabilities = 2;
    BOOST_TEST(!protocol::BuildSessionResumeTranscript(invalid, transcript));
}

BOOST_AUTO_TEST_CASE(transcript_binds_every_field_and_action_domain) {
    const auto baseline_fields = MakeFields();
    protocol::SessionResumeTranscript baseline{};
    BOOST_REQUIRE(protocol::BuildSessionResumeTranscript(baseline_fields, baseline));

    const auto expect_changed = [&baseline](
        const protocol::SessionResumeTranscriptFields& changed) {
        protocol::SessionResumeTranscript transcript{};
        BOOST_REQUIRE(protocol::BuildSessionResumeTranscript(changed, transcript));
        BOOST_TEST(transcript != baseline);
    };

    auto changed = baseline_fields;
    changed.action = protocol::SessionResumeAction::ResumeConfirm;
    expect_changed(changed);
    changed = baseline_fields;
    changed.capabilities = 0;
    protocol::SessionResumeTranscript rejected;
    rejected.fill(0xa5);
    BOOST_TEST(!protocol::BuildSessionResumeTranscript(changed, rejected));
    BOOST_TEST(std::all_of(rejected.begin(), rejected.end(),
        [](std::uint8_t value) { return value == 0; }));
    changed = baseline_fields;
    changed.session_id[0] ^= 1;
    expect_changed(changed);
    changed = baseline_fields;
    changed.generation ^= 1;
    expect_changed(changed);
    changed = baseline_fields;
    changed.client_nonce[0] ^= 1;
    expect_changed(changed);
    changed = baseline_fields;
    changed.server_nonce[0] ^= 1;
    expect_changed(changed);
    changed = baseline_fields;
    changed.candidate_binding[0] ^= 1;
    expect_changed(changed);
}

BOOST_AUTO_TEST_CASE(full_hmac_verifies_and_rejects_proof_or_transcript_tampering) {
    protocol::SessionResumeSecret root(Filled<protocol::SessionResumeSecretSize>(9));
    const auto fields = MakeFields();
    protocol::SessionResumeProof proof{};
    BOOST_REQUIRE(protocol::ComputeSessionResumeProof(root, fields, proof));
    const protocol::SessionResumeProof expected = {{
        0x90, 0xaa, 0xce, 0x7e, 0xdc, 0x11, 0xad, 0x07,
        0xb9, 0xae, 0xae, 0x2d, 0x77, 0xec, 0x6c, 0xa4,
        0xd1, 0xe1, 0x54, 0xec, 0x46, 0x3e, 0x78, 0xb8,
        0x4a, 0xc0, 0x2f, 0x43, 0xdc, 0xc4, 0xd4, 0x88,
    }};
    BOOST_TEST(proof == expected);
    BOOST_TEST(protocol::VerifySessionResumeProof(root, fields, proof));

    auto tampered_proof = proof;
    tampered_proof[31] ^= 1;
    BOOST_TEST(!protocol::VerifySessionResumeProof(root, fields, tampered_proof));

    auto changed = fields;
    changed.action = protocol::SessionResumeAction::ResumeConfirm;
    BOOST_TEST(!protocol::VerifySessionResumeProof(root, changed, proof));
    changed = fields;
    changed.capabilities = 0;
    BOOST_TEST(!protocol::VerifySessionResumeProof(root, changed, proof));
    changed = fields;
    changed.session_id[15] ^= 1;
    BOOST_TEST(!protocol::VerifySessionResumeProof(root, changed, proof));
    changed = fields;
    ++changed.generation;
    BOOST_TEST(!protocol::VerifySessionResumeProof(root, changed, proof));
    changed = fields;
    changed.client_nonce[31] ^= 1;
    BOOST_TEST(!protocol::VerifySessionResumeProof(root, changed, proof));
    changed = fields;
    changed.server_nonce[31] ^= 1;
    BOOST_TEST(!protocol::VerifySessionResumeProof(root, changed, proof));
    changed = fields;
    changed.candidate_binding[31] ^= 1;
    BOOST_TEST(!protocol::VerifySessionResumeProof(root, changed, proof));
}

BOOST_AUTO_TEST_CASE(nonces_are_csprng_generated_nonzero_and_fresh) {
    protocol::SessionResumeNonce first{};
    protocol::SessionResumeNonce second{};
    BOOST_REQUIRE(protocol::GenerateSessionResumeNonce(first));
    BOOST_REQUIRE(protocol::GenerateSessionResumeNonce(second));
    BOOST_TEST(!IsAllZero(first));
    BOOST_TEST(!IsAllZero(second));
    BOOST_TEST(first != second);
}

BOOST_AUTO_TEST_CASE(explicit_clear_exposes_testable_state_without_destructor_peeking) {
    protocol::SessionResumeSecret secret(Filled<protocol::SessionResumeSecretSize>(11));
    BOOST_TEST(secret.IsSet());
    secret.Clear();
    BOOST_TEST(!secret.IsSet());

    protocol::SessionResumePendingAttempt pending;
    pending.active = true;
    pending.fields = MakeFields();
    pending.proof = Filled<protocol::SessionResumeSecretSize>(151);
    BOOST_TEST(pending.IsActive());
    pending.Clear();
    BOOST_TEST(!pending.IsActive());
    BOOST_TEST(static_cast<std::uint8_t>(pending.fields.action) ==
        static_cast<std::uint8_t>(protocol::SessionResumeAction::None));
    BOOST_TEST(pending.fields.capabilities == 0u);
    BOOST_TEST(pending.fields.generation == 0u);
    BOOST_TEST(std::all_of(pending.fields.session_id.begin(),
        pending.fields.session_id.end(), [](std::uint8_t value) { return value == 0; }));
    BOOST_TEST(IsAllZero(pending.fields.client_nonce));
    BOOST_TEST(IsAllZero(pending.fields.server_nonce));
    BOOST_TEST(IsAllZero(pending.fields.candidate_binding));
    BOOST_TEST(IsAllZero(pending.proof));
}

BOOST_AUTO_TEST_CASE(failed_operations_clear_outputs_and_do_not_create_secrets) {
    protocol::SessionResumeSecret root;
    const protocol::SessionResumeExporter missing_exporter;
    BOOST_TEST(!protocol::DeriveSessionResumeRetainedRoot(
        missing_exporter, Filled<protocol::SessionResumeIdSize>(1), root));
    BOOST_TEST(!root.IsSet());

    protocol::SessionResumeProof proof = Filled<protocol::SessionResumeSecretSize>(5);
    BOOST_TEST(!protocol::ComputeSessionResumeProof(root, MakeFields(), proof));
    BOOST_TEST(IsAllZero(proof));
}
