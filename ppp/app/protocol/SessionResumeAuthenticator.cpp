#include <ppp/app/protocol/SessionResumeAuthenticator.h>

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <cstring>
#include <utility>

namespace {
    static constexpr std::uint8_t SessionResumeTranscriptDomain[24] = {
        'o', 'p', 'e', 'n', 'p', 'p', 'p', '2', '-', 'l', '3', '-',
        'r', 'o', 'a', 'm', 'i', 'n', 'g', '-', 'v', '1', 0, 0,
    };

    template <std::size_t N>
    static bool IsZero(const std::array<std::uint8_t, N>& value) noexcept {
        std::uint8_t combined = 0;
        for (std::uint8_t byte : value) {
            combined |= byte;
        }
        return combined == 0;
    }

    static void WriteUInt32BigEndian(std::uint8_t* output, std::uint32_t value) noexcept {
        output[0] = static_cast<std::uint8_t>(value >> 24);
        output[1] = static_cast<std::uint8_t>(value >> 16);
        output[2] = static_cast<std::uint8_t>(value >> 8);
        output[3] = static_cast<std::uint8_t>(value);
    }

    static void WriteUInt64BigEndian(std::uint8_t* output, std::uint64_t value) noexcept {
        for (std::size_t i = 0; i < sizeof(value); ++i) {
            output[i] = static_cast<std::uint8_t>(value >> ((sizeof(value) - i - 1) * 8));
        }
    }
}

namespace ppp {
    namespace app {
        namespace protocol {
            SessionResumeSecret::SessionResumeSecret(
                const SessionResumeBytes32& value) noexcept {
                Assign(value);
            }

            SessionResumeSecret::~SessionResumeSecret() noexcept {
                Clear();
            }

            SessionResumeSecret::SessionResumeSecret(
                SessionResumeSecret&& other) noexcept {
                if (other.is_set_) {
                    bytes_ = other.bytes_;
                    is_set_ = true;
                }
                other.Clear();
            }

            SessionResumeSecret& SessionResumeSecret::operator=(
                SessionResumeSecret&& other) noexcept {
                if (this != &other) {
                    Clear();
                    if (other.is_set_) {
                        bytes_ = other.bytes_;
                        is_set_ = true;
                    }
                    other.Clear();
                }
                return *this;
            }

            void SessionResumeSecret::Assign(const SessionResumeBytes32& value) noexcept {
                Clear();
                bytes_ = value;
                is_set_ = true;
            }

            void SessionResumeSecret::Clear() noexcept {
                OPENSSL_cleanse(bytes_.data(), bytes_.size());
                is_set_ = false;
            }

            bool SessionResumeSecret::IsSet() const noexcept {
                return is_set_;
            }

            const std::uint8_t* SessionResumeSecret::data() const noexcept {
                return bytes_.data();
            }

            std::size_t SessionResumeSecret::size() const noexcept {
                return bytes_.size();
            }

            SessionResumePendingAttempt::~SessionResumePendingAttempt() noexcept {
                Clear();
            }

            SessionResumePendingAttempt::SessionResumePendingAttempt(
                SessionResumePendingAttempt&& other) noexcept {
                active = other.active;
                fields = other.fields;
                proof = other.proof;
                other.Clear();
            }

            SessionResumePendingAttempt& SessionResumePendingAttempt::operator=(
                SessionResumePendingAttempt&& other) noexcept {
                if (this != &other) {
                    Clear();
                    active = other.active;
                    fields = other.fields;
                    proof = other.proof;
                    other.Clear();
                }
                return *this;
            }

            void SessionResumePendingAttempt::Clear() noexcept {
                OPENSSL_cleanse(fields.session_id.data(), fields.session_id.size());
                OPENSSL_cleanse(fields.client_nonce.data(), fields.client_nonce.size());
                OPENSSL_cleanse(fields.server_nonce.data(), fields.server_nonce.size());
                OPENSSL_cleanse(
                    fields.candidate_binding.data(), fields.candidate_binding.size());
                OPENSSL_cleanse(proof.data(), proof.size());
                fields.action = SessionResumeAction::None;
                fields.capabilities = 0;
                fields.generation = 0;
                active = false;
            }

            bool SessionResumePendingAttempt::IsActive() const noexcept {
                return active;
            }

            bool GenerateSessionResumeNonce(SessionResumeNonce& output) noexcept {
                SessionResumeNonce generated{};
                const bool ok = RAND_bytes(
                    generated.data(), static_cast<int>(generated.size())) == 1;
                if (ok) {
                    output = generated;
                }
                else {
                    OPENSSL_cleanse(output.data(), output.size());
                }
                OPENSSL_cleanse(generated.data(), generated.size());
                return ok;
            }

            bool DeriveSessionResumeRetainedRoot(
                const SessionResumeExporter& exporter,
                const SessionResumeId& session_id,
                SessionResumeSecret& output) noexcept {
                if (output.IsSet() || !exporter) {
                    return false;
                }

                SessionResumeBytes32 derived{};
                const bool ok = exporter(
                    SessionResumeRootExporterLabel,
                    session_id.data(), session_id.size(),
                    derived.data(), derived.size());
                if (ok) {
                    output.Assign(derived);
                }
                OPENSSL_cleanse(derived.data(), derived.size());
                return ok;
            }

            bool DeriveSessionResumeCandidateBinding(
                const SessionResumeExporter& exporter,
                const SessionResumeId& session_id,
                SessionResumeCandidateBinding& output) noexcept {
                if (!exporter) {
                    OPENSSL_cleanse(output.data(), output.size());
                    return false;
                }

                SessionResumeCandidateBinding derived{};
                const bool ok = exporter(
                    SessionResumeCandidateExporterLabel,
                    session_id.data(), session_id.size(),
                    derived.data(), derived.size());
                if (ok) {
                    output = derived;
                }
                else {
                    OPENSSL_cleanse(output.data(), output.size());
                }
                OPENSSL_cleanse(derived.data(), derived.size());
                return ok;
            }

            bool BuildSessionResumeTranscript(
                const SessionResumeTranscriptFields& fields,
                SessionResumeTranscript& output) noexcept {
                const std::uint8_t action = static_cast<std::uint8_t>(fields.action);
                const bool known_capabilities =
                    (fields.capabilities & ~SessionResumeControl::CapabilityV1) == 0;
                bool valid_fields = false;
                switch (fields.action) {
                    case SessionResumeAction::Offer:
                        valid_fields = fields.capabilities ==
                                SessionResumeControl::CapabilityV1 &&
                            fields.generation == 0 && IsZero(fields.client_nonce) &&
                            IsZero(fields.candidate_binding);
                        break;
                    case SessionResumeAction::Accepted:
                        valid_fields = fields.capabilities ==
                                SessionResumeControl::CapabilityV1 &&
                            fields.generation == 0 && IsZero(fields.candidate_binding);
                        break;
                    case SessionResumeAction::ResumeRequest:
                    case SessionResumeAction::GenerationSync:
                        valid_fields = fields.capabilities ==
                                SessionResumeControl::CapabilityV1 &&
                            IsZero(fields.server_nonce);
                        break;
                    case SessionResumeAction::ResumeAccept:
                    case SessionResumeAction::ResumeConfirm:
                    case SessionResumeAction::ResumeCommitted:
                        valid_fields = fields.capabilities ==
                            SessionResumeControl::CapabilityV1;
                        break;
                    case SessionResumeAction::Reject:
                        valid_fields = fields.capabilities ==
                                SessionResumeControl::CapabilityV1 ||
                            (fields.capabilities == 0 && IsZero(fields.session_id) &&
                                fields.generation == 0 && IsZero(fields.client_nonce) &&
                                IsZero(fields.server_nonce) &&
                                IsZero(fields.candidate_binding));
                        break;
                    default:
                        break;
                }
                if (!known_capabilities || !valid_fields ||
                    action < static_cast<std::uint8_t>(SessionResumeAction::Offer) ||
                    action > static_cast<std::uint8_t>(SessionResumeAction::Reject)) {
                    OPENSSL_cleanse(output.data(), output.size());
                    return false;
                }

                SessionResumeTranscript transcript{};
                std::size_t offset = 0;
                std::memcpy(transcript.data() + offset,
                    SessionResumeTranscriptDomain, sizeof(SessionResumeTranscriptDomain));
                offset += sizeof(SessionResumeTranscriptDomain);
                transcript[offset++] = SessionResumeControl::ProtocolVersion;
                transcript[offset++] = action;
                WriteUInt32BigEndian(transcript.data() + offset, fields.capabilities);
                offset += sizeof(fields.capabilities);
                std::memcpy(transcript.data() + offset,
                    fields.session_id.data(), fields.session_id.size());
                offset += fields.session_id.size();
                WriteUInt64BigEndian(transcript.data() + offset, fields.generation);
                offset += sizeof(fields.generation);
                std::memcpy(transcript.data() + offset,
                    fields.client_nonce.data(), fields.client_nonce.size());
                offset += fields.client_nonce.size();
                std::memcpy(transcript.data() + offset,
                    fields.server_nonce.data(), fields.server_nonce.size());
                offset += fields.server_nonce.size();
                std::memcpy(transcript.data() + offset,
                    fields.candidate_binding.data(), fields.candidate_binding.size());
                offset += fields.candidate_binding.size();

                if (offset != transcript.size()) {
                    OPENSSL_cleanse(transcript.data(), transcript.size());
                    return false;
                }
                output = transcript;
                OPENSSL_cleanse(transcript.data(), transcript.size());
                return true;
            }

            bool ComputeSessionResumeProof(
                const SessionResumeSecret& retained_root,
                const SessionResumeTranscriptFields& fields,
                SessionResumeProof& output) noexcept {
                if (!retained_root.IsSet()) {
                    OPENSSL_cleanse(output.data(), output.size());
                    return false;
                }

                SessionResumeTranscript transcript{};
                SessionResumeProof proof{};
                if (!BuildSessionResumeTranscript(fields, transcript)) {
                    OPENSSL_cleanse(output.data(), output.size());
                    return false;
                }

                unsigned int proof_length = 0;
                const unsigned char* result = HMAC(
                    EVP_sha256(), retained_root.data(),
                    static_cast<int>(retained_root.size()),
                    transcript.data(), transcript.size(),
                    proof.data(), &proof_length);
                const bool ok = result == proof.data() && proof_length == proof.size();
                if (ok) {
                    output = proof;
                }
                else {
                    OPENSSL_cleanse(output.data(), output.size());
                }
                OPENSSL_cleanse(proof.data(), proof.size());
                OPENSSL_cleanse(transcript.data(), transcript.size());
                return ok;
            }

            bool VerifySessionResumeProof(
                const SessionResumeSecret& retained_root,
                const SessionResumeTranscriptFields& fields,
                const SessionResumeProof& proof) noexcept {
                SessionResumeProof expected{};
                const bool computed = ComputeSessionResumeProof(
                    retained_root, fields, expected);
                const bool verified = computed &&
                    CRYPTO_memcmp(expected.data(), proof.data(), proof.size()) == 0;
                OPENSSL_cleanse(expected.data(), expected.size());
                return verified;
            }
        }
    }
}
