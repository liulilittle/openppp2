#pragma once

#include <ppp/app/protocol/VirtualEthernetInformation.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>

namespace ppp {
    namespace app {
        namespace protocol {
            inline constexpr std::size_t SessionResumeSecretSize = 32;
            inline constexpr std::size_t SessionResumeIdSize = 16;
            inline constexpr std::size_t SessionResumeTranscriptSize = 150;
            inline constexpr char SessionResumeRootExporterLabel[] =
                "EXPORTER-OPENPPP2-L3-ROAMING-ROOT-v1";
            inline constexpr char SessionResumeCandidateExporterLabel[] =
                "EXPORTER-OPENPPP2-L3-ROAMING-CANDIDATE-v1";

            using SessionResumeId = std::array<std::uint8_t, SessionResumeIdSize>;
            using SessionResumeBytes32 = std::array<std::uint8_t, SessionResumeSecretSize>;
            using SessionResumeNonce = SessionResumeBytes32;
            using SessionResumeCandidateBinding = SessionResumeBytes32;
            using SessionResumeProof = SessionResumeBytes32;
            using SessionResumeTranscript =
                std::array<std::uint8_t, SessionResumeTranscriptSize>;
            using SessionResumeExporter = std::function<bool(
                const char* label,
                const std::uint8_t* context,
                std::size_t context_length,
                std::uint8_t* output,
                std::size_t output_length)>;

            /** @brief Move-only 32-byte secret with explicit OpenSSL cleansing. */
            class SessionResumeSecret final {
            public:
                SessionResumeSecret() noexcept = default;
                explicit SessionResumeSecret(const SessionResumeBytes32& value) noexcept;
                ~SessionResumeSecret() noexcept;

                SessionResumeSecret(const SessionResumeSecret&) = delete;
                SessionResumeSecret& operator=(const SessionResumeSecret&) = delete;
                SessionResumeSecret(SessionResumeSecret&& other) noexcept;
                SessionResumeSecret& operator=(SessionResumeSecret&& other) noexcept;

                void                                                Assign(const SessionResumeBytes32& value) noexcept;
                void                                                Clear() noexcept;
                bool                                                IsSet() const noexcept;
                const std::uint8_t*                                 data() const noexcept;
                std::size_t                                         size() const noexcept;

            private:
                SessionResumeBytes32                                bytes_{};
                bool                                                is_set_ = false;
            };

            /** @brief Fields authenticated by the canonical v1 binary transcript. */
            struct SessionResumeTranscriptFields {
                SessionResumeAction                                 action = SessionResumeAction::None;
                std::uint32_t                                       capabilities = 0;
                SessionResumeId                                     session_id{};
                std::uint64_t                                       generation = 0;
                SessionResumeNonce                                  client_nonce{};
                SessionResumeNonce                                  server_nonce{};
                SessionResumeCandidateBinding                       candidate_binding{};
            };

            /** @brief Attempt-owned state; it never rotates or owns the retained root. */
            struct SessionResumePendingAttempt {
                bool                                                active = false;
                SessionResumeTranscriptFields                       fields;
                SessionResumeProof                                  proof{};

                SessionResumePendingAttempt() noexcept = default;
                ~SessionResumePendingAttempt() noexcept;
                SessionResumePendingAttempt(const SessionResumePendingAttempt&) = delete;
                SessionResumePendingAttempt& operator=(const SessionResumePendingAttempt&) = delete;
                SessionResumePendingAttempt(SessionResumePendingAttempt&& other) noexcept;
                SessionResumePendingAttempt& operator=(SessionResumePendingAttempt&& other) noexcept;

                void                                                Clear() noexcept;
                bool                                                IsActive() const noexcept;
            };

            bool                                                    GenerateSessionResumeNonce(SessionResumeNonce& output) noexcept;
            bool                                                    DeriveSessionResumeRetainedRoot(
                const SessionResumeExporter& exporter,
                const SessionResumeId& session_id,
                SessionResumeSecret& output) noexcept;
            bool                                                    DeriveSessionResumeCandidateBinding(
                const SessionResumeExporter& exporter,
                const SessionResumeId& session_id,
                SessionResumeCandidateBinding& output) noexcept;
            bool                                                    BuildSessionResumeTranscript(
                const SessionResumeTranscriptFields& fields,
                SessionResumeTranscript& output) noexcept;
            bool                                                    ComputeSessionResumeProof(
                const SessionResumeSecret& retained_root,
                const SessionResumeTranscriptFields& fields,
                SessionResumeProof& output) noexcept;
            bool                                                    VerifySessionResumeProof(
                const SessionResumeSecret& retained_root,
                const SessionResumeTranscriptFields& fields,
                const SessionResumeProof& proof) noexcept;
        }
    }
}
