#pragma once

#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/app/server/SessionResumeFallbackDecision.h>

#include <cstdint>

namespace ppp {
    namespace app {
        namespace server {

            enum class SessionResumeTransactionBeginStatus : std::uint8_t {
                Accepted,
                GenerationSync,
                Rejected,
            };

            enum class SessionResumeTransactionOutcome : std::uint8_t {
                Resumed,
                Rejected,
                PreserveSuspended,
                Fatal,
            };

            struct SessionResumeTransactionResult final {
                SessionResumeTransactionOutcome outcome =
                    SessionResumeTransactionOutcome::Rejected;
                SessionResumeFallbackReason fallback_reason =
                    SessionResumeFallbackReason::OtherResumeFailure;
            };

            /**
             * @brief Narrow adapter used by the Establish resume control transaction.
             *
             * The adapter owns carrier/exchanger details.  The transaction only
             * enforces control ordering, reservation cancellation, and the
             * write-before-publish boundary.
             */
            class SessionResumeEstablishOperations {
            public:
                using Control = ppp::app::protocol::SessionResumeControl;

                virtual ~SessionResumeEstablishOperations() = default;

                virtual bool ReadControl(Control& control) noexcept = 0;
                virtual bool SendControl(const Control& control) noexcept = 0;
                virtual SessionResumeTransactionBeginStatus Begin(
                    const Control& request, std::uint64_t& reservation_token,
                    Control& response) noexcept = 0;
                virtual bool Commit(const Control& confirm,
                    std::uint64_t reservation_token,
                    Control& committed) noexcept = 0;
                virtual bool Publish(std::uint64_t reservation_token) noexcept = 0;
                virtual void Cancel(std::uint64_t reservation_token) noexcept = 0;
            };

            /**
             * @brief Runs the existing-session resume transaction used by Establish.
             */
            SessionResumeTransactionResult RunSessionResumeEstablishTransaction(
                SessionResumeEstablishOperations& operations) noexcept;

        }
    }
}
