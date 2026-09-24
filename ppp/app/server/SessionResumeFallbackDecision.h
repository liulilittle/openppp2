#pragma once

#include <cstdint>

namespace ppp {
    namespace app {
        namespace server {

            enum class SessionResumeFallbackReason : std::uint8_t {
                ResumeDisabled,
                IneligibleCarrier,
                LookupMiss,
                BeginRejected,
                OtherResumeFailure,
            };

            enum class SessionResumeFallbackDecision : std::uint8_t {
                Fresh,
                Reject,
            };

            constexpr SessionResumeFallbackDecision DecideSessionResumeFallback(
                SessionResumeFallbackReason reason) noexcept {
                // Preserve pre-resume replacement behavior only when the feature
                // is explicitly disabled.  Once enabled, a channel already exists
                // for the session ID, so carrier eligibility and authenticated
                // control must fail closed instead of replacing that channel.
                return reason == SessionResumeFallbackReason::ResumeDisabled
                    ? SessionResumeFallbackDecision::Fresh
                    : SessionResumeFallbackDecision::Reject;
            }

        }
    }
}
