#define BOOST_TEST_MODULE session_resume_fallback_decision_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/server/SessionResumeFallbackDecision.h>

namespace server = ppp::app::server;

BOOST_AUTO_TEST_CASE(disabled_feature_preserves_legacy_replacement) {
    BOOST_TEST(static_cast<int>(server::DecideSessionResumeFallback(
        server::SessionResumeFallbackReason::ResumeDisabled)) ==
        static_cast<int>(server::SessionResumeFallbackDecision::Fresh));
}

BOOST_AUTO_TEST_CASE(enabled_feature_rejects_unauthenticated_replacement) {
    for (const auto reason : {
            server::SessionResumeFallbackReason::IneligibleCarrier,
            server::SessionResumeFallbackReason::LookupMiss,
            server::SessionResumeFallbackReason::BeginRejected,
            server::SessionResumeFallbackReason::OtherResumeFailure}) {
        BOOST_TEST(static_cast<int>(server::DecideSessionResumeFallback(reason)) ==
            static_cast<int>(server::SessionResumeFallbackDecision::Reject));
    }
}
