#include <ppp/app/server/SessionResumeEstablishTransaction.h>

namespace ppp {
    namespace app {
        namespace server {

            SessionResumeTransactionResult RunSessionResumeEstablishTransaction(
                SessionResumeEstablishOperations& operations) noexcept {
                SessionResumeTransactionResult result;

                for (int attempt = 0; attempt < 2; ++attempt) {
                    ppp::app::protocol::SessionResumeControl request;
                    if (!operations.ReadControl(request)) {
                        result.fallback_reason =
                            SessionResumeFallbackReason::LookupMiss;
                        break;
                    }

                    std::uint64_t reservation_token = 0;
                    ppp::app::protocol::SessionResumeControl response;
                    const SessionResumeTransactionBeginStatus status =
                        operations.Begin(request, reservation_token, response);
                    if (status == SessionResumeTransactionBeginStatus::Rejected) {
                        result.fallback_reason =
                            SessionResumeFallbackReason::BeginRejected;
                        break;
                    }
                    if (status ==
                        SessionResumeTransactionBeginStatus::GenerationSync) {
                        if (!operations.SendControl(response) || attempt != 0) {
                            break;
                        }
                        continue;
                    }

                    if (!operations.SendControl(response)) {
                        operations.Cancel(reservation_token);
                        break;
                    }

                    ppp::app::protocol::SessionResumeControl confirm;
                    if (!operations.ReadControl(confirm)) {
                        operations.Cancel(reservation_token);
                        break;
                    }

                    ppp::app::protocol::SessionResumeControl committed;
                    if (!operations.Commit(confirm, reservation_token,
                            committed)) {
                        operations.Cancel(reservation_token);
                        break;
                    }

                    if (!operations.SendControl(committed)) {
                        operations.Cancel(reservation_token);
                        result.outcome =
                            SessionResumeTransactionOutcome::PreserveSuspended;
                        return result;
                    }
                    if (!operations.Publish(reservation_token)) {
                        operations.Cancel(reservation_token);
                        result.outcome = SessionResumeTransactionOutcome::Fatal;
                        return result;
                    }

                    result.outcome = SessionResumeTransactionOutcome::Resumed;
                    return result;
                }

                return result;
            }

        }
    }
}
