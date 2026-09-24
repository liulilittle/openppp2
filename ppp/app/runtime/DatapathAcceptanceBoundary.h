#pragma once

#include <cstdint>
#include <string>

namespace ppp {
    namespace app {
        namespace runtime {

            struct DatapathAcceptanceBoundaryRecord final {
                static constexpr std::uint32_t SchemaVersion = 1;

                std::string run_uuid;
                std::string cell_id;
                std::uint64_t sequence = 0;
                std::string phase;
                std::uint64_t monotonic_ms = 0;
                std::uint64_t process_pid = 0;
                std::uint64_t process_start_ticks = 0;
                std::uint64_t xtcp_runtime_instance_id = 0;
            };

            struct DatapathAcceptanceBoundaryConfiguration final {
                std::string run_uuid;
                std::string cell_id;
                std::string request_path;
                std::string acknowledgement_path;
                std::uint64_t process_pid = 0;
                std::uint64_t process_start_ticks = 0;
            };

            /**
             * @brief Strict local acceptance-boundary request/acknowledgement gate.
             *
             * The gate is disabled unless a complete startup configuration is
             * available. An accepted request remains pending until its matching
             * runtime stats line has been written successfully; acknowledgement
             * publication is then retried independently without duplicating that
             * stats line.
             */
            class DatapathAcceptanceBoundary final {
            public:
                /** @brief Snapshots the acceptance-boundary environment once. */
                bool ConfigureFromEnvironment() noexcept;

                /**
                 * @brief Configures a Linux test instance with an explicit process identity.
                 *
                 * Production callers should use ConfigureFromEnvironment().
                 */
                bool ConfigureForTesting(
                    const DatapathAcceptanceBoundaryConfiguration& configuration) noexcept;

                /** @brief Returns whether the gate has a usable startup configuration. */
                bool IsEnabled() const noexcept;

                /**
                 * @brief Polls one strictly validated request, if it is eligible for stats.
                 * @param boundary Receives the immutable request fields on success.
                 * @return True when the caller must emit this boundary in its stats record.
                 */
                bool Poll(DatapathAcceptanceBoundaryRecord& boundary) noexcept;

                /**
                 * @brief Commits the pending request after its matching stats record was written.
                 * @param monotonic_ms Monotonic timestamp carried by that stats record.
                 * @param xtcp_runtime_instance_id XTCP identity carried by that stats record.
                 * @return True only when a request transitioned to acknowledgement-pending.
                 */
                bool MarkStatsWritten(std::uint64_t monotonic_ms,
                    std::uint64_t xtcp_runtime_instance_id) noexcept;

                /**
                 * @brief Atomically retries publication of the committed acknowledgement.
                 * @return True only when a pending acknowledgement was published.
                 */
                bool RetryAcknowledgement() noexcept;

                /** @brief Returns whether a stats-written acknowledgement still needs publication. */
                bool HasPendingAcknowledgement() const noexcept;

            private:
                void Reset() noexcept;
                bool Configure(
                    const DatapathAcceptanceBoundaryConfiguration& configuration) noexcept;

            private:
                bool enabled_ = false;
                bool start_committed_ = false;
                bool end_committed_ = false;
                bool pending_stats_ = false;
                bool pending_acknowledgement_ = false;
                std::uint64_t last_sequence_ = 0;
                std::string run_uuid_;
                std::string cell_id_;
                std::string request_path_;
                std::string acknowledgement_path_;
                std::string acknowledgement_directory_;
                std::uint64_t process_pid_ = 0;
                std::uint64_t process_start_ticks_ = 0;
                DatapathAcceptanceBoundaryRecord record_;
            };

        }
    }
}
