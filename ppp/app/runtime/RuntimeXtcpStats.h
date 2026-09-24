#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace ppp {
    namespace app {
        namespace runtime {

            struct XtcpDirectQueueSnapshot final {
                static constexpr std::size_t kTimingBuckets = 32;
                std::uint64_t bytes = 0;
                std::uint64_t items = 0;
                std::uint64_t backpressured = 0;
                std::uint64_t writer_active = 0;
                std::uint64_t writer_progress_age_ms = 0;
                std::uint64_t second_leg_handler_us[kTimingBuckets] = {};
                std::uint64_t second_leg_accepted_wait_to_resume_us[kTimingBuckets] = {};
            };

            class XtcpDirectQueueTelemetry final {
            public:
                void Add(std::size_t bytes) noexcept {
                    bytes_.fetch_add(bytes, std::memory_order_relaxed);
                    items_.fetch_add(1, std::memory_order_relaxed);
                }
                void Remove(std::size_t bytes, std::size_t items) noexcept {
                    bytes_.fetch_sub(bytes, std::memory_order_relaxed);
                    items_.fetch_sub(items, std::memory_order_relaxed);
                }
                void SetBackpressured(bool value) noexcept {
                    if (value) {
                        backpressured_.fetch_add(1, std::memory_order_relaxed);
                    }
                    else {
                        backpressured_.fetch_sub(1, std::memory_order_relaxed);
                    }
                }
                void WriterStarted() noexcept {
                    writer_active_.fetch_add(1, std::memory_order_relaxed);
                    WriterProgress();
                }
                void WriterProgress() noexcept {
                    writer_progress_us_.store(NowUs(), std::memory_order_relaxed);
                }
                void WriterStopped() noexcept {
                    if (writer_active_.fetch_sub(1, std::memory_order_relaxed) == 1) {
                        writer_progress_us_.store(0, std::memory_order_relaxed);
                    }
                }
                bool TimingEnabled() const noexcept {
                    return timing_enabled_.load(std::memory_order_relaxed);
                }
                void EnableTiming() noexcept {
                    timing_enabled_.store(true, std::memory_order_relaxed);
                }
                std::uint64_t Now() const noexcept { return NowUs(); }
                void RecordSecondLegHandler(std::uint64_t us) noexcept {
                    RecordTiming(second_leg_handler_us_, us);
                }
                void RecordSecondLegAcceptedWaitToResume(std::uint64_t us) noexcept {
                    RecordTiming(second_leg_accepted_wait_to_resume_us_, us);
                }
                XtcpDirectQueueSnapshot Snapshot() const noexcept {
                    XtcpDirectQueueSnapshot snapshot;
                    snapshot.bytes = bytes_.load(std::memory_order_relaxed);
                    snapshot.items = items_.load(std::memory_order_relaxed);
                    snapshot.backpressured = backpressured_.load(std::memory_order_relaxed);
                    snapshot.writer_active = writer_active_.load(std::memory_order_relaxed);
                    const std::uint64_t progress = writer_progress_us_.load(std::memory_order_relaxed);
                    const std::uint64_t now = NowUs();
                    snapshot.writer_progress_age_ms = progress != 0 && now > progress
                        ? (now - progress) / 1000 : 0;
                    for (std::size_t i = 0; i < XtcpDirectQueueSnapshot::kTimingBuckets; ++i) {
                        snapshot.second_leg_handler_us[i] =
                            second_leg_handler_us_[i].load(std::memory_order_relaxed);
                        snapshot.second_leg_accepted_wait_to_resume_us[i] =
                            second_leg_accepted_wait_to_resume_us_[i].load(std::memory_order_relaxed);
                    }
                    return snapshot;
                }

            private:
                static void RecordTiming(std::atomic<std::uint64_t>* hist,
                    std::uint64_t us) noexcept {
                    std::size_t bucket = 0;
                    while (us > 1 && bucket + 1 < XtcpDirectQueueSnapshot::kTimingBuckets) {
                        us >>= 1;
                        ++bucket;
                    }
                    hist[bucket].fetch_add(1, std::memory_order_relaxed);
                }
                static std::uint64_t NowUs() noexcept {
                    return static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count());
                }

                std::atomic<std::uint64_t> bytes_{0};
                std::atomic<std::uint64_t> items_{0};
                std::atomic<std::uint64_t> backpressured_{0};
                std::atomic<std::uint64_t> writer_active_{0};
                std::atomic<std::uint64_t> writer_progress_us_{0};
                std::atomic<bool> timing_enabled_{false};
                std::atomic<std::uint64_t>
                    second_leg_handler_us_[XtcpDirectQueueSnapshot::kTimingBuckets] = {};
                std::atomic<std::uint64_t>
                    second_leg_accepted_wait_to_resume_us_[XtcpDirectQueueSnapshot::kTimingBuckets] = {};
            };

            /**
             * @brief Monotonic counters and gauges exported by the XTCP
             *        userspace TCP stack runtime. All counters are cumulative
             *        since the current runtime generation started.
             */
            struct RuntimeXtcpStats final {
                std::uint64_t runtime_generation = 0;     /**< Current XTCP runtime generation */
                std::uint64_t runtime_instance_id = 0;    /**< Unique latest successful XTCP start identity */
                std::uint64_t direct_bridge_starts = 0;   /**< Successfully activated direct bridges */
                std::uint64_t direct_bridge_active = 0;   /**< Gauge: currently active direct bridges */
                std::uint64_t direct_bridge_fallbacks = 0;/**< Requested direct bridges that used normal fallback */
                std::uint64_t direct_upload_accepted_chunks = 0; /**< Direct uploads accepted by second legs */
                std::uint64_t direct_upload_accepted_bytes = 0; /**< Bytes in accepted direct uploads */
                std::uint64_t direct_download_accepted_bytes = 0; /**< Bytes admitted from direct downloads */
                std::uint64_t direct_upload_writable_callbacks = 0; /**< Upload-resume callbacks received */
                std::uint64_t direct_download_writable_callbacks = 0; /**< Exact accepted download callbacks delivered */
                std::uint64_t ingress_submitted = 0;      /**< IPv4/TCP datagrams accepted into the ingress queue */
                std::uint64_t ingress_dropped = 0;        /**< Datagrams rejected before queueing (not ready / budget) */
                std::uint64_t ingress_injected = 0;       /**< Datagrams handed to the XTCP stack */
                std::uint64_t flows_opened = 0;           /**< Flows created from inbound SYNs */
                std::uint64_t flows_closed = 0;           /**< Flows torn down (any reason) */
                std::uint64_t flows_active = 0;           /**< Gauge: flows currently tracked */
                std::uint64_t timer_polls = 0;            /**< PollAckTimers sweeps executed */
                std::uint64_t timer_events = 0;           /**< Timer events fired across all sweeps */
                std::uint64_t output_packets = 0;         /**< L3 packets emitted by the stack */
                std::uint64_t output_bytes = 0;           /**< L3 bytes emitted by the stack */
                bool ndi_gso_enabled = false;              /**< NDI advertises kCapTsoTx for this runtime */
                std::uint64_t ndi_gso_packets = 0;        /**< Valid NDI TSO super-packets accepted downstream */
                std::uint64_t ndi_gso_bytes = 0;          /**< L3 bytes in accepted NDI TSO super-packets */
                std::uint64_t ndi_gso_rejected = 0;       /**< Marked NDI TSO packets rejected or malformed */
                std::uint64_t connector_read_bytes = 0;   /**< Bytes read from second-leg connectors (app -> stack) */
                std::uint64_t connector_written_bytes = 0;/**< Bytes written to second-leg connectors (stack -> app) */
                std::uint64_t queued_bytes = 0;           /**< Gauge: bytes in the runtime->connector bridge queue */
                std::uint64_t queued_bytes_highwater = 0; /**< Gauge peak of queued_bytes since start */
                std::uint64_t resume_requested = 0;       /**< Direct receive resume requests: second leg or shared budget */
                std::uint64_t resume_effective = 0;       /**< Blocked XTCP receive windows actually reopened */
                std::uint64_t resume_result_not_blocked = 0; /**< Resume attempts made before/after the core latch */
                std::uint64_t resume_result_window_full = 0; /**< Resume attempts held by OOO receive-window usage */
                std::uint64_t resume_result_connection_missing = 0; /**< Resume attempts whose core connection vanished */
                std::uint64_t resume_pending = 0;         /**< Gauge: direct flows awaiting receive resume */
                std::uint64_t resume_coalesced = 0;       /**< Duplicate writable notifications merged */
                std::uint64_t resume_terminal = 0;        /**< Resume requests terminated by close/stale/missing */
                std::uint64_t resume_retry = 0;           /**< Bounded deferred resume handoffs */
                std::uint64_t resume_window_full_retry = 0; /**< Window-full results retried because app still rejected */
                std::uint64_t direct_download_chunks = 0; /**< Direct second-leg chunks accepted by the runtime */
                std::uint64_t direct_download_rejected = 0;/**< Direct second-leg chunks rejected by runtime budget */
                std::uint64_t direct_upload_rejected = 0; /**< XTCP receive chunks rejected by local/global direct upload admission */
                std::uint64_t direct_upload_queue_bytes = 0; /**< Gauge: direct upload bytes queued/in flight */
                std::uint64_t upload_budget_bytes = 0; /**< Reserved upload payload, connector + direct, including in-flight owners */
                std::uint64_t upload_budget_items = 0;
                std::uint64_t upload_budget_max_bytes = 0;
                std::uint64_t upload_budget_max_items = 0;
                std::uint64_t upload_budget_waiters = 0; /**< Gauge: ordered fair waiters */
                std::uint64_t upload_budget_wake_events = 0; /**< Credit releases that woke fair waiters */
                std::uint64_t upload_budget_wake_empty = 0; /**< Wake scans that found no grantable waiter */
                std::uint64_t upload_budget_fairness_switches = 0; /**< Grants that rotated away from the prior flow */
                std::uint64_t upload_budget_rejected = 0; /**< Admission rejected before payload allocation */
                std::uint64_t direct_upload_queue_items = 0; /**< Gauge: direct upload items queued/in flight */
                std::uint64_t direct_upload_backpressured = 0; /**< Gauge: direct bridges rejecting uploads */
                std::uint64_t direct_upload_writer_active = 0; /**< Gauge: active direct upload writers */
                std::uint64_t direct_upload_writer_progress_age_ms = 0; /**< Age of latest writer progress */
                std::uint64_t second_leg_close_requested = 0; /**< Direct second-leg close requests issued */
                std::uint64_t second_leg_close_duplicate_suppressed = 0; /**< Duplicate direct close notifications and requests skipped */
                std::uint64_t degraded_half_close = 0;   /**< Direct upload FINs degraded to full transmission disposal */
                std::uint64_t direct_download_queue_bytes = 0; /**< Gauge: second-leg bytes waiting for XTCP admission */
                std::uint64_t direct_download_queue_bytes_highwater = 0; /**< Peak direct download queue bytes */
            };

        }
    }
}
