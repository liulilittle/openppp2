#pragma once

/**
 * @file DatapathPerfJson.h
 * @brief Laboratory-only per-stage datapath performance JSONL telemetry.
 *
 * OPENPPP2_DATAPATH_PERF_JSON is a runtime environment variable containing the
 * JSONL path. This format is diagnostic-only and not a stable ABI or interface.
 */

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <mutex>
#include <ostream>
#include <string>

namespace ppp {
    namespace diagnostics {
        namespace datapath_perf {
            struct RuntimeConfig final {
                bool enabled = false;
                bool measurement_boundaries = false;
                std::string path;
            };

            /** @brief Signal-safe request state; snapshots are emitted later on a datapath thread. */
            inline volatile std::sig_atomic_t measurement_boundary_requests = 0;

            inline void MeasurementBoundarySignalHandler(int) noexcept {
                if (measurement_boundary_requests == 0) {
                    measurement_boundary_requests = 1;
                }
                else if (measurement_boundary_requests == 1) {
                    measurement_boundary_requests = 2;
                }
            }

            /** @brief Thread-safe one-time environment lookup and path copy. */
            inline const RuntimeConfig& GetRuntimeConfig() noexcept {
                static const RuntimeConfig config = []() noexcept {
                    RuntimeConfig result;
                    const char* path = std::getenv("OPENPPP2_DATAPATH_PERF_JSON");
                    if (path && *path) {
                        try {
                            result.path = path;
                            result.enabled = !result.path.empty();
                            const char* boundaries = std::getenv("OPENPPP2_DATAPATH_PERF_MEASUREMENT_BOUNDARIES");
                            result.measurement_boundaries = result.enabled && boundaries && *boundaries == '1';
                            if (result.measurement_boundaries) {
#if defined(__unix__) || defined(__APPLE__)
                                struct sigaction action {};
                                action.sa_handler = MeasurementBoundarySignalHandler;
                                sigemptyset(&action.sa_mask);
                                action.sa_flags = SA_RESTART;
                                if (sigaction(SIGUSR1, &action, nullptr) != 0) {
                                    result.measurement_boundaries = false;
                                }
#else
                                // Signal-based measurement boundaries are POSIX-only.
                                result.measurement_boundaries = false;
#endif
                            }
                        }
                        catch (...) {}
                    }
                    return result;
                }();
                return config;
            }

            inline bool IsEnabled() noexcept {
                return GetRuntimeConfig().enabled;
            }

            inline std::sig_atomic_t MeasurementBoundaryRequest() noexcept {
                return GetRuntimeConfig().measurement_boundaries ? measurement_boundary_requests : 0;
            }

            inline const char* MeasurementBoundaryName(std::sig_atomic_t request) noexcept {
                return request == 1 ? "measurement_start" : request == 2 ? "measurement_end" : nullptr;
            }

            inline void RequestMeasurementBoundaryForTesting(bool end) noexcept {
                measurement_boundary_requests = end ? 2 : 1;
            }

            /** Experiment hook: the Linux TAP mergeability analyzer renders its
             *  window into boundary records when
             *  OPENPPP2_DATAPATH_GSO_MERGEABILITY=1. */
            using MergeabilityRenderFn = void (*)(std::ostream& output, const char* boundary_name);
            inline MergeabilityRenderFn mergeability_render = nullptr;
            inline void SetMergeabilityRender(MergeabilityRenderFn fn) noexcept { mergeability_render = fn; }

            /** Production-candidate GSO ledger, installed only when
             *  OPENPPP2_DATAPATH_GSO_LEDGER=1. It is intentionally separate
             *  from generic direct-write counters because its framing domain is
             *  VNET GSO coalescer output only. */
            using GsoLedgerRenderFn = void (*)(std::ostream& output, const char* boundary_name);
            inline GsoLedgerRenderFn gso_ledger_render = nullptr;
            inline void SetGsoLedgerRender(GsoLedgerRenderFn fn) noexcept { gso_ledger_render = fn; }

            /** Linux TUN output fail-closed diagnostic renderer. Installed only when
             *  OPENPPP2_DATAPATH_TUN_OUTPUT_DIAGNOSTICS=1. */
            using TunOutputRenderFn = void (*)(std::ostream& output);
            inline TunOutputRenderFn tun_output_render = nullptr;
            inline void SetTunOutputRender(TunOutputRenderFn fn) noexcept { tun_output_render = fn; }

            struct FrameStageCounters final {
                std::atomic<uint64_t> calls{0};
                std::atomic<uint64_t> bytes{0};
                std::atomic<uint64_t> us_sum{0};
                std::atomic<uint64_t> us_max{0};
            };

            constexpr size_t kTunDirectWriteLatencyBucketCount = 9;
            constexpr size_t kTunDirectWriteSizeBucketCount = 7;
            inline constexpr std::array<const char*, kTunDirectWriteLatencyBucketCount> kTunDirectWriteLatencyBucketLabels{
                "<4us", "4-8us", "8-16us", "16-32us", "32-64us", "64-128us", "128-256us", "256-1000us", ">1ms"
            };
            inline constexpr std::array<const char*, kTunDirectWriteSizeBucketCount> kTunDirectWriteSizeBucketLabels{
                "<=128", "129-256", "257-512", "513-1024", "1025-1400", "1401-1500", ">1500"
            };

            enum class MtaHandoffPath : size_t {
                SameThread,
                SameExecutorDifferentThread,
                CrossExecutor,
                Unknown,
                Count
            };

            constexpr size_t kMtaHandoffPathCount = static_cast<size_t>(MtaHandoffPath::Count);
            inline constexpr std::array<const char*, kMtaHandoffPathCount> kMtaHandoffPathLabels{
                "same_thread", "same_executor_different_thread", "cross_executor", "unknown"
            };

            constexpr size_t kMtaHandoffSegmentCount = 4;
            constexpr size_t kMtaHandoffProducerSlotCount = 8;
            inline constexpr std::array<const char*, kMtaHandoffSegmentCount> kMtaHandoffSegmentLabels{
                "prepare", "post_call", "executor_queue", "handler_service"
            };

            /** @brief Publication state shared only by one telemetry producer and its posted handler. */
            struct MtaHandoffTimeline final {
                std::chrono::steady_clock::time_point t2;
                std::atomic<bool> post_returned{false};
            };

            struct MtaHandoffObservation final {
                bool enabled = false;
                uint64_t producer_thread_id = 0;
                uintptr_t producer_context_token = 0;
                uintptr_t target_context_token = 0;
                int bytes = 0;
                std::chrono::steady_clock::time_point t0;
                std::chrono::steady_clock::time_point t1;
                std::shared_ptr<MtaHandoffTimeline> timeline;
            };

            struct MtaHandoffPathCounters final {
                std::atomic<uint64_t> posted{0};
                std::atomic<uint64_t> dispatched{0};
                std::atomic<uint64_t> bytes{0};
                std::atomic<uint64_t> queue_us_sum{0};
                std::atomic<uint64_t> queue_us_max{0};
            };

            struct MtaHandoffSegmentCounters final {
                std::atomic<uint64_t> calls{0};
                std::atomic<uint64_t> us_sum{0};
                std::atomic<uint64_t> us_max{0};
            };

            struct MtaHandoffProducerSlotCounters final {
                uint64_t producer_thread_id = 0;
                uint64_t packets = 0;
                uint64_t bytes = 0;
                std::array<uint64_t, kMtaHandoffSegmentCount> us_sum{};
                std::array<uint64_t, kMtaHandoffSegmentCount> us_max{};
            };

            struct MtaHandoffProducerSlots final {
                std::mutex mutex;
                std::array<MtaHandoffProducerSlotCounters, kMtaHandoffProducerSlotCount> slots{};
                MtaHandoffProducerSlotCounters other{};
            };

            struct Counters final {
                std::atomic<uint64_t> tun_read_calls{0};
                std::atomic<uint64_t> tun_read_bytes{0};
                std::atomic<uint64_t> tun_write_enqueued{0};
                std::atomic<uint64_t> tun_write_enqueued_bytes{0};
                std::atomic<uint64_t> tun_write_completed{0};
                std::atomic<uint64_t> tun_write_bytes{0};
                std::atomic<uint64_t> tun_write_us_sum{0};
                std::atomic<uint64_t> tun_write_us_max{0};
                std::atomic<uint64_t> tun_direct_write_attempted{0};
                std::atomic<uint64_t> tun_direct_write_attempted_bytes{0};
                std::atomic<uint64_t> tun_direct_write_completed{0};
                std::atomic<uint64_t> tun_direct_write_bytes{0};
                std::atomic<uint64_t> tun_direct_write_failed{0};
                std::atomic<uint64_t> tun_direct_write_partial{0};
                std::atomic<uint64_t> tun_direct_write_us_sum{0};
                std::atomic<uint64_t> tun_direct_write_us_max{0};
                std::atomic<uint64_t> tun_direct_write_over_100us{0};
                std::atomic<uint64_t> tun_direct_write_inflight{0};
                std::atomic<uint64_t> tun_direct_write_inflight_max{0};
                std::atomic<uint64_t> tun_direct_write_entry_inflight_0{0};
                std::atomic<uint64_t> tun_direct_write_entry_inflight_1{0};
                std::atomic<uint64_t> tun_direct_write_entry_inflight_2{0};
                std::atomic<uint64_t> tun_direct_write_entry_inflight_3plus{0};
                std::array<std::atomic<uint64_t>, kTunDirectWriteLatencyBucketCount> tun_direct_write_latency_buckets{};
                std::array<std::atomic<uint64_t>, kTunDirectWriteSizeBucketCount> tun_direct_write_size_buckets{};
                std::atomic<uint64_t> vnet_input_calls{0};
                std::atomic<uint64_t> vnet_input_bytes{0};
                std::atomic<uint64_t> vnet_input_us_sum{0};
                std::atomic<uint64_t> vnet_input_us_max{0};
                std::atomic<uint64_t> vnet_output_calls{0};
                std::atomic<uint64_t> vnet_output_bytes{0};
                std::atomic<uint64_t> vnet_output_us_sum{0};
                std::atomic<uint64_t> vnet_output_us_max{0};
                std::atomic<uint64_t> vnet_output_direct{0};
                std::atomic<uint64_t> vnet_output_cached{0};
                std::atomic<uint64_t> vnet_mta_packet_posted{0};
                std::atomic<uint64_t> vnet_mta_packet_dispatched{0};
                std::atomic<uint64_t> vnet_mta_packet_queue_us_sum{0};
                std::atomic<uint64_t> vnet_mta_packet_queue_us_max{0};
                std::array<MtaHandoffPathCounters, kMtaHandoffPathCount> vnet_mta_handoff_paths{};
                std::array<MtaHandoffSegmentCounters, kMtaHandoffSegmentCount> vnet_mta_handoff_segments{};
                std::atomic<uint64_t> frame_encode_calls{0};
                std::atomic<uint64_t> frame_plain_bytes{0};
                std::atomic<uint64_t> frame_cipher_bytes{0};
                std::atomic<uint64_t> frame_encode_us_sum{0};
                std::atomic<uint64_t> frame_encode_us_max{0};
                std::atomic<uint64_t> frame_decode_calls{0};
                std::atomic<uint64_t> frame_decode_plain_bytes{0};
                std::atomic<uint64_t> frame_decode_us_sum{0};
                std::atomic<uint64_t> frame_decode_us_max{0};
                FrameStageCounters frame_transport_encrypt;
                FrameStageCounters frame_header_encrypt;
                FrameStageCounters frame_payload_encrypt;
                FrameStageCounters frame_pack;
                FrameStageCounters frame_header_decrypt;
                FrameStageCounters frame_payload_decrypt;
                FrameStageCounters frame_transport_decrypt;
                std::atomic<uint64_t> nat_to_tun_calls{0};
                std::atomic<uint64_t> nat_to_tun_bytes{0};
                std::atomic<uint64_t> carrier_send_calls{0};
                std::atomic<uint64_t> carrier_send_bytes{0};
                std::atomic<uint64_t> carrier_send_us_sum{0};
                std::atomic<uint64_t> carrier_send_us_max{0};
                std::atomic<uint64_t> carrier_recv_calls{0};
                std::atomic<uint64_t> carrier_recv_bytes{0};
                std::atomic<uint64_t> carrier_recv_us_sum{0};
                std::atomic<uint64_t> carrier_recv_us_max{0};
                std::atomic<uint64_t> carrier_queue_items{0};
                std::atomic<uint64_t> carrier_queue_bytes{0};
                std::atomic<uint64_t> carrier_queue_items_high{0};
                std::atomic<uint64_t> carrier_queue_bytes_high{0};
                std::atomic<uint64_t> vmux_accepted_calls{0};
                std::atomic<uint64_t> vmux_accepted_bytes{0};
                std::atomic<uint64_t> vmux_socket_write_completed_calls{0};
                std::atomic<uint64_t> vmux_socket_write_completed_bytes{0};
                std::atomic<uint64_t> vmux_socket_write_us_sum{0};
                std::atomic<uint64_t> vmux_socket_write_us_max{0};
                std::atomic<uint64_t> tcpip_bridge_socket_read_calls{0};
                std::atomic<uint64_t> tcpip_bridge_socket_read_bytes{0};
                std::atomic<uint64_t> tcpip_bridge_transmission_write_accepted_calls{0};
                std::atomic<uint64_t> tcpip_bridge_transmission_write_accepted_bytes{0};
                std::atomic<uint64_t> tcpip_bridge_transmission_write_accepted_us_sum{0};
                std::atomic<uint64_t> tcpip_bridge_transmission_write_accepted_us_max{0};
                std::atomic<uint64_t> tcpip_bridge_transmission_read_calls{0};
                std::atomic<uint64_t> tcpip_bridge_transmission_read_bytes{0};
                std::atomic<uint64_t> tcpip_bridge_socket_write_completed_calls{0};
                std::atomic<uint64_t> tcpip_bridge_socket_write_completed_bytes{0};
                std::atomic<uint64_t> tcpip_bridge_socket_write_us_sum{0};
                std::atomic<uint64_t> tcpip_bridge_socket_write_us_max{0};
            };

            inline Counters& GetCounters() noexcept {
                static Counters counters;
                return counters;
            }

            inline void AddMax(std::atomic<uint64_t>& maximum, uint64_t value) noexcept {
                uint64_t observed = maximum.load(std::memory_order_relaxed);
                while (observed < value && !maximum.compare_exchange_weak(observed, value,
                    std::memory_order_relaxed, std::memory_order_relaxed)) {}
            }

            inline uint64_t ElapsedMicroseconds(const std::chrono::steady_clock::time_point& start) noexcept {
                return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - start).count());
            }

            inline uint64_t ElapsedMicroseconds(const std::chrono::steady_clock::time_point& start,
                const std::chrono::steady_clock::time_point& end) noexcept {
                return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
            }

            inline uint64_t Exchange(std::atomic<uint64_t>& value) noexcept {
                return value.exchange(0, std::memory_order_relaxed);
            }

            inline void RecordFrameStage(FrameStageCounters& stage, int bytes, uint64_t elapsed_us) noexcept {
                stage.calls.fetch_add(1, std::memory_order_relaxed);
                stage.bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                stage.us_sum.fetch_add(elapsed_us, std::memory_order_relaxed);
                AddMax(stage.us_max, elapsed_us);
            }

            inline void WriteFrameStage(std::ostream& output, const char* name, FrameStageCounters& stage) noexcept {
                output << "\"" << name << "\":{\"calls\":" << Exchange(stage.calls)
                    << ",\"bytes\":" << Exchange(stage.bytes)
                    << ",\"us_sum\":" << Exchange(stage.us_sum)
                    << ",\"us_max\":" << Exchange(stage.us_max) << "}";
            }

            template <size_t N>
            inline void WriteHistogram(std::ostream& output, const std::array<const char*, N>& labels,
                std::array<std::atomic<uint64_t>, N>& buckets) noexcept {
                output << "[";
                for (size_t i = 0; i < N; ++i) {
                    if (i != 0) output << ",";
                    output << "{\"label\":\"" << labels[i] << "\",\"count\":" << Exchange(buckets[i]) << "}";
                }
                output << "]";
            }

            inline void WriteMtaHandoffPaths(std::ostream& output,
                std::array<MtaHandoffPathCounters, kMtaHandoffPathCount>& paths) noexcept {
                output << "{";
                for (size_t i = 0; i < kMtaHandoffPathCount; ++i) {
                    if (i != 0) output << ",";
                    MtaHandoffPathCounters& path = paths[i];
                    output << "\"" << kMtaHandoffPathLabels[i] << "\":{\"posted\":" << Exchange(path.posted)
                        << ",\"dispatched\":" << Exchange(path.dispatched)
                        << ",\"bytes\":" << Exchange(path.bytes)
                        << ",\"queue_us_sum\":" << Exchange(path.queue_us_sum)
                        << ",\"queue_us_max\":" << Exchange(path.queue_us_max) << "}";
                }
                output << "}";
            }

            inline MtaHandoffProducerSlots& GetMtaHandoffProducerSlots() noexcept {
                static MtaHandoffProducerSlots slots;
                return slots;
            }

            inline void RecordMtaHandoffSegment(MtaHandoffSegmentCounters& counters, uint64_t elapsed_us) noexcept {
                counters.calls.fetch_add(1, std::memory_order_relaxed);
                counters.us_sum.fetch_add(elapsed_us, std::memory_order_relaxed);
                AddMax(counters.us_max, elapsed_us);
            }

            inline void WriteMtaHandoffSegments(std::ostream& output,
                std::array<MtaHandoffSegmentCounters, kMtaHandoffSegmentCount>& segments) noexcept {
                output << "{";
                for (size_t i = 0; i < kMtaHandoffSegmentCount; ++i) {
                    if (i != 0) output << ",";
                    MtaHandoffSegmentCounters& segment = segments[i];
                    output << "\"" << kMtaHandoffSegmentLabels[i] << "\":{\"calls\":" << Exchange(segment.calls)
                        << ",\"us_sum\":" << Exchange(segment.us_sum)
                        << ",\"us_max\":" << Exchange(segment.us_max) << "}";
                }
                output << "}";
            }

            inline void WriteMtaHandoffProducerSlot(std::ostream& output, const MtaHandoffProducerSlotCounters& slot,
                bool include_producer_tid) noexcept {
                if (include_producer_tid) {
                    output << "\"producer_tid\":" << slot.producer_thread_id << ",";
                }
                output << "\"packets\":" << slot.packets << ",\"bytes\":" << slot.bytes << ",\"segments\":{";
                for (size_t i = 0; i < kMtaHandoffSegmentCount; ++i) {
                    if (i != 0) output << ",";
                    output << "\"" << kMtaHandoffSegmentLabels[i] << "\":{\"calls\":" << slot.packets
                        << ",\"us_sum\":" << slot.us_sum[i] << ",\"us_max\":" << slot.us_max[i] << "}";
                }
                output << "}";
            }

            inline void WriteMtaHandoffProducerSlots(std::ostream& output) noexcept {
                MtaHandoffProducerSlots& producer_slots = GetMtaHandoffProducerSlots();
                std::lock_guard<std::mutex> lock(producer_slots.mutex);
                output << "[";
                bool first = true;
                for (size_t i = 0; i < kMtaHandoffProducerSlotCount; ++i) {
                    MtaHandoffProducerSlotCounters& slot = producer_slots.slots[i];
                    if (slot.producer_thread_id == 0) continue;
                    if (!first) output << ",";
                    first = false;
                    output << "{\"slot\":" << i << ",";
                    WriteMtaHandoffProducerSlot(output, slot, true);
                    output << "}";
                    slot.packets = 0;
                    slot.bytes = 0;
                    slot.us_sum.fill(0);
                    slot.us_max.fill(0);
                }
                if (producer_slots.other.packets != 0) {
                    if (!first) output << ",";
                    output << "{\"slot\":\"other\",";
                    WriteMtaHandoffProducerSlot(output, producer_slots.other, false);
                    output << "}";
                    producer_slots.other = MtaHandoffProducerSlotCounters{};
                }
                output << "]";
            }

            inline size_t TunDirectWriteLatencyBucket(uint64_t elapsed_us) noexcept {
                if (elapsed_us < 4) return 0;
                if (elapsed_us < 8) return 1;
                if (elapsed_us < 16) return 2;
                if (elapsed_us < 32) return 3;
                if (elapsed_us < 64) return 4;
                if (elapsed_us < 128) return 5;
                if (elapsed_us < 256) return 6;
                return elapsed_us <= 1000 ? 7 : 8;
            }

            inline size_t TunDirectWriteSizeBucket(int bytes) noexcept {
                if (bytes <= 128) return 0;
                if (bytes <= 256) return 1;
                if (bytes <= 512) return 2;
                if (bytes <= 1024) return 3;
                if (bytes <= 1400) return 4;
                return bytes <= 1500 ? 5 : 6;
            }

            /** @brief Atomically snapshots/reset interval counters into one JSONL record. */
            inline void WriteSnapshot() noexcept {
                static std::mutex mutex;
                static std::chrono::steady_clock::time_point next = std::chrono::steady_clock::now() + std::chrono::seconds(1);
                static std::sig_atomic_t emitted_boundary = 0;
                const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
                const std::sig_atomic_t requested_boundary = MeasurementBoundaryRequest();
                if (requested_boundary == emitted_boundary && now < next) {
                    return;
                }

                std::lock_guard<std::mutex> lock(mutex);
                const std::sig_atomic_t boundary = MeasurementBoundaryRequest();
                const bool forced = boundary != emitted_boundary;
                if (!forced && now < next) {
                    return;
                }
                if (forced) {
                    emitted_boundary = boundary;
                }
                next = now + std::chrono::seconds(1);

                Counters& c = GetCounters();
                std::ofstream output(GetRuntimeConfig().path, std::ios::out | std::ios::app);
                if (!output) {
                    return;
                }
                const uint64_t timestamp_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
                output << "{\"timestamp_ms\":" << timestamp_ms;
                if (tun_output_render != nullptr) {
                    tun_output_render(output);
                }
                if (const char* boundary_name = MeasurementBoundaryName(forced ? boundary : 0)) {
                    output << ",\"measurement_boundary\":\"" << boundary_name << "\"";
                    if (mergeability_render != nullptr) {
                        mergeability_render(output, boundary_name);
                    }
                    if (gso_ledger_render != nullptr) {
                        gso_ledger_render(output, boundary_name);
                    }
                }
                output
                    << ",\"tun\":{\"read_calls\":" << Exchange(c.tun_read_calls)
                    << ",\"read_bytes\":" << Exchange(c.tun_read_bytes)
                    << ",\"write_enqueued\":" << Exchange(c.tun_write_enqueued)
                    << ",\"write_enqueued_bytes\":" << Exchange(c.tun_write_enqueued_bytes)
                    << ",\"write_completed\":" << Exchange(c.tun_write_completed)
                    << ",\"write_bytes\":" << Exchange(c.tun_write_bytes)
                    << ",\"write_us_sum\":" << Exchange(c.tun_write_us_sum)
                    << ",\"write_us_max\":" << Exchange(c.tun_write_us_max)
                    << ",\"direct_write_attempted\":" << Exchange(c.tun_direct_write_attempted)
                    << ",\"direct_write_attempted_bytes\":" << Exchange(c.tun_direct_write_attempted_bytes)
                    << ",\"direct_write_completed\":" << Exchange(c.tun_direct_write_completed)
                    << ",\"direct_write_bytes\":" << Exchange(c.tun_direct_write_bytes)
                    << ",\"direct_write_failed\":" << Exchange(c.tun_direct_write_failed)
                    << ",\"direct_write_partial\":" << Exchange(c.tun_direct_write_partial)
                    << ",\"direct_write_us_sum\":" << Exchange(c.tun_direct_write_us_sum)
                    << ",\"direct_write_us_max\":" << Exchange(c.tun_direct_write_us_max)
                    << ",\"direct_write_over_100us\":" << Exchange(c.tun_direct_write_over_100us)
                    << ",\"direct_write_inflight\":" << c.tun_direct_write_inflight.load(std::memory_order_relaxed)
                    << ",\"direct_write_inflight_max\":" << Exchange(c.tun_direct_write_inflight_max)
                    << ",\"direct_write_entry_inflight_0\":" << Exchange(c.tun_direct_write_entry_inflight_0)
                    << ",\"direct_write_entry_inflight_1\":" << Exchange(c.tun_direct_write_entry_inflight_1)
                    << ",\"direct_write_entry_inflight_2\":" << Exchange(c.tun_direct_write_entry_inflight_2)
                    << ",\"direct_write_entry_inflight_3plus\":" << Exchange(c.tun_direct_write_entry_inflight_3plus)
                    << ",\"direct_write_latency_buckets\":";
                WriteHistogram(output, kTunDirectWriteLatencyBucketLabels, c.tun_direct_write_latency_buckets);
                output << ",\"direct_write_size_buckets\":";
                WriteHistogram(output, kTunDirectWriteSizeBucketLabels, c.tun_direct_write_size_buckets);
                output << "}"
                    << ",\"vnet\":{\"input_calls\":" << Exchange(c.vnet_input_calls)
                    << ",\"input_bytes\":" << Exchange(c.vnet_input_bytes)
                    << ",\"input_us_sum\":" << Exchange(c.vnet_input_us_sum)
                    << ",\"input_us_max\":" << Exchange(c.vnet_input_us_max)
                    << ",\"output_calls\":" << Exchange(c.vnet_output_calls)
                    << ",\"output_bytes\":" << Exchange(c.vnet_output_bytes)
                    << ",\"output_us_sum\":" << Exchange(c.vnet_output_us_sum)
                    << ",\"output_us_max\":" << Exchange(c.vnet_output_us_max)
                    << ",\"output_direct\":" << Exchange(c.vnet_output_direct)
                    << ",\"output_cached\":" << Exchange(c.vnet_output_cached)
                    << ",\"mta_packet_posted\":" << Exchange(c.vnet_mta_packet_posted)
                    << ",\"mta_packet_dispatched\":" << Exchange(c.vnet_mta_packet_dispatched)
                    << ",\"mta_packet_queue_us_sum\":" << Exchange(c.vnet_mta_packet_queue_us_sum)
                    << ",\"mta_packet_queue_us_max\":" << Exchange(c.vnet_mta_packet_queue_us_max)
                    << ",\"mta_handoff_paths\":";
                WriteMtaHandoffPaths(output, c.vnet_mta_handoff_paths);
                output << ",\"mta_handoff_segments\":";
                WriteMtaHandoffSegments(output, c.vnet_mta_handoff_segments);
                output << ",\"mta_handoff_producer_slots\":";
                WriteMtaHandoffProducerSlots(output);
                output << "}"
                    << ",\"frame\":{\"encode_calls\":" << Exchange(c.frame_encode_calls)
                    << ",\"plain_bytes\":" << Exchange(c.frame_plain_bytes)
                    << ",\"cipher_bytes\":" << Exchange(c.frame_cipher_bytes)
                    << ",\"encode_us_sum\":" << Exchange(c.frame_encode_us_sum)
                    << ",\"encode_us_max\":" << Exchange(c.frame_encode_us_max)
                    << ",\"decode_calls\":" << Exchange(c.frame_decode_calls)
                    << ",\"decode_plain_bytes\":" << Exchange(c.frame_decode_plain_bytes)
                    << ",\"decode_us_sum\":" << Exchange(c.frame_decode_us_sum)
                    << ",\"decode_us_max\":" << Exchange(c.frame_decode_us_max) << "}"
                    << ",\"frame_stages\":{";
                WriteFrameStage(output, "transport_encrypt", c.frame_transport_encrypt);
                output << ",";
                WriteFrameStage(output, "header_encrypt", c.frame_header_encrypt);
                output << ",";
                WriteFrameStage(output, "payload_encrypt", c.frame_payload_encrypt);
                output << ",";
                WriteFrameStage(output, "pack", c.frame_pack);
                output << ",";
                WriteFrameStage(output, "header_decrypt", c.frame_header_decrypt);
                output << ",";
                WriteFrameStage(output, "payload_decrypt", c.frame_payload_decrypt);
                output << ",";
                WriteFrameStage(output, "transport_decrypt", c.frame_transport_decrypt);
                output << "}";
                output << ",\"nat_to_tun\":{\"calls\":" << Exchange(c.nat_to_tun_calls)
                    << ",\"bytes\":" << Exchange(c.nat_to_tun_bytes) << "}"
                    << ",\"carrier\":{\"send_calls\":" << Exchange(c.carrier_send_calls)
                    << ",\"send_bytes\":" << Exchange(c.carrier_send_bytes)
                    << ",\"send_us_sum\":" << Exchange(c.carrier_send_us_sum)
                    << ",\"send_us_max\":" << Exchange(c.carrier_send_us_max)
                    << ",\"recv_calls\":" << Exchange(c.carrier_recv_calls)
                    << ",\"recv_bytes\":" << Exchange(c.carrier_recv_bytes)
                    << ",\"recv_us_sum\":" << Exchange(c.carrier_recv_us_sum)
                    << ",\"recv_us_max\":" << Exchange(c.carrier_recv_us_max)
                    << ",\"queue_items\":" << Exchange(c.carrier_queue_items)
                    << ",\"queue_bytes\":" << Exchange(c.carrier_queue_bytes)
                    << ",\"queue_items_high\":" << c.carrier_queue_items_high.load(std::memory_order_relaxed)
                    << ",\"queue_bytes_high\":" << c.carrier_queue_bytes_high.load(std::memory_order_relaxed) << "}"
                    << ",\"vmux\":{\"accepted_calls\":" << Exchange(c.vmux_accepted_calls)
                    << ",\"accepted_bytes\":" << Exchange(c.vmux_accepted_bytes)
                    << ",\"socket_write_completed_calls\":" << Exchange(c.vmux_socket_write_completed_calls)
                    << ",\"socket_write_completed_bytes\":" << Exchange(c.vmux_socket_write_completed_bytes)
                    << ",\"socket_write_us_sum\":" << Exchange(c.vmux_socket_write_us_sum)
                    << ",\"socket_write_us_max\":" << Exchange(c.vmux_socket_write_us_max) << "}"
                    << ",\"tcpip_bridge\":{\"socket_read_calls\":" << Exchange(c.tcpip_bridge_socket_read_calls)
                    << ",\"socket_read_bytes\":" << Exchange(c.tcpip_bridge_socket_read_bytes)
                    << ",\"transmission_write_accepted_calls\":" << Exchange(c.tcpip_bridge_transmission_write_accepted_calls)
                    << ",\"transmission_write_accepted_bytes\":" << Exchange(c.tcpip_bridge_transmission_write_accepted_bytes)
                    << ",\"transmission_write_accepted_us_sum\":" << Exchange(c.tcpip_bridge_transmission_write_accepted_us_sum)
                    << ",\"transmission_write_accepted_us_max\":" << Exchange(c.tcpip_bridge_transmission_write_accepted_us_max)
                    << ",\"transmission_read_calls\":" << Exchange(c.tcpip_bridge_transmission_read_calls)
                    << ",\"transmission_read_bytes\":" << Exchange(c.tcpip_bridge_transmission_read_bytes)
                    << ",\"socket_write_completed_calls\":" << Exchange(c.tcpip_bridge_socket_write_completed_calls)
                    << ",\"socket_write_completed_bytes\":" << Exchange(c.tcpip_bridge_socket_write_completed_bytes)
                    << ",\"socket_write_us_sum\":" << Exchange(c.tcpip_bridge_socket_write_us_sum)
                    << ",\"socket_write_us_max\":" << Exchange(c.tcpip_bridge_socket_write_us_max) << "}}\n";
            }

            inline void RecordTunRead(int bytes) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.tun_read_calls.fetch_add(1, std::memory_order_relaxed);
                c.tun_read_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                WriteSnapshot();
            }
            inline void RecordTunWriteEnqueued(int bytes) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.tun_write_enqueued.fetch_add(1, std::memory_order_relaxed);
                c.tun_write_enqueued_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                WriteSnapshot();
            }
            inline void RecordTunWriteCompleted(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.tun_write_completed.fetch_add(1, std::memory_order_relaxed);
                c.tun_write_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                c.tun_write_us_sum.fetch_add(elapsed_us, std::memory_order_relaxed);
                AddMax(c.tun_write_us_max, elapsed_us);
                WriteSnapshot();
            }
            /** @brief Starts laboratory-only accounting around one Linux synchronous TUN write. */
            inline bool BeginTunDirectWrite() noexcept {
                if (!IsEnabled()) return false;
                Counters& c = GetCounters();
                const uint64_t already_inflight = c.tun_direct_write_inflight.fetch_add(1, std::memory_order_relaxed);
                AddMax(c.tun_direct_write_inflight_max, already_inflight + 1);
                if (already_inflight == 0) {
                    c.tun_direct_write_entry_inflight_0.fetch_add(1, std::memory_order_relaxed);
                }
                else if (already_inflight == 1) {
                    c.tun_direct_write_entry_inflight_1.fetch_add(1, std::memory_order_relaxed);
                }
                else if (already_inflight == 2) {
                    c.tun_direct_write_entry_inflight_2.fetch_add(1, std::memory_order_relaxed);
                }
                else {
                    c.tun_direct_write_entry_inflight_3plus.fetch_add(1, std::memory_order_relaxed);
                }
                return true;
            }

            /** @brief Ends laboratory-only accounting before JSON recording overhead. */
            inline void EndTunDirectWrite(bool active) noexcept {
                if (active) {
                    GetCounters().tun_direct_write_inflight.fetch_sub(1, std::memory_order_relaxed);
                }
            }

            /** @brief Records the Linux synchronous direct TUN write path. */
            inline void RecordTunDirectWrite(int attempted_bytes, int completed_bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.tun_direct_write_attempted.fetch_add(1, std::memory_order_relaxed);
                c.tun_direct_write_attempted_bytes.fetch_add(static_cast<uint64_t>(attempted_bytes), std::memory_order_relaxed);
                c.tun_direct_write_us_sum.fetch_add(elapsed_us, std::memory_order_relaxed);
                AddMax(c.tun_direct_write_us_max, elapsed_us);
                c.tun_direct_write_latency_buckets[TunDirectWriteLatencyBucket(elapsed_us)].fetch_add(1, std::memory_order_relaxed);
                if (elapsed_us > 100) {
                    c.tun_direct_write_over_100us.fetch_add(1, std::memory_order_relaxed);
                }
                if (completed_bytes == attempted_bytes) {
                    c.tun_direct_write_completed.fetch_add(1, std::memory_order_relaxed);
                    c.tun_direct_write_bytes.fetch_add(static_cast<uint64_t>(completed_bytes), std::memory_order_relaxed);
                    c.tun_direct_write_size_buckets[TunDirectWriteSizeBucket(completed_bytes)].fetch_add(1, std::memory_order_relaxed);
                }
                else if (completed_bytes < 0) {
                    c.tun_direct_write_failed.fetch_add(1, std::memory_order_relaxed);
                }
                else {
                    c.tun_direct_write_partial.fetch_add(1, std::memory_order_relaxed);
                }
                WriteSnapshot();
            }
            inline void RecordVnetInput(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.vnet_input_calls.fetch_add(1, std::memory_order_relaxed);
                c.vnet_input_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                c.vnet_input_us_sum.fetch_add(elapsed_us, std::memory_order_relaxed);
                AddMax(c.vnet_input_us_max, elapsed_us);
                WriteSnapshot();
            }
            inline void RecordVnetOutput(int bytes, uint64_t elapsed_us, bool direct) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.vnet_output_calls.fetch_add(1, std::memory_order_relaxed);
                c.vnet_output_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                c.vnet_output_us_sum.fetch_add(elapsed_us, std::memory_order_relaxed);
                AddMax(c.vnet_output_us_max, elapsed_us);
                (direct ? c.vnet_output_direct : c.vnet_output_cached).fetch_add(1, std::memory_order_relaxed);
                WriteSnapshot();
            }
            /** @brief Captures lab-only H0 identities and H3 timestamps without exporting identities. */
            inline MtaHandoffObservation CaptureVnetMtaHandoff(bool enabled, uint64_t producer_thread_id,
                const void* producer_context, const void* target_context, int bytes,
                const std::chrono::steady_clock::time_point& t0,
                const std::chrono::steady_clock::time_point& t1) noexcept {
                MtaHandoffObservation observation;
                observation.enabled = enabled;
                if (enabled) {
                    observation.producer_thread_id = producer_thread_id;
                    observation.producer_context_token = reinterpret_cast<uintptr_t>(producer_context);
                    observation.target_context_token = reinterpret_cast<uintptr_t>(target_context);
                    observation.bytes = bytes < 0 ? 0 : bytes;
                    observation.t0 = t0;
                    observation.t1 = t1;
                }
                return observation;
            }

            /** @brief Records an MTA post at the producer so live queue depth keeps H0 semantics. */
            inline void RecordVnetMtaPacketPosted() noexcept {
                if (!IsEnabled()) return;
                GetCounters().vnet_mta_packet_posted.fetch_add(1, std::memory_order_relaxed);
            }

            /** @brief Records H0 classification and all H3 segments after handler completion. */
            inline void RecordVnetMtaHandoffCompleted(const MtaHandoffObservation& observation,
                uint64_t handler_thread_id, const std::array<uint64_t, kMtaHandoffSegmentCount>& elapsed_us) noexcept {
                if (!observation.enabled) return;

                Counters& c = GetCounters();
                c.vnet_mta_packet_dispatched.fetch_add(1, std::memory_order_relaxed);
                c.vnet_mta_packet_queue_us_sum.fetch_add(elapsed_us[2], std::memory_order_relaxed);
                AddMax(c.vnet_mta_packet_queue_us_max, elapsed_us[2]);
                for (size_t i = 0; i < kMtaHandoffSegmentCount; ++i) {
                    RecordMtaHandoffSegment(c.vnet_mta_handoff_segments[i], elapsed_us[i]);
                }

                MtaHandoffPath path = MtaHandoffPath::Unknown;
                if (observation.producer_thread_id == handler_thread_id) {
                    path = MtaHandoffPath::SameThread;
                }
                else if (observation.producer_context_token != 0 && observation.target_context_token != 0) {
                    path = observation.producer_context_token == observation.target_context_token
                        ? MtaHandoffPath::SameExecutorDifferentThread
                        : MtaHandoffPath::CrossExecutor;
                }

                MtaHandoffPathCounters& path_counters = c.vnet_mta_handoff_paths[static_cast<size_t>(path)];
                path_counters.posted.fetch_add(1, std::memory_order_relaxed);
                path_counters.dispatched.fetch_add(1, std::memory_order_relaxed);
                path_counters.bytes.fetch_add(static_cast<uint64_t>(observation.bytes), std::memory_order_relaxed);
                path_counters.queue_us_sum.fetch_add(elapsed_us[2], std::memory_order_relaxed);
                AddMax(path_counters.queue_us_max, elapsed_us[2]);

                MtaHandoffProducerSlots& producer_slots = GetMtaHandoffProducerSlots();
                {
                    std::lock_guard<std::mutex> lock(producer_slots.mutex);
                    MtaHandoffProducerSlotCounters* slot = &producer_slots.other;
                    for (MtaHandoffProducerSlotCounters& candidate : producer_slots.slots) {
                        if (candidate.producer_thread_id == observation.producer_thread_id) {
                            slot = &candidate;
                            break;
                        }
                        if (candidate.producer_thread_id == 0 && slot == &producer_slots.other) {
                            candidate.producer_thread_id = observation.producer_thread_id;
                            slot = &candidate;
                        }
                    }
                    slot->packets += 1;
                    slot->bytes += static_cast<uint64_t>(observation.bytes);
                    for (size_t i = 0; i < kMtaHandoffSegmentCount; ++i) {
                        slot->us_sum[i] += elapsed_us[i];
                        slot->us_max[i] = std::max(slot->us_max[i], elapsed_us[i]);
                    }
                }
                WriteSnapshot();
            }

            inline void ResetMtaHandoffTelemetryForTesting() noexcept {
                Counters& c = GetCounters();
                c.vnet_mta_packet_posted.store(0, std::memory_order_relaxed);
                c.vnet_mta_packet_dispatched.store(0, std::memory_order_relaxed);
                c.vnet_mta_packet_queue_us_sum.store(0, std::memory_order_relaxed);
                c.vnet_mta_packet_queue_us_max.store(0, std::memory_order_relaxed);
                for (MtaHandoffPathCounters& path : c.vnet_mta_handoff_paths) {
                    path.posted.store(0, std::memory_order_relaxed);
                    path.dispatched.store(0, std::memory_order_relaxed);
                    path.bytes.store(0, std::memory_order_relaxed);
                    path.queue_us_sum.store(0, std::memory_order_relaxed);
                    path.queue_us_max.store(0, std::memory_order_relaxed);
                }
                for (MtaHandoffSegmentCounters& segment : c.vnet_mta_handoff_segments) {
                    segment.calls.store(0, std::memory_order_relaxed);
                    segment.us_sum.store(0, std::memory_order_relaxed);
                    segment.us_max.store(0, std::memory_order_relaxed);
                }
                MtaHandoffProducerSlots& producer_slots = GetMtaHandoffProducerSlots();
                std::lock_guard<std::mutex> lock(producer_slots.mutex);
                producer_slots.slots = {};
                producer_slots.other = {};
            }
            inline void RecordFrameEncode(int plain_bytes, int cipher_bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.frame_encode_calls.fetch_add(1, std::memory_order_relaxed);
                c.frame_plain_bytes.fetch_add(static_cast<uint64_t>(plain_bytes), std::memory_order_relaxed);
                c.frame_cipher_bytes.fetch_add(static_cast<uint64_t>(cipher_bytes), std::memory_order_relaxed);
                c.frame_encode_us_sum.fetch_add(elapsed_us, std::memory_order_relaxed);
                AddMax(c.frame_encode_us_max, elapsed_us);
                WriteSnapshot();
            }
            inline void RecordFrameDecode(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.frame_decode_calls.fetch_add(1, std::memory_order_relaxed);
                c.frame_decode_plain_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                c.frame_decode_us_sum.fetch_add(elapsed_us, std::memory_order_relaxed);
                AddMax(c.frame_decode_us_max, elapsed_us);
                WriteSnapshot();
            }
            inline void RecordFrameTransportEncrypt(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                RecordFrameStage(GetCounters().frame_transport_encrypt, bytes, elapsed_us);
                WriteSnapshot();
            }
            inline void RecordFrameHeaderEncrypt(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                RecordFrameStage(GetCounters().frame_header_encrypt, bytes, elapsed_us);
                WriteSnapshot();
            }
            inline void RecordFramePayloadEncrypt(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                RecordFrameStage(GetCounters().frame_payload_encrypt, bytes, elapsed_us);
                WriteSnapshot();
            }
            inline void RecordFramePack(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                RecordFrameStage(GetCounters().frame_pack, bytes, elapsed_us);
                WriteSnapshot();
            }
            inline void RecordFrameHeaderDecrypt(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                RecordFrameStage(GetCounters().frame_header_decrypt, bytes, elapsed_us);
                WriteSnapshot();
            }
            inline void RecordFramePayloadDecrypt(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                RecordFrameStage(GetCounters().frame_payload_decrypt, bytes, elapsed_us);
                WriteSnapshot();
            }
            inline void RecordFrameTransportDecrypt(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                RecordFrameStage(GetCounters().frame_transport_decrypt, bytes, elapsed_us);
                WriteSnapshot();
            }
            inline void RecordNatToTun(int bytes) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.nat_to_tun_calls.fetch_add(1, std::memory_order_relaxed);
                c.nat_to_tun_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                WriteSnapshot();
            }
            inline void RecordCarrierSend(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.carrier_send_calls.fetch_add(1, std::memory_order_relaxed);
                c.carrier_send_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                c.carrier_send_us_sum.fetch_add(elapsed_us, std::memory_order_relaxed);
                AddMax(c.carrier_send_us_max, elapsed_us);
                WriteSnapshot();
            }
            inline void RecordCarrierReceive(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.carrier_recv_calls.fetch_add(1, std::memory_order_relaxed);
                c.carrier_recv_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                c.carrier_recv_us_sum.fetch_add(elapsed_us, std::memory_order_relaxed);
                AddMax(c.carrier_recv_us_max, elapsed_us);
                WriteSnapshot();
            }
            inline void RecordVmuxAccepted(int bytes) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.vmux_accepted_calls.fetch_add(1, std::memory_order_relaxed);
                c.vmux_accepted_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                WriteSnapshot();
            }
            inline void RecordVmuxSocketWriteCompleted(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.vmux_socket_write_completed_calls.fetch_add(1, std::memory_order_relaxed);
                c.vmux_socket_write_completed_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                c.vmux_socket_write_us_sum.fetch_add(elapsed_us, std::memory_order_relaxed);
                AddMax(c.vmux_socket_write_us_max, elapsed_us);
                WriteSnapshot();
            }
            inline void RecordTcpipBridgeSocketRead(int bytes) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.tcpip_bridge_socket_read_calls.fetch_add(1, std::memory_order_relaxed);
                c.tcpip_bridge_socket_read_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                WriteSnapshot();
            }
            inline void RecordTcpipBridgeTransmissionWriteAccepted(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.tcpip_bridge_transmission_write_accepted_calls.fetch_add(1, std::memory_order_relaxed);
                c.tcpip_bridge_transmission_write_accepted_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                c.tcpip_bridge_transmission_write_accepted_us_sum.fetch_add(elapsed_us, std::memory_order_relaxed);
                AddMax(c.tcpip_bridge_transmission_write_accepted_us_max, elapsed_us);
                WriteSnapshot();
            }
            inline void RecordTcpipBridgeTransmissionRead(int bytes) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.tcpip_bridge_transmission_read_calls.fetch_add(1, std::memory_order_relaxed);
                c.tcpip_bridge_transmission_read_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                WriteSnapshot();
            }
            inline void RecordTcpipBridgeSocketWriteCompleted(int bytes, uint64_t elapsed_us) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                c.tcpip_bridge_socket_write_completed_calls.fetch_add(1, std::memory_order_relaxed);
                c.tcpip_bridge_socket_write_completed_bytes.fetch_add(static_cast<uint64_t>(bytes), std::memory_order_relaxed);
                c.tcpip_bridge_socket_write_us_sum.fetch_add(elapsed_us, std::memory_order_relaxed);
                AddMax(c.tcpip_bridge_socket_write_us_max, elapsed_us);
                WriteSnapshot();
            }
            inline void ObserveCarrierQueue(int items, int bytes) noexcept {
                if (!IsEnabled()) return;
                Counters& c = GetCounters();
                const uint64_t item_count = static_cast<uint64_t>(items < 0 ? 0 : items);
                const uint64_t byte_count = static_cast<uint64_t>(bytes < 0 ? 0 : bytes);
                c.carrier_queue_items.store(item_count, std::memory_order_relaxed);
                c.carrier_queue_bytes.store(byte_count, std::memory_order_relaxed);
                AddMax(c.carrier_queue_items_high, item_count);
                AddMax(c.carrier_queue_bytes_high, byte_count);
                WriteSnapshot();
            }

            /** @brief Scope timer with no clock access when the runtime variable is absent. */
            class Scope final {
            public:
                Scope() noexcept : enabled_(IsEnabled()) {
                    if (enabled_) start_ = std::chrono::steady_clock::now();
                }
                uint64_t Elapsed() const noexcept {
                    return enabled_ ? ElapsedMicroseconds(start_) : 0;
                }
            private:
                bool enabled_;
                std::chrono::steady_clock::time_point start_;
            };

            /** @brief RAII whole-function VNet timing; records on every return path. */
            class VnetInputScope final {
            public:
                explicit VnetInputScope(int bytes) noexcept : bytes_(bytes < 0 ? 0 : bytes) {}
                ~VnetInputScope() noexcept { RecordVnetInput(bytes_, scope_.Elapsed()); }
            private:
                int bytes_;
                Scope scope_;
            };

            /** @brief RAII whole-function VNet timing; direct means immediate TAP output. */
            class VnetOutputScope final {
            public:
                explicit VnetOutputScope(bool direct, int bytes = 0) noexcept
                    : bytes_(bytes < 0 ? 0 : bytes), direct_(direct) {}
                void SetBytes(int bytes) noexcept { bytes_ = bytes < 0 ? 0 : bytes; }
                ~VnetOutputScope() noexcept { RecordVnetOutput(bytes_, scope_.Elapsed(), direct_); }
            private:
                int bytes_ = 0;
                bool direct_;
                Scope scope_;
            };
        }
    }
}
