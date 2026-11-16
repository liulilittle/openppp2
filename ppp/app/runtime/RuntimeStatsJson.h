#pragma once

#include <ppp/app/runtime/DatapathAcceptanceBoundary.h>
#include <ppp/app/runtime/RuntimeSnapshotJson.h>
#include <ppp/app/runtime/RuntimeXtcpStats.h>
#include <ppp/tap/TapRuntimeStats.h>

#include <json/json.h>

#include <cstdint>
#include <string>

namespace ppp {
    namespace app {
        namespace runtime {

            struct RuntimeLinkStats final {
                double quality_percent = 100.0;
                std::string grade = "Unknown";
                std::uint64_t error_count = 0;
                std::uint64_t success_count = 0;
            };

            struct RuntimeStatsSample final {
                static constexpr std::uint32_t SchemaVersion = 1;

                std::uint64_t monotonic_ms = 0;
                std::uint64_t rx_bytes = 0;
                std::uint64_t tx_bytes = 0;
                RuntimeLinkStats link;
                RuntimeSnapshot runtime;
                std::string requested_tcp_stack;
                std::string active_tcp_stack;
                bool has_tap_linux = false;
                ppp::tap::TapRuntimeStats tap_linux;
                bool has_xtcp = false;
                RuntimeXtcpStats xtcp;
                bool has_acceptance_boundary = false;
                DatapathAcceptanceBoundaryRecord acceptance_boundary;
            };

            inline std::string SerializeRuntimeStats(
                const RuntimeStatsSample& sample) noexcept {
                Json::Value root(Json::objectValue);
                root["type"] = "ppp-stats";
#if defined(PPP_COROUTINE_BACKEND_COROCC)
                root["coroutine_backend"] = "corocc";
#endif
                root["version"] = RuntimeStatsSample::SchemaVersion;
                root["monotonic_ms"] = Json::UInt64(sample.monotonic_ms);
                root["rx_bytes"] = Json::UInt64(sample.rx_bytes);
                root["tx_bytes"] = Json::UInt64(sample.tx_bytes);

                Json::Value link(Json::objectValue);
                link["quality_percent"] = sample.link.quality_percent;
                link["grade"] = detail::ToRuntimeJsonString(sample.link.grade);
                link["error_count"] = Json::UInt64(sample.link.error_count);
                link["success_count"] = Json::UInt64(sample.link.success_count);
                root["link"] = std::move(link);

                if (!sample.requested_tcp_stack.empty() && !sample.active_tcp_stack.empty()) {
                    Json::Value tcp_stack(Json::objectValue);
                    tcp_stack["requested"] = detail::ToRuntimeJsonString(sample.requested_tcp_stack);
                    tcp_stack["active"] = detail::ToRuntimeJsonString(sample.active_tcp_stack);
                    root["tcp_stack"] = std::move(tcp_stack);
                }

                if (sample.has_tap_linux) {
                    Json::Value tap_linux(Json::objectValue);
                    tap_linux["writev_calls"] = Json::UInt64(sample.tap_linux.writev_calls);
                    tap_linux["writev_bytes"] = Json::UInt64(sample.tap_linux.writev_bytes);
                    tap_linux["writev_segments"] = Json::UInt64(sample.tap_linux.writev_segments);
                    tap_linux["writev_max_bytes"] = Json::UInt64(sample.tap_linux.writev_max_bytes);
                    tap_linux["writev_max_segments"] = Json::UInt64(sample.tap_linux.writev_max_segments);
                    static const char* reasons[] = {"explicit", "cap", "timeout", "incompatible",
                        "short_tail", "psh", "control", "ssmt", "terminate"};
                    for (size_t i = 0; i < sample.tap_linux.gso_flushes.size(); ++i)
                        tap_linux["gso_flushes"][reasons[i]] = Json::UInt64(sample.tap_linux.gso_flushes[i]);
                    tap_linux["vnet_header"] = sample.tap_linux.vnet_header;
                    tap_linux["gso_merge_active"] = sample.tap_linux.gso_merge_active;
                    tap_linux["tx_gso_supported"] = sample.tap_linux.tx_gso_supported;
                    tap_linux["direct_gso_packets"] = Json::UInt64(sample.tap_linux.direct_gso_packets);
                    tap_linux["direct_gso_bytes"] = Json::UInt64(sample.tap_linux.direct_gso_bytes);
                    tap_linux["direct_gso_rejected"] = Json::UInt64(sample.tap_linux.direct_gso_rejected);
                    tap_linux["bound_output_lanes"] = Json::UInt64(sample.tap_linux.bound_output_lanes);
                    tap_linux["lane_envelope_accepted"] = Json::UInt64(sample.tap_linux.lane_envelope_accepted);
                    tap_linux["lane_envelope_full_drops"] = Json::UInt64(sample.tap_linux.lane_envelope_full_drops);
                    root["tap_linux"] = std::move(tap_linux);
                }

                if (sample.has_xtcp) {
                    Json::Value xtcp(Json::objectValue);
                    xtcp["shard_policy_requested"] = sample.xtcp.shard_policy_requested.c_str();
                    xtcp["shard_policy_reason"] = sample.xtcp.shard_policy_reason.c_str();
                    xtcp["shard_count"] = sample.xtcp.shard_count;
                    xtcp["worker_count"] = sample.xtcp.worker_count;
                    xtcp["ingress_backend"] = sample.xtcp.spsc_ingress ? "spsc-serialized-producer" : "vector";
                    xtcp["effective_cpus"] = sample.xtcp.effective_cpus;
                    xtcp["online_cpus"] = sample.xtcp.online_cpus;
                    xtcp["quota_cpus"] = sample.xtcp.quota_cpus;
                    xtcp["cpu_affinity_known"] = sample.xtcp.cpu_affinity_known;
                    xtcp["cpu_quota_known"] = sample.xtcp.cpu_quota_known;
                    xtcp["affinity_reason"] = sample.xtcp.affinity_reason.c_str();
                    xtcp["affinity_strict"] = sample.xtcp.affinity_strict;
                    xtcp["affinity_mode"] = sample.xtcp.affinity_mode.c_str();
                    xtcp["queue_mode_active"] = sample.xtcp.queue_mode_active;
                    xtcp["affinity_pinned_workers"] = sample.xtcp.affinity_pinned_workers;
                    Json::Value allowed(Json::arrayValue), workers(Json::arrayValue), shards(Json::arrayValue);
                    for (unsigned cpu : sample.xtcp.allowed_cpus) allowed.append(cpu);
                    for (unsigned cpu : sample.xtcp.worker_cpus) workers.append(cpu);
                    xtcp["allowed_cpus"] = std::move(allowed);
                    xtcp["worker_cpus"] = std::move(workers);
                    Json::Value bindings(Json::arrayValue);
                    for (unsigned i = 0; i < sample.xtcp.worker_count && i < sample.xtcp.workers.size(); ++i) {
                        Json::Value binding(Json::objectValue), mask(Json::arrayValue);
                        binding["index"] = i;
                        binding["tid"] = Json::UInt64(sample.xtcp.workers[i].tid);
                        for (unsigned cpu : sample.xtcp.workers[i].effective_cpus) mask.append(cpu);
                        binding["effective_cpus"] = std::move(mask);
                        bindings.append(std::move(binding));
                    }
                    xtcp["worker_bindings"] = std::move(bindings);
                    for (unsigned i = 0; i < sample.xtcp.shard_count && i < sample.xtcp.shards.size(); ++i) {
                        const auto& shard = sample.xtcp.shards[i];
                        Json::Value entry(Json::objectValue);
                        entry["index"] = i;
                        entry["enqueued"] = Json::UInt64(shard.enqueued);
                        entry["dispatched"] = Json::UInt64(shard.dispatched);
                        entry["dropped"] = Json::UInt64(shard.dropped);
                        entry["bytes"] = Json::UInt64(shard.bytes);
                        entry["queue_items"] = Json::UInt64(shard.queue_items);
                        entry["queue_bytes"] = Json::UInt64(shard.queue_bytes);
                        entry["items_highwater"] = Json::UInt64(shard.items_highwater);
                        entry["bytes_highwater"] = Json::UInt64(shard.bytes_highwater);
                        entry["wake_posts"] = Json::UInt64(shard.wake_posts);
                        entry["wake_coalesces"] = Json::UInt64(shard.wake_coalesces);
                        entry["quanta"] = Json::UInt64(shard.quanta);
                        entry["flushes"] = Json::UInt64(shard.flushes);
                        entry["active_flows"] = Json::UInt64(shard.active_flows);
                        entry["data_flows"] = Json::UInt64(shard.data_flows);
                        entry["upload_bytes"] = Json::UInt64(shard.upload_bytes);
                        entry["download_bytes"] = Json::UInt64(shard.download_bytes);
                        shards.append(std::move(entry));
                    }
                    xtcp["shards"] = std::move(shards);
                    xtcp["runtime_generation"] = Json::UInt64(sample.xtcp.runtime_generation);
                    xtcp["runtime_instance_id"] = Json::UInt64(sample.xtcp.runtime_instance_id);
                    xtcp["direct_bridge_starts"] = Json::UInt64(sample.xtcp.direct_bridge_starts);
                    xtcp["direct_bridge_active"] = Json::UInt64(sample.xtcp.direct_bridge_active);
                    xtcp["direct_bridge_fallbacks"] = Json::UInt64(sample.xtcp.direct_bridge_fallbacks);
                    xtcp["direct_upload_accepted_chunks"] =
                        Json::UInt64(sample.xtcp.direct_upload_accepted_chunks);
                    xtcp["direct_upload_accepted_bytes"] =
                        Json::UInt64(sample.xtcp.direct_upload_accepted_bytes);
                    xtcp["direct_download_accepted_bytes"] =
                        Json::UInt64(sample.xtcp.direct_download_accepted_bytes);
                    xtcp["direct_upload_writable_callbacks"] =
                        Json::UInt64(sample.xtcp.direct_upload_writable_callbacks);
                    xtcp["direct_download_writable_callbacks"] =
                        Json::UInt64(sample.xtcp.direct_download_writable_callbacks);
                    xtcp["ingress_submitted"] = Json::UInt64(sample.xtcp.ingress_submitted);
                    xtcp["ingress_dropped"] = Json::UInt64(sample.xtcp.ingress_dropped);
                    xtcp["ingress_injected"] = Json::UInt64(sample.xtcp.ingress_injected);
                    xtcp["flows_opened"] = Json::UInt64(sample.xtcp.flows_opened);
                    xtcp["flows_closed"] = Json::UInt64(sample.xtcp.flows_closed);
                    xtcp["flows_active"] = Json::UInt64(sample.xtcp.flows_active);
                    xtcp["timer_polls"] = Json::UInt64(sample.xtcp.timer_polls);
                    xtcp["timer_events"] = Json::UInt64(sample.xtcp.timer_events);
                    xtcp["output_packets"] = Json::UInt64(sample.xtcp.output_packets);
                    xtcp["output_bytes"] = Json::UInt64(sample.xtcp.output_bytes);
                    xtcp["ndi_gso_enabled"] = sample.xtcp.ndi_gso_enabled;
                    xtcp["ndi_gso_packets"] = Json::UInt64(sample.xtcp.ndi_gso_packets);
                    xtcp["ndi_gso_bytes"] = Json::UInt64(sample.xtcp.ndi_gso_bytes);
                    xtcp["ndi_gso_rejected"] = Json::UInt64(sample.xtcp.ndi_gso_rejected);
                    xtcp["connector_read_bytes"] = Json::UInt64(sample.xtcp.connector_read_bytes);
                    xtcp["connector_written_bytes"] = Json::UInt64(sample.xtcp.connector_written_bytes);
                    xtcp["queued_bytes"] = Json::UInt64(sample.xtcp.queued_bytes);
                    xtcp["queued_bytes_highwater"] = Json::UInt64(sample.xtcp.queued_bytes_highwater);
                    xtcp["resume_requested"] = Json::UInt64(sample.xtcp.resume_requested);
                    xtcp["resume_effective"] = Json::UInt64(sample.xtcp.resume_effective);
                    xtcp["resume_result_not_blocked"] =
                        Json::UInt64(sample.xtcp.resume_result_not_blocked);
                    xtcp["resume_result_window_full"] =
                        Json::UInt64(sample.xtcp.resume_result_window_full);
                    xtcp["resume_result_connection_missing"] =
                        Json::UInt64(sample.xtcp.resume_result_connection_missing);
                    xtcp["resume_pending"] = Json::UInt64(sample.xtcp.resume_pending);
                    xtcp["resume_coalesced"] = Json::UInt64(sample.xtcp.resume_coalesced);
                    xtcp["resume_terminal"] = Json::UInt64(sample.xtcp.resume_terminal);
                    xtcp["resume_retry"] = Json::UInt64(sample.xtcp.resume_retry);
                    xtcp["resume_window_full_retry"] =
                        Json::UInt64(sample.xtcp.resume_window_full_retry);
                    xtcp["direct_download_chunks"] = Json::UInt64(sample.xtcp.direct_download_chunks);
                    xtcp["direct_download_rejected"] = Json::UInt64(sample.xtcp.direct_download_rejected);
                    xtcp["direct_upload_rejected"] = Json::UInt64(sample.xtcp.direct_upload_rejected);
                    xtcp["direct_upload_queue_bytes"] =
                        Json::UInt64(sample.xtcp.direct_upload_queue_bytes);
                    xtcp["direct_spsc_enabled"] = Json::UInt64(sample.xtcp.direct_spsc_enabled);
                    xtcp["direct_handoff_full"] = Json::UInt64(sample.xtcp.direct_handoff_full);
                    xtcp["direct_handoff_wakes"] = Json::UInt64(sample.xtcp.direct_handoff_wakes);
                    xtcp["direct_handoff_alloc_fallback"] =
                        Json::UInt64(sample.xtcp.direct_handoff_alloc_fallback);
                    xtcp["upload_budget_bytes"] = Json::UInt64(sample.xtcp.upload_budget_bytes);
                    xtcp["upload_budget_items"] = Json::UInt64(sample.xtcp.upload_budget_items);
                    xtcp["upload_budget_max_bytes"] = Json::UInt64(sample.xtcp.upload_budget_max_bytes);
                    xtcp["upload_budget_max_items"] = Json::UInt64(sample.xtcp.upload_budget_max_items);
                    xtcp["upload_budget_waiters"] =
                        Json::UInt64(sample.xtcp.upload_budget_waiters);
                    xtcp["upload_budget_wake_events"] =
                        Json::UInt64(sample.xtcp.upload_budget_wake_events);
                    xtcp["upload_budget_wake_empty"] =
                        Json::UInt64(sample.xtcp.upload_budget_wake_empty);
                    xtcp["upload_budget_fairness_switches"] =
                        Json::UInt64(sample.xtcp.upload_budget_fairness_switches);
                    xtcp["upload_budget_rejected"] = Json::UInt64(sample.xtcp.upload_budget_rejected);
                    xtcp["direct_upload_queue_items"] =
                        Json::UInt64(sample.xtcp.direct_upload_queue_items);
                    xtcp["direct_upload_backpressured"] =
                        Json::UInt64(sample.xtcp.direct_upload_backpressured);
                    xtcp["direct_upload_writer_active"] =
                        Json::UInt64(sample.xtcp.direct_upload_writer_active);
                    xtcp["direct_upload_writer_progress_age_ms"] =
                        Json::UInt64(sample.xtcp.direct_upload_writer_progress_age_ms);
                    xtcp["second_leg_close_requested"] =
                        Json::UInt64(sample.xtcp.second_leg_close_requested);
                    xtcp["second_leg_close_duplicate_suppressed"] =
                        Json::UInt64(sample.xtcp.second_leg_close_duplicate_suppressed);
                    xtcp["degraded_half_close"] = Json::UInt64(sample.xtcp.degraded_half_close);
                    xtcp["direct_download_queue_bytes"] =
                        Json::UInt64(sample.xtcp.direct_download_queue_bytes);
                    xtcp["direct_download_queue_bytes_highwater"] =
                        Json::UInt64(sample.xtcp.direct_download_queue_bytes_highwater);
                    root["xtcp"] = std::move(xtcp);
                }

                if (sample.has_acceptance_boundary) {
                    Json::Value acceptance_boundary(Json::objectValue);
                    acceptance_boundary["schema"] =
                        DatapathAcceptanceBoundaryRecord::SchemaVersion;
                    acceptance_boundary["run_uuid"] =
                        detail::ToRuntimeJsonString(sample.acceptance_boundary.run_uuid);
                    acceptance_boundary["cell_id"] =
                        detail::ToRuntimeJsonString(sample.acceptance_boundary.cell_id);
                    acceptance_boundary["sequence"] =
                        Json::UInt64(sample.acceptance_boundary.sequence);
                    acceptance_boundary["phase"] =
                        detail::ToRuntimeJsonString(sample.acceptance_boundary.phase);
                    acceptance_boundary["monotonic_ms"] =
                        Json::UInt64(sample.acceptance_boundary.monotonic_ms);
                    acceptance_boundary["process_pid"] =
                        Json::UInt64(sample.acceptance_boundary.process_pid);
                    acceptance_boundary["process_start_ticks"] =
                        Json::UInt64(sample.acceptance_boundary.process_start_ticks);
                    acceptance_boundary["xtcp_runtime_instance_id"] =
                        Json::UInt64(sample.acceptance_boundary.xtcp_runtime_instance_id);
                    root["acceptance_boundary"] = std::move(acceptance_boundary);
                }

                Json::Reader reader;
                Json::Value runtime(Json::objectValue);
                const std::string runtime_json = SerializeRuntimeSnapshot(sample.runtime);
                if (reader.parse(
                    runtime_json.data(),
                    runtime_json.data() + runtime_json.size(),
                    runtime) && runtime.isObject()) {
                    root["runtime"] = std::move(runtime);
                }

                Json::FastWriter writer;
                const Json::String encoded = writer.write(root);
                std::string json = detail::FromRuntimeJsonString(encoded);
                while (!json.empty() && (json.back() == '\n' || json.back() == '\r')) {
                    json.pop_back();
                }
                return json;
            }

        }
    }
}
