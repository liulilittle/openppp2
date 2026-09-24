// TapGsoMergeabilityAnalyzer — read-only, env-gated telemetry for
// PPP-DATAPATH-GSO-MERGEABILITY-001.
//
// Observes the packets that reach TapLinux::Output() and classifies how many
// consecutive output packets would qualify as segments of one strict-v1 GSO
// superpacket. It never caches packets, never delays or changes the write,
// keeps no borrowed pointers, and allocates nothing per packet. The owning
// call path is the single TUN writer (inflight max 1), so plain fields are
// safe without locks.

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <string>
#include <vector>

#include <linux/ppp/tap/TapGsoCoalescer.h>

namespace ppp {
    namespace tap {
        class TunGsoMergeabilityAnalyzer {
        public:
            // Production strict-v1 is capped at four segments. The 8/16 values
            // below are retained solely as explicitly labelled theoretical upper
            // bounds, never as producible coalescer frames.
            static constexpr int kBreakReasons = 23;
            static constexpr int kRunLengthBuckets = 8;
            static constexpr int kFormationThresholds[4] = {2, 4, 8, 16};
            static constexpr int kFormationBuckets = 9;

            static const char* BreakReasonName(int reason) noexcept {
                static const char* names[kBreakReasons] = {
                    "flow_change", "non_ipv4", "non_tcp", "no_payload", "fragmented",
                    "malformed_header", "seq_gap", "seq_rewind_or_retransmit",
                    "payload_size_change", "short_tail_completed", "ack_change",
                    "window_change", "urg_change", "tcp_options_change",
                    "ip_options_change", "ip_header_change", "flags_change", "psh",
                    "control_flags", "measurement_end", "mtu", "cap", "timeout"};
                return reason >= 0 && reason < kBreakReasons ? names[reason] : "unknown";
            }

            static uint64_t NowNs() noexcept {
                return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
            }

            /// Start of a measurement window: drop any open run and zero counters.
            void ResetWindow() noexcept {
                *this = TunGsoMergeabilityAnalyzer();
            }

            /// End of a measurement window: the open run still counts.
            void FinalizeOpenRun() noexcept {
                if (run_open_) {
                    FinalizeRun(reason_measurement_end);
                }
            }

            /// Observes one packet exactly as it is about to be written.
            void Observe(const uint8_t* packet, size_t length) noexcept {
                ObserveAt(packet, length, NowNs());
            }

            /// Test seam: same as Observe with an injected monotonic timestamp.
            void ObserveAt(const uint8_t* packet, size_t length, uint64_t now_ns) noexcept {
                if (packet == nullptr || length == 0) return;
                packets_seen_++;
                bytes_seen_ += length;
                // Push() flushes before parsing when the hold has elapsed.
                if (run_open_ && now_ns - run_start_ns_ >= TunGsoCoalescer::kHoldNs) {
                    FinalizeRun(reason_timeout);
                }

                const Classification classification = Classify(packet, length);
                if (!classification.eligible) {
                    if (run_open_) FinalizeRun(classification.break_reason);
                    ineligible_packets_++;
                    if (classification.break_reason == reason_psh) psh_rejected_packets_++;
                    simulated_writes_cap4_++;
                    theoretical_upper_bound_writes_cap8_++;
                    theoretical_upper_bound_writes_cap16_++;
                    return;
                }

                strict_eligible_packets_++;
                strict_eligible_bytes_ += classification.payload_bytes;
                TrackIpId(packet);

                if (run_open_) {
                    const int reason = ContinuityBreakReason(packet, classification);
                    if (reason == -1) {
                        AppendSegment(classification, now_ns);
                        if (run_segments_ == TunGsoCoalescer::kSegmentCap) FinalizeRun(reason_cap);
                        return;
                    }
                    if (reason == reason_short_tail_completed) {
                        AppendSegment(classification, now_ns);
                        FinalizeRun(reason_short_tail_completed);
                        return;
                    }
                    FinalizeRun(reason);
                }
                StartRun(packet, classification, now_ns);
            }

            /// Renders the current window (since the last ResetWindow) as JSON.
            std::string RenderWindowJson() const {
                std::string out;
                out.reserve(4096);
                out += "{";
                auto field = [&out](const char* name, uint64_t value) {
                    out += std::string("\"") + name + "\":" + std::to_string(value) + ",";
                };
                field("packets_seen", packets_seen_);
                field("bytes_seen", bytes_seen_);
                field("ipv4_packets", ipv4_packets_);
                field("tcp_packets", tcp_packets_);
                field("tcp_data_packets", tcp_data_packets_);
                field("tcp_data_bytes", tcp_data_bytes_);
                field("strict_eligible_packets", strict_eligible_packets_);
                field("strict_eligible_bytes", strict_eligible_bytes_);
                field("ineligible_packets", ineligible_packets_);
                field("psh_rejected_packets", psh_rejected_packets_);
                field("df_set_packets", df_set_packets_);
                field("ip_id_incrementing", ip_id_incrementing_);
                // This is an input-packet baseline, not a count of physical
                // direct writes (which belong to the production ledger).
                field("observed_output_packets", packets_seen_);
                field("simulated_writes_cap4", simulated_writes_cap4_);
                out += "\"theoretical_upper_bound\":{\"segment_caps\":[8,16],";
                out += "\"simulated_writes_cap8\":" + std::to_string(theoretical_upper_bound_writes_cap8_);
                out += ",\"simulated_writes_cap16\":" + std::to_string(theoretical_upper_bound_writes_cap16_) + "},";

                out += "\"break_reasons\":{";
                for (int i = 0; i < kBreakReasons; ++i) {
                    if (i != 0) out += ",";
                    out += std::string("\"") + BreakReasonName(i) + "\":" + std::to_string(break_reasons_[i]);
                }
                out += "},";

                static const char* length_bucket_names[kRunLengthBuckets] = {
                    "1", "2", "3", "4", "5-8", "9-16", "17-32", ">32"};
                out += "\"run_length_histogram\":{";
                for (int i = 0; i < kRunLengthBuckets; ++i) {
                    if (i != 0) out += ",";
                    out += std::string("\"") + length_bucket_names[i] + "\":{\"runs\":" + std::to_string(run_length_runs_[i]);
                    out += ",\"packets\":" + std::to_string(run_length_packets_[i]);
                    out += ",\"payload_bytes\":" + std::to_string(run_length_bytes_[i]) + "}";
                }
                out += "},";

                static const char* formation_names[4] = {"2", "4", "theoretical_upper_bound_8", "theoretical_upper_bound_16"};
                out += "\"formation_time_us\":{";
                for (int t = 0; t < 4; ++t) {
                    if (t != 0) out += ",";
                    out += std::string("\"") + formation_names[t] + "\":{\"samples\":" + std::to_string(formation_samples_[t]);
                    out += ",\"buckets\":[";
                    for (int b = 0; b < kFormationBuckets; ++b) {
                        if (b != 0) out += ",";
                        out += std::to_string(formation_buckets_[t][b]);
                    }
                    out += "]}";
                }
                out += "}}";
                return out;
            }

        private:
            struct Classification {
                bool eligible = false;
                int break_reason = -1; ///< packet-local reason when ineligible
                size_t payload_bytes = 0;
                uint32_t sequence = 0;
                bool psh = false;
            };

            enum : int {
                reason_flow_change = 0, reason_non_ipv4, reason_non_tcp, reason_no_payload,
                reason_fragmented, reason_malformed_header, reason_seq_gap,
                reason_seq_rewind_or_retransmit, reason_payload_size_change,
                reason_short_tail_completed, reason_ack_change, reason_window_change,
                reason_urg_change, reason_tcp_options_change, reason_ip_options_change,
                reason_ip_header_change, reason_flags_change, reason_psh,
                reason_control_flags, reason_measurement_end, reason_mtu,
                reason_cap, reason_timeout
            };

            static constexpr uint64_t bucket_bounds_us_[kFormationBuckets - 1] = {5, 10, 25, 50, 100, 200, 500, 1000};

            static int RunLengthBucket(size_t segments) noexcept {
                if (segments <= 4) return static_cast<int>(segments) - 1; // 1,2,3,4
                if (segments <= 8) return 4;
                if (segments <= 16) return 5;
                if (segments <= 32) return 6;
                return 7;
            }

            static int FormationBucket(uint64_t duration_ns) noexcept {
                const uint64_t us = duration_ns / 1000;
                for (int b = 0; b < kFormationBuckets - 1; ++b) {
                    if (us < bucket_bounds_us_[b]) return b;
                }
                return kFormationBuckets - 1;
            }

            void RecordFormation(size_t segment_count, uint64_t now_ns) noexcept {
                for (int t = 0; t < 4; ++t) {
                    if (segment_count == static_cast<size_t>(kFormationThresholds[t])) {
                        formation_samples_[t]++;
                        formation_buckets_[t][FormationBucket(now_ns - run_start_ns_)]++;
                    }
                }
            }

            Classification Classify(const uint8_t* packet, size_t length) noexcept {
                Classification result;
                if (length < 1 || (packet[0] >> 4U) != 4) {
                    result.break_reason = reason_non_ipv4;
                    return result;
                }
                ipv4_packets_++;
                const size_t ihl = static_cast<size_t>(packet[0] & 0x0fU) * 4;
                if (ihl < 20 || length < ihl) {
                    result.break_reason = reason_malformed_header;
                    return result;
                }
                const size_t total_length = static_cast<size_t>(packet[2] << 8U | packet[3]);
                if (total_length < ihl || total_length > length) {
                    result.break_reason = reason_malformed_header;
                    return result;
                }
                const uint16_t fragment = static_cast<uint16_t>(packet[6] << 8U | packet[7]);
                if ((fragment & 0x3fffU) != 0) { // MF set or non-zero offset
                    result.break_reason = reason_fragmented;
                    return result;
                }
                if (packet[9] != 6) {
                    result.break_reason = reason_non_tcp;
                    return result;
                }
                const size_t tcp_offset = ihl;
                if (length < tcp_offset + 20) {
                    result.break_reason = reason_malformed_header;
                    return result;
                }
                tcp_packets_++;
                const size_t data_offset = static_cast<size_t>(packet[tcp_offset + 12] >> 4U) * 4;
                if (data_offset < 20 || data_offset > total_length - ihl) {
                    result.break_reason = reason_malformed_header;
                    return result;
                }
                const size_t payload_bytes = total_length - ihl - data_offset;
                const uint8_t flags = packet[tcp_offset + 13];
                if ((flags & 0xE7U) != 0) { // SYN | FIN | RST | URG | ECE | CWR
                    result.break_reason = reason_control_flags;
                    return result;
                }
                if (payload_bytes == 0) {
                    result.break_reason = reason_no_payload;
                    return result;
                }
                tcp_data_packets_++;
                tcp_data_bytes_ += payload_bytes;
                if (packet[6] & 0x40U) df_set_packets_++;
                TunGsoCoalescer::PacketInfo strict_info;
                switch (TunGsoCoalescer::ClassifyStrictV1(packet, length, strict_info)) {
                case TunGsoCoalescer::RejectionReason::None:
                    break;
                case TunGsoCoalescer::RejectionReason::Psh:
                    result.break_reason = reason_psh;
                    return result;
                case TunGsoCoalescer::RejectionReason::Mtu:
                    result.break_reason = reason_mtu;
                    return result;
                case TunGsoCoalescer::RejectionReason::Control:
                    result.break_reason = reason_control_flags;
                    return result;
                default:
                    result.break_reason = reason_malformed_header;
                    return result;
                }
                result.eligible = true;
                result.payload_bytes = strict_info.payload;
                result.sequence = strict_info.seq;
                return result;
            }

            /// Returns the mutually-exclusive reason `packet` cannot continue the open run, or -1.
            int ContinuityBreakReason(const uint8_t* packet, const Classification& c) noexcept {
                const size_t ihl = static_cast<size_t>(packet[0] & 0x0fU) * 4;
                const size_t tcp_offset = ihl;
                if (std::memcmp(packet + 12, run_key_.data(), 8) != 0) return reason_flow_change;
                const uint8_t* tcp = packet + tcp_offset;
                if (std::memcmp(tcp, run_tcp_fixed_.data(), 4) != 0) return reason_flow_change;
                const int32_t seq_delta = static_cast<int32_t>((static_cast<uint32_t>(tcp[4]) << 24U) | (static_cast<uint32_t>(tcp[5]) << 16U) |
                    (static_cast<uint32_t>(tcp[6]) << 8U) | static_cast<uint32_t>(tcp[7])) - run_next_seq_;
                if (seq_delta < 0) return reason_seq_rewind_or_retransmit;
                if (seq_delta > 0) return reason_seq_gap;
                if (std::memcmp(tcp + 8, run_tcp_fixed_.data() + 4, 4) != 0) return reason_ack_change;
                if (std::memcmp(tcp + 14, run_tcp_fixed_.data() + 8, 2) != 0) return reason_window_change;
                if (std::memcmp(tcp + 18, run_tcp_fixed_.data() + 10, 2) != 0) return reason_urg_change;
                if (packet[1] != run_ip_tos_ || packet[8] != run_ip_ttl_ ||
                    (packet[6] & 0x40U) != static_cast<uint8_t>((run_ip_flags_ >> 8U) & 0x40U)) return reason_ip_header_change;
                if (ihl != run_ihl_ ||
                    (ihl > 20 && std::memcmp(packet + 20, run_ip_options_.data(), std::min<size_t>(ihl - 20, 40)) != 0)) return reason_ip_options_change;
                const size_t data_offset = static_cast<size_t>(tcp[12] >> 4U) * 4;
                if (data_offset != run_doff_) return reason_tcp_options_change;
                if (data_offset > 20 && std::memcmp(tcp + 20, run_tcp_options_.data(), std::min<size_t>(data_offset - 20, 40)) != 0) return reason_tcp_options_change;
                if (c.payload_bytes > run_gso_size_) return reason_payload_size_change;
                if (c.payload_bytes < run_gso_size_) return reason_short_tail_completed;
                return -1;
            }

            void FinalizeRun(int reason) noexcept {
                const int bucket = RunLengthBucket(run_segments_);
                run_length_runs_[bucket]++;
                run_length_packets_[bucket] += run_segments_;
                run_length_bytes_[bucket] += run_bytes_;
                break_reasons_[reason]++;
                run_open_ = false;
                simulated_writes_cap4_ += (run_segments_ + 3U) / 4U;
                theoretical_upper_bound_writes_cap8_ += (run_segments_ + 7U) / 8U;
                theoretical_upper_bound_writes_cap16_ += (run_segments_ + 15U) / 16U;
            }

            void StartRun(const uint8_t* packet, const Classification& c, uint64_t now_ns) noexcept {
                const size_t ihl = static_cast<size_t>(packet[0] & 0x0fU) * 4;
                const size_t tcp_offset = ihl;
                const uint8_t* tcp = packet + tcp_offset;
                const size_t data_offset = static_cast<size_t>(tcp[12] >> 4U) * 4;
                run_open_ = true;
                run_segments_ = 1;
                run_bytes_ = c.payload_bytes;
                run_gso_size_ = c.payload_bytes;
                run_start_ns_ = now_ns;
                run_next_seq_ = c.sequence + static_cast<uint32_t>(c.payload_bytes);
                run_ihl_ = static_cast<uint8_t>(ihl);
                run_doff_ = static_cast<uint8_t>(data_offset);
                run_ip_tos_ = packet[1];
                run_ip_ttl_ = packet[8];
                run_ip_flags_ = static_cast<uint16_t>(packet[6] << 8U | packet[7]);
                std::memcpy(run_key_.data(), packet + 12, 8); // src + dst
                const size_t ip_options = ihl > 20 ? std::min<size_t>(ihl - 20, 40) : 0;
                std::memset(run_ip_options_.data(), 0, run_ip_options_.size());
                std::memcpy(run_ip_options_.data(), packet + 20, ip_options);
                std::memcpy(run_tcp_fixed_.data(), tcp, 4);            // ports
                std::memcpy(run_tcp_fixed_.data() + 4, tcp + 8, 4);    // ack
                std::memcpy(run_tcp_fixed_.data() + 8, tcp + 14, 2);   // window
                std::memcpy(run_tcp_fixed_.data() + 10, tcp + 18, 2);  // urgent
                const size_t tcp_options = data_offset > 20 ? std::min<size_t>(data_offset - 20, 40) : 0;
                std::memset(run_tcp_options_.data(), 0, run_tcp_options_.size());
                std::memcpy(run_tcp_options_.data(), tcp + 20, tcp_options);
            }

            void AppendSegment(const Classification& c, uint64_t now_ns) noexcept {
                run_segments_++;
                run_bytes_ += c.payload_bytes;
                run_next_seq_ = c.sequence + static_cast<uint32_t>(c.payload_bytes);
                RecordFormation(run_segments_, now_ns);
            }

            void TrackIpId(const uint8_t* packet) noexcept {
                const uint16_t id = static_cast<uint16_t>((packet[4] << 8U) | packet[5]);
                if (ip_id_has_prev_) {
                    if (id == static_cast<uint16_t>(ip_id_prev_ + 1)) ip_id_incrementing_++;
                }
                ip_id_prev_ = id;
                ip_id_has_prev_ = true;
            }

            // Flow/header snapshot of the open run.
            bool run_open_ = false;
            size_t run_segments_ = 0;
            size_t run_bytes_ = 0;
            size_t run_gso_size_ = 0;
            uint32_t run_next_seq_ = 0;
            uint64_t run_start_ns_ = 0;
            uint16_t ip_id_prev_ = 0;
            bool ip_id_has_prev_ = false;
            uint8_t run_ihl_ = 20;
            uint8_t run_doff_ = 20;
            uint8_t run_ip_tos_ = 0;
            uint8_t run_ip_ttl_ = 0;
            uint16_t run_ip_flags_ = 0;
            std::vector<uint8_t> run_key_ = std::vector<uint8_t>(8, 0);      // src(4) + dst(4)
            std::vector<uint8_t> run_ip_options_ = std::vector<uint8_t>(40, 0);
            std::vector<uint8_t> run_tcp_fixed_ = std::vector<uint8_t>(12, 0); // ports(4)+ack(4)+window(2)+urgent(2)
            std::vector<uint8_t> run_tcp_options_ = std::vector<uint8_t>(40, 0);

            // Window counters.
            uint64_t packets_seen_ = 0;
            uint64_t bytes_seen_ = 0;
            uint64_t ipv4_packets_ = 0;
            uint64_t tcp_packets_ = 0;
            uint64_t tcp_data_packets_ = 0;
            uint64_t tcp_data_bytes_ = 0;
            uint64_t strict_eligible_packets_ = 0;
            uint64_t strict_eligible_bytes_ = 0;
            uint64_t ineligible_packets_ = 0;
            uint64_t psh_rejected_packets_ = 0;
            uint64_t df_set_packets_ = 0;
            uint64_t ip_id_incrementing_ = 0;
            uint64_t simulated_writes_cap4_ = 0;
            uint64_t theoretical_upper_bound_writes_cap8_ = 0;
            uint64_t theoretical_upper_bound_writes_cap16_ = 0;
            uint64_t break_reasons_[kBreakReasons] = {};
            uint64_t run_length_runs_[kRunLengthBuckets] = {};
            uint64_t run_length_packets_[kRunLengthBuckets] = {};
            uint64_t run_length_bytes_[kRunLengthBuckets] = {};
            uint64_t formation_samples_[4] = {};
            uint64_t formation_buckets_[4][kFormationBuckets] = {};
        };
    }
}
