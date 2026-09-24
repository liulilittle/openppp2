// Env-gated production ledger for the Linux TUN TCPv4 GSO coalescer.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include <linux/ppp/tap/TapGsoCoalescer.h>

namespace ppp {
namespace tap {

// This ledger deliberately covers only frames emitted by TunGsoCoalescer's
// VNET path. Bare TUN writes and other framing domains are not part of its
// counters and must not be combined into a global conservation assertion.
class TunGsoLedger final {
public:
    void ResetWindow() noexcept { *this = TunGsoLedger(); }
    void FinalizeWindow() noexcept { finalized_ = true; }
    bool finalized() const noexcept { return finalized_; }

    void OnEvent(const TunGsoCoalescer::Event& event) noexcept {
        if (finalized_) return;
        using Event = TunGsoCoalescer::Event;
        using Outcome = TunGsoCoalescer::WriteOutcome;
        if (event.kind == Event::Kind::EligiblePacket) {
            eligible_packets_++;
            eligible_bytes_ += event.packet_bytes;
            return;
        }
        if (event.kind == Event::Kind::RejectedPacket) {
            CountRejection(event.rejection);
            return;
        }
        if (event.kind == Event::Kind::NegativeFallback) {
            negative_fallback_++;
            fallback_ordinary_writes_pending_ = event.segments;
            return;
        }
        if (event.kind == Event::Kind::GsoWrite) {
            CountFlush(event.flush_reason);
            RecordHold(event.hold_ns);
            if (event.outcome == Outcome::Complete) {
                gso_full_writes_++;
                gso_full_write_bytes_ += event.frame_bytes;
                gso_segments_ += event.segments;
                merged_packets_ += event.segments;
                merged_bytes_ += event.packet_bytes;
            }
            else if (event.outcome == Outcome::PartialDelivery) {
                partial_unknown_++;
            }
            return;
        }
        if (event.kind == Event::Kind::OrdinaryWrite) {
            // A singleton flush is the only ordinary-write event that carries a
            // termination reason. A rejected direct frame has Explicit reason.
            // Negative GSO fallback has already recorded its one termination at
            // the GSO attempt, so its retained ordinary writes must not repeat it.
            const bool is_negative_fallback_write = fallback_ordinary_writes_pending_ != 0;
            if (is_negative_fallback_write) --fallback_ordinary_writes_pending_;
            if (!is_negative_fallback_write && event.flush_reason != TunGsoCoalescer::FlushReason::Explicit) {
                CountFlush(event.flush_reason);
                RecordHold(event.hold_ns);
            }
            if (event.outcome == Outcome::Complete) {
                ordinary_full_writes_++;
                ordinary_full_write_bytes_ += event.frame_bytes;
            }
            else if (event.outcome == Outcome::PartialDelivery) {
                partial_unknown_++;
            }
        }
    }

    std::string RenderWindowJson() const {
        std::string out;
        out.reserve(1400);
        auto field = [&out](const char* name, uint64_t value, bool comma = true) {
            out += std::string("\"") + name + "\":" + std::to_string(value);
            if (comma) out += ",";
        };
        out += "{\"framing_domain\":\"vnet_gso_coalescer_only_not_global\",";
        field("eligible_packets", eligible_packets_);
        field("eligible_bytes", eligible_bytes_);
        field("merged_packets", merged_packets_);
        field("merged_bytes", merged_bytes_);
        field("ordinary_full_writes", ordinary_full_writes_);
        field("ordinary_full_write_bytes", ordinary_full_write_bytes_);
        field("gso_full_writes", gso_full_writes_);
        field("gso_full_write_bytes", gso_full_write_bytes_);
        field("gso_segments", gso_segments_);
        field("negative_fallback", negative_fallback_);
        field("partial_unknown", partial_unknown_);
        out += "\"flush_or_termination_reasons\":{";
        for (size_t i = 0; i < flush_reasons_.size(); ++i) {
            if (i != 0) out += ",";
            out += std::string("\"") + FlushReasonName(static_cast<TunGsoCoalescer::FlushReason>(i)) + "\":" +
                std::to_string(flush_reasons_[i]);
        }
        out += "},\"packet_rejections\":{\"incompatible\":" + std::to_string(rejected_incompatible_) +
            ",\"psh\":" + std::to_string(rejected_psh_) + ",\"control\":" +
            std::to_string(rejected_control_) + ",\"mtu\":" + std::to_string(rejected_mtu_) + "},";
        out += "\"hold_histogram_us\":{";
        static const char* labels[kHoldBuckets] = {"<5", "5-25", "25-50", "50-100", "100-200", "200-500", "500-1000", ">=1000"};
        for (size_t i = 0; i < kHoldBuckets; ++i) {
            if (i != 0) out += ",";
            out += std::string("\"") + labels[i] + "\":" + std::to_string(hold_histogram_[i]);
        }
        out += "}}";
        return out;
    }

private:
    static constexpr size_t kFlushReasonCount = static_cast<size_t>(TunGsoCoalescer::FlushReason::Terminate) + 1;
    static constexpr size_t kHoldBuckets = 8;

    static const char* FlushReasonName(TunGsoCoalescer::FlushReason reason) noexcept {
        switch (reason) {
        case TunGsoCoalescer::FlushReason::Explicit: return "explicit";
        case TunGsoCoalescer::FlushReason::Cap: return "cap";
        case TunGsoCoalescer::FlushReason::Timeout: return "timeout";
        case TunGsoCoalescer::FlushReason::Incompatible: return "incompatible";
        case TunGsoCoalescer::FlushReason::ShortTail: return "short_tail";
        case TunGsoCoalescer::FlushReason::Psh: return "psh";
        case TunGsoCoalescer::FlushReason::Control: return "control";
        case TunGsoCoalescer::FlushReason::Ssmt: return "ssmt";
        case TunGsoCoalescer::FlushReason::Terminate: return "terminate";
        }
        return "unknown";
    }

    void CountRejection(TunGsoCoalescer::RejectionReason reason) noexcept {
        switch (reason) {
        case TunGsoCoalescer::RejectionReason::Psh: rejected_psh_++; break;
        case TunGsoCoalescer::RejectionReason::Control: rejected_control_++; break;
        case TunGsoCoalescer::RejectionReason::Mtu: rejected_mtu_++; break;
        case TunGsoCoalescer::RejectionReason::Incompatible: rejected_incompatible_++; break;
        case TunGsoCoalescer::RejectionReason::None: break;
        }
    }

    void CountFlush(TunGsoCoalescer::FlushReason reason) noexcept {
        flush_reasons_[static_cast<size_t>(reason)]++;
    }

    void RecordHold(uint64_t hold_ns) noexcept {
        const uint64_t us = hold_ns / 1000;
        const size_t bucket = us < 5 ? 0 : us < 25 ? 1 : us < 50 ? 2 : us < 100 ? 3 :
            us < 200 ? 4 : us < 500 ? 5 : us < 1000 ? 6 : 7;
        hold_histogram_[bucket]++;
    }

    bool finalized_ = false;
    uint64_t eligible_packets_ = 0;
    uint64_t eligible_bytes_ = 0;
    uint64_t merged_packets_ = 0;
    uint64_t merged_bytes_ = 0;
    uint64_t ordinary_full_writes_ = 0;
    uint64_t ordinary_full_write_bytes_ = 0;
    uint64_t gso_full_writes_ = 0;
    uint64_t gso_full_write_bytes_ = 0;
    uint64_t gso_segments_ = 0;
    uint64_t negative_fallback_ = 0;
    uint64_t fallback_ordinary_writes_pending_ = 0;
    uint64_t partial_unknown_ = 0;
    uint64_t rejected_incompatible_ = 0;
    uint64_t rejected_psh_ = 0;
    uint64_t rejected_control_ = 0;
    uint64_t rejected_mtu_ = 0;
    std::array<uint64_t, kFlushReasonCount> flush_reasons_{};
    std::array<uint64_t, kHoldBuckets> hold_histogram_{};
};

} // namespace tap
} // namespace ppp
