// Bounded Linux TUN TCPv4 GSO coalescer. It owns every byte it defers.
#pragma once

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <utility>
#include <vector>
#include <cstdlib>
#include <sys/uio.h>

#include <ppp/tap/RetainedPacketOwner.h>

#include <endian.h>
#include <sys/types.h>
// Linux UAPI exposes a member named `class`; protect C++ parsing.
#define class class_
#include <linux/virtio_net.h>
#undef class

namespace ppp {
namespace tap {

class TunGsoCoalescer final {
public:
    static constexpr size_t kSegmentCap = 4;
    static constexpr size_t kMaxSegmentCap = 48;
    static constexpr size_t kMaxPacketBytes = 1500;
    // XTCP-SHARED-PATH-001 follow-up: the merge cap is runtime-tunable
    // (OPENPPP2_TAP_GSO_SEGMENTS, default 4; up to 48 = ~64KB super-frames).
    // The opt-in XTCP DL throughput profile selects 48 only when no explicit
    // cap is supplied; it leaves the conservative default unchanged otherwise.
    static size_t SegmentCap() noexcept {
        const char* env = ::getenv("OPENPPP2_TAP_GSO_SEGMENTS");
        if (env != nullptr && env[0] != '\0') {
            const long long value = ::atoll(env);
            if (value >= 1 && value <= static_cast<long long>(kMaxSegmentCap)) {
                return static_cast<size_t>(value);
            }
        }
        const char* profile = ::getenv("OPENPPP2_XTCP_DL_GSO_PERF_PROFILE");
        if (profile != nullptr && profile[0] == '1' && profile[1] == '\0') {
            return kMaxSegmentCap;
        }
        return kSegmentCap;
    }
    static constexpr size_t kVirtioHeaderBytes = sizeof(virtio_net_hdr);
    static constexpr uint64_t kHoldNs = 100000; // 100 us
    static uint64_t HoldNs() noexcept {
        const char* env = ::getenv("OPENPPP2_TAP_GSO_HOLD_US");
        if (env != nullptr && env[0] != '\0') {
            char* end = nullptr;
            const unsigned long long value = ::strtoull(env, &end, 10);
            if (end != env && *end == '\0' && value >= 10 && value <= 1000) {
                return static_cast<uint64_t>(value) * 1000ULL;
            }
        }
        return kHoldNs;
    }
    using Writer = std::function<ssize_t(const uint8_t*, size_t)>;
    using VectoredWriter = std::function<ssize_t(const iovec*, int, size_t)>;

    enum class WriteOutcome : uint8_t {
        None,
        Complete,
        NegativeFailure,
        PartialDelivery,
    };

    // Packet-local strict-v1 admission status. Continuation constraints are
    // deliberately separate: they depend on the retained first segment.
    enum class RejectionReason : uint8_t {
        None,
        Incompatible,
        Psh,
        Control,
        Mtu,
    };

    enum class FlushReason : uint8_t {
        Explicit,
        Cap,
        Timeout,
        Incompatible,
        ShortTail,
        Psh,
        Control,
        Ssmt,
        Terminate,
    };

    struct PacketInfo final {
        size_t ihl = 0;
        size_t doff = 0;
        size_t total = 0;
        size_t payload = 0;
        uint32_t seq = 0;
    };

    // Metadata only: never carries payload bytes or flow identifiers.
    struct PacketShape final {
        bool parsed = false;
        size_t supplied_bytes = 0;
        size_t ipv4_total_length = 0;
        size_t ipv4_ihl_bytes = 0;
        size_t tcp_data_offset_bytes = 0;
        size_t tcp_payload_bytes = 0;
        uint8_t ipv4_version = 0;
        uint8_t ipv4_protocol = 0;
        uint16_t ipv4_fragment_flags = 0;
        bool ipv4_df = false;
        uint8_t tcp_flags = 0;
        size_t max_guard_bytes = kMaxPacketBytes;
        size_t excess_bytes = 0;
    };

    struct Event final {
        enum class Kind : uint8_t {
            EligiblePacket,
            RejectedPacket,
            OrdinaryWrite,
            GsoWrite,
            NegativeFallback,
        };

        Kind kind = Kind::EligiblePacket;
        RejectionReason rejection = RejectionReason::None;
        FlushReason flush_reason = FlushReason::Explicit;
        WriteOutcome outcome = WriteOutcome::None;
        size_t packet_bytes = 0; // original IPv4 packet bytes, not VNET bytes
        size_t payload_bytes = 0;
        size_t frame_bytes = 0;  // requested physical VNET frame bytes
        size_t segments = 0;
        uint64_t hold_ns = 0;
        int error_number = 0;    // captured immediately after a negative writer return
        ssize_t written_bytes = 0;
        uint64_t monotonic_ns = 0;
        PacketShape packet_shape;
    };
    using Observer = std::function<void(const Event&)>;

    explicit TunGsoCoalescer(Writer writer, Observer observer = {}, VectoredWriter vectored_writer = {},
        bool enable_psh_boundary = true, bool enable_retained_writev = true,
        uint64_t hold_ns = HoldNs()) noexcept
        : segment_cap_(SegmentCap()),
          superpacket_(kVirtioHeaderBytes + SegmentCap() * kMaxPacketBytes),
          writer_(std::move(writer)), observer_(std::move(observer)),
          vectored_writer_(std::move(vectored_writer)),
          enable_psh_boundary_(enable_psh_boundary), enable_retained_writev_(enable_retained_writev),
          hold_ns_(hold_ns == 0 ? kHoldNs : hold_ns) {}


    static uint64_t NowNs() noexcept {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    // Shared strict-v1 packet-local predicate for production and analysis.
    // PSH is admitted as a possible final segment; PushInternal flushes it
    // immediately so later payload cannot cross its push boundary.
    static RejectionReason ClassifyStrictV1(const uint8_t* packet, size_t length, PacketInfo& out) noexcept {
        if (!ParsePacket(packet, length, out)) return RejectionReason::Incompatible;
        const uint8_t flags = packet[out.ihl + 13];
        if ((flags & 0xE7U) != 0) return RejectionReason::Control;
        return length > kMaxPacketBytes ? RejectionReason::Mtu : RejectionReason::None;
    }

    bool enabled() const noexcept { return enabled_; }
    bool has_pending() const noexcept { return count_ != 0; }
    uint64_t hold_ns() const noexcept { return hold_ns_; }
    WriteOutcome last_write_outcome() const noexcept { return last_write_outcome_; }
    void SetObserver(Observer observer) noexcept { observer_ = std::move(observer); }

    // Writes one ordinary VNET-framed packet without changing merge state.
    // The caller serializes access to this coalescer and its writer.
    bool WriteOrdinaryFrame(const uint8_t* packet, size_t length,
        bool checksum_partial = false) noexcept {
        return WriteOrdinary(packet, length, FlushReason::Explicit, 0, checksum_partial);
    }

    // Called by the single TUN writer. A false return has the same meaning as
    // the old direct write path (the relevant direct write failed).
    bool Push(const uint8_t* packet, size_t length, uint64_t now_ns = NowNs()) noexcept {
        return PushInternal(packet, length, nullptr, false, now_ns);
    }

    bool PushOwned(const uint8_t* packet, size_t length, RetainedPacketOwner&& owner,
        uint64_t now_ns = NowNs()) noexcept {
        if (!owner.HasValue()) return false;
        return PushInternal(packet, length, &owner, owner.ChecksumPartial(), now_ns);
    }

private:
    bool PushInternal(const uint8_t* packet, size_t length, RetainedPacketOwner* owner,
        bool checksum_partial, uint64_t now_ns) noexcept {
        if (packet == nullptr || length == 0) return false;
        if (!enabled_) return WriteOrdinary(packet, length, FlushReason::Explicit, 0, checksum_partial);
        if (count_ != 0 && now_ns - started_ns_ >= hold_ns_ && !Flush(FlushReason::Timeout, now_ns)) return false;

        PacketInfo parsed{};
        RejectionReason rejection = ClassifyStrictV1(packet, length, parsed);
        const bool psh = rejection == RejectionReason::None && (packet[parsed.ihl + 13] & 0x08U) != 0;
        if (psh && !enable_psh_boundary_) rejection = RejectionReason::Psh;
        if (rejection != RejectionReason::None) {
            Emit({Event::Kind::RejectedPacket, rejection, FlushReason::Explicit, WriteOutcome::None,
                length, 0, 0, 0, 0, 0, 0, 0,
                MakePacketShape(packet, length, parsed, rejection != RejectionReason::Incompatible)});
            if (!Flush(FlushForRejection(rejection), now_ns)) return false;
            return WriteOrdinary(packet, length, FlushReason::Explicit, 0, checksum_partial);
        }
        // EligiblePacket is diagnostic-only. Avoid constructing its relatively
        // large PacketShape-bearing event on the default unobserved hot path.
        if (observer_) {
            const Event event{Event::Kind::EligiblePacket, RejectionReason::None,
                FlushReason::Explicit, WriteOutcome::None, length, parsed.payload, 0, 1, 0};
            observer_(event);
        }
        if (count_ != 0 && !CanAppend(packet, parsed)) {
            if (!Flush(FlushReason::Incompatible, now_ns)) return false;
        }
        if (count_ == 0) Start(packet, length, parsed, owner, now_ns);
        else Append(packet, length, parsed, owner);

        if (psh) {
            // Linux TCP GSO keeps PSH on the final segment and clears it on
            // preceding segments. Mark the aggregate header, then flush now;
            // a subsequent packet must never be merged past this boundary.
            pending_psh_ = true;
            return Flush(FlushReason::Psh, now_ns);
        }

        if (parsed.payload < gso_size_) return Flush(FlushReason::ShortTail, now_ns);
        if (count_ == segment_cap_) return Flush(FlushReason::Cap, now_ns);
        return true;
    }

public:

    bool FlushExpired(uint64_t now_ns = NowNs()) noexcept {
        return count_ == 0 || now_ns - started_ns_ < hold_ns_ || Flush(FlushReason::Timeout, now_ns);
    }

    bool Flush(FlushReason reason = FlushReason::Explicit, uint64_t now_ns = NowNs()) noexcept {
        if (count_ == 0) return true;
        const uint64_t hold_ns = now_ns >= started_ns_ ? now_ns - started_ns_ : 0;
        if (count_ == 1) {
            const bool ok = WriteOrdinaryStored(0, reason, hold_ns);
            Reset();
            return ok;
        }
        const size_t size = BuildGso();
        const WriteOutcome outcome = HasRetainedOwners()
            ? WriteFrame(BuildIovecs(), static_cast<int>(count_ + 1), size)
            : WriteFrame(superpacket_.data(), size);
        // Ledger-only totals require re-parsing retained originals. Do not do
        // that work unless OPENPPP2_DATAPATH_GSO_LEDGER installed an observer.
        size_t packet_bytes = 0;
        size_t payload_bytes = 0;
        if (observer_) {
            packet_bytes = PendingPacketBytes();
            payload_bytes = PendingPayloadBytes();
        }
        Emit({Event::Kind::GsoWrite, RejectionReason::None, reason, outcome,
            packet_bytes, payload_bytes, size, count_, hold_ns, last_error_number_,
            last_written_bytes_, last_write_monotonic_ns_});
        if (outcome == WriteOutcome::Complete) {
            Reset();
            return true;
        }
        enabled_ = false;
        if (outcome == WriteOutcome::PartialDelivery) {
            // A positive short write has unknown kernel-delivery semantics. Never
            // replay originals, because doing so could duplicate delivered bytes.
            Reset();
            return false;
        }
        // A negative write did not commit the GSO frame. Retry the retained
        // originals in order as ordinary VNET frames, stopping at first failure.
        Emit({Event::Kind::NegativeFallback, RejectionReason::None, reason, outcome,
            packet_bytes, payload_bytes, 0, count_, hold_ns});
        for (size_t i = 0; i < count_; ++i) {
            if (!WriteOrdinaryStored(i, reason, hold_ns)) {
                Reset();
                return false;
            }
        }
        Reset();
        return true;
    }

    bool DisableAndFlush(FlushReason reason = FlushReason::Terminate) noexcept {
        const bool ok = !enabled_ || Flush(reason);
        enabled_ = false;
        return ok;
    }

private:
    static uint16_t Read16(const uint8_t* p) noexcept { return static_cast<uint16_t>(p[0] << 8U | p[1]); }
    static uint32_t Read32(const uint8_t* p) noexcept {
        return (static_cast<uint32_t>(p[0]) << 24U) | (static_cast<uint32_t>(p[1]) << 16U) |
            (static_cast<uint32_t>(p[2]) << 8U) | p[3];
    }
    static void Write16(uint8_t* p, uint16_t v) noexcept { p[0] = static_cast<uint8_t>(v >> 8U); p[1] = static_cast<uint8_t>(v); }
    static uint32_t ChecksumSum(const uint8_t* p, size_t n, uint32_t sum = 0) noexcept {
        while (n >= 2) { sum += Read16(p); p += 2; n -= 2; }
        return n == 0 ? sum : sum + static_cast<uint16_t>(p[0] << 8U);
    }
    static uint16_t FoldChecksum(uint32_t sum) noexcept {
        while (sum >> 16U) sum = (sum & 0xffffU) + (sum >> 16U);
        return static_cast<uint16_t>(~sum);
    }
    static PacketShape MakePacketShape(const uint8_t* packet, size_t length,
        const PacketInfo& parsed, bool parsed_ok) noexcept {
        PacketShape shape;
        shape.supplied_bytes = length;
        shape.excess_bytes = length > kMaxPacketBytes ? length - kMaxPacketBytes : 0;
        if (!parsed_ok) return shape;
        shape.parsed = true;
        shape.ipv4_total_length = parsed.total;
        shape.ipv4_ihl_bytes = parsed.ihl;
        shape.tcp_data_offset_bytes = parsed.doff;
        shape.tcp_payload_bytes = parsed.payload;
        shape.ipv4_version = packet[0] >> 4U;
        shape.ipv4_protocol = packet[9];
        shape.ipv4_fragment_flags = static_cast<uint16_t>(Read16(packet + 6) & 0xe000U);
        shape.ipv4_df = (packet[6] & 0x40U) != 0;
        shape.tcp_flags = packet[parsed.ihl + 13];
        return shape;
    }

    static bool ParsePacket(const uint8_t* packet, size_t length, PacketInfo& out) noexcept {
        if (packet == nullptr || length < 1 || (packet[0] >> 4U) != 4) return false;
        out.ihl = static_cast<size_t>(packet[0] & 0x0fU) * 4U;
        if (out.ihl < 20 || length < out.ihl) return false;
        out.total = Read16(packet + 2);
        if (out.total < out.ihl || out.total > length) return false;
        if ((Read16(packet + 6) & 0x3fffU) != 0 || packet[9] != 6 || length < out.ihl + 20) return false;
        const uint8_t* tcp = packet + out.ihl;
        out.doff = static_cast<size_t>(tcp[12] >> 4U) * 4U;
        if (out.doff < 20 || out.doff > out.total - out.ihl) return false;
        out.payload = out.total - out.ihl - out.doff;
        if (out.payload == 0) return false;
        out.seq = Read32(tcp + 4);
        return true;
    }

    static FlushReason FlushForRejection(RejectionReason reason) noexcept {
        return reason == RejectionReason::Psh ? FlushReason::Psh :
            reason == RejectionReason::Control ? FlushReason::Control : FlushReason::Incompatible;
    }

    bool CanAppend(const uint8_t* packet, const PacketInfo& p) const noexcept {
        const uint8_t* tcp = packet + p.ihl;
        if (std::memcmp(packet + 12, flow_.data(), flow_.size()) != 0 ||
            std::memcmp(tcp, tcp_fixed_.data(), 4) != 0) return false;
        const int32_t delta = static_cast<int32_t>(p.seq - next_seq_);
        if (delta != 0 || std::memcmp(tcp + 8, tcp_fixed_.data() + 4, 4) != 0 ||
            std::memcmp(tcp + 14, tcp_fixed_.data() + 8, 2) != 0 ||
            std::memcmp(tcp + 18, tcp_fixed_.data() + 10, 2) != 0) return false;
        if (packet[1] != tos_ || packet[8] != ttl_ || (packet[6] & 0x40U) != df_ || p.ihl != ihl_ || p.doff != doff_) return false;
        if ((ihl_ > 20 && std::memcmp(packet + 20, ip_options_.data(), ihl_ - 20) != 0) ||
            (doff_ > 20 && std::memcmp(tcp + 20, tcp_options_.data(), doff_ - 20) != 0)) return false;
        if (p.payload > gso_size_) return false;

        // IPv4 total_length is a 16-bit field. A large configured GSO segment
        // cap must flush before the aggregate L3 packet exceeds the IPv4
        // maximum, even though the backing vector can hold more bytes.
        const size_t aggregate_payload = count_ * gso_size_ + p.payload;
        return ihl_ + doff_ + aggregate_payload <= UINT16_MAX;
    }

    void Start(const uint8_t* packet, size_t length, const PacketInfo& p,
        RetainedPacketOwner* owner, uint64_t now_ns) noexcept {
        count_ = 1; started_ns_ = now_ns; ihl_ = p.ihl; doff_ = p.doff; gso_size_ = p.payload; next_seq_ = p.seq + static_cast<uint32_t>(p.payload);
        pending_psh_ = false;
        tos_ = packet[1]; ttl_ = packet[8]; df_ = packet[6] & 0x40U;
        std::memcpy(flow_.data(), packet + 12, flow_.size());
        const uint8_t* tcp = packet + p.ihl;
        std::memcpy(tcp_fixed_.data(), tcp, 4); std::memcpy(tcp_fixed_.data() + 4, tcp + 8, 4);
        std::memcpy(tcp_fixed_.data() + 8, tcp + 14, 2); std::memcpy(tcp_fixed_.data() + 10, tcp + 18, 2);
        std::memset(ip_options_.data(), 0, ip_options_.size()); std::memset(tcp_options_.data(), 0, tcp_options_.size());
        if (ihl_ > 20) std::memcpy(ip_options_.data(), packet + 20, ihl_ - 20);
        if (doff_ > 20) std::memcpy(tcp_options_.data(), tcp + 20, doff_ - 20);
        StoreSegment(0, packet, length, p, owner);
    }
    void Append(const uint8_t* packet, size_t length, const PacketInfo& p,
        RetainedPacketOwner* owner) noexcept {
        StoreSegment(count_, packet, length, p, owner);
        ++count_;
        next_seq_ = p.seq + static_cast<uint32_t>(p.payload);
    }
    void StoreSegment(size_t index, const uint8_t* packet, size_t length, const PacketInfo& p,
        RetainedPacketOwner* owner) noexcept {
        const size_t header_size = p.ihl + p.doff;
        const size_t tail_size = length - p.total;
        header_sizes_[index] = header_size;
        payload_sizes_[index] = p.payload;
        checksum_partial_[index] = owner != nullptr && owner->ChecksumPartial();
        checksum_start_[index] = p.ihl;
        payload_offsets_[index] = payload_total_;
        tail_sizes_[index] = tail_size;
        packet_sizes_[index] = length;
        payload_ptrs_[index] = nullptr;
        if (owner != nullptr && enable_retained_writev_ && vectored_writer_) {
            owners_[index] = std::move(*owner);
            payload_ptrs_[index] = packet + header_size;
        }
        std::memcpy(headers_[index].data(), packet, header_size);
        if (tail_size != 0) std::memcpy(tails_[index].data(), packet + p.total, tail_size);

        uint8_t* ip = superpacket_.data() + kVirtioHeaderBytes;
        if (index == 0) {
            std::memcpy(ip, packet, header_size);
        }
        if (payload_ptrs_[index] == nullptr) {
            std::memcpy(ip + header_size + payload_total_, packet + header_size, p.payload);
        }
        payload_total_ += p.payload;
    }
    size_t PendingPacketBytes() const noexcept {
        size_t total = 0;
        for (size_t i = 0; i < count_; ++i) total += packet_sizes_[i];
        return total;
    }
    size_t PendingPayloadBytes() const noexcept {
        size_t total = 0;
        for (size_t i = 0; i < count_; ++i) total += payload_sizes_[i];
        return total;
    }
    WriteOutcome WriteFrame(const uint8_t* frame, size_t size) noexcept {
        const ssize_t written = writer_(frame, size);
        const int error_number = written < 0 ? errno : 0;
        last_written_bytes_ = written;
        last_error_number_ = error_number;
        last_write_monotonic_ns_ = observer_ ? NowNs() : 0;
        if (written == static_cast<ssize_t>(size)) return last_write_outcome_ = WriteOutcome::Complete;
        if (written < 0) return last_write_outcome_ = WriteOutcome::NegativeFailure;
        return last_write_outcome_ = WriteOutcome::PartialDelivery;
    }
    bool HasRetainedOwners() const noexcept {
        if (!enable_retained_writev_ || !vectored_writer_) return false;
        for (size_t i = 0; i < count_; ++i) {
            if (owners_[i].HasValue()) return true;
        }
        return false;
    }
    const iovec* BuildIovecs() noexcept {
        iov_count_ = 0;
        iovecs_[iov_count_++] = {superpacket_.data(), kVirtioHeaderBytes + ihl_ + doff_};
        for (size_t i = 0; i < count_; ++i) {
            const uint8_t* payload = payload_ptrs_[i] != nullptr
                ? payload_ptrs_[i]
                : superpacket_.data() + kVirtioHeaderBytes + ihl_ + doff_ + payload_offsets_[i];
            iovecs_[iov_count_++] = {const_cast<uint8_t*>(payload), payload_sizes_[i]};
        }
        return iovecs_.data();
    }
    WriteOutcome WriteFrame(const iovec* iovecs, int count, size_t size) noexcept {
        const ssize_t written = vectored_writer_(iovecs, count, size);
        const int error_number = written < 0 ? errno : 0;
        last_written_bytes_ = written;
        last_error_number_ = error_number;
        last_write_monotonic_ns_ = observer_ ? NowNs() : 0;
        if (written == static_cast<ssize_t>(size)) return last_write_outcome_ = WriteOutcome::Complete;
        if (written < 0) return last_write_outcome_ = WriteOutcome::NegativeFailure;
        return last_write_outcome_ = WriteOutcome::PartialDelivery;
    }
    bool WriteOrdinary(const uint8_t* packet, size_t length, FlushReason reason = FlushReason::Explicit,
        uint64_t hold_ns = 0, bool checksum_partial = false) noexcept {
        if (length > kMaxPacketBytes) {
            last_write_outcome_ = WriteOutcome::NegativeFailure;
            Emit({Event::Kind::OrdinaryWrite, RejectionReason::Mtu, reason, last_write_outcome_,
                length, 0, 0, 1, hold_ns, 0, 0, 0});
            return false;
        }
        std::memset(ordinary_.data(), 0, kVirtioHeaderBytes);
        if (checksum_partial) {
            PacketInfo parsed{};
            if (!ParsePacket(packet, length, parsed)) return false;
            ordinary_[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
            const uint16_t start = htole16(static_cast<uint16_t>(parsed.ihl));
            const uint16_t offset = htole16(16);
            std::memcpy(ordinary_.data() + 6, &start, sizeof(start));
            std::memcpy(ordinary_.data() + 8, &offset, sizeof(offset));
        }
        std::memcpy(ordinary_.data() + kVirtioHeaderBytes, packet, length);
        const WriteOutcome outcome = WriteFrame(ordinary_.data(), kVirtioHeaderBytes + length);
        Emit({Event::Kind::OrdinaryWrite, RejectionReason::None, reason, outcome,
            length, 0, kVirtioHeaderBytes + length, 1, hold_ns, last_error_number_,
            last_written_bytes_, last_write_monotonic_ns_});
        return outcome == WriteOutcome::Complete;
    }
    bool WriteOrdinaryStored(size_t index, FlushReason reason, uint64_t hold_ns) noexcept {
        const size_t header_size = header_sizes_[index];
        const size_t payload_size = payload_sizes_[index];
        const size_t tail_size = tail_sizes_[index];
        const size_t packet_size = packet_sizes_[index];
        std::memset(ordinary_.data(), 0, kVirtioHeaderBytes);
        if (checksum_partial_[index]) {
            ordinary_[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
            const uint16_t start = htole16(static_cast<uint16_t>(checksum_start_[index]));
            const uint16_t offset = htole16(16);
            std::memcpy(ordinary_.data() + 6, &start, sizeof(start));
            std::memcpy(ordinary_.data() + 8, &offset, sizeof(offset));
        }
        uint8_t* output = ordinary_.data() + kVirtioHeaderBytes;
        std::memcpy(output, headers_[index].data(), header_size);
        const uint8_t* merged_payload = superpacket_.data() + kVirtioHeaderBytes + ihl_ + doff_ + payload_offsets_[index];
        const size_t frame_size = kVirtioHeaderBytes + packet_size;
        const uint8_t* source_payload = payload_ptrs_[index] != nullptr
            ? payload_ptrs_[index] : merged_payload;
        std::memcpy(output + header_size, source_payload, payload_size);
        if (tail_size != 0) {
            std::memcpy(output + header_size + payload_size, tails_[index].data(), tail_size);
        }
        const WriteOutcome outcome = WriteFrame(ordinary_.data(), frame_size);
        Emit({Event::Kind::OrdinaryWrite, RejectionReason::None, reason, outcome,
            packet_size, 0, frame_size, 1, hold_ns, last_error_number_,
            last_written_bytes_, last_write_monotonic_ns_});
        return outcome == WriteOutcome::Complete;
    }
    size_t BuildGso() noexcept {
        std::memset(superpacket_.data(), 0, kVirtioHeaderBytes);
        virtio_net_hdr* virtio = reinterpret_cast<virtio_net_hdr*>(superpacket_.data());
        virtio->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
        virtio->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
        virtio->hdr_len = htole16(static_cast<uint16_t>(ihl_ + doff_));
        virtio->gso_size = htole16(static_cast<uint16_t>(gso_size_));
        virtio->csum_start = htole16(static_cast<uint16_t>(ihl_));
        virtio->csum_offset = htole16(16);
        uint8_t* ip = superpacket_.data() + kVirtioHeaderBytes;
        if (pending_psh_) ip[ihl_ + 13] |= 0x08U;
        Write16(ip + 2, static_cast<uint16_t>(ihl_ + doff_ + payload_total_));
        Write16(ip + 10, 0); Write16(ip + 10, FoldChecksum(ChecksumSum(ip, ihl_)));
        uint8_t* tcp = ip + ihl_; Write16(tcp + 16, 0);
        const size_t tcp_bytes = doff_ + payload_total_;
        uint32_t partial = ChecksumSum(ip + 12, 8);
        const uint8_t pseudo[] = {0, 6, static_cast<uint8_t>(tcp_bytes >> 8U), static_cast<uint8_t>(tcp_bytes)};
        partial = ChecksumSum(pseudo, sizeof(pseudo), partial);
        Write16(tcp + 16, static_cast<uint16_t>(~FoldChecksum(partial)));
        return kVirtioHeaderBytes + ihl_ + doff_ + payload_total_;
    }
    void Emit(const Event& event) noexcept { if (observer_) observer_(event); }
    void Reset() noexcept {
        for (size_t i = 0; i < count_; ++i) {
            owners_[i].Reset();
            payload_ptrs_[i] = nullptr;
            checksum_partial_[i] = false;
            checksum_start_[i] = 0;
        }
        count_ = 0;
        payload_total_ = 0;
        pending_psh_ = false;
    }

    Writer writer_;
    Observer observer_;
    VectoredWriter vectored_writer_;
    bool enable_psh_boundary_ = true;
    bool enable_retained_writev_ = true;
    uint64_t hold_ns_ = kHoldNs;
    WriteOutcome last_write_outcome_ = WriteOutcome::None;
    int last_error_number_ = 0;
    ssize_t last_written_bytes_ = 0;
    uint64_t last_write_monotonic_ns_ = 0;
    bool enabled_ = true;
    size_t segment_cap_ = kSegmentCap;
    size_t count_ = 0, ihl_ = 0, doff_ = 0, gso_size_ = 0;
    bool pending_psh_ = false;
    uint64_t started_ns_ = 0;
    uint32_t next_seq_ = 0;
    uint8_t tos_ = 0, ttl_ = 0, df_ = 0;
    std::array<uint8_t, 8> flow_{};
    std::array<uint8_t, 12> tcp_fixed_{};
    std::array<uint8_t, 40> ip_options_{};
    std::array<uint8_t, 40> tcp_options_{};
    static constexpr size_t kMaxHeaderBytes = 120; // IPv4 IHL (60) + TCP data offset (60)
    std::array<std::array<uint8_t, kMaxHeaderBytes>, kMaxSegmentCap> headers_{};
    std::array<std::array<uint8_t, kMaxPacketBytes>, kMaxSegmentCap> tails_{};
    std::array<size_t, kMaxSegmentCap> header_sizes_{};
    std::array<size_t, kMaxSegmentCap> payload_sizes_{};
    std::array<size_t, kMaxSegmentCap> payload_offsets_{};
    std::array<size_t, kMaxSegmentCap> tail_sizes_{};
    std::array<size_t, kMaxSegmentCap> packet_sizes_{};
    std::array<RetainedPacketOwner, kMaxSegmentCap> owners_{};
    std::array<bool, kMaxSegmentCap> checksum_partial_{};
    std::array<size_t, kMaxSegmentCap> checksum_start_{};
    std::array<const uint8_t*, kMaxSegmentCap> payload_ptrs_{};
    std::array<iovec, kMaxSegmentCap + 1> iovecs_{};
    int iov_count_ = 0;
    size_t payload_total_ = 0;
    std::array<uint8_t, kVirtioHeaderBytes + kMaxPacketBytes> ordinary_{};
    std::vector<uint8_t> superpacket_;
};

// Decodes coalescer events for one synchronous Push() call. The persistent
// snapshot is committed only when that Push() returns false, so it describes
// the terminal write failure rather than a recoverable negative GSO attempt.
// The caller serializes BeginPush(), OnEvent(), and EndPush() with the
// coalescer. Rendering may run on another thread, so access is synchronized.
class TunGsoFirstPushFailure final {
public:
    enum class Kind : uint8_t {
        None,
        Ordinary,
        Gso,
    };

    struct Precursor final {
        bool present = false;
        int error_number = 0;
        size_t requested_bytes = 0;
        ssize_t written_bytes = 0;
        uint64_t monotonic_ns = 0;
    };

    struct Snapshot final {
        Kind kind = Kind::None;
        TunGsoCoalescer::WriteOutcome outcome = TunGsoCoalescer::WriteOutcome::None;
        TunGsoCoalescer::RejectionReason rejection = TunGsoCoalescer::RejectionReason::None;
        TunGsoCoalescer::FlushReason flush_reason = TunGsoCoalescer::FlushReason::Explicit;
        size_t packet_bytes = 0;
        size_t frame_bytes = 0;
        size_t segments = 0;
        uint64_t hold_ns = 0;
        bool negative_fallback = false;
        int error_number = 0;
        ssize_t written_bytes = 0;
        uint64_t monotonic_ns = 0;
        Precursor precursor;
        TunGsoCoalescer::PacketShape packet_shape;
    };

    void BeginPush() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        current_rejection_ = TunGsoCoalescer::RejectionReason::None;
        current_packet_shape_ = {};
        fallback_ordinary_writes_pending_ = 0;
        current_terminal_ = {};
        current_precursor_ = {};
    }

    void OnEvent(const TunGsoCoalescer::Event& event) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (event.kind == TunGsoCoalescer::Event::Kind::RejectedPacket) {
            current_rejection_ = event.rejection;
            current_packet_shape_ = event.packet_shape;
            return;
        }
        if (event.kind == TunGsoCoalescer::Event::Kind::NegativeFallback) {
            fallback_ordinary_writes_pending_ = event.segments;
            return;
        }
        if (event.kind == TunGsoCoalescer::Event::Kind::GsoWrite &&
            event.outcome == TunGsoCoalescer::WriteOutcome::NegativeFailure &&
            !current_precursor_.present) {
            current_precursor_ = {true, event.error_number, event.frame_bytes,
                event.written_bytes, event.monotonic_ns};
            return;
        }

        const bool is_ordinary = event.kind == TunGsoCoalescer::Event::Kind::OrdinaryWrite;
        const bool negative_fallback = is_ordinary && fallback_ordinary_writes_pending_ != 0;
        if (is_ordinary && fallback_ordinary_writes_pending_ != 0) {
            --fallback_ordinary_writes_pending_;
        }
        if (current_terminal_.kind != Kind::None) return;
        if (event.kind == TunGsoCoalescer::Event::Kind::GsoWrite &&
            event.outcome == TunGsoCoalescer::WriteOutcome::PartialDelivery) {
            CaptureTerminal(Kind::Gso, event, false);
        }
        else if (is_ordinary && (event.outcome == TunGsoCoalescer::WriteOutcome::NegativeFailure ||
            event.outcome == TunGsoCoalescer::WriteOutcome::PartialDelivery)) {
            CaptureTerminal(Kind::Ordinary, event, negative_fallback);
        }
    }

    // Returns false only for a false Push() without a terminal write event.
    bool EndPush(bool push_succeeded) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        const bool terminal_present = current_terminal_.kind != Kind::None;
        if (!push_succeeded && terminal_present && snapshot_.kind == Kind::None) {
            snapshot_ = current_terminal_;
        }
        current_rejection_ = TunGsoCoalescer::RejectionReason::None;
        current_packet_shape_ = {};
        fallback_ordinary_writes_pending_ = 0;
        current_terminal_ = {};
        current_precursor_ = {};
        return push_succeeded || terminal_present;
    }

    Snapshot GetSnapshot() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return snapshot_;
    }

private:
    void CaptureTerminal(Kind kind, const TunGsoCoalescer::Event& event,
        bool negative_fallback) noexcept {
        const TunGsoCoalescer::RejectionReason rejection =
            event.rejection != TunGsoCoalescer::RejectionReason::None ? event.rejection : current_rejection_;
        const TunGsoCoalescer::PacketShape packet_shape =
            rejection == TunGsoCoalescer::RejectionReason::Mtu ? current_packet_shape_ : TunGsoCoalescer::PacketShape{};
        current_terminal_ = {kind, event.outcome, rejection,
            event.flush_reason, event.packet_bytes, event.frame_bytes, event.segments, event.hold_ns,
            negative_fallback, event.error_number, event.written_bytes, event.monotonic_ns,
            current_precursor_, packet_shape};
    }

    mutable std::mutex mutex_;
    Snapshot snapshot_;
    Snapshot current_terminal_;
    Precursor current_precursor_;
    TunGsoCoalescer::RejectionReason current_rejection_ = TunGsoCoalescer::RejectionReason::None;
    TunGsoCoalescer::PacketShape current_packet_shape_;
    size_t fallback_ordinary_writes_pending_ = 0;
};

} // namespace tap
} // namespace ppp
