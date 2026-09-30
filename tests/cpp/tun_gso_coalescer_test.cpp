#define BOOST_TEST_MODULE tun_gso_coalescer_test
#include <boost/test/included/unit_test.hpp>

#include <linux/ppp/tap/TapGsoCoalescer.h>

#include <cerrno>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {
using ppp::tap::TunGsoCoalescer;

struct Spec { uint16_t payload = 100; uint32_t seq = 1000; uint32_t ack = 7; uint16_t window = 42; bool psh = false; bool control = false; bool tcp_options = false; uint16_t dport = 2; };
std::vector<uint8_t> packet(const Spec& s = {}) {
    const size_t tcp_header = s.tcp_options ? 24 : 20;
    std::vector<uint8_t> p(20 + tcp_header + s.payload, 0);
    p[0] = 0x45; p[2] = static_cast<uint8_t>(p.size() >> 8U); p[3] = static_cast<uint8_t>(p.size()); p[6] = 0x40; p[8] = 64; p[9] = 6;
    p[12] = 10; p[15] = 1; p[16] = 10; p[19] = 2;
    p[20] = 0; p[21] = 1; p[22] = static_cast<uint8_t>(s.dport >> 8U); p[23] = static_cast<uint8_t>(s.dport);
    p[24] = static_cast<uint8_t>(s.seq >> 24U); p[25] = static_cast<uint8_t>(s.seq >> 16U); p[26] = static_cast<uint8_t>(s.seq >> 8U); p[27] = static_cast<uint8_t>(s.seq);
    p[28] = static_cast<uint8_t>(s.ack >> 24U); p[29] = static_cast<uint8_t>(s.ack >> 16U); p[30] = static_cast<uint8_t>(s.ack >> 8U); p[31] = static_cast<uint8_t>(s.ack);
    p[32] = static_cast<uint8_t>((tcp_header / 4U) << 4U); p[33] = static_cast<uint8_t>(0x10 | (s.psh ? 0x08 : 0) | (s.control ? 0x02 : 0));
    p[34] = static_cast<uint8_t>(s.window >> 8U); p[35] = static_cast<uint8_t>(s.window);
    for (size_t i = 40; i < p.size(); ++i) p[i] = static_cast<uint8_t>(i);
    return p;
}
struct Sink {
    enum class GsoFailure { None, Negative, PositiveShort };
    std::vector<std::vector<uint8_t>> writes;
    GsoFailure gso_failure = GsoFailure::None;
    bool ordinary_negative = false;
    bool ordinary_positive_short = false;
    ssize_t operator()(const uint8_t* p, size_t n) {
        writes.emplace_back(p, p + n);
        if (n > 1 && p[1] == VIRTIO_NET_HDR_GSO_TCPV4) {
            if (gso_failure == GsoFailure::Negative) {
                errno = EIO;
                return -1;
            }
            if (gso_failure == GsoFailure::PositiveShort) return static_cast<ssize_t>(n - 1);
        }
        if (ordinary_negative) {
            errno = ENOSPC;
            return -1;
        }
        if (ordinary_positive_short) return static_cast<ssize_t>(n - 1);
        return static_cast<ssize_t>(n);
    }
};
uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>(p[0] << 8U | p[1]); }
uint32_t checksum_sum(const uint8_t* p, size_t n, uint32_t value = 0) {
    while (n >= 2) { value += be16(p); p += 2; n -= 2; }
    return n == 0 ? value : value + static_cast<uint16_t>(p[0] << 8U);
}
uint16_t fold_checksum(uint32_t value) {
    while (value >> 16U) value = (value & 0xffffU) + (value >> 16U);
    return static_cast<uint16_t>(~value);
}
}

BOOST_AUTO_TEST_CASE(cap_four_builds_one_tcpv4_gso_frame) {
    Sink sink; TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); });
    for (int i = 0; i != 4; ++i) BOOST_REQUIRE(c.Push(packet({.seq = static_cast<uint32_t>(1000 + i * 100)}).data(), 140, 1000 + i));
    BOOST_REQUIRE_EQUAL(sink.writes.size(), 1U);
    const auto& frame = sink.writes.front();
    BOOST_TEST(frame[0] == VIRTIO_NET_HDR_F_NEEDS_CSUM);
    BOOST_TEST(frame[1] == VIRTIO_NET_HDR_GSO_TCPV4);
    BOOST_TEST(frame[4] == 100U); // little-endian virtio gso_size
    BOOST_TEST(frame[5] == 0U);
    BOOST_TEST(be16(frame.data() + 12) == 440U);

    // Match the successful kernel probe: TUN_F_CSUM receives the
    // uncomplemented pseudo-header seed, not a finalized TCP checksum.
    const uint8_t* ip = frame.data() + TunGsoCoalescer::kVirtioHeaderBytes;
    const uint8_t* tcp = ip + 20;
    const size_t tcp_bytes = be16(ip + 2) - 20;
    const uint8_t pseudo[] = {0, 6, static_cast<uint8_t>(tcp_bytes >> 8U), static_cast<uint8_t>(tcp_bytes)};
    const uint16_t expected_partial = static_cast<uint16_t>(~fold_checksum(checksum_sum(pseudo, sizeof(pseudo), checksum_sum(ip + 12, 8))));
    BOOST_TEST(be16(tcp + 16) == expected_partial);
}

BOOST_AUTO_TEST_CASE(retained_owner_payloads_are_written_as_iovecs) {
    std::vector<uint8_t> frame;
    const auto first = packet({.payload = 100, .seq = 1000});
    const auto second = packet({.payload = 100, .seq = 1100});
    auto first_storage = std::make_shared<std::vector<uint8_t>>(first);
    auto second_storage = std::make_shared<std::vector<uint8_t>>(second);
    const uint8_t* first_data = first_storage->data();
    const uint8_t* second_data = second_storage->data();
    std::weak_ptr<std::vector<uint8_t>> first_lifetime = first_storage;
    std::weak_ptr<std::vector<uint8_t>> second_lifetime = second_storage;
    bool vectored = false;
    const auto vectored_writer = [&](const iovec* iov, int count, size_t total) -> ssize_t {
        vectored = true;
        BOOST_REQUIRE_EQUAL(count, 3);
        BOOST_TEST(iov[1].iov_base == first_data + 40);
        BOOST_TEST(iov[2].iov_base == second_data + 40);
        frame.clear();
        for (int i = 0; i < count; ++i) {
            const auto* bytes = static_cast<const uint8_t*>(iov[i].iov_base);
            frame.insert(frame.end(), bytes, bytes + iov[i].iov_len);
        }
        BOOST_REQUIRE_EQUAL(frame.size(), total);
        return static_cast<ssize_t>(frame.size());
    };
    TunGsoCoalescer coalescer([](const uint8_t*, size_t n) { return static_cast<ssize_t>(n); },
        {}, vectored_writer);

    BOOST_REQUIRE(coalescer.PushOwned(first_storage->data(), first.size(),
        ppp::tap::RetainedPacketOwner(first_storage), 1000));
    BOOST_REQUIRE(coalescer.PushOwned(second_storage->data(), second.size(),
        ppp::tap::RetainedPacketOwner(second_storage), 1001));
    first_storage.reset();
    second_storage.reset();
    BOOST_REQUIRE(!first_lifetime.expired());
    BOOST_REQUIRE(!second_lifetime.expired());
    BOOST_REQUIRE(coalescer.Flush(TunGsoCoalescer::FlushReason::Explicit, 1002));
    BOOST_TEST(vectored);
    BOOST_TEST(frame[1] == VIRTIO_NET_HDR_GSO_TCPV4);
    BOOST_TEST(be16(frame.data() + TunGsoCoalescer::kVirtioHeaderBytes + 2) == 240U);
    BOOST_TEST(std::equal(first.begin() + 40, first.end(), frame.begin() + 50));
    BOOST_TEST(std::equal(second.begin() + 40, second.end(), frame.begin() + 150));
    BOOST_TEST(first_lifetime.expired());
    BOOST_TEST(second_lifetime.expired());
}

BOOST_AUTO_TEST_CASE(runtime_segment_cap_can_reach_maximum_without_overflow) {
    ::setenv("OPENPPP2_TAP_GSO_SEGMENTS", "48", 1);
    Sink sink;
    TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); });
    for (size_t i = 0; i != TunGsoCoalescer::kMaxSegmentCap; ++i) {
        const auto value = packet({.payload = 1460, .seq = static_cast<uint32_t>(1000 + i * 1460)});
        BOOST_REQUIRE(c.Push(value.data(), value.size(), 1000 + i));
    }
    BOOST_REQUIRE(c.Flush());
    ::unsetenv("OPENPPP2_TAP_GSO_SEGMENTS");

    // 45 * 1460 + 40 exceeds IPv4's 16-bit total_length. Even with cap 48,
    // the coalescer must flush the largest legal first frame and continue.
    BOOST_REQUIRE_EQUAL(sink.writes.size(), 2U);
    const auto verify_ipv4_length = [](const std::vector<uint8_t>& frame) {
        BOOST_TEST(frame[1] == VIRTIO_NET_HDR_GSO_TCPV4);
        BOOST_REQUIRE(frame.size() >= TunGsoCoalescer::kVirtioHeaderBytes + 20U);
        const uint8_t* ip = frame.data() + TunGsoCoalescer::kVirtioHeaderBytes;
        const size_t ipv4_total = be16(ip + 2);
        BOOST_TEST(ipv4_total <= UINT16_MAX);
        BOOST_TEST(frame.size() == TunGsoCoalescer::kVirtioHeaderBytes + ipv4_total);
    };
    verify_ipv4_length(sink.writes[0]);
    verify_ipv4_length(sink.writes[1]);
    BOOST_TEST(be16(sink.writes[0].data() + TunGsoCoalescer::kVirtioHeaderBytes + 2) == 64280U);
    BOOST_TEST(be16(sink.writes[1].data() + TunGsoCoalescer::kVirtioHeaderBytes + 2) == 5880U);
}

BOOST_AUTO_TEST_CASE(xtcp_dl_profile_defaults_gso_cap_but_explicit_cap_wins) {
    const char* old_profile = std::getenv("OPENPPP2_XTCP_DL_GSO_PERF_PROFILE");
    const std::string saved_profile = old_profile != nullptr ? old_profile : "";
    const bool had_profile = old_profile != nullptr;
    const char* old_cap = std::getenv("OPENPPP2_TAP_GSO_SEGMENTS");
    const std::string saved_cap = old_cap != nullptr ? old_cap : "";
    const bool had_cap = old_cap != nullptr;

    BOOST_REQUIRE_EQUAL(::unsetenv("OPENPPP2_TAP_GSO_SEGMENTS"), 0);
    BOOST_REQUIRE_EQUAL(::setenv("OPENPPP2_XTCP_DL_GSO_PERF_PROFILE", "1", 1), 0);
    BOOST_TEST(TunGsoCoalescer::SegmentCap() == TunGsoCoalescer::kMaxSegmentCap);

    BOOST_REQUIRE_EQUAL(::setenv("OPENPPP2_TAP_GSO_SEGMENTS", "8", 1), 0);
    BOOST_TEST(TunGsoCoalescer::SegmentCap() == 8U);

    if (had_cap) ::setenv("OPENPPP2_TAP_GSO_SEGMENTS", saved_cap.c_str(), 1);
    else ::unsetenv("OPENPPP2_TAP_GSO_SEGMENTS");
    if (had_profile) ::setenv("OPENPPP2_XTCP_DL_GSO_PERF_PROFILE", saved_profile.c_str(), 1);
    else ::unsetenv("OPENPPP2_XTCP_DL_GSO_PERF_PROFILE");
}

BOOST_AUTO_TEST_CASE(disabled_merge_writes_one_ordinary_vnet_frame_immediately) {
    Sink sink; TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); });
    const auto original = packet();

    BOOST_REQUIRE(c.WriteOrdinaryFrame(original.data(), original.size()));
    BOOST_REQUIRE_EQUAL(sink.writes.size(), 1U);
    const auto& frame = sink.writes.front();
    BOOST_TEST(frame.size() == original.size() + TunGsoCoalescer::kVirtioHeaderBytes);
    for (size_t i = 0; i < TunGsoCoalescer::kVirtioHeaderBytes; ++i) BOOST_TEST(frame[i] == 0U);
    BOOST_TEST(std::memcmp(frame.data() + TunGsoCoalescer::kVirtioHeaderBytes, original.data(), original.size()) == 0);
    BOOST_TEST(!c.has_pending());
    BOOST_TEST(c.enabled());
}

BOOST_AUTO_TEST_CASE(partial_checksum_survives_singleton_ordinary_vnet_flush) {
    Sink sink;
    TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); });
    auto value = packet();
    auto storage = std::make_shared<std::vector<uint8_t>>(value);
    ppp::tap::RetainedPacketOwner owner(std::shared_ptr<uint8_t>(storage, storage->data()), true);
    BOOST_REQUIRE(c.PushOwned(value.data(), value.size(), std::move(owner), 1000));
    BOOST_REQUIRE(c.Flush(TunGsoCoalescer::FlushReason::Explicit, 1001));
    BOOST_REQUIRE_EQUAL(sink.writes.size(), 1U);
    const auto& frame = sink.writes.front();
    BOOST_TEST(frame[0] == VIRTIO_NET_HDR_F_NEEDS_CSUM);
    BOOST_TEST(frame[1] == VIRTIO_NET_HDR_GSO_NONE);
    BOOST_TEST(frame[6] == 20U);
    BOOST_TEST(frame[7] == 0U);
    BOOST_TEST(frame[8] == 16U);
    BOOST_TEST(frame[9] == 0U);
    BOOST_TEST(std::memcmp(frame.data() + TunGsoCoalescer::kVirtioHeaderBytes,
        value.data(), value.size()) == 0);
}

BOOST_AUTO_TEST_CASE(hold_and_short_tail_flush) {
    Sink sink; TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); });
    auto a = packet(); BOOST_REQUIRE(c.Push(a.data(), a.size(), 1000));
    BOOST_TEST(c.has_pending());
    // TapLinux's hold-timer completion invokes this seam while holding its GSO lock.
    BOOST_REQUIRE(c.FlushExpired(1000 + TunGsoCoalescer::kHoldNs));
    BOOST_TEST(!c.has_pending());
    BOOST_TEST(sink.writes.size() == 1U); // singleton ordinary VNET frame
    auto b = packet(); auto tail = packet({.payload = 30, .seq = 1100});
    BOOST_REQUIRE(c.Push(b.data(), b.size(), 3000)); BOOST_REQUIRE(c.Push(tail.data(), tail.size(), 3001));
    BOOST_TEST(sink.writes.size() == 2U);
    BOOST_TEST(sink.writes.back()[1] == VIRTIO_NET_HDR_GSO_TCPV4);
}

BOOST_AUTO_TEST_CASE(configurable_hold_window) {
    Sink sink;
    TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); }, {}, {}, true, true, 200000);
    BOOST_TEST(c.hold_ns() == 200000U);
    auto a = packet();
    BOOST_REQUIRE(c.Push(a.data(), a.size(), 1000));
    BOOST_TEST(c.FlushExpired(200999));
    BOOST_TEST(c.has_pending());
    BOOST_REQUIRE(c.FlushExpired(201000));
    BOOST_TEST(!c.has_pending());
    BOOST_TEST(sink.writes.size() == 1U);
}

BOOST_AUTO_TEST_CASE(incompatible_packets_preserve_order_as_ordinary_frames) {
    Sink sink; TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); });
    auto first = packet(); auto psh = packet({.seq = 1100, .psh = true}); auto ctl = packet({.seq = 1200, .control = true});
    auto flow = packet({.seq = 1300, .dport = 3}); auto gap = packet({.seq = 1500});
    BOOST_REQUIRE(c.Push(first.data(), first.size(), 1)); BOOST_REQUIRE(c.Push(psh.data(), psh.size(), 2));
    BOOST_REQUIRE(c.Push(ctl.data(), ctl.size(), 3)); BOOST_REQUIRE(c.Push(flow.data(), flow.size(), 4)); BOOST_REQUIRE(c.Push(gap.data(), gap.size(), 5));
    BOOST_REQUIRE(c.Flush());
    BOOST_TEST(sink.writes.size() == 4U);
    BOOST_TEST(sink.writes[0][1] == VIRTIO_NET_HDR_GSO_TCPV4);
    for (size_t i = 1; i < sink.writes.size(); ++i) BOOST_TEST(sink.writes[i][1] == VIRTIO_NET_HDR_GSO_NONE);
}

BOOST_AUTO_TEST_CASE(psh_is_merged_only_as_the_final_gso_segment) {
    Sink sink; TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); });
    const auto first = packet();
    const auto psh = packet({.seq = 1100, .psh = true});
    BOOST_REQUIRE(c.Push(first.data(), first.size(), 1));
    BOOST_TEST(c.has_pending());
    BOOST_REQUIRE(c.Push(psh.data(), psh.size(), 2));
    BOOST_TEST(!c.has_pending());
    BOOST_REQUIRE_EQUAL(sink.writes.size(), 1U);
    const auto& gso = sink.writes.front();
    BOOST_TEST(gso[1] == VIRTIO_NET_HDR_GSO_TCPV4);
    BOOST_TEST((gso[TunGsoCoalescer::kVirtioHeaderBytes + 20U + 13U] & 0x08U) != 0U);
    BOOST_TEST(gso.size() == TunGsoCoalescer::kVirtioHeaderBytes + 40U + 200U);

    // A later segment starts a fresh run and cannot be merged past PSH.
    const auto later = packet({.seq = 1200});
    BOOST_REQUIRE(c.Push(later.data(), later.size(), 3));
    BOOST_TEST(c.has_pending());
    BOOST_REQUIRE(c.Flush());
    BOOST_REQUIRE_EQUAL(sink.writes.size(), 2U);
    BOOST_TEST(sink.writes.back()[1] == VIRTIO_NET_HDR_GSO_NONE);
}

BOOST_AUTO_TEST_CASE(ack_window_options_equivalent_changes_break_runs) {
    Sink sink; TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); });
    auto first = packet(); auto ack = packet({.seq = 1100, .ack = 8}); auto window = packet({.seq = 1200, .window = 43});
    auto options = packet({.seq = 1300, .tcp_options = true});
    BOOST_REQUIRE(c.Push(first.data(), first.size(), 1)); BOOST_REQUIRE(c.Push(ack.data(), ack.size(), 2)); BOOST_REQUIRE(c.Push(window.data(), window.size(), 3)); BOOST_REQUIRE(c.Push(options.data(), options.size(), 4)); BOOST_REQUIRE(c.Flush());
    BOOST_TEST(sink.writes.size() == 4U);
}

BOOST_AUTO_TEST_CASE(negative_gso_write_falls_back_to_exact_original_byte_order) {
    Sink sink; sink.gso_failure = Sink::GsoFailure::Negative; TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); });
    std::vector<std::vector<uint8_t>> originals;
    for (int i = 0; i != 4; ++i) { originals.push_back(packet({.seq = static_cast<uint32_t>(1000 + i * 100)})); BOOST_REQUIRE(c.Push(originals.back().data(), originals.back().size(), i)); }
    BOOST_TEST(!c.enabled());
    BOOST_REQUIRE_EQUAL(sink.writes.size(), 5U);
    for (size_t i = 0; i != originals.size(); ++i) {
        BOOST_TEST(sink.writes[i + 1].size() == originals[i].size() + TunGsoCoalescer::kVirtioHeaderBytes);
        BOOST_TEST(std::memcmp(sink.writes[i + 1].data() + TunGsoCoalescer::kVirtioHeaderBytes, originals[i].data(), originals[i].size()) == 0);
    }
}

BOOST_AUTO_TEST_CASE(negative_gso_fallback_preserves_packet_trailing_bytes) {
    Sink sink;
    sink.gso_failure = Sink::GsoFailure::Negative;
    TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); });
    std::vector<std::vector<uint8_t>> originals;
    for (int i = 0; i != 4; ++i) {
        originals.push_back(packet({.seq = static_cast<uint32_t>(1000 + i * 100)}));
        originals.back().insert(originals.back().end(), {0xA0, static_cast<uint8_t>(i), 0x5A});
        BOOST_REQUIRE(c.Push(originals.back().data(), originals.back().size(), i));
    }

    BOOST_REQUIRE_EQUAL(sink.writes.size(), 5U);
    for (size_t i = 0; i != originals.size(); ++i) {
        BOOST_REQUIRE_EQUAL(sink.writes[i + 1].size(), originals[i].size() + TunGsoCoalescer::kVirtioHeaderBytes);
        BOOST_TEST(std::memcmp(sink.writes[i + 1].data() + TunGsoCoalescer::kVirtioHeaderBytes,
            originals[i].data(), originals[i].size()) == 0);
    }
}

BOOST_AUTO_TEST_CASE(positive_short_gso_write_never_replays_originals) {
    Sink sink; sink.gso_failure = Sink::GsoFailure::PositiveShort; TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); });
    for (int i = 0; i != 4; ++i) {
        const auto segment = packet({.seq = static_cast<uint32_t>(1000 + i * 100)});
        if (i == 3) BOOST_TEST(!c.Push(segment.data(), segment.size(), i));
        else BOOST_REQUIRE(c.Push(segment.data(), segment.size(), i));
    }
    BOOST_TEST(!c.enabled());
    BOOST_TEST(static_cast<int>(c.last_write_outcome()) == static_cast<int>(TunGsoCoalescer::WriteOutcome::PartialDelivery));
    BOOST_TEST(sink.writes.size() == 1U);
    BOOST_TEST(sink.writes.front()[1] == VIRTIO_NET_HDR_GSO_TCPV4);
}

BOOST_AUTO_TEST_CASE(positive_short_ordinary_write_is_not_success) {
    Sink sink; sink.ordinary_positive_short = true; TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); });
    const auto original = packet();
    BOOST_TEST(!c.WriteOrdinaryFrame(original.data(), original.size()));
    BOOST_TEST(static_cast<int>(c.last_write_outcome()) == static_cast<int>(TunGsoCoalescer::WriteOutcome::PartialDelivery));
    BOOST_TEST(sink.writes.size() == 1U);
}

BOOST_AUTO_TEST_CASE(first_push_failure_ignores_negative_gso_when_ordinary_fallback_succeeds) {
    Sink sink; sink.gso_failure = Sink::GsoFailure::Negative;
    ppp::tap::TunGsoFirstPushFailure failure;
    TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); },
        [&failure](const TunGsoCoalescer::Event& event) { failure.OnEvent(event); });
    for (int i = 0; i != 4; ++i) {
        const auto segment = packet({.seq = static_cast<uint32_t>(1000 + i * 100)});
        failure.BeginPush();
        const bool ok = c.Push(segment.data(), segment.size(), i);
        BOOST_REQUIRE(ok);
        BOOST_TEST(failure.EndPush(ok));
    }
    BOOST_TEST(static_cast<int>(failure.GetSnapshot().kind) == static_cast<int>(ppp::tap::TunGsoFirstPushFailure::Kind::None));
}

BOOST_AUTO_TEST_CASE(first_push_failure_records_terminal_ordinary_after_negative_gso) {
    Sink sink; sink.gso_failure = Sink::GsoFailure::Negative; sink.ordinary_negative = true;
    ppp::tap::TunGsoFirstPushFailure failure;
    TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); },
        [&failure](const TunGsoCoalescer::Event& event) { failure.OnEvent(event); });
    for (int i = 0; i != 4; ++i) {
        const auto segment = packet({.seq = static_cast<uint32_t>(1000 + i * 100)});
        failure.BeginPush();
        const bool ok = c.Push(segment.data(), segment.size(), i);
        if (i == 3) {
            BOOST_TEST(!ok);
            BOOST_TEST(failure.EndPush(ok)); // false Push always has a terminal event
        } else {
            BOOST_REQUIRE(ok);
            BOOST_TEST(failure.EndPush(ok));
        }
    }
    const auto snapshot = failure.GetSnapshot();
    BOOST_TEST(static_cast<int>(snapshot.kind) == static_cast<int>(ppp::tap::TunGsoFirstPushFailure::Kind::Ordinary));
    BOOST_TEST(static_cast<int>(snapshot.outcome) == static_cast<int>(TunGsoCoalescer::WriteOutcome::NegativeFailure));
    BOOST_TEST(snapshot.negative_fallback);
    BOOST_TEST(snapshot.segments == 1U);
    BOOST_TEST(snapshot.packet_bytes == 140U);
    BOOST_TEST(snapshot.frame_bytes == 150U);
    BOOST_TEST(snapshot.error_number == ENOSPC);
    BOOST_TEST(snapshot.written_bytes == -1);
    BOOST_TEST(snapshot.monotonic_ns != 0U);
    BOOST_TEST(snapshot.precursor.present);
    BOOST_TEST(snapshot.precursor.error_number == EIO);
    BOOST_TEST(snapshot.precursor.requested_bytes == 450U);
    BOOST_TEST(snapshot.precursor.written_bytes == -1);
    BOOST_TEST(snapshot.precursor.monotonic_ns != 0U);
}

BOOST_AUTO_TEST_CASE(first_push_failure_records_terminal_partial_gso_write) {
    Sink sink; sink.gso_failure = Sink::GsoFailure::PositiveShort;
    ppp::tap::TunGsoFirstPushFailure failure;
    TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); },
        [&failure](const TunGsoCoalescer::Event& event) { failure.OnEvent(event); });
    for (int i = 0; i != 4; ++i) {
        const auto segment = packet({.seq = static_cast<uint32_t>(1000 + i * 100)});
        failure.BeginPush();
        const bool ok = c.Push(segment.data(), segment.size(), i);
        if (i == 3) {
            BOOST_TEST(!ok);
            BOOST_TEST(failure.EndPush(ok));
        } else {
            BOOST_REQUIRE(ok);
            BOOST_TEST(failure.EndPush(ok));
        }
    }
    const auto snapshot = failure.GetSnapshot();
    BOOST_TEST(static_cast<int>(snapshot.kind) == static_cast<int>(ppp::tap::TunGsoFirstPushFailure::Kind::Gso));
    BOOST_TEST(static_cast<int>(snapshot.outcome) == static_cast<int>(TunGsoCoalescer::WriteOutcome::PartialDelivery));
    BOOST_TEST(!snapshot.negative_fallback);
    BOOST_TEST(snapshot.segments == 4U);
    BOOST_TEST(snapshot.packet_bytes == 560U);
    BOOST_TEST(snapshot.frame_bytes == 450U); // one VNET/IP/TCP header plus four payloads
    BOOST_TEST(snapshot.error_number == 0);
    BOOST_TEST(snapshot.written_bytes == 449);
    BOOST_TEST(snapshot.written_bytes < static_cast<ssize_t>(snapshot.frame_bytes));
    BOOST_TEST(!snapshot.precursor.present);
}

BOOST_AUTO_TEST_CASE(first_push_failure_records_terminal_psh_ordinary_write) {
    Sink sink; sink.ordinary_negative = true;
    ppp::tap::TunGsoFirstPushFailure failure;
    TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); },
        [&failure](const TunGsoCoalescer::Event& event) { failure.OnEvent(event); });
    const auto psh = packet({.psh = true});
    failure.BeginPush();
    const bool ok = c.Push(psh.data(), psh.size(), 1);
    BOOST_TEST(!ok);
    BOOST_TEST(failure.EndPush(ok));
    const auto snapshot = failure.GetSnapshot();
    BOOST_TEST(static_cast<int>(snapshot.kind) == static_cast<int>(ppp::tap::TunGsoFirstPushFailure::Kind::Ordinary));
    BOOST_TEST(static_cast<int>(snapshot.outcome) == static_cast<int>(TunGsoCoalescer::WriteOutcome::NegativeFailure));
    BOOST_TEST(static_cast<int>(snapshot.rejection) == static_cast<int>(TunGsoCoalescer::RejectionReason::None));
    BOOST_TEST(static_cast<int>(snapshot.flush_reason) == static_cast<int>(TunGsoCoalescer::FlushReason::Psh));
    BOOST_TEST(!snapshot.negative_fallback);
    BOOST_TEST(snapshot.error_number == ENOSPC);
    BOOST_TEST(snapshot.written_bytes == -1);
    BOOST_TEST(!snapshot.precursor.present);
}

BOOST_AUTO_TEST_CASE(first_push_failure_records_mtu_packet_shape_from_ipv4_tcp_packet) {
    Sink sink;
    ppp::tap::TunGsoFirstPushFailure failure;
    TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); },
        [&failure](const TunGsoCoalescer::Event& event) { failure.OnEvent(event); });
    const auto oversized = packet({.payload = 1472}); // IPv4 total and supplied size are 1512.

    failure.BeginPush();
    const bool ok = c.Push(oversized.data(), oversized.size(), 1);
    BOOST_TEST(!ok);
    BOOST_TEST(failure.EndPush(ok));
    const auto snapshot = failure.GetSnapshot();
    const auto& shape = snapshot.packet_shape;
    BOOST_TEST(static_cast<int>(snapshot.rejection) == static_cast<int>(TunGsoCoalescer::RejectionReason::Mtu));
    BOOST_TEST(snapshot.packet_bytes == 1512U);
    BOOST_TEST(snapshot.frame_bytes == 0U);
    BOOST_TEST(snapshot.written_bytes == 0);
    BOOST_TEST(snapshot.error_number == 0);
    BOOST_TEST(!snapshot.precursor.present);
    BOOST_TEST(shape.parsed);
    BOOST_TEST(shape.supplied_bytes == 1512U);
    BOOST_TEST(shape.ipv4_total_length == 1512U);
    BOOST_TEST(shape.ipv4_ihl_bytes == 20U);
    BOOST_TEST(shape.tcp_data_offset_bytes == 20U);
    BOOST_TEST(shape.tcp_payload_bytes == 1472U);
    BOOST_TEST(shape.ipv4_version == 4U);
    BOOST_TEST(shape.ipv4_protocol == 6U);
    BOOST_TEST(shape.ipv4_fragment_flags == 0x4000U);
    BOOST_TEST(shape.ipv4_df);
    BOOST_TEST(shape.tcp_flags == 0x10U);
    BOOST_TEST(shape.max_guard_bytes == TunGsoCoalescer::kMaxPacketBytes);
    BOOST_TEST(shape.excess_bytes == 12U);
}

BOOST_AUTO_TEST_CASE(first_push_failure_uses_supplied_length_not_ipv4_total_for_mtu_shape) {
    Sink sink;
    ppp::tap::TunGsoFirstPushFailure failure;
    TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); },
        [&failure](const TunGsoCoalescer::Event& event) { failure.OnEvent(event); });
    auto trailing_bytes = packet({.payload = 1460}); // IPv4 total is 1500.
    trailing_bytes.resize(1512, 0); // Supplied buffer has 12 non-packet trailing bytes.

    failure.BeginPush();
    const bool ok = c.Push(trailing_bytes.data(), trailing_bytes.size(), 1);
    BOOST_TEST(!ok);
    BOOST_TEST(failure.EndPush(ok));
    const auto snapshot = failure.GetSnapshot();
    const auto& shape = snapshot.packet_shape;
    BOOST_TEST(static_cast<int>(snapshot.rejection) == static_cast<int>(TunGsoCoalescer::RejectionReason::Mtu));
    BOOST_TEST(shape.parsed);
    BOOST_TEST(shape.supplied_bytes == 1512U);
    BOOST_TEST(shape.ipv4_total_length == 1500U);
    BOOST_TEST(shape.tcp_payload_bytes == 1460U);
    BOOST_TEST(shape.max_guard_bytes == 1500U);
    BOOST_TEST(shape.excess_bytes == 12U);
}

BOOST_AUTO_TEST_CASE(first_push_failure_marks_malformed_mtu_shape_unparsed) {
    Sink sink;
    ppp::tap::TunGsoFirstPushFailure failure;
    TunGsoCoalescer c([&sink](const uint8_t* p, size_t n) { return sink(p, n); },
        [&failure](const TunGsoCoalescer::Event& event) { failure.OnEvent(event); });
    std::vector<uint8_t> malformed(1512, 0);

    failure.BeginPush();
    const bool ok = c.Push(malformed.data(), malformed.size(), 1);
    BOOST_TEST(!ok);
    BOOST_TEST(failure.EndPush(ok));
    const auto snapshot = failure.GetSnapshot();
    const auto& shape = snapshot.packet_shape;
    BOOST_TEST(static_cast<int>(snapshot.rejection) == static_cast<int>(TunGsoCoalescer::RejectionReason::Mtu));
    BOOST_TEST(!shape.parsed);
    BOOST_TEST(shape.supplied_bytes == 1512U);
    BOOST_TEST(shape.ipv4_total_length == 0U);
    BOOST_TEST(shape.ipv4_ihl_bytes == 0U);
    BOOST_TEST(shape.tcp_data_offset_bytes == 0U);
    BOOST_TEST(shape.tcp_payload_bytes == 0U);
    BOOST_TEST(shape.ipv4_version == 0U);
    BOOST_TEST(shape.ipv4_protocol == 0U);
    BOOST_TEST(shape.ipv4_fragment_flags == 0U);
    BOOST_TEST(!shape.ipv4_df);
    BOOST_TEST(shape.tcp_flags == 0U);
    BOOST_TEST(shape.max_guard_bytes == 1500U);
    BOOST_TEST(shape.excess_bytes == 12U);
}
