#define BOOST_TEST_MODULE tun_gso_mergeability_test
#include <boost/test/included/unit_test.hpp>

#include <linux/ppp/tap/TapGsoCoalescer.h>
#include <linux/ppp/tap/TapGsoMergeabilityAnalyzer.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace {
using ppp::tap::TunGsoMergeabilityAnalyzer;

/// Builds one IPv4+TCP packet the way the VPN stack hands it to TapLinux::Output.
struct PacketSpec {
    uint16_t payload = 1460;
    uint32_t seq = 1000;
    uint32_t ack = 5000;
    uint16_t sport = 40000;
    uint16_t dport = 40001;
    uint8_t ttl = 64;
    uint8_t tos = 0;
    bool df = true;
    bool psh = false;
    uint8_t fin_syn_rst = 0;       // FIN|SYN|RST bits, default none
    uint16_t window = 65535;
    uint16_t urg = 0;
    std::vector<uint8_t> ip_options;
    std::vector<uint8_t> tcp_options;
    bool fragmented = false;
    bool ipv6 = false;
    uint8_t protocol = 6;          // TCP
    bool ip_total_length_short = false;
};

std::vector<uint8_t> build(const PacketSpec& spec) {
    if (spec.ipv6) return std::vector<uint8_t>(40 + spec.payload, 0x60);
    const size_t ihl = 20 + spec.ip_options.size();
    const size_t doff = 20 + spec.tcp_options.size();
    std::vector<uint8_t> packet(ihl + doff + spec.payload, 0);
    uint8_t* ip = packet.data();
    ip[0] = 0x40 | (ihl / 4);
    ip[1] = spec.tos;
    const uint16_t total = spec.ip_total_length_short ? static_cast<uint16_t>(ihl) : static_cast<uint16_t>(packet.size());
    ip[2] = static_cast<uint8_t>(total >> 8U);
    ip[3] = static_cast<uint8_t>(total);
    ip[4] = 0x12; ip[5] = 0x34;
    ip[6] = static_cast<uint8_t>((spec.df ? 0x40 : 0) | (spec.fragmented ? 0x20 : 0));
    ip[8] = spec.ttl;
    ip[9] = spec.protocol;
    ip[12] = 10; ip[13] = 42; ip[14] = 0; ip[15] = 1;
    ip[16] = 10; ip[17] = 42; ip[18] = 0; ip[19] = 2;
    std::memcpy(ip + 20, spec.ip_options.data(), spec.ip_options.size());
    uint8_t* tcp = packet.data() + ihl;
    tcp[0] = static_cast<uint8_t>(spec.sport >> 8U); tcp[1] = static_cast<uint8_t>(spec.sport);
    tcp[2] = static_cast<uint8_t>(spec.dport >> 8U); tcp[3] = static_cast<uint8_t>(spec.dport);
    tcp[4] = static_cast<uint8_t>(spec.seq >> 24U); tcp[5] = static_cast<uint8_t>(spec.seq >> 16U);
    tcp[6] = static_cast<uint8_t>(spec.seq >> 8U); tcp[7] = static_cast<uint8_t>(spec.seq);
    tcp[8] = static_cast<uint8_t>(spec.ack >> 24U); tcp[9] = static_cast<uint8_t>(spec.ack >> 16U);
    tcp[10] = static_cast<uint8_t>(spec.ack >> 8U); tcp[11] = static_cast<uint8_t>(spec.ack);
    tcp[12] = static_cast<uint8_t>(doff / 4) << 4U;
    tcp[13] = static_cast<uint8_t>(0x10 | (spec.psh ? 0x08 : 0) | spec.fin_syn_rst);
    tcp[14] = static_cast<uint8_t>(spec.window >> 8U); tcp[15] = static_cast<uint8_t>(spec.window);
    tcp[18] = static_cast<uint8_t>(spec.urg >> 8U); tcp[19] = static_cast<uint8_t>(spec.urg);
    std::memcpy(tcp + 20, spec.tcp_options.data(), spec.tcp_options.size());
    for (size_t i = 0; i < spec.payload; ++i) packet[ihl + doff + i] = static_cast<uint8_t>(i);
    return packet;
}

uint64_t sum_break_reason(const TunGsoMergeabilityAnalyzer& analyzer, const char* name) {
    // RenderWindowJson is the only counter readout; parse the single reason.
    const std::string json = analyzer.RenderWindowJson();
    const std::string key = std::string("\"") + name + "\":";
    const size_t at = json.find(key);
    if (at == std::string::npos) return 0;
    return std::strtoull(json.c_str() + at + key.size(), nullptr, 10);
}

uint64_t json_int(const TunGsoMergeabilityAnalyzer& analyzer, const char* key_name) {
    const std::string json = analyzer.RenderWindowJson();
    const std::string key = std::string("\"") + key_name + "\":";
    const size_t at = json.find(key);
    if (at == std::string::npos) return 0;
    return std::strtoull(json.c_str() + at + key.size(), nullptr, 10);
}
} // namespace

// 1+14: two strictly compatible packets form one run of 2.
BOOST_AUTO_TEST_CASE(two_compatible_packets_form_run_of_two) {
    TunGsoMergeabilityAnalyzer a;
    a.ObserveAt(build({}).data(), 1500, 1000);
    a.ObserveAt(build({.seq = 2460}).data(), 1500, 2000);
    a.FinalizeOpenRun();
    BOOST_TEST(sum_break_reason(a, "measurement_end") == 1);
    BOOST_TEST(json_int(a, "strict_eligible_packets") == 2);
}

// 2: production strict-v1 closes at four; 8/16 remain labelled theoretical only.
BOOST_AUTO_TEST_CASE(production_cap_four_and_theoretical_upper_bounds) {
    TunGsoMergeabilityAnalyzer a;
    for (int i = 0; i < 8; ++i) {
        a.ObserveAt(build({.seq = static_cast<uint32_t>(1000 + i * 1460)}).data(), 1500, 1000 + i * 1000);
    }
    a.FinalizeOpenRun();
    const std::string json = a.RenderWindowJson();
    BOOST_TEST(sum_break_reason(a, "cap") == 2);
    BOOST_TEST(json.find("\"4\":{\"runs\":2") != std::string::npos);
    BOOST_TEST(json.find("\"theoretical_upper_bound\":{\"segment_caps\":[8,16]") != std::string::npos);
    BOOST_TEST(json.find("\"theoretical_upper_bound_8\"") != std::string::npos);
}

// 3: a different flow breaks the run with flow_change.
BOOST_AUTO_TEST_CASE(flow_change_breaks_run) {
    TunGsoMergeabilityAnalyzer a;
    a.ObserveAt(build({}).data(), 1500, 1000);
    a.ObserveAt(build({.dport = 40002}).data(), 1500, 2000);
    a.FinalizeOpenRun();
    BOOST_TEST(sum_break_reason(a, "flow_change") == 1);
    BOOST_TEST(sum_break_reason(a, "measurement_end") == 1);
}

// 4+5: sequence gaps and rewinds are distinct exclusive reasons.
BOOST_AUTO_TEST_CASE(seq_gap_and_rewind) {
    TunGsoMergeabilityAnalyzer a;
    a.ObserveAt(build({}).data(), 1500, 1000);
    a.ObserveAt(build({.seq = 1000 + 1460 + 40}).data(), 1500, 2000);
    a.FinalizeOpenRun();
    BOOST_TEST(sum_break_reason(a, "seq_gap") == 1);

    TunGsoMergeabilityAnalyzer b;
    b.ObserveAt(build({}).data(), 1500, 1000);
    b.ObserveAt(build({}).data(), 1500, 2000); // retransmission, same seq
    b.FinalizeOpenRun();
    BOOST_TEST(sum_break_reason(b, "seq_rewind_or_retransmit") == 1);
}

// 6: ACK and window changes break with their own reasons.
BOOST_AUTO_TEST_CASE(ack_and_window_changes) {
    TunGsoMergeabilityAnalyzer a;
    a.ObserveAt(build({}).data(), 1500, 1000);
    a.ObserveAt(build({.seq = 2460, .ack = 5100}).data(), 1500, 2000);
    a.FinalizeOpenRun();
    BOOST_TEST(sum_break_reason(a, "ack_change") == 1);

    TunGsoMergeabilityAnalyzer b;
    b.ObserveAt(build({}).data(), 1500, 1000);
    b.ObserveAt(build({.seq = 2460, .window = static_cast<uint16_t>(65535 - 100)}).data(), 1500, 2000);
    b.FinalizeOpenRun();
    BOOST_TEST(sum_break_reason(b, "window_change") == 1);
}

// 7+8: TCP option and IP header (TOS) changes break with their own reasons.
BOOST_AUTO_TEST_CASE(option_and_header_changes) {
    TunGsoMergeabilityAnalyzer a;
    a.ObserveAt(build({}).data(), 1500, 1000);
    PacketSpec with_options;
    with_options.seq = 2460;
    with_options.tcp_options = {1, 1, 1, 1}; // NOPs keep doff aligned
    with_options.payload = 1456; // keep the IPv4 packet at strict-v1 MTU
    a.ObserveAt(build(with_options).data(), 1500, 2000);
    a.FinalizeOpenRun();
    BOOST_TEST(sum_break_reason(a, "tcp_options_change") == 1);

    TunGsoMergeabilityAnalyzer b;
    b.ObserveAt(build({}).data(), 1500, 1000);
    b.ObserveAt(build({.seq = 2460, .ttl = 63}).data(), 1500, 2000);
    b.FinalizeOpenRun();
    BOOST_TEST(sum_break_reason(b, "ip_header_change") == 1);
}

// 9+10: fragmented and ACK-only packets are ineligible control traffic.
BOOST_AUTO_TEST_CASE(ineligible_fragmented_and_ack_only) {
    TunGsoMergeabilityAnalyzer a;
    a.ObserveAt(build({}).data(), 1500, 1000);
    PacketSpec frag;
    frag.fragmented = true;
    frag.payload = 1460;
    a.ObserveAt(build(frag).data(), 1500, 2000);
    BOOST_TEST(json_int(a, "ineligible_packets") == 1);
    BOOST_TEST(sum_break_reason(a, "fragmented") == 1);

    TunGsoMergeabilityAnalyzer b;
    b.ObserveAt(build({.payload = 0}).data(), 40, 1000);
    BOOST_TEST(json_int(b, "ineligible_packets") == 1);
    BOOST_TEST(sum_break_reason(b, "no_payload") == 0); // nothing was open
}

// 11+12: a short final segment appends, completes the run, and the next same-flow packet starts a new run.
BOOST_AUTO_TEST_CASE(short_tail_then_new_run) {
    TunGsoMergeabilityAnalyzer a;
    a.ObserveAt(build({}).data(), 1500, 1000);
    a.ObserveAt(build({.payload = 600, .seq = 2460}).data(), 640, 2000);
    BOOST_TEST(sum_break_reason(a, "short_tail_completed") == 1);
    a.ObserveAt(build({.seq = 3060}).data(), 1500, 3000);
    a.FinalizeOpenRun();
    const std::string json = a.RenderWindowJson();
    BOOST_TEST(json.find("\"1\":{\"runs\":1") != std::string::npos);
    BOOST_TEST(json.find("\"2\":{\"runs\":1") != std::string::npos);
}

// 13: PSH never starts or completes a strict-v1 frame, including after a run.
BOOST_AUTO_TEST_CASE(psh_rejected_before_continuation) {
    TunGsoMergeabilityAnalyzer a;
    a.ObserveAt(build({}).data(), 1500, 1000);
    a.ObserveAt(build({.seq = 2460, .psh = true}).data(), 1500, 2000);
    BOOST_TEST(sum_break_reason(a, "psh") == 1);
    BOOST_TEST(json_int(a, "psh_rejected_packets") == 1);
    BOOST_TEST(json_int(a, "strict_eligible_packets") == 1);
}

// 14+15: SYN packets are control traffic; IPv6/UDP packets are non-IPv4/non-TCP.
BOOST_AUTO_TEST_CASE(control_and_non_tcp_packets) {
    TunGsoMergeabilityAnalyzer a;
    a.ObserveAt(build({.fin_syn_rst = 0x02}).data(), 1500, 1000);
    BOOST_TEST(json_int(a, "ineligible_packets") == 1);
    BOOST_TEST(sum_break_reason(a, "control_flags") == 0);

    TunGsoMergeabilityAnalyzer b;
    b.ObserveAt(build({.ipv6 = true}).data(), 1500, 1000);
    b.ObserveAt(build({.protocol = 17}).data(), 1500, 2000);
    BOOST_TEST(sum_break_reason(b, "non_ipv4") == 0);
    BOOST_TEST(sum_break_reason(b, "non_tcp") == 0);
    BOOST_TEST(json_int(b, "ineligible_packets") == 2);
}

// 16: closure — run packets plus ineligible packets equals packets seen.
BOOST_AUTO_TEST_CASE(counters_closure) {
    TunGsoMergeabilityAnalyzer a;
    for (int i = 0; i < 4; ++i) a.ObserveAt(build({.seq = static_cast<uint32_t>(1000 + i * 1460)}).data(), 1500, 1000 + i);
    PacketSpec ack;
    ack.payload = 0;
    a.ObserveAt(build(ack).data(), 40, 9000);
    a.ObserveAt(build({.ipv6 = true}).data(), 1500, 9500);
    a.FinalizeOpenRun();
    const uint64_t seen = json_int(a, "packets_seen");
    const uint64_t ineligible = json_int(a, "ineligible_packets");
    const uint64_t runs_packets = json_int(a, "strict_eligible_packets");
    BOOST_TEST(seen == 6);
    BOOST_TEST(ineligible == 2);
    BOOST_TEST(runs_packets == 4);
}

// 17: measurement start reset discards the open run and zeroes the window.
BOOST_AUTO_TEST_CASE(reset_window_discards_state) {
    TunGsoMergeabilityAnalyzer a;
    a.ObserveAt(build({}).data(), 1500, 1000);
    a.ResetWindow();
    BOOST_TEST(json_int(a, "packets_seen") == 0);
    a.ObserveAt(build({}).data(), 1500, 2000);
    a.FinalizeOpenRun();
    BOOST_TEST(json_int(a, "packets_seen") == 1);
    BOOST_TEST(sum_break_reason(a, "measurement_end") == 1);
}

// Correspondence: the analyzer's strict-v1 decisions agree with the actual
// production coalescer at cap, timeout, PSH (including a short PSH), and MTU.
BOOST_AUTO_TEST_CASE(production_coalescer_correspondence) {
    struct Sink {
        size_t gso_writes = 0;
        size_t ordinary_writes = 0;
        ssize_t operator()(const uint8_t* frame, size_t size) {
            if (frame[1] == VIRTIO_NET_HDR_GSO_TCPV4) ++gso_writes;
            else ++ordinary_writes;
            return static_cast<ssize_t>(size);
        }
    } sink;
    ppp::tap::TunGsoCoalescer coalescer([&sink](const uint8_t* frame, size_t size) { return sink(frame, size); });
    TunGsoMergeabilityAnalyzer analyzer;
    for (int i = 0; i < 4; ++i) {
        const auto packet = build({.seq = static_cast<uint32_t>(1000 + i * 1460)});
        BOOST_REQUIRE(coalescer.Push(packet.data(), packet.size(), static_cast<uint64_t>(i)));
        analyzer.ObserveAt(packet.data(), packet.size(), static_cast<uint64_t>(i));
    }
    BOOST_TEST(sink.gso_writes == 1U);
    BOOST_TEST(sum_break_reason(analyzer, "cap") == 1U);

    const auto psh_first = build({.psh = true});
    BOOST_REQUIRE(coalescer.Push(psh_first.data(), psh_first.size(), 20));
    analyzer.ObserveAt(psh_first.data(), psh_first.size(), 20);
    BOOST_TEST(json_int(analyzer, "psh_rejected_packets") == 1U);
    BOOST_TEST(json_int(analyzer, "strict_eligible_packets") == 4U);

    Sink short_sink;
    ppp::tap::TunGsoCoalescer short_coalescer([&short_sink](const uint8_t* frame, size_t size) { return short_sink(frame, size); });
    TunGsoMergeabilityAnalyzer short_analyzer;
    const auto full = build({});
    const auto short_psh = build({.payload = 600, .seq = 2460, .psh = true});
    BOOST_REQUIRE(short_coalescer.Push(full.data(), full.size(), 0));
    BOOST_REQUIRE(short_coalescer.Push(short_psh.data(), short_psh.size(), 1));
    short_analyzer.ObserveAt(full.data(), full.size(), 0);
    short_analyzer.ObserveAt(short_psh.data(), short_psh.size(), 1);
    BOOST_TEST(short_sink.gso_writes == 0U);
    BOOST_TEST(short_sink.ordinary_writes == 2U);
    BOOST_TEST(sum_break_reason(short_analyzer, "psh") == 1U);
    BOOST_TEST(json_int(short_analyzer, "psh_rejected_packets") == 1U);

    TunGsoMergeabilityAnalyzer mtu_analyzer;
    const auto mtu = build({.payload = 1461});
    mtu_analyzer.ObserveAt(mtu.data(), mtu.size(), 0);
    BOOST_TEST(json_int(mtu_analyzer, "strict_eligible_packets") == 0U);
    BOOST_TEST(json_int(mtu_analyzer, "ineligible_packets") == 1U);

    Sink timeout_sink;
    ppp::tap::TunGsoCoalescer timeout_coalescer([&timeout_sink](const uint8_t* frame, size_t size) { return timeout_sink(frame, size); });
    TunGsoMergeabilityAnalyzer timeout_analyzer;
    BOOST_REQUIRE(timeout_coalescer.Push(full.data(), full.size(), 0));
    timeout_analyzer.ObserveAt(full.data(), full.size(), 0);
    const auto next = build({.seq = 2460});
    BOOST_REQUIRE(timeout_coalescer.Push(next.data(), next.size(), ppp::tap::TunGsoCoalescer::kHoldNs));
    timeout_analyzer.ObserveAt(next.data(), next.size(), ppp::tap::TunGsoCoalescer::kHoldNs);
    BOOST_TEST(timeout_sink.ordinary_writes == 1U);
    BOOST_TEST(sum_break_reason(timeout_analyzer, "timeout") == 1U);
}
