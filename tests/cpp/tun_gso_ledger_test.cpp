#define BOOST_TEST_MODULE tun_gso_ledger_test
#include <boost/test/included/unit_test.hpp>

#include <linux/ppp/tap/TapGsoLedger.h>

#include <cstdlib>
#include <string>
#include <vector>

namespace {
using ppp::tap::TunGsoCoalescer;
using ppp::tap::TunGsoLedger;

struct Spec { uint16_t payload = 100; uint32_t seq = 1000; bool psh = false; bool control = false; };
std::vector<uint8_t> Packet(const Spec& spec = {}) {
    std::vector<uint8_t> packet(40 + spec.payload, 0);
    packet[0] = 0x45;
    packet[2] = static_cast<uint8_t>(packet.size() >> 8U);
    packet[3] = static_cast<uint8_t>(packet.size());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 6;
    packet[12] = 10; packet[15] = 1; packet[16] = 10; packet[19] = 2;
    packet[20] = 0; packet[21] = 1; packet[22] = 0; packet[23] = 2;
    packet[24] = static_cast<uint8_t>(spec.seq >> 24U);
    packet[25] = static_cast<uint8_t>(spec.seq >> 16U);
    packet[26] = static_cast<uint8_t>(spec.seq >> 8U);
    packet[27] = static_cast<uint8_t>(spec.seq);
    packet[32] = 0x50;
    packet[33] = static_cast<uint8_t>(0x10 | (spec.psh ? 0x08 : 0) | (spec.control ? 0x02 : 0));
    return packet;
}

struct Sink {
    enum class Mode { Complete, NegativeGso, PartialGso } mode = Mode::Complete;
    ssize_t operator()(const uint8_t* frame, size_t size) const {
        if (frame[1] == VIRTIO_NET_HDR_GSO_TCPV4) {
            if (mode == Mode::NegativeGso) return -1;
            if (mode == Mode::PartialGso) return static_cast<ssize_t>(size - 1);
        }
        return static_cast<ssize_t>(size);
    }
};

uint64_t JsonInt(const std::string& json, const char* name) {
    const std::string key = std::string("\"") + name + "\":";
    const size_t pos = json.find(key);
    return pos == std::string::npos ? 0 : std::strtoull(json.c_str() + pos + key.size(), nullptr, 10);
}
} // namespace

BOOST_AUTO_TEST_CASE(successful_events_render_a_vnet_local_ledger) {
    TunGsoLedger ledger;
    Sink sink;
    TunGsoCoalescer coalescer([&sink](const uint8_t* frame, size_t size) { return sink(frame, size); },
        [&ledger](const TunGsoCoalescer::Event& event) { ledger.OnEvent(event); });

    for (int i = 0; i < 4; ++i) {
        const auto packet = Packet({.seq = static_cast<uint32_t>(1000 + i * 100)});
        BOOST_REQUIRE(coalescer.Push(packet.data(), packet.size(), static_cast<uint64_t>(i)));
    }
    const auto singleton = Packet({.seq = 1400});
    BOOST_REQUIRE(coalescer.Push(singleton.data(), singleton.size(), 1000));
    BOOST_REQUIRE(coalescer.FlushExpired(1000 + TunGsoCoalescer::kHoldNs));
    const auto psh = Packet({.seq = 1500, .psh = true});
    BOOST_REQUIRE(coalescer.Push(psh.data(), psh.size(), 3000));
    const auto control = Packet({.seq = 1600, .control = true});
    BOOST_REQUIRE(coalescer.Push(control.data(), control.size(), 4000));

    const std::string json = ledger.RenderWindowJson();
    BOOST_TEST(json.find("\"framing_domain\":\"vnet_gso_coalescer_only_not_global\"") != std::string::npos);
    BOOST_TEST(JsonInt(json, "eligible_packets") == 5U);
    BOOST_TEST(JsonInt(json, "merged_packets") == 4U);
    BOOST_TEST(JsonInt(json, "gso_full_writes") == 1U);
    BOOST_TEST(JsonInt(json, "gso_segments") == 4U);
    BOOST_TEST(JsonInt(json, "ordinary_full_writes") == 3U);
    BOOST_TEST(JsonInt(json, "timeout") == 1U);
    BOOST_TEST(JsonInt(json, "cap") == 1U);
    BOOST_TEST(json.find("\"packet_rejections\":{\"incompatible\":0,\"psh\":1,\"control\":1") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(negative_fallback_and_partial_delivery_are_not_reported_as_merges) {
    TunGsoLedger negative_ledger;
    Sink negative_sink; negative_sink.mode = Sink::Mode::NegativeGso;
    TunGsoCoalescer negative([&negative_sink](const uint8_t* frame, size_t size) { return negative_sink(frame, size); },
        [&negative_ledger](const TunGsoCoalescer::Event& event) { negative_ledger.OnEvent(event); });
    for (int i = 0; i < 2; ++i) {
        const auto packet = Packet({.seq = static_cast<uint32_t>(1000 + i * 100)});
        BOOST_REQUIRE(negative.Push(packet.data(), packet.size(), static_cast<uint64_t>(i)));
    }
    BOOST_REQUIRE(negative.Flush());
    const std::string negative_json = negative_ledger.RenderWindowJson();
    BOOST_TEST(JsonInt(negative_json, "negative_fallback") == 1U);
    BOOST_TEST(JsonInt(negative_json, "gso_full_writes") == 0U);
    BOOST_TEST(JsonInt(negative_json, "ordinary_full_writes") == 2U);

    TunGsoLedger partial_ledger;
    Sink partial_sink; partial_sink.mode = Sink::Mode::PartialGso;
    TunGsoCoalescer partial([&partial_sink](const uint8_t* frame, size_t size) { return partial_sink(frame, size); },
        [&partial_ledger](const TunGsoCoalescer::Event& event) { partial_ledger.OnEvent(event); });
    for (int i = 0; i < 2; ++i) {
        const auto packet = Packet({.seq = static_cast<uint32_t>(1000 + i * 100)});
        BOOST_REQUIRE(partial.Push(packet.data(), packet.size(), static_cast<uint64_t>(i)));
    }
    BOOST_TEST(!partial.Flush());
    const std::string partial_json = partial_ledger.RenderWindowJson();
    BOOST_TEST(JsonInt(partial_json, "partial_unknown") == 1U);
    BOOST_TEST(JsonInt(partial_json, "merged_packets") == 0U);
    BOOST_TEST(JsonInt(partial_json, "ordinary_full_writes") == 0U);
}
