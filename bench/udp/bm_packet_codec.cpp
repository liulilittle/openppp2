#include <benchmark/benchmark.h>

#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/native/checksum.h>

#include <cstring>
#include <vector>

using ppp::Byte;
using ppp::net::IPEndPoint;
using ppp::net::packet::BufferSegment;
using ppp::net::packet::IPFrame;
using ppp::net::packet::UdpFrame;

namespace {
UdpFrame make_frame(int payload_size) {
    auto bytes = ppp::threading::BufferswapAllocator::MakeByteArray(nullptr, payload_size);
    std::memset(bytes.get(), 0x2a, payload_size);
    UdpFrame frame;
    frame.Source = IPEndPoint(inet_addr("192.0.2.1"), 12000);
    frame.Destination = IPEndPoint(inet_addr("198.51.100.2"), 13000);
    frame.Payload = std::make_shared<BufferSegment>(bytes, payload_size);
    return frame;
}

bool roundtrip_ok(int payload_size) {
    UdpFrame source = make_frame(payload_size);
    auto ip = source.ToIp(nullptr);
    auto wire = ip ? ip->ToArray(nullptr) : nullptr;
    auto decoded_ip = wire ? IPFrame::Parse(nullptr, wire->Buffer.get(), wire->Length) : nullptr;
    auto decoded_udp = decoded_ip ? UdpFrame::Parse(decoded_ip.get()) : nullptr;
    const bool ip_checksum_ok = wire && ppp::net::native::inet_chksum(
        wire->Buffer.get(), sizeof(ppp::net::native::ip_hdr)) == 0;
    const bool udp_checksum_ok = decoded_ip && ppp::net::native::inet_chksum_pseudo(
        decoded_ip->Payload->Buffer.get(), ppp::net::native::ip_hdr::IP_PROTO_UDP,
        decoded_ip->Payload->Length, decoded_ip->Source, decoded_ip->Destination) == 0;
    return ip_checksum_ok && udp_checksum_ok && decoded_udp && decoded_udp->Payload && decoded_udp->Payload->Length == payload_size &&
        std::memcmp(source.Payload->Buffer.get(), decoded_udp->Payload->Buffer.get(), payload_size) == 0;
}

void BM_PacketCodec(benchmark::State& state) {
    const int payload_size = static_cast<int>(state.range(0));
    if (!roundtrip_ok(payload_size)) {
        state.SkipWithError("UDP/IP packet codec roundtrip failed");
        return;
    }
    UdpFrame source = make_frame(payload_size);
    for (auto _ : state) {
        auto ip = source.ToIp(nullptr);
        auto wire = ip->ToArray(nullptr);
        auto decoded_ip = IPFrame::Parse(nullptr, wire->Buffer.get(), wire->Length);
        auto decoded_udp = UdpFrame::Parse(decoded_ip.get());
        benchmark::DoNotOptimize(decoded_udp.get());
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * payload_size);
    state.counters["allocations"] = 9;
}
} // namespace

BENCHMARK(BM_PacketCodec)->Arg(64)->Arg(1400);
BENCHMARK_MAIN();
