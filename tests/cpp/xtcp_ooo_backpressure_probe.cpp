#include <xtcp/buf/bufref.h>
#include <xtcp/core/tcp.h>

#include <algorithm>
#include <cstdio>
#include <vector>

using namespace xtcp::core;

namespace {

int failures = 0;

#define CHECK(value) do { \
    if (!(value)) { ++failures; std::fprintf(stderr, "FAIL %d: %s\n", __LINE__, #value); } \
} while (0)

void Put32(Byte* p, UInt32 v) {
    p[0] = Byte(v >> 24); p[1] = Byte(v >> 16);
    p[2] = Byte(v >> 8); p[3] = Byte(v);
}

struct Probe {
    TcpConn conn;
    std::vector<std::vector<Byte>> ack_packets;
    std::vector<Byte> received;
    bool allow_tail = false;

    Probe(TcpState state, UInt32 irs) : conn(state, Endpoint4(), Endpoint4(), 100, irs,
                                            [this](xtcp::buf::BufRef&& ref) {
                                                ack_packets.emplace_back(ref.Data(), ref.Data() + ref.Len());
                                            }) {
        conn.SetSackOk(true);
        conn.SetRecvHandler([this](const Byte* data, UInt32 n) {
            if (received.size() >= 1000 && !allow_tail) return false;
            received.insert(received.end(), data, data + n);
            return true;
        });
    }

    static Endpoint& Endpoint4() {
        static Endpoint endpoint;
        endpoint.family = 4;
        endpoint.addr[0] = 0x0a000001;
        endpoint.port = 443;
        return endpoint;
    }

    void Segment(UInt32 seq, Byte fill, UInt32 len) {
        std::vector<Byte> packet(20 + len, 0);
        packet[0] = 0x01; packet[1] = 0xbb;
        packet[2] = 0x01; packet[3] = 0xbb;
        Put32(packet.data() + 4, seq);
        Put32(packet.data() + 8, 101);
        packet[12] = 0x50;
        packet[13] = Byte(kFlagAck);
        std::fill(packet.begin() + 20, packet.end(), fill);
        conn.OnSegment(packet.data(), static_cast<UInt32>(packet.size()));
    }
};

bool SackContains(const std::vector<std::vector<Byte>>& output, UInt32 begin, UInt32 end) {
    for (const std::vector<Byte>& data : output) {
        if (data.size() < 40) continue;
        const UInt32 tcp_offset = (data[0] & 15U) * 4U;
        if (data.size() < tcp_offset + 20U) continue;
        const UInt32 tcp_end = tcp_offset + (data[tcp_offset + 12] >> 4U) * 4U;
        UInt32 offset = tcp_offset + 20U;
        while (offset < tcp_end) {
            const Byte kind = data[offset];
            if (kind == 0) break;
            if (kind == 1) {
                ++offset;
                continue;
            }
            if (offset + 1 >= tcp_end) break;
            const Byte length = data[offset + 1];
            if (length < 2 || offset + length > tcp_end) break;
            if (kind == 5 && length >= 10) {
                const UInt32 left = (UInt32(data[offset + 2]) << 24) |
                                    (UInt32(data[offset + 3]) << 16) |
                                    (UInt32(data[offset + 4]) << 8) |
                                    UInt32(data[offset + 5]);
                const UInt32 right = (UInt32(data[offset + 6]) << 24) |
                                     (UInt32(data[offset + 7]) << 16) |
                                     (UInt32(data[offset + 8]) << 8) |
                                     UInt32(data[offset + 9]);
                if (left == begin && right == end) return true;
            }
            offset += length;
        }
    }
    return false;
}

void RunCase(TcpState state, UInt32 irs) {
    Probe probe(state, irs);
    const UInt32 future = irs + 1001;
    probe.Segment(future, 1, 1000);
    CHECK(probe.conn.ReceiveState().ooo_bytes == 1000);
    std::printf(
        "future: state=%d irs=%u ack_count=%zu ooo=%u rcv_nxt=%u sack=%d\n",
        static_cast<int>(state), irs, probe.ack_packets.size(),
        probe.conn.ReceiveState().ooo_bytes, probe.conn.RcvNxt(),
        SackContains(probe.ack_packets, future, future + 1000) ? 1 : 0);
    CHECK(SackContains(probe.ack_packets, future, future + 1000));
    CHECK(probe.conn.RcvNxt() == irs + 1);

    probe.Segment(irs + 1, 0, 1000);
    CHECK(probe.received.size() == 1000);
    CHECK(probe.received == std::vector<Byte>(1000, Byte(0)));
    CHECK(probe.conn.RcvNxt() == irs + 1001);
    CHECK(probe.conn.ReceiveState().rcv_blocked == true);
    CHECK(probe.conn.ReceiveState().ooo_bytes == 1000);

    probe.allow_tail = true;
    CHECK(probe.conn.ResumeReceiveDetailed() == ReceiveResumeResult::kResumed);
    CHECK(probe.received.size() == 2000);
    std::vector<Byte> expected(1000, Byte(0));
    expected.insert(expected.end(), 1000, Byte(1));
    CHECK(probe.received == expected);
    CHECK(probe.conn.RcvNxt() == irs + 2001);
    CHECK(probe.conn.ReceiveState().ooo_bytes == 0);
    CHECK(probe.conn.ResumeReceiveDetailed() == ReceiveResumeResult::kNotBlocked);
    CHECK(probe.conn.ReceiveState().ooo_bytes == 0);
    CHECK(probe.received.size() == 2000);
}

}  // namespace

int main() {
    xtcp::buf::InitPools();
    for (UInt32 irs : {200U, 0xfffffff0U}) {
        RunCase(TcpState::kEstablished, irs);
        RunCase(TcpState::kFinWait2, irs);
    }
    xtcp::buf::ShutdownPools();
    std::printf("OOO backpressure probe: 4 cases, %d failures\n", failures);
    return failures ? 1 : 0;
}
