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

struct CallbackResult {
    UInt32 len = 0;
    bool accepted = false;
};

struct Probe {
    std::vector<std::vector<Byte>> ack_packets;
    std::vector<Byte> received;
    std::vector<CallbackResult> callback_results;
    bool allow_tail = false;
    TcpConn conn;

    Probe(TcpState state, UInt32 irs)
        : conn(state, LocalEndpoint(), RemoteEndpoint(), 100, irs,
               [this](xtcp::buf::BufRef&& ref) {
                   ack_packets.emplace_back(ref.Data(), ref.Data() + ref.Len());
               }) {
        conn.SetSackOk(true);
        InstallHandler();
    }

    void InstallHandler() {
        conn.SetRecvHandler([this](const Byte* data, UInt32 len) {
            const bool accepted = allow_tail || received.empty();
            callback_results.push_back({len, accepted});
            if (accepted) received.insert(received.end(), data, data + len);
            return accepted;
        });
    }

    static Endpoint& LocalEndpoint() {
        static Endpoint endpoint;
        endpoint.family = 4;
        endpoint.addr[0] = 0x0a000001;
        endpoint.port = 1001;
        return endpoint;
    }

    static Endpoint& RemoteEndpoint() {
        static Endpoint endpoint;
        endpoint.family = 4;
        endpoint.addr[0] = 0x0a000002;
        endpoint.port = 2001;
        return endpoint;
    }

    void Segment(UInt32 seq, Byte fill, UInt32 len) {
        std::vector<Byte> packet(20 + len, 0);
        packet[0] = 0x04; packet[1] = 0xd3;
        packet[2] = 0x07; packet[3] = 0xd2;
        Put32(packet.data() + 4, seq);
        Put32(packet.data() + 8, 101);
        packet[12] = 0x50;
        packet[13] = Byte(kFlagAck | kFlagPsh);
        std::fill(packet.begin() + 20, packet.end(), fill);
        conn.OnSegment(packet.data(), static_cast<UInt32>(packet.size()));
    }

    bool LastTcpAck(UInt32& ack) const {
        for (auto packet = ack_packets.rbegin(); packet != ack_packets.rend(); ++packet) {
            if (packet->size() < 20 || ((*packet)[0] >> 4) != 4) continue;
            const UInt32 ip_ihl = ((*packet)[0] & 15U) * 4U;
            if (ip_ihl < 20 || ip_ihl > packet->size()) continue;
            const UInt32 total_length = (UInt32((*packet)[2]) << 8) | (*packet)[3];
            if (total_length < ip_ihl + 20 || total_length > packet->size()) continue;
            TcpHdr tcp;
            if (!ParseTcp(packet->data() + ip_ihl, total_length - ip_ihl, tcp) || !tcp.IsAck()) continue;
            ack = tcp.ack;
            return true;
        }
        return false;
    }

    std::vector<Byte> Expected(UInt32 length, UInt32 leading_zeros) const {
        std::vector<Byte> expected(length, Byte(1));
        std::fill(expected.begin(), expected.begin() + leading_zeros, Byte(0));
        return expected;
    }
};

void FutureTailResumeContract(UInt32 irs) {
    Probe probe(TcpState::kEstablished, irs);
    probe.Segment(irs + 1001, 1, 1000);
    CHECK(probe.conn.ReceiveState().ooo_bytes == 1000);

    probe.Segment(irs + 1, 0, 1000);
    CHECK(!probe.callback_results.empty());
    CHECK(probe.callback_results.front().accepted == true);

    CHECK(probe.received.size() == 1000);
    CHECK(probe.conn.RcvNxt() == irs + 1001);
    CHECK(probe.conn.ReceiveState().rcv_blocked == true);
    CHECK(probe.conn.ReceiveState().ooo_bytes == 1000);

    probe.allow_tail = true;
    probe.InstallHandler();
    CHECK(probe.conn.ResumeReceiveDetailed() == ReceiveResumeResult::kResumed);
    CHECK(probe.received == probe.Expected(2000, 1000));
    CHECK(probe.callback_results.size() >= 1);
    CHECK(probe.conn.RcvNxt() == irs + 2001);
    CHECK(probe.conn.ReceiveState().ooo_bytes == 0);
    UInt32 ack = 0;
    CHECK(probe.LastTcpAck(ack));
    CHECK(ack == irs + 2001);
}

void WindowFullFrontierResumeContract(UInt32 irs) {
    Probe probe(TcpState::kEstablished, irs);
    probe.Segment(irs + 1000, 1, 32000);
    probe.Segment(irs + 1500, 1, 33535);
    CHECK(probe.conn.ReceiveState().ooo_bytes == 65535);
    CHECK(probe.conn.ReceiveState().advertised_window == 0);

    probe.Segment(irs + 1, 0, 1000);
    CHECK(!probe.callback_results.empty());
    CHECK(probe.callback_results.front().accepted == true);

    CHECK(probe.received.size() == 1000);
    CHECK(probe.conn.RcvNxt() == irs + 1001);
    CHECK(probe.conn.ReceiveState().rcv_blocked == true);
    CHECK(probe.conn.ReceiveState().ooo_bytes == 65534);
    CHECK(probe.conn.ReceiveState().advertised_window == 0);

    probe.allow_tail = true;
    probe.InstallHandler();
    CHECK(probe.conn.ResumeReceiveDetailed() == ReceiveResumeResult::kResumed);
    CHECK(probe.received == probe.Expected(35034, 1000));
    CHECK(probe.callback_results.size() >= 1);
    CHECK(probe.conn.RcvNxt() == irs + 35035);
    CHECK(probe.conn.ReceiveState().ooo_bytes == 0);
    UInt32 ack = 0;
    CHECK(probe.LastTcpAck(ack));
    CHECK(ack == irs + 35035);
}

}  // namespace

int main() {
    xtcp::buf::InitPools();
    for (UInt32 irs : {200U, 0xfffffff0U}) {
        FutureTailResumeContract(irs);
        WindowFullFrontierResumeContract(irs);
    }
    xtcp::buf::ShutdownPools();
    std::printf("OOO resume contract: 4 cases, %d failures\n", failures);
    return failures ? 1 : 0;
}
