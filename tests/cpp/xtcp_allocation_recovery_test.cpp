#include <xtcp/buf/bufref.h>
#include <xtcp/core/tcp.h>

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

namespace {
using namespace xtcp::core;
int failures = 0;
#define CHECK(x) do { if (!(x)) { ++failures; std::fprintf(stderr, "FAIL %d: %s\n", __LINE__, #x); } } while (0)

void Put32(Byte* p, UInt32 n) {
    p[0] = Byte(n >> 24); p[1] = Byte(n >> 16);
    p[2] = Byte(n >> 8); p[3] = Byte(n);
}

UInt64 Now() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

// Keep the releasing thread alive: its TLS cache must not be flushed by exit.
class Pressure {
public:
    explicit Pressure(UInt32 size = 40) {
        for (;;) {
            auto ref = xtcp::buf::BufRef::Acquire(size);
            if (ref.IsEmpty()) break;
            held_.push_back(std::move(ref));
        }
        CHECK(!held_.empty());
        CHECK(xtcp::buf::BufRef::Acquire(size).IsEmpty());
    }
    void Release() {
        worker_ = std::thread([this] {
            held_.clear();
            std::unique_lock<std::mutex> lock(mutex_);
            released_ = true;
            cv_.notify_all();
            cv_.wait(lock, [this] { return done_; });
        });
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return released_; });
    }
    ~Pressure() {
        if (!worker_.joinable()) return;
        { std::lock_guard<std::mutex> lock(mutex_); done_ = true; }
        cv_.notify_all();
        worker_.join();
    }
private:
    std::vector<xtcp::buf::BufRef> held_;
    std::thread worker_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool released_ = false, done_ = false;
};

struct Probe {
    static Endpoint EndpointAt(UInt32 ip, UInt16 port) {
        Endpoint e; e.family = 4; e.addr[0] = ip; e.port = port; return e;
    }
    std::vector<std::vector<Byte>> output;
    std::vector<Byte> delivered;
    bool accepting = true;
    TcpConn conn;
    explicit Probe(TcpState state = TcpState::kEstablished) : conn(state, EndpointAt(0x0a000001, 1001),
        EndpointAt(0x0a000002, 2001), 100, 200,
        [this](xtcp::buf::BufRef&& ref) {
            output.emplace_back(ref.Data(), ref.Data() + ref.Len());
        }) {
        conn.SetRecvHandler([this](const Byte* p, UInt32 n) {
            if (!accepting) return false;
            delivered.insert(delivered.end(), p, p + n);
            return true;
        });
    }
    void Segment(UInt64 now, UInt32 seq = 201, UInt16 flags = kFlagAck, bool data = true,
                 UInt32 ack = 101) {
        Byte packet[21] = {};
        packet[0] = 7; packet[1] = 0xd1;
        packet[2] = 3; packet[3] = 0xe9;
        Put32(packet + 4, seq); Put32(packet + 8, ack);
        packet[12] = 0x50; packet[13] = Byte(flags);
        packet[14] = 0xff; packet[15] = 0xff; packet[20] = 0x5a;
        conn.OnSegment(packet, data ? sizeof(packet) : 20, now);
    }
    bool CurrentAck() const {
        for (const auto& packet : output) {
            TcpHdr hdr;
            if (packet.size() >= 40 && ParseTcp(packet.data() + 20,
                UInt32(packet.size() - 20), hdr) && hdr.IsAck() &&
                hdr.ack == 202 && hdr.window != 0) return true;
        }
        return false;
    }
    void Poll(UInt64 start) {
        for (unsigned i = 1; i <= 100; ++i) conn.OnPoll(start + i * 10000);
    }
};

void DelayedAck(bool close) {
    Probe p;
    const auto now = Now();
    p.Segment(now);
    CHECK(p.delivered == std::vector<Byte>{0x5a});
    CHECK(p.conn.RcvNxt() == 202);
    const auto deadline = p.conn.NextAckTime();
    CHECK(deadline > now);
    p.output.clear();
    Pressure pressure;
    p.conn.OnPoll(deadline);
    p.conn.OnPoll(deadline + 10000);
    CHECK(p.output.empty());
    if (close) p.conn.Abort();
    pressure.Release();
    p.Poll(deadline + 10000);
    if (close) CHECK(p.output.empty());
    else CHECK(p.CurrentAck());
    std::printf("delayed_ack%s: frontier=%u outputs=%zu next_ack=%llu\n",
        close ? "_close" : "", p.conn.RcvNxt(), p.output.size(),
        static_cast<unsigned long long>(p.conn.NextAckTime()));
}

void Resume() {
    Probe p;
    const auto now = Now();
    p.accepting = false;
    p.Segment(now);
    CHECK(p.conn.ReceiveState().rcv_blocked);
    p.output.clear();
    Pressure pressure;
    p.accepting = true;
    CHECK(p.conn.ResumeReceiveDetailed() == ReceiveResumeResult::kResumed);
    CHECK(p.delivered == std::vector<Byte>{0x5a});
    CHECK(p.conn.RcvNxt() == 202);
    CHECK(p.output.empty());
    pressure.Release();
    p.Poll(now);
    CHECK(p.CurrentAck());
    std::printf("resume: frontier=%u outputs=%zu\n", p.conn.RcvNxt(), p.output.size());
}

void LostAck() {
    Probe p;
    const auto now = Now();
    p.Segment(now);
    p.Poll(now);
    CHECK(p.CurrentAck());
    p.output.clear();
    p.Segment(now + 1100000);
    CHECK(p.CurrentAck());
    CHECK(p.delivered == std::vector<Byte>{0x5a});
}

void Repeated(bool resume, bool close) {
    Probe p;
    const auto now = Now();
    p.accepting = !resume;
    p.Segment(now);
    p.output.clear();
    Pressure pressure;
    if (resume) {
        p.accepting = true;
        CHECK(p.conn.ResumeReceiveDetailed() == ReceiveResumeResult::kResumed);
    }
    auto deadline = p.conn.NextTimerDeadline();
    CHECK(deadline > now && deadline <= now + 1000000);
    for (unsigned i = 0; i < 32 && deadline <= now + 2000000; ++i) {
        CHECK(p.conn.OnPoll(deadline - 1) == 0);
        p.conn.OnPoll(deadline);
        const auto next = p.conn.NextTimerDeadline();
        CHECK(next > deadline && next <= deadline + 100000);
        CHECK(p.conn.TimersDirty());
        deadline = next;
    }
    CHECK(p.output.empty());
    if (close) p.conn.Abort();
    pressure.Release();
    if (deadline < now + 2000000) p.Poll(deadline);
    if (close) CHECK(p.output.empty());
    else {
        CHECK(p.CurrentAck());
        CHECK(p.output.size() == 1);
        CHECK(!p.conn.TimersDirty());
    }
    CHECK(p.delivered == std::vector<Byte>{0x5a});
}

void PeerProbe() {
    Probe p;
    const auto now = Now();
    p.Segment(now);
    p.Poll(now);
    CHECK(p.CurrentAck());
    p.output.clear(); // An emitted packet is lost after construction.
    p.Segment(now + 1100000, 201, kFlagAck, false);
    CHECK(p.CurrentAck());
    CHECK(p.delivered == std::vector<Byte>{0x5a});
}

void Fin(bool timewait) {
    Probe p;
    const auto now = Now();
    if (timewait) {
        p.conn.Close();
        p.Segment(now, 201, kFlagAck, false);
        // Our FIN consumes sequence 101; acknowledge it explicitly.
        Byte ack[20] = {};
        ack[0] = 7; ack[1] = 0xd1; ack[2] = 3; ack[3] = 0xe9;
        Put32(ack + 4, 201); Put32(ack + 8, 102);
        ack[12] = 0x50; ack[13] = kFlagAck; ack[14] = 0xff; ack[15] = 0xff;
        p.conn.OnSegment(ack, sizeof(ack), now);
        CHECK(p.conn.State() == TcpState::kFinWait2);
    }
    p.output.clear();
    Pressure pressure;
    const auto failed_at = Now();
    p.Segment(failed_at, 201, kFlagAck | kFlagFin, false);
    CHECK(p.conn.RcvNxt() == 202);
    CHECK(p.conn.State() == (timewait ? TcpState::kTimeWait : TcpState::kCloseWait));
    CHECK(p.output.empty());
    const auto deadline = p.conn.NextTimerDeadline();
    CHECK(deadline > failed_at && deadline <= Now() + 100000);
    pressure.Release();
    p.conn.OnPoll(deadline);
    CHECK(p.CurrentAck());
    CHECK(p.delivered.empty());
}

void Dsack() {
    Probe p;
    p.conn.SetSackOk(true);
    const auto now = Now();
    p.Segment(now);
    p.Poll(now);
    p.output.clear();
    Pressure pressure;
    p.Segment(now + 1100000);
    CHECK(p.output.empty());
    pressure.Release();
    p.Poll(now + 1100000);
    CHECK(p.CurrentAck());
    bool dsack = false;
    for (const auto& packet : p.output) {
        TcpHdr hdr;
        if (ParseTcp(packet.data() + 20, UInt32(packet.size() - 20), hdr)) {
            TcpOpts opts;
            CHECK(ParseTcpOpts(packet.data() + 20, UInt32(packet.size() - 20), hdr.hdr_len, opts));
            dsack |= opts.sack_count > 0 && opts.sack[0][0] == 201 && opts.sack[0][1] == 202;
        }
    }
    CHECK(dsack);
    CHECK(p.delivered == std::vector<Byte>{0x5a});
}

void Ecn() {
    Probe p(TcpState::kSynSent);
    const auto now = Now();
    p.conn.SetEcnRequested(true);
    p.conn.SendSyn();
    p.Segment(now, 200, kFlagSyn | kFlagAck | kFlagEce, false);
    CHECK(p.conn.State() == TcpState::kEstablished);
    CHECK(p.conn.EcnActive());
    p.conn.SetCeSeen();
    // Send actual data first: ECE only requests CWR with data outstanding.
    const Byte data = 0x42;
    CHECK(p.conn.SendData(&data, 1, now));
    p.output.clear();
    Pressure pressure;
    p.Segment(now + 1, 201, kFlagAck | kFlagEce, false);
    p.conn.SendAck();
    CHECK(p.output.empty());
    pressure.Release();
    p.Poll(now);
    bool flags = false;
    for (const auto& packet : p.output) {
        TcpHdr hdr;
        if (ParseTcp(packet.data() + 20, UInt32(packet.size() - 20), hdr)) {
            flags |= hdr.IsAck() && hdr.IsCwr() && (hdr.flags & kFlagEce);
        }
    }
    CHECK(flags);
    p.output.clear();
    p.conn.SendAck();
    CHECK(p.output.size() == 1);
    if (!p.output.empty()) CHECK((p.output[0][33] & kFlagCwr) == 0);
}
void RunCase(const char* name) {
    if (std::strcmp(name, "delayed") == 0) DelayedAck(false);
    else if (std::strcmp(name, "resume") == 0) Resume();
    else if (std::strcmp(name, "closed") == 0) DelayedAck(true);
    else if (std::strcmp(name, "lost") == 0) LostAck();
    else if (std::strcmp(name, "repeated-delayed") == 0) Repeated(false, false);
    else if (std::strcmp(name, "repeated-resume") == 0) Repeated(true, false);
    else if (std::strcmp(name, "repeated-closed") == 0) Repeated(true, true);
    else if (std::strcmp(name, "probe") == 0) PeerProbe();
    else if (std::strcmp(name, "fin") == 0) Fin(false);
    else if (std::strcmp(name, "timewait") == 0) Fin(true);
    else if (std::strcmp(name, "dsack") == 0) Dsack();
    else if (std::strcmp(name, "ecn") == 0) Ecn();
    else CHECK(false);
}
} // namespace

int main(int argc, char** argv) {
    if (argc > 2) return 2;
    xtcp::buf::InitPools();
    if (argc == 2) RunCase(argv[1]);
    else {
        const char* cases[] = {"delayed", "resume", "closed", "lost", "repeated-delayed",
            "repeated-resume", "repeated-closed", "probe", "fin", "timewait", "dsack", "ecn"};
        for (const auto* name : cases) RunCase(name);
    }
    xtcp::buf::ShutdownPools();
    return failures ? 1 : 0;
}
