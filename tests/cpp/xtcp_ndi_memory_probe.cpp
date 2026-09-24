#include <ppp/app/client/xtcp/XtcpNdiBackend.h>

#include <xtcp/buf/bufref.h>
#include <xtcp/core/stack.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <optional>
#include <string>
#include <utility>

namespace {
using Clock = std::chrono::steady_clock;
using Backend = ppp::app::client::xtcp::XtcpNdiBackend;

struct MemoryFrame final {
    std::shared_ptr<Byte> bytes;
    int length = 0;
    std::optional<ppp::tap::TxGsoMetadata> gso;
};

struct ProbeResult final {
    UInt64 bytes_sent = 0;
    UInt64 bytes_recv = 0;
    UInt64 packets = 0;
    bool payload_exact = true;
    std::string failure;
};

Byte PatternByte(UInt64 offset) noexcept {
    return static_cast<Byte>((offset * 131u + 17u) & 0xffu);
}

bool PumpMemory(std::deque<MemoryFrame>& from, Backend& to, ProbeResult& result) noexcept {
    while (!from.empty()) {
        MemoryFrame frame = std::move(from.front());
        from.pop_front();
        if (!frame.bytes || frame.length <= 0) {
            result.failure = "invalid_output_frame";
            return false;
        }
        xtcp::buf::BufRef input = xtcp::buf::BufRef::Acquire(static_cast<UInt32>(frame.length));
        if (input.IsEmpty()) {
            result.failure = "input_pool_exhausted";
            return false;
        }
        std::memcpy(input.Data(), frame.bytes.get(), static_cast<std::size_t>(frame.length));
        input.SetLen(static_cast<UInt32>(frame.length));
        if (!to.Inject(std::move(input))) {
            result.failure = "backend_inject_rejected";
            return false;
        }
        ++result.packets;
    }
    return true;
}

bool PumpBoth(std::deque<MemoryFrame>& a_to_b, Backend& backend_b,
              std::deque<MemoryFrame>& b_to_a, Backend& backend_a,
              ProbeResult& result) noexcept {
    while (!a_to_b.empty() || !b_to_a.empty()) {
        if (!PumpMemory(a_to_b, backend_b, result) ||
            !PumpMemory(b_to_a, backend_a, result)) {
            return false;
        }
    }
    return true;
}

void PrintResult(const ProbeResult& result, double seconds,
                 const Backend::TxStats& stats_a, const Backend::TxStats& stats_b) noexcept {
    const double mbps = seconds > 0.0 ? (static_cast<double>(result.bytes_recv) * 8.0) / 1000000.0 / seconds : 0.0;
    std::printf(
        "{\"bytes_sent\":%llu,\"bytes_recv\":%llu,\"seconds\":%.6f,\"mbps\":%.2f,\"packets\":%llu,"
        "\"a\":{\"attempts\":%llu,\"accepted\":%llu,\"rejected\":%llu},"
        "\"b\":{\"attempts\":%llu,\"accepted\":%llu,\"rejected\":%llu},\"failure\":\"%s\"}\n",
        static_cast<unsigned long long>(result.bytes_sent),
        static_cast<unsigned long long>(result.bytes_recv), seconds, mbps,
        static_cast<unsigned long long>(result.packets),
        static_cast<unsigned long long>(stats_a.attempts),
        static_cast<unsigned long long>(stats_a.accepted),
        static_cast<unsigned long long>(stats_a.rejected),
        static_cast<unsigned long long>(stats_b.attempts),
        static_cast<unsigned long long>(stats_b.accepted),
        static_cast<unsigned long long>(stats_b.rejected), result.failure.c_str());
}

int RunMemoryLoopback(UInt64 total_bytes, UInt32 chunk) noexcept {
    ProbeResult result;
    Backend::TxStats stats_a;
    Backend::TxStats stats_b;
    const auto start = Clock::now();
    {
        std::deque<MemoryFrame> a_to_b;
        std::deque<MemoryFrame> b_to_a;
        Backend backend_a([&a_to_b](std::shared_ptr<Byte>&& bytes, int length,
                                    std::optional<ppp::tap::TxGsoMetadata> gso) noexcept {
            a_to_b.push_back({std::move(bytes), length, std::move(gso)});
            return true;
        });
        Backend backend_b([&b_to_a](std::shared_ptr<Byte>&& bytes, int length,
                                    std::optional<ppp::tap::TxGsoMetadata> gso) noexcept {
            b_to_a.push_back({std::move(bytes), length, std::move(gso)});
            return true;
        });
        xtcp::XtcpStack stack_a(&backend_a);
        xtcp::XtcpStack stack_b(&backend_b);

        backend_a.SetRxHandler([&stack_a](xtcp::ndi::Packet&& packet) {
            stack_a.OnPacket(std::move(packet.owned));
        });
        backend_b.SetRxHandler([&stack_b](xtcp::ndi::Packet&& packet) {
            stack_b.OnPacket(std::move(packet.owned));
        });

        UInt64 receiver_conn = 0;
        stack_b.SetRecvHandler([&result, &receiver_conn, total_bytes](UInt64 conn_id,
                                                                        const Byte* data, UInt32 length) {
            receiver_conn = conn_id;
            if (result.bytes_recv + length > total_bytes) {
                result.payload_exact = false;
                result.failure = "received_too_many_bytes";
                return;
            }
            for (UInt32 i = 0; i < length; ++i) {
                if (data[i] != PatternByte(result.bytes_recv + i)) {
                    result.payload_exact = false;
                    result.failure = "payload_mismatch";
                    return;
                }
            }
            result.bytes_recv += length;
        });

        xtcp::core::Endpoint local_a;
        local_a.family = 4;
        local_a.addr[0] = 0xC0A80102;
        local_a.port = 40000;
        xtcp::core::Endpoint remote_a;
        remote_a.family = 4;
        remote_a.addr[0] = 0x0A000001;
        remote_a.port = 443;
        if (!stack_b.Listen(remote_a)) {
            result.failure = "listen_failed";
        }
        const UInt64 conn = result.failure.empty() ? stack_a.Connect(local_a, remote_a) : 0;
        if (result.failure.empty() && conn == 0) {
            result.failure = "connect_failed";
        }
        const Int32 on = 1;
        if (result.failure.empty()) {
            stack_a.SetOption(conn, xtcp::options::kTcpNodelay, &on, sizeof(on));
            if (!PumpBoth(a_to_b, backend_b, b_to_a, backend_a, result)) {
                // PumpMemory set the failure reason.
            }
        }

        std::string payload(chunk, '\0');
        UInt64 next_offset = 0;
        bool quickack_set = false;
        const auto deadline = start + std::chrono::seconds(30);
        while (result.failure.empty() && result.bytes_recv < total_bytes && Clock::now() < deadline) {
            bool sent_any = false;
            while (result.bytes_sent < total_bytes) {
                const UInt32 length = static_cast<UInt32>(
                    (total_bytes - result.bytes_sent) < chunk ? (total_bytes - result.bytes_sent) : chunk);
                for (UInt32 i = 0; i < length; ++i) {
                    payload[i] = static_cast<char>(PatternByte(next_offset + i));
                }
                if (!stack_a.Send(conn, reinterpret_cast<const Byte*>(payload.data()), length)) {
                    break;
                }
                result.bytes_sent += length;
                next_offset += length;
                sent_any = true;
                if (!PumpBoth(a_to_b, backend_b, b_to_a, backend_a, result)) {
                    break;
                }
            }
            if (receiver_conn != 0 && !quickack_set) {
                stack_b.SetOption(receiver_conn, xtcp::options::kTcpQuickack, &on, sizeof(on));
                quickack_set = true;
            }
            stack_a.PollAckTimers();
            stack_b.PollAckTimers();
            if (!PumpBoth(a_to_b, backend_b, b_to_a, backend_a, result)) {
                break;
            }
            if (!sent_any && a_to_b.empty() && b_to_a.empty()) {
                // Timer polling above drives the ACK-clock/persist paths.
            }
        }
        if (result.failure.empty() && result.bytes_recv != total_bytes) {
            result.failure = "timeout";
        }
        if (result.failure.empty() && !result.payload_exact) {
            result.failure = "payload_mismatch";
        }
        stats_a = backend_a.SnapshotTxStats();
        stats_b = backend_b.SnapshotTxStats();
    }
    const double seconds = std::chrono::duration<double>(Clock::now() - start).count();
    if (result.failure.empty() && (stats_a.rejected != 0 || stats_b.rejected != 0)) {
        result.failure = "ndi_output_rejected";
    }
    PrintResult(result, seconds, stats_a, stats_b);
    return result.failure.empty() && result.bytes_sent == total_bytes && result.bytes_recv == total_bytes ? 0 : 1;
}
} // namespace

int main(int argc, char** argv) {
    UInt64 total_bytes = 64ull * 1024 * 1024;
    UInt32 chunk = 16u * 1024;
    if (argc >= 2) {
        total_bytes = static_cast<UInt64>(std::strtoull(argv[1], nullptr, 10));
    }
    if (argc >= 3) {
        chunk = static_cast<UInt32>(std::strtoul(argv[2], nullptr, 10));
    }
    if (total_bytes == 0 || chunk == 0 || chunk > xtcp::buf::kMaxPoolPayload) {
        std::fprintf(stderr, "usage: %s [total_bytes>0] [chunk=1..%u]\n", argv[0],
                     static_cast<unsigned>(xtcp::buf::kMaxPoolPayload));
        return 2;
    }
    xtcp::buf::InitPools();
    const int rc = RunMemoryLoopback(total_bytes, chunk);
    xtcp::buf::ShutdownPools();
    return rc;
}
