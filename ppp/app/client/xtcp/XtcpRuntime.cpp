#include <ppp/stdafx.h>
#include <ppp/app/client/xtcp/XtcpRuntime.h>

#include <thread>

#if defined(__linux__)
#include <pthread.h>
#endif
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <chrono>

#if defined(PPP_ENABLE_XTCP)
#include <ppp/app/client/xtcp/XtcpNdiBackend.h>
#include <ppp/app/client/xtcp/XtcpPoolLease.h>
#include <ppp/app/client/xtcp/XtcpRuntimePolicy.h>

#include <xtcp/core/ip.h>
#include <xtcp/core/stack.h>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/steady_timer.hpp>
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <fstream>
#include <limits>
#include <mutex>
#include <new>
#include <unordered_map>
#include <utility>
#include <vector>
#endif

namespace ppp::app::client::xtcp {
namespace {

std::uint16_t ReadBigEndian16(const std::uint8_t* bytes) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[0]) << 8) | static_cast<std::uint16_t>(bytes[1]));
}

XtcpOutputRejectionPacketShape ParseRejectedPacketShape(const void* data, int length) noexcept {
    XtcpOutputRejectionPacketShape shape;
    shape.captured = true;
    if (length <= 0) {
        return shape;
    }
    shape.supplied_bytes = static_cast<std::uint32_t>(length);
    if (data == nullptr) {
        return shape;
    }

    const auto* bytes = static_cast<const std::uint8_t*>(data);
    const std::size_t supplied = static_cast<std::size_t>(length);
    if (supplied < 20 || (bytes[0] >> 4) != 4) {
        return shape;
    }
    const std::size_t ip_header_length = static_cast<std::size_t>(bytes[0] & 0x0f) * 4;
    if (ip_header_length < 20 || ip_header_length > supplied || bytes[9] != 6) {
        return shape;
    }
    const std::size_t ipv4_total_length = ReadBigEndian16(bytes + 2);
    if (ipv4_total_length < ip_header_length + 20 || ipv4_total_length > supplied) {
        return shape;
    }

    const std::uint8_t* tcp = bytes + ip_header_length;
    const std::size_t tcp_header_length = static_cast<std::size_t>(tcp[12] >> 4) * 4;
    if (tcp_header_length < 20 || ip_header_length + tcp_header_length > ipv4_total_length) {
        return shape;
    }

    bool timestamps = false;
    bool sack = false;
    bool md5 = false;
    bool unknown = false;
    for (std::size_t option = 20; option < tcp_header_length;) {
        const std::uint8_t kind = tcp[option];
        if (kind == 0) {
            break;
        }
        if (kind == 1) {
            ++option;
            continue;
        }
        if (option + 1 >= tcp_header_length) {
            return shape;
        }
        const std::size_t option_length = tcp[option + 1];
        if (option_length < 2 || option + option_length > tcp_header_length) {
            return shape;
        }
        if (kind == 8) {
            if (option_length != 10) {
                return shape;
            }
            timestamps = true;
        }
        else if (kind == 5) {
            if (option_length < 10 || (option_length - 2) % 8 != 0) {
                return shape;
            }
            sack = true;
        }
        else if (kind == 19) {
            if (option_length != 18) {
                return shape;
            }
            md5 = true;
        }
        else {
            unknown = true;
        }
        option += option_length;
    }

    shape.parsed = true;
    shape.ipv4_total_length = static_cast<std::uint16_t>(ipv4_total_length);
    shape.ipv4_ihl = static_cast<std::uint8_t>(ip_header_length);
    shape.tcp_data_offset = static_cast<std::uint8_t>(tcp_header_length);
    shape.tcp_payload_length = static_cast<std::uint16_t>(
        ipv4_total_length - ip_header_length - tcp_header_length);
    shape.tcp_flags = tcp[13];
    shape.tcp_option_timestamps = timestamps;
    shape.tcp_option_sack = sack;
    shape.tcp_option_md5 = md5;
    shape.tcp_option_unknown = unknown;
    return shape;
}

bool IsOversizeIPv4Packet(const void* data, int length) noexcept {
    if (data == nullptr || length < 20) {
        return false;
    }
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    const std::size_t supplied = static_cast<std::size_t>(length);
    if ((bytes[0] >> 4) != 4) {
        return false;
    }
    const std::size_t ip_header_length = static_cast<std::size_t>(bytes[0] & 0x0f) * 4;
    return ip_header_length >= 20 && ip_header_length <= supplied &&
        ReadBigEndian16(bytes + 2) > 1500;
}

} // namespace

void XtcpOutputRejectionDiagnostics::Record(
    bool owner_present, bool vethernet_disposed, bool tap_present, bool accepted) noexcept {
    if (!enabled_) return;
    // The production output handler calls owner->Output exactly when owner is
    // present, then passes that returned value here.
    if (owner_present && !accepted) {
        const std::uint64_t now_ns = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        std::uint64_t expected = 0;
        (void)first_actual_output_rejected_monotonic_ns_.compare_exchange_strong(
            expected, now_ns, std::memory_order_relaxed);
    }
    if (!owner_present) {
        weak_owner_expired_.fetch_add(1, std::memory_order_relaxed);
    }
    else if (vethernet_disposed) {
        vethernet_disposed_.fetch_add(1, std::memory_order_relaxed);
    }
    else if (!tap_present) {
        tap_missing_.fetch_add(1, std::memory_order_relaxed);
    }
    else if (!accepted) {
        output_rejected_.fetch_add(1, std::memory_order_relaxed);
    }
    else {
        accepted_.fetch_add(1, std::memory_order_relaxed);
    }
}

void XtcpOutputRejectionDiagnostics::RecordRejectedPacketShape(
    const void* data, int length) noexcept {
    if (!enabled_) {
        return;
    }
    std::lock_guard<std::mutex> lock(packet_shape_sync_);
    if (first_rejected_packet_shape_.captured) {
        return;
    }
    first_rejected_packet_shape_ = ParseRejectedPacketShape(data, length);
}

void XtcpOutputRejectionDiagnostics::RecordOversizeOutputAttempt(
    const void* data, int length) noexcept {
    if (!enabled_ || !IsOversizeIPv4Packet(data, length)) {
        return;
    }
    std::lock_guard<std::mutex> lock(packet_shape_sync_);
    if (first_oversize_output_attempt_.packet_shape.captured) {
        return;
    }
    first_oversize_output_attempt_.packet_shape = ParseRejectedPacketShape(data, length);
    first_oversize_output_attempt_.first_monotonic_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

XtcpOutputRejectionSnapshot XtcpOutputRejectionDiagnostics::Snapshot() const noexcept {
    XtcpOutputRejectionPacketShape packet_shape;
    XtcpOutputPreCallOversizeAttemptSnapshot oversize_output_attempt;
    {
        std::lock_guard<std::mutex> lock(packet_shape_sync_);
        packet_shape = first_rejected_packet_shape_;
        oversize_output_attempt = first_oversize_output_attempt_;
    }
    return {
        weak_owner_expired_.load(std::memory_order_relaxed),
        vethernet_disposed_.load(std::memory_order_relaxed),
        tap_missing_.load(std::memory_order_relaxed),
        output_rejected_.load(std::memory_order_relaxed),
        accepted_.load(std::memory_order_relaxed),
        first_actual_output_rejected_monotonic_ns_.load(std::memory_order_relaxed),
        packet_shape,
        oversize_output_attempt,
    };
}

#if !defined(PPP_ENABLE_XTCP)
class XtcpRuntime::Impl final {};

XtcpRuntime::XtcpRuntime(
    const std::shared_ptr<boost::asio::io_context>&,
    OutputHandler,
    ListenerEndpointHandler,
    ExternalAcceptHandler,
    ExternalCancelHandler,
    std::shared_ptr<XtcpOutputRejectionDiagnostics>,
    bool) noexcept {}
XtcpRuntime::~XtcpRuntime() noexcept = default;
bool XtcpRuntime::Start() noexcept { return false; }
void XtcpRuntime::MarkReady() noexcept {}
void XtcpRuntime::Stop() noexcept {}
bool XtcpRuntime::SubmitIPv4Tcp(const void*, int) noexcept { return false; }
bool XtcpRuntime::IsReady() const noexcept { return false; }
bool XtcpRuntime::IsRunning() const noexcept { return false; }
std::uint64_t XtcpRuntime::Generation() const noexcept { return 0; }
ppp::app::runtime::RuntimeXtcpStats XtcpRuntime::SnapshotStats() const noexcept { return {}; }
#if defined(PPP_XTCP_RUNTIME_TESTING)
bool XtcpRuntime::EmitOutputForTesting(const std::shared_ptr<Byte>&, int,
    std::optional<ppp::tap::TxGsoMetadata>) noexcept { return false; }
#endif
#else
namespace {
std::atomic<std::uint64_t> g_next_runtime_instance_id{0};

std::uint64_t AllocateRuntimeInstanceId() noexcept {
    std::uint64_t last_issued = g_next_runtime_instance_id.load(std::memory_order_relaxed);
    for (;;) {
        const std::uint64_t id = last_issued == std::numeric_limits<std::uint64_t>::max()
            ? 1 : last_issued + 1;
        if (g_next_runtime_instance_id.compare_exchange_weak(last_issued, id,
                std::memory_order_relaxed, std::memory_order_relaxed)) {
            return id;
        }
    }
}

constexpr std::size_t kIngressMaxItems = 1024;
constexpr std::size_t kIngressMaxBytes = 8 * 1024 * 1024;
// XTCP-KCC-SNDBUF-001 (post-0005 sweep): with a large per-conn snd_buf the
// peer can offer far more in-flight data than the 1024-item ingress budget
// absorbs during the initial 16-flow burst, and the resulting loss spiral
// wedges the run (P16 DL sndbuf>=512K). Both caps get env overrides so the
// lab can size the budget with the snd_buf sweep; defaults unchanged.
std::size_t IngressMaxItems() noexcept {
    const char* env = ::getenv("OPENPPP2_XTCP_INGRESS_ITEMS");
    if (env != nullptr && env[0] != '\0') {
        const long long value = ::atoll(env);
        if (value >= 1024 && value <= 65536) {
            return static_cast<std::size_t>(value);
        }
    }
    return kIngressMaxItems;
}

std::size_t IngressMaxBytes() noexcept {
    const char* env = ::getenv("OPENPPP2_XTCP_INGRESS_BYTES");
    if (env != nullptr && env[0] != '\0') {
        const long long value = ::atoll(env);
        if (value >= 8ll * 1024 * 1024 && value <= 1024ll * 1024 * 1024) {
            return static_cast<std::size_t>(value);
        }
    }
    return kIngressMaxBytes;
}
constexpr std::size_t kMaxFlows = 4096;
constexpr std::size_t kConnectorReadBytes = 64 * 1024;
constexpr std::size_t kGsoRxMtu = 1500;
constexpr std::size_t kGsoRxDirectMtu = 24 * 1024;
constexpr std::size_t kGsoRxBridgeMtu = 12 * 1024;
constexpr std::size_t kDirectReadBudget = 32 * 1024 * 1024;
constexpr std::size_t kDirectReadFlowBudget = 16 * 1024;
// Per-flow bridge queue cap for XTCP -> connector data. Rejecting a segment
// makes the stack advertise backpressure; write completion explicitly reopens
// the receive window after both per-flow and global queues reach low watermarks.
// OPENPPP2_XTCP_WRITE_CAP_BYTES overrides it for cap-sweep experiments.
std::size_t ConnectorWriteCap() noexcept {
    const char* env = ::getenv("OPENPPP2_XTCP_WRITE_CAP_BYTES");
    if (env != nullptr) {
        const long long value = ::atoll(env);
        if (value >= static_cast<long long>(kConnectorReadBytes)) {
            return static_cast<std::size_t>(value);
        }
    }
    // 4 MiB: cap-sweep evidence - smaller caps make OnReceive reject during
    // bursts, which makes the stack withhold ACKs (peer RTOs) and collapses
    // upload throughput (64K=17, 256K=87, 1M=249, 4M=387 Mbps).
    return 4 * 1024 * 1024;
}
// Runtime-wide queued-byte budget across all flows. The per-flow cap alone is
// not a resource guard (4MiB x kMaxFlows), so admission also checks this sum.
// XTCP-UL-WRITE-BATCH-002: gather queued connector chunks into one
// async_write (one writev per batch) instead of one syscall + one completion
// per ~1.4KB segment. WRITE-BATCH-001 failed at a 256KB single chunk (loopback
// reader latency); the batch cap bounds that latency while still amortizing
// the syscall. 0/1 disables batching (A/B baseline).
std::size_t ConnectorBatchBytes() noexcept {
    const char* env = ::getenv("OPENPPP2_XTCP_CONNECTOR_BATCH_BYTES");
    if (env != nullptr && env[0] != '\0') {
        const long long value = ::atoll(env);
        if (value >= 0 && value <= 256ll * 1024) {
            return static_cast<std::size_t>(value);
        }
    }
    return 32 * 1024;
}

std::size_t GlobalQueueBudget() noexcept {
    const char* env = ::getenv("OPENPPP2_XTCP_GLOBAL_QUEUE_BYTES");
    if (env != nullptr) {
        const long long value = ::atoll(env);
        if (value > 0) {
            return static_cast<std::size_t>(value);
        }
    }
    return 32ull * 1024 * 1024;
}
// Send-admission retry cadence. Laboratory default: 1ms. LAB-ONLY knob
// (OPENPPP2_XTCP_LAB_SEND_RETRY_US): the A1 experiment proved retry cadence
// does not move throughput (stall is ACK-release bound), so this must never
// be treated as a production tuning parameter. Values below 50us clamp to 50.
std::chrono::microseconds SendRetryDelay() noexcept {
    const char* env = ::getenv("OPENPPP2_XTCP_LAB_SEND_RETRY_US");
    if (env != nullptr) {
        const long value = ::atol(env);
        if (value >= 50) {
            return std::chrono::microseconds(value);
        }
    }
    return std::chrono::milliseconds(1);
}

std::size_t GsoRxDirectMtu(std::size_t active_flows, bool direct_bridge) noexcept {
    const char* env = ::getenv("OPENPPP2_XTCP_GRO_BYTES");
    if (env != nullptr && env[0] != '\0') {
        const unsigned long long value = ::atoll(env);
        if (value >= kGsoRxMtu && value <= ::xtcp::buf::kMaxPoolPayload) {
            return static_cast<std::size_t>(value);
        }
    }
    if (direct_bridge) {
        return kGsoRxBridgeMtu;
    }
    if (active_flows < 4) {
        return kGsoRxMtu;
    }
    return kGsoRxDirectMtu;
}

bool EnvEnabled(const char* name) noexcept {
    const char* value = ::getenv(name);
    return value != nullptr && value[0] != '\0' &&
        !(value[0] == '0' && value[1] == '\0');
}

constexpr std::uint8_t kTcpFin = 0x01;
constexpr std::uint8_t kTcpSyn = 0x02;
constexpr std::uint8_t kTcpRst = 0x04;
constexpr std::uint8_t kTcpAck = 0x10;

struct FlowKey final {
    std::uint32_t remote_address = 0;
    std::uint32_t local_address = 0;
    std::uint16_t remote_port = 0;
    std::uint16_t local_port = 0;

    bool operator==(const FlowKey& other) const noexcept {
        return remote_address == other.remote_address &&
            local_address == other.local_address &&
            remote_port == other.remote_port && local_port == other.local_port;
    }
};

struct FlowKeyHash final {
    std::size_t operator()(const FlowKey& key) const noexcept {
        // XTCP-SHARED-PATH-001 S1: FNV + murmur finalizer。原 xor-hash 的最低位
        // 只由 local_port 决定 (remote/local 地址与 remote_port<<16 的低位恒定),
        // 顺序源端口共享奇偶时 16 条 flow 全部落进同一 shard (实测 100%/0%)。
        // 逐字段乘法混合 + finalizer 让每个字段影响全部位, 分片均匀。
        std::uint64_t value = 1469598103934665603ull;
        value ^= key.remote_address;
        value *= 1099511628211ull;
        value ^= key.local_address;
        value *= 1099511628211ull;
        value ^= (static_cast<std::uint64_t>(key.remote_port) << 16) ^ key.remote_port;
        value *= 1099511628211ull;
        value ^= key.local_port;
        value *= 1099511628211ull;
        value ^= value >> 33;
        value *= 0xff51afd7ed558ccdULL;
        value ^= value >> 33;
        return static_cast<std::size_t>(value);
    }
};

struct ParsedPacket final {
    FlowKey key;
    ::xtcp::core::Endpoint remote;
    ::xtcp::core::Endpoint local;
    std::uint8_t flags = 0;
};

bool ParsePacket(const void* packet, int packet_length, ParsedPacket& parsed) noexcept {
    if (packet == nullptr || packet_length < 40) {
        return false;
    }
    const Byte* bytes = static_cast<const Byte*>(packet);
    ::xtcp::core::Ip4Hdr ip;
    if (!::xtcp::core::ParseIp4(bytes, static_cast<UInt32>(packet_length), ip) ||
        ip.proto != 6 || IsFragmentedIPv4(ip.frag_off, ip.flags) ||
        ip.payload_off + 20 > static_cast<UInt32>(packet_length)) {
        return false;
    }
    const Byte* tcp = bytes + ip.payload_off;
    parsed.key.remote_address = ip.src;
    parsed.key.local_address = ip.dst;
    parsed.key.remote_port = static_cast<std::uint16_t>((tcp[0] << 8) | tcp[1]);
    parsed.key.local_port = static_cast<std::uint16_t>((tcp[2] << 8) | tcp[3]);
    parsed.flags = tcp[13];
    parsed.remote.family = 4;
    parsed.remote.addr[0] = ip.src;
    parsed.remote.port = parsed.key.remote_port;
    parsed.local.family = 4;
    parsed.local.addr[0] = ip.dst;
    parsed.local.port = parsed.key.local_port;
    return parsed.key.remote_port != 0 && parsed.key.local_port != 0;
}

// Split a TCPv4 super-frame into bounded GRO chunks. The default keeps native
// GRO for four or more active flows while single-flow traffic stays on the
// stable MSS path. OPENPPP2_XTCP_GSO_RX=1 forces MSS splitting and
// OPENPPP2_XTCP_GRO_BYTES overrides the direct-GRO chunk size.
uint32_t GsoChecksumRaw(const uint8_t* data, std::size_t length) noexcept {
    uint32_t sum = 0;
    std::size_t i = 0;
    while (i + 2 <= length) {
        sum += static_cast<uint32_t>(data[i] << 8) | data[i + 1];
        i += 2;
    }
    if (i < length) {
        sum += static_cast<uint32_t>(data[i]) << 8;
    }
    return sum;
}

uint16_t GsoChecksum(const uint8_t* data, std::size_t length, uint32_t sum = 0) noexcept {
    std::size_t i = 0;
    while (i + 2 <= length) {
        sum += static_cast<uint32_t>(data[i] << 8) | data[i + 1];
        i += 2;
    }
    if (i < length) {
        sum += static_cast<uint32_t>(data[i]) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

std::size_t GsoSplit(const uint8_t* frame, std::size_t length,
    std::size_t target_mtu, ::xtcp::buf::BufRef* out, std::size_t out_cap) noexcept {
    const std::size_t ihl = static_cast<std::size_t>(frame[0] & 0x0F) * 4;
    if (ihl < 20 || length < ihl + 20) {
        return 0;
    }
    const std::size_t total_len = static_cast<std::size_t>(frame[2] << 8) | frame[3];
    if (total_len > length) {
        return 0;
    }
    const uint8_t* tcp = frame + ihl;
    const std::size_t doff = static_cast<std::size_t>(tcp[12] >> 4) * 4;
    if (doff < 20 || ihl + doff > total_len) {
        return 0;
    }
    const std::size_t payload = total_len - ihl - doff;
    if (target_mtu <= ihl + doff) {
        return 0;
    }
    const std::size_t seg_payload = target_mtu - ihl - doff;
    const std::size_t count = (payload + seg_payload - 1) / seg_payload;
    if (count > out_cap) {
        return 0;
    }
    const uint32_t seq0 = (static_cast<uint32_t>(tcp[4]) << 24) |
        (static_cast<uint32_t>(tcp[5]) << 16) |
        (static_cast<uint32_t>(tcp[6]) << 8) | tcp[7];
    for (std::size_t k = 0; k < count; ++k) {
        const std::size_t off = k * seg_payload;
        const std::size_t this_payload = off + seg_payload <= payload ? seg_payload : payload - off;
        const std::size_t seg_len = ihl + doff + this_payload;
        ::xtcp::buf::BufRef ref = ::xtcp::buf::BufRef::Acquire(static_cast<UInt32>(seg_len));
        if (ref.IsEmpty()) {
            return 0;
        }
        uint8_t* w = ref.Data();
        std::memcpy(w, frame, ihl + doff);
        std::memcpy(w + ihl + doff, frame + ihl + doff + off, this_payload);
        const uint16_t ip_total = static_cast<uint16_t>(seg_len);
        w[2] = static_cast<uint8_t>(ip_total >> 8);
        w[3] = static_cast<uint8_t>(ip_total);
        w[10] = 0; w[11] = 0;
        const uint16_t ip_csum = GsoChecksum(w, ihl);
        w[10] = static_cast<uint8_t>(ip_csum >> 8);
        w[11] = static_cast<uint8_t>(ip_csum);
        const uint32_t seq = seq0 + static_cast<uint32_t>(off);
        uint8_t* t = w + ihl;
        t[4] = static_cast<uint8_t>(seq >> 24);
        t[5] = static_cast<uint8_t>(seq >> 16);
        t[6] = static_cast<uint8_t>(seq >> 8);
        t[7] = static_cast<uint8_t>(seq);
        t[16] = 0; t[17] = 0;
        uint32_t partial = GsoChecksumRaw(w + 12, 8);
        // 伪首部 (协议=6, TCP 长度) 按 BE16 字对求和。
        partial += static_cast<uint32_t>(0x0006);
        partial += static_cast<uint32_t>(doff + this_payload);
        const uint16_t tcp_csum = GsoChecksum(t, doff + this_payload, partial);
        t[16] = static_cast<uint8_t>(tcp_csum >> 8);
        t[17] = static_cast<uint8_t>(tcp_csum);
        ref.SetLen(static_cast<UInt32>(seg_len));
        out[k] = std::move(ref);
    }
    return count;
}

boost::asio::ip::address_v4 ToAddress(std::uint32_t network_address) noexcept {
    return boost::asio::ip::address_v4(IPv4AddressBytes(network_address));
}
} // namespace

class XtcpRuntime::Impl final :
    public XtcpFirstLegHooks,
    public std::enable_shared_from_this<XtcpRuntime::Impl> {
public:
    using Strand = boost::asio::strand<boost::asio::io_context::executor_type>;

    struct Flow final {
        Flow(
            const std::shared_ptr<boost::asio::io_context>& context,
            const FlowKey& flow_key,
            const ::xtcp::core::Endpoint& remote_endpoint,
            const ::xtcp::core::Endpoint& local_endpoint,
            std::uint64_t generation_value) noexcept
            : key(flow_key), remote(remote_endpoint), local(local_endpoint),
              generation(generation_value), connector(*context), retry_timer(*context),
              resume_timer(*context) {}

        FlowKey key;
        ::xtcp::core::Endpoint remote;
        ::xtcp::core::Endpoint local;
        std::uint64_t generation = 0;
        std::size_t shard = 0;  // XTCP-SHARED-PATH-001 S1: owning shard index
        UInt64 connection_id = 0;
        std::uint16_t source_port = 0;
        std::shared_ptr<XtcpSecondLegHooks> direct_second_leg;
        bool direct_bridge = false;
        boost::asio::ip::tcp::socket connector;
        boost::asio::steady_timer retry_timer;
        boost::asio::steady_timer resume_timer;
        ::xtcp::buf::BufRef deferred_syn;
        std::array<Byte, kConnectorReadBytes> read_buffer{};
        std::vector<Byte> pending_read;
        struct DirectReadItem final {
            XtcpDirectReadReservation reservation;
            std::shared_ptr<Byte> payload;
            std::uint64_t admitted_us = 0;
        };
        std::deque<DirectReadItem> direct_read_queue;
        std::size_t direct_read_bytes = 0;
        std::deque<std::shared_ptr<std::vector<Byte>>> write_queue;
        std::vector<boost::asio::const_buffer> write_buffers_;
        std::vector<std::shared_ptr<std::vector<Byte>>> write_in_flight_;
        std::size_t write_bytes = 0;
        bool connector_connected = false;
        bool connector_read_eof = false;
        bool direct_peer_eof = false;
        bool second_leg_close_requested = false;
        bool connector_send_shutdown = false;
        bool first_leg_ready = false;
        bool first_leg_eof = false;
        bool first_leg_close_started = false;
        bool connector_receive_backpressured = false;
        bool resume_pending = false;
        bool resume_capacity_available = false;
        bool resume_terminal = false;
        bool resume_recheck_posted = false;
        bool receive_rejected = false;
        std::uint32_t upload_budget_blocked_bytes = 0;
        std::uint8_t resume_retries = 0;
        // The ppp-side forwarding for this flow is gone: the connector's peer
        // socket is closed or about to be. The read side still drains whatever
        // the kernel already received (EOF then closes the first leg
        // gracefully; a reset aborts it, since unread data was lost).
        bool peer_gone = false;
        // Set when the second leg failed before the first leg was established:
        // the deferred SYN is injected only so OnAccept rejects it with RST,
        // failing the app's pending connect fast instead of timing out.
        bool abort_when_ready = false;
        bool write_active = false;
        bool read_active = false;
        bool closing = false;
        // Perf diagnostic (strand-only): when Send admission rejected this
        // chunk, when the chunk finally went through; feeds send_stall_us.
        std::uint64_t send_stall_start_us = 0;
        // Timestamp carried only while OPENPPP2_XTCP_PERF_JSON is active.
        std::uint64_t direct_send_accepted_us = 0;
        // XTCP-KCC-PACING-001: consecutive SendData rejections back the retry
        // cadence off exponentially (1ms -> 32ms) so a persistently full
        // snd_buf cannot turn N flows into a N*1K/s retry storm that spins
        // the executor and amplifies offered load (P16 sndbuf>=512K wedge).
        std::uint32_t send_retry_shift = 0;
        // Optional transition-only SendData rejection snapshot. No packet
        // pointer is retained, and a successful admission clears this state.
        bool send_admission_blocked = false;
        bool send_admission_snapshot_valid = false;
        std::uint64_t send_admission_blocked_since_us = 0;
        ::xtcp::core::SendAdmissionSnapshot send_admission_snapshot;
        // Perf diagnostic (strand-only): async_write submit timestamp and the
        // previous completion timestamp, for cycle/gap histograms.
        std::uint64_t write_submit_us = 0;
        std::uint64_t write_last_complete_us = 0;
        // Bytes handed to the in-flight async_write; queued-byte accounting
        // is debited here on completion and for the remainder at teardown.
        std::size_t in_flight_bytes = 0;
    };

    Impl(
        const std::shared_ptr<boost::asio::io_context>& context,
        OutputHandler output,
        ListenerEndpointHandler listener_endpoint,
        ExternalAcceptHandler external_accept,
        ExternalCancelHandler external_cancel,
        std::shared_ptr<XtcpOutputRejectionDiagnostics> output_rejection_diagnostics,
        bool tx_gso_supported) noexcept
        : context_(context),
          output_(std::move(output)), tx_gso_supported_(tx_gso_supported),
          listener_endpoint_(std::move(listener_endpoint)),
          external_accept_(std::move(external_accept)), external_cancel_(std::move(external_cancel)),
          output_rejection_diagnostics_(std::move(output_rejection_diagnostics)) {}

    ~Impl() noexcept {
        running_.store(false, std::memory_order_release);
        if (own_context_) {
            own_context_->stop();
        }
        for (std::thread& t : own_threads_) {
            if (t.joinable()) {
                t.join();
            }
        }
    }

    bool Start() noexcept {
        std::lock_guard<std::mutex> lock(state_sync_);
        if (!context_ || running_.load(std::memory_order_acquire) ||
            stopping_.load(std::memory_order_acquire)) {
            return false;
        }
        lease_ = XtcpPoolLease::Acquire();
        if (!lease_) {
            return false;
        }
        CompleteAndClearDirectReads();
        direct_flows_.store(0, std::memory_order_relaxed);
        connector_receive_blocked_.store(0, std::memory_order_relaxed);
        stats_.Reset();
        perf_json_enabled_.store(false, std::memory_order_relaxed);
        send_admission_enabled_ = false;
        ack_release_enabled_ = false;
        output_rejection_enabled_ = false;
        perf_prev_ = {};
        tcp_sample_ = {};
        ndi_stats_ = {};
        ndi_prev_ = {};
        shard_prev_.clear();
        ndi_pps_ = 0;
        ndi_out_p50_us_ = 0.0;
        ndi_out_p95_us_ = 0.0;
        ndi_out_p99_us_ = 0.0;
        ndi_iv_p50_us_ = 0.0;
        ndi_iv_p95_us_ = 0.0;
        ndi_batch_avg_ = 0.0;
        ndi_batch_max_ = 0;
        flows_above_256k_ = 0;
        flows_above_1m_ = 0;
        flows_above_2m_ = 0;
        std::atomic_store_explicit(&direct_queue_telemetry_,
            std::make_shared<ppp::app::runtime::XtcpDirectQueueTelemetry>(),
            std::memory_order_release);
        const std::weak_ptr<Impl> weak = shared_from_this();
        counted_output_ = [weak, handler = output_](std::shared_ptr<Byte>&& data, int length,
            std::optional<ppp::tap::TxGsoMetadata> gso) noexcept {
            if (!handler) {
                return false;
            }
            const Byte* raw = data ? data.get() : nullptr;
            if (const std::shared_ptr<Impl> self = weak.lock()) {
                if (self->output_rejection_diagnostics_ &&
                    self->output_rejection_diagnostics_->Enabled()) {
                    self->output_rejection_diagnostics_->RecordOversizeOutputAttempt(raw, length);
                }
            }
            if (!handler(std::move(data), length, gso)) {
                if (const std::shared_ptr<Impl> self = weak.lock()) {
                    if (self->output_rejection_diagnostics_ &&
                        self->output_rejection_diagnostics_->Enabled()) {
                        self->output_rejection_diagnostics_->RecordRejectedPacketShape(raw, length);
                    }
                }
                return false;
            }
            if (const std::shared_ptr<Impl> self = weak.lock()) {
                self->stats_.output_packets.fetch_add(1, std::memory_order_relaxed);
                self->stats_.output_bytes.fetch_add(
                    static_cast<std::uint64_t>(static_cast<std::size_t>(length)),
                    std::memory_order_relaxed);
            }
            return true;
        };
        // XTCP-SHARED-PATH-001 S1: shard 数 (env OPENPPP2_XTCP_SHARDS, 默认 1)。
        // 每 shard = 独立 strand/stack/backend/ingress budget/handoff/poll timer/
        // flow 表; Submit 按 4-tuple hash 路由, 同一 flow (含 SYN) 永远同 shard。
        int shard_count = 1;
        {
            const char* shards_env = ::getenv("OPENPPP2_XTCP_SHARDS");
            if (shards_env != nullptr && shards_env[0] != '\0') {
                const long value = ::atol(shards_env);
                if (1 <= value && value <= 8) {
                    shard_count = static_cast<int>(value);
                }
            }
        }
        const char* cc_env = ::getenv("OPENPPP2_XTCP_CC");
        const char* cc = (cc_env != nullptr && cc_env[0] != '\0') ? cc_env : "kcc";
        unsigned long long sndbuf_value = 0;
        {
            const char* sndbuf_env = ::getenv("OPENPPP2_XTCP_SNDBUF_BYTES");
            if (sndbuf_env != nullptr && sndbuf_env[0] != '\0') {
                const unsigned long long sndbuf = ::atoll(sndbuf_env);
                if (sndbuf >= 1024) {
                    sndbuf_value = sndbuf;
                }
            }
        }
        unix_bridge_ = []() noexcept {
            const char* env = ::getenv("OPENPPP2_XTCP_UNIX_BRIDGE");
            return env != nullptr && env[0] == '1' && env[1] == '\0';
        }();
        shard_count_ = shard_count;
        if (shard_count > 1) {
            // XTCP-SHARED-PATH-001 S1: 默认 context 只在主线程 run (Executors::Run),
            // strand 再多也没有并行执行域。shards>1 时给 runtime 建专属 io_context
            // + 每 shard 一个工作线程; 所有 shard strand/poll timer/flow connector
            // 都跑在这个池上。shards=1 保持外部 context 不变 (行为零变化)。
            own_context_ = std::make_shared<boost::asio::io_context>();
            context_ = own_context_;
        }
        shards_.resize(static_cast<std::size_t>(shard_count));
        for (std::size_t i = 0; i < shards_.size(); ++i) {
            Shard& s = shards_[i];
            s.index = i;
            s.strand = std::make_shared<Strand>(context_->get_executor());
            s.backend = std::unique_ptr<XtcpNdiBackend>(
                new (std::nothrow) XtcpNdiBackend(counted_output_, tx_gso_supported_));
            if (!s.backend) {
                for (std::size_t j = 0; j < i; ++j) {
                    shards_[j].backend->Stop();
                }
                shards_.clear();
                lease_.reset();
                return false;
            }
            s.stack = std::unique_ptr<::xtcp::XtcpStack>(
                new (std::nothrow) ::xtcp::XtcpStack(s.backend.get()));
            if (!s.stack) {
                s.backend->Stop();
                for (std::size_t j = 0; j < i; ++j) {
                    shards_[j].backend->Stop();
                }
                shards_.clear();
                lease_.reset();
                return false;
            }
            // 拥塞控制可选 (XTCP-CC-SELECT-001): 默认 KCC (上游默认, 开发者维护)。
            // env 可切 bbr/cubic/reno (0005 修复后 KCC 追平 CUBIC, 恢复默认)。
            s.stack->SetDefaultCongestionControl(cc);
            // KCC snd_buf 实验 (XTCP-KCC-SNDBUF-001): env 可调, 默认不设 (=上游 64K)。
            if (sndbuf_value != 0) {
                s.stack->SetSndBuf(static_cast<UInt32>(sndbuf_value));
            }
            s.stack->SetAcceptHandler([weak, i](UInt64 connection_id,
                const ::xtcp::core::Endpoint& remote,
                const ::xtcp::core::Endpoint& local) noexcept {
                const std::shared_ptr<Impl> self = weak.lock();
                return self && self->OnAccept(self->shards_[i], connection_id, remote, local);
            });
            s.stack->SetRecvHandlerChecked([weak, i](UInt64 connection_id, const Byte* data, UInt32 length) noexcept {
                const std::shared_ptr<Impl> self = weak.lock();
                return self && self->OnReceive(self->shards_[i], connection_id, data, length);
            });
            s.stack->SetStateHandler([weak, i](UInt64 connection_id, ::xtcp::core::TcpState state) noexcept {
                if (const std::shared_ptr<Impl> self = weak.lock()) {
                    self->OnState(self->shards_[i], connection_id, state);
                }
            });
        }
        {
            std::uint64_t budget_generation = 0;
            for (Shard& s : shards_) {
                budget_generation = s.budget.Start();
            }
            generation_.store(budget_generation, std::memory_order_release);
        }
        if (!InitializeUploadBudget()) {
            for (Shard& s : shards_) {
                s.backend->Stop();
                s.stack.reset();
                s.backend.reset();
            }
            shards_.clear();
            lease_.reset();
            return false;
        }
        running_.store(true, std::memory_order_release);
        ready_.store(false, std::memory_order_release);
        if (own_context_) {
            for (int i = 0; i < shard_count; ++i) {
                own_threads_.emplace_back([own = own_context_]() noexcept {
#if defined(__linux__)
                    // 线程名用于 /proc thread dump 诊断 (测试目标不链 stdafx.cpp,
                    // 故不走 ppp::SetThreadName)。
                    pthread_setname_np(pthread_self(), "xtcp-io");
#endif
                    const auto guard = boost::asio::make_work_guard(*own);
                    own->run();
                });
            }
        }
        StartPerfDump();
        for (Shard& s : shards_) {
            SchedulePoll(s, generation_.load(std::memory_order_acquire));
        }
        runtime_instance_id_.store(AllocateRuntimeInstanceId(), std::memory_order_release);
        return true;
    }

#if defined(PPP_XTCP_RUNTIME_TESTING)
    bool EmitOutputForTesting(const std::shared_ptr<Byte>& data, int length,
        std::optional<ppp::tap::TxGsoMetadata> gso) noexcept {
        return counted_output_ && counted_output_(std::shared_ptr<Byte>(data), length, gso);
    }
#endif

    void MarkReady() noexcept {
        const std::uint64_t generation = generation_.load(std::memory_order_acquire);
        {
            std::lock_guard<std::mutex> lock(state_sync_);
            if (!running_.load(std::memory_order_acquire)) {
                return;
            }
            for (Shard& s : shards_) {
                s.budget.MarkReady(generation);
                ready_.store(s.budget.IsReady(), std::memory_order_release);
            }
        }
    }

    void Stop() noexcept {
        bool expected = false;
        if (!stopping_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            return;
        }
        running_.store(false, std::memory_order_release);
        ready_.store(false, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(state_sync_);
            for (Shard& s : shards_) {
                s.budget.Stop();
            }
        }
        if (shards_.empty()) {
            DoStopFinalize();
            return;
        }
        const std::shared_ptr<Impl> self = shared_from_this();
        const std::shared_ptr<std::atomic<int>> remaining =
            std::make_shared<std::atomic<int>>(static_cast<int>(shards_.size()));
        for (std::size_t i = 0; i < shards_.size(); ++i) {
            boost::asio::post(*shards_[i].strand, [self, i, remaining]() noexcept {
                self->DoStopShard(self->shards_[i]);
                if (remaining->fetch_sub(1, std::memory_order_acq_rel) == 1) {
                    self->DoStopFinalize();
                }
            });
        }
    }

    bool Submit(const void* packet, int packet_length) noexcept {
        if (packet == nullptr || packet_length < 1 || !ready_.load(std::memory_order_acquire)) {
            stats_.ingress_dropped.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        const std::uint64_t generation = generation_.load(std::memory_order_acquire);
        // XTCP-SHARED-PATH-001 S1: 按 4-tuple hash 路由, 同一 flow (含 SYN)
        // 永远落同一 shard (ordering/ACK 状态/deferred SYN/generation/close
        // 生命周期因此天然保持)。解析失败的包走 shard 0, 在 ProcessIngress
        // 里重解析并按原语义静默丢弃。
        ParsedPacket parsed;
        const bool has_parsed = ParsePacket(packet, packet_length, parsed);
        const std::size_t index = has_parsed && shard_count_ > 1
            ? FlowKeyHash{}(parsed.key) % shards_.size() : 0;
        Shard& s = shards_[index];
        // Preserve large GRO chunks for multi-flow traffic, bounded by the
        // largest XTCP pool tier. Single-flow traffic keeps MSS-sized chunks.
        static const bool gso_rx = EnvEnabled("OPENPPP2_XTCP_GSO_RX");
        ::xtcp::buf::BufRef splits[64];
        std::size_t split_count = 0;
        const std::uint64_t opened = stats_.flows_opened.load(std::memory_order_relaxed);
        const std::uint64_t closed = stats_.flows_closed.load(std::memory_order_relaxed);
        const std::size_t active_flows = static_cast<std::size_t>(
            opened >= closed ? opened - closed : 0);
        const std::size_t gso_rx_target = gso_rx
            ? kGsoRxMtu : GsoRxDirectMtu(active_flows,
                direct_flows_.load(std::memory_order_relaxed) != 0);
        if (has_parsed && packet_length > static_cast<int>(gso_rx_target)) {
            split_count = GsoSplit(static_cast<const uint8_t*>(packet),
                static_cast<std::size_t>(packet_length), gso_rx_target, splits, 64);
            if (split_count == 0) {
                stats_.ingress_dropped.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
            std::size_t admitted = 0;
            for (; admitted < split_count; ++admitted) {
                if (!s.budget.TryAdmit(generation, splits[admitted].Len())) {
                    break;
                }
            }
            if (admitted != split_count) {
                for (std::size_t k = 0; k < admitted; ++k) {
                    s.budget.Release(splits[k].Len());
                }
                stats_.ingress_dropped.fetch_add(1, std::memory_order_relaxed);
                s.dropped.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
            const std::uint64_t enqueue_us = NowUs();
            {
                std::lock_guard<std::mutex> lock(s.handoff_sync);
                for (std::size_t k = 0; k < split_count; ++k) {
                    HandoffItem& item = s.handoff.emplace_back();
                    item.packet = std::move(splits[k]);
                    item.parsed = parsed;
                    item.has_parsed = true;
                    item.generation = generation;
                    item.enqueue_us = enqueue_us;
                }
            }
            const std::shared_ptr<Impl> self = shared_from_this();
            if (!s.handoff_posted.exchange(true, std::memory_order_acq_rel)) {
                boost::asio::post(*s.strand, [self, index]() noexcept {
                    self->DrainIngress(self->shards_[index]);
                });
            }
            stats_.ingress_enqueued.fetch_add(split_count, std::memory_order_relaxed);
            stats_.ingress_submitted.fetch_add(split_count, std::memory_order_relaxed);
            s.enqueued.fetch_add(split_count, std::memory_order_relaxed);
            return true;
        }
        if (!s.budget.TryAdmit(generation, static_cast<std::size_t>(packet_length))) {
            stats_.ingress_dropped.fetch_add(1, std::memory_order_relaxed);
            s.dropped.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        // XTCP-UL-ZEROCOPY-001: 上游 BufRef 是 zero-copy 语义 (movable, not
        // copyable)。Submit 直接分配一次 BufRef, ProcessIngress 直接注入,
        // StartFlow 把 SYN 的 BufRef 移交给 deferred_syn, 全程 1 次分配 + 1 次拷贝。
        ::xtcp::buf::BufRef owned = ::xtcp::buf::BufRef::Acquire(
            static_cast<UInt32>(packet_length));
        if (owned.IsEmpty()) {
            s.budget.Release(static_cast<std::size_t>(packet_length));
            stats_.ingress_dropped.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        std::memcpy(owned.Data(), packet, static_cast<std::size_t>(packet_length));
        owned.SetLen(static_cast<UInt32>(packet_length));
        // XTCP-STRAND-DISPATCH-001 批量投递: 每包一次 asio::post 在 64KB 突发
        // (~44 段) 下把 strand 变成 post 风暴, in-flight 打满 budget 上限后丢包
        // (owner.dropped 累计 68 万, UL GSO-on 崩到 0.3-0.55x)。改为 Submit 压入
        // handoff 队列, 每个突发只 post 一次 drain 闭包, strand 单次调度消化整批。
        {
            std::lock_guard<std::mutex> lock(s.handoff_sync);
            HandoffItem& item = s.handoff.emplace_back();
            item.packet = std::move(owned);
            item.parsed = parsed;
            item.has_parsed = has_parsed;
            item.generation = generation;
            item.enqueue_us = NowUs();
        }
        const std::shared_ptr<Impl> self = shared_from_this();
        if (!s.handoff_posted.exchange(true, std::memory_order_acq_rel)) {
            try {
                boost::asio::post(*s.strand, [self, index]() noexcept {
                    self->DrainIngress(self->shards_[index]);
                });
            }
            catch (...) {
                std::vector<HandoffItem> abandoned;
                {
                    std::lock_guard<std::mutex> lock(s.handoff_sync);
                    abandoned.swap(s.handoff);
                    s.handoff_posted.store(false, std::memory_order_release);
                }
                for (HandoffItem& item : abandoned) {
                    s.budget.Release(item.packet.IsEmpty() ? 0 : item.packet.Len());
                    stats_.ingress_dropped.fetch_add(1, std::memory_order_relaxed);
                }
                return false;
            }
        }
        stats_.ingress_enqueued.fetch_add(1, std::memory_order_relaxed);
        stats_.ingress_submitted.fetch_add(1, std::memory_order_relaxed);
        s.enqueued.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    bool IsReady() const noexcept { return ready_.load(std::memory_order_acquire); }
    bool IsRunning() const noexcept { return running_.load(std::memory_order_acquire); }
    std::uint64_t Generation() const noexcept { return generation_.load(std::memory_order_acquire); }

    ppp::app::runtime::RuntimeXtcpStats SnapshotStats() const noexcept {
        ppp::app::runtime::RuntimeXtcpStats snapshot;
        snapshot.runtime_generation = Generation();
        snapshot.runtime_instance_id = runtime_instance_id_.load(std::memory_order_acquire);
        snapshot.direct_bridge_starts =
            stats_.direct_bridge_starts.load(std::memory_order_relaxed);
        snapshot.direct_bridge_active = direct_flows_.load(std::memory_order_relaxed);
        snapshot.direct_bridge_fallbacks =
            stats_.direct_bridge_fallbacks.load(std::memory_order_relaxed);
        snapshot.direct_upload_accepted_chunks =
            stats_.direct_upload_accepted_chunks.load(std::memory_order_relaxed);
        snapshot.direct_upload_accepted_bytes =
            stats_.direct_upload_accepted_bytes.load(std::memory_order_relaxed);
        snapshot.direct_download_accepted_bytes =
            stats_.direct_download_accepted_bytes.load(std::memory_order_relaxed);
        snapshot.direct_upload_writable_callbacks =
            stats_.direct_upload_writable_callbacks.load(std::memory_order_relaxed);
        snapshot.direct_download_writable_callbacks =
            stats_.direct_download_writable_callbacks.load(std::memory_order_relaxed);
        snapshot.ingress_submitted = stats_.ingress_submitted.load(std::memory_order_relaxed);
        snapshot.ingress_dropped = stats_.ingress_dropped.load(std::memory_order_relaxed);
        snapshot.ingress_injected = stats_.ingress_injected.load(std::memory_order_relaxed);
        snapshot.flows_opened = stats_.flows_opened.load(std::memory_order_relaxed);
        snapshot.flows_closed = stats_.flows_closed.load(std::memory_order_relaxed);
        snapshot.flows_active = snapshot.flows_opened >= snapshot.flows_closed
            ? snapshot.flows_opened - snapshot.flows_closed : 0;
        snapshot.timer_polls = stats_.timer_polls.load(std::memory_order_relaxed);
        snapshot.timer_events = stats_.timer_events.load(std::memory_order_relaxed);
        snapshot.output_packets = stats_.output_packets.load(std::memory_order_relaxed);
        snapshot.output_bytes = stats_.output_bytes.load(std::memory_order_relaxed);
        for (const Shard& shard : shards_) {
            if (shard.backend) {
                if (shard.backend->Caps() == ::xtcp::ndi::kCapTsoTx) {
                    snapshot.ndi_gso_enabled = true;
                }
                const XtcpNdiBackend::TxStats ndi = shard.backend->SnapshotTxStats();
                snapshot.ndi_gso_packets += ndi.gso_packets;
                snapshot.ndi_gso_bytes += ndi.gso_bytes;
                snapshot.ndi_gso_rejected += ndi.gso_rejected;
            }
        }
        snapshot.connector_read_bytes = stats_.connector_read_bytes.load(std::memory_order_relaxed);
        snapshot.connector_written_bytes = stats_.connector_written_bytes.load(std::memory_order_relaxed);
        snapshot.queued_bytes = stats_.queued_bytes_total.load(std::memory_order_relaxed);
        snapshot.queued_bytes_highwater = stats_.queued_bytes_highwater.load(std::memory_order_relaxed);
        snapshot.resume_requested = stats_.resume_requested.load(std::memory_order_relaxed);
        snapshot.resume_effective = stats_.resume_effective.load(std::memory_order_relaxed);
        snapshot.resume_result_not_blocked =
            stats_.resume_result_not_blocked.load(std::memory_order_relaxed);
        snapshot.resume_result_window_full =
            stats_.resume_result_window_full.load(std::memory_order_relaxed);
        snapshot.resume_result_connection_missing =
            stats_.resume_result_connection_missing.load(std::memory_order_relaxed);
        snapshot.resume_pending = stats_.resume_pending.load(std::memory_order_relaxed);
        snapshot.resume_coalesced = stats_.resume_coalesced.load(std::memory_order_relaxed);
        snapshot.resume_terminal = stats_.resume_terminal.load(std::memory_order_relaxed);
        snapshot.resume_retry = stats_.resume_retry.load(std::memory_order_relaxed);
        snapshot.resume_window_full_retry =
            stats_.resume_window_full_retry.load(std::memory_order_relaxed);
        snapshot.direct_download_chunks = stats_.direct_download_chunks.load(std::memory_order_relaxed);
        snapshot.direct_download_rejected = stats_.direct_download_rejected.load(std::memory_order_relaxed);
        snapshot.direct_upload_rejected = stats_.direct_upload_rejected.load(std::memory_order_relaxed);
        snapshot.upload_budget_rejected = stats_.upload_budget_rejected.load(std::memory_order_relaxed);
        if (auto budget = std::atomic_load_explicit(&upload_budget_, std::memory_order_acquire)) {
            const auto state = budget->Snapshot();
            snapshot.upload_budget_bytes = state.bytes;
            snapshot.upload_budget_items = state.items;
            snapshot.upload_budget_max_bytes = state.max_bytes;
            snapshot.upload_budget_max_items = state.max_items;
            snapshot.upload_budget_waiters = state.waiters;
            snapshot.upload_budget_wake_events = state.wake_events;
            snapshot.upload_budget_fairness_switches = state.fairness_switches;
        }
        snapshot.upload_budget_wake_empty =
            stats_.upload_budget_wake_empty.load(std::memory_order_relaxed);
        if (const std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry> telemetry =
                std::atomic_load_explicit(&direct_queue_telemetry_, std::memory_order_acquire)) {
            const ppp::app::runtime::XtcpDirectQueueSnapshot direct_queue = telemetry->Snapshot();
            snapshot.direct_upload_queue_bytes = direct_queue.bytes;
            snapshot.direct_upload_queue_items = direct_queue.items;
            snapshot.direct_upload_backpressured = direct_queue.backpressured;
            snapshot.direct_upload_writer_active = direct_queue.writer_active;
            snapshot.direct_upload_writer_progress_age_ms = direct_queue.writer_progress_age_ms;
        }
        snapshot.second_leg_close_requested =
            stats_.second_leg_close_requested.load(std::memory_order_relaxed);
        snapshot.second_leg_close_duplicate_suppressed =
            stats_.second_leg_close_duplicate_suppressed.load(std::memory_order_relaxed);
        snapshot.degraded_half_close = stats_.degraded_half_close.load(std::memory_order_relaxed);
        snapshot.direct_download_queue_bytes =
            direct_read_bytes_.load(std::memory_order_relaxed);
        snapshot.direct_download_queue_bytes_highwater =
            stats_.direct_download_queue_bytes_highwater.load(std::memory_order_relaxed);
        return snapshot;
    }

    void OnFirstLegReady(std::uint64_t runtime_generation, std::uint64_t flow_generation) noexcept override {
        PostFirstLegReady(runtime_generation, flow_generation, {});
    }

    void OnFirstLegDirectReady(std::uint64_t runtime_generation,
        std::uint64_t flow_generation,
        const std::shared_ptr<XtcpSecondLegHooks>& second_leg) noexcept override {
        if (!second_leg || !IsCurrent(runtime_generation)) {
            PostFirstLegReady(runtime_generation, flow_generation, {});
            return;
        }
        const std::size_t shard_index = static_cast<std::size_t>(flow_generation >> 56);
        if (flow_generation == 0 || shard_index >= shards_.size()) {
            return;
        }
        try {
            {
                std::lock_guard<std::mutex> lock(direct_read_sync_);
                direct_second_legs_[flow_generation] = second_leg;
            }
            second_leg->SetDirectQueueTelemetry(std::atomic_load_explicit(
                &direct_queue_telemetry_, std::memory_order_acquire));
        }
        catch (...) {
            return;
        }
        PostFirstLegReady(runtime_generation, flow_generation, second_leg);
    }

    void PostFirstLegReady(std::uint64_t runtime_generation, std::uint64_t flow_generation,
        const std::shared_ptr<XtcpSecondLegHooks>& second_leg) noexcept {
        const std::shared_ptr<Impl> self = shared_from_this();
        // S1: flow generation 高位带 shard 标签, 直接投递到该 shard strand。
        const std::size_t shard_index = static_cast<std::size_t>(flow_generation >> 56);
        if (shard_index >= shards_.size()) {
            return;
        }
        try {
            boost::asio::post(*shards_[shard_index].strand,
                [self, runtime_generation, flow_generation, second_leg]() noexcept {
                if (!self->IsCurrent(runtime_generation)) {
                    if (second_leg) {
                        self->EraseDirectSecondLeg(flow_generation, second_leg);
                    }
                    return;
                }
                const std::shared_ptr<Flow> flow = self->FindFlowGeneration(flow_generation);
                if (!flow || flow->closing || flow->first_leg_ready) {
                    if (second_leg) {
                        self->EraseDirectSecondLeg(flow_generation, second_leg);
                    }
                    return;
                }
                flow->direct_second_leg = second_leg;
                flow->direct_bridge = static_cast<bool>(second_leg);
                if (flow->direct_bridge) {
                    self->direct_flows_.fetch_add(1, std::memory_order_relaxed);
                    self->stats_.direct_bridge_starts.fetch_add(1, std::memory_order_relaxed);
                }
                flow->first_leg_ready = true;
                Shard& s = self->shards_[flow->shard];
                if (!flow->deferred_syn.IsEmpty() && s.backend) {
                    if (s.backend->Inject(std::move(flow->deferred_syn))) {
                        self->stats_.ingress_injected.fetch_add(1, std::memory_order_relaxed);
                        s.injected.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                self->KickPoll(s);
            });
        }
        catch (...) {
            if (second_leg) {
                EraseDirectSecondLeg(flow_generation, second_leg);
            }
        }
    }

    XtcpDirectResult OnSecondLegPayload(XtcpDirectReadReservation& reservation,
        const std::shared_ptr<Byte>& payload) noexcept override {
        if (!payload || reservation.runtime_generation == 0 || reservation.flow_generation == 0 ||
            reservation.length == 0 || !IsCurrent(reservation.runtime_generation)) {
            return XtcpDirectResult::Closed;
        }
        if (reservation.token == 0 && !AllocateDirectReadToken(reservation)) {
            return XtcpDirectResult::Closed;
        }

        std::uint64_t current = 0;
        {
            std::lock_guard<std::mutex> lock(direct_read_sync_);
            if (!IsCurrent(reservation.runtime_generation)) {
                return XtcpDirectResult::Closed;
            }
            const auto second_leg = direct_second_legs_.find(reservation.flow_generation);
            if (second_leg == direct_second_legs_.end()) {
                return XtcpDirectResult::Closed;
            }
            if (direct_read_reservations_.find(reservation.flow_generation) !=
                direct_read_reservations_.end() || reservation.length > kDirectReadFlowBudget) {
                stats_.direct_download_rejected.fetch_add(1, std::memory_order_relaxed);
                return XtcpDirectResult::Backpressured;
            }
            current = direct_read_bytes_.load(std::memory_order_relaxed);
            if (current >= kDirectReadBudget || reservation.length > kDirectReadBudget - current) {
                stats_.direct_download_rejected.fetch_add(1, std::memory_order_relaxed);
                return XtcpDirectResult::Backpressured;
            }
            try {
                DirectReadReservation active;
                active.reservation = reservation;
                active.second_leg = second_leg->second;
                direct_read_reservations_.emplace(reservation.flow_generation, std::move(active));
            }
            catch (...) {
                return XtcpDirectResult::Closed;
            }
            direct_read_bytes_.fetch_add(reservation.length, std::memory_order_relaxed);
        }
        {
            const std::uint64_t queued = current + reservation.length;
            std::uint64_t highwater =
                stats_.direct_download_queue_bytes_highwater.load(std::memory_order_relaxed);
            while (queued > highwater &&
                   !stats_.direct_download_queue_bytes_highwater.compare_exchange_weak(
                       highwater, queued, std::memory_order_relaxed)) {
            }
        }

        const std::size_t shard_index = static_cast<std::size_t>(reservation.flow_generation >> 56);
        if (shard_index >= shards_.size()) {
            CompleteDirectRead(reservation, XtcpDirectCompletion::Terminal);
            return XtcpDirectResult::Closed;
        }
        const std::uint64_t admitted_us = perf_json_enabled_.load(std::memory_order_relaxed)
            ? NowUs() : 0;
        const std::shared_ptr<Impl> self = shared_from_this();
        try {
            boost::asio::post(*shards_[shard_index].strand,
                [self, reservation, payload, admitted_us]() noexcept {
                    if (admitted_us != 0) {
                        HistAdd(self->stats_.direct_handoff_admit_to_shard_us,
                            NowUs() - admitted_us);
                    }
                    if (!self->IsCurrent(reservation.runtime_generation)) {
                        self->CompleteDirectRead(reservation, XtcpDirectCompletion::Terminal);
                        return;
                    }
                    const std::shared_ptr<Flow> flow =
                        self->FindFlowGeneration(reservation.flow_generation);
                    if (!flow || flow->closing) {
                        self->CompleteDirectRead(reservation, XtcpDirectCompletion::Terminal);
                        return;
                    }
                    try {
                        flow->direct_read_queue.push_back({reservation, payload, admitted_us});
                        flow->direct_read_bytes += reservation.length;
                    }
                    catch (...) {
                        self->CompleteDirectRead(reservation, XtcpDirectCompletion::Terminal);
                        self->CloseFlow(flow, true);
                        return;
                    }
                    self->TrySendPending(flow, reservation.runtime_generation);
                });
        }
        catch (...) {
            CompleteDirectRead(reservation, XtcpDirectCompletion::Terminal);
            return XtcpDirectResult::Closed;
        }
        stats_.direct_download_chunks.fetch_add(1, std::memory_order_relaxed);
        stats_.direct_download_accepted_bytes.fetch_add(reservation.length, std::memory_order_relaxed);
        return XtcpDirectResult::Accepted;
    }

    void OnSecondLegWritable(std::uint64_t runtime_generation,
        std::uint64_t flow_generation) noexcept override {
        stats_.direct_upload_writable_callbacks.fetch_add(1, std::memory_order_relaxed);
        stats_.resume_requested.fetch_add(1, std::memory_order_relaxed);
        const std::size_t shard_index = static_cast<std::size_t>(flow_generation >> 56);
        if (shard_index >= shards_.size()) {
            stats_.resume_terminal.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        const std::shared_ptr<Impl> self = shared_from_this();
        boost::asio::post(*shards_[shard_index].strand,
            [self, runtime_generation, flow_generation]() noexcept {
                if (!self->IsCurrent(runtime_generation)) {
                    self->stats_.resume_terminal.fetch_add(1, std::memory_order_relaxed);
                    return;
                }
                const std::shared_ptr<Flow> flow = self->FindFlowGeneration(flow_generation);
                if (!flow || flow->closing || flow->connection_id == 0) {
                    self->stats_.resume_terminal.fetch_add(1, std::memory_order_relaxed);
                    return;
                }
                if (flow->resume_capacity_available) {
                    self->stats_.resume_coalesced.fetch_add(1, std::memory_order_relaxed);
                    return;
                }
                flow->resume_capacity_available = true;
                self->BeginResume(flow);
                self->AttemptResume(flow, runtime_generation);
            });
    }

    void OnSecondLegClosed(std::uint64_t runtime_generation,
        std::uint64_t flow_generation) noexcept override {
        const std::size_t shard_index = static_cast<std::size_t>(flow_generation >> 56);
        if (shard_index >= shards_.size()) {
            return;
        }
        const std::shared_ptr<Impl> self = shared_from_this();
        try {
            boost::asio::post(*shards_[shard_index].strand,
                [self, runtime_generation, flow_generation]() noexcept {
                    if (!self->IsCurrent(runtime_generation)) {
                        return;
                    }
                    const std::shared_ptr<Flow> flow = self->FindFlowGeneration(flow_generation);
                    if (!flow || flow->closing) {
                        return;
                    }
                    if (flow->direct_peer_eof) {
                        self->stats_.second_leg_close_duplicate_suppressed.fetch_add(
                            1, std::memory_order_relaxed);
                        return;
                    }
                    flow->direct_peer_eof = true;
                    if (flow->direct_read_queue.empty() && flow->pending_read.empty()) {
                        self->BeginFirstLegClose(flow);
                    }
                });
        }
        catch (...) {
        }
    }

    void OnDirectBridgeFallback(std::uint64_t runtime_generation,
        std::uint64_t flow_generation) noexcept override {
        if (flow_generation == 0 || !IsCurrent(runtime_generation)) {
            return;
        }
        const std::size_t shard_index = static_cast<std::size_t>(flow_generation >> 56);
        if (shard_index >= shards_.size()) {
            return;
        }
        const std::shared_ptr<Impl> self = shared_from_this();
        try {
            boost::asio::post(*shards_[shard_index].strand,
                [self, runtime_generation, flow_generation]() noexcept {
                    if (!self->IsCurrent(runtime_generation)) {
                        return;
                    }
                    const std::shared_ptr<Flow> flow = self->FindFlowGeneration(flow_generation);
                    if (flow && !flow->closing) {
                        self->stats_.direct_bridge_fallbacks.fetch_add(1,
                            std::memory_order_relaxed);
                    }
                });
        }
        catch (...) {
        }
    }

    void OnFirstLegClosed(std::uint64_t runtime_generation, std::uint64_t flow_generation) noexcept override {
        const std::shared_ptr<Impl> self = shared_from_this();
        const std::size_t shard_index = static_cast<std::size_t>(flow_generation >> 56);
        if (shard_index >= shards_.size()) {
            return;
        }
        boost::asio::post(*shards_[shard_index].strand,
            [self, runtime_generation, flow_generation]() noexcept {
            if (!self->IsCurrent(runtime_generation)) {
                return;
            }
            if (const std::shared_ptr<Flow> flow = self->FindFlowGeneration(flow_generation)) {
                self->HandlePeerGone(flow, runtime_generation);
            }
        });
    }

    void BeginResume(const std::shared_ptr<Flow>& flow) noexcept {
        if (!flow || flow->resume_pending || flow->resume_terminal) {
            return;
        }
        flow->resume_pending = true;
        stats_.resume_pending.fetch_add(1, std::memory_order_relaxed);
    }

    void FinishResume(const std::shared_ptr<Flow>& flow, bool terminal) noexcept {
        if (!flow) {
            return;
        }
        if (flow->resume_pending) {
            flow->resume_pending = false;
            stats_.resume_pending.fetch_sub(1, std::memory_order_relaxed);
        }
        boost::system::error_code ec;
        flow->resume_timer.cancel(ec);
        flow->resume_recheck_posted = false;
        flow->resume_retries = 0;
        if (terminal && !flow->resume_terminal) {
            flow->resume_terminal = true;
            stats_.resume_terminal.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void ScheduleResumeRecheck(
        const std::shared_ptr<Flow>& flow, std::uint64_t runtime_generation) noexcept {
        if (!flow || flow->resume_recheck_posted || flow->resume_terminal ||
            flow->resume_retries >= 2) {
            return;
        }
        flow->resume_recheck_posted = true;
        ++flow->resume_retries;
        stats_.resume_retry.fetch_add(1, std::memory_order_relaxed);
        const std::shared_ptr<Impl> self = shared_from_this();
        if (flow->resume_retries == 1) {
            boost::asio::post(*shards_[flow->shard].strand,
                [self, flow, runtime_generation]() noexcept {
                    flow->resume_recheck_posted = false;
                    if (!self->IsFlowCurrent(flow, runtime_generation)) {
                        self->FinishResume(flow, true);
                        return;
                    }
                    self->AttemptResume(flow, runtime_generation);
                });
            return;
        }
        flow->resume_timer.expires_after(std::chrono::milliseconds(10));
        flow->resume_timer.async_wait(boost::asio::bind_executor(*shards_[flow->shard].strand,
            [self, flow, runtime_generation](const boost::system::error_code& ec) noexcept {
                flow->resume_recheck_posted = false;
                if (ec) {
                    return;
                }
                if (!self->IsFlowCurrent(flow, runtime_generation)) {
                    self->FinishResume(flow, true);
                    return;
                }
                self->AttemptResume(flow, runtime_generation);
            }));
    }

    void AttemptResume(
        const std::shared_ptr<Flow>& flow, std::uint64_t runtime_generation) noexcept {
        if (!flow || !flow->resume_pending || flow->resume_terminal) {
            return;
        }
        if (!IsFlowCurrent(flow, runtime_generation) || flow->connection_id == 0) {
            FinishResume(flow, true);
            return;
        }
        Shard& s = shards_[flow->shard];
        if (!s.stack) {
            FinishResume(flow, true);
            return;
        }
        ::xtcp::core::ReceiveStateSnapshot receive_state;
        const ::xtcp::core::ReceiveResumeResult result =
            s.stack->ResumeReceiveDetailed(flow->connection_id, &receive_state);
        switch (result) {
        case ::xtcp::core::ReceiveResumeResult::kResumed:
            stats_.resume_effective.fetch_add(1, std::memory_order_relaxed);
            flow->receive_rejected = false;
            flow->resume_capacity_available = false;
            FinishResume(flow, false);
            KickPoll(s);
            break;
        case ::xtcp::core::ReceiveResumeResult::kNotBlocked:
            stats_.resume_result_not_blocked.fetch_add(1, std::memory_order_relaxed);
            if (flow->receive_rejected && flow->resume_retries < 2) {
                ScheduleResumeRecheck(flow, runtime_generation);
            }
            else if (flow->resume_retries == 0) {
                ScheduleResumeRecheck(flow, runtime_generation);
            }
            else {
                FinishResume(flow, false);
            }
            break;
        case ::xtcp::core::ReceiveResumeResult::kReceiveWindowFull:
            // Application backpressure is gone even though OOO occupancy still
            // makes the protocol window zero. Consume this level notification;
            // retaining it would coalesce future writable edges indefinitely.
            stats_.resume_result_window_full.fetch_add(1, std::memory_order_relaxed);
            flow->receive_rejected = false;
            flow->resume_capacity_available = false;
            FinishResume(flow, false);
            KickPoll(s);
            break;
        case ::xtcp::core::ReceiveResumeResult::kConnectionMissing:
            stats_.resume_result_connection_missing.fetch_add(1, std::memory_order_relaxed);
            flow->resume_capacity_available = false;
            FinishResume(flow, true);
            break;
        }
    }

    // The ppp-side forwarding object for this flow was disposed. Direct
    // bridges cannot retain kernel-buffered connector data, so they abort
    // immediately, including during the direct-ready handoff window.
    void HandlePeerGone(const std::shared_ptr<Flow>& flow, std::uint64_t runtime_generation) noexcept {
        if (!flow || flow->closing || flow->peer_gone) {
            return;
        }
        bool direct_pending = flow->direct_bridge;
        if (!direct_pending) {
            std::lock_guard<std::mutex> lock(direct_read_sync_);
            direct_pending = direct_second_legs_.find(flow->generation) != direct_second_legs_.end();
        }
        if (direct_pending) {
            CloseFlow(flow, true);
            return;
        }
        flow->peer_gone = true;
        Shard& s = shards_[flow->shard];
        if (!flow->first_leg_ready) {
            if (!flow->deferred_syn.IsEmpty() && s.backend) {
                flow->abort_when_ready = true;
                if (s.backend->Inject(std::move(flow->deferred_syn))) {
                    stats_.ingress_injected.fetch_add(1, std::memory_order_relaxed);
                    s.injected.fetch_add(1, std::memory_order_relaxed);
                    KickPoll(s);
                    return;
                }
                flow->abort_when_ready = false;
            }
            CloseFlow(flow, true);
            return;
        }
        // Upload data still queued for the connector can never be delivered;
        // drop it. The in-flight chunk is debited by its own completion
        // handler, so only the not-yet-submitted remainder is refunded here.
        const std::size_t unsubmitted =
            flow->write_bytes >= flow->in_flight_bytes
                ? flow->write_bytes - flow->in_flight_bytes : 0;
        stats_.queued_bytes_total.fetch_sub(unsubmitted, std::memory_order_relaxed);
        flow->write_queue.clear();
        flow->write_bytes = flow->in_flight_bytes;
        (void)runtime_generation;
    }

private:
    struct Stats final {
        std::atomic<std::uint64_t> ingress_submitted{0};
        std::atomic<std::uint64_t> ingress_dropped{0};
        std::atomic<std::uint64_t> ingress_injected{0};
        std::atomic<std::uint64_t> flows_opened{0};
        std::atomic<std::uint64_t> flows_closed{0};
        std::atomic<std::uint64_t> timer_polls{0};
        std::atomic<std::uint64_t> timer_events{0};
        std::atomic<std::uint64_t> output_packets{0};
        std::atomic<std::uint64_t> output_bytes{0};
        std::atomic<std::uint64_t> connector_read_bytes{0};
        std::atomic<std::uint64_t> connector_written_bytes{0};
        // Perf diagnostics for the env-gated JSON dump (see Start()); all
        // relaxed, none read on the stable stats path.
        std::atomic<std::uint64_t> timer_armed{0};
        std::atomic<std::uint64_t> timer_kick_requests{0};
        std::atomic<std::uint64_t> timer_kick_due_now{0};
        std::atomic<std::uint64_t> timer_kick_lead_us_sum{0};
        std::atomic<std::uint64_t> timer_rearm_attempts{0};
        std::atomic<std::uint64_t> timer_rearm_suppressed_slack{0};
        std::atomic<std::uint64_t> connector_read_calls{0};
        std::atomic<std::uint64_t> connector_write_ops{0};
        std::atomic<std::uint64_t> recv_cb_calls{0};
        std::atomic<std::uint64_t> recv_cb_bytes{0};
        std::atomic<std::uint64_t> write_queue_highwater{0};
        std::atomic<std::uint64_t> stack_send_calls{0};
        std::atomic<std::uint64_t> stack_send_rejected{0};
        std::atomic<std::uint64_t> send_retry_armed{0};
        std::atomic<std::uint64_t> send_retry_fired{0};
        std::atomic<std::uint64_t> send_stall_us_sum{0};
        std::atomic<std::uint64_t> send_stall_events{0};
        std::atomic<std::uint64_t> ingress_enqueued{0};
        std::atomic<std::uint64_t> ingress_dispatched{0};
        std::atomic<std::uint64_t> on_receive_rejected{0};
        std::atomic<std::uint64_t> on_receive_rejected_bytes{0};
        std::atomic<std::uint64_t> resume_requested{0};
        std::atomic<std::uint64_t> resume_effective{0};
        std::atomic<std::uint64_t> resume_result_not_blocked{0};
        std::atomic<std::uint64_t> resume_result_window_full{0};
        std::atomic<std::uint64_t> resume_result_connection_missing{0};
        std::atomic<std::uint64_t> resume_pending{0};
        std::atomic<std::uint64_t> resume_coalesced{0};
        std::atomic<std::uint64_t> resume_terminal{0};
        std::atomic<std::uint64_t> resume_retry{0};
        std::atomic<std::uint64_t> resume_window_full_retry{0};
        std::atomic<std::uint64_t> direct_bridge_starts{0};
        std::atomic<std::uint64_t> direct_bridge_fallbacks{0};
        std::atomic<std::uint64_t> direct_upload_accepted_chunks{0};
        std::atomic<std::uint64_t> direct_upload_accepted_bytes{0};
        std::atomic<std::uint64_t> direct_download_accepted_bytes{0};
        std::atomic<std::uint64_t> direct_upload_writable_callbacks{0};
        std::atomic<std::uint64_t> direct_download_writable_callbacks{0};
        std::atomic<std::uint64_t> direct_download_chunks{0};
        std::atomic<std::uint64_t> direct_download_rejected{0};
        std::atomic<std::uint64_t> direct_upload_rejected{0};
        std::atomic<std::uint64_t> upload_budget_rejected{0};
        std::atomic<std::uint64_t> upload_budget_wake_empty{0};
        std::atomic<std::uint64_t> second_leg_close_requested{0};
        std::atomic<std::uint64_t> second_leg_close_duplicate_suppressed{0};
        std::atomic<std::uint64_t> degraded_half_close{0};
        std::atomic<std::uint64_t> direct_download_queue_bytes_highwater{0};
        std::atomic<std::uint64_t> queued_bytes_total{0};
        std::atomic<std::uint64_t> queued_bytes_highwater{0};
        // log2(us) histograms: bucket b counts samples in [2^b, 2^(b+1)).
        static constexpr std::size_t kHistBuckets = 32;
        using Hist = std::array<std::atomic<std::uint64_t>, kHistBuckets>;
        Hist queue_delay_us{};
        Hist timer_late_us{};
        Hist write_cycle_us{};
        Hist write_gap_us{};
        Hist direct_handoff_admit_to_shard_us{};
        Hist direct_handoff_admit_to_accept_us{};
        Hist direct_handoff_accept_to_writable_us{};

        void Reset() noexcept {
            ingress_submitted.store(0, std::memory_order_relaxed);
            ingress_dropped.store(0, std::memory_order_relaxed);
            ingress_injected.store(0, std::memory_order_relaxed);
            flows_opened.store(0, std::memory_order_relaxed);
            flows_closed.store(0, std::memory_order_relaxed);
            timer_polls.store(0, std::memory_order_relaxed);
            timer_events.store(0, std::memory_order_relaxed);
            output_packets.store(0, std::memory_order_relaxed);
            output_bytes.store(0, std::memory_order_relaxed);
            connector_read_bytes.store(0, std::memory_order_relaxed);
            connector_written_bytes.store(0, std::memory_order_relaxed);
            timer_armed.store(0, std::memory_order_relaxed);
            timer_kick_requests.store(0, std::memory_order_relaxed);
            timer_kick_due_now.store(0, std::memory_order_relaxed);
            timer_kick_lead_us_sum.store(0, std::memory_order_relaxed);
            timer_rearm_attempts.store(0, std::memory_order_relaxed);
            timer_rearm_suppressed_slack.store(0, std::memory_order_relaxed);
            connector_read_calls.store(0, std::memory_order_relaxed);
            connector_write_ops.store(0, std::memory_order_relaxed);
            recv_cb_calls.store(0, std::memory_order_relaxed);
            recv_cb_bytes.store(0, std::memory_order_relaxed);
            write_queue_highwater.store(0, std::memory_order_relaxed);
            stack_send_calls.store(0, std::memory_order_relaxed);
            stack_send_rejected.store(0, std::memory_order_relaxed);
            send_retry_armed.store(0, std::memory_order_relaxed);
            send_retry_fired.store(0, std::memory_order_relaxed);
            send_stall_us_sum.store(0, std::memory_order_relaxed);
            send_stall_events.store(0, std::memory_order_relaxed);
            ingress_enqueued.store(0, std::memory_order_relaxed);
            ingress_dispatched.store(0, std::memory_order_relaxed);
            on_receive_rejected.store(0, std::memory_order_relaxed);
            on_receive_rejected_bytes.store(0, std::memory_order_relaxed);
            resume_requested.store(0, std::memory_order_relaxed);
            resume_effective.store(0, std::memory_order_relaxed);
            resume_result_not_blocked.store(0, std::memory_order_relaxed);
            resume_result_window_full.store(0, std::memory_order_relaxed);
            resume_result_connection_missing.store(0, std::memory_order_relaxed);
            resume_pending.store(0, std::memory_order_relaxed);
            resume_coalesced.store(0, std::memory_order_relaxed);
            resume_terminal.store(0, std::memory_order_relaxed);
            resume_retry.store(0, std::memory_order_relaxed);
            resume_window_full_retry.store(0, std::memory_order_relaxed);
            direct_bridge_starts.store(0, std::memory_order_relaxed);
            direct_bridge_fallbacks.store(0, std::memory_order_relaxed);
            direct_upload_accepted_chunks.store(0, std::memory_order_relaxed);
            direct_upload_accepted_bytes.store(0, std::memory_order_relaxed);
            direct_download_accepted_bytes.store(0, std::memory_order_relaxed);
            direct_upload_writable_callbacks.store(0, std::memory_order_relaxed);
            direct_download_writable_callbacks.store(0, std::memory_order_relaxed);
            direct_download_chunks.store(0, std::memory_order_relaxed);
            direct_download_rejected.store(0, std::memory_order_relaxed);
            direct_upload_rejected.store(0, std::memory_order_relaxed);
            upload_budget_rejected.store(0, std::memory_order_relaxed);
            upload_budget_wake_empty.store(0, std::memory_order_relaxed);
            second_leg_close_requested.store(0, std::memory_order_relaxed);
            second_leg_close_duplicate_suppressed.store(0, std::memory_order_relaxed);
            degraded_half_close.store(0, std::memory_order_relaxed);
            direct_download_queue_bytes_highwater.store(0, std::memory_order_relaxed);
            queued_bytes_total.store(0, std::memory_order_relaxed);
            queued_bytes_highwater.store(0, std::memory_order_relaxed);
            for (std::atomic<std::uint64_t>& bucket : queue_delay_us) {
                bucket.store(0, std::memory_order_relaxed);
            }
            for (std::atomic<std::uint64_t>& bucket : timer_late_us) {
                bucket.store(0, std::memory_order_relaxed);
            }
            for (std::atomic<std::uint64_t>& bucket : write_cycle_us) {
                bucket.store(0, std::memory_order_relaxed);
            }
            for (std::atomic<std::uint64_t>& bucket : write_gap_us) {
                bucket.store(0, std::memory_order_relaxed);
            }
            for (std::atomic<std::uint64_t>& bucket : direct_handoff_admit_to_shard_us) {
                bucket.store(0, std::memory_order_relaxed);
            }
            for (std::atomic<std::uint64_t>& bucket : direct_handoff_admit_to_accept_us) {
                bucket.store(0, std::memory_order_relaxed);
            }
            for (std::atomic<std::uint64_t>& bucket : direct_handoff_accept_to_writable_us) {
                bucket.store(0, std::memory_order_relaxed);
            }
        }
    };
    // Histogram helpers (bucket = floor(log2(us)), clamped).
    static void HistAdd(Stats::Hist& hist, std::uint64_t us) noexcept {
        std::size_t bucket = 0;
        std::uint64_t value = us;
        while (value > 1 && bucket + 1 < Stats::kHistBuckets) {
            value >>= 1;
            ++bucket;
        }
        hist[bucket].fetch_add(1, std::memory_order_relaxed);
    }
    static double HistPercentile(
        const Stats::Hist& hist, std::uint64_t total, double pct) noexcept {
        if (total == 0) {
            return 0.0;
        }
        const std::uint64_t target = static_cast<std::uint64_t>(
            static_cast<double>(total) * pct);
        std::uint64_t seen = 0;
        for (std::size_t i = 0; i < Stats::kHistBuckets; ++i) {
            seen += hist[i].load(std::memory_order_relaxed);
            if (seen >= target && seen != 0) {
                return static_cast<double>(std::uint64_t{1} << i);
            }
        }
        return 0.0;
    }

    bool IsCurrent(std::uint64_t generation) const noexcept {
        return running_.load(std::memory_order_acquire) && generation != 0 &&
            generation == generation_.load(std::memory_order_acquire);
    }

    // XTCP-SHARED-PATH-001 S1: 一个执行域 = 一个 shard。flow 4-tuple hash
    // 亲和路由; shard 表 Start 后不再 resize (handler 捕获 index 安全)。
    struct HandoffItem final {
        ::xtcp::buf::BufRef packet;
        ParsedPacket parsed;
        bool has_parsed = false;
        std::uint64_t generation = 0;
        std::uint64_t enqueue_us = 0;
    };
    struct Shard final {
        std::size_t index = 0;
        std::shared_ptr<Strand> strand;
        std::unique_ptr<XtcpNdiBackend> backend;
        std::unique_ptr<::xtcp::XtcpStack> stack;
        XtcpIngressBudget budget{IngressMaxItems(), IngressMaxBytes()};
        std::mutex handoff_sync;
        std::vector<HandoffItem> handoff;
        std::atomic<bool> handoff_posted{false};
        std::shared_ptr<boost::asio::steady_timer> poll_timer;
        std::unordered_map<FlowKey, std::shared_ptr<Flow>, FlowKeyHash> flows;
        std::unordered_map<UInt64, FlowKey> connections;
        std::unordered_map<UInt64, std::pair<::xtcp::core::Endpoint, std::uint32_t>> listener_refs;
        std::atomic<std::uint64_t> enqueued{0};
        std::atomic<std::uint64_t> dispatched{0};
        std::atomic<std::uint64_t> injected{0};
        std::atomic<std::uint64_t> dropped{0};
        Stats::Hist queue_delay_us{};
    };

    bool InitializeUploadBudget() noexcept {
        try {
            auto budget = std::atomic_load_explicit(&upload_budget_, std::memory_order_acquire);
            if (!budget) {
                // One shared cap for connector and direct uploads. Keep the
                // same object on restart: old in-flight owners still count.
                budget = std::make_shared<XtcpUploadBudget>(GlobalQueueBudget(), 64 * 1024);
            }
            const std::weak_ptr<Impl> weak = shared_from_this();
            const std::weak_ptr<boost::asio::io_context> context = context_;
            const std::uint64_t generation = Generation();
            std::vector<std::weak_ptr<Strand>> targets;
            for (const Shard& s : shards_) targets.emplace_back(s.strand);
            auto posted = std::make_shared<std::array<std::atomic<bool>, 8>>();
            for (auto& flag : *posted) flag.store(false, std::memory_order_relaxed);
            budget->SetWakeHandler([weak, context, generation, targets = std::move(targets), posted]() {
                // Weak executors avoid a cycle from a stopped io_context's
                // pending write -> credit -> budget -> io_context.
                const auto live_context = context.lock();
                const auto self = weak.lock();
                if (!live_context || !self || !self->IsCurrent(generation)) return;
                for (std::size_t i = 0; i < targets.size(); ++i) {
                    const auto strand = targets[i].lock();
                    if (!strand || (*posted)[i].exchange(true, std::memory_order_acq_rel)) continue;
                    try {
                        boost::asio::post(*strand, [weak, generation, i, posted]() noexcept {
                            (*posted)[i].store(false, std::memory_order_release);
                            if (const auto current = weak.lock()) {
                                if (current->IsCurrent(generation)) {
                                    current->ResumeUploadBudgetWaiters(current->shards_[i], generation);
                                }
                            }
                        });
                    }
                    catch (...) {
                        (*posted)[i].store(false, std::memory_order_release);
                        throw;
                    }
                }
            });
            std::atomic_store_explicit(&upload_budget_, std::move(budget), std::memory_order_release);
            return true;
        }
        catch (...) { return false; }
    }

    void ResumeUploadBudgetWaiters(Shard& s, std::uint64_t generation) noexcept {
        const auto budget = std::atomic_load_explicit(&upload_budget_, std::memory_order_acquire);
        if (!budget || !s.stack) return;
        std::vector<XtcpUploadBudget::WaitToken> tokens;
        try {
            tokens = budget->WaiterTokens();
        }
        catch (...) { return; }
        bool resumed = false;
        for (const auto token : tokens) {
            // Output during resume may close a flow reentrantly; never keep
            // iterators into the live flow map across an external callback.
            if (!IsCurrent(generation) || !s.stack) return;
            const std::shared_ptr<Flow> flow = FindFlowGeneration(token);
            if (!flow || flow->shard != s.index) continue;
            const auto needed = flow->upload_budget_blocked_bytes;
            if (!needed || flow->closing || flow->peer_gone || !flow->connection_id) {
                budget->CancelWait(token);
                flow->upload_budget_blocked_bytes = 0;
                continue;
            }
            if (!budget->AwaitCapacity(token, needed)) continue;
            flow->upload_budget_blocked_bytes = 0;
            if (flow->direct_second_leg) {
                stats_.resume_requested.fetch_add(1, std::memory_order_relaxed);
                flow->resume_capacity_available = true;
                BeginResume(flow);
                AttemptResume(flow, generation);
                // A successful attempt removes the token when it reserves
                // credit. Any token still queued did not make progress and
                // must yield the head position to the next flow.
                budget->RotateWait(token);
            }
            else {
                s.stack->ResumeReceiveDetailed(flow->connection_id);
                resumed = true;
            }
        }
        if (!resumed && !tokens.empty()) {
            stats_.upload_budget_wake_empty.fetch_add(1, std::memory_order_relaxed);
        }
        if (resumed) KickPoll(s);
    }

    // XTCP-STRAND-DISPATCH-001: strand 侧批量 drain。Submit 只在 handoff 从空
    // 变非空时 post 一次本闭包, 本函数循环换出整个突发逐包注入, 直到换出为空
    // 才清 handoff_posted_ (同一把锁内检查+清位, 保证 Submit 侧不会有包滞留)。
    void DrainIngress(Shard& s) noexcept {
        std::vector<HandoffItem> local;
        for (;;) {
            {
                std::lock_guard<std::mutex> lock(s.handoff_sync);
                if (s.handoff.empty()) {
                    s.handoff_posted.store(false, std::memory_order_release);
                    return;
                }
                local.swap(s.handoff);
            }
            for (HandoffItem& item : local) {
                ProcessIngress(s, std::move(item.packet), item.generation,
                    item.enqueue_us, item.parsed, item.has_parsed);
            }
            local.clear();
        }
    }

    void ProcessIngress(Shard& s, ::xtcp::buf::BufRef&& packet, std::uint64_t generation,
        std::uint64_t enqueue_us, const ParsedPacket& item_parsed, bool item_has_parsed) noexcept {
        stats_.ingress_dispatched.fetch_add(1, std::memory_order_relaxed);
        s.dispatched.fetch_add(1, std::memory_order_relaxed);
        const std::uint64_t delay_us = NowUs() - enqueue_us;
        HistAdd(stats_.queue_delay_us, delay_us);
        HistAdd(s.queue_delay_us, delay_us);
        s.budget.Release(packet.IsEmpty() ? 0 : packet.Len());
        if (packet.IsEmpty() || !IsCurrent(generation) || !s.stack || !s.backend) {
            return;
        }
        ParsedPacket local;
        const ParsedPacket* parsed_ptr = &item_parsed;
        if (!item_has_parsed) {
            if (!ParsePacket(packet.Data(), static_cast<int>(packet.Len()), local)) {
                return;
            }
            parsed_ptr = &local;
        }
        const ParsedPacket& parsed = *parsed_ptr;
        const auto existing = s.flows.find(parsed.key);
        if (existing != s.flows.end()) {
            const std::shared_ptr<Flow>& flow = existing->second;
            if (flow->closing) {
                return;
            }
            if (!flow->first_leg_ready) {
                if ((parsed.flags & kTcpRst) != 0) {
                    CloseFlow(flow, false);
                }
                return;
            }
            const bool injected = s.backend->Inject(std::move(packet));
            if (injected) {
                stats_.ingress_injected.fetch_add(1, std::memory_order_relaxed);
                s.injected.fetch_add(1, std::memory_order_relaxed);
            }
            if (flow->resume_pending && !flow->closing) {
                AttemptResume(flow, generation);
            }
            KickPoll(s);
            return;
        }
        if ((parsed.flags & kTcpSyn) == 0 || (parsed.flags & kTcpAck) != 0 ||
            s.flows.size() >= kMaxFlows) {
            return;
        }
        StartFlow(s, parsed, std::move(packet));
    }

    void StartFlow(Shard& s, const ParsedPacket& parsed, ::xtcp::buf::BufRef&& packet) noexcept {
        // XTCP-SHARED-PATH-001 S1: flow generation 高位打 shard 标签,
        // FindFlowGeneration O(1) 定位 shard 且免跨 shard 索引。
        const std::uint64_t flow_generation =
            (static_cast<std::uint64_t>(s.index) << 56) |
            (next_flow_generation_.fetch_add(1, std::memory_order_relaxed) + 1);
        std::shared_ptr<Flow> flow;
        try {
            flow = std::make_shared<Flow>(context_, parsed.key, parsed.remote, parsed.local, flow_generation);
        }
        catch (...) {
            return;
        }
        flow->shard = s.index;
        flow->deferred_syn = std::move(packet);
        if (flow->deferred_syn.IsEmpty()) {
            return;
        }

        const UInt64 listener_key = ::xtcp::EndpointKey(parsed.local);
        auto listener = s.listener_refs.find(listener_key);
        if (listener == s.listener_refs.end()) {
            if (!s.stack->Listen(parsed.local)) {
                return;
            }
            s.listener_refs.emplace(listener_key, std::make_pair(parsed.local, 1u));
        }
        else {
            ++listener->second.second;
        }
        s.flows.emplace(parsed.key, flow);
        stats_.flows_opened.fetch_add(1, std::memory_order_relaxed);

        int bridge_fd = -1;
        boost::system::error_code ec;
        if (unix_bridge_) {
#if !defined(_WIN32)
            // XTCP-VNET-BRIDGE-BYPASS-001: AF_UNIX socketpair 替代内核 loopback
            // TCP 桥。内核 TCP 的 sendmsg/ACK/定时器/skb 拷贝链（profile 实测
            // ~25-30% 单核）换成纯队列 socketpair; fd1 交 netstack 采纳。
            int fds[2] = {-1, -1};
            if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
                CloseFlow(flow, false);
                return;
            }
            // fd0 交给 asio (必须 O_NONBLOCK); fd1 留给 netstack 泵的阻塞 read。
            const int flags0 = ::fcntl(fds[0], F_GETFL, 0);
            ::fcntl(fds[0], F_SETFL, flags0 | O_NONBLOCK);
            flow->connector.assign(boost::asio::ip::tcp::v4(), fds[0], ec);
            if (ec) {
                ::close(fds[0]);
                ::close(fds[1]);
                CloseFlow(flow, false);
                return;
            }
            // 合成 source_port: netstack 注册键, 不与真实监听/应用端口耦合。
            const std::uint32_t slot =
                next_external_port_.fetch_add(1, std::memory_order_relaxed) % 16384u;
            flow->source_port = static_cast<std::uint16_t>(49152u + slot);
            bridge_fd = fds[1];
            (void)0;
#else
            CloseFlow(flow, false);
            return;
#endif
        }
        else {
            flow->connector.open(boost::asio::ip::tcp::v4(), ec);
            if (!ec) {
                flow->connector.bind(boost::asio::ip::tcp::endpoint(
                    boost::asio::ip::address_v4::loopback(), 0), ec);
            }
            if (ec) {
                CloseFlow(flow, false);
                return;
            }
            flow->source_port = flow->connector.local_endpoint(ec).port();
        }
        if (ec || flow->source_port == 0 || !external_accept_) {
            if (bridge_fd >= 0) {
                ::close(bridge_fd);
            }
            CloseFlow(flow, false);
            return;
        }
        const boost::asio::ip::tcp::endpoint local_endpoint(
            ToAddress(parsed.key.remote_address), parsed.key.remote_port);
        const boost::asio::ip::tcp::endpoint remote_endpoint(
            ToAddress(parsed.key.local_address), parsed.key.local_port);
        std::weak_ptr<XtcpFirstLegHooks> hooks = shared_from_this();
        const std::uint64_t runtime_generation = Generation();
        // A non-negative bridge descriptor transfers to the callback at
        // invocation, including when the callback rejects this flow.
        if (!external_accept_(local_endpoint, remote_endpoint, flow->source_port,
                runtime_generation, flow_generation, hooks, bridge_fd)) {
            CloseFlow(flow, false);
            return;
        }
        if (bridge_fd >= 0) {
            // XTCP-VNET-BRIDGE-BYPASS-001: socketpair 路径无 listener connect
            // 完成回调, 这里直接置位连接态并启动 connector 读循环 (泵的双向
            // 数据面由此接通); fd1 所有权已移交 netstack。
            flow->connector_connected = true;
            StartRead(flow, runtime_generation);
            return;
        }
        const boost::asio::ip::tcp::endpoint listener_endpoint = listener_endpoint_
            ? listener_endpoint_() : boost::asio::ip::tcp::endpoint();
        if (listener_endpoint.port() == 0) {
            CloseFlow(flow, false);
            return;
        }
        const std::shared_ptr<Impl> self = shared_from_this();
        flow->connector.async_connect(listener_endpoint,
            boost::asio::bind_executor(*s.strand,
                [self, flow, runtime_generation](const boost::system::error_code& connect_ec) noexcept {
                    if (!self->IsFlowCurrent(flow, runtime_generation)) {
                        return;
                    }
                    if (connect_ec) {
                        self->CloseFlow(flow, true);
                        return;
                    }
                    flow->connector_connected = true;
                    self->StartRead(flow, runtime_generation);
                }));
    }

    bool OnAccept(Shard& s, UInt64 connection_id, const ::xtcp::core::Endpoint& remote,
        const ::xtcp::core::Endpoint& local) noexcept {
        FlowKey key;
        key.remote_address = remote.addr[0];
        key.local_address = local.addr[0];
        key.remote_port = remote.port;
        key.local_port = local.port;
        const auto found = s.flows.find(key);
        if (found == s.flows.end() || found->second->closing ||
            found->second->connection_id != 0) {
            return false;
        }
        if (found->second->abort_when_ready) {
            // The second leg already refused this flow: reject so the stack
            // answers the app's pending connect with RST instead of SYN+ACK.
            // The flow cleanup runs after the stack finished this segment.
            const std::shared_ptr<Impl> self = shared_from_this();
            const std::shared_ptr<Flow> flow = found->second;
            const std::uint64_t runtime_generation = Generation();
            boost::asio::post(*s.strand, [self, flow, runtime_generation]() noexcept {
                if (self->IsFlowCurrent(flow, runtime_generation)) {
                    self->CloseFlow(flow, false);
                }
            });
            return false;
        }
        try {
            if (!s.connections.emplace(connection_id, key).second) {
                return false;
            }
        }
        catch (...) {
            return false;
        }
        found->second->connection_id = connection_id;
        return true;
    }

    bool OnReceive(Shard& s, UInt64 connection_id, const Byte* data, UInt32 length) noexcept {
        stats_.recv_cb_calls.fetch_add(1, std::memory_order_relaxed);
        if (data != nullptr) {
            stats_.recv_cb_bytes.fetch_add(length, std::memory_order_relaxed);
        }
        const std::shared_ptr<Flow> flow = FindConnection(s, connection_id);
        if (!flow || flow->closing || data == nullptr || length == 0) {
            return false;
        }
        if (flow->peer_gone) {
            // The second leg is gone: consume and discard so the first leg's
            // flow control keeps moving until the close lands on the app.
            return true;
        }
        const auto direct = flow->direct_second_leg;
        if (!direct && length > kConnectorReadBytes + ConnectorWriteCap() - flow->write_bytes) {
            if (!flow->connector_receive_backpressured) {
                flow->connector_receive_backpressured = true;
                connector_receive_blocked_.fetch_add(1, std::memory_order_relaxed);
            }
            stats_.on_receive_rejected.fetch_add(1, std::memory_order_relaxed);
            stats_.on_receive_rejected_bytes.fetch_add(length, std::memory_order_relaxed);
            return false;
        }
        const auto budget = std::atomic_load_explicit(&upload_budget_, std::memory_order_acquire);
        auto credit = budget
            ? budget->TryReserveFor(flow->generation, length)
            : XtcpUploadBudget::Reservation{};
        if (!credit) {
            flow->upload_budget_blocked_bytes = length;
            if (budget) {
                budget->AwaitCapacity(flow->generation, length);
                budget->RotateWait(flow->generation);
            }
            stats_.upload_budget_rejected.fetch_add(1, std::memory_order_relaxed);
            if (direct) {
                flow->receive_rejected = true;
                stats_.direct_upload_rejected.fetch_add(1, std::memory_order_relaxed);
            }
            stats_.on_receive_rejected.fetch_add(1, std::memory_order_relaxed);
            stats_.on_receive_rejected_bytes.fetch_add(length, std::memory_order_relaxed);
            return false;
        }
        flow->upload_budget_blocked_bytes = 0;
        if (budget) {
            budget->CancelWait(flow->generation);
        }
        if (direct) {
            const XtcpDirectResult result = direct->SendToPeer(data, length, std::move(credit));
            if (result == XtcpDirectResult::Accepted) {
                stats_.direct_upload_accepted_chunks.fetch_add(1, std::memory_order_relaxed);
                stats_.direct_upload_accepted_bytes.fetch_add(length, std::memory_order_relaxed);
                flow->receive_rejected = false;
                flow->resume_capacity_available = false;
                if (flow->resume_pending) {
                    FinishResume(flow, false);
                }
                return true;
            }
            if (result == XtcpDirectResult::Closed) {
                flow->peer_gone = true;
                const std::shared_ptr<Impl> self = shared_from_this();
                boost::asio::post(*s.strand, [self, flow]() noexcept {
                    if (!flow->closing) {
                        self->CloseFlow(flow, true);
                    }
                });
                return true;
            }
            stats_.direct_upload_rejected.fetch_add(1, std::memory_order_relaxed);
            stats_.on_receive_rejected.fetch_add(1, std::memory_order_relaxed);
            stats_.on_receive_rejected_bytes.fetch_add(length, std::memory_order_relaxed);
            flow->receive_rejected = true;
            if (flow->resume_capacity_available) {
                BeginResume(flow);
                ScheduleResumeRecheck(flow, Generation());
            }
            return false;
        }
        try {
            auto payload = std::make_shared<XtcpUploadChunk>(data, length, std::move(credit));
            flow->write_queue.emplace_back(payload, &payload->bytes);
        }
        catch (...) {
            return false;
        }
        flow->write_bytes += length;
        stats_.queued_bytes_total.fetch_add(length, std::memory_order_relaxed);
        {
            std::uint64_t highwater =
                stats_.write_queue_highwater.load(std::memory_order_relaxed);
            while (flow->write_bytes > highwater &&
                   !stats_.write_queue_highwater.compare_exchange_weak(
                       highwater, flow->write_bytes, std::memory_order_relaxed)) {
            }
        }
        {
            std::uint64_t global_high =
                stats_.queued_bytes_highwater.load(std::memory_order_relaxed);
            const std::uint64_t total =
                stats_.queued_bytes_total.load(std::memory_order_relaxed);
            while (total > global_high &&
                   !stats_.queued_bytes_highwater.compare_exchange_weak(
                       global_high, total, std::memory_order_relaxed)) {
            }
        }
        // The callback already runs on the shard strand. Posting again adds
        // one scheduler round-trip per receive delivery.
        StartWrite(flow, Generation());
        return true;
    }

    void OnState(Shard& s, UInt64 connection_id, ::xtcp::core::TcpState state) noexcept {
        if (state != ::xtcp::core::TcpState::kClosed &&
            state != ::xtcp::core::TcpState::kCloseWait &&
            state != ::xtcp::core::TcpState::kTimeWait) {
            return;
        }
        const std::shared_ptr<Impl> self = shared_from_this();
        const std::uint64_t runtime_generation = Generation();
        boost::asio::post(*s.strand, [self, &s, connection_id, state, runtime_generation]() noexcept {
            if (!self->IsCurrent(runtime_generation)) {
                return;
            }
            if (const std::shared_ptr<Flow> flow = self->FindConnection(s, connection_id)) {
                if (state == ::xtcp::core::TcpState::kCloseWait) {
                    flow->first_leg_eof = true;
                    if (flow->direct_bridge) {
                        self->RequestSecondLegClose(flow);
                    }
                    else {
                        self->MaybeShutdownConnectorSend(flow, runtime_generation);
                    }
                }
                else {
                    self->CloseFlow(flow, false);
                }
            }
            self->KickPoll(s);
        });
    }

    void StartRead(const std::shared_ptr<Flow>& flow, std::uint64_t runtime_generation) noexcept {
        if (!IsFlowCurrent(flow, runtime_generation) || flow->read_active ||
            !flow->connector_connected || flow->connector_read_eof ||
            !flow->pending_read.empty() || flow->direct_bridge) {
            return;
        }
        flow->read_active = true;
        const std::shared_ptr<Impl> self = shared_from_this();
        flow->connector.async_read_some(boost::asio::buffer(flow->read_buffer),
            boost::asio::bind_executor(*shards_[flow->shard].strand,
                [self, flow, runtime_generation](const boost::system::error_code& ec,
                    std::size_t length) noexcept {
                    flow->read_active = false;
                    if (!self->IsFlowCurrent(flow, runtime_generation)) {
                        return;
                    }
                    if (ec && ec != boost::asio::error::eof) {
                        self->CloseFlow(flow, true);
                        return;
                    }
                    flow->connector_read_eof = ec == boost::asio::error::eof || length == 0;
                    if (length != 0) {
                        self->stats_.connector_read_calls.fetch_add(1, std::memory_order_relaxed);
                        self->stats_.connector_read_bytes.fetch_add(
                            static_cast<std::uint64_t>(length), std::memory_order_relaxed);
                        flow->pending_read.assign(flow->read_buffer.data(),
                            flow->read_buffer.data() + length);
                        self->TrySendPending(flow, runtime_generation);
                    }
                    else {
                        self->BeginFirstLegClose(flow);
                    }
                }));
    }

    void TrySendPending(const std::shared_ptr<Flow>& flow, std::uint64_t runtime_generation) noexcept {
        if (!IsFlowCurrent(flow, runtime_generation) ||
            (flow->pending_read.empty() && flow->direct_read_queue.empty())) {
            return;
        }
        Shard& s = shards_[flow->shard];
        const bool direct_payload = flow->pending_read.empty();
        const Byte* send_data = direct_payload
            ? flow->direct_read_queue.front().payload.get()
            : flow->pending_read.data();
        const UInt32 send_length = direct_payload
            ? flow->direct_read_queue.front().reservation.length
            : static_cast<UInt32>(flow->pending_read.size());
        stats_.stack_send_calls.fetch_add(1, std::memory_order_relaxed);
        const bool accepted = flow->connection_id != 0 && s.stack &&
            s.stack->Send(flow->connection_id, send_data, send_length);
        if (accepted) {
            if (flow->send_stall_start_us != 0) {
                stats_.send_stall_us_sum.fetch_add(
                    NowUs() - std::exchange(flow->send_stall_start_us, 0),
                    std::memory_order_relaxed);
                stats_.send_stall_events.fetch_add(1, std::memory_order_relaxed);
            }
            if (send_admission_enabled_) {
                flow->send_admission_blocked = false;
                flow->send_admission_snapshot_valid = false;
                flow->send_admission_blocked_since_us = 0;
                flow->send_admission_snapshot = {};
            }
            if (direct_payload) {
                const Flow::DirectReadItem item = std::move(flow->direct_read_queue.front());
                if (item.admitted_us != 0) {
                    const std::uint64_t accepted_us = NowUs();
                    HistAdd(stats_.direct_handoff_admit_to_accept_us,
                        accepted_us - item.admitted_us);
                    flow->direct_send_accepted_us = accepted_us;
                }
                flow->direct_read_queue.pop_front();
                flow->direct_read_bytes = send_length <= flow->direct_read_bytes
                    ? flow->direct_read_bytes - send_length : 0;
                CompleteDirectRead(item.reservation, XtcpDirectCompletion::Accepted);
            }
            else {
                flow->pending_read.clear();
            }
            flow->send_retry_shift = 0;
            KickPoll(s);
            if (direct_payload) {
                if (!flow->direct_read_queue.empty()) {
                    const std::shared_ptr<Impl> self = shared_from_this();
                    boost::asio::post(*s.strand, [self, flow, runtime_generation]() noexcept {
                        self->TrySendPending(flow, runtime_generation);
                    });
                }
                else if (flow->direct_peer_eof) {
                    BeginFirstLegClose(flow);
                }
                return;
            }
            if (flow->connector_read_eof) {
                BeginFirstLegClose(flow);
            }
            else {
                StartRead(flow, runtime_generation);
            }
            return;
        }
        stats_.stack_send_rejected.fetch_add(1, std::memory_order_relaxed);
        if (flow->send_stall_start_us == 0) {
            flow->send_stall_start_us = NowUs();
        }
        // Read exactly one upstream snapshot on the transition into blocked;
        // subsequent 1ms retries deliberately do not sample again.
        if (send_admission_enabled_ && !flow->send_admission_blocked) {
            flow->send_admission_blocked = true;
            flow->send_admission_blocked_since_us = NowUs();
            flow->send_admission_snapshot = {};
            flow->send_admission_snapshot_valid = flow->connection_id != 0 && s.stack &&
                s.stack->ConnLastSendAdmission(flow->connection_id, flow->send_admission_snapshot);
        }
        stats_.send_retry_armed.fetch_add(1, std::memory_order_relaxed);
        flow->retry_timer.expires_after(SendRetryDelay() * (1u << flow->send_retry_shift));
        flow->send_retry_shift = std::min<std::uint32_t>(flow->send_retry_shift + 1, 5);
        const std::shared_ptr<Impl> self = shared_from_this();
        flow->retry_timer.async_wait(boost::asio::bind_executor(*shards_[flow->shard].strand,
            [self, flow, runtime_generation](const boost::system::error_code& ec) noexcept {
                if (!ec && self->IsFlowCurrent(flow, runtime_generation)) {
                    self->stats_.send_retry_fired.fetch_add(1, std::memory_order_relaxed);
                    self->TrySendPending(flow, runtime_generation);
                }
            }));
    }

    void StartWrite(const std::shared_ptr<Flow>& flow, std::uint64_t runtime_generation) noexcept {
        if (!IsFlowCurrent(flow, runtime_generation) || flow->write_active ||
            flow->peer_gone || !flow->connector_connected) {
            return;
        }
        if (flow->write_queue.empty()) {
            MaybeShutdownConnectorSend(flow, runtime_generation);
            return;
        }
        // 注: XTCP-UL-WRITE-BATCH-001 (256KB 单块) 已回滚——UL on 崩到 2.6Mbps。
        // WRITE-BATCH-002 重试小批量 gather-write: strand 串行投递修复 (0005/S1)
        // 之后 per-segment syscall+completion 才成为可观测成本 (avg_wr~1.4KB)。
        // 批量 cap 默认 32KB (env 可回退为 1=逐段), 不等待攒批、只收割已排队块。
        flow->write_active = true;
        const std::size_t batch_cap = ConnectorBatchBytes();
        std::size_t total = 0;
        flow->write_buffers_.clear();
        flow->write_in_flight_.clear();
        while (!flow->write_queue.empty()) {
            const std::shared_ptr<std::vector<Byte>>& chunk = flow->write_queue.front();
            if (!flow->write_in_flight_.empty() && total + chunk->size() > batch_cap) {
                break;
            }
            total += chunk->size();
            flow->write_buffers_.emplace_back(chunk->data(), chunk->size());
            flow->write_in_flight_.push_back(chunk);
            flow->write_queue.pop_front();
        }
        flow->in_flight_bytes = total;
        const std::uint64_t submit_us = NowUs();
        if (flow->write_last_complete_us != 0) {
            HistAdd(stats_.write_gap_us,
                submit_us > flow->write_last_complete_us
                    ? submit_us - flow->write_last_complete_us : 0);
        }
        flow->write_submit_us = submit_us;
        const std::shared_ptr<Impl> self = shared_from_this();
        boost::asio::async_write(flow->connector, flow->write_buffers_,
            boost::asio::bind_executor(*shards_[flow->shard].strand,
                [self, flow, total, runtime_generation](const boost::system::error_code& ec,
                    std::size_t) noexcept {
                    // Debit the queued-byte ledger for this batch exactly once,
                    // regardless of the outcome.
                    self->stats_.queued_bytes_total.fetch_sub(
                        std::exchange(flow->in_flight_bytes, 0),
                        std::memory_order_relaxed);
                    flow->write_active = false;
                    flow->write_buffers_.clear();
                    flow->write_in_flight_.clear();
                    if (!self->IsFlowCurrent(flow, runtime_generation)) {
                        return;
                    }
                    if (ec) {
                        if (flow->peer_gone) {
                            // The second leg is gone: the write side is dead,
                            // but the read side may still drain buffered bytes
                            // before the peer's EOF arrives.
                            return;
                        }
                        self->CloseFlow(flow, true);
                        return;
                    }
                    if (flow->write_submit_us != 0) {
                        HistAdd(self->stats_.write_cycle_us,
                            NowUs() - std::exchange(flow->write_submit_us, 0));
                        flow->write_last_complete_us = NowUs();
                    }
                    flow->write_bytes = total <= flow->write_bytes
                        ? flow->write_bytes - total : 0;
                    self->stats_.connector_write_ops.fetch_add(1, std::memory_order_relaxed);
                    self->stats_.connector_written_bytes.fetch_add(total, std::memory_order_relaxed);
                    self->ScheduleConnectorReceiveResume(runtime_generation);
                    self->StartWrite(flow, runtime_generation);
                }));
    }

    void ScheduleConnectorReceiveResume(std::uint64_t runtime_generation) noexcept {
        if (connector_receive_blocked_.load(std::memory_order_relaxed) == 0 ||
            stats_.queued_bytes_total.load(std::memory_order_relaxed) > GlobalQueueBudget() / 2) {
            return;
        }
        const std::shared_ptr<Impl> self = shared_from_this();
        for (std::size_t shard_index = 0; shard_index < shards_.size(); ++shard_index) {
            boost::asio::post(*shards_[shard_index].strand,
                [self, runtime_generation, shard_index]() noexcept {
                    if (!self->IsCurrent(runtime_generation)) {
                        return;
                    }
                    Shard& shard = self->shards_[shard_index];
                    bool resumed = false;
                    for (const auto& entry : shard.flows) {
                        const std::shared_ptr<Flow>& candidate = entry.second;
                        if (!candidate->connector_receive_backpressured || candidate->closing ||
                            candidate->write_bytes > ConnectorWriteCap() / 2) {
                            continue;
                        }
                        candidate->connector_receive_backpressured = false;
                        self->connector_receive_blocked_.fetch_sub(1, std::memory_order_relaxed);
                        self->stats_.resume_requested.fetch_add(1, std::memory_order_relaxed);
                        if (candidate->connection_id != 0 && shard.stack &&
                            shard.stack->ResumeReceive(candidate->connection_id)) {
                            self->stats_.resume_effective.fetch_add(1, std::memory_order_relaxed);
                            resumed = true;
                        }
                    }
                    if (resumed) {
                        self->KickPoll(shard);
                    }
                });
        }
    }

    void MaybeShutdownConnectorSend(
        const std::shared_ptr<Flow>& flow,
        std::uint64_t runtime_generation) noexcept {
        if (!IsFlowCurrent(flow, runtime_generation) || !flow->first_leg_eof ||
            flow->connector_send_shutdown || flow->write_active ||
            !flow->write_queue.empty()) {
            return;
        }
        boost::system::error_code ec;
        flow->connector.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        if (ec) {
            if (flow->peer_gone) {
                // The peer socket is already gone; the read side still drains.
                flow->connector_send_shutdown = true;
                return;
            }
            CloseFlow(flow, true);
            return;
        }
        flow->connector_send_shutdown = true;
    }

    struct DirectReadReservation final {
        XtcpDirectReadReservation reservation;
        std::shared_ptr<XtcpSecondLegHooks> second_leg;
    };

    bool AllocateDirectReadToken(XtcpDirectReadReservation& reservation) noexcept {
        std::uint64_t current = next_direct_read_token_.load(std::memory_order_relaxed);
        for (;;) {
            if (current == std::numeric_limits<std::uint64_t>::max()) {
                return false;
            }
            const std::uint64_t token = current + 1;
            if (next_direct_read_token_.compare_exchange_weak(current, token,
                    std::memory_order_relaxed, std::memory_order_relaxed)) {
                reservation.token = token;
                return true;
            }
        }
    }

    void EraseDirectSecondLeg(std::uint64_t flow_generation,
        const std::shared_ptr<XtcpSecondLegHooks>& expected = {}) noexcept {
        std::lock_guard<std::mutex> lock(direct_read_sync_);
        const auto found = direct_second_legs_.find(flow_generation);
        if (found != direct_second_legs_.end() && (!expected || found->second == expected)) {
            direct_second_legs_.erase(found);
        }
    }

    bool ExtractDirectRead(const XtcpDirectReadReservation& reservation,
        DirectReadReservation& extracted) noexcept {
        std::lock_guard<std::mutex> lock(direct_read_sync_);
        const auto found = direct_read_reservations_.find(reservation.flow_generation);
        if (found == direct_read_reservations_.end() ||
            !found->second.reservation.IsSame(reservation)) {
            return false;
        }
        extracted = std::move(found->second);
        direct_read_reservations_.erase(found);
        direct_read_bytes_.fetch_sub(reservation.length, std::memory_order_relaxed);
        return true;
    }

    void CompleteDirectRead(const XtcpDirectReadReservation& reservation,
        XtcpDirectCompletion completion) noexcept {
        DirectReadReservation extracted;
        if (!ExtractDirectRead(reservation, extracted) || !extracted.second_leg) {
            return;
        }
        if (completion == XtcpDirectCompletion::Accepted) {
            if (const std::shared_ptr<Flow> flow = FindFlowGeneration(reservation.flow_generation)) {
                if (flow->direct_send_accepted_us != 0) {
                    HistAdd(stats_.direct_handoff_accept_to_writable_us,
                        NowUs() - std::exchange(flow->direct_send_accepted_us, 0));
                }
            }
        }
        bool delivered = false;
        try {
            extracted.second_leg->OnDownloadComplete(reservation, completion);
            delivered = true;
        }
        catch (...) {
        }
        if (delivered && completion == XtcpDirectCompletion::Accepted) {
            stats_.direct_download_writable_callbacks.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void CompleteAllDirectReads(std::uint64_t flow_generation) noexcept {
        DirectReadReservation extracted;
        {
            std::lock_guard<std::mutex> lock(direct_read_sync_);
            const auto found = direct_read_reservations_.find(flow_generation);
            if (found == direct_read_reservations_.end()) {
                return;
            }
            extracted = std::move(found->second);
            direct_read_reservations_.erase(found);
            direct_read_bytes_.fetch_sub(extracted.reservation.length, std::memory_order_relaxed);
        }
        if (extracted.second_leg) {
            try {
                extracted.second_leg->OnDownloadComplete(extracted.reservation,
                    XtcpDirectCompletion::Terminal);
            }
            catch (...) {
            }
        }
    }

    void CompleteAndClearDirectReads() noexcept {
        std::unordered_map<std::uint64_t, DirectReadReservation> abandoned;
        std::unordered_map<std::uint64_t, std::shared_ptr<XtcpSecondLegHooks>> hooks;
        {
            std::lock_guard<std::mutex> lock(direct_read_sync_);
            abandoned.swap(direct_read_reservations_);
            hooks.swap(direct_second_legs_);
            direct_read_bytes_.store(0, std::memory_order_relaxed);
        }
        for (const auto& entry : abandoned) {
            const DirectReadReservation& reservation = entry.second;
            if (reservation.second_leg) {
                try {
                    reservation.second_leg->OnDownloadComplete(reservation.reservation,
                        XtcpDirectCompletion::Terminal);
                }
                catch (...) {
                }
            }
        }
    }

    void BeginFirstLegClose(const std::shared_ptr<Flow>& flow) noexcept {
        if (!flow || flow->closing || flow->first_leg_close_started) {
            return;
        }
        Shard& s = shards_[flow->shard];
        if (flow->connection_id == 0 || !s.stack) {
            CloseFlow(flow, false);
            return;
        }
        flow->first_leg_close_started = true;
        s.stack->Close(flow->connection_id);
        KickPoll(s);
    }

    // Called only from the owning shard strand. Mark before invoking the
    // second leg so any later close path observes the request as completed.
    void RequestSecondLegClose(const std::shared_ptr<Flow>& flow) noexcept {
        if (!flow || !flow->direct_bridge) {
            return;
        }
        if (flow->second_leg_close_requested) {
            stats_.second_leg_close_duplicate_suppressed.fetch_add(
                1, std::memory_order_relaxed);
            return;
        }
        flow->second_leg_close_requested = true;
        stats_.second_leg_close_requested.fetch_add(1, std::memory_order_relaxed);
        if (const std::shared_ptr<XtcpSecondLegHooks> direct = flow->direct_second_leg) {
            direct->ClosePeerSend();
        }
    }

    bool IsFlowCurrent(const std::shared_ptr<Flow>& flow, std::uint64_t runtime_generation) const noexcept {
        if (!flow || flow->closing || !IsCurrent(runtime_generation)) {
            return false;
        }
        const auto& shard_flows = shards_[flow->shard].flows;
        const auto found = shard_flows.find(flow->key);
        return found != shard_flows.end() && found->second == flow;
    }

    std::shared_ptr<Flow> FindFlowGeneration(std::uint64_t flow_generation) noexcept {
        // S1: 高位是 shard 标签 (StartFlow 打上), 免跨 shard 扫描。
        const std::size_t shard_index = static_cast<std::size_t>(flow_generation >> 56);
        if (shard_index >= shards_.size()) {
            return nullptr;
        }
        for (const auto& entry : shards_[shard_index].flows) {
            if (entry.second->generation == flow_generation) {
                return entry.second;
            }
        }
        return nullptr;
    }

    std::shared_ptr<Flow> FindConnection(Shard& s, UInt64 connection_id) noexcept {
        const auto key = s.connections.find(connection_id);
        if (key == s.connections.end()) {
            return nullptr;
        }
        const auto flow = s.flows.find(key->second);
        return flow == s.flows.end() ? nullptr : flow->second;
    }

    void CloseFlow(const std::shared_ptr<Flow>& flow, bool abort_stack) noexcept {
        if (!flow || flow->closing) {
            return;
        }
        if (flow->resume_pending) {
            FinishResume(flow, true);
        }
        flow->resume_capacity_available = false;
        flow->closing = true;
        flow->upload_budget_blocked_bytes = 0;
        if (const auto budget = std::atomic_load_explicit(&upload_budget_,
                std::memory_order_acquire)) {
            budget->CancelWait(flow->generation);
        }
        if (flow->connector_receive_backpressured) {
            flow->connector_receive_backpressured = false;
            connector_receive_blocked_.fetch_sub(1, std::memory_order_relaxed);
        }
        CompleteAllDirectReads(flow->generation);
        EraseDirectSecondLeg(flow->generation);
        if (flow->direct_bridge) {
            direct_flows_.fetch_sub(1, std::memory_order_relaxed);
            flow->direct_bridge = false;
        }
        flow->direct_read_queue.clear();
        flow->direct_read_bytes = 0;
        flow->direct_second_leg.reset();
        // Refund only the not-yet-submitted tail; the in-flight chunk is
        // debited by its own completion handler even after cancellation.
        const std::size_t unsubmitted =
            flow->write_bytes >= flow->in_flight_bytes
                ? flow->write_bytes - flow->in_flight_bytes : 0;
        stats_.queued_bytes_total.fetch_sub(unsubmitted, std::memory_order_relaxed);
        // Pending callbacks may retain Flow after close. Release abandoned
        // queue credit now, but leave write_in_flight_ alive until completion.
        flow->write_queue.clear();
        if (external_cancel_ && flow->source_port != 0) {
            external_cancel_(flow->source_port, Generation());
        }
        boost::system::error_code ec;
        flow->retry_timer.cancel(ec);
        flow->connector.cancel(ec);
        flow->connector.close(ec);
        Shard& s = shards_[flow->shard];
        if (flow->connection_id != 0) {
            s.connections.erase(flow->connection_id);
            if (abort_stack && s.stack) {
                s.stack->Abort(flow->connection_id);
            }
        }
        const UInt64 listener_key = ::xtcp::EndpointKey(flow->local);
        const auto listener = s.listener_refs.find(listener_key);
        if (listener != s.listener_refs.end()) {
            if (listener->second.second > 1) {
                --listener->second.second;
            }
            else {
                if (s.stack) {
                    s.stack->StopListen(listener->second.first);
                }
                s.listener_refs.erase(listener);
            }
        }
        s.flows.erase(flow->key);
        stats_.flows_closed.fetch_add(1, std::memory_order_relaxed);
        KickPoll(s);
    }

    static std::uint64_t NowUs() noexcept {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    // ---------------------------------------------------------------- perf dump
    // Env-gated (OPENPPP2_XTCP_PERF_JSON=<path>): appends one JSON line per
    // second with per-interval deltas of the diagnostic counters. Off by
    // default; when unset there is no timer and no I/O.
    struct PerfPrev final {
        std::uint64_t stack_send_calls = 0;
        std::uint64_t stack_send_rejected = 0;
        std::uint64_t send_retry_armed = 0;
        std::uint64_t send_retry_fired = 0;
        std::uint64_t send_stall_us_sum = 0;
        std::uint64_t send_stall_events = 0;
        std::uint64_t connector_read_calls = 0;
        std::uint64_t connector_read_bytes = 0;
        std::uint64_t connector_write_ops = 0;
        std::uint64_t connector_written_bytes = 0;
        std::uint64_t recv_cb_calls = 0;
        std::uint64_t recv_cb_bytes = 0;
        std::uint64_t ingress_enqueued = 0;
        std::uint64_t ingress_dispatched = 0;
        std::uint64_t ingress_dropped = 0;
        std::uint64_t ingress_injected = 0;
        std::uint64_t on_receive_rejected = 0;
        std::uint64_t on_receive_rejected_bytes = 0;
        std::uint64_t output_packets = 0;
        std::uint64_t output_bytes = 0;
        std::uint64_t timer_armed = 0;
        std::uint64_t timer_kick_requests = 0;
        std::uint64_t timer_kick_due_now = 0;
        std::uint64_t timer_kick_lead_us_sum = 0;
        std::uint64_t timer_rearm_attempts = 0;
        std::uint64_t timer_rearm_suppressed_slack = 0;
        ::xtcp::core::AckReleaseTelemetrySnapshot ack_release;
        ::xtcp::core::TsoGateTelemetrySnapshot tso_gate;
        XtcpOutputRejectionSnapshot output_rejections;
        // Plain snapshots of the atomic histograms (copyable).
        std::uint64_t queue_delay_us[Stats::kHistBuckets] = {};
        std::uint64_t timer_late_us[Stats::kHistBuckets] = {};
        std::uint64_t write_cycle_us[Stats::kHistBuckets] = {};
        std::uint64_t write_gap_us[Stats::kHistBuckets] = {};
        std::uint64_t direct_handoff_admit_to_shard_us[Stats::kHistBuckets] = {};
        std::uint64_t direct_handoff_admit_to_accept_us[Stats::kHistBuckets] = {};
        std::uint64_t direct_handoff_accept_to_writable_us[Stats::kHistBuckets] = {};
        std::uint64_t direct_second_leg_handler_us[Stats::kHistBuckets] = {};
        std::uint64_t direct_second_leg_accepted_wait_to_resume_us[Stats::kHistBuckets] = {};
    };

    void StartPerfDump() noexcept {
        const char* path = ::getenv("OPENPPP2_XTCP_PERF_JSON");
        if (path == nullptr || path[0] == '\0' || !context_ || shards_.empty()) {
            return;
        }
        shard_prev_.assign(shards_.size() * 4, 0);
        perf_json_enabled_.store(true, std::memory_order_relaxed);
        if (const std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry> telemetry =
                std::atomic_load_explicit(&direct_queue_telemetry_, std::memory_order_acquire)) {
            telemetry->EnableTiming();
        }
        send_admission_enabled_ = EnvEnabled("OPENPPP2_XTCP_SEND_ADMISSION_JSON");
        ack_release_enabled_ = EnvEnabled("OPENPPP2_XTCP_ACK_RELEASE_JSON");
        output_rejection_enabled_ = EnvEnabled("OPENPPP2_XTCP_OUTPUT_REJECTION_JSON") &&
            output_rejection_diagnostics_ && output_rejection_diagnostics_->Enabled();
        perf_json_path_ = path;
        boost::asio::post(*shards_[0].strand, [self = shared_from_this()]() noexcept {
            self->perf_out_.open(self->perf_json_path_, std::ios::app);
            if (!self->perf_out_.is_open()) {
                return;
            }
            self->ArmPerfDump();
        });
    }

    void ArmPerfDump() noexcept {
        if (!running_.load(std::memory_order_acquire)) {
            return;
        }
        perf_dump_timer_ = std::make_shared<boost::asio::steady_timer>(*context_);
        perf_dump_timer_->expires_after(std::chrono::milliseconds(1000));
        const std::shared_ptr<Impl> self = shared_from_this();
        perf_dump_timer_->async_wait(boost::asio::bind_executor(*shards_[0].strand,
            [self](const boost::system::error_code& ec) noexcept {
                if (ec || !self->running_.load(std::memory_order_acquire)) {
                    return;
                }
                self->WritePerfLine();
                self->ArmPerfDump();
            }));
    }

    template <typename T>
    static T DeltaOf(const std::atomic<T>& counter, T& prev) noexcept {
        const T now_value = counter.load(std::memory_order_relaxed);
        const T delta = now_value > prev ? now_value - prev : 0;
        prev = now_value;
        return delta;
    }

    void WritePerfLine() noexcept {
        if (shards_.empty()) {
            return;
        }
        Shard& s0 = shards_[0];
        PerfPrev now_prev;
        // Sample the first live connection's TCP internals (real cwnd /
        // inflight / peer window) so the DL analysis uses stack truth.
        // S1: TCP/flow/NDI 诊断采样取 shard 0 (诊断口径, 不影响数据面)。
        tcp_sample_ = {};
        for (const auto& entry : s0.flows) {
            const std::shared_ptr<Flow>& flow = entry.second;
            if (!flow->closing && flow->connection_id != 0 && s0.stack) {
                s0.stack->ConnStats(flow->connection_id, tcp_sample_.inflight,
                    tcp_sample_.cwnd, tcp_sample_.ssthresh, tcp_sample_.snd_wnd,
                    tcp_sample_.retx, tcp_sample_.rto_deadline, tcp_sample_.dup_acks,
                    tcp_sample_.fast_rec, tcp_sample_.front_seq, tcp_sample_.snd_una,
                    tcp_sample_.local_port, tcp_sample_.remote_port);
                break;
            }
        }
        now_prev.stack_send_calls = stats_.stack_send_calls.load(std::memory_order_relaxed);
        now_prev.stack_send_rejected = stats_.stack_send_rejected.load(std::memory_order_relaxed);
        now_prev.send_retry_armed = stats_.send_retry_armed.load(std::memory_order_relaxed);
        now_prev.send_retry_fired = stats_.send_retry_fired.load(std::memory_order_relaxed);
        now_prev.send_stall_us_sum = stats_.send_stall_us_sum.load(std::memory_order_relaxed);
        now_prev.send_stall_events = stats_.send_stall_events.load(std::memory_order_relaxed);
        now_prev.connector_read_calls = stats_.connector_read_calls.load(std::memory_order_relaxed);
        now_prev.connector_read_bytes = stats_.connector_read_bytes.load(std::memory_order_relaxed);
        now_prev.connector_write_ops = stats_.connector_write_ops.load(std::memory_order_relaxed);
        now_prev.connector_written_bytes = stats_.connector_written_bytes.load(std::memory_order_relaxed);
        now_prev.recv_cb_calls = stats_.recv_cb_calls.load(std::memory_order_relaxed);
        now_prev.recv_cb_bytes = stats_.recv_cb_bytes.load(std::memory_order_relaxed);
        now_prev.ingress_enqueued = stats_.ingress_enqueued.load(std::memory_order_relaxed);
        now_prev.ingress_dispatched = stats_.ingress_dispatched.load(std::memory_order_relaxed);
        now_prev.ingress_dropped = stats_.ingress_dropped.load(std::memory_order_relaxed);
        now_prev.ingress_injected = stats_.ingress_injected.load(std::memory_order_relaxed);
        now_prev.on_receive_rejected = stats_.on_receive_rejected.load(std::memory_order_relaxed);
        now_prev.on_receive_rejected_bytes =
            stats_.on_receive_rejected_bytes.load(std::memory_order_relaxed);
    // A2-0: NDI output-path snapshot and per-flow queue distribution.
        ndi_stats_ = s0.backend ? s0.backend->SnapshotTxStats() : XtcpNdiBackend::TxStats{};
        std::uint32_t above_256k = 0;
        std::uint32_t above_1m = 0;
        std::uint32_t above_2m = 0;
        for (const auto& entry : s0.flows) {
            const std::size_t bytes = entry.second->write_bytes;
            if (bytes > 256 * 1024) {
                ++above_256k;
            }
            if (bytes > 1024 * 1024) {
                ++above_1m;
            }
            if (bytes > 2 * 1024 * 1024) {
                ++above_2m;
            }
        }
        flows_above_256k_ = above_256k;
        flows_above_1m_ = above_1m;
        flows_above_2m_ = above_2m;
        now_prev.output_packets = stats_.output_packets.load(std::memory_order_relaxed);
        now_prev.output_bytes = stats_.output_bytes.load(std::memory_order_relaxed);
        now_prev.timer_armed = stats_.timer_armed.load(std::memory_order_relaxed);
        now_prev.timer_kick_requests = stats_.timer_kick_requests.load(std::memory_order_relaxed);
        now_prev.timer_kick_due_now = stats_.timer_kick_due_now.load(std::memory_order_relaxed);
        now_prev.timer_kick_lead_us_sum =
            stats_.timer_kick_lead_us_sum.load(std::memory_order_relaxed);
        now_prev.timer_rearm_attempts = stats_.timer_rearm_attempts.load(std::memory_order_relaxed);
        now_prev.timer_rearm_suppressed_slack =
            stats_.timer_rearm_suppressed_slack.load(std::memory_order_relaxed);
        if (ack_release_enabled_) {
            const auto add_ack_release = [](::xtcp::core::AckReleaseTelemetrySnapshot& total,
                                            const ::xtcp::core::AckReleaseTelemetrySnapshot& value) noexcept {
                total.valid_acks += value.valid_acks;
                total.ack_advance_events += value.ack_advance_events;
                total.ack_advance_bytes += value.ack_advance_bytes;
                total.pending_flush_attempts += value.pending_flush_attempts;
                total.tx_sink_packets += value.tx_sink_packets;
                total.tx_sink_bytes += value.tx_sink_bytes;
                total.pending_flush_pacing += value.pending_flush_pacing;
                total.pending_flush_window_cwnd += value.pending_flush_window_cwnd;
                total.pending_flush_fast_recovery_pipe += value.pending_flush_fast_recovery_pipe;
                total.pending_flush_packet_allocation += value.pending_flush_packet_allocation;
                total.rate_change_events += value.rate_change_events;
                total.rate_change_with_pending += value.rate_change_with_pending;
                total.rate_change_old_rate_sum += value.rate_change_old_rate_sum;
                total.rate_change_new_rate_sum += value.rate_change_new_rate_sum;
                total.rate_change_flush_packets += value.rate_change_flush_packets;
                total.rate_change_flush_bytes += value.rate_change_flush_bytes;
                total.rate_change_deadline_active += value.rate_change_deadline_active;
                total.rate_change_deadline_remaining_us_sum +=
                    value.rate_change_deadline_remaining_us_sum;
            };
            const auto add_tso_gate = [](::xtcp::core::TsoGateTelemetrySnapshot& total,
                                         const ::xtcp::core::TsoGateTelemetrySnapshot& value) noexcept {
                total.direct_candidates += value.direct_candidates;
                total.direct_disabled += value.direct_disabled;
                total.direct_pending += value.direct_pending;
                total.direct_outstanding += value.direct_outstanding;
                total.direct_fast_recovery += value.direct_fast_recovery;
                total.direct_window_cwnd += value.direct_window_cwnd;
                total.direct_pacing += value.direct_pacing;
                total.direct_pool_limit += value.direct_pool_limit;
                total.direct_emitted += value.direct_emitted;
                total.flush_candidates += value.flush_candidates;
                total.flush_disabled += value.flush_disabled;
                total.flush_outstanding += value.flush_outstanding;
                total.flush_fast_recovery += value.flush_fast_recovery;
                total.flush_window_cwnd += value.flush_window_cwnd;
                total.flush_pacing += value.flush_pacing;
                total.flush_emitted += value.flush_emitted;
            };
            for (const Shard& shard : shards_) {
                if (shard.stack) {
                    add_ack_release(now_prev.ack_release, shard.stack->AckReleaseTelemetry());
                    add_tso_gate(now_prev.tso_gate, shard.stack->TsoGateTelemetry());
                }
            }
        }
        if (output_rejection_enabled_) {
            now_prev.output_rejections = output_rejection_diagnostics_->Snapshot();
        }
        ppp::app::runtime::XtcpDirectQueueSnapshot direct_queue;
        if (const std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry> telemetry =
                std::atomic_load_explicit(&direct_queue_telemetry_, std::memory_order_acquire)) {
            direct_queue = telemetry->Snapshot();
        }
        for (std::size_t i = 0; i < Stats::kHistBuckets; ++i) {
            now_prev.queue_delay_us[i] = stats_.queue_delay_us[i].load(std::memory_order_relaxed);
            now_prev.timer_late_us[i] = stats_.timer_late_us[i].load(std::memory_order_relaxed);
            now_prev.write_cycle_us[i] = stats_.write_cycle_us[i].load(std::memory_order_relaxed);
            now_prev.write_gap_us[i] = stats_.write_gap_us[i].load(std::memory_order_relaxed);
            now_prev.direct_handoff_admit_to_shard_us[i] =
                stats_.direct_handoff_admit_to_shard_us[i].load(std::memory_order_relaxed);
            now_prev.direct_handoff_admit_to_accept_us[i] =
                stats_.direct_handoff_admit_to_accept_us[i].load(std::memory_order_relaxed);
            now_prev.direct_handoff_accept_to_writable_us[i] =
                stats_.direct_handoff_accept_to_writable_us[i].load(std::memory_order_relaxed);
            now_prev.direct_second_leg_handler_us[i] = direct_queue.second_leg_handler_us[i];
            now_prev.direct_second_leg_accepted_wait_to_resume_us[i] =
                direct_queue.second_leg_accepted_wait_to_resume_us[i];
        }
        const PerfPrev& p = perf_prev_;
        const std::uint64_t send_calls = now_prev.stack_send_calls >= p.stack_send_calls
            ? now_prev.stack_send_calls - p.stack_send_calls : 0;
        const std::uint64_t send_rejected = now_prev.stack_send_rejected >= p.stack_send_rejected
            ? now_prev.stack_send_rejected - p.stack_send_rejected : 0;
        const std::uint64_t stall_us = now_prev.send_stall_us_sum >= p.send_stall_us_sum
            ? now_prev.send_stall_us_sum - p.send_stall_us_sum : 0;
        const std::uint64_t rd_calls = now_prev.connector_read_calls >= p.connector_read_calls
            ? now_prev.connector_read_calls - p.connector_read_calls : 0;
        const std::uint64_t rd_bytes = now_prev.connector_read_bytes >= p.connector_read_bytes
            ? now_prev.connector_read_bytes - p.connector_read_bytes : 0;
        const std::uint64_t wr_ops = now_prev.connector_write_ops >= p.connector_write_ops
            ? now_prev.connector_write_ops - p.connector_write_ops : 0;
        const std::uint64_t wr_bytes = now_prev.connector_written_bytes >= p.connector_written_bytes
            ? now_prev.connector_written_bytes - p.connector_written_bytes : 0;
        const std::uint64_t recv_calls = now_prev.recv_cb_calls >= p.recv_cb_calls
            ? now_prev.recv_cb_calls - p.recv_cb_calls : 0;
        const std::uint64_t recv_bytes = now_prev.recv_cb_bytes >= p.recv_cb_bytes
            ? now_prev.recv_cb_bytes - p.recv_cb_bytes : 0;
        const std::uint64_t out_pkts = now_prev.output_packets >= p.output_packets
            ? now_prev.output_packets - p.output_packets : 0;
        const std::uint64_t out_bytes = now_prev.output_bytes >= p.output_bytes
            ? now_prev.output_bytes - p.output_bytes : 0;

        Stats::Hist queue_hist{};
        std::uint64_t q_total = 0;
        for (std::size_t i = 0; i < Stats::kHistBuckets; ++i) {
            const std::uint64_t delta =
                now_prev.queue_delay_us[i] > p.queue_delay_us[i]
                    ? now_prev.queue_delay_us[i] - p.queue_delay_us[i] : 0;
            queue_hist[i].store(delta, std::memory_order_relaxed);
            q_total += delta;
        }
        Stats::Hist late_hist{};
        std::uint64_t l_total = 0;
        for (std::size_t i = 0; i < Stats::kHistBuckets; ++i) {
            const std::uint64_t delta =
                now_prev.timer_late_us[i] > p.timer_late_us[i]
                    ? now_prev.timer_late_us[i] - p.timer_late_us[i] : 0;
            late_hist[i].store(delta, std::memory_order_relaxed);
            l_total += delta;
        }

        Stats::Hist cycle_hist{};
        std::uint64_t c_total = 0;
        for (std::size_t i = 0; i < Stats::kHistBuckets; ++i) {
            const std::uint64_t delta =
                now_prev.write_cycle_us[i] > p.write_cycle_us[i]
                    ? now_prev.write_cycle_us[i] - p.write_cycle_us[i] : 0;
            cycle_hist[i].store(delta, std::memory_order_relaxed);
            c_total += delta;
        }
        Stats::Hist gap_hist{};
        std::uint64_t g_total = 0;
        for (std::size_t i = 0; i < Stats::kHistBuckets; ++i) {
            const std::uint64_t delta =
                now_prev.write_gap_us[i] > p.write_gap_us[i]
                    ? now_prev.write_gap_us[i] - p.write_gap_us[i] : 0;
            gap_hist[i].store(delta, std::memory_order_relaxed);
            g_total += delta;
        }
        Stats::Hist handoff_admit_to_shard_hist{};
        Stats::Hist handoff_admit_to_accept_hist{};
        Stats::Hist handoff_accept_to_writable_hist{};
        Stats::Hist direct_second_leg_handler_hist{};
        Stats::Hist direct_second_leg_accepted_wait_to_resume_hist{};
        std::uint64_t handoff_admit_to_shard_total = 0;
        std::uint64_t handoff_admit_to_accept_total = 0;
        std::uint64_t handoff_accept_to_writable_total = 0;
        std::uint64_t direct_second_leg_handler_total = 0;
        std::uint64_t direct_second_leg_accepted_wait_to_resume_total = 0;
        for (std::size_t i = 0; i < Stats::kHistBuckets; ++i) {
            const std::uint64_t admit_to_shard =
                now_prev.direct_handoff_admit_to_shard_us[i] > p.direct_handoff_admit_to_shard_us[i]
                    ? now_prev.direct_handoff_admit_to_shard_us[i] - p.direct_handoff_admit_to_shard_us[i] : 0;
            handoff_admit_to_shard_hist[i].store(admit_to_shard, std::memory_order_relaxed);
            handoff_admit_to_shard_total += admit_to_shard;
            const std::uint64_t admit_to_accept =
                now_prev.direct_handoff_admit_to_accept_us[i] > p.direct_handoff_admit_to_accept_us[i]
                    ? now_prev.direct_handoff_admit_to_accept_us[i] - p.direct_handoff_admit_to_accept_us[i] : 0;
            handoff_admit_to_accept_hist[i].store(admit_to_accept, std::memory_order_relaxed);
            handoff_admit_to_accept_total += admit_to_accept;
            const std::uint64_t accept_to_writable =
                now_prev.direct_handoff_accept_to_writable_us[i] > p.direct_handoff_accept_to_writable_us[i]
                    ? now_prev.direct_handoff_accept_to_writable_us[i] - p.direct_handoff_accept_to_writable_us[i] : 0;
            handoff_accept_to_writable_hist[i].store(accept_to_writable, std::memory_order_relaxed);
            handoff_accept_to_writable_total += accept_to_writable;
            const std::uint64_t second_leg_handler =
                now_prev.direct_second_leg_handler_us[i] > p.direct_second_leg_handler_us[i]
                    ? now_prev.direct_second_leg_handler_us[i] - p.direct_second_leg_handler_us[i] : 0;
            direct_second_leg_handler_hist[i].store(second_leg_handler, std::memory_order_relaxed);
            direct_second_leg_handler_total += second_leg_handler;
            const std::uint64_t second_leg_wait =
                now_prev.direct_second_leg_accepted_wait_to_resume_us[i] >
                    p.direct_second_leg_accepted_wait_to_resume_us[i]
                    ? now_prev.direct_second_leg_accepted_wait_to_resume_us[i] -
                        p.direct_second_leg_accepted_wait_to_resume_us[i] : 0;
            direct_second_leg_accepted_wait_to_resume_hist[i].store(
                second_leg_wait, std::memory_order_relaxed);
            direct_second_leg_accepted_wait_to_resume_total += second_leg_wait;
        }

        // A2-0 NDI deltas: per-interval packet rate and wall-time percentiles.
        ndi_pps_ = ndi_stats_.tx_calls >= ndi_prev_.tx_calls
            ? ndi_stats_.tx_calls - ndi_prev_.tx_calls : 0;
        const std::uint64_t batch_delta = ndi_stats_.batch_packets >= ndi_prev_.batch_packets
            ? ndi_stats_.batch_packets - ndi_prev_.batch_packets : 0;
        ndi_batch_avg_ = ndi_stats_.batch_calls > ndi_prev_.batch_calls && batch_delta != 0
            ? static_cast<double>(batch_delta) /
                  (ndi_stats_.batch_calls - ndi_prev_.batch_calls)
            : 0.0;
        ndi_batch_max_ = ndi_stats_.batch_max;
        auto ndi_percentile = [](const std::uint64_t (&now_hist)[32],
                                 const std::uint64_t (&prev_hist)[32], double pct) -> double {
            std::uint64_t total = 0;
            std::uint64_t delta[32] = {};
            for (std::size_t i = 0; i < 32; ++i) {
                delta[i] = now_hist[i] > prev_hist[i] ? now_hist[i] - prev_hist[i] : 0;
                total += delta[i];
            }
            if (total == 0) {
                return 0.0;
            }
            const std::uint64_t target =
                static_cast<std::uint64_t>(static_cast<double>(total) * pct);
            std::uint64_t seen = 0;
            for (std::size_t i = 0; i < 32; ++i) {
                seen += delta[i];
                if (seen >= target && seen != 0) {
                    return static_cast<double>(std::uint64_t{1} << i);
                }
            }
            return 0.0;
        };
        ndi_out_p50_us_ = ndi_percentile(ndi_stats_.output_us, ndi_prev_.output_us, 0.50);
        ndi_out_p95_us_ = ndi_percentile(ndi_stats_.output_us, ndi_prev_.output_us, 0.95);
        ndi_out_p99_us_ = ndi_percentile(ndi_stats_.output_us, ndi_prev_.output_us, 0.99);
        ndi_iv_p50_us_ = ndi_percentile(ndi_stats_.interval_us, ndi_prev_.interval_us, 0.50);
        ndi_iv_p95_us_ = ndi_percentile(ndi_stats_.interval_us, ndi_prev_.interval_us, 0.95);
        const auto counter_delta = [](std::uint64_t now_value, std::uint64_t previous) noexcept {
            return now_value >= previous ? now_value - previous : std::uint64_t{0};
        };
        const std::uint64_t ndi_attempts = counter_delta(ndi_stats_.attempts, ndi_prev_.attempts);
        const std::uint64_t ndi_accepted = counter_delta(ndi_stats_.accepted, ndi_prev_.accepted);
        const std::uint64_t ndi_rejected = counter_delta(ndi_stats_.rejected, ndi_prev_.rejected);
        const std::uint64_t ndi_gso_packets = counter_delta(ndi_stats_.gso_packets, ndi_prev_.gso_packets);
        const std::uint64_t ndi_gso_bytes = counter_delta(ndi_stats_.gso_bytes, ndi_prev_.gso_bytes);
        const std::uint64_t ndi_gso_rejected = counter_delta(ndi_stats_.gso_rejected, ndi_prev_.gso_rejected);
        char ack_release_buf[4096] = {};
        if (ack_release_enabled_) {
            const ::xtcp::core::AckReleaseTelemetrySnapshot& ack = now_prev.ack_release;
            const ::xtcp::core::AckReleaseTelemetrySnapshot& ack_prev = p.ack_release;
            const ::xtcp::core::TsoGateTelemetrySnapshot& tso = now_prev.tso_gate;
            const ::xtcp::core::TsoGateTelemetrySnapshot& tso_prev = p.tso_gate;
            const int ack_release_written = std::snprintf(ack_release_buf, sizeof(ack_release_buf),
                "\"ack\":{\"valid\":%llu,\"advance_events\":%llu,\"advance_bytes\":%llu},"
                "\"pending_flush\":{\"attempts\":%llu,\"tx_sink_packets\":%llu,"
                "\"tx_sink_bytes\":%llu,\"pacing\":%llu,\"window_cwnd\":%llu,"
                "\"fast_recovery_pipe\":%llu,\"packet_allocation\":%llu},"
                "\"rate_change\":{\"events\":%llu,\"with_pending\":%llu,"
                "\"old_rate_sum\":%llu,\"new_rate_sum\":%llu,\"flush_packets\":%llu,"
                "\"flush_bytes\":%llu,\"deadline_active\":%llu,\"deadline_remaining_us_sum\":%llu},"
                "\"tso_gate\":{\"direct\":{\"candidates\":%llu,\"disabled\":%llu,"
                "\"pending\":%llu,\"outstanding\":%llu,\"fast_recovery\":%llu,"
                "\"window_cwnd\":%llu,\"pacing\":%llu,\"pool_limit\":%llu,\"emitted\":%llu},"
                "\"flush\":{\"candidates\":%llu,\"disabled\":%llu,\"outstanding\":%llu,"
                "\"fast_recovery\":%llu,\"window_cwnd\":%llu,\"pacing\":%llu,\"emitted\":%llu}},"
                "\"ndi_acceptance\":{\"attempts\":%llu,\"accepted\":%llu,\"rejected\":%llu},",
                (unsigned long long)counter_delta(ack.valid_acks, ack_prev.valid_acks),
                (unsigned long long)counter_delta(ack.ack_advance_events, ack_prev.ack_advance_events),
                (unsigned long long)counter_delta(ack.ack_advance_bytes, ack_prev.ack_advance_bytes),
                (unsigned long long)counter_delta(ack.pending_flush_attempts, ack_prev.pending_flush_attempts),
                (unsigned long long)counter_delta(ack.tx_sink_packets, ack_prev.tx_sink_packets),
                (unsigned long long)counter_delta(ack.tx_sink_bytes, ack_prev.tx_sink_bytes),
                (unsigned long long)counter_delta(ack.pending_flush_pacing, ack_prev.pending_flush_pacing),
                (unsigned long long)counter_delta(ack.pending_flush_window_cwnd, ack_prev.pending_flush_window_cwnd),
                (unsigned long long)counter_delta(ack.pending_flush_fast_recovery_pipe,
                    ack_prev.pending_flush_fast_recovery_pipe),
                (unsigned long long)counter_delta(ack.pending_flush_packet_allocation,
                    ack_prev.pending_flush_packet_allocation),
                (unsigned long long)counter_delta(ack.rate_change_events, ack_prev.rate_change_events),
                (unsigned long long)counter_delta(ack.rate_change_with_pending,
                    ack_prev.rate_change_with_pending),
                (unsigned long long)counter_delta(ack.rate_change_old_rate_sum,
                    ack_prev.rate_change_old_rate_sum),
                (unsigned long long)counter_delta(ack.rate_change_new_rate_sum,
                    ack_prev.rate_change_new_rate_sum),
                (unsigned long long)counter_delta(ack.rate_change_flush_packets,
                    ack_prev.rate_change_flush_packets),
                (unsigned long long)counter_delta(ack.rate_change_flush_bytes,
                    ack_prev.rate_change_flush_bytes),
                (unsigned long long)counter_delta(ack.rate_change_deadline_active,
                    ack_prev.rate_change_deadline_active),
                (unsigned long long)counter_delta(ack.rate_change_deadline_remaining_us_sum,
                    ack_prev.rate_change_deadline_remaining_us_sum),
                (unsigned long long)counter_delta(tso.direct_candidates, tso_prev.direct_candidates),
                (unsigned long long)counter_delta(tso.direct_disabled, tso_prev.direct_disabled),
                (unsigned long long)counter_delta(tso.direct_pending, tso_prev.direct_pending),
                (unsigned long long)counter_delta(tso.direct_outstanding, tso_prev.direct_outstanding),
                (unsigned long long)counter_delta(tso.direct_fast_recovery, tso_prev.direct_fast_recovery),
                (unsigned long long)counter_delta(tso.direct_window_cwnd, tso_prev.direct_window_cwnd),
                (unsigned long long)counter_delta(tso.direct_pacing, tso_prev.direct_pacing),
                (unsigned long long)counter_delta(tso.direct_pool_limit, tso_prev.direct_pool_limit),
                (unsigned long long)counter_delta(tso.direct_emitted, tso_prev.direct_emitted),
                (unsigned long long)counter_delta(tso.flush_candidates, tso_prev.flush_candidates),
                (unsigned long long)counter_delta(tso.flush_disabled, tso_prev.flush_disabled),
                (unsigned long long)counter_delta(tso.flush_outstanding, tso_prev.flush_outstanding),
                (unsigned long long)counter_delta(tso.flush_fast_recovery, tso_prev.flush_fast_recovery),
                (unsigned long long)counter_delta(tso.flush_window_cwnd, tso_prev.flush_window_cwnd),
                (unsigned long long)counter_delta(tso.flush_pacing, tso_prev.flush_pacing),
                (unsigned long long)counter_delta(tso.flush_emitted, tso_prev.flush_emitted),
                (unsigned long long)ndi_attempts, (unsigned long long)ndi_accepted,
                (unsigned long long)ndi_rejected);
            if (ack_release_written < 0 ||
                static_cast<std::size_t>(ack_release_written) >= sizeof(ack_release_buf)) {
                perf_prev_ = now_prev;
                return;
            }
        }
        ndi_prev_ = ndi_stats_;

        char admission_buf[1024] = {};
        if (send_admission_enabled_) {
            std::uint32_t blocked = 0;
            std::uint32_t non_sendable = 0;
            std::uint32_t sndbuf_quota = 0;
            std::uint32_t unknown = 0;
            std::uint64_t blocked_bytes = 0;
            std::uint64_t max_current_us = 0;
            bool have_snapshot = false;
            UInt32 attempt_min = 0, attempt_max = 0;
            UInt32 pending_min = 0, pending_max = 0;
            UInt32 inflight_min = 0, inflight_max = 0;
            UInt32 sndbuf_min = 0, sndbuf_max = 0;
            UInt32 sndwnd_min = 0, sndwnd_max = 0;
            UInt64 cwnd_min = 0, cwnd_max = 0;
            UInt64 pacing_due_min = 0, pacing_due_max = 0;
            const std::uint64_t now_us = NowUs();
            for (const auto& entry : s0.flows) {
                const std::shared_ptr<Flow>& flow = entry.second;
                if (!flow->send_admission_blocked) {
                    continue;
                }
                ++blocked;
                blocked_bytes += flow->pending_read.size() + flow->direct_read_bytes;
                max_current_us = std::max(max_current_us,
                    now_us > flow->send_admission_blocked_since_us
                        ? now_us - flow->send_admission_blocked_since_us : 0);
                if (!flow->send_admission_snapshot_valid) {
                    ++unknown;
                    continue;
                }
                const ::xtcp::core::SendAdmissionSnapshot& snapshot =
                    flow->send_admission_snapshot;
                if (snapshot.reason == ::xtcp::core::SendAdmissionReason::kNonSendableState) {
                    ++non_sendable;
                }
                else if (snapshot.reason == ::xtcp::core::SendAdmissionReason::kSndBufQuota) {
                    ++sndbuf_quota;
                }
                else {
                    ++unknown;
                }
                const UInt64 pacing_due = snapshot.pacing_deadline > now_us
                    ? snapshot.pacing_deadline - now_us : 0;
                if (!have_snapshot) {
                    have_snapshot = true;
                    attempt_min = attempt_max = snapshot.attempted_len;
                    pending_min = pending_max = snapshot.pending_send;
                    inflight_min = inflight_max = snapshot.inflight;
                    sndbuf_min = sndbuf_max = snapshot.snd_buf;
                    sndwnd_min = sndwnd_max = snapshot.snd_wnd;
                    cwnd_min = cwnd_max = snapshot.cwnd_bytes;
                    pacing_due_min = pacing_due_max = pacing_due;
                    continue;
                }
                attempt_min = std::min(attempt_min, snapshot.attempted_len);
                attempt_max = std::max(attempt_max, snapshot.attempted_len);
                pending_min = std::min(pending_min, snapshot.pending_send);
                pending_max = std::max(pending_max, snapshot.pending_send);
                inflight_min = std::min(inflight_min, snapshot.inflight);
                inflight_max = std::max(inflight_max, snapshot.inflight);
                sndbuf_min = std::min(sndbuf_min, snapshot.snd_buf);
                sndbuf_max = std::max(sndbuf_max, snapshot.snd_buf);
                sndwnd_min = std::min(sndwnd_min, snapshot.snd_wnd);
                sndwnd_max = std::max(sndwnd_max, snapshot.snd_wnd);
                cwnd_min = std::min(cwnd_min, snapshot.cwnd_bytes);
                cwnd_max = std::max(cwnd_max, snapshot.cwnd_bytes);
                pacing_due_min = std::min(pacing_due_min, pacing_due);
                pacing_due_max = std::max(pacing_due_max, pacing_due);
            }
            std::snprintf(admission_buf, sizeof(admission_buf),
                "\"admission\":{\"blocked\":%u,\"bytes\":%llu,\"non_sendable\":%u,"
                "\"sndbuf_quota\":%u,\"unknown\":%u,\"max_current_ms\":%.3f,"
                "\"attempt_min\":%u,\"attempt_max\":%u,\"pending_min\":%u,\"pending_max\":%u,"
                "\"inflight_min\":%u,\"inflight_max\":%u,\"sndbuf_min\":%u,\"sndbuf_max\":%u,"
                "\"sndwnd_min\":%u,\"sndwnd_max\":%u,\"cwnd_min\":%llu,\"cwnd_max\":%llu,"
                "\"pacing_due_min_us\":%llu,\"pacing_due_max_us\":%llu},",
                blocked, (unsigned long long)blocked_bytes, non_sendable, sndbuf_quota, unknown,
                static_cast<double>(max_current_us) / 1000.0,
                attempt_min, attempt_max, pending_min, pending_max, inflight_min, inflight_max,
                sndbuf_min, sndbuf_max, sndwnd_min, sndwnd_max,
                (unsigned long long)cwnd_min, (unsigned long long)cwnd_max,
                (unsigned long long)pacing_due_min, (unsigned long long)pacing_due_max);
        }

        char output_rejection_buf[2048] = {};
        if (output_rejection_enabled_) {
            const XtcpOutputRejectionSnapshot& output = now_prev.output_rejections;
            const XtcpOutputRejectionSnapshot& previous = p.output_rejections;
            const XtcpOutputRejectionPacketShape& shape = output.packet_shape;
            const XtcpOutputPreCallOversizeAttemptSnapshot& oversize =
                output.first_oversize_output_attempt;
            const XtcpOutputRejectionPacketShape& oversize_shape = oversize.packet_shape;
            std::snprintf(output_rejection_buf, sizeof(output_rejection_buf),
                "\"output_rejection\":{\"weak_owner_expired\":%llu,\"vethernet_disposed\":%llu,"
                "\"tap_missing\":%llu,\"output_rejected\":%llu,\"accepted\":%llu,"
                "\"first_actual_output_rejected_monotonic_ns\":%llu,\"packet_shape\":{"
                "\"captured\":%s,\"parsed\":%s,\"supplied_bytes\":%u,"
                "\"ipv4_total_length\":%u,\"ipv4_ihl\":%u,\"tcp_data_offset\":%u,"
                "\"tcp_payload_length\":%u,\"tcp_flags\":%u,"
                "\"tcp_option_timestamps\":%s,\"tcp_option_sack\":%s,"
                "\"tcp_option_md5\":%s,\"tcp_option_unknown\":%s},"
                "\"first_oversize_output_attempt\":{\"first_monotonic_ns\":%llu,\"packet_shape\":{"
                "\"captured\":%s,\"parsed\":%s,\"supplied_bytes\":%u,"
                "\"ipv4_total_length\":%u,\"ipv4_ihl\":%u,\"tcp_data_offset\":%u,"
                "\"tcp_payload_length\":%u,\"tcp_flags\":%u,"
                "\"tcp_option_timestamps\":%s,\"tcp_option_sack\":%s,"
                "\"tcp_option_md5\":%s,\"tcp_option_unknown\":%s}}},",
                (unsigned long long)counter_delta(output.weak_owner_expired, previous.weak_owner_expired),
                (unsigned long long)counter_delta(output.vethernet_disposed, previous.vethernet_disposed),
                (unsigned long long)counter_delta(output.tap_missing, previous.tap_missing),
                (unsigned long long)counter_delta(output.output_rejected, previous.output_rejected),
                (unsigned long long)counter_delta(output.accepted, previous.accepted),
                (unsigned long long)output.first_actual_output_rejected_monotonic_ns,
                shape.captured ? "true" : "false", shape.parsed ? "true" : "false",
                (unsigned)shape.supplied_bytes, (unsigned)shape.ipv4_total_length,
                (unsigned)shape.ipv4_ihl, (unsigned)shape.tcp_data_offset,
                (unsigned)shape.tcp_payload_length, (unsigned)shape.tcp_flags,
                shape.tcp_option_timestamps ? "true" : "false",
                shape.tcp_option_sack ? "true" : "false",
                shape.tcp_option_md5 ? "true" : "false",
                shape.tcp_option_unknown ? "true" : "false",
                (unsigned long long)oversize.first_monotonic_ns,
                oversize_shape.captured ? "true" : "false", oversize_shape.parsed ? "true" : "false",
                (unsigned)oversize_shape.supplied_bytes, (unsigned)oversize_shape.ipv4_total_length,
                (unsigned)oversize_shape.ipv4_ihl, (unsigned)oversize_shape.tcp_data_offset,
                (unsigned)oversize_shape.tcp_payload_length, (unsigned)oversize_shape.tcp_flags,
                oversize_shape.tcp_option_timestamps ? "true" : "false",
                oversize_shape.tcp_option_sack ? "true" : "false",
                oversize_shape.tcp_option_md5 ? "true" : "false",
                oversize_shape.tcp_option_unknown ? "true" : "false");
        }

        // S1: per-shard 计数 delta (窗口) + 累计 queue 延迟分位。
        char shard_buf[1280] = {};
        {
            std::size_t off = 0;
            for (std::size_t i = 0; i < shards_.size() && off < sizeof(shard_buf); ++i) {
                const Shard& s = shards_[i];
                const std::uint64_t enq = s.enqueued.load(std::memory_order_relaxed);
                const std::uint64_t disp = s.dispatched.load(std::memory_order_relaxed);
                const std::uint64_t inj = s.injected.load(std::memory_order_relaxed);
                const std::uint64_t drp = s.dropped.load(std::memory_order_relaxed);
                std::uint64_t pe = 0, pd = 0, pi = 0, px = 0;
                if (shard_prev_.size() == shards_.size() * 4) {
                    pe = shard_prev_[i * 4];
                    pd = shard_prev_[i * 4 + 1];
                    pi = shard_prev_[i * 4 + 2];
                    px = shard_prev_[i * 4 + 3];
                }
                std::uint64_t q_total = 0;
                for (std::size_t b = 0; b < Stats::kHistBuckets; ++b) {
                    q_total += s.queue_delay_us[b].load(std::memory_order_relaxed);
                }
                const int written = std::snprintf(shard_buf + off, sizeof(shard_buf) - off,
                    "{\"i\":%zu,\"enq\":%llu,\"disp\":%llu,\"inj\":%llu,\"drop\":%llu,"
                    "\"q50\":%.0f,\"q95\":%.0f}%s",
                    i,
                    (unsigned long long)counter_delta(enq, pe),
                    (unsigned long long)counter_delta(disp, pd),
                    (unsigned long long)counter_delta(inj, pi),
                    (unsigned long long)counter_delta(drp, px),
                    HistPercentile(s.queue_delay_us, q_total, 0.50),
                    HistPercentile(s.queue_delay_us, q_total, 0.95),
                    i + 1 < shards_.size() ? "," : "");
                if (written < 0) {
                    break;
                }
                off += static_cast<std::size_t>(written);
            }
            shard_prev_.resize(shards_.size() * 4);
            for (std::size_t i = 0; i < shards_.size(); ++i) {
                shard_prev_[i * 4] = shards_[i].enqueued.load(std::memory_order_relaxed);
                shard_prev_[i * 4 + 1] = shards_[i].dispatched.load(std::memory_order_relaxed);
                shard_prev_[i * 4 + 2] = shards_[i].injected.load(std::memory_order_relaxed);
                shard_prev_[i * 4 + 3] = shards_[i].dropped.load(std::memory_order_relaxed);
            }
        }
        char line[8192];
        char ndi_buf[4096];
        const int ndi_written = std::snprintf(ndi_buf, sizeof(ndi_buf),
            "%s%s%s\"ndi\":{\"pps\":%llu,\"out_p50_us\":%.0f,\"out_p95_us\":%.0f,\"out_p99_us\":%.0f,"
            "\"iv_p50_us\":%.0f,\"iv_p95_us\":%.0f,\"batch_avg\":%.1f,\"batch_max\":%u},"
            "\"ndi_gso\":{\"packets\":%llu,\"bytes\":%llu,\"rejected\":%llu},",
            ack_release_buf, admission_buf, output_rejection_buf, (unsigned long long)ndi_pps_,
            ndi_out_p50_us_, ndi_out_p95_us_, ndi_out_p99_us_,
            ndi_iv_p50_us_, ndi_iv_p95_us_,
            ndi_batch_avg_, (unsigned)ndi_batch_max_,
            (unsigned long long)ndi_gso_packets, (unsigned long long)ndi_gso_bytes,
            (unsigned long long)ndi_gso_rejected);
        if (ndi_written < 0 || static_cast<std::size_t>(ndi_written) >= sizeof(ndi_buf)) {
            perf_prev_ = now_prev;
            return;
        }
        const int line_written = std::snprintf(line, sizeof(line),
            "{\"send\":{\"calls\":%llu,\"rejected\":%llu,\"stall_ms\":%.3f,\"events\":%llu},"
            "\"conn\":{\"rd_calls\":%llu,\"rd_bytes\":%llu,\"avg_rd\":%.0f,"
            "\"wr_ops\":%llu,\"wr_bytes\":%llu,\"avg_wr\":%.0f,\"q_high\":%llu,"
            "\"wr_cyc_p50_us\":%.0f,\"wr_cyc_p95_us\":%.0f,"
            "\"wr_gap_p50_us\":%.0f,\"wr_gap_p95_us\":%.0f,"
            "\"rej\":%llu,\"rej_bytes\":%llu},"
            "\"recv\":{\"calls\":%llu,\"bytes\":%llu,\"avg_seg\":%.0f},"
            "\"out\":{\"pkts\":%llu,\"bytes\":%llu,\"avg_pkt\":%.0f},"
            "\"tcp\":{\"cwnd_mss\":%u,\"inflight\":%u,\"snd_wnd\":%u,\"ssthresh\":%u,"
            "\"retx\":%u,\"dup_acks\":%u,\"fast_rec\":%u},"
            "\"owner\":{\"posts\":%llu,\"dispatched\":%llu,\"dropped\":%llu,\"injected\":%llu,"
            "\"q_p50_us\":%.0f,\"q_p95_us\":%.0f},"
            "\"shards\":[%s],"
            "%s"
            "\"queue\":{\"global\":%llu,\"global_high\":%llu,"
            "\"above_256k\":%u,\"above_1m\":%u,\"above_2m\":%u},"
            "\"direct\":{\"second_leg_close_requested\":%llu,"
            "\"second_leg_close_duplicate_suppressed\":%llu,"
            "\"degraded_half_close\":%llu,\"download_queue_bytes\":%llu,"
            "\"download_queue_bytes_highwater\":%llu,\"handoff\":{"
            "\"admit_to_shard\":{\"count\":%llu,\"p50_us\":%.0f,\"p95_us\":%.0f},"
            "\"admit_to_accept\":{\"count\":%llu,\"p50_us\":%.0f,\"p95_us\":%.0f},"
            "\"accept_to_writable\":{\"count\":%llu,\"p50_us\":%.0f,\"p95_us\":%.0f}},"
            "\"second_leg\":{\"handler\":{\"count\":%llu,\"p50_us\":%.0f,\"p95_us\":%.0f},"
            "\"accepted_wait_to_resume\":{\"count\":%llu,\"p50_us\":%.0f,\"p95_us\":%.0f}}},"
            "\"timer\":{\"armed\":%llu,\"kick_requests\":%llu,\"kick_due_now\":%llu,"
            "\"kick_lead_us_sum\":%llu,\"rearm_attempts\":%llu,\"rearm_suppressed_slack\":%llu,"
            "\"late_n\":%llu,\"late_p50_us\":%.0f,\"late_p95_us\":%.0f}}",
            (unsigned long long)send_calls,
            (unsigned long long)send_rejected,
            static_cast<double>(stall_us) / 1000.0,
            (unsigned long long)(now_prev.send_stall_events >= p.send_stall_events
                ? now_prev.send_stall_events - p.send_stall_events : 0),
            (unsigned long long)rd_calls, (unsigned long long)rd_bytes,
            rd_calls != 0 ? static_cast<double>(rd_bytes) / rd_calls : 0.0,
            (unsigned long long)wr_ops, (unsigned long long)wr_bytes,
            wr_ops != 0 ? static_cast<double>(wr_bytes) / wr_ops : 0.0,
            (unsigned long long)stats_.write_queue_highwater.load(std::memory_order_relaxed),
            HistPercentile(cycle_hist, c_total, 0.50),
            HistPercentile(cycle_hist, c_total, 0.95),
            HistPercentile(gap_hist, g_total, 0.50),
            HistPercentile(gap_hist, g_total, 0.95),
            (unsigned long long)(now_prev.on_receive_rejected >= p.on_receive_rejected
                ? now_prev.on_receive_rejected - p.on_receive_rejected : 0),
            (unsigned long long)(now_prev.on_receive_rejected_bytes >= p.on_receive_rejected_bytes
                ? now_prev.on_receive_rejected_bytes - p.on_receive_rejected_bytes : 0),
            (unsigned long long)recv_calls, (unsigned long long)recv_bytes,
            recv_calls != 0 ? static_cast<double>(recv_bytes) / recv_calls : 0.0,
            (unsigned long long)out_pkts, (unsigned long long)out_bytes,
            out_pkts != 0 ? static_cast<double>(out_bytes) / out_pkts : 0.0,
            tcp_sample_.cwnd, tcp_sample_.inflight, tcp_sample_.snd_wnd,
            tcp_sample_.ssthresh, tcp_sample_.retx, tcp_sample_.dup_acks,
            tcp_sample_.fast_rec,
            (unsigned long long)(now_prev.ingress_enqueued >= p.ingress_enqueued
                ? now_prev.ingress_enqueued - p.ingress_enqueued : 0),
            (unsigned long long)(now_prev.ingress_dispatched >= p.ingress_dispatched
                ? now_prev.ingress_dispatched - p.ingress_dispatched : 0),
            (unsigned long long)(now_prev.ingress_dropped >= p.ingress_dropped
                ? now_prev.ingress_dropped - p.ingress_dropped : 0),
            (unsigned long long)(now_prev.ingress_injected >= p.ingress_injected
                ? now_prev.ingress_injected - p.ingress_injected : 0),
            HistPercentile(queue_hist, q_total, 0.50),
            HistPercentile(queue_hist, q_total, 0.95),
            shard_buf,
            ndi_buf,
            (unsigned long long)stats_.queued_bytes_total.load(std::memory_order_relaxed),
            (unsigned long long)stats_.queued_bytes_highwater.load(std::memory_order_relaxed),
            flows_above_256k_, flows_above_1m_, flows_above_2m_,
            (unsigned long long)stats_.second_leg_close_requested.load(std::memory_order_relaxed),
            (unsigned long long)stats_.second_leg_close_duplicate_suppressed.load(std::memory_order_relaxed),
            (unsigned long long)stats_.degraded_half_close.load(std::memory_order_relaxed),
            (unsigned long long)direct_read_bytes_.load(std::memory_order_relaxed),
            (unsigned long long)stats_.direct_download_queue_bytes_highwater.load(std::memory_order_relaxed),
            (unsigned long long)handoff_admit_to_shard_total,
            HistPercentile(handoff_admit_to_shard_hist, handoff_admit_to_shard_total, 0.50),
            HistPercentile(handoff_admit_to_shard_hist, handoff_admit_to_shard_total, 0.95),
            (unsigned long long)handoff_admit_to_accept_total,
            HistPercentile(handoff_admit_to_accept_hist, handoff_admit_to_accept_total, 0.50),
            HistPercentile(handoff_admit_to_accept_hist, handoff_admit_to_accept_total, 0.95),
            (unsigned long long)handoff_accept_to_writable_total,
            HistPercentile(handoff_accept_to_writable_hist, handoff_accept_to_writable_total, 0.50),
            HistPercentile(handoff_accept_to_writable_hist, handoff_accept_to_writable_total, 0.95),
            (unsigned long long)direct_second_leg_handler_total,
            HistPercentile(direct_second_leg_handler_hist, direct_second_leg_handler_total, 0.50),
            HistPercentile(direct_second_leg_handler_hist, direct_second_leg_handler_total, 0.95),
            (unsigned long long)direct_second_leg_accepted_wait_to_resume_total,
            HistPercentile(direct_second_leg_accepted_wait_to_resume_hist,
                direct_second_leg_accepted_wait_to_resume_total, 0.50),
            HistPercentile(direct_second_leg_accepted_wait_to_resume_hist,
                direct_second_leg_accepted_wait_to_resume_total, 0.95),
            (unsigned long long)(now_prev.timer_armed >= p.timer_armed
                ? now_prev.timer_armed - p.timer_armed : 0),
            (unsigned long long)(now_prev.timer_kick_requests >= p.timer_kick_requests
                ? now_prev.timer_kick_requests - p.timer_kick_requests : 0),
            (unsigned long long)(now_prev.timer_kick_due_now >= p.timer_kick_due_now
                ? now_prev.timer_kick_due_now - p.timer_kick_due_now : 0),
            (unsigned long long)(now_prev.timer_kick_lead_us_sum >= p.timer_kick_lead_us_sum
                ? now_prev.timer_kick_lead_us_sum - p.timer_kick_lead_us_sum : 0),
            (unsigned long long)(now_prev.timer_rearm_attempts >= p.timer_rearm_attempts
                ? now_prev.timer_rearm_attempts - p.timer_rearm_attempts : 0),
            (unsigned long long)(now_prev.timer_rearm_suppressed_slack >=
                p.timer_rearm_suppressed_slack
                ? now_prev.timer_rearm_suppressed_slack - p.timer_rearm_suppressed_slack : 0),
            (unsigned long long)l_total,
            HistPercentile(late_hist, l_total, 0.50),
            HistPercentile(late_hist, l_total, 0.95));
        if (line_written < 0 || static_cast<std::size_t>(line_written) >= sizeof(line)) {
            perf_prev_ = now_prev;
            return;
        }
        perf_out_.write(line, line_written);
        perf_out_.put('\n');
        perf_out_.flush();
        perf_prev_ = now_prev;
    }

#if defined(PPP_XTCP_HAS_TIMER_DEADLINE)
    // Deadline-driven polling: the timer is armed for the stack's next timer
    // deadline instead of a fixed cadence. Stack-mutating paths call
    // KickPoll() so a freshly armed earlier deadline preempts a pending wait;
    // the idle watchdog bounds the wait when nothing is armed.
    static constexpr std::uint64_t kIdlePollIntervalMs = 10;
    // XTCP-STRAND-DISPATCH-001: re-arm slack. With pacing (0005) the stack's
    // next deadline advances on every flush; re-arming (cancel + async_wait)
    // per packet on a burst burns the strand on timer churn. A new deadline
    // less than this much earlier than the armed one rides the pending wait
    // (one extra poll at most, <= slack late).
    static constexpr std::int64_t kRearmSlackUs = 50;

    std::chrono::steady_clock::duration PollDelay(const Shard& s) const noexcept {
        if (!s.stack) {
            return std::chrono::milliseconds(1);
        }
        const UInt64 due = s.stack->NextTimerDeadlineUs();
        if (due == ::xtcp::XtcpStack::kNoTimerDeadline) {
            return std::chrono::milliseconds(kIdlePollIntervalMs);
        }
        const std::uint64_t now = NowUs();
        return due <= now
            ? std::chrono::microseconds(0)
            : std::chrono::microseconds(due - now);
    }

    void KickPoll(Shard& s) noexcept {
        if (!running_.load(std::memory_order_acquire) || !s.stack || !s.poll_timer) {
            return;
        }
        const bool observe = perf_json_enabled_.load(std::memory_order_relaxed);
        if (observe) {
            stats_.timer_kick_requests.fetch_add(1, std::memory_order_relaxed);
        }
        const std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
        const std::chrono::steady_clock::time_point target = now + PollDelay(s);
        if (observe) {
            if (target <= now) {
                stats_.timer_kick_due_now.fetch_add(1, std::memory_order_relaxed);
            }
            else {
                stats_.timer_kick_lead_us_sum.fetch_add(static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(target - now).count()),
                    std::memory_order_relaxed);
            }
        }
        if (target + std::chrono::microseconds(kRearmSlackUs) < s.poll_timer->expiry()) {
            if (observe) {
                stats_.timer_rearm_attempts.fetch_add(1, std::memory_order_relaxed);
            }
            boost::system::error_code ec;
            s.poll_timer->cancel(ec);
            SchedulePoll(s, generation_.load(std::memory_order_acquire));
        }
        else if (observe && target < s.poll_timer->expiry()) {
            stats_.timer_rearm_suppressed_slack.fetch_add(1, std::memory_order_relaxed);
        }
    }
#else
    void KickPoll(Shard&) noexcept {}
#endif

    void SchedulePoll(Shard& s, std::uint64_t runtime_generation) noexcept {
        if (!IsCurrent(runtime_generation)) {
            return;
        }
        // XTCP-STRAND-DISPATCH-001: one steady_timer object is created per
        // shard and reused; make_shared per poll was a per-packet heap
        // allocation on bursts.
        if (!s.poll_timer) {
            s.poll_timer = std::make_shared<boost::asio::steady_timer>(*context_);
        }
#if defined(PPP_XTCP_HAS_TIMER_DEADLINE)
        s.poll_timer->expires_after(PollDelay(s));
#else
        s.poll_timer->expires_after(std::chrono::milliseconds(1));
#endif
        stats_.timer_armed.fetch_add(1, std::memory_order_relaxed);
        const std::shared_ptr<Impl> self = shared_from_this();
        const std::size_t shard_index = s.index;
        s.poll_timer->async_wait(boost::asio::bind_executor(*s.strand,
            [self, shard_index, runtime_generation](const boost::system::error_code& ec) noexcept {
                if (ec || !self->IsCurrent(runtime_generation)) {
                    return;
                }
                Shard& s = self->shards_[shard_index];
                if (!s.stack) {
                    return;
                }
                if (s.poll_timer) {
                    const auto overdue = std::chrono::steady_clock::now() -
                        s.poll_timer->expiry();
                    if (overdue.count() > 0) {
                        HistAdd(self->stats_.timer_late_us,
                            static_cast<std::uint64_t>(
                                std::chrono::duration_cast<std::chrono::microseconds>(
                                    overdue).count()));
                    }
                }
                self->stats_.timer_polls.fetch_add(1, std::memory_order_relaxed);
                self->stats_.timer_events.fetch_add(
                    s.stack->PollAckTimers(), std::memory_order_relaxed);
                self->SchedulePoll(s, runtime_generation);
            }));
    }

    // S1: 每 shard 的 teardown 在自己的 strand 上执行 (与其余在途 handler
    // 串行); 全部 shard 完成后由最后一个 shard 调 DoStopFinalize 收尾。
    void DoStopShard(Shard& s) noexcept {
        if (s.poll_timer) {
            boost::system::error_code ec;
            s.poll_timer->cancel(ec);
            s.poll_timer.reset();
        }
        while (!s.flows.empty()) {
            CloseFlow(s.flows.begin()->second, true);
        }
        s.connections.clear();
        s.listener_refs.clear();
        s.stack.reset();
        if (s.backend) {
            s.backend->Stop();
            s.backend.reset();
        }
    }

    void DoStopFinalize() noexcept {
        if (perf_dump_timer_) {
            boost::system::error_code ec;
            perf_dump_timer_->cancel(ec);
            perf_dump_timer_.reset();
        }
        if (perf_out_.is_open()) {
            perf_out_.flush();
            perf_out_.close();
        }
        CompleteAndClearDirectReads();
        direct_flows_.store(0, std::memory_order_relaxed);
        connector_receive_blocked_.store(0, std::memory_order_relaxed);
        std::atomic_store_explicit(&direct_queue_telemetry_,
            std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry>{},
            std::memory_order_release);
        lease_.reset();
        if (own_context_) {
            own_context_->stop();
        }
        stopping_.store(false, std::memory_order_release);
    }

private:
    std::shared_ptr<boost::asio::io_context> context_;
    OutputHandler output_;
    OutputHandler counted_output_;
    bool tx_gso_supported_ = false;
    ListenerEndpointHandler listener_endpoint_;
    ExternalAcceptHandler external_accept_;
    ExternalCancelHandler external_cancel_;
    std::shared_ptr<XtcpOutputRejectionDiagnostics> output_rejection_diagnostics_;
    mutable std::mutex state_sync_;
    std::atomic<bool> running_{false};
    std::atomic<bool> ready_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<std::uint64_t> generation_{0};
    std::atomic<std::uint64_t> runtime_instance_id_{0};
    std::atomic<std::uint64_t> next_flow_generation_{0};
    std::atomic<std::uint64_t> direct_read_bytes_{0};
    std::mutex direct_read_sync_;
    std::unordered_map<std::uint64_t, DirectReadReservation> direct_read_reservations_;
    std::unordered_map<std::uint64_t, std::shared_ptr<XtcpSecondLegHooks>> direct_second_legs_;
    std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry> direct_queue_telemetry_;
    std::shared_ptr<XtcpUploadBudget> upload_budget_;
    std::atomic<std::uint64_t> next_direct_read_token_{0};
    std::atomic<std::uint32_t> direct_flows_{0};
    std::atomic<std::uint32_t> connector_receive_blocked_{0};
    Stats stats_;
    std::unique_ptr<XtcpPoolLease> lease_;
    // Perf diagnostics state (strand-only once Start() armed the dump).
    std::string perf_json_path_;
    bool send_admission_enabled_ = false;
    bool ack_release_enabled_ = false;
    bool output_rejection_enabled_ = false;
    std::atomic<bool> perf_json_enabled_{false};
    std::shared_ptr<boost::asio::steady_timer> perf_dump_timer_;
    std::ofstream perf_out_;
    PerfPrev perf_prev_;
    struct TcpSample final {
        UInt32 inflight = 0;
        UInt32 cwnd = 0;
        UInt32 ssthresh = 0;
        UInt32 snd_wnd = 0;
        UInt32 retx = 0;
        UInt32 dup_acks = 0;
        UInt32 fast_rec = 0;
        UInt32 front_seq = 0;
        UInt32 snd_una = 0;
        UInt16 local_port = 0;
        UInt16 remote_port = 0;
        UInt64 rto_deadline = 0;
    };
    TcpSample tcp_sample_;
    XtcpNdiBackend::TxStats ndi_stats_;
    XtcpNdiBackend::TxStats ndi_prev_;
    std::vector<std::uint64_t> shard_prev_;
    // Per-interval NDI aggregates written into the JSON line.
    std::uint64_t ndi_pps_ = 0;
    double ndi_out_p50_us_ = 0.0;
    double ndi_out_p95_us_ = 0.0;
    double ndi_out_p99_us_ = 0.0;
    double ndi_iv_p50_us_ = 0.0;
    double ndi_iv_p95_us_ = 0.0;
    double ndi_batch_avg_ = 0.0;
    std::uint32_t ndi_batch_max_ = 0;
    std::uint32_t flows_above_256k_ = 0;
    std::uint32_t flows_above_1m_ = 0;
    std::uint32_t flows_above_2m_ = 0;
    // deque 而非 vector: Shard 含 mutex/atomic 不可移动, deque 元素永不搬迁。
    std::deque<Shard> shards_;
    int shard_count_ = 1;
    std::atomic<std::uint32_t> next_external_port_{0};
    // shards>1 时的专属执行池 (XtcpRuntime 独享, 析构时 stop+join)。
    std::shared_ptr<boost::asio::io_context> own_context_;
    std::vector<std::thread> own_threads_;
    bool unix_bridge_ = false;
};

XtcpRuntime::XtcpRuntime(
    const std::shared_ptr<boost::asio::io_context>& context,
    OutputHandler output,
    ListenerEndpointHandler listener_endpoint,
    ExternalAcceptHandler external_accept,
    ExternalCancelHandler external_cancel,
    std::shared_ptr<XtcpOutputRejectionDiagnostics> output_rejection_diagnostics,
    bool tx_gso_supported) noexcept {
    try {
        impl_ = std::make_shared<Impl>(context, std::move(output),
            std::move(listener_endpoint), std::move(external_accept),
            std::move(external_cancel), std::move(output_rejection_diagnostics),
            tx_gso_supported);
    }
    catch (...) {}
}

XtcpRuntime::~XtcpRuntime() noexcept {
    Stop();
}

bool XtcpRuntime::Start() noexcept { return impl_ && impl_->Start(); }
void XtcpRuntime::MarkReady() noexcept { if (impl_) impl_->MarkReady(); }
void XtcpRuntime::Stop() noexcept { if (impl_) impl_->Stop(); }
bool XtcpRuntime::SubmitIPv4Tcp(const void* packet, int packet_length) noexcept {
    return impl_ && impl_->Submit(packet, packet_length);
}
bool XtcpRuntime::IsReady() const noexcept { return impl_ && impl_->IsReady(); }
bool XtcpRuntime::IsRunning() const noexcept { return impl_ && impl_->IsRunning(); }
std::uint64_t XtcpRuntime::Generation() const noexcept { return impl_ ? impl_->Generation() : 0; }
ppp::app::runtime::RuntimeXtcpStats XtcpRuntime::SnapshotStats() const noexcept {
    return impl_ ? impl_->SnapshotStats() : ppp::app::runtime::RuntimeXtcpStats{};
}
#if defined(PPP_XTCP_RUNTIME_TESTING)
bool XtcpRuntime::EmitOutputForTesting(const std::shared_ptr<Byte>& data, int length,
    std::optional<ppp::tap::TxGsoMetadata> gso) noexcept {
    return impl_ && impl_->EmitOutputForTesting(data, length, gso);
}
#endif
#endif

} // namespace ppp::app::client::xtcp
