#include <ppp/app/client/xtcp/XtcpNdiBackend.h>
#include <ppp/app/client/xtcp/XtcpRuntime.h>
#include <ppp/app/client/xtcp/XtcpRuntimePolicy.h>

#include <xtcp/buf/bufref.h>

#include <boost/asio/io_context.hpp>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

namespace {
std::shared_ptr<Byte> MakeTestBuffer(const Byte* bytes, std::size_t length) noexcept {
    const std::shared_ptr<std::vector<Byte>> holder =
        std::make_shared<std::vector<Byte>>(bytes, bytes + length);
    return std::shared_ptr<Byte>(holder, holder->data());
}
}

namespace ppp::app::client::xtcp {
std::size_t GsoSplitForTesting(const uint8_t* frame, std::size_t length,
    std::size_t target_mtu, ::xtcp::buf::BufRef* out, std::size_t out_cap) noexcept;
}

namespace {
int failures = 0;

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
                         #condition);                                        \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

void TestConsumePolicy() {
    using ppp::app::client::xtcp::ShouldConsumeXtcpPacket;
    CHECK(ShouldConsumeXtcpPacket(true, false, false));
    CHECK(ShouldConsumeXtcpPacket(false, true, true));
    CHECK(!ShouldConsumeXtcpPacket(false, true, false));
    CHECK(!ShouldConsumeXtcpPacket(false, false, true));
}

void TestIngressCapsStopAndGeneration() {
    ppp::app::client::xtcp::XtcpIngressBudget budget(2, 10);
    const std::uint64_t first = budget.Start();
    CHECK(!budget.TryReserve(1));
    budget.MarkReady(first);
    CHECK(budget.TryReserve(4));
    CHECK(budget.TryReserve(6));
    CHECK(!budget.TryReserve(1));
    budget.Release(4);
    CHECK(budget.TryReserve(4));
    budget.Stop();
    CHECK(!budget.TryReserve(1));
    CHECK(!budget.Accepts(first));

    const std::uint64_t second = budget.Start();
    CHECK(second != first);
    budget.MarkReady(first);
    CHECK(!budget.IsReady());
    budget.MarkReady(second);
    CHECK(budget.IsReady());
}

void TestFlowCallbackIdentity() {
    using ppp::app::client::xtcp::IsCurrentXtcpFlowCallback;
    using ppp::app::client::xtcp::XtcpFlowCallbackIdentity;
    const XtcpFlowCallbackIdentity queued_old_event{7, 41};
    CHECK(IsCurrentXtcpFlowCallback(queued_old_event, 7, 41));
    CHECK(!IsCurrentXtcpFlowCallback(queued_old_event, 7, 42));
    CHECK(!IsCurrentXtcpFlowCallback(queued_old_event, 8, 41));
}

void TestGsoSplitFlagPlacement() {
    using ppp::app::client::xtcp::XtcpGsoSplitSegmentFlags;
    constexpr std::uint8_t kFinPshAckCwr = 0x01 | 0x08 | 0x10 | 0x80;
    CHECK(XtcpGsoSplitSegmentFlags(kFinPshAckCwr, 0, 3) == (0x10 | 0x80));
    CHECK(XtcpGsoSplitSegmentFlags(kFinPshAckCwr, 1, 3) == 0x10);
    CHECK(XtcpGsoSplitSegmentFlags(kFinPshAckCwr, 2, 3) == (0x01 | 0x08 | 0x10));
    CHECK(XtcpGsoSplitSegmentFlags(kFinPshAckCwr, 0, 1) == kFinPshAckCwr);

    // A client half-close can reach the TUN as one super-frame carrying the
    // data tail plus FIN. Only the last split may carry FIN; otherwise the
    // stack consumes FIN mid-stream and trims a byte of the next split.
    constexpr std::size_t kPayload = 3000;
    std::vector<std::uint8_t> frame(40 + kPayload);
    frame[0] = 0x45;
    frame[2] = static_cast<std::uint8_t>(frame.size() >> 8);
    frame[3] = static_cast<std::uint8_t>(frame.size());
    frame[8] = 64;
    frame[9] = 6;
    const std::uint8_t src[4] = { 10, 0, 0, 2 };
    const std::uint8_t dst[4] = { 192, 0, 2, 2 };
    std::memcpy(&frame[12], src, 4);
    std::memcpy(&frame[16], dst, 4);
    std::uint8_t* tcp = &frame[20];
    tcp[0] = 0xC3; tcp[1] = 0x50;  // 50000
    tcp[2] = 0x4D; tcp[3] = 0x54;  // 19796
    const std::uint32_t seq0 = 0xFFFFF000u;  // crosses the 2^32 wrap
    tcp[4] = static_cast<std::uint8_t>(seq0 >> 24);
    tcp[5] = static_cast<std::uint8_t>(seq0 >> 16);
    tcp[6] = static_cast<std::uint8_t>(seq0 >> 8);
    tcp[7] = static_cast<std::uint8_t>(seq0);
    tcp[12] = 5 << 4;
    tcp[13] = 0x01 | 0x08 | 0x10;  // FIN|PSH|ACK
    tcp[14] = 0xFF; tcp[15] = 0xFF;
    for (std::size_t i = 0; i < kPayload; ++i) {
        frame[40 + i] = static_cast<std::uint8_t>(i);
    }
    ::xtcp::buf::BufRef parts[8];
    const std::size_t count = ppp::app::client::xtcp::GsoSplitForTesting(
        frame.data(), frame.size(), 1500, parts, 8);
    CHECK(count == 3);
    std::size_t carried = 0;
    std::size_t fins = 0;
    for (std::size_t k = 0; k < count; ++k) {
        const std::uint8_t* w = parts[k].Data();
        const std::uint8_t* t = w + 20;
        const std::uint32_t seq = (static_cast<std::uint32_t>(t[4]) << 24) |
            (static_cast<std::uint32_t>(t[5]) << 16) |
            (static_cast<std::uint32_t>(t[6]) << 8) | t[7];
        CHECK(seq == static_cast<std::uint32_t>(seq0 + carried));
        const bool last = k + 1 == count;
        CHECK(((t[13] & 0x01) != 0) == last);
        CHECK(((t[13] & 0x08) != 0) == last);
        CHECK((t[13] & 0x10) != 0);
        fins += (t[13] & 0x01) != 0 ? 1u : 0u;
        const std::size_t payload = parts[k].Len() - 40;
        CHECK(w[40] == static_cast<std::uint8_t>(carried));
        carried += payload;
    }
    CHECK(carried == kPayload);
    CHECK(fins == 1);
}

void TestExternalLoopbackGate() {
    using ppp::app::client::xtcp::IsRegisteredExternalLoopback;
    CHECK(IsRegisteredExternalLoopback(true, 40001, 40001, 7, 7));
    CHECK(!IsRegisteredExternalLoopback(false, 40001, 40001, 7, 7));
    CHECK(!IsRegisteredExternalLoopback(true, 40002, 40001, 7, 7));
    CHECK(!IsRegisteredExternalLoopback(true, 40001, 40001, 8, 7));
    CHECK(!IsRegisteredExternalLoopback(true, 0, 0, 7, 7));
}

void TestIPv4PolicyHelpers() {
    using ppp::app::client::xtcp::IPv4AddressBytes;
    using ppp::app::client::xtcp::IsFragmentedIPv4;

    const auto bytes = IPv4AddressBytes(0x0a000002u);
    CHECK(bytes[0] == 10);
    CHECK(bytes[1] == 0);
    CHECK(bytes[2] == 0);
    CHECK(bytes[3] == 2);

    CHECK(!IsFragmentedIPv4(0, 0));
    CHECK(!IsFragmentedIPv4(0, 2));
    CHECK(IsFragmentedIPv4(0, 1));
    CHECK(IsFragmentedIPv4(1, 0));
}

void TestProductionNdiOwnership() {
    bool accept = false;
    std::shared_ptr<Byte> retained;
    ppp::app::client::xtcp::XtcpNdiBackend backend(
        [&accept, &retained](std::shared_ptr<Byte>&& buffer, int,
            std::optional<ppp::tap::TxGsoMetadata>) noexcept {
            if (accept) {
                retained = std::move(buffer);
            }
            return accept;
        });

    xtcp::buf::BufRef owned = xtcp::buf::BufRef::Acquire(64);
    CHECK(!owned.IsEmpty());
    owned.Data()[0] = 0x5a;
    owned.SetLen(1);
    // Keep a stack-side clone to verify async output retains the same pool
    // block, and that the final consumer release returns its reference.
    xtcp::buf::BufRef stack_ref = owned.Clone();
    xtcp::ndi::Packet packet;
    packet.data = owned.Data();
    packet.len = owned.Len();
    packet.eth_type = 0x0800;
    packet.owned = std::move(owned);

    CHECK(!backend.Tx(std::move(packet)));
    CHECK(!packet.owned.IsEmpty());
    CHECK(packet.owned.Data()[0] == 0x5a);
    CHECK(!retained);
    CHECK(stack_ref.UseCount() == 2);
    auto stats = backend.SnapshotTxStats();
    CHECK(stats.attempts == 1);
    CHECK(stats.accepted == 0);
    CHECK(stats.rejected == 1);
    CHECK(stats.tx_calls == 1);
    CHECK(stats.tx_bytes == 1);

    accept = true;
    CHECK(backend.Tx(std::move(packet)));
    CHECK(packet.owned.IsEmpty());
    CHECK(retained.get() == stack_ref.Data());
    CHECK(stack_ref.UseCount() == 2);
    stats = backend.SnapshotTxStats();
    CHECK(stats.attempts == 2);
    CHECK(stats.accepted == 1);
    CHECK(stats.rejected == 1);
    CHECK(stats.tx_calls == 2);
    CHECK(stats.tx_bytes == 2);

    backend.Stop();
    CHECK(retained && retained.get()[0] == 0x5a);
    retained.reset();
    CHECK(stack_ref.UseCount() == 1);
    xtcp::buf::BufRef stopped_owned = xtcp::buf::BufRef::Acquire(64);
    CHECK(!stopped_owned.IsEmpty());
    stopped_owned.Data()[0] = 0xa5;
    stopped_owned.SetLen(1);
    xtcp::ndi::Packet stopped_packet;
    stopped_packet.data = stopped_owned.Data();
    stopped_packet.len = stopped_owned.Len();
    stopped_packet.eth_type = 0x0800;
    stopped_packet.owned = std::move(stopped_owned);
    CHECK(!backend.Tx(std::move(stopped_packet)));
    CHECK(!stopped_packet.owned.IsEmpty());
    CHECK(stopped_packet.owned.Data()[0] == 0xa5);
    stats = backend.SnapshotTxStats();
    CHECK(stats.attempts == 3);
    CHECK(stats.accepted == 1);
    CHECK(stats.rejected == 2);
    CHECK(stats.tx_calls == 2);
    CHECK(stats.tx_bytes == 2);

    ppp::app::client::xtcp::XtcpOutputRejectionDiagnostics diagnostics(true);
    diagnostics.Record(false, false, false, false);
    diagnostics.Record(true, true, true, false);
    diagnostics.Record(true, false, false, false);
    diagnostics.Record(true, false, true, false);
    diagnostics.Record(true, false, true, true);
    const auto output_snapshot = diagnostics.Snapshot();
    CHECK(output_snapshot.weak_owner_expired == 1);
    CHECK(output_snapshot.vethernet_disposed == 1);
    CHECK(output_snapshot.tap_missing == 1);
    CHECK(output_snapshot.output_rejected == 1);
    CHECK(output_snapshot.accepted == 1);
    CHECK(output_snapshot.first_actual_output_rejected_monotonic_ns != 0);
    const std::uint64_t first_rejected_ns =
        output_snapshot.first_actual_output_rejected_monotonic_ns;
    diagnostics.Record(true, false, true, false);
    const auto repeated_output_snapshot = diagnostics.Snapshot();
    CHECK(repeated_output_snapshot.output_rejected == 2);
    CHECK(repeated_output_snapshot.first_actual_output_rejected_monotonic_ns == first_rejected_ns);
}

void TestSynchronousBorrowedNdiOutput() {
    bool accept = false;
    const Byte* observed = nullptr;
    ppp::app::client::xtcp::XtcpNdiBackend backend(
        [](std::shared_ptr<Byte>&&, int, std::optional<ppp::tap::TxGsoMetadata>) noexcept {
            return false;
        }, false,
        [&accept, &observed](const Byte* data, int size,
            std::optional<ppp::tap::TxGsoMetadata> gso) noexcept {
            CHECK(size == 1);
            CHECK(!gso);
            observed = data;
            return accept;
        });

    xtcp::buf::BufRef owned = xtcp::buf::BufRef::Acquire(64);
    CHECK(!owned.IsEmpty());
    owned.Data()[0] = 0x6b;
    owned.SetLen(1);
    xtcp::buf::BufRef stack_ref = owned.Clone();
    xtcp::ndi::Packet packet;
    packet.data = owned.Data();
    packet.len = owned.Len();
    packet.owned = std::move(owned);

    CHECK(!backend.Tx(std::move(packet)));
    CHECK(observed == stack_ref.Data());
    CHECK(!packet.owned.IsEmpty());
    CHECK(stack_ref.UseCount() == 2);

    accept = true;
    CHECK(backend.Tx(std::move(packet)));
    CHECK(packet.owned.IsEmpty());
    CHECK(stack_ref.UseCount() == 1);
    CHECK(stack_ref.Data()[0] == 0x6b);
}

void TestNdiDiagnosticsCanBeDisabled() {
    bool accepted = false;
    ppp::app::client::xtcp::XtcpNdiBackend backend(
        [&accepted](std::shared_ptr<Byte>&& buffer, int length,
            std::optional<ppp::tap::TxGsoMetadata>) noexcept {
            accepted = buffer != nullptr && length == 1 && buffer.get()[0] == 0x37;
            return accepted;
        });
    backend.SetDiagnosticsEnabled(false);

    xtcp::buf::BufRef owned = xtcp::buf::BufRef::Acquire(64);
    CHECK(!owned.IsEmpty());
    owned.Data()[0] = 0x37;
    owned.SetLen(1);
    xtcp::ndi::Packet packet;
    packet.data = owned.Data();
    packet.len = owned.Len();
    packet.eth_type = 0x0800;
    packet.owned = std::move(owned);

    CHECK(backend.Tx(std::move(packet)));
    CHECK(accepted);
    const auto stats = backend.SnapshotTxStats();
    CHECK(stats.attempts == 0);
    CHECK(stats.accepted == 0);
    CHECK(stats.rejected == 0);
    CHECK(stats.tx_calls == 0);
    CHECK(stats.tx_bytes == 0);
    CHECK(stats.gso_packets == 0);
    CHECK(stats.gso_bytes == 0);
    CHECK(stats.gso_rejected == 0);
}

void TestProductionNdiTsoMetadata() {
    const char* previous = std::getenv("OPENPPP2_XTCP_NDI_TSO_TX");
    const bool had_previous = previous != nullptr;
    const std::string previous_value = previous ? previous : "";
    unsetenv("OPENPPP2_XTCP_NDI_TSO_TX");

    using Backend = ppp::app::client::xtcp::XtcpNdiBackend;
    Backend gate_off([](std::shared_ptr<Byte>&&, int,
        std::optional<ppp::tap::TxGsoMetadata>) noexcept { return true; }, true);
    CHECK(gate_off.Caps() == xtcp::ndi::kCapNone);

    setenv("OPENPPP2_XTCP_NDI_TSO_TX", "1", 1);
    Backend unsupported([](std::shared_ptr<Byte>&&, int,
        std::optional<ppp::tap::TxGsoMetadata>) noexcept { return true; }, false);
    CHECK(unsupported.Caps() == xtcp::ndi::kCapNone);

    bool accept = false;
    int calls = 0;
    std::optional<ppp::tap::TxGsoMetadata> observed;
    Backend backend([&](std::shared_ptr<Byte>&&, int,
        std::optional<ppp::tap::TxGsoMetadata> gso) noexcept {
        ++calls;
        observed = gso;
        return accept;
    }, true);
    CHECK(backend.Caps() == xtcp::ndi::kCapTsoTx);

    auto make_packet = [](std::uint16_t segments) {
        constexpr UInt32 kPacketSize = 2440;
        xtcp::buf::BufRef owned = xtcp::buf::BufRef::Acquire(kPacketSize);
        CHECK(!owned.IsEmpty());
        std::memset(owned.Data(), 0, kPacketSize);
        owned.Data()[0] = 0x45;
        owned.Data()[2] = static_cast<Byte>(kPacketSize >> 8);
        owned.Data()[3] = static_cast<Byte>(kPacketSize);
        owned.Data()[6] = 0x40;
        owned.Data()[8] = 64;
        owned.Data()[9] = 6;
        owned.Data()[20 + 12] = 0x50;
        owned.Data()[20 + 13] = 0x18;
        owned.SetLen(kPacketSize);
        owned.Meta().gso_size = 1400;
        owned.Meta().mss = 1460;
        owned.Meta().segs = segments;
        xtcp::ndi::Packet packet;
        packet.data = owned.Data();
        packet.len = owned.Len();
        packet.eth_type = 0x0800;
        packet.owned = std::move(owned);
        return packet;
    };

    xtcp::ndi::Packet packet = make_packet(2);
    CHECK(!backend.Tx(std::move(packet)));
    CHECK(!packet.owned.IsEmpty());
    CHECK(packet.owned.Meta().segs == 2);
    CHECK(calls == 1);
    CHECK(observed && observed->GsoSize() == 1400);
    CHECK(observed && observed->HeaderLength() == 40);
    CHECK(observed && observed->Segments() == 2);
    auto stats = backend.SnapshotTxStats();
    CHECK(stats.gso_packets == 0);
    CHECK(stats.gso_rejected == 1);

    accept = true;
    CHECK(backend.Tx(std::move(packet)));
    CHECK(packet.owned.IsEmpty());
    stats = backend.SnapshotTxStats();
    CHECK(stats.gso_packets == 1);
    CHECK(stats.gso_bytes == 2440);
    CHECK(stats.gso_rejected == 1);

    xtcp::ndi::Packet malformed = make_packet(3);
    CHECK(!backend.Tx(std::move(malformed)));
    CHECK(!malformed.owned.IsEmpty());
    CHECK(calls == 2);
    stats = backend.SnapshotTxStats();
    CHECK(stats.gso_packets == 1);
    CHECK(stats.gso_rejected == 2);

    if (had_previous) {
        setenv("OPENPPP2_XTCP_NDI_TSO_TX", previous_value.c_str(), 1);
    }
    else {
        unsetenv("OPENPPP2_XTCP_NDI_TSO_TX");
    }
}

void TestPartialChecksumCapabilityIsExplicitAndRetained() {
    const char* previous = std::getenv("OPENPPP2_XTCP_TUN_CSUM_PARTIAL");
    const bool had_previous = previous != nullptr;
    const std::string previous_value = previous ? previous : "";
    const char* previous_tso = std::getenv("OPENPPP2_XTCP_NDI_TSO_TX");
    const bool had_previous_tso = previous_tso != nullptr;
    const std::string previous_tso_value = previous_tso ? previous_tso : "";
    unsetenv("OPENPPP2_XTCP_NDI_TSO_TX");
    setenv("OPENPPP2_XTCP_TUN_CSUM_PARTIAL", "1", 1);

    bool retained_partial = false;
    using Backend = ppp::app::client::xtcp::XtcpNdiBackend;
    Backend backend([](std::shared_ptr<Byte>&&, int,
        std::optional<ppp::tap::TxGsoMetadata>) noexcept { return true; }, true, {},
        [&retained_partial](const Byte*, int, ppp::tap::RetainedPacketOwner&& owner) noexcept {
            retained_partial = owner.ChecksumPartial();
            return true;
        });
    CHECK(0 != (backend.Caps() & xtcp::ndi::kCapChecksumPartialTx));
    CHECK(0 == (backend.Caps() & xtcp::ndi::kCapTsoTx));

    xtcp::buf::BufRef owned = xtcp::buf::BufRef::Acquire(40);
    CHECK(!owned.IsEmpty());
    std::memset(owned.Data(), 0, 40);
    owned.Meta().checksum_partial = true;
    xtcp::ndi::Packet packet;
    packet.data = owned.Data();
    packet.len = 40;
    packet.eth_type = 0x0800;
    packet.owned = std::move(owned);
    CHECK(backend.Tx(std::move(packet)));
    CHECK(retained_partial);

    if (had_previous) setenv("OPENPPP2_XTCP_TUN_CSUM_PARTIAL", previous_value.c_str(), 1);
    else unsetenv("OPENPPP2_XTCP_TUN_CSUM_PARTIAL");
    if (had_previous_tso) setenv("OPENPPP2_XTCP_NDI_TSO_TX", previous_tso_value.c_str(), 1);
    else unsetenv("OPENPPP2_XTCP_NDI_TSO_TX");
}

struct RejectedPacket final {
    Byte bytes[1512] = {};
};

enum class TcpOptionLayout {
    Timestamps,
    Sack,
    Malformed,
};

RejectedPacket MakeRejectedPacket(TcpOptionLayout layout) {
    RejectedPacket packet;
    packet.bytes[0] = 0x45;
    packet.bytes[2] = 0x05;
    packet.bytes[3] = 0xe8;
    packet.bytes[9] = 6;
    Byte* tcp = packet.bytes + 20;
    tcp[12] = 0x80;
    tcp[13] = 0x18;
    switch (layout) {
    case TcpOptionLayout::Timestamps:
        tcp[20] = 8;
        tcp[21] = 10;
        tcp[30] = 1;
        tcp[31] = 1;
        break;
    case TcpOptionLayout::Sack:
        tcp[20] = 5;
        tcp[21] = 10;
        tcp[30] = 1;
        tcp[31] = 1;
        break;
    case TcpOptionLayout::Malformed:
        tcp[20] = 8;
        tcp[21] = 1;
        break;
    }
    return packet;
}

std::shared_ptr<ppp::app::client::xtcp::XtcpRuntime> MakeRejectingRuntime(
    const std::shared_ptr<boost::asio::io_context>& context,
    const std::shared_ptr<ppp::app::client::xtcp::XtcpOutputRejectionDiagnostics>& diagnostics,
    int* calls, bool* saw_oversize_attempt_before_handler = nullptr) {
    using ppp::app::client::xtcp::XtcpFirstLegHooks;
    using ppp::app::client::xtcp::XtcpRuntime;
    return std::make_shared<XtcpRuntime>(
        context,
        [calls, diagnostics, saw_oversize_attempt_before_handler](std::shared_ptr<Byte>&&, int,
            std::optional<ppp::tap::TxGsoMetadata>) noexcept {
            ++*calls;
            if (saw_oversize_attempt_before_handler != nullptr) {
                *saw_oversize_attempt_before_handler =
                    diagnostics->Snapshot().first_oversize_output_attempt.packet_shape.captured;
            }
            return false;
        },
        []() noexcept { return boost::asio::ip::tcp::endpoint(); },
        [](const boost::asio::ip::tcp::endpoint&, const boost::asio::ip::tcp::endpoint&,
           std::uint16_t, std::uint64_t, std::uint64_t,
           const std::weak_ptr<XtcpFirstLegHooks>&, int) noexcept { return false; },
        [](std::uint16_t, std::uint64_t) noexcept {}, diagnostics);
}

void StopRuntime(const std::shared_ptr<boost::asio::io_context>& context,
    const std::shared_ptr<ppp::app::client::xtcp::XtcpRuntime>& runtime) {
    runtime->Stop();
    context->run_for(std::chrono::milliseconds(10));
}

void TestRuntimeOutputRejectionPacketShapes() {
    const RejectedPacket timestamps = MakeRejectedPacket(TcpOptionLayout::Timestamps);
    const RejectedPacket sack = MakeRejectedPacket(TcpOptionLayout::Sack);
    const RejectedPacket malformed = MakeRejectedPacket(TcpOptionLayout::Malformed);

    {
        auto context = std::make_shared<boost::asio::io_context>();
        auto diagnostics = std::make_shared<ppp::app::client::xtcp::XtcpOutputRejectionDiagnostics>(false);
        int calls = 0;
        const auto runtime = MakeRejectingRuntime(context, diagnostics, &calls);
        CHECK(runtime->Start());
        CHECK(!runtime->EmitOutputForTesting(MakeTestBuffer(timestamps.bytes, sizeof(timestamps.bytes)), sizeof(timestamps.bytes)));
        CHECK(calls == 1);
        const auto snapshot = diagnostics->Snapshot();
        CHECK(!snapshot.packet_shape.captured);
        CHECK(!snapshot.first_oversize_output_attempt.packet_shape.captured);
        CHECK(snapshot.first_oversize_output_attempt.first_monotonic_ns == 0);
        CHECK(runtime->SnapshotStats().output_packets == 0);
        CHECK(runtime->SnapshotStats().output_bytes == 0);
        StopRuntime(context, runtime);
    }

    {
        auto context = std::make_shared<boost::asio::io_context>();
        auto diagnostics = std::make_shared<ppp::app::client::xtcp::XtcpOutputRejectionDiagnostics>(true);
        int calls = 0;
        bool saw_oversize_attempt_before_handler = false;
        const auto runtime = MakeRejectingRuntime(
            context, diagnostics, &calls, &saw_oversize_attempt_before_handler);
        CHECK(runtime->Start());
        CHECK(!runtime->EmitOutputForTesting(MakeTestBuffer(timestamps.bytes, sizeof(timestamps.bytes)), sizeof(timestamps.bytes)));
        CHECK(calls == 1);
        CHECK(saw_oversize_attempt_before_handler);
        const auto snapshot = diagnostics->Snapshot();
        const auto shape = snapshot.packet_shape;
        const auto oversize_shape = snapshot.first_oversize_output_attempt.packet_shape;
        CHECK(shape.captured);
        CHECK(shape.parsed);
        CHECK(shape.supplied_bytes == sizeof(timestamps.bytes));
        CHECK(shape.ipv4_total_length == 1512);
        CHECK(shape.ipv4_ihl == 20);
        CHECK(shape.tcp_data_offset == 32);
        CHECK(shape.tcp_payload_length == 1460);
        CHECK(shape.tcp_flags == 0x18);
        CHECK(shape.tcp_option_timestamps);
        CHECK(!shape.tcp_option_sack);
        CHECK(!shape.tcp_option_md5);
        CHECK(!shape.tcp_option_unknown);
        CHECK(snapshot.first_oversize_output_attempt.first_monotonic_ns != 0);
        CHECK(oversize_shape.captured);
        CHECK(oversize_shape.parsed);
        CHECK(oversize_shape.supplied_bytes == sizeof(timestamps.bytes));
        CHECK(oversize_shape.ipv4_total_length == 1512);
        CHECK(oversize_shape.ipv4_ihl == 20);
        CHECK(oversize_shape.tcp_data_offset == 32);
        CHECK(oversize_shape.tcp_payload_length == 1460);
        CHECK(oversize_shape.tcp_flags == 0x18);
        CHECK(oversize_shape.tcp_option_timestamps);
        CHECK(!oversize_shape.tcp_option_sack);
        CHECK(!oversize_shape.tcp_option_md5);
        CHECK(!oversize_shape.tcp_option_unknown);
        CHECK(runtime->SnapshotStats().output_packets == 0);
        CHECK(runtime->SnapshotStats().output_bytes == 0);
        StopRuntime(context, runtime);
    }

    {
        auto context = std::make_shared<boost::asio::io_context>();
        auto diagnostics = std::make_shared<ppp::app::client::xtcp::XtcpOutputRejectionDiagnostics>(true);
        int calls = 0;
        const auto runtime = MakeRejectingRuntime(context, diagnostics, &calls);
        CHECK(runtime->Start());
        CHECK(!runtime->EmitOutputForTesting(MakeTestBuffer(sack.bytes, sizeof(sack.bytes)), sizeof(sack.bytes)));
        CHECK(calls == 1);
        const auto shape = diagnostics->Snapshot().packet_shape;
        CHECK(shape.captured);
        CHECK(shape.parsed);
        CHECK(shape.supplied_bytes == sizeof(sack.bytes));
        CHECK(shape.tcp_option_sack);
        CHECK(!shape.tcp_option_timestamps);
        CHECK(!shape.tcp_option_md5);
        CHECK(!shape.tcp_option_unknown);
        StopRuntime(context, runtime);
    }

    {
        auto context = std::make_shared<boost::asio::io_context>();
        auto diagnostics = std::make_shared<ppp::app::client::xtcp::XtcpOutputRejectionDiagnostics>(true);
        int calls = 0;
        const auto runtime = MakeRejectingRuntime(context, diagnostics, &calls);
        CHECK(runtime->Start());
        CHECK(!runtime->EmitOutputForTesting(MakeTestBuffer(malformed.bytes, sizeof(malformed.bytes)), sizeof(malformed.bytes)));
        CHECK(calls == 1);
        const auto shape = diagnostics->Snapshot().packet_shape;
        CHECK(shape.captured);
        CHECK(!shape.parsed);
        CHECK(shape.supplied_bytes == sizeof(malformed.bytes));
        CHECK(shape.ipv4_total_length == 0);
        CHECK(shape.tcp_data_offset == 0);
        CHECK(!shape.tcp_option_timestamps);
        CHECK(!shape.tcp_option_sack);
        CHECK(!shape.tcp_option_md5);
        CHECK(!shape.tcp_option_unknown);
        StopRuntime(context, runtime);
    }
}

void TestRuntimeRejectsNullContext() {
    using Runtime = ppp::app::client::xtcp::XtcpRuntime;
    auto runtime = std::make_shared<Runtime>(
        std::shared_ptr<boost::asio::io_context>(),
        Runtime::OutputHandler(), Runtime::ListenerEndpointHandler(),
        Runtime::ExternalAcceptHandler(), Runtime::ExternalCancelHandler());
    CHECK(!runtime->Start());
    runtime->Stop();
    CHECK(!runtime->IsRunning());
}

void TestRuntimeRepeatedStartStop() {
    auto context = std::make_shared<boost::asio::io_context>();
    auto runtime = std::make_shared<ppp::app::client::xtcp::XtcpRuntime>(
        context,
        [](std::shared_ptr<Byte>&&, int,
            std::optional<ppp::tap::TxGsoMetadata>) noexcept { return true; },
        []() noexcept { return boost::asio::ip::tcp::endpoint(); },
        [](const boost::asio::ip::tcp::endpoint&,
           const boost::asio::ip::tcp::endpoint&,
           std::uint16_t, std::uint64_t, std::uint64_t,
           const std::weak_ptr<ppp::app::client::xtcp::XtcpFirstLegHooks>&, int) noexcept {
            return false;
        },
        [](std::uint16_t, std::uint64_t) noexcept {});

    CHECK(runtime->Start());
    const auto first_snapshot = runtime->SnapshotStats();
    const std::uint64_t first = runtime->Generation();
    CHECK(first_snapshot.runtime_instance_id != 0);
    runtime->MarkReady();
    CHECK(runtime->IsReady());
    runtime->Stop();
    CHECK(!runtime->IsRunning());
    context->run_for(std::chrono::milliseconds(10));

    context->restart();
    CHECK(runtime->Start());
    const auto second_snapshot = runtime->SnapshotStats();
    CHECK(runtime->Generation() != first);
    CHECK(second_snapshot.runtime_instance_id != 0);
    CHECK(second_snapshot.runtime_instance_id != first_snapshot.runtime_instance_id);
    runtime->MarkReady();
    CHECK(runtime->IsReady());
    runtime->Stop();
    context->run_for(std::chrono::milliseconds(10));
}

void TestPrivateRuntimeLifecycle() {
    const char* old_shards = std::getenv("OPENPPP2_XTCP_SHARDS");
    const char* old_private = std::getenv("OPENPPP2_XTCP_PRIVATE_IO");
    const bool had_shards = old_shards != nullptr;
    const bool had_private = old_private != nullptr;
    const std::string saved_shards = old_shards ? old_shards : "";
    const std::string saved_private = old_private ? old_private : "";
    setenv("OPENPPP2_XTCP_SHARDS", "1", 1);

    for (bool private_io : {false, true}) {
        setenv("OPENPPP2_XTCP_PRIVATE_IO", private_io ? "1" : "0", 1);
        auto context = std::make_shared<boost::asio::io_context>();
        using Runtime = ppp::app::client::xtcp::XtcpRuntime;
        auto runtime = std::make_shared<Runtime>(context,
            Runtime::OutputHandler(), Runtime::ListenerEndpointHandler(),
            Runtime::ExternalAcceptHandler(), Runtime::ExternalCancelHandler());
        CHECK(runtime->Start());
        runtime->MarkReady();
        const auto generation = runtime->Generation();
        runtime->Stop();

        bool restarted = false;
        if (private_io) {
            // The supplied context is deliberately never run: shutdown and
            // restart must progress entirely on the runtime's private worker.
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            while (!(restarted = runtime->Start()) && std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            CHECK(restarted);
        }
        else {
            CHECK(!runtime->Start());
        }
        if (!restarted) {
            context->run_for(std::chrono::milliseconds(10));
            context->restart();
            CHECK(runtime->Start());
        }
        CHECK(runtime->Generation() != generation);
        runtime->MarkReady();
        CHECK(runtime->IsReady());
        runtime->Stop();
        const std::weak_ptr<Runtime> weak = runtime;
        runtime.reset();
        context->restart();
        context->run_for(std::chrono::milliseconds(10));
        CHECK(weak.expired());
    }

    if (had_shards) setenv("OPENPPP2_XTCP_SHARDS", saved_shards.c_str(), 1);
    else unsetenv("OPENPPP2_XTCP_SHARDS");
    if (had_private) setenv("OPENPPP2_XTCP_PRIVATE_IO", saved_private.c_str(), 1);
    else unsetenv("OPENPPP2_XTCP_PRIVATE_IO");
}

void TestSpscIngressLifecycle() {
    const char* previous = std::getenv("OPENPPP2_XTCP_SPSC_INGRESS");
    const std::string saved = previous ? previous : "";
    const char* shards = std::getenv("OPENPPP2_XTCP_SHARDS");
    const std::string saved_shards = shards ? shards : "";
    setenv("OPENPPP2_XTCP_SPSC_INGRESS", "1", 1);
    setenv("OPENPPP2_XTCP_SHARDS", "1", 1);
    auto context = std::make_shared<boost::asio::io_context>();
    using Runtime = ppp::app::client::xtcp::XtcpRuntime;
    auto runtime = std::make_shared<Runtime>(context, Runtime::OutputHandler{},
        Runtime::ListenerEndpointHandler{}, Runtime::ExternalAcceptHandler{}, Runtime::ExternalCancelHandler{});
    CHECK(runtime->Start());
    runtime->MarkReady();
    CHECK(runtime->SnapshotStats().spsc_ingress);
    // Invalid L3 packets are deliberately routed to shard zero and discarded by
    // production validation. They exercise handoff without creating any socket.
    const unsigned char packet[40] = {};
    std::vector<unsigned char> gro(3000, 0);
    gro[0] = 0x45; gro[2] = 0x0b; gro[3] = 0xb8; gro[9] = 6;
    gro[20] = 0x12; gro[21] = 0x34; gro[22] = 0x56; gro[23] = 0x78;
    gro[32] = 0x50; gro[33] = 0x10; // ACK only: no new second-leg connection
    // Three MSS chunks cannot fit into the last two slots. All credits and
    // packets remain with the caller until the whole batch can be admitted.
    for (unsigned i = 0; i < 1022; ++i) CHECK(runtime->SubmitIPv4Tcp(packet, sizeof(packet)));
    CHECK(!runtime->SubmitIPv4Tcp(gro.data(), static_cast<int>(gro.size())));
    CHECK(runtime->SnapshotStats().shards[0].queue_items == 1022);
    CHECK(runtime->SnapshotStats().ingress_dropped == 1);
    context->run_for(std::chrono::milliseconds(20));
    CHECK(runtime->SubmitIPv4Tcp(gro.data(), static_cast<int>(gro.size())));
    CHECK(runtime->SnapshotStats().shards[0].queue_items == 3);
    context->run_for(std::chrono::milliseconds(20));
    auto before = runtime->SnapshotStats();
    std::atomic<unsigned> accepted{0};
    auto producer = [&] {
        for (unsigned i = 0; i < 700; ++i)
            if (runtime->SubmitIPv4Tcp(packet, sizeof(packet))) ++accepted;
    };
    std::thread first(producer), second(producer);
    first.join(); second.join();
    CHECK(accepted == 1024);
    auto snapshot = runtime->SnapshotStats();
    CHECK(snapshot.shards[0].queue_items == 1024);
    CHECK(snapshot.shards[0].items_highwater == 1024);
    CHECK(snapshot.shards[0].bytes_highwater == 1024 * sizeof(packet));
    CHECK(snapshot.shards[0].wake_posts == before.shards[0].wake_posts + 1);
    context->run_for(std::chrono::milliseconds(20));
    snapshot = runtime->SnapshotStats();
    CHECK(snapshot.shards[0].dispatched == before.shards[0].dispatched + accepted);
    CHECK(snapshot.shards[0].queue_items == 0 && snapshot.shards[0].queue_bytes == 0);
    CHECK(snapshot.shards[0].quanta >= 16);
    // Stop with accepted work still queued, then restart while old captures are
    // retained by the context. Old callbacks must not claim the new endpoint.
    CHECK(runtime->SubmitIPv4Tcp(packet, sizeof(packet)));
    runtime->Stop();
    context->run_for(std::chrono::milliseconds(10));
    context->restart();
    CHECK(runtime->Start());
    runtime->MarkReady();
    CHECK(runtime->SubmitIPv4Tcp(packet, sizeof(packet)));
    context->run_for(std::chrono::milliseconds(10));
    snapshot = runtime->SnapshotStats();
    CHECK(snapshot.shards[0].queue_items == 0);
    runtime->Stop();
    context->run_for(std::chrono::milliseconds(10));
    if (saved.empty()) unsetenv("OPENPPP2_XTCP_SPSC_INGRESS");
    else setenv("OPENPPP2_XTCP_SPSC_INGRESS", saved.c_str(), 1);
    if (saved_shards.empty()) unsetenv("OPENPPP2_XTCP_SHARDS");
    else setenv("OPENPPP2_XTCP_SHARDS", saved_shards.c_str(), 1);
}
} // namespace

int main() {
    xtcp::buf::InitPools();
    TestConsumePolicy();
    TestIngressCapsStopAndGeneration();
    TestFlowCallbackIdentity();
    TestGsoSplitFlagPlacement();
    TestExternalLoopbackGate();
    TestIPv4PolicyHelpers();
    TestProductionNdiOwnership();
    TestSynchronousBorrowedNdiOutput();
    TestNdiDiagnosticsCanBeDisabled();
    TestProductionNdiTsoMetadata();
    TestPartialChecksumCapabilityIsExplicitAndRetained();
    TestRuntimeOutputRejectionPacketShapes();
    xtcp::buf::ShutdownPools();
    TestRuntimeRejectsNullContext();
    TestRuntimeRepeatedStartStop();
    TestPrivateRuntimeLifecycle();
    TestSpscIngressLifecycle();

    if (failures != 0) {
        std::fprintf(stderr, "xtcp_runtime_adapter_test: %d failure(s)\n", failures);
        return 1;
    }
    std::puts("xtcp_runtime_adapter_test: passed");
    return 0;
}
