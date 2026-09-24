#include <ppp/app/client/xtcp/XtcpNdiBackend.h>
#include <ppp/app/client/xtcp/XtcpRuntime.h>
#include <ppp/app/client/xtcp/XtcpRuntimePolicy.h>

#include <xtcp/buf/bufref.h>

#include <boost/asio/io_context.hpp>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {
std::shared_ptr<Byte> MakeTestBuffer(const Byte* bytes, std::size_t length) noexcept {
    const std::shared_ptr<std::vector<Byte>> holder =
        std::make_shared<std::vector<Byte>>(bytes, bytes + length);
    return std::shared_ptr<Byte>(holder, holder->data());
}
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
} // namespace

int main() {
    xtcp::buf::InitPools();
    TestConsumePolicy();
    TestIngressCapsStopAndGeneration();
    TestExternalLoopbackGate();
    TestIPv4PolicyHelpers();
    TestProductionNdiOwnership();
    TestProductionNdiTsoMetadata();
    TestRuntimeOutputRejectionPacketShapes();
    xtcp::buf::ShutdownPools();
    TestRuntimeRejectsNullContext();
    TestRuntimeRepeatedStartStop();

    if (failures != 0) {
        std::fprintf(stderr, "xtcp_runtime_adapter_test: %d failure(s)\n", failures);
        return 1;
    }
    std::puts("xtcp_runtime_adapter_test: passed");
    return 0;
}
