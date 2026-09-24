#pragma once

#include <ppp/app/client/xtcp/XtcpFirstLegHooks.h>
#include <ppp/app/runtime/RuntimeXtcpStats.h>
#include <ppp/tap/TxGsoMetadata.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>

namespace ppp::app::client::xtcp {

struct XtcpOutputRejectionPacketShape final {
    bool captured = false;
    bool parsed = false;
    std::uint32_t supplied_bytes = 0;
    std::uint16_t ipv4_total_length = 0;
    std::uint8_t ipv4_ihl = 0;
    std::uint8_t tcp_data_offset = 0;
    std::uint16_t tcp_payload_length = 0;
    std::uint8_t tcp_flags = 0;
    bool tcp_option_timestamps = false;
    bool tcp_option_sack = false;
    bool tcp_option_md5 = false;
    bool tcp_option_unknown = false;
};

struct XtcpOutputPreCallOversizeAttemptSnapshot final {
    // An XTCP-to-runtime-output-handler pre-call attempt, not a global Tap input event.
    std::uint64_t first_monotonic_ns = 0;
    XtcpOutputRejectionPacketShape packet_shape;
};

struct XtcpOutputRejectionSnapshot final {
    std::uint64_t weak_owner_expired = 0;
    std::uint64_t vethernet_disposed = 0;
    std::uint64_t tap_missing = 0;
    std::uint64_t output_rejected = 0;
    std::uint64_t accepted = 0;
    std::uint64_t first_actual_output_rejected_monotonic_ns = 0;
    XtcpOutputRejectionPacketShape packet_shape;
    XtcpOutputPreCallOversizeAttemptSnapshot first_oversize_output_attempt;
};

class XtcpOutputRejectionDiagnostics final {
public:
    explicit XtcpOutputRejectionDiagnostics(bool enabled) noexcept : enabled_(enabled) {}

    bool Enabled() const noexcept { return enabled_; }
    void Record(bool owner_present, bool vethernet_disposed, bool tap_present, bool accepted) noexcept;
    void RecordRejectedPacketShape(const void* data, int length) noexcept;
    // Records only an XTCP-to-runtime-output-handler pre-call IPv4 attempt
    // whose declared total length exceeds 1500; no packet data is retained.
    void RecordOversizeOutputAttempt(const void* data, int length) noexcept;
    XtcpOutputRejectionSnapshot Snapshot() const noexcept;

private:
    bool enabled_ = false;
    std::atomic<std::uint64_t> weak_owner_expired_{0};
    std::atomic<std::uint64_t> vethernet_disposed_{0};
    std::atomic<std::uint64_t> tap_missing_{0};
    std::atomic<std::uint64_t> output_rejected_{0};
    std::atomic<std::uint64_t> accepted_{0};
    std::atomic<std::uint64_t> first_actual_output_rejected_monotonic_ns_{0};
    mutable std::mutex packet_shape_sync_;
    XtcpOutputRejectionPacketShape first_rejected_packet_shape_;
    XtcpOutputPreCallOversizeAttemptSnapshot first_oversize_output_attempt_;
};

class XtcpRuntime final : public std::enable_shared_from_this<XtcpRuntime> {
public:
    // XTCP-STRAND-DISPATCH-001 (data-plane tier): owning-buffer output so the
    // stack's BufRef reaches the TAP write queue zero-copy.
    using OutputHandler = std::function<bool(std::shared_ptr<std::uint8_t>&&, int,
        std::optional<ppp::tap::TxGsoMetadata>)>;
    using ListenerEndpointHandler = std::function<boost::asio::ip::tcp::endpoint()>;
    // Invoking this handler transfers a non-negative fd to the handler,
    // regardless of whether the handler returns true or false.
    using ExternalAcceptHandler = std::function<bool(
        const boost::asio::ip::tcp::endpoint&,
        const boost::asio::ip::tcp::endpoint&,
        std::uint16_t,
        std::uint64_t,
        std::uint64_t,
        const std::weak_ptr<XtcpFirstLegHooks>&,
        int fd)>;
    using ExternalCancelHandler = std::function<void(std::uint16_t, std::uint64_t)>;

    XtcpRuntime(
        const std::shared_ptr<boost::asio::io_context>& context,
        OutputHandler output,
        ListenerEndpointHandler listener_endpoint,
        ExternalAcceptHandler external_accept,
        ExternalCancelHandler external_cancel,
        std::shared_ptr<XtcpOutputRejectionDiagnostics> output_rejection_diagnostics = nullptr,
        bool tx_gso_supported = false) noexcept;
    ~XtcpRuntime() noexcept;

    bool Start() noexcept;
    void MarkReady() noexcept;
    void Stop() noexcept;
    bool SubmitIPv4Tcp(const void* packet, int packet_length) noexcept;
    bool IsReady() const noexcept;
    bool IsRunning() const noexcept;
    std::uint64_t Generation() const noexcept;
    ppp::app::runtime::RuntimeXtcpStats SnapshotStats() const noexcept;
#if defined(PPP_XTCP_RUNTIME_TESTING)
    bool EmitOutputForTesting(const std::shared_ptr<std::uint8_t>& data, int length,
        std::optional<ppp::tap::TxGsoMetadata> gso = std::nullopt) noexcept;
#endif

private:
    class Impl;
    std::shared_ptr<Impl> impl_;
};

} // namespace ppp::app::client::xtcp
