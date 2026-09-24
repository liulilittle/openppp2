#pragma once

#include <functional>
#include <optional>
#include <ppp/tap/TxGsoMetadata.h>
#include <memory>
#include <mutex>

#if defined(PPP_ENABLE_XTCP)
#include <array>
#include <atomic>
#include <cstdint>
#include <xtcp/ndi.h>
#endif

namespace ppp::app::client::xtcp {

#if defined(PPP_ENABLE_XTCP)
class XtcpNdiBackend final : public ::xtcp::ndi::Backend {
public:
    // XTCP-STRAND-DISPATCH-001 (data-plane tier): the handler receives an
    // owning shared_ptr<Byte> (a stack BufRef wrapped by a deleter) so the
    // TAP write queue can hold the buffer zero-copy instead of copying.
    // Byte == unsigned char == std::uint8_t.
    using OutputHandler = std::function<bool(std::shared_ptr<std::uint8_t>&&, int,
        std::optional<ppp::tap::TxGsoMetadata>)>;

    explicit XtcpNdiBackend(OutputHandler output, bool tx_gso_supported = false) noexcept;

    bool Tx(::xtcp::ndi::Packet&& packet) noexcept override;
    UInt32 TxBatch(::xtcp::ndi::Packet* packets, UInt32 count) noexcept override;
    void SetRxHandler(::xtcp::ndi::RxHandler handler) noexcept override;
    ::xtcp::ndi::BackendCaps Caps() const noexcept override;

    bool Inject(::xtcp::buf::BufRef&& packet) noexcept;
    void Stop() noexcept;

    /** @brief Snapshot of the A2-0 output-path diagnostics (cumulative). */
    struct TxStats final {
        std::uint64_t tx_calls = 0;
        std::uint64_t tx_bytes = 0;
        std::uint64_t attempts = 0;
        std::uint64_t accepted = 0;
        std::uint64_t rejected = 0;
        std::uint64_t gso_packets = 0;
        std::uint64_t gso_bytes = 0;
        std::uint64_t gso_rejected = 0;
        std::uint64_t batch_calls = 0;
        std::uint64_t batch_packets = 0;
        std::uint32_t batch_max = 0;
        // log2(us) histograms: bucket b counts samples in [2^b, 2^(b+1)).
        std::uint64_t output_us[32] = {};
        std::uint64_t interval_us[32] = {};
    };
    TxStats SnapshotTxStats() const noexcept;

private:
    mutable std::mutex sync_;
    OutputHandler output_;
    ::xtcp::ndi::RxHandler rx_handler_;
    bool stopped_ = false;
    bool tx_gso_enabled_ = false;
    // A2-0 output-path diagnostics. Written on the stack owner thread only;
    // read via SnapshotTxStats().
    std::atomic<std::uint64_t> tx_calls_{0};
    std::atomic<std::uint64_t> tx_bytes_{0};
    std::atomic<std::uint64_t> attempts_{0};
    std::atomic<std::uint64_t> accepted_{0};
    std::atomic<std::uint64_t> rejected_{0};
    std::atomic<std::uint64_t> gso_packets_{0};
    std::atomic<std::uint64_t> gso_bytes_{0};
    std::atomic<std::uint64_t> gso_rejected_{0};
    std::atomic<std::uint64_t> batch_calls_{0};
    std::atomic<std::uint64_t> batch_packets_{0};
    std::atomic<std::uint32_t> batch_max_{0};
    std::atomic<std::uint64_t> output_us_[32]{};
    std::atomic<std::uint64_t> interval_us_[32]{};
    std::uint64_t last_tx_start_us_ = 0;
};
#endif

} // namespace ppp::app::client::xtcp
