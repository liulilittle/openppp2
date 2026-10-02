#include <ppp/app/client/xtcp/XtcpNdiBackend.h>

#if defined(PPP_ENABLE_XTCP)
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <vector>

namespace ppp::app::client::xtcp {
namespace {
void HistAdd(std::atomic<std::uint64_t>* hist, std::uint64_t us) noexcept {
    std::size_t bucket = 0;
    std::uint64_t value = us;
    while (value > 1 && bucket + 1 < 32) {
        value >>= 1;
        ++bucket;
    }
    hist[bucket].fetch_add(1, std::memory_order_relaxed);
}
} // namespace

XtcpNdiBackend::XtcpNdiBackend(OutputHandler output, bool tx_gso_supported,
    BorrowedOutputHandler borrowed_output, RetainedOutputHandler retained_output) noexcept {
    try {
        if (output) {
            output_ = std::make_shared<OutputHandler>(std::move(output));
        }
        if (borrowed_output) {
            borrowed_output_ = std::make_shared<BorrowedOutputHandler>(std::move(borrowed_output));
        }
        if (retained_output) {
            retained_output_ = std::make_shared<RetainedOutputHandler>(std::move(retained_output));
        }
    }
    catch (...) {
        // Keep the owning path available if the optional borrowed callback
        // cannot be allocated. A missing owning callback makes Tx reject.
    }
    const char* gate = std::getenv("OPENPPP2_XTCP_NDI_TSO_TX");
    tx_gso_enabled_ = tx_gso_supported && gate != nullptr && gate[0] == '1' && gate[1] == '\0';
    const char* checksum_gate = std::getenv("OPENPPP2_XTCP_TUN_CSUM_PARTIAL");
    tx_checksum_partial_enabled_ = tx_gso_supported && !tx_gso_enabled_ && retained_output_ != nullptr &&
        checksum_gate != nullptr && checksum_gate[0] == '1' && checksum_gate[1] == '\0';
}

bool XtcpNdiBackend::Tx(::xtcp::ndi::Packet&& packet) noexcept {
    const bool observe = diagnostics_enabled_.load(std::memory_order_relaxed);
    if (observe) {
        attempts_.fetch_add(1, std::memory_order_relaxed);
    }
    // Output handlers are immutable after construction. Keep them alive until
    // backend destruction so the hot Tx path can read them without taking the
    // RX-handler mutex or incrementing shared_ptr reference counts per packet.
    if (tx_stopped_.load(std::memory_order_acquire) || !output_) {
        if (observe) {
            rejected_.fetch_add(1, std::memory_order_relaxed);
        }
        return false;
    }
    const OutputHandler& output = *output_;
    const BorrowedOutputHandler* borrowed_output = borrowed_output_.get();
    const RetainedOutputHandler* retained_output = retained_output_.get();
    // A2-0 diagnostics: per-packet Output() wall time plus the interval since
    // the previous Tx entry (the NDI callback cadence).
    const std::uint64_t start_us = observe
        ? std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()
        : 0;
    bool emitted = false;
    std::optional<ppp::tap::TxGsoMetadata> gso;
    bool gso_marked = false;
    if (!packet.owned.IsEmpty()) {
        const ::xtcp::buf::SegMeta meta = packet.owned.Meta();
        gso_marked = meta.gso_size != 0 || meta.mss != 0 || meta.segs != 0;
        if (gso_marked) {
            if (!tx_gso_enabled_ || meta.gso_size == 0 || meta.mss == 0 ||
                meta.gso_size > meta.mss || packet.len > ::xtcp::buf::kMaxPoolPayload) {
                gso_rejected_.fetch_add(1, std::memory_order_relaxed);
                if (observe) {
                    rejected_.fetch_add(1, std::memory_order_relaxed);
                }
                return false;
            }
            gso = ppp::tap::TxGsoMetadata::ParseTcpV4(
                packet.data, packet.len, meta.gso_size, meta.segs);
            if (!gso) {
                gso_rejected_.fetch_add(1, std::memory_order_relaxed);
                if (observe) {
                    rejected_.fetch_add(1, std::memory_order_relaxed);
                }
                return false;
            }
        }
    }
    if (packet.data != nullptr && packet.len != 0) {
        if (!packet.owned.IsEmpty()) {
            if (packet.owned.Meta().checksum_partial &&
                (!tx_checksum_partial_enabled_ || retained_output == nullptr)) {
                if (observe) rejected_.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
            if (retained_output != nullptr && !gso) {
                // Clone is an atomic refcount increment only. The retained
                // output may defer the buffer, while rejection leaves the
                // original packet ownership untouched.
                ppp::tap::RetainedPacketOwner retained(packet.owned.Clone(),
                    packet.owned.Meta().checksum_partial);
                emitted = (*retained_output)(packet.data, static_cast<int>(packet.len),
                    std::move(retained));
                if (emitted) {
                    packet.owned = ::xtcp::buf::BufRef{};
                }
            }
            else if (borrowed_output != nullptr && !gso) {
                // The borrowed path is strictly synchronous. In particular,
                // it must not enqueue or retain this pointer after returning.
                emitted = (*borrowed_output)(packet.data, static_cast<int>(packet.len), std::nullopt);
                if (emitted) {
                    packet.owned = ::xtcp::buf::BufRef{};
                }
            }
            else {
                // XTCP-STRAND-DISPATCH-001 (data-plane tier): hand the stack's
                // BufRef to the consumer through an owning shared_ptr; the buffer
                // returns to the pool when the TAP write completes. One shared
                // holder allocation, no payload copy or second control block.
                // Ownership is RESTORED to packet.owned when the consumer
                // rejects: a rejected Tx must leave the packet as it arrived.
                struct BufRefHolder final {
                    ::xtcp::buf::BufRef ref;
                };
                const std::shared_ptr<BufRefHolder> holder =
                    std::make_shared<BufRefHolder>();
                holder->ref = std::move(packet.owned);
                std::shared_ptr<Byte> buffer(holder, holder->ref.Data());
                emitted = output(std::move(buffer), static_cast<int>(packet.len), gso);
                if (!emitted) {
                    packet.owned = std::move(holder->ref);
                }
            }
        }
        else {
            // Defensive: a Tx packet without a backing BufRef cannot be handed
            // off zero-copy; copy once so the consumer still owns the bytes.
            const std::shared_ptr<std::vector<Byte>> holder =
                std::make_shared<std::vector<Byte>>(packet.data, packet.data + packet.len);
            std::shared_ptr<Byte> buffer(holder, holder->data());
            emitted = output(std::move(buffer), static_cast<int>(packet.len), gso);
        }
    }
    if (observe) {
        const std::uint64_t end_us = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        tx_calls_.fetch_add(1, std::memory_order_relaxed);
        if (packet.data != nullptr) {
            tx_bytes_.fetch_add(packet.len, std::memory_order_relaxed);
        }
        HistAdd(output_us_, end_us > start_us ? end_us - start_us : 0);
        if (last_tx_start_us_ != 0) {
            HistAdd(interval_us_, start_us > last_tx_start_us_ ? start_us - last_tx_start_us_ : 0);
        }
        last_tx_start_us_ = start_us;
    }
    if (!emitted) {
        if (gso_marked) {
            gso_rejected_.fetch_add(1, std::memory_order_relaxed);
        }
        if (observe) {
            rejected_.fetch_add(1, std::memory_order_relaxed);
        }
        return false;
    }
    if (observe) {
        accepted_.fetch_add(1, std::memory_order_relaxed);
    }
    if (gso_marked) {
        gso_packets_.fetch_add(1, std::memory_order_relaxed);
        gso_bytes_.fetch_add(packet.len, std::memory_order_relaxed);
    }
    return true;
}

UInt32 XtcpNdiBackend::TxBatch(::xtcp::ndi::Packet* packets, UInt32 count) noexcept {
    if (packets == nullptr) {
        return 0;
    }
    if (diagnostics_enabled_.load(std::memory_order_relaxed)) {
        batch_calls_.fetch_add(1, std::memory_order_relaxed);
        batch_packets_.fetch_add(count, std::memory_order_relaxed);
        std::uint32_t prev_max = batch_max_.load(std::memory_order_relaxed);
        while (count > prev_max &&
               !batch_max_.compare_exchange_weak(prev_max, count, std::memory_order_relaxed)) {
        }
    }
    UInt32 accepted = 0;
    for (; accepted < count; ++accepted) {
        if (!Tx(std::move(packets[accepted]))) {
            break;
        }
    }
    return accepted;
}

void XtcpNdiBackend::SetDiagnosticsEnabled(bool enabled) noexcept {
    diagnostics_enabled_.store(enabled, std::memory_order_relaxed);
}

void XtcpNdiBackend::SetRxHandler(::xtcp::ndi::RxHandler handler) noexcept {
    std::lock_guard<std::mutex> lock(sync_);
    if (!stopped_) {
        rx_handler_ = std::move(handler);
    }
}

::xtcp::ndi::BackendCaps XtcpNdiBackend::Caps() const noexcept {
    ::xtcp::ndi::BackendCaps caps = ::xtcp::ndi::kCapNone;
    if (tx_gso_enabled_) caps = static_cast<::xtcp::ndi::BackendCaps>(caps | ::xtcp::ndi::kCapTsoTx);
    if (tx_checksum_partial_enabled_) {
        caps = static_cast<::xtcp::ndi::BackendCaps>(caps | ::xtcp::ndi::kCapChecksumPartialTx);
    }
    return caps;
}

bool XtcpNdiBackend::Inject(::xtcp::buf::BufRef&& packet) noexcept {
    ::xtcp::ndi::RxHandler handler;
    {
        std::lock_guard<std::mutex> lock(sync_);
        if (stopped_ || !rx_handler_ || packet.IsEmpty()) {
            return false;
        }
        handler = rx_handler_;
    }
    ::xtcp::ndi::Packet input;
    input.data = packet.Data();
    input.len = packet.Len();
    input.eth_type = 0x0800;
    input.owned = std::move(packet);
    handler(std::move(input));
    return true;
}

XtcpNdiBackend::TxStats XtcpNdiBackend::SnapshotTxStats() const noexcept {
    TxStats stats;
    stats.tx_calls = tx_calls_.load(std::memory_order_relaxed);
    stats.tx_bytes = tx_bytes_.load(std::memory_order_relaxed);
    stats.attempts = attempts_.load(std::memory_order_relaxed);
    stats.accepted = accepted_.load(std::memory_order_relaxed);
    stats.rejected = rejected_.load(std::memory_order_relaxed);
    stats.gso_packets = gso_packets_.load(std::memory_order_relaxed);
    stats.gso_bytes = gso_bytes_.load(std::memory_order_relaxed);
    stats.gso_rejected = gso_rejected_.load(std::memory_order_relaxed);
    stats.batch_calls = batch_calls_.load(std::memory_order_relaxed);
    stats.batch_packets = batch_packets_.load(std::memory_order_relaxed);
    stats.batch_max = batch_max_.load(std::memory_order_relaxed);
    for (std::size_t i = 0; i < 32; ++i) {
        stats.output_us[i] = output_us_[i].load(std::memory_order_relaxed);
        stats.interval_us[i] = interval_us_[i].load(std::memory_order_relaxed);
    }
    return stats;
}

void XtcpNdiBackend::Stop() noexcept {
    std::lock_guard<std::mutex> lock(sync_);
    stopped_ = true;
    tx_stopped_.store(true, std::memory_order_release);
    rx_handler_ = nullptr;
    // Do not clear output_ here: Tx may have observed tx_stopped_ as false just
    // before Stop() and is allowed to finish that already-started callback.
    // The immutable handler is released with the backend itself.
}

} // namespace ppp::app::client::xtcp
#endif
