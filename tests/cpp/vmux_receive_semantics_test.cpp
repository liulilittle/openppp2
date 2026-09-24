#include <ppp/stdafx.h>
#include <ppp/app/mux/vmux_net.h>
#include <ppp/app/mux/vmux_skt.h>
#include <ppp/configurations/AppConfiguration.h>

#include <cstring>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace vmux {

struct vmux_net_test_access {
    template <typename Handler>
    static auto RunOnStrand(vmux_net& mux, Handler&& handler) -> decltype(handler()) {
        using Result = decltype(handler());
        if (mux.is_strand_thread()) {
            return handler();
        }
        if (!mux.context_ || !mux.strand_) {
            throw std::runtime_error("mux executor unavailable");
        }

        std::optional<Result> result;
        std::exception_ptr error;
        boost::asio::post(*mux.strand_, [&]() {
            try {
                result.emplace(handler());
            }
            catch (...) {
                error = std::current_exception();
            }
        });
        mux.context_->restart();
        while (!result && !error) {
            if (mux.context_->run_one() == 0) {
                throw std::runtime_error("mux strand handler did not run");
            }
        }
        if (error) {
            std::rethrow_exception(error);
        }
        return std::move(*result);
    }

    template <typename Handler>
    static void RunOnStrandVoid(vmux_net& mux, Handler&& handler) {
        RunOnStrand(mux, [&]() {
            handler();
            return true;
        });
    }
    static void ConfigureFlowV2(
        vmux_net& mux,
        std::size_t reorder_cap_bytes,
        std::uint64_t reorder_timeout_ms,
        std::size_t session_reorder_cap_bytes = 0,
        std::size_t max_open_flows = 0) {
        RunOnStrandVoid(mux, [&]() {
            mux.ordering_mode_ = vmux_net::ordering_flow_v2;
            mux.flow_reorder_cap_bytes_ = reorder_cap_bytes;
            mux.flow_reorder_timeout_ = reorder_timeout_ms;
            mux.session_reorder_cap_bytes_ = session_reorder_cap_bytes;
            mux.session_reorder_bytes_ = 0;
            mux.max_open_flows_ = max_open_flows;
            mux.tx_ctrl_budget_frames_ = 32;
            mux.base_.established_ = true;
            mux.base_.disposed_.store(false, std::memory_order_release);
        });
    }

    static std::size_t SessionReorderBytes(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.session_reorder_bytes_; });
    }

    static std::size_t SktCount(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.skts_.size(); });
    }

    static bool ProcessRxConnecting(
        const std::shared_ptr<vmux_net>& mux,
        std::uint32_t connection_id,
        const char* host) {
        return RunOnStrand(*mux, [&]() {
            std::shared_ptr<vmux_skt> skt;
            return mux->process_rx_connecting(skt, connection_id, host, static_cast<int>(std::strlen(host)));
        });
    }

    static void SetCtrlBudget(vmux_net& mux, std::size_t n) {
        RunOnStrandVoid(mux, [&]() { mux.tx_ctrl_budget_frames_ = n; });
    }

    static std::size_t CtrlQueueSize(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.tx_ctrl_queue_.size(); });
    }

    static void EmplaceCtrlFrame(vmux_net& mux, int n) {
        RunOnStrandVoid(mux, [&]() {
            for (int i = 0; i < n; ++i) {
                auto buf = mux.make_byte_array(static_cast<int>(sizeof(vmux_net::vmux_hdr)));
                if (!buf) throw std::runtime_error("alloc");
                auto* h = reinterpret_cast<vmux_net::vmux_hdr*>(buf.get());
                std::memset(h, 0, sizeof(*h));
                h->cmd = static_cast<std::uint8_t>(vmux_net::cmd_keep_alived);
                mux.tx_ctrl_queue_.emplace_back(vmux_net::tx_packet{ buf, static_cast<int>(sizeof(vmux_net::vmux_hdr)), nullptr });
            }
        });
    }

    static bool ProcessTxAll(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.process_tx_all_packets(); });
    }

    static std::shared_ptr<vmux_skt> InstallQueueOnlySkt(
        const std::shared_ptr<vmux_net>& mux,
        std::uint32_t connection_id) {
        return RunOnStrand(*mux, [&]() {
            auto skt = ppp::make_shared_object<vmux_skt>(mux, connection_id);
            if (!skt) {
                throw std::runtime_error("skt alloc failed");
            }
            skt->status_.connected_ = true;
            skt->status_.disposed_ = false;
            skt->status_.fin_ = false;
            skt->status_.sending_.store(1, std::memory_order_relaxed); // queue-only input path
            mux->skts_[connection_id] = skt;
            return skt;
        });
    }

    static std::size_t QueuedRx(const vmux_skt& skt) noexcept {
        return skt.rx_queue_.size();
    }

    static std::size_t QueuedRxBytes(const vmux_skt& skt) noexcept {
        std::size_t total = 0;
        for (const auto& packet : skt.rx_queue_) {
            if (packet.buffer_size > 0) {
                total += static_cast<std::size_t>(packet.buffer_size);
            }
        }
        return total;
    }

    static bool FlowExists(vmux_net& mux, std::uint32_t connection_id) {
        return RunOnStrand(mux, [&]() { return mux.flows_.find(connection_id) != mux.flows_.end(); });
    }

    static std::size_t FlowBufferedBytes(vmux_net& mux, std::uint32_t connection_id) {
        return RunOnStrand(mux, [&]() {
            auto it = mux.flows_.find(connection_id);
            return it == mux.flows_.end() ? 0 : it->second.flow_reorder_.buffered_bytes();
        });
    }

    static bool InjectPush(
        vmux_net& mux,
        std::uint32_t connection_id,
        std::uint32_t dsn,
        const void* payload,
        int payload_len,
        std::uint64_t now) {
        return RunOnStrand(mux, [&]() {
            const int frame_len = static_cast<int>(sizeof(vmux_net::vmux_hdr)) + payload_len;
            std::vector<std::uint8_t> frame(static_cast<std::size_t>(frame_len));
            auto* h = reinterpret_cast<vmux_net::vmux_hdr*>(frame.data());
            std::memset(h, 0, sizeof(*h));
            h->seq = htonl(dsn);
            h->cmd = static_cast<std::uint8_t>(vmux_net::cmd_push);
            h->connection_id = htonl(connection_id);
            if (payload_len > 0 && payload != nullptr) {
                std::memcpy(h + 1, payload, static_cast<std::size_t>(payload_len));
            }
            return mux.packet_input_flow(vmux_net::vmux_linklayer_ptr{}, h, frame_len, now);
        });
    }

    static void EvictExpired(vmux_net& mux, std::uint64_t now) {
        RunOnStrandVoid(mux, [&]() { mux.flow_evict_expired(now); });
    }

    static void FailFlow(vmux_net& mux, std::uint32_t connection_id, const char* reason) {
        RunOnStrandVoid(mux, [&]() { mux.fail_flow(connection_id, reason); });
    }

    static bool SktDisposed(vmux_net& mux, const vmux_skt& skt) {
        return RunOnStrand(mux, [&]() { return skt.status_.disposed_; });
    }

    static void ConfigureCompat(
        vmux_net& mux,
        std::uint64_t gap_timeout_ms,
        std::size_t session_reorder_cap_bytes = 0) {
        RunOnStrandVoid(mux, [&]() {
            mux.ordering_mode_ = vmux_net::ordering_compat;
            mux.flow_reorder_timeout_ = gap_timeout_ms;
            mux.session_reorder_cap_bytes_ = session_reorder_cap_bytes;
            mux.session_reorder_bytes_ = 0;
            mux.rx_gap_oldest_tick_ = 0;
            mux.base_.established_ = true;
            mux.base_.disposed_.store(false, std::memory_order_release);
            mux.status_.rx_ack_ = 1; // next expected global seq
            mux.status_.last_ = 0;
        });
    }

    static bool InjectCompatFrame(
        vmux_net& mux,
        std::uint32_t seq,
        std::uint32_t connection_id,
        std::uint64_t now) {
        return RunOnStrand(mux, [&]() {
            const int frame_len = static_cast<int>(sizeof(vmux_net::vmux_hdr));
            std::vector<std::uint8_t> frame(static_cast<std::size_t>(frame_len));
            auto* h = reinterpret_cast<vmux_net::vmux_hdr*>(frame.data());
            std::memset(h, 0, sizeof(*h));
            h->seq = htonl(seq);
            h->cmd = static_cast<std::uint8_t>(vmux_net::cmd_keep_alived);
            h->connection_id = htonl(connection_id);
            return mux.packet_input_unorder(vmux_net::vmux_linklayer_ptr{}, h, frame_len, now);
        });
    }

    static std::uint64_t LastActive(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.status_.last_.load(std::memory_order_acquire); });
    }

    static std::size_t FlowMapSize(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.flows_.size(); });
    }

    static std::size_t CompatReorderSize(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.rx_queue_.size(); });
    }

    static void CompatEvict(vmux_net& mux, std::uint64_t now) {
        RunOnStrandVoid(mux, [&]() { mux.compat_evict_expired(now); });
    }

    static bool IsDisposed(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.base_.disposed_.load(std::memory_order_acquire); });
    }

    static bool ConnectRequire(vmux_net& mux) {
        return RunOnStrand(mux, [&]() {
            auto socket = std::make_shared<boost::asio::ip::tcp::socket>(*mux.context_);
            return mux.connect_require(socket, "127.0.0.1", 80);
        });
    }

    static bool SendToPeerBeforeOpen(
        const std::shared_ptr<vmux_skt>& skt,
        const void* packet,
        int packet_length) {
        return RunOnStrand(*skt->mux_, [&]() {
            skt->status_.connected_ = false;
            return skt->send_to_peer(packet, packet_length, nullptr);
        });
    }

    static bool SendToPeerOffStrand(const std::shared_ptr<vmux_skt>& skt, const void* packet, int packet_length) {
        return skt->send_to_peer(packet, packet_length, nullptr);
    }

    static bool PostCommand(vmux_net& mux, bool on_strand) {
        auto invoke = [&]() {
            vmux_net::PostInternalAsynchronousCallback callback;
            return mux.post_internal(vmux_net::cmd_keep_alived, nullptr, 0, 0, false, callback);
        };
        return on_strand ? RunOnStrand(mux, invoke) : invoke();
    }

    static bool PostFrame(vmux_net& mux, bool on_strand) {
        auto frame = mux.make_byte_array(static_cast<int>(sizeof(vmux_net::vmux_hdr)));
        if (!frame) {
            throw std::runtime_error("frame alloc failed");
        }
        std::memset(frame.get(), 0, sizeof(vmux_net::vmux_hdr));
        reinterpret_cast<vmux_net::vmux_hdr*>(frame.get())->cmd = vmux_net::cmd_keep_alived;
        auto invoke = [&]() {
            vmux_net::PostInternalAsynchronousCallback callback;
            return mux.post_internal(frame, static_cast<int>(sizeof(vmux_net::vmux_hdr)), false, callback);
        };
        return on_strand ? RunOnStrand(mux, invoke) : invoke();
    }

    static vmux_net::vmux_linklayer_ptr MakeDeadLink(bool handshake_complete) {
        auto link = std::make_shared<vmux_net::vmux_linklayer>();
        link->handshake_complete_ = handshake_complete;
        return link;
    }

    static void AttachLink(vmux_net& mux, const vmux_net::vmux_linklayer_ptr& link) {
        RunOnStrandVoid(mux, [&]() {
            mux.rx_links_.push_back(link);
            if (link->handshake_complete_ && !link->drain_.retiring()) {
                mux.tx_links_.push_back(link);
            }
            mux.refresh_runtime_active_links();
        });
    }

    static void OnLinkExit(vmux_net& mux, const vmux_net::vmux_linklayer_ptr& link, const char* reason) {
        RunOnStrandVoid(mux, [&]() { mux.on_link_exit(link, reason); });
    }

    static std::size_t LiveCarriers(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.count_live_carriers(nullptr); });
    }

    static std::size_t RxLinkCount(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.rx_links_.size(); });
    }

    static bool LinkHasByteCredit(const vmux_net::vmux_linklayer_ptr& link, int len) {
        return vmux_net::link_has_byte_credit(link, len);
    }

    static void SetQueuedBytes(const vmux_net::vmux_linklayer_ptr& link, std::size_t n) {
        link->queued_bytes_ = n;
    }

    static void EmplaceDataFrame(vmux_net& mux, std::uint32_t cid, int payload_len) {
        RunOnStrandVoid(mux, [&]() {
            const int frame_len = static_cast<int>(sizeof(vmux_net::vmux_hdr)) + payload_len;
            auto buf = ppp::make_shared_alloc<Byte>(frame_len);
            if (!buf) {
                throw std::runtime_error("alloc data frame");
            }
            auto* h = reinterpret_cast<vmux_net::vmux_hdr*>(buf.get());
            std::memset(h, 0, sizeof(*h));
            h->cmd = static_cast<std::uint8_t>(vmux_net::cmd_push);
            h->connection_id = htonl(cid);
            h->seq = htonl(1);
            if (payload_len > 0) {
                std::memset(h + 1, 'd', static_cast<std::size_t>(payload_len));
            }
            mux.enqueue_flow_tx(cid, vmux_net::tx_packet{ buf, frame_len, nullptr });
        });
    }

    /** Pop next DRR frame and return its cid (0 if empty). Leaves queue unchanged by requeue. */
    static std::uint32_t DrrPeekNextCid(vmux_net& mux) {
        return RunOnStrand(mux, [&]() {
            vmux_net::tx_packet pkt;
            if (!mux.drr_pop_next(pkt)) {
                return std::uint32_t{0};
            }
            const std::uint32_t cid = vmux_net::peek_connection_id(pkt.buffer, pkt.length);
            mux.drr_requeue_front(std::move(pkt));
            return cid;
        });
    }

    /** Drain one quantum from head cid repeatedly until DRR switches or empty. */
    static std::uint32_t DrrSelectAfterQuantum(vmux_net& mux, std::uint32_t burn_cid, std::size_t burn_bytes) {
        return RunOnStrand(mux, [&]() {
            std::uint32_t last = 0;
            std::size_t burned = 0;
            while (burned < burn_bytes) {
                vmux_net::tx_packet pkt;
                if (!mux.drr_pop_next(pkt)) {
                    break;
                }
                last = vmux_net::peek_connection_id(pkt.buffer, pkt.length);
                burned += (std::size_t)(pkt.length > 0 ? pkt.length : 0);
                if (last != burn_cid) {
                    mux.drr_requeue_front(std::move(pkt));
                    return last;
                }
            }
            return DrrPeekNextCid(mux);
        });
    }

    static std::uint32_t PeekTxHeadCid(vmux_net& mux) {
        return DrrPeekNextCid(mux);
    }

    static std::uint32_t PopTxCid(vmux_net& mux) {
        return RunOnStrand(mux, [&]() {
            vmux_net::tx_packet pkt;
            if (!mux.drr_pop_next(pkt)) {
                return std::uint32_t{0};
            }
            return vmux_net::peek_connection_id(pkt.buffer, pkt.length);
        });
    }

    static void ClearTxQueue(vmux_net& mux) {
        RunOnStrandVoid(mux, [&]() {
            mux.clear_flow_tx();
            mux.tx_ctrl_queue_.clear();
        });
    }

    static void CloseAndDrain(const std::shared_ptr<vmux_net>& mux) noexcept {
        if (!mux) {
            return;
        }

        const auto& context = mux->get_context();
        if (!context) {
            return;
        }

        context->restart();
        mux->close_exec();
        for (int i = 0; i < 64; ++i) {
            const std::size_t n = context->poll();
            context->restart();
            if (n == 0) {
                break;
            }
        }
    }

};

} // namespace vmux

namespace {

using ppp::threading::Executors;

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class ScopedMux final {
public:
    explicit ScopedMux(std::shared_ptr<vmux::vmux_net> mux) noexcept
        : mux_(std::move(mux)) {
    }

    ScopedMux(const ScopedMux&) = delete;
    ScopedMux& operator=(const ScopedMux&) = delete;

    ScopedMux(ScopedMux&& other) noexcept
        : mux_(std::move(other.mux_)) {
    }

    ~ScopedMux() {
        vmux::vmux_net_test_access::CloseAndDrain(mux_);
    }

    vmux::vmux_net* operator->() const noexcept {
        return mux_.get();
    }

    vmux::vmux_net& operator*() const noexcept {
        return *mux_;
    }

    operator const std::shared_ptr<vmux::vmux_net>&() const noexcept {
        return mux_;
    }

private:
    std::shared_ptr<vmux::vmux_net> mux_;
};

ScopedMux MakeMux() {
    auto context = std::make_shared<boost::asio::io_context>();
    auto strand = std::make_shared<Executors::Strand>(context->get_executor());
    auto mux = ppp::make_shared_object<vmux::vmux_net>(
        context, strand, 1, true, false, vmux::vmux_net::mux_mode_balance);
    Require(static_cast<bool>(mux), "vmux allocation failed");
    auto cfg = ppp::make_shared_object<ppp::configurations::AppConfiguration>();
    Require(static_cast<bool>(cfg), "cfg allocation failed");
    cfg->mux.congestions = 0; // disable congestion accounting path in tests
    mux->AppConfiguration = cfg;
    return ScopedMux(std::move(mux));
}

void TestGapTimeoutResetsFlowWithoutHoleDelivery() {
    auto mux = MakeMux();
    constexpr std::uint32_t cid = 7;
    constexpr std::uint64_t timeout_ms = 50;
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, /*cap*/ 64 * 1024, timeout_ms);

    auto skt = vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, cid);
    const char p1[] = "A";
    const char p3[] = "C";

    Require(vmux::vmux_net_test_access::InjectPush(*mux, cid, 1, p1, 1, 1000), "dsn1 inject");
    Require(vmux::vmux_net_test_access::QueuedRx(*skt) == 1, "dsn1 must deliver to skt");
    Require(vmux::vmux_net_test_access::FlowExists(*mux, cid), "flow after dsn1");

    Require(vmux::vmux_net_test_access::InjectPush(*mux, cid, 3, p3, 1, 1001), "dsn3 inject");
    Require(vmux::vmux_net_test_access::QueuedRx(*skt) == 1, "dsn3 must not deliver while gap open");
    Require(vmux::vmux_net_test_access::FlowBufferedBytes(*mux, cid) > 0, "dsn3 buffered");

    vmux::vmux_net_test_access::EvictExpired(*mux, 1001 + timeout_ms + 1);

    Require(vmux::vmux_net_test_access::QueuedRx(*skt) == 1, "dsn3 must never be delivered after gap fail");
    Require(!vmux::vmux_net_test_access::FlowExists(*mux, cid), "gap timeout must erase flow");
    // close() is posted async; poll executor so finalize can run.
    auto ctx = mux->get_context();
    Require(static_cast<bool>(ctx), "context");
    ctx->poll();
    ctx->restart();
}

void TestReorderOverflowResetsFlow() {
    auto mux = MakeMux();
    constexpr std::uint32_t cid = 9;
    // Small cap: header(9)+payload must fit one future frame, second future overflows.
    constexpr std::size_t cap = 32;
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, cap, 1000);

    auto skt = vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, cid);
    const char p1[] = "A";
    char payload[16];
    std::memset(payload, 'x', sizeof(payload));

    Require(vmux::vmux_net_test_access::InjectPush(*mux, cid, 1, p1, 1, 2000), "dsn1");
    Require(vmux::vmux_net_test_access::QueuedRx(*skt) == 1, "dsn1 delivered");

    // Future frame ~ 9+16 = 25 bytes buffered under cap 32.
    Require(vmux::vmux_net_test_access::InjectPush(*mux, cid, 3, payload, 16, 2001), "dsn3 buffer");
    Require(vmux::vmux_net_test_access::QueuedRx(*skt) == 1, "no hole delivery on buffer");
    Require(vmux::vmux_net_test_access::FlowExists(*mux, cid), "still open after first buffer");

    // Another future frame cannot fit: overflow -> fail_flow.
    Require(vmux::vmux_net_test_access::InjectPush(*mux, cid, 4, payload, 16, 2002), "dsn4 overflow");
    Require(vmux::vmux_net_test_access::QueuedRx(*skt) == 1, "no force-advance delivery of buffered frames");
    Require(!vmux::vmux_net_test_access::FlowExists(*mux, cid), "overflow must reset flow");
}

void TestFrameOversizeResetsFlow() {
    auto mux = MakeMux();
    constexpr std::uint32_t cid = 11;
    constexpr std::size_t cap = 64;
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, cap, 1000);

    auto skt = vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, cid);
    const char p1[] = "A";
    Require(vmux::vmux_net_test_access::InjectPush(*mux, cid, 1, p1, 1, 3000), "dsn1");

    std::vector<char> big(cap); // frame length = hdr + cap > cap
    std::memset(big.data(), 'Z', big.size());
    Require(vmux::vmux_net_test_access::InjectPush(
                *mux, cid, 3, big.data(), static_cast<int>(big.size()), 3001),
            "oversize future inject returns");
    Require(vmux::vmux_net_test_access::QueuedRx(*skt) == 1, "oversize must not deliver hole");
    Require(!vmux::vmux_net_test_access::FlowExists(*mux, cid), "oversize must reset flow");
}

void TestInOrderStillDelivers() {
    auto mux = MakeMux();
    constexpr std::uint32_t cid = 13;
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000);
    auto skt = vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, cid);

    const char a[] = "A";
    const char b[] = "B";
    Require(vmux::vmux_net_test_access::InjectPush(*mux, cid, 1, a, 1, 4000), "a");
    Require(vmux::vmux_net_test_access::InjectPush(*mux, cid, 2, b, 1, 4001), "b");
    Require(vmux::vmux_net_test_access::QueuedRx(*skt) == 2, "in-order contiguous delivery");
    Require(vmux::vmux_net_test_access::FlowExists(*mux, cid), "flow remains without gap fail");
}

void TestFirstObservedFutureDsnWaitsForDsnOne() {
    auto mux = MakeMux();
    constexpr std::uint32_t cid = 14;
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000);
    auto skt = vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, cid);

    const char a[] = "A";
    const char b[] = "B";
    Require(vmux::vmux_net_test_access::InjectPush(*mux, cid, 2, b, 1, 4100), "dsn2 first");
    Require(vmux::vmux_net_test_access::QueuedRx(*skt) == 0, "dsn2 must wait for initial dsn1");
    Require(vmux::vmux_net_test_access::FlowBufferedBytes(*mux, cid) > 0, "dsn2 buffered");

    Require(vmux::vmux_net_test_access::InjectPush(*mux, cid, 1, a, 1, 4101), "dsn1 closes gap");
    Require(vmux::vmux_net_test_access::QueuedRx(*skt) == 2, "dsn1 then dsn2 delivered contiguously");
}

} // namespace

void TestCompatOooRefreshesActivity() {
    auto mux = MakeMux();
    constexpr std::uint64_t timeout_ms = 400;
    vmux::vmux_net_test_access::ConfigureCompat(*mux, timeout_ms);
    Require(vmux::vmux_net_test_access::LastActive(*mux) == 0, "last starts zero");

    // Future seq only (gap open): must still refresh session activity.
    Require(vmux::vmux_net_test_access::InjectCompatFrame(*mux, /*seq*/ 3, /*cid*/ 1, /*now*/ 5000),
            "ooo insert");
    Require(vmux::vmux_net_test_access::CompatReorderSize(*mux) == 1, "one buffered");
    Require(vmux::vmux_net_test_access::LastActive(*mux) == 5000, "ooo must call active(now)");
}

void TestCompatGapTimeoutClosesSession() {
    auto mux = MakeMux();
    constexpr std::uint64_t timeout_ms = 50;
    vmux::vmux_net_test_access::ConfigureCompat(*mux, timeout_ms);
    Require(vmux::vmux_net_test_access::InjectCompatFrame(*mux, 5, 1, 10000), "buffer future");
    Require(vmux::vmux_net_test_access::CompatReorderSize(*mux) == 1, "buffered");

    vmux::vmux_net_test_access::CompatEvict(*mux, 10000 + timeout_ms); // not yet
    Require(!vmux::vmux_net_test_access::IsDisposed(*mux), "not timed out yet");

    vmux::vmux_net_test_access::CompatEvict(*mux, 10000 + timeout_ms + 1);
    // close_exec posts finalize async; poll once
    auto ctx = mux->get_context();
    Require(static_cast<bool>(ctx), "ctx");
    ctx->poll();
    ctx->restart();
    Require(vmux::vmux_net_test_access::IsDisposed(*mux), "compat gap timeout must dispose session");
}

void TestCompatReorderCapClosesSession() {
    auto mux = MakeMux();
    constexpr std::size_t frame_size = 9;
    vmux::vmux_net_test_access::ConfigureCompat(*mux, 1000, frame_size);

    Require(vmux::vmux_net_test_access::InjectCompatFrame(*mux, 3, 1, 11000), "first future frame");
    Require(vmux::vmux_net_test_access::CompatReorderSize(*mux) == 1, "first frame fits cap");
    Require(vmux::vmux_net_test_access::InjectCompatFrame(*mux, 4, 1, 11001), "overflow schedules close");
    auto ctx = mux->get_context();
    Require(static_cast<bool>(ctx), "ctx");
    ctx->poll();
    ctx->restart();
    Require(vmux::vmux_net_test_access::IsDisposed(*mux), "compat reorder overflow must close session");
}

void TestUnknownCidDoesNotGrowFlowsUnbounded() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 64 * 1024, 400);
    // No skt installed: random cids must not create permanent flows_ entries.
    for (std::uint32_t i = 1; i <= 10000; ++i) {
        const char p[] = "x";
        Require(vmux::vmux_net_test_access::InjectPush(*mux, i, 1, p, 1, 20000 + i), "inject");
    }
    Require(vmux::vmux_net_test_access::FlowMapSize(*mux) == 0, "unknown cid must not grow flows_");
}

void TestInitiatorOpenBarrierBlocksPush() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 400);
    auto skt = vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, 42);
    // Install sets connected_=true; force barrier condition.
    const char payload[] = "hello";
    Require(!vmux::vmux_net_test_access::SendToPeerBeforeOpen(skt, payload, 5),
            "push before connected must fail");
}

void TestSessionReorderCapResetsFlow() {
    auto mux = MakeMux();
    // per-flow cap large; session cap fits one future frame (~29B) but not two.
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, /*per*/ 1024, /*to*/ 1000, /*session*/ 40, /*max_open*/ 0);
    auto skt1 = vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, 1);
    auto skt2 = vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, 2);
    const char p1[] = "A";
    Require(vmux::vmux_net_test_access::InjectPush(*mux, 1, 1, p1, 1, 5000), "cid1 dsn1");
    char payload[20];
    std::memset(payload, 'x', sizeof(payload));
    // buffer future on flow1: hdr+20 ~ 29 bytes under session cap 40
    Require(vmux::vmux_net_test_access::InjectPush(*mux, 1, 3, payload, 20, 5001), "cid1 gap buffer");
    Require(vmux::vmux_net_test_access::FlowExists(*mux, 1), "flow1 open after buffer");
    Require(vmux::vmux_net_test_access::SessionReorderBytes(*mux) > 0, "session bytes accounted");
    Require(vmux::vmux_net_test_access::InjectPush(*mux, 2, 1, p1, 1, 5002), "cid2 dsn1");
    Require(vmux::vmux_net_test_access::InjectPush(*mux, 2, 3, payload, 20, 5003), "cid2 triggers session cap");
    // Oldest gapped flow (cid1) must be failed; session must remain within cap.
    Require(!vmux::vmux_net_test_access::FlowExists(*mux, 1), "oldest gap flow failed on session cap");
    Require(vmux::vmux_net_test_access::SessionReorderBytes(*mux) <= 40, "session reorder bounded");
}

void TestMaxOpenFlowsEnforced() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000, 0, /*max_open*/ 1);
    // Seed one open skt without full accept path.
    (void)vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, 1);
    Require(vmux::vmux_net_test_access::SktCount(*mux) == 1, "one skt");
    Require(!vmux::vmux_net_test_access::ProcessRxConnecting(mux, 2, "127.0.0.1:81"), "second open rejected");
    Require(!vmux::vmux_net_test_access::ConnectRequire(*mux), "locally initiated open must use the same cap");
    Require(vmux::vmux_net_test_access::SktCount(*mux) == 1, "still one skt");
}

void TestCtrlBudgetDoesNotDrainAll() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000);
    vmux::vmux_net_test_access::SetCtrlBudget(*mux, 2);
    // No tx_links => process_tx_ctrl returns early without draining - not useful.
    // Just verify budget field is latched and queue can hold frames.
    vmux::vmux_net_test_access::EmplaceCtrlFrame(*mux, 10);
    Require(vmux::vmux_net_test_access::CtrlQueueSize(*mux) == 10, "ctrl queued");
    // Without links, process returns true and leaves queue (existing behavior).
    Require(vmux::vmux_net_test_access::ProcessTxAll(*mux), "process ok");
    Require(vmux::vmux_net_test_access::CtrlQueueSize(*mux) == 10, "no links => no drain");
    vmux::vmux_net_test_access::ClearTxQueue(*mux);
}

void DrainContext(const std::shared_ptr<vmux::vmux_net>& mux) {
    auto ctx = mux->get_context();
    if (!ctx) {
        return;
    }
    for (int i = 0; i < 64; ++i) {
        const std::size_t n = ctx->poll();
        ctx->restart();
        if (n == 0) {
            break;
        }
    }
}

void TestLinkExitIsolatesWhenOthersLive() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000);
    auto a = vmux::vmux_net_test_access::MakeDeadLink(true);
    auto b = vmux::vmux_net_test_access::MakeDeadLink(true);
    vmux::vmux_net_test_access::AttachLink(*mux, a);
    vmux::vmux_net_test_access::AttachLink(*mux, b);
    Require(vmux::vmux_net_test_access::LiveCarriers(*mux) == 2, "two live");
    vmux::vmux_net_test_access::OnLinkExit(*mux, a, "test");
    Require(!vmux::vmux_net_test_access::IsDisposed(*mux), "session survives with remaining link");
    Require(vmux::vmux_net_test_access::LiveCarriers(*mux) == 1, "one live left");
    Require(vmux::vmux_net_test_access::RxLinkCount(*mux) == 1, "dead removed from rx");
}

void TestLinkExitClosesWhenLast() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000);
    auto only = vmux::vmux_net_test_access::MakeDeadLink(true);
    vmux::vmux_net_test_access::AttachLink(*mux, only);
    vmux::vmux_net_test_access::OnLinkExit(*mux, only, "last");
    DrainContext(mux);
    Require(vmux::vmux_net_test_access::IsDisposed(*mux), "last carrier closes session");
}

void TestLinkByteCreditHighWater() {
    auto link = vmux::vmux_net_test_access::MakeDeadLink(true);
    Require(vmux::vmux_net_test_access::LinkHasByteCredit(link, 1024), "idle has credit");
    vmux::vmux_net_test_access::SetQueuedBytes(link, static_cast<std::size_t>(PPP_MUX_LINK_BYTE_HIGH_WATER));
    Require(!vmux::vmux_net_test_access::LinkHasByteCredit(link, 1), "at high water denies");
    vmux::vmux_net_test_access::SetQueuedBytes(link, static_cast<std::size_t>(PPP_MUX_LINK_BYTE_HIGH_WATER) - 16);
    Require(vmux::vmux_net_test_access::LinkHasByteCredit(link, 16), "exactly fits");
    Require(!vmux::vmux_net_test_access::LinkHasByteCredit(link, 17), "over denies");
}

void TestTxFlowDrrPrefersOtherCidAfterQuantum() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000);
    // Enqueue many frames for cid=1 then one for cid=2.
    // With quantum Q, after draining ~Q bytes from cid1, DRR must serve cid2.
    constexpr int frame_payload = 100;
    constexpr int frame_hdr = 9; // sizeof(vmux_hdr); private type, keep in sync
    constexpr int frame_len = frame_hdr + frame_payload;
    const int frames_to_fill_quantum =
        (int)((PPP_MUX_TX_FLOW_QUANTUM_BYTES + frame_len - 1) / frame_len) + 1;
    for (int i = 0; i < frames_to_fill_quantum; ++i) {
        vmux::vmux_net_test_access::EmplaceDataFrame(*mux, 1, frame_payload);
    }
    vmux::vmux_net_test_access::EmplaceDataFrame(*mux, 2, frame_payload);
    Require(vmux::vmux_net_test_access::PeekTxHeadCid(*mux) == 1, "first DRR pick is cid1");
    const auto next = vmux::vmux_net_test_access::DrrSelectAfterQuantum(
        *mux, 1, (std::size_t)PPP_MUX_TX_FLOW_QUANTUM_BYTES);
    Require(next == 2, "after one quantum of cid1, DRR serves cid2");
    vmux::vmux_net_test_access::ClearTxQueue(*mux);
}

void TestTxFlowDrrDrainsBytesWithinQuantumBeforeRotating() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000);
    vmux::vmux_net_test_access::EmplaceDataFrame(*mux, 1, 100);
    vmux::vmux_net_test_access::EmplaceDataFrame(*mux, 1, 100);
    vmux::vmux_net_test_access::EmplaceDataFrame(*mux, 2, 100);

    Require(vmux::vmux_net_test_access::PopTxCid(*mux) == 1, "cid1 begins its quantum");
    Require(vmux::vmux_net_test_access::PopTxCid(*mux) == 1, "cid1 keeps the turn while deficit remains");
    Require(vmux::vmux_net_test_access::PopTxCid(*mux) == 2, "cid2 runs after cid1 queue drains");
}

void TestVmuxCreatesMissingStrand() {
    auto context = std::make_shared<boost::asio::io_context>();
    vmux::StrandPtr strand;
    auto mux = ppp::make_shared_object<vmux::vmux_net>(
        context, strand, 1, true, false, vmux::vmux_net::mux_mode_balance);
    Require(static_cast<bool>(mux), "fallback mux allocation");
    Require(static_cast<bool>(mux->get_strand()), "valid context must create missing strand");
    Require(!mux->is_disposed(), "fallback strand keeps mux usable");
    vmux::vmux_net_test_access::CloseAndDrain(mux);
}

void TestStrandAffineSendAndPostRejectOffStrand() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000);
    auto skt = vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, 77);
    const char payload[] = "x";

    Require(!vmux::vmux_net_test_access::SendToPeerOffStrand(skt, payload, 1),
        "send_to_peer must synchronously reject off-strand calls");
    Require(!vmux::vmux_net_test_access::PostCommand(*mux, false),
        "command post_internal must reject off-strand calls");
    Require(!vmux::vmux_net_test_access::PostFrame(*mux, false),
        "frame post_internal must reject off-strand calls");
    Require(vmux::vmux_net_test_access::PostCommand(*mux, true),
        "command post_internal remains synchronous on strand");
    Require(vmux::vmux_net_test_access::PostFrame(*mux, true),
        "frame post_internal remains synchronous on strand");
}

int main() {
    try {
        TestTxFlowDrrPrefersOtherCidAfterQuantum();
        TestTxFlowDrrDrainsBytesWithinQuantumBeforeRotating();
        TestInOrderStillDelivers();
        TestFirstObservedFutureDsnWaitsForDsnOne();
        TestGapTimeoutResetsFlowWithoutHoleDelivery();
        TestReorderOverflowResetsFlow();
        TestFrameOversizeResetsFlow();
        TestCompatOooRefreshesActivity();
        TestCompatGapTimeoutClosesSession();
        TestCompatReorderCapClosesSession();
        TestUnknownCidDoesNotGrowFlowsUnbounded();
        TestInitiatorOpenBarrierBlocksPush();
        TestSessionReorderCapResetsFlow();
        TestMaxOpenFlowsEnforced();
        TestCtrlBudgetDoesNotDrainAll();
        TestLinkExitIsolatesWhenOthersLive();
        TestLinkExitClosesWhenLast();
        TestLinkByteCreditHighWater();
        TestVmuxCreatesMissingStrand();
        TestStrandAffineSendAndPostRejectOffStrand();
        std::cout << "vmux_receive_semantics_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "vmux_receive_semantics_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
