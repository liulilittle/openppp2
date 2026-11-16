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
        return InjectPushOn(mux, vmux_net::vmux_linklayer_ptr{}, connection_id, dsn, payload, payload_len, now);
    }

    static bool InjectPushOn(
        vmux_net& mux,
        const vmux_net::vmux_linklayer_ptr& link,
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
            return mux.packet_input_flow(link, h, frame_len, now);
        });
    }

    static void EnableCompatReliability(vmux_net& mux, bool fast) {
        RunOnStrandVoid(mux, [&]() {
            mux.ordering_mode_ = vmux_net::ordering_compat;
            mux.reliability_on_ = true;
            mux.rtx_fast_on_ = fast;
            mux.rtx_pto_on_ = false;
            mux.base_.established_ = true;
            mux.base_.disposed_.store(false, std::memory_order_release);
        });
    }

    static bool TrackSentCompat(vmux_net& mux, std::uint32_t seq, std::uint16_t link_id, std::uint64_t now) {
        return RunOnStrand(mux, [&]() {
            const int frame_len = static_cast<int>(sizeof(vmux_net::vmux_hdr)) + 1;
            auto buf = mux.make_byte_array(frame_len);
            if (!buf) {
                throw std::runtime_error("alloc tracked frame");
            }
            auto* h = reinterpret_cast<vmux_net::vmux_hdr*>(buf.get());
            std::memset(buf.get(), 0, static_cast<std::size_t>(frame_len));
            h->seq = htonl(seq);
            h->cmd = static_cast<std::uint8_t>(vmux_net::cmd_push);
            h->connection_id = htonl(1);
            return mux.track_sent_frame(buf, frame_len, now, link_id);
        });
    }

    static void InjectCompatAck(vmux_net& mux, std::uint32_t start, std::uint32_t end, std::uint64_t now) {
        RunOnStrandVoid(mux, [&]() {
            ppp::app::mux::MuxAckBlock block;
            block.connection_id = 0;
            block.largest = end;
            block.ranges.push_back(ppp::app::mux::MuxAckRange{ start, end });
            const std::size_t cap = ppp::app::mux::MuxAckFrameMaxSize(1, 1);
            std::vector<std::uint8_t> payload(cap);
            const std::size_t len = ppp::app::mux::EncodeMuxAckFrame(&block, 1, payload.data(), cap, 1);
            if (len == 0) {
                throw std::runtime_error("encode ack");
            }
            mux.packet_input_ack(payload.data(), static_cast<int>(len), now);
        });
    }

    static std::size_t PendingRtx(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.rtx_pending_.size(); });
    }

    static std::size_t RtxSize(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.rtx_.size(); });
    }

    static std::uint16_t RtxLastLink(vmux_net& mux, std::uint32_t seq) {
        return RunOnStrand(mux, [&]() {
            const ppp::app::mux::MuxRtxEntry* entry =
                mux.rtx_.Find(ppp::app::mux::MuxRetransmitBuffer::Key(0, seq));
            return entry == nullptr ? std::uint16_t{0xFFFF} : entry->last_link_id;
        });
    }

    static bool IsRxPaused(const vmux_net::vmux_linklayer_ptr& link) {
        return link->rx_paused_.load(std::memory_order_acquire);
    }

    static std::size_t PausedLinkCount(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.rx_paused_links_.size(); });
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
        return InjectCompatFrameOn(mux, vmux_net::vmux_linklayer_ptr{}, seq, connection_id, now);
    }

    static bool InjectCompatFrameOn(
        vmux_net& mux,
        const vmux_net::vmux_linklayer_ptr& link,
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
            return mux.packet_input_unorder(link, h, frame_len, now);
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
                link->in_tx_links_ = true;
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

    /** Inject a peer cmd_acceleration; version < 0 sends the legacy 1-byte form. */
    static bool InjectAcceleration(vmux_net& mux, std::uint32_t cid, bool on, long long version, std::uint64_t now) {
        return RunOnStrand(mux, [&]() {
            std::vector<std::uint8_t> frame(sizeof(vmux_net::vmux_hdr) + 1 + (version >= 0 ? 4 : 0));
            auto* h = reinterpret_cast<vmux_net::vmux_hdr*>(frame.data());
            std::memset(h, 0, sizeof(*h));
            h->cmd = static_cast<std::uint8_t>(vmux_net::cmd_acceleration);
            h->connection_id = htonl(cid);
            std::uint8_t* p = frame.data() + sizeof(vmux_net::vmux_hdr);
            p[0] = on ? 1 : 0;
            if (version >= 0) {
                const std::uint32_t v = htonl(static_cast<std::uint32_t>(version));
                std::memcpy(p + 1, &v, sizeof(v));
            }
            return mux.packet_input(h->cmd, frame.data(), static_cast<int>(frame.size()), now);
        });
    }

    static bool SktTxAcceleration(vmux_net& mux, const vmux_skt& skt) {
        return RunOnStrand(mux, [&]() { return (bool)skt.status_.tx_acceleration_; });
    }

    static std::size_t AggregateReorderBytes(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.flow_aggregate_bytes_; });
    }

    /** Pop frames in DRR order, assigning deferred compat sequences as a send would. */
    static std::vector<std::uint32_t> PopAndAssignSeqs(vmux_net& mux, int n) {
        return RunOnStrand(mux, [&]() {
            std::vector<std::uint32_t> seqs;
            for (int i = 0; i < n; ++i) {
                vmux_net::tx_packet pkt;
                if (!mux.drr_pop_next(pkt)) {
                    break;
                }
                mux.tx_assign_seq(pkt);
                seqs.push_back(ntohl(reinterpret_cast<vmux_net::vmux_hdr*>(pkt.buffer.get())->seq));
            }
            return seqs;
        });
    }

    static std::uint32_t TxSeq(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.status_.tx_seq_; });
    }

    static void OfferLink(vmux_net& mux, const vmux_net::vmux_linklayer_ptr& link) {
        RunOnStrandVoid(mux, [&]() { mux.tx_link_offer(link); });
    }

    static void WithdrawLink(vmux_net& mux, const vmux_net::vmux_linklayer_ptr& link) {
        RunOnStrandVoid(mux, [&]() { mux.tx_link_withdraw(link); });
    }

    static vmux_net::vmux_linklayer_ptr PickLink(vmux_net& mux, int len) {
        return RunOnStrand(mux, [&]() { return mux.tx_link_pick(len); });
    }

    /** Post one push frame through post_internal (no acceleration, no completion). */
    static bool PostPush(vmux_net& mux, std::uint32_t cid, int payload_len) {
        return RunOnStrand(mux, [&]() {
            std::vector<std::uint8_t> payload(static_cast<std::size_t>(payload_len), 'p');
            vmux_net::PostInternalAsynchronousCallback none;
            return mux.post_internal(vmux_net::cmd_push, payload.data(), payload_len, cid, false, none);
        });
    }

    static std::size_t TxFlowFrames(vmux_net& mux, std::uint32_t cid) {
        return RunOnStrand(mux, [&]() {
            auto it = mux.tx_flows_.find(cid);
            return it == mux.tx_flows_.end() ? std::size_t{0} : it->second.queue.size();
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

    static void EmplaceDataFrameSeq(vmux_net& mux, std::uint32_t cid, std::uint32_t seq, int payload_len) {
        RunOnStrandVoid(mux, [&]() {
            const int frame_len = static_cast<int>(sizeof(vmux_net::vmux_hdr)) + payload_len;
            auto buf = ppp::make_shared_alloc<Byte>(frame_len);
            if (!buf) {
                throw std::runtime_error("alloc data frame");
            }
            auto* h = reinterpret_cast<vmux_net::vmux_hdr*>(buf.get());
            std::memset(buf.get(), 'd', static_cast<std::size_t>(frame_len));
            h->cmd = static_cast<std::uint8_t>(vmux_net::cmd_push);
            h->connection_id = htonl(cid);
            h->seq = htonl(seq);
            mux.enqueue_flow_tx(cid, vmux_net::tx_packet{ buf, frame_len, nullptr });
        });
    }

    static void EnableFlowReliability(vmux_net& mux) {
        RunOnStrandVoid(mux, [&]() {
            mux.reliability_on_ = true;
            mux.rtx_fast_on_ = false;
            mux.rtx_pto_on_ = false;
        });
    }

    static void SetRtxWindow(vmux_net& mux, std::size_t bytes) {
        RunOnStrandVoid(mux, [&]() { mux.rtx_cap_bytes_ = bytes; });
    }

    static bool TrackSentFlow(vmux_net& mux, std::uint32_t cid, std::uint32_t dsn, int frame_len, std::uint64_t now) {
        return RunOnStrand(mux, [&]() {
            auto buf = mux.make_byte_array(frame_len);
            if (!buf) {
                throw std::runtime_error("alloc tracked flow frame");
            }
            std::memset(buf.get(), 0, static_cast<std::size_t>(frame_len));
            auto* h = reinterpret_cast<vmux_net::vmux_hdr*>(buf.get());
            h->seq = htonl(dsn);
            h->cmd = static_cast<std::uint8_t>(vmux_net::cmd_push);
            h->connection_id = htonl(cid);
            return mux.track_sent_frame(buf, frame_len, now, 0);
        });
    }

    static void InjectAck(vmux_net& mux, std::uint32_t cid, std::uint32_t start, std::uint32_t end, std::uint64_t now) {
        RunOnStrandVoid(mux, [&]() {
            ppp::app::mux::MuxAckBlock block;
            block.connection_id = cid;
            block.largest = end;
            block.ranges.push_back(ppp::app::mux::MuxAckRange{ start, end });
            const std::size_t cap = ppp::app::mux::MuxAckFrameMaxSize(1, 1);
            std::vector<std::uint8_t> payload(cap);
            const std::size_t len = ppp::app::mux::EncodeMuxAckFrame(&block, 1, payload.data(), cap, 1);
            if (len == 0) {
                throw std::runtime_error("encode ack");
            }
            mux.packet_input_ack(payload.data(), static_cast<int>(len), now);
        });
    }

    static bool PostAckFrame(vmux_net& mux) {
        return RunOnStrand(mux, [&]() {
            auto buf = mux.make_byte_array(static_cast<int>(sizeof(vmux_net::vmux_hdr)));
            if (!buf) {
                throw std::runtime_error("alloc ack");
            }
            std::memset(buf.get(), 0, sizeof(vmux_net::vmux_hdr));
            auto* h = reinterpret_cast<vmux_net::vmux_hdr*>(buf.get());
            h->cmd = static_cast<std::uint8_t>(vmux_net::cmd_ack);
            vmux_net::PostInternalAsynchronousCallback callback;
            return mux.post_internal(buf, static_cast<int>(sizeof(vmux_net::vmux_hdr)), false, callback);
        });
    }

    static std::size_t TxDataFrames(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.tx_data_frames_; });
    }

    static std::size_t TxActiveRingSize(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.active_tx_flows_.size(); });
    }

    static bool TxFlowParked(vmux_net& mux, std::uint32_t cid) {
        return RunOnStrand(mux, [&]() { return mux.tx_flow_parked(cid); });
    }

    static std::size_t FreeTxLinkCount(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.tx_links_.size(); });
    }

    static std::size_t RtxBytes(vmux_net& mux) {
        return RunOnStrand(mux, [&]() { return mux.rtx_.bytes(); });
    }

    static void PauseRx(vmux_net& mux, const vmux_net::vmux_linklayer_ptr& link) {
        RunOnStrandVoid(mux, [&]() { mux.rx_pause_link(link); });
    }

    /** Everything a late write completion / forwarding exit / timer can still do to a session. */
    static void LateTeardownCalls(vmux_net& mux, const vmux_net::vmux_linklayer_ptr& link, std::uint64_t now) {
        RunOnStrandVoid(mux, [&]() {
            mux.tx_link_offer(link);
            mux.process_tx_all_packets();
            mux.rx_pause_link(link);
            mux.reinject_link_inflight(link, now);
            mux.retransmit_pending(now);
            mux.on_link_exit(link, "late");
            mux.rx_maybe_resume();
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

    // Over the soft cap but within cap * PPP_MUX_REORDER_HARD_FACTOR: buffered
    // (backpressure), the flow stays open.
    Require(vmux::vmux_net_test_access::InjectPush(*mux, cid, 4, payload, 16, 2002), "dsn4 soft overflow");
    Require(vmux::vmux_net_test_access::FlowExists(*mux, cid), "soft overflow must not reset flow");

    // Past the hard bound: overflow -> fail_flow.
    Require(vmux::vmux_net_test_access::InjectPush(*mux, cid, 5, payload, 16, 2003), "dsn5 hard overflow");
    Require(vmux::vmux_net_test_access::QueuedRx(*skt) == 1, "no force-advance delivery of buffered frames");
    Require(!vmux::vmux_net_test_access::FlowExists(*mux, cid), "hard overflow must reset flow");
}

void TestFlowSoftCapPausesDeliveringCarrier() {
    auto mux = MakeMux();
    constexpr std::uint32_t cid = 10;
    constexpr std::size_t cap = 32;
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, cap, 1000);
    auto fast = vmux::vmux_net_test_access::MakeDeadLink(true);
    auto slow = vmux::vmux_net_test_access::MakeDeadLink(true);
    vmux::vmux_net_test_access::AttachLink(*mux, fast);
    vmux::vmux_net_test_access::AttachLink(*mux, slow);

    auto skt = vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, cid);
    char payload[16];
    std::memset(payload, 'x', sizeof(payload));
    const char p1[] = "A";

    Require(vmux::vmux_net_test_access::InjectPushOn(*mux, slow, cid, 1, p1, 1, 2100), "dsn1");
    Require(vmux::vmux_net_test_access::InjectPushOn(*mux, fast, cid, 3, payload, 16, 2101), "dsn3");
    Require(!vmux::vmux_net_test_access::IsRxPaused(fast), "within soft cap: no pause");
    Require(vmux::vmux_net_test_access::InjectPushOn(*mux, fast, cid, 4, payload, 16, 2102), "dsn4");
    Require(vmux::vmux_net_test_access::IsRxPaused(fast), "over soft cap: delivering carrier paused");
    Require(!vmux::vmux_net_test_access::IsRxPaused(slow), "lagging carrier keeps reading");

    // The lagging frame arrives on the slow carrier; the buffer drains and
    // the fast carrier is released.
    Require(vmux::vmux_net_test_access::InjectPushOn(*mux, slow, cid, 2, p1, 1, 2103), "dsn2 closes gap");
    Require(vmux::vmux_net_test_access::QueuedRx(*skt) == 4, "dsn1..4 delivered in order");
    Require(!vmux::vmux_net_test_access::IsRxPaused(fast), "drained: carrier resumed");
    Require(vmux::vmux_net_test_access::PausedLinkCount(*mux) == 0, "no paused carriers left");
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

void TestCompatGapClockRestartsOnProgress() {
    // Sustained reorder with progress must not time the session out: the gap
    // clock restarts whenever in-order delivery advances.
    auto mux = MakeMux();
    constexpr std::uint64_t timeout_ms = 50;
    vmux::vmux_net_test_access::ConfigureCompat(*mux, timeout_ms);
    Require(vmux::vmux_net_test_access::InjectCompatFrame(*mux, 3, 1, 10000), "seq3 buffered");
    Require(vmux::vmux_net_test_access::InjectCompatFrame(*mux, 1, 1, 10040), "seq1 delivers");
    Require(vmux::vmux_net_test_access::CompatReorderSize(*mux) == 1, "seq3 still waits for seq2");

    vmux::vmux_net_test_access::CompatEvict(*mux, 10000 + timeout_ms + 1);
    Require(!vmux::vmux_net_test_access::IsDisposed(*mux), "progress restarted the gap clock");

    vmux::vmux_net_test_access::CompatEvict(*mux, 10040 + timeout_ms + 1);
    auto ctx = mux->get_context();
    Require(static_cast<bool>(ctx), "ctx");
    ctx->poll();
    ctx->restart();
    Require(vmux::vmux_net_test_access::IsDisposed(*mux), "a real stall still times out");
}

void TestCompatReorderSoftCapPausesInsteadOfClosing() {
    auto mux = MakeMux();
    constexpr std::size_t frame_size = 9;
    vmux::vmux_net_test_access::ConfigureCompat(*mux, 1000, frame_size);
    auto fast = vmux::vmux_net_test_access::MakeDeadLink(true);
    auto slow = vmux::vmux_net_test_access::MakeDeadLink(true);
    vmux::vmux_net_test_access::AttachLink(*mux, fast);
    vmux::vmux_net_test_access::AttachLink(*mux, slow);

    Require(vmux::vmux_net_test_access::InjectCompatFrameOn(*mux, fast, 3, 1, 11000), "first future frame");
    Require(vmux::vmux_net_test_access::InjectCompatFrameOn(*mux, fast, 4, 1, 11001), "soft overflow buffered");
    auto ctx = mux->get_context();
    ctx->poll();
    ctx->restart();
    Require(!vmux::vmux_net_test_access::IsDisposed(*mux), "soft overflow must not close session");
    Require(vmux::vmux_net_test_access::IsRxPaused(fast), "delivering carrier paused");
    Require(!vmux::vmux_net_test_access::IsRxPaused(slow), "other carrier keeps reading");

    Require(vmux::vmux_net_test_access::InjectCompatFrameOn(*mux, slow, 1, 1, 11002), "seq1");
    Require(vmux::vmux_net_test_access::InjectCompatFrameOn(*mux, slow, 2, 1, 11003), "seq2 drains");
    Require(vmux::vmux_net_test_access::CompatReorderSize(*mux) == 0, "drained");
    Require(!vmux::vmux_net_test_access::IsRxPaused(fast), "resumed after drain");
}

void TestCompatSinglePausedCarrierIsReleased() {
    // Pausing the only live carrier would deadlock (it may carry the missing
    // frame): the guard releases it immediately.
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureCompat(*mux, 1000, 9);
    auto only = vmux::vmux_net_test_access::MakeDeadLink(true);
    vmux::vmux_net_test_access::AttachLink(*mux, only);
    Require(vmux::vmux_net_test_access::InjectCompatFrameOn(*mux, only, 3, 1, 12000), "first");
    Require(vmux::vmux_net_test_access::InjectCompatFrameOn(*mux, only, 4, 1, 12001), "soft overflow");
    Require(!vmux::vmux_net_test_access::IsRxPaused(only), "sole carrier never left paused");
}

void TestFastRetransmitOffByDefaultIgnoresDupAckHoles() {
    // seq 2..5 acked above an unacked seq 1: with fast retransmit off (default
    // on reliable carriers) the hole is cross-carrier reordering, not loss.
    for (int fast = 0; fast <= 1; ++fast) {
        auto mux = MakeMux();
        vmux::vmux_net_test_access::EnableCompatReliability(*mux, fast != 0);
        for (std::uint32_t seq = 1; seq <= 5; ++seq) {
            Require(vmux::vmux_net_test_access::TrackSentCompat(*mux, seq, 5, 13000 + seq), "track");
        }
        vmux::vmux_net_test_access::InjectCompatAck(*mux, 2, 5, 13100);
        Require(vmux::vmux_net_test_access::RtxSize(*mux) == 1, "acked frames released either way");
        if (fast != 0) {
            Require(vmux::vmux_net_test_access::PendingRtx(*mux) == 1, "fast on: hole scheduled");
        }
        else {
            Require(vmux::vmux_net_test_access::PendingRtx(*mux) == 0, "fast off: hole not re-sent");
        }
    }
}

void TestLinkExitReinjectsInflightFrames() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::EnableCompatReliability(*mux, false);
    auto dead = vmux::vmux_net_test_access::MakeDeadLink(true);
    auto live = vmux::vmux_net_test_access::MakeDeadLink(true);
    dead->id_ = 5;
    live->id_ = 6;
    vmux::vmux_net_test_access::AttachLink(*mux, dead);
    vmux::vmux_net_test_access::AttachLink(*mux, live);

    Require(vmux::vmux_net_test_access::TrackSentCompat(*mux, 1, 5, 14000), "seq1 on dead carrier");
    Require(vmux::vmux_net_test_access::TrackSentCompat(*mux, 2, 6, 14001), "seq2 on live carrier");

    vmux::vmux_net_test_access::OnLinkExit(*mux, dead, "test");
    Require(!vmux::vmux_net_test_access::IsDisposed(*mux), "other carrier still live");
    // The survivor here has no transport, so the re-send cannot go out yet:
    // the frame must stay scheduled (not dropped) and orphaned from carrier 5.
    Require(vmux::vmux_net_test_access::PendingRtx(*mux) == 1, "dead carrier's frame scheduled for re-send");
    Require(vmux::vmux_net_test_access::RtxLastLink(*mux, 1) == 0, "orphaned from the dead carrier id");
    Require(vmux::vmux_net_test_access::RtxLastLink(*mux, 2) == 6, "live carrier's frame untouched");
}

void TestRtxWindowHoldsFrameUntilAck() {
    // Retransmit cap is a send window: a frame that would cross it stays in
    // the DRR queue (no send attempted, nothing dropped, session alive) and
    // the ACK that frees bytes resumes sending.
    auto mux = MakeMux();
    vmux::vmux_net_test_access::EnableCompatReliability(*mux, false);
    constexpr std::size_t frame_len = 10; // sizeof(vmux_hdr) + 1, as TrackSentCompat
    vmux::vmux_net_test_access::SetRtxWindow(*mux, 2 * frame_len);
    auto link = vmux::vmux_net_test_access::MakeDeadLink(true);
    link->id_ = 3;
    vmux::vmux_net_test_access::AttachLink(*mux, link);

    Require(vmux::vmux_net_test_access::TrackSentCompat(*mux, 1, 3, 15000), "seq1 in flight");
    Require(vmux::vmux_net_test_access::TrackSentCompat(*mux, 2, 3, 15000), "seq2 in flight");
    Require(vmux::vmux_net_test_access::RtxBytes(*mux) == 2 * frame_len, "window full");

    vmux::vmux_net_test_access::EmplaceDataFrameSeq(*mux, 1, 3, 1);
    Require(vmux::vmux_net_test_access::ProcessTxAll(*mux), "drain with full window");
    Require(vmux::vmux_net_test_access::TxDataFrames(*mux) == 1, "held frame stays queued");
    Require(vmux::vmux_net_test_access::TxFlowParked(*mux, 1), "flow parked on the window");
    Require(vmux::vmux_net_test_access::FreeTxLinkCount(*mux) == 1, "no send attempted while window full");
    Require(!vmux::vmux_net_test_access::IsDisposed(*mux), "full window must not close the session");

    // Later frames queue behind the parked head without re-entering the ring.
    vmux::vmux_net_test_access::EmplaceDataFrameSeq(*mux, 1, 4, 1);
    Require(vmux::vmux_net_test_access::TxDataFrames(*mux) == 2, "second frame queued");
    Require(vmux::vmux_net_test_access::TxActiveRingSize(*mux) == 0, "parked flow stays off the DRR ring");

    vmux::vmux_net_test_access::InjectCompatAck(*mux, 1, 1, 15100);
    Require(vmux::vmux_net_test_access::RtxBytes(*mux) == frame_len, "ack released seq1");
    Require(!vmux::vmux_net_test_access::TxFlowParked(*mux, 1), "ack resumes the parked flow");
    // The test carrier has no transport: the resumed send is attempted (link
    // taken) and fails, so the frame is requeued rather than lost.
    Require(vmux::vmux_net_test_access::FreeTxLinkCount(*mux) == 0, "resumed send attempted on the free carrier");
    Require(vmux::vmux_net_test_access::TxDataFrames(*mux) == 2, "nothing dropped across hold/resume");
    Require(!vmux::vmux_net_test_access::IsDisposed(*mux), "session alive after resume");
}

void TestRtxWindowOnlyHardCapClosesCompatSession() {
    // Frames that bypass the window (e.g. turbo SYN) may overshoot it; only
    // window * PPP_MUX_RTX_HARD_FACTOR still rebuilds the session.
    auto mux = MakeMux();
    vmux::vmux_net_test_access::EnableCompatReliability(*mux, false);
    constexpr std::size_t frame_len = 10;
    vmux::vmux_net_test_access::SetRtxWindow(*mux, frame_len);
    const std::uint32_t within_hard = static_cast<std::uint32_t>(PPP_MUX_RTX_HARD_FACTOR);
    for (std::uint32_t seq = 1; seq <= within_hard; ++seq) {
        Require(vmux::vmux_net_test_access::TrackSentCompat(*mux, seq, 0, 16000), "within hard bound tracks");
    }
    auto ctx = mux->get_context();
    Require(static_cast<bool>(ctx), "ctx");
    ctx->poll();
    ctx->restart();
    Require(!vmux::vmux_net_test_access::IsDisposed(*mux), "over the window but within hard bound keeps session");

    Require(!vmux::vmux_net_test_access::TrackSentCompat(*mux, within_hard + 1, 0, 16001), "hard bound rejects");
    ctx->poll();
    ctx->restart();
    Require(vmux::vmux_net_test_access::IsDisposed(*mux), "hard bound still rebuilds the session");
}

void TestRtxFlowWindowParksOnlyThatFlow() {
    // flow_v2: a flow over its per-flow window is parked; other flows keep
    // sending, and the flow's ACK resumes it.
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 64 * 1024, 1000);
    vmux::vmux_net_test_access::EnableFlowReliability(*mux);
    auto link = vmux::vmux_net_test_access::MakeDeadLink(true);
    link->id_ = 4;
    vmux::vmux_net_test_access::AttachLink(*mux, link);

    Require(vmux::vmux_net_test_access::TrackSentFlow(*mux, 1, 1, PPP_MUX_RTX_FLOW_MAX_BYTES, 17000),
        "cid1 fills its flow window");
    vmux::vmux_net_test_access::EmplaceDataFrameSeq(*mux, 1, 2, 1);
    vmux::vmux_net_test_access::EmplaceDataFrameSeq(*mux, 2, 1, 1);
    Require(vmux::vmux_net_test_access::ProcessTxAll(*mux), "drain");
    Require(vmux::vmux_net_test_access::TxFlowParked(*mux, 1), "cid1 parked on its flow window");
    Require(!vmux::vmux_net_test_access::TxFlowParked(*mux, 2), "cid2 not parked");
    Require(vmux::vmux_net_test_access::FreeTxLinkCount(*mux) == 0, "cid2 send attempted despite cid1 hold");
    Require(vmux::vmux_net_test_access::TxDataFrames(*mux) == 2, "both frames still queued (dead carrier)");

    vmux::vmux_net_test_access::InjectAck(*mux, 1, 1, 1, 17100);
    Require(vmux::vmux_net_test_access::RtxBytes(*mux) == 0, "ack released cid1 window");
    Require(!vmux::vmux_net_test_access::TxFlowParked(*mux, 1), "ack resumes cid1");
    Require(vmux::vmux_net_test_access::TxDataFrames(*mux) == 2, "nothing dropped");
}

void TestCompatAckFramesBypassParkedData() {
    // An ACK must never wait behind parked data, or both peers' windows could
    // stall on each other: reliability control takes the priority queue in
    // compat too.
    auto mux = MakeMux();
    vmux::vmux_net_test_access::EnableCompatReliability(*mux, false);
    Require(vmux::vmux_net_test_access::PostAckFrame(*mux), "post ack");
    Require(vmux::vmux_net_test_access::CtrlQueueSize(*mux) == 1, "compat ack queued on the priority queue");
    Require(vmux::vmux_net_test_access::TxDataFrames(*mux) == 0, "ack not in the DRR data queue");
}

void TestCompatReorderHardCapClosesSession() {
    auto mux = MakeMux();
    constexpr std::size_t frame_size = 9;
    vmux::vmux_net_test_access::ConfigureCompat(*mux, 1000, frame_size);

    Require(vmux::vmux_net_test_access::InjectCompatFrame(*mux, 3, 1, 11000), "first future frame");
    Require(vmux::vmux_net_test_access::CompatReorderSize(*mux) == 1, "first frame fits cap");
    Require(vmux::vmux_net_test_access::InjectCompatFrame(*mux, 4, 1, 11001), "soft overflow");
    Require(vmux::vmux_net_test_access::CompatReorderSize(*mux) == 2, "within hard bound");
    Require(vmux::vmux_net_test_access::InjectCompatFrame(*mux, 5, 1, 11002), "hard overflow schedules close");
    auto ctx = mux->get_context();
    Require(static_cast<bool>(ctx), "ctx");
    ctx->poll();
    ctx->restart();
    Require(vmux::vmux_net_test_access::IsDisposed(*mux), "compat reorder hard overflow must close session");
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
    Require(vmux::vmux_net_test_access::InjectPush(*mux, 2, 3, payload, 20, 5003), "cid2 over soft session cap");
    // Soft cap: buffered with backpressure, nobody is reset yet.
    Require(vmux::vmux_net_test_access::FlowExists(*mux, 1), "soft session cap keeps cid1");
    Require(vmux::vmux_net_test_access::FlowExists(*mux, 2), "soft session cap keeps cid2");
    auto skt3 = vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, 3);
    Require(vmux::vmux_net_test_access::InjectPush(*mux, 3, 1, p1, 1, 5004), "cid3 dsn1");
    Require(vmux::vmux_net_test_access::InjectPush(*mux, 3, 3, payload, 20, 5005), "cid3 triggers hard session cap");
    // Oldest gapped flow (cid1) must be failed; session must remain within the hard bound.
    Require(!vmux::vmux_net_test_access::FlowExists(*mux, 1), "oldest gap flow failed on hard session cap");
    Require(vmux::vmux_net_test_access::SessionReorderBytes(*mux) <= 80, "session reorder bounded by hard cap");
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

void TestCtrlSendFailureKeepsFrameAndSession() {
    // A carrier that refuses the write (here: no transport) must not fail the
    // session; the control frame waits for the next carrier.
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000);
    auto dead = vmux::vmux_net_test_access::MakeDeadLink(true);
    vmux::vmux_net_test_access::AttachLink(*mux, dead);
    vmux::vmux_net_test_access::EmplaceCtrlFrame(*mux, 1);
    Require(vmux::vmux_net_test_access::ProcessTxAll(*mux), "ctrl drain must not fail on a refusing carrier");
    Require(vmux::vmux_net_test_access::CtrlQueueSize(*mux) == 1, "control frame kept for the next carrier");
    Require(!vmux::vmux_net_test_access::IsDisposed(*mux), "session stays up");
    vmux::vmux_net_test_access::ClearTxQueue(*mux);
}

void TestStaleXonDoesNotOverrideNewerXoff() {
    // flow_v2: XON/XOFF are unordered control frames and may overtake each
    // other across carriers. XOFF v2 then a late XON v1 must leave the stream
    // stopped (applying the XON here would also close this transport-less skt).
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000);
    auto skt = vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, 31);
    Require(vmux::vmux_net_test_access::InjectAcceleration(*mux, 31, false, 2, 18000), "xoff v2");
    Require(!vmux::vmux_net_test_access::SktTxAcceleration(*mux, *skt), "xoff applied");
    Require(vmux::vmux_net_test_access::InjectAcceleration(*mux, 31, true, 1, 18001), "stale xon v1");
    Require(!vmux::vmux_net_test_access::SktTxAcceleration(*mux, *skt), "stale xon ignored");
    Require(!vmux::vmux_net_test_access::SktDisposed(*mux, *skt), "skt untouched by the stale frame");
    // A legacy (unversioned) XOFF from an older peer still applies.
    Require(vmux::vmux_net_test_access::InjectAcceleration(*mux, 31, false, -1, 18002), "legacy xoff");
    Require(!vmux::vmux_net_test_access::SktTxAcceleration(*mux, *skt), "legacy xoff applied");
}

void TestCompatSequenceFollowsSendOrder() {
    // DRR serves cid1 A1..A8 (visit cap), then cid2 B1, then A9. With numbers
    // assigned at enqueue that was seq ...7, 9, 8: reordering on one carrier.
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureCompat(*mux, 1000);
    const std::uint32_t first = vmux::vmux_net_test_access::TxSeq(*mux);
    for (int i = 0; i < 9; ++i) {
        Require(vmux::vmux_net_test_access::PostPush(*mux, 41, 100), "post cid41");
    }
    Require(vmux::vmux_net_test_access::PostPush(*mux, 42, 100), "post cid42");
    Require(vmux::vmux_net_test_access::TxSeq(*mux) == first, "nothing numbered before it is sent");
    const auto seqs = vmux::vmux_net_test_access::PopAndAssignSeqs(*mux, 10);
    Require(seqs.size() == 10, "all ten frames popped");
    for (std::size_t i = 0; i < seqs.size(); ++i) {
        Require(seqs[i] == first + (std::uint32_t)i, "global sequence is contiguous in send order");
    }
}

void TestTxLinkListingIsUniqueAndBudgeted() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureCompat(*mux, 1000);
    auto a = vmux::vmux_net_test_access::MakeDeadLink(true);
    auto b = vmux::vmux_net_test_access::MakeDeadLink(true);
    vmux::vmux_net_test_access::OfferLink(*mux, a);
    vmux::vmux_net_test_access::OfferLink(*mux, a);
    Require(vmux::vmux_net_test_access::FreeTxLinkCount(*mux) == 1, "offering twice lists once");
    vmux::vmux_net_test_access::SetQueuedBytes(b, (std::size_t)PPP_MUX_LINK_BYTE_HIGH_WATER);
    vmux::vmux_net_test_access::OfferLink(*mux, b);
    Require(vmux::vmux_net_test_access::FreeTxLinkCount(*mux) == 1, "a carrier at its byte budget is not listed");
    vmux::vmux_net_test_access::SetQueuedBytes(b, 1000);
    vmux::vmux_net_test_access::OfferLink(*mux, b);
    Require(vmux::vmux_net_test_access::FreeTxLinkCount(*mux) == 2, "listed once it has room");
    vmux::vmux_net_test_access::SetQueuedBytes(a, 5000);
    Require(vmux::vmux_net_test_access::PickLink(*mux, 100) == b, "least bytes in flight wins");
    vmux::vmux_net_test_access::WithdrawLink(*mux, b);
    vmux::vmux_net_test_access::WithdrawLink(*mux, b);
    Require(vmux::vmux_net_test_access::FreeTxLinkCount(*mux) == 1, "withdraw is idempotent");
    Require(vmux::vmux_net_test_access::PickLink(*mux, 100) == a, "only listed carriers are picked");
    vmux::vmux_net_test_access::ClearTxQueue(*mux);
}

void TestIdleCarriersTakeTurns() {
    // Field test: with "least bytes in flight" alone every idle tie went to the
    // first carrier, so request/response frames queued behind each other on one
    // TCP connection under Nagle (+1 RTT each). Equal loads must rotate.
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureCompat(*mux, 1000);
    auto a = vmux::vmux_net_test_access::MakeDeadLink(true);
    auto b = vmux::vmux_net_test_access::MakeDeadLink(true);
    auto c = vmux::vmux_net_test_access::MakeDeadLink(true);
    vmux::vmux_net_test_access::OfferLink(*mux, a);
    vmux::vmux_net_test_access::OfferLink(*mux, b);
    vmux::vmux_net_test_access::OfferLink(*mux, c);
    auto p1 = vmux::vmux_net_test_access::PickLink(*mux, 100);
    auto p2 = vmux::vmux_net_test_access::PickLink(*mux, 100);
    auto p3 = vmux::vmux_net_test_access::PickLink(*mux, 100);
    Require(p1 != p2 && p2 != p3 && p1 != p3, "idle carriers take turns");
    Require(vmux::vmux_net_test_access::PickLink(*mux, 100) == p1, "round robin wraps");
    vmux::vmux_net_test_access::SetQueuedBytes(p2, 9000);
    vmux::vmux_net_test_access::SetQueuedBytes(p3, 9000);
    Require(vmux::vmux_net_test_access::PickLink(*mux, 100) == p1, "load still wins over rotation");
    vmux::vmux_net_test_access::ClearTxQueue(*mux);
}

void TestFlowReorderCountersStayInStep() {
    // flow_v2 used to bump only the session counter on insert and drain it on
    // delivery, while fail_flow drained both: the counters drifted apart.
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 64 * 1024, 1000);
    auto skt = vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, 51);
    auto skt2 = vmux::vmux_net_test_access::InstallQueueOnlySkt(mux, 52);
    const char p[] = "xyz";
    Require(vmux::vmux_net_test_access::InjectPush(*mux, 51, 2, p, 3, 19000), "buffer dsn2");
    Require(vmux::vmux_net_test_access::InjectPush(*mux, 52, 3, p, 3, 19001), "buffer cid52 dsn3");
    Require(vmux::vmux_net_test_access::SessionReorderBytes(*mux) > 0, "bytes buffered");
    Require(vmux::vmux_net_test_access::AggregateReorderBytes(*mux) ==
            vmux::vmux_net_test_access::SessionReorderBytes(*mux), "insert keeps counters equal");
    Require(vmux::vmux_net_test_access::InjectPush(*mux, 51, 1, p, 3, 19002), "dsn1 drains cid51");
    Require(vmux::vmux_net_test_access::AggregateReorderBytes(*mux) ==
            vmux::vmux_net_test_access::SessionReorderBytes(*mux), "delivery keeps counters equal");
    vmux::vmux_net_test_access::FailFlow(*mux, 52, "test");
    Require(vmux::vmux_net_test_access::SessionReorderBytes(*mux) == 0, "all drained");
    Require(vmux::vmux_net_test_access::AggregateReorderBytes(*mux) == 0, "aggregate drained too");
}

void FillFlowToCap(vmux::vmux_net& mux, std::uint32_t cid) {
    // 16 frames of ~64 KiB (1,040,144 bytes) fit the 1 MiB per-flow TX cap;
    // a 17th does not.
    for (int i = 0; i < 16; ++i) {
        vmux::vmux_net_test_access::EmplaceDataFrame(mux, cid, 65000);
    }
}

void TestCompatTxFlowOverflowFailsInsteadOfDropping() {
    // compat: the frame's global sequence is assigned before enqueue, so a
    // silent drop left a permanent hole. Overflow must now be reported.
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureCompat(*mux, 1000);
    FillFlowToCap(*mux, 21);
    const std::size_t before = vmux::vmux_net_test_access::TxFlowFrames(*mux, 21);
    Require(!vmux::vmux_net_test_access::PostPush(*mux, 21, 65000), "compat overflow reports failure");
    Require(vmux::vmux_net_test_access::TxFlowFrames(*mux, 21) == before, "rejected frame not queued");
    vmux::vmux_net_test_access::ClearTxQueue(*mux);
}

void TestFlowV2TxFlowOverflowResetsOnlyThatFlow() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000);
    FillFlowToCap(*mux, 22);
    vmux::vmux_net_test_access::EmplaceDataFrame(*mux, 23, 100);
    Require(vmux::vmux_net_test_access::PostPush(*mux, 22, 65000), "flow_v2 overflow keeps the session");
    Require(vmux::vmux_net_test_access::TxFlowFrames(*mux, 22) == 0, "overflowing flow reset");
    Require(vmux::vmux_net_test_access::TxFlowFrames(*mux, 23) == 1, "other flow untouched");
    Require(!vmux::vmux_net_test_access::IsDisposed(*mux), "session stays up");
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

void TestTxFlowDrrSendsFrameLargerThanQuantumImmediately() {
    // Field bug (2026-10-18): a ~64 KiB push frame is larger than the 16 KiB
    // DRR quantum. drr_pop_next scanned one cycle, found no flow with enough
    // deficit and returned false, so the frame waited for unrelated events to
    // add one quantum each (seconds per frame on a quiet uplink).
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000);
    const int big_payload = 65526 - 1; // just under max_buffers_size
    Require(big_payload > PPP_MUX_TX_FLOW_QUANTUM_BYTES, "frame must exceed one quantum");
    vmux::vmux_net_test_access::EmplaceDataFrame(*mux, 7, big_payload);
    Require(vmux::vmux_net_test_access::PopTxCid(*mux) == 7, "oversized head frame pops on the first call");

    // Several flows each holding one oversized frame: every one drains, one per call.
    for (std::uint32_t cid = 11; cid <= 14; ++cid) {
        vmux::vmux_net_test_access::EmplaceDataFrame(*mux, cid, big_payload);
    }
    int popped = 0;
    for (int i = 0; i < 4; ++i) {
        popped += vmux::vmux_net_test_access::PopTxCid(*mux) != 0 ? 1 : 0;
    }
    Require(popped == 4, "each oversized frame pops without an external re-drive");
    Require(vmux::vmux_net_test_access::PopTxCid(*mux) == 0, "queue empty afterwards");
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

void TestExitedCarrierIsNotListedAgain() {
    // A write that was in flight when its carrier exited still completes. The
    // completion used to list the dead carrier for new frames again.
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000);
    auto dead = vmux::vmux_net_test_access::MakeDeadLink(true);
    auto live = vmux::vmux_net_test_access::MakeDeadLink(true);
    vmux::vmux_net_test_access::AttachLink(*mux, dead);
    vmux::vmux_net_test_access::AttachLink(*mux, live);

    vmux::vmux_net_test_access::OnLinkExit(*mux, dead, "write_failed");
    vmux::vmux_net_test_access::OfferLink(*mux, dead); // late completion
    Require(vmux::vmux_net_test_access::FreeTxLinkCount(*mux) == 1, "exited carrier stays unlisted");
    Require(vmux::vmux_net_test_access::PickLink(*mux, 64) == live, "frames go to the survivor");
    Require(dead->drain_.retiring(), "an exited carrier is retiring");
}

void TestDuplicateLinkExitIsIgnored() {
    // A failed write and the end of the carrier's forwarding loop both report
    // the same exit; the second report must not act again.
    auto mux = MakeMux();
    vmux::vmux_net_test_access::EnableCompatReliability(*mux, false);
    auto a = vmux::vmux_net_test_access::MakeDeadLink(true);
    auto b = vmux::vmux_net_test_access::MakeDeadLink(true);
    a->id_ = 3;
    b->id_ = 4;
    vmux::vmux_net_test_access::AttachLink(*mux, a);
    vmux::vmux_net_test_access::AttachLink(*mux, b);
    Require(vmux::vmux_net_test_access::TrackSentCompat(*mux, 1, 3, 16000), "seq1 on carrier a");

    vmux::vmux_net_test_access::OnLinkExit(*mux, a, "write_failed");
    vmux::vmux_net_test_access::OnLinkExit(*mux, a, "forwarding_end");
    Require(!vmux::vmux_net_test_access::IsDisposed(*mux), "survivor keeps the session");
    Require(vmux::vmux_net_test_access::LiveCarriers(*mux) == 1, "one carrier left");
    Require(vmux::vmux_net_test_access::RxLinkCount(*mux) == 1, "exited carrier removed once");
    Require(vmux::vmux_net_test_access::PendingRtx(*mux) == 1, "in-flight frame scheduled once");
}

void TestLateCallsAfterSessionCloseAreHarmless() {
    // Session teardown while work is outstanding on the last carrier: queued
    // data, unacked frames, a paused receive side. Write completions, the
    // forwarding exit and timers that arrive afterwards must not touch
    // scheduler state (run under ASan to catch use-after-free).
    auto mux = MakeMux();
    vmux::vmux_net_test_access::EnableCompatReliability(*mux, false);
    auto only = vmux::vmux_net_test_access::MakeDeadLink(true);
    only->id_ = 7;
    vmux::vmux_net_test_access::AttachLink(*mux, only);
    vmux::vmux_net_test_access::EmplaceDataFrame(*mux, 9, 512);
    vmux::vmux_net_test_access::EmplaceDataFrame(*mux, 9, 512);
    Require(vmux::vmux_net_test_access::TrackSentCompat(*mux, 1, 7, 17000), "seq1 in flight");
    Require(vmux::vmux_net_test_access::TrackSentCompat(*mux, 2, 7, 17001), "seq2 in flight");

    vmux::vmux_net_test_access::OnLinkExit(*mux, only, "write_failed");
    DrainContext(mux);
    Require(vmux::vmux_net_test_access::IsDisposed(*mux), "last carrier closes the session");

    vmux::vmux_net_test_access::LateTeardownCalls(*mux, only, 17100);
    DrainContext(mux);
    Require(vmux::vmux_net_test_access::IsDisposed(*mux), "still disposed");
    Require(vmux::vmux_net_test_access::FreeTxLinkCount(*mux) == 0, "nothing listed after close");
    Require(vmux::vmux_net_test_access::RxLinkCount(*mux) == 0, "no carriers after close");
    Require(vmux::vmux_net_test_access::PendingRtx(*mux) == 0, "no retransmissions after close");
    Require(vmux::vmux_net_test_access::PausedLinkCount(*mux) == 0, "no paused carriers after close");
    Require(vmux::vmux_net_test_access::TxDataFrames(*mux) == 0, "queued data dropped with the session");
}

void TestPausedCarrierExitReleasesPause() {
    // A carrier that exits while its receive side is paused must not stay on
    // the paused list (the survivors would otherwise be held by its count).
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux, 1024, 1000);
    auto a = vmux::vmux_net_test_access::MakeDeadLink(true);
    auto b = vmux::vmux_net_test_access::MakeDeadLink(true);
    auto c = vmux::vmux_net_test_access::MakeDeadLink(true);
    vmux::vmux_net_test_access::AttachLink(*mux, a);
    vmux::vmux_net_test_access::AttachLink(*mux, b);
    vmux::vmux_net_test_access::AttachLink(*mux, c);
    vmux::vmux_net_test_access::PauseRx(*mux, a);
    Require(vmux::vmux_net_test_access::IsRxPaused(a), "a paused");

    vmux::vmux_net_test_access::OnLinkExit(*mux, a, "forwarding_end");
    Require(!vmux::vmux_net_test_access::IsRxPaused(a), "exit clears the pause");
    Require(vmux::vmux_net_test_access::PausedLinkCount(*mux) == 0, "exit forgets the paused carrier");
    vmux::vmux_net_test_access::PauseRx(*mux, a);
    Require(vmux::vmux_net_test_access::PausedLinkCount(*mux) == 0, "an exited carrier is never paused again");
}

int main() {
    try {
        TestTxFlowDrrPrefersOtherCidAfterQuantum();
        TestTxFlowDrrDrainsBytesWithinQuantumBeforeRotating();
        TestTxFlowDrrSendsFrameLargerThanQuantumImmediately();
        TestInOrderStillDelivers();
        TestFirstObservedFutureDsnWaitsForDsnOne();
        TestGapTimeoutResetsFlowWithoutHoleDelivery();
        TestReorderOverflowResetsFlow();
        TestFlowSoftCapPausesDeliveringCarrier();
        TestFrameOversizeResetsFlow();
        TestCompatOooRefreshesActivity();
        TestCompatGapTimeoutClosesSession();
        TestCompatGapClockRestartsOnProgress();
        TestCompatReorderSoftCapPausesInsteadOfClosing();
        TestCompatSinglePausedCarrierIsReleased();
        TestCompatReorderHardCapClosesSession();
        TestFastRetransmitOffByDefaultIgnoresDupAckHoles();
        TestLinkExitReinjectsInflightFrames();
        TestRtxWindowHoldsFrameUntilAck();
        TestRtxWindowOnlyHardCapClosesCompatSession();
        TestRtxFlowWindowParksOnlyThatFlow();
        TestCompatAckFramesBypassParkedData();
        TestUnknownCidDoesNotGrowFlowsUnbounded();
        TestInitiatorOpenBarrierBlocksPush();
        TestSessionReorderCapResetsFlow();
        TestMaxOpenFlowsEnforced();
        TestCtrlBudgetDoesNotDrainAll();
        TestCtrlSendFailureKeepsFrameAndSession();
        TestStaleXonDoesNotOverrideNewerXoff();
        TestCompatSequenceFollowsSendOrder();
        TestFlowReorderCountersStayInStep();
        TestIdleCarriersTakeTurns();
        TestTxLinkListingIsUniqueAndBudgeted();
        TestCompatTxFlowOverflowFailsInsteadOfDropping();
        TestFlowV2TxFlowOverflowResetsOnlyThatFlow();
        TestLinkExitIsolatesWhenOthersLive();
        TestLinkExitClosesWhenLast();
        TestExitedCarrierIsNotListedAgain();
        TestDuplicateLinkExitIsIgnored();
        TestLateCallsAfterSessionCloseAreHarmless();
        TestPausedCarrierExitReleasesPause();
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
