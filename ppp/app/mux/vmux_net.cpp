#include "vmux.h"
#include "vmux_net.h"
#include "vmux_skt.h"
#include <ppp/configurations/AppConfiguration.h>
#include <chrono>
#include <openssl/crypto.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>

#include "ppp/collections/Dictionary.h"

/**
 * @file vmux_net.cpp
 * @brief Implements vmux network multiplexing, handshake, and packet forwarding.
 * @license GPL-3.0
 */

namespace vmux {
    /**
     * @brief Parses a textual MUX scheduler mode.
     */
    vmux_net::mux_mode vmux_net::parse_mode(const ppp::string& mode) noexcept {
        ppp::string value = ppp::ToLower<ppp::string>(ppp::LTrim(ppp::RTrim(mode)));
        if (value == "flow" || value == "flow-v1" || value == "primary" || value == "primary-link") {
            return mux_mode_flow;
        }

        if (value == "balance" || value == "balanced" || value == "lb" || value == "load-balance") {
            return mux_mode_balance;
        }

        if (value == "stripe" || value == "striped" || value == "striping") {
            return mux_mode_stripe;
        }

        return mux_mode_compat;
    }

    /**
     * @brief Maps a wire mode byte to a valid scheduler mode.
     * @return The mode for known values; mux_mode_compat for anything else.
     */
    vmux_net::mux_mode vmux_net::parse_mode_byte(Byte mode_value) noexcept {
        switch (mode_value) {
        case mux_mode_flow:
            return mux_mode_flow;
        case mux_mode_balance:
            return mux_mode_balance;
        case mux_mode_stripe:
            return mux_mode_stripe;
        default:
            return mux_mode_compat;
        }
    }

    /**
     * @brief Returns the stable text name for a scheduler mode.
     */
    const char* vmux_net::mode_name(mux_mode mode) noexcept {
        switch (mode) {
        case mux_mode_flow:
            return "flow";
        case mux_mode_balance:
            return "balance";
        case mux_mode_stripe:
            return "stripe";
        default:
            return "compat";
        }
    }

    /**
     * @brief Switches the active scheduler mode at runtime.
     * @details Must run on the vmux strand. Resets per-mode scheduling state
     *          (primary link, affinity map, stripe cursor) so the next drain
     *          re-picks links under the new policy.
     */
    void vmux_net::set_mode(mux_mode mode) noexcept {
        mux_mode normalized = mode;
        switch (normalized) {
        case mux_mode_flow:
        case mux_mode_balance:
        case mux_mode_stripe:
            break;
        default:
            normalized = mux_mode_compat;
            break;
        }

        if (mode_ == normalized) {
            return;
        }

        mode_ = normalized;
        {
            std::lock_guard<std::mutex> scope(runtime_state_mutex_);
            runtime_state_.effective_mode = mode_name(mode_);
            ppp::app::mux::FillMuxPresentation(runtime_state_);
            publish_runtime_snapshot_locked();
        }
        stripe_cursor_ = 0;
        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "scheduler mode switched to %s", mode_name(mode_));
    }

    /**
     * @brief Applies the negotiated receiver ordering mode (flow v2).
     * @details Effective only before the session is established (no hot switch
     *          between compat and flow-v2). Also latches the per-connection
     *          reorder bounds from AppConfiguration when entering flow-v2.
     */
    void vmux_net::set_ordering_mode(receiver_ordering_mode m) noexcept {
        if (base_.established_) {
            return; // session-level, immutable after establishment.
        }

        receiver_ordering_mode normalized = (m == ordering_flow_v2) ? ordering_flow_v2 : ordering_compat;
        ordering_mode_ = normalized;
        {
            std::lock_guard<std::mutex> scope(runtime_state_mutex_);
            runtime_state_.receiver_ordering = normalized == ordering_flow_v2 ? "flow_v2" : "compat";
        }

        // Latch send-side backpressure / watchdog bounds from config (applies to
        // all modes; AppConfiguration is set by the exchanger before establishment).
        if (NULLPTR != AppConfiguration) {
            int qmax = AppConfiguration->mux.tx.queue.max;
            int qstall = AppConfiguration->mux.tx.queue.stall;
            tx_queue_high_water_ = (qmax > 0) ? (size_t)qmax : (size_t)PPP_MUX_TX_QUEUE_HIGH_WATER;
            tx_backlog_stall_ms_ = (qstall > 0) ? (uint64_t)qstall : (uint64_t)PPP_MUX_TX_BACKLOG_STALL_TIMEOUT;
            // flow turbo: only meaningful under flow mode; harmless to latch always.
            turbo_ = AppConfiguration->mux.turbo && (mode_ == mux_mode_flow);
            {
                std::lock_guard<std::mutex> scope(runtime_state_mutex_);
                runtime_state_.turbo = turbo_;
                ppp::app::mux::FillMuxPresentation(runtime_state_);
                publish_runtime_snapshot_locked();
            }
        }

        // Latch gap-timeout for both ordering modes (flow_v2 per-flow; compat global).
        {
            int timeout_ms = (NULLPTR != AppConfiguration) ? AppConfiguration->mux.flow.reorder.timeout : 0;
            flow_reorder_timeout_ = (timeout_ms > 0) ? (uint64_t)timeout_ms : (uint64_t)PPP_MUX_FLOW_REORDER_TIMEOUT;
        }
        {
            int session_cap = (NULLPTR != AppConfiguration) ? AppConfiguration->mux.flow.session_reorder.bytes : 0;
            session_reorder_cap_bytes_ = (session_cap > 0) ? (size_t)session_cap : (size_t)PPP_MUX_FLOW_SESSION_REORDER_BYTES;
            int max_open = (NULLPTR != AppConfiguration) ? AppConfiguration->mux.flow.max_open : 0;
            max_open_flows_ = (max_open > 0) ? (size_t)max_open : (size_t)PPP_MUX_FLOW_MAX_OPEN;
            int ctrl_budget = (NULLPTR != AppConfiguration) ? AppConfiguration->mux.tx.ctrl.budget_frames : 0;
            tx_ctrl_budget_frames_ = (ctrl_budget > 0) ? (size_t)ctrl_budget : (size_t)PPP_MUX_TX_CTRL_BUDGET_FRAMES;
        }
        if (normalized == ordering_flow_v2) {
            // Latch bounded-reorder byte cap from config; fall back to safe defaults.
            int cap_bytes = (NULLPTR != AppConfiguration) ? AppConfiguration->mux.flow.reorder.bytes : 0;
            flow_reorder_cap_bytes_ = (cap_bytes > 0) ? (size_t)cap_bytes : (size_t)PPP_MUX_FLOW_REORDER_BYTES;
            flow_context_cap_ = (size_t)PPP_MUX_FLOW_MAX_CONTEXTS;
            flow_aggregate_cap_bytes_ = (size_t)PPP_MUX_FLOW_AGGREGATE_BYTES;
            if (flow_aggregate_cap_bytes_ < flow_reorder_cap_bytes_) {
                flow_aggregate_cap_bytes_ = flow_reorder_cap_bytes_;
            }
            if (session_reorder_cap_bytes_ > 0 && session_reorder_cap_bytes_ < flow_aggregate_cap_bytes_) {
                flow_aggregate_cap_bytes_ = session_reorder_cap_bytes_;
            }
        }

        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "ordering mode=%s",
            normalized == ordering_flow_v2 ? "flow-v2" : "compat");
    }

    void vmux_net::apply_negotiation(bool local_supports_flow_v2, bool peer_supports_flow_v2, bool local_reliability, bool peer_reliability, bool local_fec, bool peer_fec) noexcept {
        ppp::app::mux::MuxRuntimeState state;
        {
            std::lock_guard<std::mutex> scope(runtime_state_mutex_);
            // turbo_ may already be latched from config; include it so flow+turbo
            // negotiates ordering correctly and presentation shows adaptive pool.
            state = ppp::app::mux::NegotiateMuxRuntimeState(
                runtime_state_.requested_mode,
                local_supports_flow_v2,
                peer_supports_flow_v2,
                runtime_state_.active_links,
                turbo_ || runtime_state_.turbo,
                local_reliability,
                peer_reliability,
                local_fec,
                peer_fec);
            runtime_state_ = state;
            publish_runtime_snapshot_locked();
        }
        set_mode(parse_mode(ppp::string(state.effective_mode.data(), state.effective_mode.size())));
        set_ordering_mode(state.receiver_ordering == "flow_v2" ? ordering_flow_v2 : ordering_compat);
        latch_reliability(state.reliability, state.fec);
        // Keep presentation fields in sync after ordering/turbo latch.
        {
            std::lock_guard<std::mutex> scope(runtime_state_mutex_);
            runtime_state_.turbo = turbo_;
            ppp::app::mux::FillMuxPresentation(runtime_state_);
            publish_runtime_snapshot_locked();
        }
    }

    void vmux_net::apply_agreed_ordering(bool agreed_flow_v2, bool agreed_reliability, bool agreed_fec) noexcept {
        ppp::app::mux::MuxRuntimeState state;
        {
            std::lock_guard<std::mutex> scope(runtime_state_mutex_);
            state = ppp::app::mux::ApplyAgreedMuxRuntimeState(
                runtime_state_.requested_mode,
                agreed_flow_v2,
                runtime_state_.active_links,
                turbo_ || runtime_state_.turbo,
                agreed_reliability,
                agreed_fec);
            runtime_state_ = state;
            publish_runtime_snapshot_locked();
        }

        set_mode(parse_mode(ppp::string(state.effective_mode.data(), state.effective_mode.size())));
        set_ordering_mode(state.receiver_ordering == "flow_v2"
            ? ordering_flow_v2
            : ordering_compat);
        latch_reliability(state.reliability, state.fec);
        {
            std::lock_guard<std::mutex> scope(runtime_state_mutex_);
            runtime_state_.turbo = turbo_;
            ppp::app::mux::FillMuxPresentation(runtime_state_);
            publish_runtime_snapshot_locked();
        }
    }

    ppp::app::mux::MuxRuntimeState vmux_net::get_runtime_state() const noexcept {
        // Prefer lock-free snapshot published on the vmux strand (P2-5).
        if (auto snap = std::atomic_load_explicit(&runtime_snapshot_, std::memory_order_acquire)) {
            return *snap;
        }
        // Cold path: first read before any publish, or mid-construction.
        std::lock_guard<std::mutex> scope(runtime_state_mutex_);
        ppp::app::mux::MuxRuntimeState state = runtime_state_;
        state.turbo = turbo_;
        if (state.effective_mode.empty()) {
            state.effective_mode = mode_name(mode_);
        }
        ppp::app::mux::FillMuxPresentation(state);
        return state;
    }

    void vmux_net::refresh_runtime_active_links() noexcept {
        // Read-only container walk: safe without syncobj_ because container
        // mutations join the syncobj_ domain (see remove/reap/attach) and
        // handshake_complete_ is atomic, so the carrier handshake's store is
        // safely visible here.
        std::size_t active_links = 0;
        for (const vmux_linklayer_ptr& linklayer : rx_links_) {
            if (NULLPTR != linklayer && linklayer->schedulable()) {
                ++active_links;
            }
        }
        std::lock_guard<std::mutex> scope(runtime_state_mutex_);
        runtime_state_.active_links = static_cast<std::uint16_t>(
            std::min<std::size_t>(active_links, UINT16_MAX));
        publish_runtime_snapshot_locked();
    }

    /**
     * @brief Raises the carrier-link ceiling for turbo before establishment.
     */
    void vmux_net::set_pool_hard_max(uint16_t hard_max) noexcept {
        if (base_.established_) {
            return; // base/ceiling are fixed once the initial links are built.
        }

        if (hard_max < status_.max_connections) {
            hard_max = status_.max_connections;
        }

        status_.pool_hard_max = hard_max;
        // pool_current stays at the base until the controller moves it.
        if (status_.pool_current < status_.max_connections) {
            status_.pool_current = status_.max_connections;
        }
    }

    /**
     * @brief Consumes the turbo controller's pending grow request.
     */
    int vmux_net::take_turbo_pending_grow() noexcept {
        int n = turbo_pending_grow_;
        turbo_pending_grow_ = 0;
        return n;
    }

    /**
     * @brief Debug-only wire payload for cmd_mux_mode_set.
     *
     * Layout: [mode:1][key_len:1][key:key_len]. The key authorizes the change;
     * the receiver applies the mode only when the key matches its own non-empty
     * mux.debug.key. No new per-frame header field is introduced.
     */
    bool vmux_net::post_mux_mode_set(mux_mode mode) noexcept {
        if (NULLPTR == AppConfiguration) {
            return false;
        }

        const ppp::string& debug_key = AppConfiguration->mux.debug.key;
        if (debug_key.empty()) {
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "mux-mode-set ignored: no local debug key configured");
            return false;
        }

        size_t key_length = debug_key.size();
        if (key_length > 255) {
            key_length = 255;
        }

        ppp::vector<Byte> payload(2 + key_length);
        payload[0] = static_cast<Byte>(mode);
        payload[1] = static_cast<Byte>(key_length);
        if (key_length > 0) {
            memcpy(payload.data() + 2, debug_key.data(), key_length);
        }

        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "mux-mode-set requesting peer mode=%s", mode_name(mode));
        return post(cmd_mux_mode_set, payload.data(), static_cast<int>(payload.size()), 0);
    }

    using ppp::telemetry::Level;

    /**
     * @brief Constructs a vmux network core with runtime mode/capacity settings.
     */
    vmux_net::vmux_net(const ContextPtr& context, const StrandPtr strand, uint16_t max_connections, bool server_mode, bool acceleration, mux_mode mode) noexcept {
        assert(max_connections > 0 && "The value of max_connections must be greater than 0.");

        vmux_net* const m             = this;
        m->Vlan                       = 0;
   
        m->base_.server_or_client_    = server_mode;
        m->base_.disposed_.store(false, std::memory_order_release);
        m->base_.ftt_                 = false;
        m->base_.established_         = false;
        m->base_.acceleration_        = acceleration;
        
        m->status_.max_connections    = max_connections;
        m->status_.pool_hard_max      = max_connections; // raised by turbo via set_pool_hard_max() before establishment.
        m->status_.pool_current       = max_connections; // runtime target; equals base until the turbo controller moves it.
        m->status_.opened_connections = 0;

        m->status_.rx_ack_            = 0;
        m->status_.tx_seq_            = 0;

        m->mode_                      = mode;
        switch (m->mode_) {
        case mux_mode_flow:
        case mux_mode_balance:
        case mux_mode_stripe:
            break;
        default:
            m->mode_                  = mux_mode_compat;
            break;
        }
        m->runtime_state_.requested_mode = mode_name(m->mode_);
        m->runtime_state_.effective_mode = mode_name(m->mode_);
        m->runtime_state_.receiver_ordering = "compat";
        m->runtime_state_.turbo = false;
        ppp::app::mux::FillMuxPresentation(m->runtime_state_);
        m->runtime_snapshot_ = std::make_shared<const ppp::app::mux::MuxRuntimeState>(m->runtime_state_);

        ppp::telemetry::Log(Level::kInfo, "mux", "mode=%s", mode_name(m->mode_));
        uint64_t now                  = now_tick();
        m->status_.last_              = now;
        m->status_.last_heartbeat_    = now;
        m->status_.heartbeat_timeout_ = 0;

        m->context_                   = context;
        m->strand_                    = strand;
        if (NULLPTR != m->context_ && NULLPTR == m->strand_) {
            m->strand_ = ppp::make_shared_object<Strand>(m->context_->get_executor());
        }
        if (NULLPTR == m->context_ || NULLPTR == m->strand_) {
            m->base_.disposed_.store(true, std::memory_order_release);
            ppp::diagnostics::SetLastErrorCode(NULLPTR == m->context_
                ? ppp::diagnostics::ErrorCode::RuntimeIoContextMissing
                : ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
        }
    }

    vmux_net::tx_completion_ptr vmux_net::make_tx_completion(const PostInternalAsynchronousCallback& callback) noexcept {
        if (NULLPTR == callback) {
            return NULLPTR;
        }
        try {
            return ppp::make_shared_object<tx_completion>(callback);
        }
        catch (...) {
            return NULLPTR;
        }
    }

    bool vmux_net::track_tx_completion(const tx_completion_ptr& completion) noexcept {
        if (NULLPTR == completion) {
            return true;
        }

        bool accepted = false;
        {
            std::lock_guard<std::mutex> scope(tx_completion_mutex_);
            if (!close_requested_) {
                try {
                    pending_tx_completions_.emplace_back(completion);
                    accepted = true;
                }
                catch (...) {
                }
            }
        }

        if (!accepted) {
            completion->Finish(false);
        }
        return accepted;
    }

    void vmux_net::finish_tx_completion(const tx_completion_ptr& completion, bool successed) noexcept {
        if (NULLPTR == completion) {
            return;
        }

        {
            std::lock_guard<std::mutex> scope(tx_completion_mutex_);
            for (tx_completion_list::iterator it = pending_tx_completions_.begin(); it != pending_tx_completions_.end();) {
                if (*it == completion) {
                    it = pending_tx_completions_.erase(it);
                }
                else {
                    ++it;
                }
            }
        }
        completion->Finish(successed);
    }

    void vmux_net::finish_tx_completions(tx_completion_list& completions, bool successed) noexcept {
        while (!completions.empty()) {
            tx_completion_ptr completion = std::move(completions.front());
            completions.pop_front();
            if (NULLPTR != completion) {
                completion->Finish(successed);
            }
        }
    }

    void vmux_net::fail_pending_tx_completions() noexcept {
        tx_completion_list completions;
        {
            std::lock_guard<std::mutex> scope(tx_completion_mutex_);
            completions.swap(pending_tx_completions_);
        }
        finish_tx_completions(completions, false);
    }

    bool vmux_net::begin_close() noexcept {
        tx_completion_list completions;
        {
            std::lock_guard<std::mutex> scope(tx_completion_mutex_);
            if (close_requested_) {
                return false;
            }
            close_requested_ = true;
            completions.swap(pending_tx_completions_);
        }
        finish_tx_completions(completions, false);
        return true;
    }

    bool vmux_net::close_requested() const noexcept {
        std::lock_guard<std::mutex> scope(tx_completion_mutex_);
        return close_requested_;
    }

    /**
     * @brief Destroys the vmux network and releases runtime resources.
     */
    vmux_net::~vmux_net() noexcept {
        // A destructor can run on any thread; finalize() detects the missing
        // shared owner / stopped executor and tears down inline. close_exec()
        // remains the preferred early entry.
        finalize();
    }

    /**
     * @brief Finalizes queues, sockets, and linklayers, then marks disposed.
     */
    void vmux_net::finalize() noexcept {
        // Strand-affine teardown, always performed inline. Entries: on the vmux
        // strand (directly, or posted there by close_exec), the close_exec()
        // stopped-executor fallback, and the destructor -- in the latter two no
        // strand handler can run concurrently. Idempotent via disposed_.
        begin_close();
        vmux_linklayer_vector rx_links;
        rx_packet_ssqueue rx_queue;
        vmux_skt_map skts;
        std::shared_ptr<boost::asio::ip::tcp::resolver> tx_resolver;

        for (;;) {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            // Idempotent: all teardown state below is owned by this strand.
            if (base_.disposed_.load(std::memory_order_acquire)) {
                return;
            }
            base_.disposed_.store(true, std::memory_order_release);
            status_.last_ = now_tick();

            rx_links = std::move(rx_links_);
            const size_t residual_frames = tx_data_frames_;
            rx_queue = std::move(rx_queue_);

            // Early-ACK observability: residual data still queued when the session dies.
            if (residual_frames > 0) {
                ppp::telemetry::Count("mux.tx.residual.frames", (int64_t)residual_frames);
                ppp::telemetry::Gauge("mux.tx.residual.depth", (int64_t)residual_frames);
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux",
                    "finalize residual tx data frames=%u (local write may have been early-acked)",
                    (unsigned)residual_frames);
            }

            skts = std::move(skts_);
            skts_.clear();

            clear_flow_tx();
            tx_ctrl_queue_.clear();
            rx_queue_.clear();
            rx_links_.clear();
            refresh_runtime_active_links();
            tx_links_.clear();
            stripe_cursor_ = 0;
            flows_.clear();
            tx_flow_seq_.clear();

            // Reliability sub-protocol teardown: stop the maintenance timer and
            // drop all ACK / retransmit / FEC state with the session.
            if (NULLPTR != reliability_timer_) {
                reliability_timer_->cancel();
                reliability_timer_.reset();
            }
            rtx_.Clear();
            rtx_pending_.clear();
            ack_trackers_.clear();
            ack_pending_count_ = 0;
            ack_first_pending_tick_ = 0;
            srtt_ms_ = 0;
            fec_encoder_.Reset(now_tick());
            fec_groups_.clear();
            fec_frame_cache_.clear();
            fec_frame_cache_order_.clear();
            fec_frame_cache_bytes_ = 0;
            fec_flush_due_ = false;
            break;
        }

        for (const std::pair<uint32_t, vmux_skt_ptr>& kv : skts) {
            const vmux_skt_ptr& skt = kv.second;
            if (NULLPTR != skt) {
                // finalize() already owns the VMUX strand, so avoid another posted
                // close that could remain queued forever after an executor stop.
                skt->finalize();
            }
        }

        for (vmux_linklayer_ptr& linklayer : rx_links) {
            if (NULLPTR == linklayer) {
                continue;
            }
            ppp::telemetry::Log(Level::kInfo, "mux", "link close");
            ppp::telemetry::Count("mux.link.close", 1);

            IMuxTransportPtr& connection = linklayer->connection;
            if (NULLPTR != connection) {
                connection->Dispose();
            }
        }

        if (NULLPTR != tx_resolver) {
            vmux_post_exec(context_, strand_,
                [tx_resolver]() noexcept {
                    ppp::net::Socket::Cancel(*tx_resolver);
                });
        }
    }

    /** @brief Returns the first active linklayer connection, if available. */
    vmux_net::IMuxTransportPtr vmux_net::get_linklayer() noexcept {
        SynchronizationObjectScope __SCOPE__(syncobj_);
        vmux_linklayer_vector::iterator tail = rx_links_.begin();
        vmux_linklayer_vector::iterator endl = rx_links_.end();
        return tail != endl ? (*tail)->connection : NULLPTR;
    }

    /** @brief Removes one link-layer endpoint from the scheduling containers; caller holds syncobj_. */
    void vmux_net::remove_linklayer_locked(const vmux_linklayer_ptr& linklayer) noexcept {
        for (vmux_linklayer_vector::iterator it = rx_links_.begin(); it != rx_links_.end();) {
            if (*it == linklayer) {
                it = rx_links_.erase(it);
            }
            else {
                ++it;
            }
        }

        for (vmux_linklayer_list::iterator it = tx_links_.begin(); it != tx_links_.end();) {
            if (*it == linklayer) {
                it = tx_links_.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    /** @brief Removes one link-layer endpoint from receive/transmit scheduling state. */
    void vmux_net::remove_linklayer(const vmux_linklayer_ptr& linklayer) noexcept {
        if (NULLPTR == linklayer) {
            return;
        }

        {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            remove_linklayer_locked(linklayer);
        }
        refresh_runtime_active_links();
    }

    size_t vmux_net::count_live_carriers(const vmux_linklayer_ptr& except) const noexcept {
        // Read-only walk: handshake_complete_ is atomic; container mutations are
        // strand-side and join the syncobj_ domain (see remove/reap/attach).
        size_t live = 0;
        for (const vmux_linklayer_ptr& link : rx_links_) {
            if (NULLPTR == link || link == except) {
                continue;
            }
            if (link->schedulable()) {
                ++live;
            }
        }
        return live;
    }

    bool vmux_net::link_has_byte_credit(const vmux_linklayer_ptr& linklayer, int packet_length) noexcept {
        if (NULLPTR == linklayer || packet_length < 0) {
            return false;
        }
        const size_t hw = (size_t)PPP_MUX_LINK_BYTE_HIGH_WATER;
        const size_t need = (size_t)packet_length;
        if (need > hw) {
            return linklayer->queued_bytes_ == 0; // allow one oversize frame if idle
        }
        return linklayer->queued_bytes_ + need <= hw;
    }

    void vmux_net::on_link_exit(const vmux_linklayer_ptr& linklayer, const char* reason) noexcept {
        if (base_.disposed_.load(std::memory_order_acquire)) {
            return;
        }

        const char* why = (reason != NULLPTR && reason[0] != '\0') ? reason : "unspecified";
        const size_t remaining = count_live_carriers(linklayer);

        remove_linklayer(linklayer);
        if (NULLPTR != linklayer && NULLPTR != linklayer->connection) {
            linklayer->connection->Dispose();
        }

        if (remaining == 0) {
            ppp::telemetry::Count("mux.link.exit.session", 1);
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux",
                "last carrier exit reason=%s; closing session", why);
            close_exec();
            return;
        }

        ppp::telemetry::Count("mux.link.exit.isolated", 1);
        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux",
            "carrier exit isolated reason=%s remaining=%u", why, (unsigned)remaining);
        process_tx_all_packets();
    }

    size_t vmux_net::tx_data_depth() const noexcept {
        return tx_data_frames_;
    }

    size_t vmux_net::tx_data_bytes() const noexcept {
        return tx_data_bytes_total_;
    }

    void vmux_net::enqueue_flow_tx(uint32_t connection_id, tx_packet&& packet) noexcept {
        // connection_id 0 is session control; data frames use non-zero cids.
        // Still route cid=0 through DRR as a single "control-data" bucket if needed.
        flow_tx_context& fx = tx_flows_[connection_id];
        const size_t nbytes = packet.length > 0 ? (size_t)packet.length : 0;
        // Per-flow TX quota: a single slow consumer cannot monopolize the session
        // TX budget. When the per-flow frame or byte cap is exceeded, fail only
        // this flow rather than degrading the entire session.
        if (fx.queue.size() >= (size_t)PPP_MUX_TX_FLOW_MAX_FRAMES ||
            fx.bytes + nbytes > (size_t)PPP_MUX_TX_FLOW_MAX_BYTES) {
            ppp::telemetry::Count("mux.tx.flow_overflow", 1);
            if (ordering_mode_ == ordering_flow_v2) {
                fail_flow(connection_id, "tx_flow_overflow");
            }
            return;
        }
        fx.queue.emplace_back(std::move(packet));
        fx.bytes += nbytes;
        tx_data_frames_++;
        tx_data_bytes_total_ += nbytes;
        if (!fx.active) {
            fx.active = true;
            fx.deficit = 0;
            fx.quantum_due = true;
            active_tx_flows_.emplace_back(connection_id);
        }
    }

    void vmux_net::clear_flow_tx() noexcept {
        tx_flows_.clear();
        active_tx_flows_.clear();
        tx_data_frames_ = 0;
        tx_data_bytes_total_ = 0;
    }

    void vmux_net::drr_requeue_front(tx_packet&& packet) noexcept {
        const uint32_t cid = peek_connection_id(packet.buffer, packet.length);
        flow_tx_context& fx = tx_flows_[cid];
        const size_t nbytes = packet.length > 0 ? (size_t)packet.length : 0;
        fx.queue.emplace_front(std::move(packet));
        fx.bytes += nbytes;
        tx_data_frames_++;
        tx_data_bytes_total_ += nbytes;
        fx.deficit += static_cast<int64_t>(nbytes);
        fx.quantum_due = false;
        fx.visit_count = 0;
        if (!fx.active) {
            fx.active = true;
            // Do not reset deficit — preserve remaining credit for this round.
            active_tx_flows_.emplace_front(cid);
        }
    }

    bool vmux_net::drr_pop_next(tx_packet& out) noexcept {
        if (active_tx_flows_.empty()) {
            return false;
        }

        const size_t quantum = (size_t)PPP_MUX_TX_FLOW_QUANTUM_BYTES;
        const size_t q = quantum > 0 ? quantum : (size_t)1;
        const size_t n = active_tx_flows_.size();

        // Walk at most one full cycle of the active ring.
        for (size_t scanned = 0; scanned < n; ++scanned) {
            uint32_t cid = active_tx_flows_.front();
            active_tx_flows_.pop_front();

            auto it = tx_flows_.find(cid);
            if (it == tx_flows_.end() || it->second.queue.empty()) {
                if (it != tx_flows_.end()) {
                    it->second.active = false;
                    it->second.deficit = 0;
                    it->second.quantum_due = true;
                    if (it->second.queue.empty() && it->second.bytes == 0) {
                        tx_flows_.erase(it);
                    }
                }
                continue;
            }

            flow_tx_context& fx = it->second;
            if (fx.quantum_due) {
                fx.deficit += static_cast<int64_t>(q);
                fx.quantum_due = false;
            }

            // Per-visit frame cap: even when deficit allows, yield to the next
            // flow after max_visit frames so a single elephant flow cannot
            // monopolize an entire drain turn at the expense of mice flows.
            if (fx.visit_count >= (uint32_t)PPP_MUX_TX_FLOW_MAX_VISIT_FRAMES) {
                fx.visit_count = 0;
                fx.quantum_due = true;
                active_tx_flows_.emplace_back(cid);
                continue;
            }

            // Skip this flow for this round if the head frame exceeds remaining deficit.
            // (Classic DRR: only send when deficit >= packet size.)
            const int head_len = fx.queue.front().length;
            if (head_len > 0 && fx.deficit < (int64_t)head_len) {
                // Preserve unused credit and add another quantum next round.
                fx.visit_count = 0;
                fx.quantum_due = true;
                active_tx_flows_.emplace_back(cid);
                continue;
            }

            out = std::move(fx.queue.front());
            fx.queue.pop_front();
            fx.visit_count++;
            const size_t nbytes = out.length > 0 ? (size_t)out.length : 0;
            if (nbytes <= fx.bytes) {
                fx.bytes -= nbytes;
            }
            else {
                fx.bytes = 0;
            }
            if (tx_data_frames_ > 0) {
                tx_data_frames_--;
            }
            if (nbytes <= tx_data_bytes_total_) {
                tx_data_bytes_total_ -= nbytes;
            }
            else {
                tx_data_bytes_total_ = 0;
            }
            fx.deficit -= (int64_t)(nbytes > 0 ? nbytes : 0);
            if (fx.deficit < 0) {
                fx.deficit = 0;
            }

            if (fx.queue.empty()) {
                fx.active = false;
                fx.deficit = 0;
                fx.quantum_due = true;
                fx.visit_count = 0;
                // Leave empty context; cleaned on next miss or finalize.
            }
            else if (fx.queue.front().length <= 0 ||
                fx.deficit >= static_cast<int64_t>(fx.queue.front().length)) {
                // Continue this flow's turn until its byte deficit is exhausted.
                active_tx_flows_.emplace_front(cid);
            }
            else {
                fx.quantum_due = true;
                fx.visit_count = 0;
                active_tx_flows_.emplace_back(cid);
            }
            return true;
        }

        return false;
    }

    void vmux_net::publish_runtime_snapshot_locked() noexcept {
        // Caller holds runtime_state_mutex_ OR is the sole strand mutator of runtime_state_.
        auto snap = std::make_shared<const ppp::app::mux::MuxRuntimeState>(runtime_state_);
        std::atomic_store_explicit(&runtime_snapshot_, std::move(snap), std::memory_order_release);
    }

    /**
     * @brief Performs first-time-transfer sequence initialization/validation.
     */
    bool vmux_net::ftt(uint32_t seq, uint32_t ack) noexcept {
        SynchronizationObjectScope __SCOPE__(syncobj_);
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }
        
        if (!base_.ftt_) {
            base_.ftt_ = true;
            status_.tx_seq_ = seq;
            status_.rx_ack_ = ack;
        }

        return (status_.tx_seq_ == seq) && (status_.rx_ack_ == ack);
    }

    /** @brief Produces a randomized signed identifier encoded as uint32_t. */
    uint32_t vmux_net::ftt_random_aid(int min, int max) noexcept {
        int a = ppp::RandomNext();
        int b = a & 1;
        if (b != 0) {
            return (uint32_t)-ppp::RandomNext(min, max);
        }
        else {
            return (uint32_t)ppp::RandomNext(min, max);
        }
    }

    /** @brief Begins terminal close and finalizes on the VMUX strand (inline when the executor is stopped). */
    void vmux_net::close_exec() noexcept {
        std::shared_ptr<vmux_net> self = weak_from_this().lock();
        if (NULLPTR == self || !self->begin_close()) {
            return;
        }

        if (NULLPTR != self->strand_ && self->strand_->running_in_this_thread()) {
            self->finalize();
            return;
        }

        const ContextPtr& context = self->context_;
        if (NULLPTR == context || context->stopped() ||
            !vmux_post_exec(context, self->strand_,
                [self]() noexcept {
                    self->finalize();
                })) {
            // Stopped executor: a posted finalizer would never run and the session
            // would leak. finalize() detects this and tears down inline.
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
            self->finalize();
        }
    }

    /**
     * @brief Writes a packet via transmission and dispatches completion on vmux strand.
     */
    static bool transmission_write(
        std::shared_ptr<vmux_net>                                           self,
        const vmux_net::ITransmissionPtr&                                   transmission,
        const std::shared_ptr<Byte>&                                        packet,
        int                                                                 packet_length,
        const ppp::transmissions::ITransmission::AsynchronousWriteCallback& ac,
        const ppp::function<void()>&                                        accounting_fallback) noexcept {

        ContextPtr context = transmission->GetContext();
        StrandPtr strand = transmission->GetStrand();
        ContextPtr vmux_context = self->get_context();
        if (NULLPTR == context || NULLPTR == vmux_context || context->stopped() || vmux_context->stopped()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
            return false;
        }

        const ppp::function<void(bool)> on_completely =
            [self, ac, accounting_fallback](bool successed) noexcept {
                const ContextPtr callback_context = self->get_context();
                const bool posted = NULLPTR != callback_context && !callback_context->stopped() &&
                    vmux_post_exec(callback_context, self->get_strand(),
                        [self, successed, ac]() noexcept {
                            ac(successed);
                        });
                if (!posted && NULLPTR != accounting_fallback) {
                    accounting_fallback();
                }
            };

        bool posted = vmux_post_exec(context, strand,
            [self, transmission, context, strand, packet, packet_length, on_completely]() noexcept {
                bool forwarding =
                    transmission->Write(packet.get(), packet_length,
                        [self, context, strand, on_completely](bool ok) noexcept {
                            on_completely(ok);
                        });

                if (!forwarding) {
                    on_completely(false);
                }
            });

        if (!posted) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
        }

        return posted;
    }
    
    /**
     * @brief Sends one packet through the specified underlying linklayer.
     */
    bool vmux_net::underlyin_sent(const vmux_linklayer_ptr& linklayer, const std::shared_ptr<Byte>& packet, int packet_length, const tx_completion_ptr& completion) noexcept {
        if (NULLPTR == linklayer || NULLPTR == packet || packet_length < sizeof(vmux_hdr)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
            return false;
        }
        
        if (base_.disposed_.load(std::memory_order_acquire) || close_requested()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        IMuxTransportPtr& connection = linklayer->connection;
        if (NULLPTR == connection || !connection->IsLinked()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
            return false;
        }

        ITransmissionPtr transmission = connection->GetTransmission();
        if (NULLPTR == transmission) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
            return false;
        }

        if (!link_has_byte_credit(linklayer, packet_length)) {
            ppp::telemetry::Count("mux.link.byte_credit.deny", 1);
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
            return false;
        }

        std::shared_ptr<vmux_net> self = weak_from_this().lock();
        if (NULLPTR == self) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }
        ppp::telemetry::Count("mux.link.send", 1);
        // Track in-flight writes per link (strand-affine) so runtime link removal
        // (turbo dynamic pool) can retire a link only after its last write
        // completes — a late completion must never touch a freed/retired link's
        // scheduling state.
        const ppp::app::mux::MuxLinkDrainState::WriteTicket write =
            linklayer->drain_.BeginWrite();
        if (!write) {
            return false;
        }

        linklayer->queued_bytes_ += (size_t)packet_length;
        linklayer->total_sent_bytes_ += (uint64_t)packet_length;
        const int accounted_length = packet_length;

        bool queued = transmission_write(self, transmission, packet, packet_length,
            [self, this, linklayer, completion, write, accounted_length](bool ok) noexcept {
                // Decrement in-flight first; this completion is accounted regardless
                // of what follows. Runtime removal checks inflight_ == 0 to retire.
                if (!linklayer->drain_.CompleteWrite(write)) {
                    self->finish_tx_completion(completion, ok);
                    return;
                }

                if ((size_t)accounted_length <= linklayer->queued_bytes_) {
                    linklayer->queued_bytes_ -= (size_t)accounted_length;
                }
                else {
                    linklayer->queued_bytes_ = 0;
                }

                self->finish_tx_completion(completion, ok);

                // Teardown guard: a send may complete after the session has been
                // finalized (link flap, idle timeout, or peer close). finalize()
                // clears tx_links_/tx_flows_ under syncobj_; touching them again
                // from this strand callback (emplace_back / erase / re-drain) would
                // race the teardown and operate on freed list nodes. Once closing or
                // disposed, no scheduler state may be touched again.
                if (base_.disposed_.load(std::memory_order_acquire) || self->close_requested()) {
                    return;
                }

                // A link being retired for runtime removal stops taking new frames;
                // do not re-credit it. Once its in-flight drains to 0 the periodic
                // maintenance path removes it. Re-drive the scheduler so queued
                // frames continue on the remaining links.
                if (linklayer->drain_.retiring()) {
                    process_tx_all_packets();
                    return;
                }

                if (!ok) {
                    // Local write failed: isolate this carrier when others remain.
                    on_link_exit(linklayer, "write_failed");
                    return;
                }

                // stripe picks a link per packet (round-robin), so on completion
                // it returns this link's credit and re-runs the scheduler to
                // route the next frame by policy. compat / flow / balance all use
                // the competition drain (driven from the free-link list): they
                // keep sending the next queued frame on this same just-freed link.
                bool per_packet_policy_drain = (mode_ == mux_mode_stripe);
                if (per_packet_policy_drain) {
                    tx_links_.emplace_back(linklayer);
                    if (!process_tx_all_packets()) {
                        on_link_exit(linklayer, "tx_drain_failed");
                    }
                }
                else {
                    tx_packet packet;
                    if (!drr_pop_next(packet)) {
                        tx_links_.emplace_back(linklayer);
                    }
                    else if (!link_has_byte_credit(linklayer, packet.length)) {
                        drr_requeue_front(std::move(packet));
                        tx_links_.emplace_back(linklayer);
                        process_tx_all_packets();
                    }
                    else if (!underlyin_sent(linklayer, packet.buffer, packet.length, packet.completion)) {
                        drr_requeue_front(std::move(packet));
                        process_tx_all_packets();
                    }
                }
            },
            [self, linklayer, completion, write]() noexcept {
                // This fallback may run on the carrier executor. MuxLinkDrainState
                // is thread-safe; queued_bytes_ and scheduler containers are not.
                (void)linklayer->drain_.AbortWrite(write);
                self->finish_tx_completion(completion, false);
            });
        if (!queued) {
            if ((size_t)accounted_length <= linklayer->queued_bytes_) {
                linklayer->queued_bytes_ -= (size_t)accounted_length;
            }
            else {
                linklayer->queued_bytes_ = 0;
            }
            (void)linklayer->drain_.AbortWrite(write);
        }

        // Reliability: retain a copy for retransmission and fold data frames
        // into the running FEC parity group once the frame is on the wire.
        if (queued) {
            const uint64_t sent_now = now_tick();
            if (track_sent_frame(packet, packet_length, sent_now, linklayer->id_)) {
                fec_note_sent(packet, packet_length, sent_now);
            }
        }
        return queued;
    }

    /**
     * @brief Periodically updates timeout state and closes stale sockets.
     */
    bool vmux_net::update() noexcept {
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        std::shared_ptr<vmux_net> self = shared_from_this();
        bool posted = vmux_post_exec(context_, strand_,
            [self, this]() noexcept {
                list<vmux_skt_ptr> release_skts;

                uint64_t max_tcp_inactive_timeout = ((uint64_t)AppConfiguration->tcp.inactive.timeout) * 1000ULL;
                uint64_t max_tcp_connect_timeout = ((uint64_t)AppConfiguration->tcp.connect.timeout) * 1000ULL;

                uint64_t now = now_tick();
                if (base_.established_) {
                    for (const std::pair<uint32_t, vmux_skt_ptr>& kv : skts_) {
                        bool is_port_aging = false;
                        const vmux_skt_ptr& skt = kv.second;

                        uint64_t delta_time = now - skt->last_;
                        if (skt->status_.connected_) {
                            is_port_aging = delta_time >= max_tcp_inactive_timeout;
                        }
                        else {
                            is_port_aging = delta_time >= max_tcp_connect_timeout;
                        }

                        if (is_port_aging) {
                            release_skts.emplace_back(skt);
                        }
                    }
                }

                /**
                 * @brief Complex maintenance step:
                 * - close per-socket idle/connect-timeout entries,
                 * - enforce global mux inactivity timeout,
                 * - schedule heartbeat keepalive when established.
                 */
                uint64_t max_mux_inactive_timeout = ((uint64_t)AppConfiguration->mux.inactive.timeout) * 1000ULL;
                uint64_t max_mux_connect_timeout = ((uint64_t)AppConfiguration->mux.connect.timeout) * 1000ULL;

                if ((now - status_.last_) >= (base_.established_ ? max_mux_inactive_timeout : max_mux_connect_timeout)) {
                    close_exec();
                }
                elif(base_.established_ && (now - status_.last_heartbeat_) >= status_.heartbeat_timeout_) {
                    if (post(cmd_keep_alived, NULLPTR, 0, ftt_random_aid(1, INT32_MAX))) {
                        status_.last_heartbeat_ = now;
                        switch_to_next_heartbeat_timeout();
                    }
                }

                for (vmux_skt_ptr& skt : release_skts) {
                    skt->close();
                }

                /**
                 * @brief Debug-only one-shot mux-mode push.
                 *
                 * Once the session is established, if a transient
                 * `--mux-mode-set` request and a non-empty `--debug-key` are
                 * configured locally, push the requested scheduler mode to the
                 * peer exactly once. The peer applies it only when its own
                 * debug key matches (see packet_input_mux_mode_set).
                 */
                if (base_.established_ && !mux_mode_set_pushed_ && NULLPTR != AppConfiguration) {
                    const ppp::string& set_mode = AppConfiguration->mux.debug.set_mode;
                    if (!set_mode.empty() && !AppConfiguration->mux.debug.key.empty()) {
                        if (post_mux_mode_set(parse_mode(set_mode))) {
                            mux_mode_set_pushed_ = true;
                        }
                    }
                    else {
                        mux_mode_set_pushed_ = true; // Nothing to push; do not re-check every tick.
                    }
                }

                /**
                 * @brief Scheduler observability (Phase 2 telemetry):
                 * publish the active scheduler mode together with the transmit
                 * queue depth, the out-of-order reorder queue depth, and the
                 * number of attached link-layers. These run on the vmux strand,
                 * so reading the queues/link containers here is race-free.
                 */
                if (!base_.disposed_.load(std::memory_order_acquire)) {
                    // flow-v2: advance any per-connection gap whose wait timed out so a
                    // permanently lost frame cannot stall that connection's delivery.
                    flow_evict_expired(now);
                    compat_evict_expired(now);

                    // turbo dynamic pool: dispose any carrier link that finished
                    // retiring (its in-flight writes drained to 0) since last tick.
                    reap_retired_linklayers();

                    // turbo dynamic pool controller: move the pool one step toward
                    // the quality-derived target (grow request / shrink retire).
                    turbo_controller_tick(now);

                    // D11 stall watchdog: if the data tx queue stays at/over the
                    // high-water mark for longer than the stall timeout, the send
                    // side is wedged (carrier not draining; new connections starve)
                    // and cannot self-heal. Tear the session down so it is rebuilt,
                    // rather than hang forever serving nothing. Control frames have
                    // their own priority queue, so this only triggers on a genuine
                    // data-path wedge.
                    size_t tx_depth = tx_data_frames_;
                    if (tx_depth >= tx_queue_high_water_) {
                        if (tx_backlog_since_ == 0) {
                            tx_backlog_since_ = now;
                        }
                        elif((now - tx_backlog_since_) >= tx_backlog_stall_ms_) {
                            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux",
                                "tx backlog stall watchdog: depth=%d held >= %dms, rebuilding session",
                                (int)tx_depth, (int)tx_backlog_stall_ms_);
                            ppp::telemetry::Count("mux.tx.backlog.stall", 1);
                            close_exec();
                        }
                    }
                    else {
                        tx_backlog_since_ = 0;
                    }

                    ppp::telemetry::Gauge("mux.sched.mode", static_cast<int64_t>(mode_));
                    ppp::telemetry::Gauge("mux.tx.queue.depth", static_cast<int64_t>(tx_data_frames_));
                    ppp::telemetry::Gauge("mux.rx.reorder.depth", static_cast<int64_t>(rx_queue_.size()));
                    ppp::telemetry::Gauge("mux.link.count", static_cast<int64_t>(rx_links_.size()));
                }
            });

        if (!posted) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
        }

        return posted;
    }

    /** @brief Selects the next randomized heartbeat timeout window. */
    void vmux_net::switch_to_next_heartbeat_timeout() noexcept {
        int min = std::max<int>(0, AppConfiguration->mux.keep_alived[0]);
        int max = std::max<int>(0, AppConfiguration->mux.keep_alived[1]);
        if (min > max) {
            std::swap(min, max);
        }

        if (max == 0) {
            max = AppConfiguration->mux.connect.timeout;
        }

        min = std::max<int>(1, min) * 1000;
        max = std::max<int>(1, max) * 1000;
        status_.heartbeat_timeout_ = ppp::RandomNext(min, max + 1);
    }

    /**
     * @brief Processes in-order/out-of-order packets and advances ACK state.
     */
    bool vmux_net::packet_input_unorder(const vmux_linklayer_ptr& linklayer, vmux_hdr* h, int length, uint64_t now, const std::shared_ptr<Byte>& owner) noexcept {
        // Prepare the ack frames.
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        ppp::telemetry::Count("mux.link.recv", 1);

        // Reliability control frames are unordered in both modes: handle them
        // inline before any sequence-space reasoning (they carry seq=0).
        if (is_reliability_control(h->cmd)) {
            if (!packet_input(h->cmd, (Byte*)h, length, now, owner)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                return false;
            }

            active(now);
            linklayer_update(linklayer);
            return true;
        }

        uint32_t seq = ntohl(h->seq);
        if (status_.rx_ack_ == seq) {
                if (packet_input(h->cmd, (Byte*)h, length, now, owner)) {
                    status_.rx_ack_++;
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                    return false;
                }

            for (;;) {
                rx_packet_ssqueue::iterator packet_tail = rx_queue_.begin();
                rx_packet_ssqueue::iterator packet_endl = rx_queue_.end();
                if (packet_tail != packet_endl && status_.rx_ack_ == packet_tail->first) {
                    rx_packet i = packet_tail->second;
                    vmux_hdr* p = (vmux_hdr*)i.buffer.get();
                    rx_queue_.erase(packet_tail);

                    note_flow_unbuffered(static_cast<size_t>(i.length));

                    if (packet_input(p->cmd, (Byte*)p, i.length, now, i.buffer)) {
                        status_.rx_ack_++;
                    }
                    else {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                        return false;
                    }
                }
                else {
                    break;
                }
            }

            if (rx_queue_.empty()) {
                rx_gap_oldest_tick_ = 0;
            }

            active(now);
            linklayer_update(linklayer);
            return true;
        }
        elif(packet_less<uint32_t>::after(seq, status_.rx_ack_)) {
            /**
             * @brief Complex reorder path:
             * buffers future packets by sequence and replays contiguous packets once
             * the missing sequence is received.
             */
            // Protect against absurd packet sizes and allocate within limit.
            // 'length' here includes the vmux_hdr; ensure it's at least a header
            // and does not exceed header + max_buffers_size.
            if (length < sizeof(vmux_hdr) || length > (sizeof(vmux_hdr) + max_buffers_size)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                return false;
            }

            if (session_reorder_cap_bytes_ > 0 &&
                session_reorder_bytes_ + static_cast<size_t>(length) > session_reorder_cap_bytes_) {
                ppp::telemetry::Count("mux.rx.compat.reorder_cap", 1);
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux",
                    "compat reorder cap exceeded: buffered=%u incoming=%u cap=%u; rebuilding session",
                    (unsigned)session_reorder_bytes_, (unsigned)length,
                    (unsigned)session_reorder_cap_bytes_);
                close_exec();
                active(now);
                linklayer_update(linklayer);
                return true;
            }

            std::shared_ptr<Byte> buf;
            if (NULLPTR != owner) {
                buf = ppp::wrap_shared_pointer(reinterpret_cast<ppp::Byte*>(h), owner);
            } else {
                buf = make_byte_array(length);
                if (NULLPTR != buf) {
                    memcpy(buf.get(), h, length);
                }
            }
            if (NULLPTR == buf) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetReorderPacketBufferAllocFailed);
                return false;
            }

            rx_packet packet = { buf, length };

            bool inserted = rx_queue_.emplace(std::make_pair(seq, packet)).second;
            if (!inserted) {
                // Duplicate of an already-buffered out-of-order frame (a
                // retransmit): with reliability negotiated this is expected.
                if (reliability_on_) {
                    active(now);
                    linklayer_update(linklayer);
                    return true;
                }
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MappingEntryConflict);
            }
            else {
                note_flow_buffered(static_cast<size_t>(length));
                if (rx_gap_oldest_tick_ == 0) {
                    rx_gap_oldest_tick_ = now;
                }
            }

            // Any valid framed traffic (including OOO) proves peer liveness.
            active(now);
            linklayer_update(linklayer);
            return inserted;
        }
        else {
            // Stale/duplicate (already delivered): with reliability negotiated
            // this is an expected retransmit duplicate — drop it silently.
            if (reliability_on_) {
                active(now);
                linklayer_update(linklayer);
                return true;
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
            return false;
        }
    }

    /** @brief Delivers payload data to one logical vmux socket. */
    void vmux_net::packet_input_read(uint32_t connection_id, Byte* buffer, int buffer_size, uint64_t now, const std::shared_ptr<Byte>& owner) noexcept {
        vmux_skt_ptr skt = get_connection(connection_id);
        if (NULLPTR != skt) {
            if (skt->input(owner, buffer, buffer_size)) {
                skt->active(now);
            }
            else {
                skt->close();
            }
        }
    }

    /**
     * @brief Dispatches an incoming vmux command frame to its handler.
     */
    bool vmux_net::packet_input(Byte cmd, Byte* buffer, int buffer_size, uint64_t now, const std::shared_ptr<Byte>& owner) noexcept {
        buffer_size -= sizeof(vmux_hdr);
        if (buffer_size < 0) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
            return false;
        }

        vmux_hdr* h = (vmux_hdr*)buffer;
        buffer = (Byte*)(h + 1);

        uint32_t connection_id = ntohl(h->connection_id);
        if (cmd == cmd_push) {
            packet_input_read(connection_id, buffer, buffer_size, now, owner);
        }
        elif(cmd == cmd_fin) {
            packet_input_read(connection_id, NULLPTR, 0, now);
        }
        elif(cmd == cmd_syn) {
            std::shared_ptr<vmux_skt> sk;
            bool successed = process_rx_connecting(sk, connection_id, (char*)buffer, buffer_size);

            if (NULLPTR != sk) {
                if (successed) {
                    sk->active(now);
                }
                else {
                    sk->close();
                }
            }
        }
        elif(cmd == cmd_syn_ok) {
            vmux_skt_ptr skt = get_connection(connection_id);
            if (NULLPTR != skt) {
                bool successed = false;
                if (buffer_size > 0) {
                    const Byte err = static_cast<Byte>(*buffer);
                    successed = skt->connect_ok(err == 'A');
                }

                if (successed) {
                    skt->active(now);
                }
                else {
                    skt->close();
                }
            }
        }
        elif(cmd == cmd_acceleration) {
            vmux_skt_ptr skt = get_connection(connection_id);
            if (NULLPTR != skt) {
                bool acceleration = true;
                if (buffer_size > 0) {
                    acceleration = static_cast<Byte>(*buffer) != FALSE;
                }

                if (skt->tx_acceleration(acceleration)) {
                    skt->active(now);
                }
                else {
                    skt->close();
                }
            }
        }
        elif(cmd == cmd_keep_alived) {
            active(now);
        }
        elif(cmd == cmd_mux_mode_set) {
            packet_input_mux_mode_set(buffer, buffer_size);
            active(now);
        }
        elif(cmd == cmd_ack) {
            packet_input_ack(buffer, buffer_size, now);
            active(now);
        }
        elif(cmd == cmd_fec) {
            packet_input_fec(NULLPTR, buffer, buffer_size, now);
            active(now);
        }
        else {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
            return false;
        }

        return true;
    }

    /**
     * @brief Handles a debug-only cmd_mux_mode_set control frame.
     *
     * Applies the requested scheduler mode only when remote control is enabled
     * locally (non-empty mux.debug.key) and the key carried in the frame matches
     * exactly. Mismatches are logged and ignored; the session is never closed,
     * so a malformed/forged frame cannot disrupt traffic.
     */
    void vmux_net::packet_input_mux_mode_set(const Byte* buffer, int buffer_size) noexcept {
        if (NULLPTR == AppConfiguration) {
            return;
        }

        const ppp::string& debug_key = AppConfiguration->mux.debug.key;
        if (debug_key.empty()) {
            // Default-off: no debug key means remote scheduler control is disabled.
            if ((++mux_mode_set_reject_streak_ % 32) == 1) {
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux",
                    "mux-mode-set rejected: remote control disabled (no debug key)");
            }
            ppp::telemetry::Count("mux.debug.mode_set.reject", 1);
            return;
        }

        if (NULLPTR == buffer || buffer_size < 2) {
            ppp::telemetry::Count("mux.debug.mode_set.reject", 1);
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "mux-mode-set rejected: malformed control frame");
            return;
        }

        Byte requested = buffer[0];
        int key_length = static_cast<int>(buffer[1]);
        if (key_length <= 0 || (2 + key_length) > buffer_size) {
            ppp::telemetry::Count("mux.debug.mode_set.reject", 1);
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "mux-mode-set rejected: invalid key length");
            return;
        }

        bool key_matched =
            key_length == static_cast<int>(debug_key.size()) &&
            CRYPTO_memcmp(buffer + 2, debug_key.data(), key_length) == 0;
        if (!key_matched) {
            ppp::telemetry::Count("mux.debug.mode_set.reject", 1);
            if ((++mux_mode_set_reject_streak_ % 16) == 1) {
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "mux-mode-set rejected: debug key mismatch");
            }
            return;
        }

        // Rate limit accepted changes (and successful-auth attempts) to reduce abuse.
        const uint64_t now = now_tick();
        const uint64_t min_interval_ms = 1000;
        if (mux_mode_set_last_accept_ != 0 && (now - mux_mode_set_last_accept_) < min_interval_ms) {
            ppp::telemetry::Count("mux.debug.mode_set.rate_limited", 1);
            return;
        }

        mux_mode mode = parse_mode_byte(requested);
        // set_mode only switches the transmit scheduler (compat/flow/balance/stripe).
        // Receiver ordering remains session-immutable after establishment (see set_ordering_mode).
        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux",
            "mux-mode-set accepted from peer: scheduler=%s (ordering unchanged=%s)",
            mode_name(mode),
            ordering_mode_ == ordering_flow_v2 ? "flow_v2" : "compat");

        // Apply to the live session and record a lock-free runtime override on the
        // shared runtime config so the change survives mux session rebuilds (link
        // flap, idle/heartbeat timeout). The exchanger reconstructs a vmux_net via
        // AppConfiguration->GetEffectiveMuxMode() on reconnect; without this the
        // pushed mode would be lost and silently revert to the configured value.
        AppConfiguration->SetMuxModeRuntimeOverride(static_cast<int>(mode));
        set_mode(mode);
        mux_mode_set_last_accept_ = now;
        mux_mode_set_reject_streak_ = 0;
        ppp::telemetry::Count("mux.debug.mode_set.accept", 1);
    }

    /**
     * @brief Delivers one framed data packet (push/fin) to its logical connection.
     * @details Mirrors the per-command routing of packet_input() for the two
     *          per-flow data commands. cmd_push forwards the payload; cmd_fin
     *          delivers an end-of-stream (NULL payload) to the connection.
     */
    bool vmux_net::deliver_one(Byte cmd, vmux_hdr* h, int length, uint64_t now, const std::shared_ptr<Byte>& owner) noexcept {
        int buffer_size = length - (int)sizeof(vmux_hdr);
        if (buffer_size < 0) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
            return false;
        }

        Byte* payload = (Byte*)(h + 1);
        uint32_t connection_id = ntohl(h->connection_id);
        if (cmd == cmd_push) {
            packet_input_read(connection_id, payload, buffer_size, now, owner);
        }
        else { // cmd_fin
            packet_input_read(connection_id, NULLPTR, 0, now);
        }

        return true;
    }

    /**
     * @brief Releases a flow context once its FIN has been delivered and drained.
     */
    void vmux_net::maybe_release_flow(uint32_t connection_id, flow_rx_context& fx) noexcept {
        if (fx.fin_seen_ && fx.flow_reorder_.empty()) {
            flows_.erase(connection_id);
            tx_flow_seq_.erase(connection_id);
            release_flow_reliability_state(connection_id);
        }
    }

    /**
     * @brief Fails one logical flow without delivering past an unrecovered gap.
     * @details Erases receive/send flow state and closes the logical socket if
     *          present. Buffered out-of-order payloads for this cid are dropped
     *          with the flow context (no force-advance delivery).
     */

    void vmux_net::note_flow_buffered(size_t bytes) noexcept {
        flow_aggregate_bytes_ += bytes;
        session_reorder_bytes_ += bytes;
    }

    void vmux_net::note_flow_unbuffered(size_t bytes) noexcept {
        if (bytes >= flow_aggregate_bytes_) {
            flow_aggregate_bytes_ = 0;
        }
        else {
            flow_aggregate_bytes_ -= bytes;
        }
        if (bytes >= session_reorder_bytes_) {
            session_reorder_bytes_ = 0;
        }
        else {
            session_reorder_bytes_ -= bytes;
        }
    }

    vmux_net::flow_rx_context* vmux_net::try_get_or_create_flow(uint32_t connection_id) noexcept {
        const bool already_tracked = flows_.find(connection_id) != flows_.end();
        const bool socket_exists = NULLPTR != get_connection(connection_id);
        const size_t cap = flow_context_cap_ > 0
            ? flow_context_cap_
            : (size_t)PPP_MUX_FLOW_MAX_CONTEXTS;
        const ppp::app::mux::FlowContextAdmission decision =
            ppp::app::mux::AdmitFlowContext(
                connection_id,
                already_tracked,
                socket_exists,
                flows_.size(),
                cap);

        switch (decision) {
        case ppp::app::mux::FlowContextAdmission::AllowExisting:
            return &flows_[connection_id];
        case ppp::app::mux::FlowContextAdmission::AllowCreate:
            return &flows_[connection_id];
        case ppp::app::mux::FlowContextAdmission::RejectUnknown:
            ppp::telemetry::Count("mux.rx.flow.unknown_cid", 1);
            ppp::telemetry::Count("mux.rx.unknown_cid", 1);
            return NULLPTR;
        case ppp::app::mux::FlowContextAdmission::RejectCap:
            ppp::telemetry::Count("mux.rx.flow.context_cap", 1);
            return NULLPTR;
        case ppp::app::mux::FlowContextAdmission::RejectZero:
        default:
            return NULLPTR;
        }
    }

    void vmux_net::fail_flow(uint32_t connection_id, const char* reason) noexcept {
        const char* why = (reason != NULLPTR && reason[0] != '\0') ? reason : "unspecified";
        ppp::telemetry::Count("mux.rx.flow.reset", 1);
        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux",
            "flow reset cid=%u reason=%s", (unsigned)connection_id, why);

        auto fit = flows_.find(connection_id);
        if (fit != flows_.end()) {
            note_flow_unbuffered(fit->second.flow_reorder_.buffered_bytes());
            flows_.erase(fit);
        }
        tx_flow_seq_.erase(connection_id);
        release_flow_reliability_state(connection_id);

        // Drop any remaining TX frames for this cid so a failed flow does not
        // keep consuming DRR send budget or retain memory in the TX queue.
        auto txit = tx_flows_.find(connection_id);
        if (txit != tx_flows_.end()) {
            if (tx_data_frames_ >= txit->second.queue.size()) {
                tx_data_frames_ -= txit->second.queue.size();
            }
            else {
                tx_data_frames_ = 0;
            }
            if (txit->second.bytes <= tx_data_bytes_total_) {
                tx_data_bytes_total_ -= txit->second.bytes;
            }
            else {
                tx_data_bytes_total_ = 0;
            }
            if (txit->second.active) {
                active_tx_flows_.remove(connection_id);
            }
            tx_flows_.erase(txit);
        }

        vmux_skt_ptr skt = get_connection(connection_id);
        if (NULLPTR != skt) {
            // Suppress outbound FIN: post(cmd_fin) would fail without TX credit and
            // post()'s failure path calls close_exec(), killing the whole session
            // for a single-flow reset. Local close is enough for gap/overflow fail.
            skt->status_.fin_ = true;
            skt->close();
        }
    }

    /**
     * @brief Per-flow (flow v2) receive path: independent per-connection DSN delivery.
     * @details Control frames bypass the DSN gate entirely. Per-flow data frames
     *          (push/fin) are delivered in per-connection DSN order, buffering
     *          future frames in a bounded reorder buffer. One slow link cannot
     *          head-of-line block other connections because each connection_id
     *          has its own flow_rx_next_ and reorder buffer.
     */
    bool vmux_net::packet_input_flow(const vmux_linklayer_ptr& linklayer, vmux_hdr* h, int length, uint64_t now, const std::shared_ptr<Byte>& owner) noexcept {
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        ppp::telemetry::Count("mux.link.recv", 1);

        Byte cmd = h->cmd;

        // Control frames are not gated by any per-flow DSN; handle them inline.
        if (is_session_control(cmd) || is_connection_control(cmd) || is_reliability_control(cmd)) {
            if (!packet_input(cmd, (Byte*)h, length, now, owner)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                return false;
            }

            active(now);
            linklayer_update(linklayer);
            return true;
        }

        // Any other non per-flow-data command is invalid on the flow path.
        if (!is_per_flow_data(cmd)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
            return false;
        }

        uint32_t cid = ntohl(h->connection_id);
        uint32_t seq = ntohl(h->seq);

        flow_rx_context* fxp = try_get_or_create_flow(cid);
        if (NULLPTR == fxp) {
            active(now);
            linklayer_update(linklayer);
            return true;
        }
        flow_rx_context& fx = *fxp;
        if (!fx.primed_) {
            fx.primed_ = true;
            fx.flow_rx_next_ = 1; // Sender DSNs are session-local and start at one.
        }

        if (seq == fx.flow_rx_next_) {
            // In-order: deliver immediately, then replay any contiguous buffered frames.
            if (cmd == cmd_fin) {
                fx.fin_seen_ = true;
            }

            if (!deliver_one(cmd, h, length, now, owner)) {
                return false;
            }
            fx.flow_rx_next_++;

            for (;;) {
                rx_packet pk;
                if (fx.flow_reorder_.Take(fx.flow_rx_next_, pk)) {
                    if ((size_t)pk.length <= session_reorder_bytes_) {
                        session_reorder_bytes_ -= (size_t)pk.length;
                    }
                    else {
                        session_reorder_bytes_ = 0;
                    }
                    vmux_hdr* ph = (vmux_hdr*)pk.buffer.get();
                    Byte pcmd = ph->cmd;
                    if (pcmd == cmd_fin) {
                        fx.fin_seen_ = true;
                    }
                    if (!deliver_one(pcmd, ph, pk.length, now, pk.buffer)) {
                        return false;
                    }
                    fx.flow_rx_next_++;
                }
                else {
                    break;
                }
            }

            if (fx.flow_reorder_.empty()) {
                fx.oldest_buffered_tick_ = 0;
            }

            maybe_release_flow(cid, fx);
            active(now);
            linklayer_update(linklayer);
            return true;
        }
        elif(packet_less<uint32_t>::after(seq, fx.flow_rx_next_)) {
            // Future frame: buffer it (bounded by bytes), unless it is itself too large.
            if (length < (int)sizeof(vmux_hdr) || length > (int)(sizeof(vmux_hdr) + max_buffers_size)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                return false;
            }

            // A single frame larger than the whole per-connection cap can never be
            // buffered; fail the flow rather than skip-and-deliver past a hole.
            if ((size_t)length > flow_reorder_cap_bytes_) {
                fail_flow(cid, "frame_oversize");
                active(now);
                linklayer_update(linklayer);
                return true;
            }

            // Reorder overflow: fail the flow instead of force-advancing past a gap.
            if (fx.flow_reorder_.buffered_bytes() + (size_t)length > flow_reorder_cap_bytes_ && !fx.flow_reorder_.empty()) {
                fail_flow(cid, "reorder_overflow");
                active(now);
                linklayer_update(linklayer);
                return true;
            }
            if (session_reorder_cap_bytes_ > 0 &&
                session_reorder_bytes_ + (size_t)length > session_reorder_cap_bytes_) {
                if (!fx.flow_reorder_.empty()) {
                    fail_flow(cid, "session_reorder_overflow");
                    active(now);
                    linklayer_update(linklayer);
                    return true;
                }
                uint32_t victim = 0;
                uint64_t oldest = 0;
                for (auto it = flows_.begin(); it != flows_.end(); ++it) {
                    if (it->second.flow_reorder_.empty() || it->second.oldest_buffered_tick_ == 0) {
                        continue;
                    }
                    if (oldest == 0 || it->second.oldest_buffered_tick_ < oldest) {
                        oldest = it->second.oldest_buffered_tick_;
                        victim = it->first;
                    }
                }
                if (victim != 0) {
                    fail_flow(victim, "session_reorder_overflow");
                }
                if (session_reorder_bytes_ + (size_t)length > session_reorder_cap_bytes_) {
                    ppp::telemetry::Count("mux.rx.session_reorder.drop", 1);
                    active(now);
                    linklayer_update(linklayer);
                    return true;
                }
            }

            std::shared_ptr<Byte> buf;
            if (NULLPTR != owner) {
                buf = ppp::wrap_shared_pointer(reinterpret_cast<ppp::Byte*>(h), owner);
            } else {
                buf = make_byte_array(length);
                if (NULLPTR != buf) {
                    memcpy(buf.get(), h, length);
                }
            }
            if (NULLPTR == buf) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetReorderPacketBufferAllocFailed);
                return false;
            }

            rx_packet packet = { buf, length };

            const size_t entry_cap = std::max<size_t>(
                1, flow_reorder_cap_bytes_ / sizeof(vmux_hdr));
            if (fx.flow_reorder_.size() >= entry_cap) {
                fail_flow(cid, "reorder_overflow");
                active(now);
                linklayer_update(linklayer);
                return true;
            }

            bool inserted = fx.flow_reorder_.TryInsert(
                seq,
                fx.flow_rx_next_,
                packet,
                (size_t)length,
                flow_reorder_cap_bytes_,
                entry_cap);
            if (inserted) {
                session_reorder_bytes_ += (size_t)length;
                if (fx.oldest_buffered_tick_ == 0) {
                    fx.oldest_buffered_tick_ = now;
                }
            }
            // Duplicate future DSN (or other non-overflow reject): keep original, drop duplicate.

            active(now);
            linklayer_update(linklayer);
            return true;
        }
        else {
            // Stale/duplicate (before flow_rx_next_): drop, not an error.
            active(now);
            return true;
        }
    }

    /**
     * @brief Periodically fails per-flow contexts whose gap has timed out.
     * @details Runs only under flow-v2. An unrecovered gap past the timeout
     *          resets that logical flow; it must not skip and deliver past a hole.
     */
    void vmux_net::flow_evict_expired(uint64_t now) noexcept {
        if (ordering_mode_ != ordering_flow_v2) {
            return;
        }

        // With reliability negotiated, retransmission fills gaps first; use the
        // wider reliability gap timeout as the final backstop.
        const uint64_t gap_timeout = (reliability_on_ && reliability_gap_timeout_ms_ > 0)
            ? reliability_gap_timeout_ms_
            : flow_reorder_timeout_;

        // Collect first: fail_flow erases from flows_ while we iterate.
        ppp::vector<uint32_t> expired;
        for (vmux_flow_map::iterator it = flows_.begin(); it != flows_.end(); ++it) {
            flow_rx_context& fx = it->second;
            if (!fx.flow_reorder_.empty() && fx.oldest_buffered_tick_ != 0 &&
                (now - fx.oldest_buffered_tick_) > gap_timeout) {
                expired.emplace_back(it->first);
            }
        }

        for (uint32_t cid : expired) {
            fail_flow(cid, "gap_timeout");
        }
    }

    /**
     * @brief Fails the session when a compat global reorder gap has timed out.
     * @details Under ordering_compat the single rx_queue_ can hold future frames
     *          forever if a missing seq never arrives. That is an unrecovered gap:
     *          rebuild the session instead of stalling silently.
     */
    void vmux_net::compat_evict_expired(uint64_t now) noexcept {
        if (ordering_mode_ != ordering_compat) {
            return;
        }
        if (rx_queue_.empty() || rx_gap_oldest_tick_ == 0) {
            return;
        }

        uint64_t timeout = flow_reorder_timeout_;
        if (timeout == 0) {
            timeout = (uint64_t)PPP_MUX_FLOW_REORDER_TIMEOUT;
        }
        if (reliability_on_ && reliability_gap_timeout_ms_ > 0) {
            timeout = reliability_gap_timeout_ms_;
        }
        if ((now - rx_gap_oldest_tick_) <= timeout) {
            return;
        }

        ppp::telemetry::Count("mux.rx.compat.gap_timeout", 1);
        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux",
            "compat gap timeout: buffered=%d age_ms=%llu, rebuilding session",
            (int)rx_queue_.size(),
            (unsigned long long)(now - rx_gap_oldest_tick_));
        close_exec();
    }
    
    // ------------------------------------------------------------------------
    // Reliability sub-protocol (negotiated): ACK feedback, retransmission, FEC.
    // All state below is strand-affine unless noted otherwise.
    // ------------------------------------------------------------------------

    void vmux_net::latch_reliability(bool agreed_reliability, bool agreed_fec) noexcept {
        reliability_on_ = agreed_reliability;
        fec_on_ = agreed_fec && agreed_reliability;

        if (NULLPTR != AppConfiguration) {
            const int rtx_bytes = AppConfiguration->mux.reliability.rtx.bytes;
            const int rtx_attempts = AppConfiguration->mux.reliability.rtx.max_attempts;
            const int ack_delay = AppConfiguration->mux.reliability.ack.delay;
            const int gap_timeout = AppConfiguration->mux.reliability.gap.timeout;
            rtx_cap_bytes_ = (rtx_bytes > 0) ? (size_t)rtx_bytes : (size_t)PPP_MUX_RELIABILITY_RTX_BYTES;
            rtx_max_attempts_ = (rtx_attempts > 0) ? (uint32_t)rtx_attempts : (uint32_t)PPP_MUX_RELIABILITY_RTX_MAX_ATTEMPTS;
            ack_delay_ms_ = (ack_delay > 0) ? (uint64_t)ack_delay : (uint64_t)PPP_MUX_RELIABILITY_ACK_DELAY;
            reliability_gap_timeout_ms_ = (gap_timeout > 0) ? (uint64_t)gap_timeout : (uint64_t)PPP_MUX_RELIABILITY_GAP_TIMEOUT;

            const int fec_group = AppConfiguration->mux.fec.group;
            const int fec_flush = AppConfiguration->mux.fec.flush;
            fec_group_k_ = (fec_group > 0) ? fec_group : PPP_MUX_FEC_GROUP;
            fec_flush_ms_ = (fec_flush > 0) ? (uint64_t)fec_flush : (uint64_t)PPP_MUX_FEC_FLUSH;
        }

        {
            std::lock_guard<std::mutex> scope(runtime_state_mutex_);
            runtime_state_.reliability = reliability_on_;
            runtime_state_.fec = fec_on_;
            publish_runtime_snapshot_locked();
        }

        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "reliability=%d fec=%d",
            reliability_on_ ? 1 : 0,
            fec_on_ ? 1 : 0);
        start_reliability_timer();
    }

    void vmux_net::note_inbound_reliability_frame(const vmux_linklayer_ptr& linklayer, const std::shared_ptr<Byte>& frame, vmux_hdr* h, int length, uint64_t now) noexcept {
        if (!reliability_on_ || NULLPTR == h) {
            return;
        }

        const Byte cmd = h->cmd;
        if (is_reliability_control(cmd)) {
            return; // ACK/FEC frames are never themselves ACKed or protected.
        }

        const uint32_t cid = ntohl(h->connection_id);
        const uint32_t seq = ntohl(h->seq);
        if (ordering_mode_ == ordering_flow_v2) {
            // flow_v2: only per-flow data frames participate in the DSN spaces.
            if (!is_per_flow_data(cmd)) {
                return;
            }
            note_ack_pending(cid, seq, now);
            fec_note_received(linklayer, cid, seq, frame, length, now);
        }
        else {
            // compat: every sequenced frame shares the global space (cid 0).
            note_ack_pending(0, seq, now);
            if (is_per_flow_data(cmd)) {
                fec_note_received(linklayer, cid, seq, frame, length, now);
            }
        }
    }

    void vmux_net::note_ack_pending(uint32_t connection_id, uint32_t seq, uint64_t now) noexcept {
        if (!reliability_on_) {
            return;
        }

        const uint32_t key_cid = (ordering_mode_ == ordering_compat) ? 0u : connection_id;
        ack_trackers_[key_cid].Add(seq, (size_t)PPP_MUX_ACK_MAX_RANGES);
        if (ack_pending_count_ == 0) {
            ack_first_pending_tick_ = now;
        }
        ack_pending_count_++;
        maybe_send_ack(now, false);
    }

    void vmux_net::maybe_send_ack(uint64_t now, bool force) noexcept {
        if (!reliability_on_ || !base_.established_ || ack_pending_count_ == 0) {
            return;
        }
        if (!force && ack_pending_count_ < 2 && (now - ack_first_pending_tick_) < ack_delay_ms_) {
            return;
        }

        // ACK coalescing: if we just sent an ACK within the last half delay window,
        // suppress this one to avoid redundant ACK bursts under high frame rates.
        // The pending sequences are already accumulated in ack_trackers_ and will be
        // included in the next emission, so no data is lost.
        if (!force && ack_last_sent_tick_ > 0 &&
            (now - ack_last_sent_tick_) < (ack_delay_ms_ / 2)) {
            return;
        }

        ppp::app::mux::MuxAckBlock blocks[PPP_MUX_ACK_MAX_BLOCKS];
        size_t block_count = 0;
        for (const std::pair<const uint32_t, ppp::app::mux::MuxAckTracker>& kv : ack_trackers_) {
            if (block_count >= (size_t)PPP_MUX_ACK_MAX_BLOCKS) {
                break; // Remaining sequence spaces are carried by the next ACK.
            }
            if (kv.second.empty()) {
                continue;
            }

            ppp::app::mux::MuxAckBlock& block = blocks[block_count++];
            block.connection_id = kv.first;
            block.largest = kv.second.largest();
            block.ranges = kv.second.ranges();
        }
        if (block_count == 0) {
            ack_pending_count_ = 0;
            return;
        }

        const size_t payload_cap = ppp::app::mux::MuxAckFrameMaxSize(
            (size_t)PPP_MUX_ACK_MAX_BLOCKS, (size_t)PPP_MUX_ACK_MAX_RANGES);
        std::shared_ptr<Byte> packet = make_byte_array((int)(sizeof(vmux_hdr) + payload_cap));
        if (NULLPTR == packet) {
            return;
        }

        const size_t payload_len = ppp::app::mux::EncodeMuxAckFrame(
            blocks, block_count, packet.get() + sizeof(vmux_hdr), payload_cap, (size_t)PPP_MUX_ACK_MAX_RANGES);
        if (payload_len == 0) {
            return;
        }

        vmux_hdr* h = (vmux_hdr*)packet.get();
        h->cmd = cmd_ack;
        h->connection_id = htonl(0);

        // Best-effort: ACK frames are periodic and cumulative, so a queueing
        // failure must not tear the session down (post() would close_exec).
        PostInternalAsynchronousCallback null_ac;
        if (post_internal(packet, (int)(sizeof(vmux_hdr) + payload_len), false, null_ac)) {
            ack_pending_count_ = 0;
            ack_last_sent_tick_ = now;
            ppp::telemetry::Count("mux.ack.send", 1);
        }
    }

    void vmux_net::packet_input_ack(Byte* buffer, int buffer_size, uint64_t now) noexcept {
        if (!reliability_on_) {
            ppp::telemetry::Count("mux.ack.unexpected", 1);
            return;
        }

        std::vector<ppp::app::mux::MuxAckBlock> blocks;
        if (!ppp::app::mux::DecodeMuxAckFrame((const uint8_t*)buffer, (size_t)std::max(0, buffer_size),
            (size_t)PPP_MUX_ACK_MAX_BLOCKS, (size_t)PPP_MUX_ACK_MAX_RANGES, blocks)) {
            // Malformed feedback: drop the frame, never kill the session.
            ppp::telemetry::Count("mux.ack.malformed", 1);
            return;
        }

        ppp::telemetry::Count("mux.ack.recv", 1);
        for (const ppp::app::mux::MuxAckBlock& block : blocks) {
            const uint32_t key_cid = (ordering_mode_ == ordering_compat) ? 0u : block.connection_id;
            std::vector<uint64_t> candidates;
            uint16_t ack_link_id = 0;
            // Fast-RTX time threshold: QUIC-style max(SRTT/4, 1ms) to suppress
            // spurious fast retransmits on heterogeneous multi-path links where
            // a DSN gap may simply be reordering, not loss.
            const uint64_t fast_time_threshold = (srtt_ms_ > 0)
                ? (srtt_ms_ / 4 > 0 ? srtt_ms_ / 4 : 1) : 0;
            const uint64_t sample = rtx_.Ack(key_cid, block.largest, block.ranges, now,
                (uint32_t)PPP_MUX_FAST_RETX_THRESHOLD, fast_time_threshold, candidates, &ack_link_id);
            if (sample > 0) {
                // Session-level SRTT (fallback for single-link / no link_id).
                srtt_ms_ = (srtt_ms_ == 0) ? sample : (srtt_ms_ * 7 + sample) / 8;

                // Per-link SRTT (QUIC-style EWMA) when the ACK can be
                // attributed to a specific carrier link.
                if (ack_link_id != 0) {
                    for (const vmux_linklayer_ptr& ll : rx_links_) {
                        if (NULLPTR != ll && ll->id_ == ack_link_id) {
                            if (!ll->has_rtt_sample_) {
                                ll->srtt_ms_ = sample;
                                ll->rttvar_ms_ = sample / 2;
                                ll->min_rtt_ms_ = sample;
                                ll->has_rtt_sample_ = true;
                            } else {
                                const uint64_t abs_diff = (ll->srtt_ms_ >= sample)
                                    ? (ll->srtt_ms_ - sample)
                                    : (sample - ll->srtt_ms_);
                                ll->rttvar_ms_ = (ll->rttvar_ms_ * 3 + abs_diff) / 4;
                                ll->srtt_ms_ = (ll->srtt_ms_ * 7 + sample) / 8;
                                if (sample < ll->min_rtt_ms_) {
                                    ll->min_rtt_ms_ = sample;
                                }
                            }
                            break;
                        }
                    }
                }
            }
            for (uint64_t key : candidates) {
                rtx_pending_.emplace_back(key);
            }
        }

        if (!rtx_pending_.empty()) {
            ppp::telemetry::Count("mux.rtx.fast", (int64_t)rtx_pending_.size());
            retransmit_pending(now);
        }
    }

    bool vmux_net::track_sent_frame(const std::shared_ptr<Byte>& packet, int packet_length, uint64_t now, uint16_t link_id) noexcept {
        if (!reliability_on_ || NULLPTR == packet || packet_length < (int)sizeof(vmux_hdr)) {
            return false;
        }

        const vmux_hdr* h = (const vmux_hdr*)packet.get();
        const Byte cmd = h->cmd;
        if (is_reliability_control(cmd)) {
            return false;
        }

        const uint32_t cid = ntohl(h->connection_id);
        const uint32_t seq = ntohl(h->seq);
        uint32_t key_cid = cid;
        if (ordering_mode_ == ordering_flow_v2) {
            // flow_v2: control frames carry no DSN and are not tracked; their
            // loss is tolerated (connect timeout / periodic retry covers them).
            if (!is_per_flow_data(cmd)) {
                return false;
            }
        }
        else {
            key_cid = 0; // compat: one global sequence space.
        }

        const uint64_t key = ppp::app::mux::MuxRetransmitBuffer::Key(key_cid, seq);
        if (NULLPTR != rtx_.Find(key)) {
            return false; // A retransmission, not a first send.
        }
        // Per-flow RTX byte quota: a single flow cannot exhaust the entire
        // session RTX budget. When the per-flow cap is exceeded, fail only this
        // flow rather than degrading the entire session.
        if (ordering_mode_ == ordering_flow_v2) {
            size_t& flow_rtx = rtx_flow_bytes_[cid];
            if (flow_rtx + (size_t)packet_length > (size_t)PPP_MUX_RTX_FLOW_MAX_BYTES) {
                ppp::telemetry::Count("mux.rtx.flow_cap", 1);
                fail_flow(cid, "rtx_flow_overflow");
                return false;
            }
            flow_rtx += (size_t)packet_length;
        }
        if (!rtx_.Track(key_cid, seq, packet, packet_length, now, rtx_cap_bytes_, link_id)) {
            // Retransmit buffer exhausted: degrade exactly like an unrecovered gap.
            ppp::telemetry::Count("mux.rtx.cap", 1);
            if (ordering_mode_ == ordering_flow_v2) {
                fail_flow(cid, "rtx_buffer_overflow");
            }
            else {
                close_exec();
            }
            return false;
        }
        return true;
    }

    void vmux_net::retransmit_pending(uint64_t now) noexcept {
        if (rtx_pending_.empty() || base_.disposed_.load(std::memory_order_acquire)) {
            return;
        }

        size_t burst = (size_t)PPP_MUX_RELIABILITY_RXT_BURST;
        std::vector<uint64_t> leftover;
        for (uint64_t key : rtx_pending_) {
            ppp::app::mux::MuxRtxEntry* entry = rtx_.Find(key);
            if (NULLPTR == entry) {
                ppp::telemetry::Count("mux.rtx.spurious", 1);
                continue; // ACKed/released since it was scheduled.
            }
            if (burst == 0) {
                leftover.emplace_back(key);
                continue;
            }
            if (entry->last_sent_tick == now) {
                continue; // Already (re)sent this turn (duplicate schedule).
            }
            if (entry->attempts >= rtx_max_attempts_) {
                // Unrecoverable frame: degrade exactly like an unrecovered gap.
                ppp::telemetry::Count("mux.rtx.exhausted", 1);
                const uint32_t cid = ppp::app::mux::MuxRetransmitBuffer::KeyCid(key);
                if (ordering_mode_ == ordering_flow_v2) {
                    fail_flow(cid, "rtx_exhausted");
                    continue;
                }

                close_exec();
                return;
            }

            // Pick any free link with byte credit; retransmissions keep the
            // ORIGINAL sequence number so the receiver deduplicates them.
            vmux_linklayer_ptr chosen;
            for (vmux_linklayer_list::iterator it = tx_links_.begin(); it != tx_links_.end(); ++it) {
                // Skip links that are draining/dead: a retransmission on a
                // dying link would just be lost again and waste the attempt.
                if ((*it) == NULLPTR || !(*it)->schedulable()) {
                    continue;
                }
                if (link_has_byte_credit(*it, entry->length)) {
                    chosen = *it;
                    tx_links_.erase(it);
                    break;
                }
            }
            if (NULLPTR == chosen) {
                leftover.emplace_back(key); // No credit right now; a completion re-drives us.
                continue;
            }

            if (!underlyin_sent(chosen, entry->buffer, entry->length, tx_completion_ptr())) {
                leftover.emplace_back(key);
                continue;
            }

            rtx_.MarkRetransmitted(key, now, chosen->id_);
            ppp::telemetry::Count("mux.rtx.send", 1);
            --burst;
        }
        rtx_pending_.swap(leftover);
    }

    uint64_t vmux_net::current_pto() const noexcept {
        // Session-level fallback: use the session SRTT when per-link state is
        // unavailable (single link, no sample yet, or compat mode).
        uint64_t pto = (srtt_ms_ > 0) ? (srtt_ms_ * 2) : (uint64_t)PPP_MUX_RELIABILITY_PTO_INIT;
        if (pto < (uint64_t)PPP_MUX_RELIABILITY_PTO_MIN) {
            pto = (uint64_t)PPP_MUX_RELIABILITY_PTO_MIN;
        }
        if (pto > (uint64_t)PPP_MUX_RELIABILITY_PTO_MAX) {
            pto = (uint64_t)PPP_MUX_RELIABILITY_PTO_MAX;
        }
        return pto;
    }

    uint64_t vmux_net::current_pto(const vmux_linklayer_ptr& linklayer) const noexcept {
        // Per-link PTO using QUIC-style formula:
        //   PTO = SRTT + max(4*RTTVAR, granularity) + max_ack_delay
        // Currently max_ack_delay = 0 (no delayed-ACK delay configured).
        // Falls back to session-level PTO when the link has no RTT sample.
        if (NULLPTR == linklayer || !linklayer->has_rtt_sample_) {
            return current_pto();
        }
        const uint64_t srtt = linklayer->srtt_ms_;
        const uint64_t rttvar = linklayer->rttvar_ms_;
        const uint64_t granularity = 1; // 1 ms tick granularity floor.
        uint64_t backoff = rttvar * 4;
        if (backoff < granularity) {
            backoff = granularity;
        }
        uint64_t pto = srtt + backoff;
        if (pto < (uint64_t)PPP_MUX_RELIABILITY_PTO_MIN) {
            pto = (uint64_t)PPP_MUX_RELIABILITY_PTO_MIN;
        }
        if (pto > (uint64_t)PPP_MUX_RELIABILITY_PTO_MAX) {
            pto = (uint64_t)PPP_MUX_RELIABILITY_PTO_MAX;
        }
        return pto;
    }

    void vmux_net::reliability_tick() noexcept {
        if (base_.disposed_.load(std::memory_order_acquire) || NULLPTR == reliability_timer_) {
            return;
        }

        const uint64_t now = now_tick();
        if (base_.established_ && reliability_on_) {
            maybe_send_ack(now, false);

            rtx_.CollectExpired(now, current_pto(), (uint64_t)PPP_MUX_RELIABILITY_PTO_MAX, (size_t)PPP_MUX_RELIABILITY_RXT_BURST, rtx_pending_);
            if (!rtx_pending_.empty()) {
                ppp::telemetry::Count("mux.rtx.pto", 1);
                retransmit_pending(now);
            }

            if (fec_on_ && fec_encoder_.count() > 0 &&
                (fec_flush_due_ || (now - fec_encoder_.first_add_tick()) >= fec_flush_ms_)) {
                fec_flush_due_ = false;
                fec_flush_group();
            }
        }

        std::weak_ptr<vmux_net> weak = weak_from_this();
        reliability_timer_->expires_after(std::chrono::milliseconds(PPP_MUX_RELIABILITY_TIMER_MS));
        reliability_timer_->async_wait(
            [weak](const boost::system::error_code& ec) noexcept {
                if (ec) {
                    return;
                }
                if (std::shared_ptr<vmux_net> self = weak.lock()) {
                    self->reliability_tick();
                }
            });
    }

    void vmux_net::start_reliability_timer() noexcept {
        if (!reliability_on_ || NULLPTR != reliability_timer_ || NULLPTR == strand_) {
            return;
        }

        reliability_timer_ = std::make_shared<boost::asio::steady_timer>(*strand_);
        reliability_tick(); // Arms the wait chain; work is a no-op pre-establishment.
    }

    void vmux_net::release_flow_reliability_state(uint32_t connection_id) noexcept {
        if (ordering_mode_ == ordering_flow_v2) {
            rtx_.EraseCid(connection_id);
            ack_trackers_.erase(connection_id);
            rtx_flow_bytes_.erase(connection_id);
        }
        if (!fec_on_) {
            return;
        }

        for (vmux::list<uint64_t>::iterator it = fec_frame_cache_order_.begin(); it != fec_frame_cache_order_.end();) {
            if (ppp::app::mux::MuxRetransmitBuffer::KeyCid(*it) == connection_id) {
                vmux::unordered_map<uint64_t, fec_cached_frame>::iterator cit = fec_frame_cache_.find(*it);
                if (cit != fec_frame_cache_.end()) {
                    fec_frame_cache_bytes_ -= (size_t)cit->second.length;
                    fec_frame_cache_.erase(cit);
                }
                it = fec_frame_cache_order_.erase(it);
            }
            else {
                ++it;
            }
        }
        for (vmux::list<fec_rx_group>::iterator it = fec_groups_.begin(); it != fec_groups_.end();) {
            bool references = false;
            for (const ppp::app::mux::MuxFecFrameId& id : it->view.entries) {
                if (id.connection_id == connection_id) {
                    references = true;
                    break;
                }
            }
            if (references) {
                it = fec_groups_.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    void vmux_net::fec_note_sent(const std::shared_ptr<Byte>& packet, int packet_length, uint64_t now) noexcept {
        if (!fec_on_ || NULLPTR == packet) {
            return;
        }
        if (packet_length < (int)sizeof(vmux_hdr) || packet_length > PPP_MUX_FEC_MAX_FRAME) {
            return; // Oversize frames stay retransmit-only (parity must fit one frame).
        }

        const vmux_hdr* h = (const vmux_hdr*)packet.get();
        if (!is_per_flow_data(h->cmd)) {
            return; // Parity covers reliable data frames only.
        }

        if (fec_encoder_.count() == 0) {
            fec_encoder_.Reset(now);
        }
        fec_encoder_.Add(ntohl(h->connection_id), ntohl(h->seq), packet.get(), packet_length);
        if (fec_encoder_.count() >= fec_group_k_) {
            // Defer emission to the maintenance tick: fec_note_sent runs inside
            // the transmit drain, where re-entering the scheduler would corrupt it.
            fec_flush_due_ = true;
        }
    }

    void vmux_net::fec_flush_group() noexcept {
        if (fec_encoder_.count() == 0) {
            return;
        }

        const uint64_t now = now_tick();
        do {
            if (!fec_on_ || !base_.established_) {
                break;
            }

            const int payload_cap = (int)fec_encoder_.MaxPayloadSize();
            std::shared_ptr<Byte> packet = make_byte_array((int)sizeof(vmux_hdr) + payload_cap);
            if (NULLPTR == packet) {
                break;
            }

            const int payload_len = fec_encoder_.Build(packet.get() + sizeof(vmux_hdr), payload_cap);
            if (payload_len <= 0) {
                break;
            }

            vmux_hdr* h = (vmux_hdr*)packet.get();
            h->cmd = cmd_fec;
            h->connection_id = htonl(0);

            PostInternalAsynchronousCallback null_ac;
            if (post_internal(packet, (int)sizeof(vmux_hdr) + payload_len, false, null_ac)) {
                ppp::telemetry::Count("mux.fec.send", 1);
            }
        } while (false);

        fec_encoder_.Reset(now);
    }

    void vmux_net::fec_note_received(const vmux_linklayer_ptr& linklayer, uint32_t connection_id, uint32_t seq, const std::shared_ptr<Byte>& buffer, int length, uint64_t now) noexcept {
        if (!fec_on_ || NULLPTR == buffer || length < (int)sizeof(vmux_hdr)) {
            return;
        }

        // Cache the frame for later single-loss recovery (bounded FIFO).
        const uint64_t key = ppp::app::mux::MuxRetransmitBuffer::Key(connection_id, seq);
        if (fec_frame_cache_.find(key) == fec_frame_cache_.end()) {
            const size_t entry_cap = (size_t)PPP_MUX_FEC_WINDOW_GROUPS * (size_t)std::max(1, fec_group_k_);
            while (!fec_frame_cache_order_.empty() &&
                (fec_frame_cache_bytes_ + (size_t)length > (size_t)PPP_MUX_FEC_CACHE_BYTES ||
                    fec_frame_cache_.size() >= entry_cap)) {
                const uint64_t victim = fec_frame_cache_order_.front();
                fec_frame_cache_order_.pop_front();
                vmux::unordered_map<uint64_t, fec_cached_frame>::iterator vit = fec_frame_cache_.find(victim);
                if (vit != fec_frame_cache_.end()) {
                    fec_frame_cache_bytes_ -= (size_t)vit->second.length;
                    fec_frame_cache_.erase(vit);
                }
            }

            fec_cached_frame cached;
            cached.buffer = buffer;
            cached.length = length;
            fec_frame_cache_.emplace(key, cached);
            fec_frame_cache_order_.emplace_back(key);
            fec_frame_cache_bytes_ += (size_t)length;
        }

        fec_try_recover_groups(linklayer, connection_id, seq, now);
    }

    void vmux_net::fec_try_recover_groups(const vmux_linklayer_ptr& linklayer, uint32_t connection_id, uint32_t seq, uint64_t now) noexcept {
        for (vmux::list<fec_rx_group>::iterator git = fec_groups_.begin(); git != fec_groups_.end();) {
            fec_rx_group& group = *git;

            int slot = -1;
            for (size_t i = 0; i < group.view.entries.size(); ++i) {
                if (group.view.entries[i].connection_id == connection_id &&
                    group.view.entries[i].sequence == seq) {
                    slot = (int)i;
                    break;
                }
            }
            if (slot < 0) {
                ++git;
                continue;
            }

            if (NULLPTR == group.frames[slot]) {
                vmux::unordered_map<uint64_t, fec_cached_frame>::iterator cit =
                    fec_frame_cache_.find(ppp::app::mux::MuxRetransmitBuffer::Key(connection_id, seq));
                if (cit != fec_frame_cache_.end()) {
                    group.frames[slot] = cit->second.buffer;
                    group.lengths[slot] = cit->second.length;
                    group.missing--;
                }
            }

            bool erase_group = false;
            if (group.missing <= 0) {
                erase_group = true; // Complete without needing recovery.
            }
            else if (group.missing == 1) {
                int missing_index = -1;
                std::vector<const uint8_t*> present(group.frames.size(), nullptr);
                std::vector<int> present_lengths(group.lengths.size(), 0);
                for (size_t i = 0; i < group.frames.size(); ++i) {
                    if (NULLPTR == group.frames[i]) {
                        missing_index = (int)i;
                    }
                    else {
                        present[i] = group.frames[i].get();
                        present_lengths[i] = group.lengths[i];
                    }
                }

                const int cap = (int)group.view.parity.size();
                std::shared_ptr<Byte> recovered = make_byte_array(std::max(cap, (int)sizeof(vmux_hdr)));
                const int recovered_length = (NULLPTR != recovered)
                    ? ppp::app::mux::MuxFecRecover(group.view, present.data(), present_lengths.data(),
                        missing_index, recovered.get(), cap)
                    : 0;
                if (recovered_length >= (int)sizeof(vmux_hdr)) {
                    vmux_hdr* rh = (vmux_hdr*)recovered.get();
                    const ppp::app::mux::MuxFecFrameId& want = group.view.entries[missing_index];
                    if (is_per_flow_data(rh->cmd) &&
                        ntohl(rh->connection_id) == want.connection_id &&
                        ntohl(rh->seq) == want.sequence) {
                        ppp::telemetry::Count("mux.fec.recovered", 1);
                        note_ack_pending(want.connection_id, want.sequence, now);
                        const bool delivered = (ordering_mode_ == ordering_flow_v2)
                            ? packet_input_flow(linklayer, rh, recovered_length, now, recovered)
                            : packet_input_unorder(linklayer, rh, recovered_length, now, recovered);
                        if (!delivered) {
                            close_exec();
                            return;
                        }
                    }
                    else {
                        ppp::telemetry::Count("mux.fec.recover_invalid", 1);
                    }
                }
                else {
                    ppp::telemetry::Count("mux.fec.recover_failed", 1);
                }
                erase_group = true;
            }

            if (erase_group) {
                git = fec_groups_.erase(git);
            }
            else {
                ++git;
            }
        }
    }

    void vmux_net::packet_input_fec(const vmux_linklayer_ptr& linklayer, Byte* buffer, int buffer_size, uint64_t now) noexcept {
        if (!fec_on_) {
            ppp::telemetry::Count("mux.fec.unexpected", 1);
            return;
        }

        ppp::app::mux::MuxFecFrameView view;
        const int max_count = std::max(1, fec_group_k_ * 4);
        if (!ppp::app::mux::ParseMuxFecFrame((const uint8_t*)buffer, buffer_size, max_count, view)) {
            ppp::telemetry::Count("mux.fec.malformed", 1);
            return;
        }

        ppp::telemetry::Count("mux.fec.recv", 1);
        while (fec_groups_.size() >= (size_t)PPP_MUX_FEC_WINDOW_GROUPS) {
            fec_groups_.pop_front();
            ppp::telemetry::Count("mux.fec.group.evict", 1);
        }

        fec_rx_group group;
        group.frames.resize(view.entries.size());
        group.lengths.resize(view.entries.size(), 0);
        group.missing = 0;
        for (size_t i = 0; i < view.entries.size(); ++i) {
            const ppp::app::mux::MuxFecFrameId& id = view.entries[i];
            vmux::unordered_map<uint64_t, fec_cached_frame>::iterator cit =
                fec_frame_cache_.find(ppp::app::mux::MuxRetransmitBuffer::Key(id.connection_id, id.sequence));
            if (cit != fec_frame_cache_.end()) {
                group.frames[i] = cit->second.buffer;
                group.lengths[i] = cit->second.length;
            }
            else {
                group.missing++;
            }
        }
        group.view = std::move(view);
        fec_groups_.emplace_back(std::move(group));

        // Slots were filled from the cache above; evaluate immediately in case
        // the group is already one frame short (or complete).
        if (!fec_groups_.empty() && !fec_groups_.back().view.entries.empty()) {
            const ppp::app::mux::MuxFecFrameId& first = fec_groups_.back().view.entries.front();
            fec_try_recover_groups(linklayer, first.connection_id, first.sequence, now);
        }
    }

    /**
     * @brief Handles remote SYN by creating and accepting a vmux socket instance.
     */
    bool vmux_net::process_rx_connecting(std::shared_ptr<vmux_skt>& skt, uint32_t connection_id, const char* host, int host_size) noexcept {
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        if (max_open_flows_ > 0 && skts_.size() >= max_open_flows_) {
            ppp::telemetry::Count("mux.rx.flow.max_open", 1);
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetProcessRxConnectingIdConflict);
            return false;
        }

        vmux_skt_map::iterator tail = skts_.find(connection_id);
        vmux_skt_map::iterator endl = skts_.end();
        if (tail != endl) {
            skt = tail->second;
            if (NULLPTR != skt) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetProcessRxConnectingIdConflict);
                return false;
            }
        }

        std::shared_ptr<vmux_net> self = shared_from_this();
        skt = ppp::make_shared_object<vmux_skt>(self, connection_id);

        if (NULLPTR == skt) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetProcessRxConnectingSocketAllocFailed);
            return false;
        }

        skt->self_weak_ = skt;
        skts_[connection_id] = skt;
        return skt->accept(template_string(host, host_size));
    }

    /** @brief Generates a non-zero session-local connection identifier.
     *  @details IDs are allocated from a per-session counter and never reused
     *           within the session. When the 32-bit space wraps, further
     *           allocation fails (returns 0) so callers rebuild the session
     *           rather than risk delayed frames landing on a recycled cid.
     */
    uint32_t vmux_net::generate_id() noexcept {
        if (connection_id_wrap_) {
            return 0;
        }

        // First call: pick a random non-zero start so peers do not share a fixed pattern.
        if (next_connection_id_ == 0) {
            next_connection_id_ = ftt_random_aid(1, INT32_MAX);
            if (next_connection_id_ == 0) {
                next_connection_id_ = 1;
            }
        }

        for (uint32_t attempts = 0; attempts < 0xffffffffu; ++attempts) {
            uint32_t n = next_connection_id_++;
            if (next_connection_id_ == 0) {
                // Exhausted; mark wrap so we do not recycle within this session.
                connection_id_wrap_ = true;
                if (n != 0 && skts_.find(n) == skts_.end()) {
                    return n;
                }
                ppp::telemetry::Count("mux.cid.wrap", 1);
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux",
                    "connection id space exhausted; refuse new logical connections until session rebuild");
                return 0;
            }
            if (n == 0) {
                continue;
            }
            if (skts_.find(n) == skts_.end()) {
                return n;
            }
            // Extremely unlikely collision with an in-flight id; try next.
        }

        connection_id_wrap_ = true;
        return 0;
    }

    /** @brief Looks up a vmux socket by logical connection identifier. */
    vmux_net::vmux_skt_ptr vmux_net::get_connection(uint32_t connection_id) noexcept {
        vmux_skt_ptr skt;
        if (connection_id != 0) {
            vmux_skt_map::iterator tail = skts_.find(connection_id);
            vmux_skt_map::iterator endl = skts_.end();
            if (tail != endl) {
                skt = tail->second;
            }
        }

        return skt;
    }

    /**
     * @brief Removes a vmux socket only when pointer identity matches the caller.
     */
    vmux_net::vmux_skt_ptr vmux_net::release_connection(uint32_t connection_id, vmux_skt* refer_pointer) noexcept {
        vmux_skt_ptr skt;
        if (connection_id != 0) {
            vmux_skt_map::iterator tail = skts_.find(connection_id);
            vmux_skt_map::iterator endl = skts_.end();
            if (tail != endl) {
                skt = tail->second;
                if (skt.get() == refer_pointer) {
                    skts_.erase(tail);
                    flows_.erase(connection_id);          // drop per-flow receive context (flow v2)
                    tx_flow_seq_.erase(connection_id);    // drop per-flow send DSN counter (flow v2)
                    release_flow_reliability_state(connection_id); // free RTX/FEC state for this cid
                    // Drop any remaining TX frames for this cid (DRR fairness state).
                    auto txit = tx_flows_.find(connection_id);
                    if (txit != tx_flows_.end()) {
                        if (tx_data_frames_ >= txit->second.queue.size()) {
                            tx_data_frames_ -= txit->second.queue.size();
                        }
                        else {
                            tx_data_frames_ = 0;
                        }
                        if (txit->second.bytes <= tx_data_bytes_total_) {
                            tx_data_bytes_total_ -= txit->second.bytes;
                        }
                        else {
                            tx_data_bytes_total_ = 0;
                        }
                        if (txit->second.active) {
                            active_tx_flows_.remove(connection_id);
                        }
                        tx_flows_.erase(txit);
                    }
                }
            }
        }

        return skt;
    }

    /**
     * @brief Queues or directly dispatches a prepared packet frame for transmit.
     */
    bool vmux_net::post_internal(const std::shared_ptr<Byte>& packet, int packet_length, bool acceleration, const PostInternalAsynchronousCallback& posted_ac) noexcept {
        if (!is_strand_thread()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEventDispatchFailed);
            return false;
        }

        if (NULLPTR == packet || packet_length < sizeof(vmux_hdr)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
            return false;
        }
        
        if (base_.disposed_.load(std::memory_order_acquire) || !base_.established_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetPostInternalNotEstablished);
            return false;
        }

        // Exactly-once completion for this post: tracked so a session close fails
        // the waiter instead of leaving it hanging. track_tx_completion() failing
        // means close already began (it has fired the completion with false).
        tx_completion_ptr completion = make_tx_completion(posted_ac);
        if (!track_tx_completion(completion)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        vmux_hdr* h = (vmux_hdr*)packet.get();
        bool prioritize_ctrl = false;
        if (is_reliability_control(h->cmd)) {
            // Reliability control frames (ack/fec) are unordered in BOTH modes:
            // seq=0, never DSN-gated, never ACKed/retransmitted/FEC-protected.
            h->seq = htonl(0);
            prioritize_ctrl = (ordering_mode_ == ordering_flow_v2);
        }
        else if (ordering_mode_ == ordering_flow_v2) {
            // flow v2: per-flow data frames carry a per-connection DSN; control
            // frames carry seq=0 (the receiver ignores their DSN). This keeps the
            // wire header unchanged while letting the receiver order each
            // connection independently.
            Byte cmd = h->cmd;
            if (is_per_flow_data(cmd)) {
                uint32_t cid = ntohl(h->connection_id);
                // Per-connection DSN starts at 1; 0 is reserved as the control-frame
                // placeholder so a data DSN is never confused with a control frame.
                uint32_t& dsn = tx_flow_seq_[cid];
                if (dsn == 0) {
                    dsn = 1;
                }
                h->seq = htonl(dsn++);
            }
            else {
                h->seq = htonl(0);
                // Control frames (syn/syn_ok/acceleration/keep_alived/mux_mode_set)
                // are not DSN-gated at the receiver, so under flow v2 they take the
                // high-priority queue and are never starved by a data backlog.
                prioritize_ctrl = is_session_control(cmd) || is_connection_control(cmd);
            }
        }
        else {
            h->seq = htonl(status_.tx_seq_++);
        }

        if (prioritize_ctrl) {
            // Control frames bypass acceleration and jump the data backlog. The
            // optional completion is fired immediately (the frame is queued for a
            // priority drain that runs at the top of process_tx_all_packets).
            // Hard cap: a malicious or buggy peer cannot flood the control queue
            // without bound. When full, drop the oldest non-critical frame to make
            // room; SYN/FIN are never dropped, only stale ACKs/keepalives.
            if (tx_ctrl_queue_.size() >= (size_t)PPP_MUX_TX_CTRL_MAX_FRAMES) {
                ppp::telemetry::Count("mux.tx.ctrl_cap", 1);
                bool dropped = false;
                for (auto it = tx_ctrl_queue_.begin(); it != tx_ctrl_queue_.end(); ++it) {
                    const vmux_hdr* fh = (const vmux_hdr*)it->buffer.get();
                    const Byte fcmd = fh->cmd;
                    // Only drop feedback/keepalive frames, never SYN/FIN/mode_set.
                    if (fcmd == cmd_ack || fcmd == cmd_keep_alived) {
                        tx_ctrl_queue_.erase(it);
                        dropped = true;
                        break;
                    }
                }
                if (!dropped) {
                    // All queued frames are critical (SYN/FIN); reject the new one.
                    return false;
                }
            }
            tx_ctrl_queue_.emplace_back(tx_packet{ packet, packet_length, completion });
            return process_tx_all_packets();
        }

        // flow turbo: a new connection's first packet (cmd_syn) is sent over the
        // most-recently-active link to cut first-byte latency. This is a one-shot
        // hint only — the connection is NOT bound; all subsequent frames go through
        // the normal competition drain. Recency is an approximate signal (not RTT);
        // fail-open to competition when no turbo link is available or the link has
        // no send credit.
        if (turbo_ && h->cmd == cmd_syn) {
            vmux_linklayer_ptr turbo_link = select_turbo_linklayer();
            if (NULLPTR != turbo_link) {
                vmux_linklayer_list::iterator lt = tx_links_.begin();
                vmux_linklayer_list::iterator le = tx_links_.end();
                while (lt != le && *lt != turbo_link) {
                    ++lt;
                }

                if (lt != le) {
                    tx_links_.erase(lt);
                    ppp::telemetry::Count("mux.turbo.syn", 1);
                    return underlyin_sent(turbo_link, packet, packet_length, completion);
                }
            }
            // fall through to the normal path when no free turbo link is available.
        }

        if (acceleration && base_.acceleration_) {
            vmux_linklayer_list::iterator linklayer_tail = tx_links_.begin();
            vmux_linklayer_list::iterator linklayer_endl = tx_links_.end();

            if (linklayer_tail != linklayer_endl) {
                // D11 backpressure: normally the acceleration fast-path fires the
                // completion immediately so the skt read-pump reads the next chunk
                // without waiting for the send to finish. That decouples reading
                // from draining and lets data TX grow unbounded when the carrier
                // stalls. Once the data queue reaches the high-water mark, fall back
                // to attaching the completion to the frame so it fires only when the
                // frame is actually sent — this re-couples the read-pump to drain
                // progress and throttles ingestion until the backlog clears.
                const uint32_t cid = peek_connection_id(packet, packet_length);
                bool throttle = tx_data_frames_ >= tx_queue_high_water_;
                if (throttle) {
                    enqueue_flow_tx(cid, tx_packet{ packet, packet_length, completion });
                }
                else {
                    enqueue_flow_tx(cid, tx_packet{ packet, packet_length, tx_completion_ptr() });
                    if (NULLPTR != completion) {
                        // Early-ack through the tracked completion so a concurrent
                        // session close still resolves it exactly once; when the
                        // executor is already stopped, fail it inline instead of
                        // dropping the waiter.
                        std::shared_ptr<vmux_net> self = weak_from_this().lock();
                        bool fired = NULLPTR != self &&
                            vmux_post_exec(context_, strand_,
                                [self, completion]() noexcept {
                                    self->finish_tx_completion(completion, true);
                                });
                        if (!fired) {
                            finish_tx_completion(completion, false);
                        }
                    }
                }

                return process_tx_all_packets();
            }
        }

        {
            const uint32_t cid = peek_connection_id(packet, packet_length);
            enqueue_flow_tx(cid, tx_packet{ packet, packet_length, completion });
        }
        return process_tx_all_packets();
    }

    /** @brief True when an underlying link-layer endpoint is usable. */
    bool vmux_net::is_linklayer_active(const vmux_linklayer_ptr& linklayer) noexcept {
        if (NULLPTR == linklayer) {
            return false;
        }

        // Unified schedulability check (handshake complete + not retiring).
        if (!linklayer->schedulable()) {
            return false;
        }

        const IMuxTransportPtr& connection = linklayer->connection;
        return NULLPTR != connection && connection->IsLinked();
    }

    /** @brief Drains queued packets across free links using per-flow byte DRR. */
    bool vmux_net::process_tx_compat_packets() noexcept {
        while (!tx_links_.empty() && tx_data_frames_ > 0) {
            tx_packet nexting_packet;
            if (!drr_pop_next(nexting_packet)) {
                break;
            }

            // Prefer a free link that still has byte credit for this frame.
            vmux_linklayer_list::iterator chosen = tx_links_.end();
            for (auto it = tx_links_.begin(); it != tx_links_.end(); ++it) {
                if (link_has_byte_credit(*it, nexting_packet.length)) {
                    chosen = it;
                    break;
                }
            }
            if (chosen == tx_links_.end()) {
                drr_requeue_front(std::move(nexting_packet));
                break; // no credit; a completion will re-drive us
            }

            vmux_linklayer_ptr linklayer = *chosen;
            tx_links_.erase(chosen);

            if (!underlyin_sent(linklayer, nexting_packet.buffer, nexting_packet.length, nexting_packet.completion)) {
                drr_requeue_front(std::move(nexting_packet));
                if (tx_links_.empty()) {
                    return true;
                }
                continue;
            }
        }

        return true;
    }

    /** @brief Drains queued packets for flow mode.
     *  @details flow is the latency-oriented "new direction": pure competition on
     *           the send side (any free link sends the next queued frame — no
     *           per-connection binding, which would risk load imbalance and the
     *           single-TCP degeneration the competition model is designed to avoid),
     *           with global ordering on receive (no per-flow reordering wait). The
     *           optional turbo path (best-link-first first packet + prewarmed carrier
     *           links) layers on top via --mux-mode-turbo without changing this
     *           competition core. */
    bool vmux_net::process_tx_flow_packets() noexcept {
        return process_tx_compat_packets();
    }

    /** @brief Reads the connection_id field stored in a queued vmux frame buffer. */
    uint32_t vmux_net::peek_connection_id(const std::shared_ptr<Byte>& packet, int packet_length) noexcept {
        if (NULLPTR == packet || packet_length < (int)sizeof(vmux_hdr)) {
            return 0;
        }

        const vmux_hdr* h = (const vmux_hdr*)packet.get();
        return ntohl(h->connection_id);
    }

    /** @brief Picks the next active link-layer round-robin for stripe mode. */
    vmux_net::vmux_linklayer_ptr vmux_net::select_striped_linklayer() noexcept {
        size_t count = rx_links_.size();
        if (count == 0) {
            return NULLPTR;
        }

        for (size_t i = 0; i < count; i++) {
            const vmux_linklayer_ptr& linklayer = rx_links_[stripe_cursor_ % count];
            stripe_cursor_++;
            if (is_linklayer_active(linklayer)) {
                return linklayer;
            }
        }

        return NULLPTR;
    }

    /** @brief Picks the best available link for a turbo first packet. */
    vmux_net::vmux_linklayer_ptr vmux_net::select_turbo_linklayer() noexcept {
        // Prefer lowest outstanding local write bytes, then recency (last_active_).
        // Still not RTT; still a one-shot SYN hint with no connection binding.
        vmux_linklayer_ptr best;
        for (const vmux_linklayer_ptr& linklayer : rx_links_) {
            if (!is_linklayer_active(linklayer)) {
                continue;
            }
            if (!link_has_byte_credit(linklayer, (int)sizeof(vmux_hdr))) {
                continue;
            }

            if (NULLPTR == best) {
                best = linklayer;
                continue;
            }

            if (linklayer->queued_bytes_ < best->queued_bytes_) {
                best = linklayer;
            }
            else if (linklayer->queued_bytes_ == best->queued_bytes_ &&
                     linklayer->last_active_ >= best->last_active_) {
                best = linklayer;
            }
        }

        return best;
    }

    bool vmux_net::linklayer_id_in_use(uint16_t id, const vmux_linklayer_ptr& except) noexcept {
        if (id == 0) {
            return true;
        }

        for (const vmux_linklayer_ptr& linklayer : rx_links_) {
            if (NULLPTR != linklayer && linklayer != except && linklayer->id_ == id) {
                return true;
            }
        }

        return false;
    }

    uint16_t vmux_net::allocate_linklayer_id(const vmux_linklayer_ptr& linklayer) noexcept {
        if (NULLPTR == linklayer || status_.pool_hard_max == 0) {
            return 0;
        }

        if (linklayer->id_ != 0 && linklayer->id_ <= status_.pool_hard_max && !linklayer_id_in_use(linklayer->id_, linklayer)) {
            return linklayer->id_;
        }

        for (uint32_t id = 1; id <= status_.pool_hard_max; id++) {
            uint16_t candidate = (uint16_t)id;
            if (!linklayer_id_in_use(candidate, linklayer)) {
                linklayer->id_ = candidate;
                return candidate;
            }
        }

        return 0;
    }

    /**
     * @brief Send-side scheduling for balance mode.
     * @details balance uses the same competition policy as compat (any link with
     *          send credit sends the next queued frame; no per-connection binding).
     *          Per-connection link binding was removed deliberately: pinning a
     *          connection to a link makes load unpredictable and, in the worst case
     *          (several heavy flows landing on one link), degenerates to a single
     *          TCP — defeating multi-link VMUX. Instead balance keeps competition on
     *          send and adds per-flow DSN reordering on receive (negotiated flow v2),
     *          so a slow/blocked connection only head-of-line blocks itself, not the
     *          others, while every link stays fully and adaptively utilized.
     */
    bool vmux_net::process_tx_balance_packets() noexcept {
        return process_tx_compat_packets();
    }

    /** @brief Drains DRR-ordered packets; prefers striped link when it has credit. */
    bool vmux_net::process_tx_stripe_packets() noexcept {
        while (!tx_links_.empty() && tx_data_frames_ > 0) {
            tx_packet nexting_packet;
            if (!drr_pop_next(nexting_packet)) {
                return true;
            }

            // Prefer the round-robin target when it currently has send credit;
            // otherwise use any free link so a busy target does not stall output.
            vmux_linklayer_ptr preferred = select_striped_linklayer();
            vmux_linklayer_list::iterator link_tail = tx_links_.end();
            if (NULLPTR != preferred) {
                for (auto it = tx_links_.begin(); it != tx_links_.end(); ++it) {
                    if (*it == preferred && link_has_byte_credit(*it, nexting_packet.length)) {
                        link_tail = it;
                        break;
                    }
                }
            }
            if (link_tail == tx_links_.end()) {
                for (auto it = tx_links_.begin(); it != tx_links_.end(); ++it) {
                    if (link_has_byte_credit(*it, nexting_packet.length)) {
                        link_tail = it;
                        break;
                    }
                }
            }
            if (link_tail == tx_links_.end()) {
                drr_requeue_front(std::move(nexting_packet));
                return true;
            }

            vmux_linklayer_ptr linklayer = *link_tail;
            tx_links_.erase(link_tail);

            if (!underlyin_sent(linklayer, nexting_packet.buffer, nexting_packet.length, nexting_packet.completion)) {
                drr_requeue_front(std::move(nexting_packet));
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }
        }
        return true;
    }

    /** @brief Drains the high-priority control-frame queue (flow v2). */
    bool vmux_net::process_tx_ctrl_packets() noexcept {
        // Control frames are link-agnostic under flow v2 (seq=0, delivered inline by
        // the receiver), so send each on any link that currently has credit. Budget
        // the drain so a ctrl flood cannot starve data for an entire turn.
        size_t budget = tx_ctrl_budget_frames_ > 0 ? tx_ctrl_budget_frames_ : (size_t)PPP_MUX_TX_CTRL_BUDGET_FRAMES;
        while (!tx_ctrl_queue_.empty() && budget > 0) {
            if (tx_links_.empty()) {
                return true; // no credit right now; a completion will re-drive us.
            }

            vmux_linklayer_list::iterator link_tail = tx_links_.begin();
            vmux_linklayer_ptr linklayer = *link_tail;
            tx_links_.erase(link_tail);

            tx_packet_ssqueue::iterator packet_tail = tx_ctrl_queue_.begin();
            tx_packet nexting_packet = *packet_tail;
            tx_ctrl_queue_.erase(packet_tail);

            if (!underlyin_sent(linklayer, nexting_packet.buffer, nexting_packet.length, nexting_packet.completion)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }
            --budget;
        }

        return true;
    }

    /** @brief Drains queued packets according to selected scheduler mode. */
    bool vmux_net::process_tx_all_packets() noexcept {
        // Always flush the high-priority control queue first (flow v2 only; empty
        // under compat). Keeps new-connection setup and heartbeats alive even when
        // the data queue is backlogged.
        if (!tx_ctrl_queue_.empty()) {
            if (!process_tx_ctrl_packets()) {
                return false;
            }
        }

        switch (mode_) {
        case mux_mode_flow:
            return process_tx_flow_packets();
        case mux_mode_balance:
            return process_tx_balance_packets();
        case mux_mode_stripe:
            return process_tx_stripe_packets();
        default:
            return process_tx_compat_packets();
        }
    }
    /**
     * @brief Builds a vmux frame from command/payload and schedules transmit.
     */
    bool vmux_net::post_internal(Byte cmd, const void* buffer, int buffer_size, uint32_t connection_id, bool acceleration, const PostInternalAsynchronousCallback& posted_ac) noexcept {
        if (!is_strand_thread()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEventDispatchFailed);
            return false;
        }

        if (NULLPTR != buffer && buffer_size < 0) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetPostInternalNegativeBufferSize);
            return false;
        }

        if (base_.disposed_.load(std::memory_order_acquire) || !base_.established_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetPostFrameNotEstablished);
            return false;
        }

        // Ensure packet length does not exceed negotiated max buffer size.
        if (buffer_size > max_buffers_size) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketTooLarge);
            return false;
        }

        int packet_length = sizeof(vmux_hdr) + buffer_size;
        std::shared_ptr<Byte> packet_managed = make_byte_array(packet_length);

        if (NULLPTR == packet_managed) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetPostFrameAllocFailed);
            return false;
        }

        Byte* packet_memory = packet_managed.get();
        if (NULLPTR != buffer && buffer_size > 0) {
            // memcpy with validated length to avoid overflow.
            memcpy(packet_memory + sizeof(vmux_hdr), buffer, buffer_size);
        }

        vmux_hdr* h = (vmux_hdr*)packet_memory;
        h->cmd = cmd;
        h->connection_id = htonl(connection_id);
        
        return post_internal(packet_managed, packet_length, acceleration, posted_ac);
    }

    /**
     * @brief Attaches one validated carrier to the live link containers.
     * @note Caller holds syncobj_. Handshake/forwarding starts in add_linklayer().
     */
    bool vmux_net::attach_linklayer_locked(
        const IMuxTransportPtr& connection,
        vmux_linklayer_ptr& linklayer) noexcept {
        linklayer = ppp::make_shared_object<vmux_linklayer>();
        if (NULLPTR == linklayer) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetAddLinklayerAllocFailed);
            return false;
        }

        std::shared_ptr<Byte> buffer = make_byte_array(max_buffers_size);
        if (NULLPTR == buffer) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetAddLinklayerBufferAllocFailed);
            return false;
        }

        linklayer->connection = connection;
        tx_links_.emplace_back(linklayer);
        rx_links_.emplace_back(linklayer);
        refresh_runtime_active_links();

        ppp::telemetry::Log(Level::kInfo, "mux", "link open");
        ppp::telemetry::Count("mux.link.open", 1);
        ppp::telemetry::Log(Level::kDebug, "mux", "link count=%d", static_cast<int>(rx_links_.size()));
        return true;
    }

    /**
     * @brief Adds a new transport linklayer and optionally starts full forwarding.
     */
    bool vmux_net::add_linklayer(const IMuxTransportPtr& connection, vmux_linklayer_ptr& linklayer, const vmux_native_add_linklayer_after_success_before_callback& cb) noexcept {
        if (NULLPTR == connection) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetAddLinklayerNullConnection);
            return false;
        }

        SynchronizationObjectScope __SCOPE__(syncobj_);
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        if (!connection->IsLinked()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
            return false;
        }

        if (rx_links_.size() >= status_.pool_hard_max) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);
            return false;
        }

        if (!attach_linklayer_locked(connection, linklayer)) {
            return false;
        }

        // Runtime addition: the session is already established (turbo dynamic pool
        // grow on either end). Attach exactly this one link and spawn exactly ONE
        // forwarding coroutine for it — never iterate rx_links_ (which would
        // re-spawn forwarding on existing links = double-forwarding). The optional
        // cb (server-side DoMuxON ack) still runs.
        if (base_.established_) {
            // Keep the pending link in rx_links_ so it counts toward the hard
            // ceiling, but withhold send credit until its handshake completes.
            for (vmux_linklayer_list::iterator it = tx_links_.begin(); it != tx_links_.end();) {
                if (*it == linklayer) {
                    it = tx_links_.erase(it);
                }
                else {
                    ++it;
                }
            }

            if (NULLPTR != cb && !cb()) {
                remove_linklayer_locked(linklayer);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }

            uint16_t connection_id = 0;
            if (base_.server_or_client_) {
                connection_id = allocate_linklayer_id(linklayer);
                if (connection_id == 0) {
                    remove_linklayer_locked(linklayer);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);
                    return false;
                }
            }

            std::shared_ptr<vmux_net> self = shared_from_this();
            vmux_linklayer_ptr added = linklayer;

            ContextPtr connection_context = connection->GetContext();
            StrandPtr connection_strand = connection->GetStrand();

            auto process =
                [self, this, added, connection_id, connection_context, connection_strand](ppp::coroutines::YieldContext& y) noexcept {
                    bool ok = handshake(added, connection_id, y);
                    if (ok) {
                        ok = vmux_post_exec(context_, strand_,
                            [self, this, added]() noexcept {
                                if (base_.disposed_.load(std::memory_order_acquire) || added->drain_.retiring()) {
                                    return false;
                                }

                                tx_links_.emplace_back(added);
                                linklayer_update(added);
                                if (!process_tx_all_packets()) {
                                    close_exec();
                                    return false;
                                }

                                return true;
                            });
                    }

                    if (ok) {
                        (void)forwarding(added, y);
                    }

                    // Runtime grow links share on_link_exit: isolate when others live.
                    vmux_post_exec(context_, strand_,
                        [self, this, added]() noexcept {
                            on_link_exit(added, "runtime_forwarding_end");
                            return true;
                        });
                };
            if (!ppp::coroutines::YieldContext::Spawn(BufferAllocator.get(), *connection_context, connection_strand.get(), process)) {
                remove_linklayer_locked(linklayer);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineSpawnFailed);
                return false;
            }

            ppp::telemetry::Count("mux.link.open.runtime", 1);
            return true;
        }

        bool unlimited = rx_links_.size() < status_.max_connections;
        if (unlimited) {
            if (NULLPTR != cb && !cb()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }

            return true;
        }
        elif(NULLPTR != cb && !cb()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
            return false;
        }

        uint64_t now = now_tick();
        active(now);

        /**
         * @brief Complex startup block:
         * once enough linklayers are attached, spawn one forwarding coroutine per
         * linklayer and execute handshake + forwarding lifecycle on each.
         */
        std::shared_ptr<vmux_net> self = shared_from_this();
        for (vmux_linklayer_ptr& linklayer : rx_links_) {

            uint16_t connection_id = 0;
            if (base_.server_or_client_) {
                connection_id = allocate_linklayer_id(linklayer);
                if (connection_id == 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);
                    return false;
                }
            }

            auto& connection = linklayer->connection;
            ContextPtr connection_context = connection->GetContext();
            StrandPtr connection_strand = connection->GetStrand();

            auto process =
                [self, this, linklayer, connection_id, connection_context, connection_strand](ppp::coroutines::YieldContext& y) noexcept {
                    if (handshake(linklayer, connection_id, y)) {
                        forwarding(linklayer, y);
                    }

                    // Carrier exit: isolate if other live carriers remain.
                    vmux_post_exec(context_, strand_,
                        [self, this, linklayer]() noexcept {
                            on_link_exit(linklayer, "forwarding_end");
                            return true;
                        });
                };

            if (!ppp::coroutines::YieldContext::Spawn(BufferAllocator.get(), *connection_context, connection_strand.get(), process)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineSpawnFailed);
                return false;
            }

            linklayer_update(linklayer);
        }

        return true;
    }

    /**
     * @brief Begins retiring the least-recently-active carrier link at runtime (C-B4).
     */
    bool vmux_net::retire_linklayer_runtime() noexcept {
        vmux_linklayer_vector reaped;
        {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            if (base_.disposed_.load(std::memory_order_acquire) || !base_.established_) {
                return false;
            }

            // Never shrink below the base (--tun-mux): the base pool must always stand.
            // Count links that are not already retiring.
            size_t live = 0;
            for (const vmux_linklayer_ptr& l : rx_links_) {
                if (NULLPTR != l && l->schedulable()) {
                    live++;
                }
            }

            if (live <= status_.max_connections) {
                return false;
            }

            // Shrink victim selection: prefer idle candidates (zero queued + zero
            // inflight) to avoid disrupting in-flight data. Among non-idle
            // candidates, pick the one with the lowest composite score
            // (inflight + queued + recency penalty) so we retire the weakest
            // contributor rather than simply the oldest.
            vmux_linklayer_ptr victim;
            vmux_linklayer_ptr idle_victim;
            uint64_t best_score = 0;
            for (const vmux_linklayer_ptr& l : rx_links_) {
                if (NULLPTR == l || !l->schedulable()) {
                    continue;
                }

                const size_t inflight = l->drain_.inflight();
                const size_t queued = l->queued_bytes_;

                // Prefer idle candidates (no queued or in-flight data).
                if (inflight == 0 && queued == 0) {
                    if (NULLPTR == idle_victim || l->last_active_ <= idle_victim->last_active_) {
                        idle_victim = l;
                    }
                    continue;
                }

                // Composite score: lower = weaker contributor = better victim.
                // In-flight bytes dominate, then queued bytes, then recency.
                const uint64_t score =
                    (uint64_t)inflight * 4 +
                    (uint64_t)queued +
                    (l->last_active_ / 1000); // coarse recency (seconds)

                if (NULLPTR == victim || score < best_score) {
                    victim = l;
                    best_score = score;
                }
            }

            // Prefer an idle candidate if one exists; otherwise use the
            // lowest-score non-idle candidate.
            if (NULLPTR != idle_victim) {
                victim = idle_victim;
            }

            if (NULLPTR == victim) {
                return false;
            }

            victim->drain_.BeginRetire();
            refresh_runtime_active_links();

            // Stop sending new frames on the victim: remove it from the free-link list.
            // (If it is currently busy it is not in tx_links_; its completion sees
            // retiring_ and will not re-credit it.)
            for (vmux_linklayer_list::iterator it = tx_links_.begin(); it != tx_links_.end(); ++it) {
                if (*it == victim) {
                    tx_links_.erase(it);
                    break;
                }
            }

            ppp::telemetry::Count("mux.link.retire.begin", 1);
            ppp::telemetry::Log(Level::kInfo, "mux", "link retiring (runtime shrink), inflight=%d", (int)victim->drain_.inflight());

            // If it already has no in-flight writes, reap immediately. Reaped
            // transports are disposed after the lock is released (no I/O under syncobj_).
            reap_retired_linklayers_locked(reaped);
        }

        for (vmux_linklayer_ptr& linklayer : reaped) {
            if (NULLPTR != linklayer && NULLPTR != linklayer->connection) {
                linklayer->connection->Dispose();
            }
            ppp::telemetry::Count("mux.link.retire.done", 1);
            ppp::telemetry::Log(Level::kInfo, "mux", "link retired (runtime shrink), links=%d", (int)rx_links_.size());
        }
        return true;
    }

    /**
     * @brief Collects carrier links that finished retiring (inflight_ == 0); caller holds syncobj_.
     */
    void vmux_net::reap_retired_linklayers_locked(vmux_linklayer_vector& reaped) noexcept {
        // Container ops only: reaped transports are disposed by the caller after
        // the lock is released (no I/O under syncobj_).
        bool erased_any = false;
        for (vmux_linklayer_vector::iterator it = rx_links_.begin(); it != rx_links_.end();) {
            vmux_linklayer_ptr linklayer = *it;
            if (NULLPTR != linklayer && linklayer->drain_.reapable()) {
                it = rx_links_.erase(it);
                erased_any = true;

                // Ensure it is not left in the free-link list.
                for (vmux_linklayer_list::iterator t = tx_links_.begin(); t != tx_links_.end();) {
                    if (*t == linklayer) {
                        t = tx_links_.erase(t);
                    }
                    else {
                        ++t;
                    }
                }

                reaped.emplace_back(linklayer);
            }
            else {
                ++it;
            }
        }

        if (erased_any) {
            refresh_runtime_active_links();
        }
    }

    /**
     * @brief Disposes carrier links that finished retiring (inflight_ == 0).
     */
    void vmux_net::reap_retired_linklayers() noexcept {
        vmux_linklayer_vector reaped;
        {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            reap_retired_linklayers_locked(reaped);
        }

        for (vmux_linklayer_ptr& linklayer : reaped) {
            if (NULLPTR != linklayer && NULLPTR != linklayer->connection) {
                linklayer->connection->Dispose();
            }
            ppp::telemetry::Count("mux.link.retire.done", 1);
            ppp::telemetry::Log(Level::kInfo, "mux", "link retired (runtime shrink), links=%d", (int)rx_links_.size());
        }
    }

    /**
     * @brief Turbo pool controller step (C-B5): derive a quality target and move
     *        the live pool one step toward it, rate-limited by a cooldown.
     */
    void vmux_net::turbo_controller_tick(uint64_t now) noexcept {
        if (!turbo_ || base_.disposed_.load(std::memory_order_acquire) || !base_.established_) {
            return;
        }

        uint16_t base = status_.max_connections;
        uint16_t hard_max = status_.pool_hard_max;
        if (hard_max <= base) {
            return; // no headroom (turbo factor 1 or misconfigured): nothing to do.
        }

        // Cooldown / hysteresis: at most one grow or shrink step per cooldown window.
        if (turbo_last_adjust_ != 0 && (now - turbo_last_adjust_) < (uint64_t)PPP_MUX_TURBO_CONTROL_COOLDOWN) {
            return;
        }

        // Dual-threshold hold: backlog must stay high/low for a hold window before
        // arming grow/shrink. Avoids expand/collapse on short bursts.
        size_t depth = tx_data_frames_;
        size_t hw = (tx_queue_high_water_ > 0) ? tx_queue_high_water_ : (size_t)PPP_MUX_TX_QUEUE_HIGH_WATER;
        const size_t grow_depth = (hw * (size_t)PPP_MUX_TURBO_GROW_DEPTH_RATIO) / 100u;
        const size_t shrink_depth = (hw * (size_t)PPP_MUX_TURBO_SHRINK_DEPTH_RATIO) / 100u;

        if (depth >= grow_depth && grow_depth > 0) {
            if (turbo_grow_hold_since_ == 0) {
                turbo_grow_hold_since_ = now;
            }
            turbo_shrink_hold_since_ = 0;
        }
        else if (depth <= shrink_depth) {
            if (turbo_shrink_hold_since_ == 0) {
                turbo_shrink_hold_since_ = now;
            }
            turbo_grow_hold_since_ = 0;
        }
        else {
            turbo_grow_hold_since_ = 0;
            turbo_shrink_hold_since_ = 0;
        }

        const bool grow_ready = turbo_grow_hold_since_ != 0 &&
            (now - turbo_grow_hold_since_) >= (uint64_t)PPP_MUX_TURBO_GROW_HOLD_MS;
        const bool shrink_ready = turbo_shrink_hold_since_ != 0 &&
            (now - turbo_shrink_hold_since_) >= (uint64_t)PPP_MUX_TURBO_SHRINK_HOLD_MS;

        int factor = 1;
        if (grow_ready) {
            if (depth >= hw) {
                factor = PPP_MUX_TURBO_FACTOR_MAX;
            }
            else if (depth > grow_depth) {
                int span = PPP_MUX_TURBO_FACTOR_MAX - 1;
                factor = 1 + (int)(((depth - grow_depth) * (size_t)span) / (hw > grow_depth ? (hw - grow_depth) : 1));
                if (factor < 1) {
                    factor = 1;
                }
                else if (factor > PPP_MUX_TURBO_FACTOR_MAX) {
                    factor = PPP_MUX_TURBO_FACTOR_MAX;
                }
            }
            else {
                factor = 2;
            }
        }
        else if (!shrink_ready && depth > shrink_depth) {
            // Hold current pool size while in the dead-band / hold windows.
            factor = 0; // sentinel: no move
        }

        // Count live (non-retiring) links and any pending grow already requested.
        size_t live = 0;
        for (const vmux_linklayer_ptr& l : rx_links_) {
            if (NULLPTR != l && l->schedulable()) {
                live++;
            }
        }

        size_t effective = live + (size_t)(turbo_pending_grow_ > 0 ? turbo_pending_grow_ : 0);

        if (factor == 0) {
            status_.pool_current = (uint16_t)std::min<uint32_t>((uint32_t)live, hard_max);
            return;
        }

        uint32_t target = (uint32_t)base * (uint32_t)factor;
        if (target < base) {
            target = base;
        }
        else if (target > hard_max) {
            target = hard_max;
        }

        if (grow_ready && effective < (size_t)target) {
            turbo_pending_grow_++;
            turbo_last_adjust_ = now;
            turbo_grow_hold_since_ = 0;
            status_.pool_current = (uint16_t)std::min<uint32_t>(effective + 1, hard_max);
            ppp::telemetry::Gauge("mux.turbo.pool.target", (int64_t)target);
            ppp::telemetry::Count("mux.turbo.pool.grow", 1);
        }
        elif(shrink_ready && (size_t)target < live && live > base) {
            if (retire_linklayer_runtime()) {
                turbo_last_adjust_ = now;
                turbo_shrink_hold_since_ = 0;
                status_.pool_current = (uint16_t)(live - 1);
                ppp::telemetry::Gauge("mux.turbo.pool.target", (int64_t)target);
                ppp::telemetry::Count("mux.turbo.pool.shrink", 1);
            }
        }
    }

    /**
     * @brief Performs server/client handshake for one attached linklayer.
     */
    bool vmux_net::handshake(const vmux_linklayer_ptr& linklayer, uint16_t connection_id, ppp::coroutines::YieldContext& y) noexcept {
        ppp::telemetry::SpanScope span("mux.link.setup");
        auto setup_started_at = std::chrono::steady_clock::now();

        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        IMuxTransportPtr& linklayer_socket = linklayer->connection;
        if (!linklayer_socket->IsLinked()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
            return false;
        }

        ITransmissionPtr linklayer_transmission = linklayer_socket->GetTransmission();
        if (NULLPTR == linklayer_transmission) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
            return false;
        }

        /** @brief Packed handshake acknowledgement payload carrying receive id. */
#pragma pack(push, 1)
        typedef struct 
#if defined(__GNUC__) || defined(__clang__)
            __attribute__((packed)) 
#endif
        {
            uint16_t receive_id;
        } vmux_linlayer_add_ack_packet;
#pragma pack(pop)

        if (base_.server_or_client_) {
            if (connection_id == 0 || connection_id > status_.pool_hard_max) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }

            vmux_linlayer_add_ack_packet packet;
            packet.receive_id = htons(connection_id);

            if (!linklayer_transmission->Write(y, &packet, sizeof(vmux_linlayer_add_ack_packet))) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }
        }
        else {
            int buffer_size = 0;
            std::shared_ptr<Byte> packet_memory = linklayer_transmission->Read(y, buffer_size);
            if (NULLPTR == packet_memory || buffer_size < sizeof(vmux_linlayer_add_ack_packet)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                return false;
            }

            vmux_linlayer_add_ack_packet* packet = (vmux_linlayer_add_ack_packet*)packet_memory.get();
            uint32_t receive_id = ntohs(packet->receive_id);

            // receive_id is assigned by the server and may exceed the base pool
            // when turbo grows carrier links at runtime.
            if (receive_id == 0 || receive_id > status_.pool_hard_max) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }

            SynchronizationObjectScope __SCOPE__(syncobj_);
            if (linklayer_id_in_use((uint16_t)receive_id, linklayer)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }

            linklayer->id_ = (uint16_t)receive_id;
        }

        {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            linklayer->handshake_complete_ = true;
            if (!base_.established_ && status_.opened_connections < status_.max_connections) {
                status_.opened_connections++;
            }
            refresh_runtime_active_links();
        }

        linklayer_established();
        auto setup_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - setup_started_at).count();
        ppp::telemetry::Histogram("mux.link.setup.us", setup_elapsed);
        return true;
    }

    /** @brief Updates mux established state once enough linklayers are opened. */
    void vmux_net::linklayer_established() noexcept {
        SynchronizationObjectScope __SCOPE__(syncobj_);
        if (!base_.established_) {
            base_.established_ = 
                status_.opened_connections >= status_.max_connections;

            ppp::telemetry::Log(Level::kDebug, "mux", "linklayer handshake complete, links=%d", static_cast<int>(status_.opened_connections));

            uint64_t now = now_tick();
            status_.last_heartbeat_ = now;

            active(now);
            switch_to_next_heartbeat_timeout();
        }
    }

    /**
     * @brief Runs continuous read/dispatch forwarding on one linklayer.
     */
    bool vmux_net::forwarding(const vmux_linklayer_ptr& linklayer, ppp::coroutines::YieldContext& y) noexcept {
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        IMuxTransportPtr& linklayer_socket = linklayer->connection;
        if (!linklayer_socket->IsLinked()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
            return false;
        }

        ITransmissionPtr linklayer_transmission = linklayer_socket->GetTransmission();
        if (NULLPTR == linklayer_transmission) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
            return false;
        }

        int buffer_size = 0;
        boost::system::error_code ec;

        bool any = false;
        std::shared_ptr<vmux_net> self = shared_from_this();

        linklayer_update(linklayer);
        for (;;) {
            if (base_.disposed_.load(std::memory_order_acquire)) {
                break;
            }

            if (!linklayer_socket->IsLinked()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                break;
            }

            std::shared_ptr<Byte> buffer_memory = linklayer_transmission->Read(y, buffer_size);
            if (NULLPTR == buffer_memory || buffer_size < sizeof(vmux_hdr)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                break;
            }

            vmux_hdr* h = (vmux_hdr*)buffer_memory.get();
            Byte cmd = h->cmd;
            if (cmd <= cmd_none || cmd >= cmd_max) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                break;
            }

            bool posted = vmux_post_exec(context_, strand_,
                [self, this, linklayer, buffer_memory, h, buffer_size]() noexcept {
                    uint64_t now = now_tick();
                    note_inbound_reliability_frame(linklayer, buffer_memory, h, buffer_size, now);
                    bool delivered = (ordering_mode_ == ordering_flow_v2)
                        ? packet_input_flow(linklayer, h, buffer_size, now, buffer_memory)
                        : packet_input_unorder(linklayer, h, buffer_size, now, buffer_memory);
                    if (delivered) {
                        return true;
                    }
                    else {
                        close_exec();
                        return false;
                    }
                });

            if (!posted) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
            }

            any |= posted;
        }
        
        return any;
    }

    /** @brief Refreshes activity on the underlying linklayer connection. */
    void vmux_net::linklayer_update(const vmux_linklayer_ptr& linklayer) noexcept {
        if (NULLPTR == linklayer) {
            return;
        }

        // Stamp the most-recent-inbound tick used by turbo's approximate
        // best-link selection (recency, not RTT). Atomic: written by the vmux
        // strand on every inbound frame and by the carrier forwarding coroutine.
        linklayer->last_active_ = now_tick();

        IMuxTransportPtr& connection = linklayer->connection;
        if (NULLPTR != connection && connection->IsLinked()) {
            connection->Update();
        }
    }

    /** @brief Validates preconditions for initiating a logical vmux connect. */
    bool vmux_net::connect_require(
        const std::shared_ptr<boost::asio::ip::tcp::socket>& sk,
        const template_string&                               host,
        int                                                  port) noexcept {

        if (base_.disposed_.load(std::memory_order_acquire) || !base_.established_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetConnectRequireNotEstablished);
            return false;
        }

        if (host.empty() || port <= 0 || port > UINT16_MAX) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetConnectRequireHostOrPortInvalid);
            return false;
        }

        if (NULLPTR == sk) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetConnectRequireNullSocket);
            return false;
        }

        if (max_open_flows_ > 0 && skts_.size() >= max_open_flows_) {
            ppp::telemetry::Count("mux.tx.flow.max_open", 1);
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);
            return false;
        }

        return true;
    }

    /**
     * @brief Coroutine-friendly connect helper that waits for async completion.
     */
    bool vmux_net::connect_yield(
        ppp::coroutines::YieldContext&                       y,
        const ContextPtr&                                    context,
        const StrandPtr&                                     strand,
        const std::shared_ptr<boost::asio::ip::tcp::socket>& sk,
        const template_string&                               host,
        int                                                  port,
        const std::shared_ptr<vmux_skt_ptr>&                 return_connection) noexcept {

        if (!y || !return_connection) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetConnectYieldInvalidArguments);
            return false;
        }

        if (NULLPTR == context) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppContextUnavailable);
            return false;
        }

        if (!connect_require(sk, host, port)) {
            return false;
        }

        std::shared_ptr<vmux_net::atomic_int> status = ppp::make_shared_object<vmux_net::atomic_int>(-1);
        if (NULLPTR == status) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetConnectYieldStatusAllocFailed);
            return false;
        }

        // Guard Suspend() behind the post result: if the executor is unavailable the
        // lambda (and every ppp::coroutines::asio::R() inside it) will never run, so
        // calling Suspend() would park the coroutine with no future Resume() �?a
        // permanent coroutine leak.
        // Capture a strong reference to keep *this alive until the posted
        // lambda finishes.  finalize() does not drain strand_, so a bare
        // this would dangle after the last shared_ptr is released.
        std::shared_ptr<vmux_net> self = shared_from_this();

        bool posted = vmux_post_exec(context_, strand_,
            [self, sk, host, port, status, context, strand, return_connection, &y]() noexcept {
                bool ok = self->connect(context, strand, sk, host, port,
                    [status, return_connection, &y](vmux_skt* sender, bool success) noexcept {

                        ppp::coroutines::asio::R(y, *status, success, 
                            [return_connection, sender]() noexcept {
                                /* The socket may already be inside its destructor when
                                 * this failure callback fires (session teardown while a
                                 * logical connect is in flight). shared_from_this() on a
                                 * dying object throws bad_weak_ptr across noexcept
                                 * boundaries -> std::terminate. Locking the weak
                                 * self-reference instead returns an empty pointer
                                 * without throwing, which safely reports the failure. */
                                std::shared_ptr<vmux_skt> connection =
                                    NULLPTR != sender ? sender->self_weak_.lock() : NULLPTR;
                                if (NULLPTR != connection) {
                                    *return_connection = connection;
                                }
                            });
                    });

                if (!ok) {
                    ppp::coroutines::asio::R(y, *status, false);
                }
            });

        if (!posted) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
            return false;
        }

        y.Suspend();
        return status->load() > 0;
    }

    /**
     * @brief Starts an asynchronous logical vmux connection creation workflow.
     */
    bool vmux_net::connect(const ContextPtr& context, const StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& sk, const template_string& host, int port, const ConnectAsynchronousCallback& ac) noexcept {
        if (NULLPTR == context || !connect_require(sk, host, port)) {
            if (NULLPTR == context) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppContextUnavailable);
            }
            return false;
        }

        vmux_skt_ptr skt;
        std::shared_ptr<vmux_net> self = shared_from_this();

        for (;;) {
            uint32_t connection_id = generate_id();
            if (connection_id == 0) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);
                return false;
            }

            vmux_skt_map::iterator skt_tail = skts_.find(connection_id);
            vmux_skt_map::iterator skt_endl = skts_.end();
            if (skt_tail != skt_endl) {
                continue;
            }

            skt = ppp::make_shared_object<vmux_skt>(self, connection_id);
            if (NULLPTR == skt) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetConnectSocketAllocFailed);
                return false;
            }

            skt->self_weak_ = skt;
            skt->tx_socket_ = sk;
            skts_[connection_id] = skt;
            break;
        }

        if (skt->connect(context, strand, host, port, ac)) {
            return true;
        }
        else {
            skt->clear_event();
            skt->close();
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketConnectFailed);
            return false;
        }
    }
}
