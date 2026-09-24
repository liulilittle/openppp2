#pragma once

/**
 * @file vmux_net.h
 * @brief Core vmux network session and packet scheduler.
 * @license GPL-3.0
 */

#include "vmux.h"
#include <ppp/app/mux/MuxFlowReorderBuffer.h>
#include <ppp/app/mux/MuxFlowContextAdmission.h>
#include <ppp/app/mux/IMuxTransport.h>
#include <ppp/app/mux/MuxLinkDrainState.h>
#include <ppp/app/mux/MuxRuntimeState.h>
#include <ppp/app/mux/MuxAckTracker.h>
#include <ppp/app/mux/MuxRetransmitBuffer.h>
#include <ppp/app/mux/MuxFecCodec.h>

namespace vmux {
    class vmux_skt;

    /**
     * @brief Multiplexed transport controller for vmux sockets.
     * @details Owns connection maps, packet queues, link layers, and heartbeat
     * management for one vmux transport session.
     */
    class vmux_net final : public std::enable_shared_from_this<vmux_net> {
    public:
        /** @brief Callback used when an async connect attempt finishes. */
        typedef ppp::function<void(vmux_skt*, bool)>                                ConnectAsynchronousCallback;
        /** @brief Host-neutral carrier transport interface. */
        typedef ppp::app::mux::IMuxTransport                                        IMuxTransport;
        typedef ppp::app::mux::IMuxTransportPtr                                     IMuxTransportPtr;
        /** @brief Shared pointer to transmission metadata object. */
        typedef std::shared_ptr<ppp::transmissions::ITransmission>                  ITransmissionPtr;

        std::shared_ptr<ppp::threading::BufferswapAllocator>                        BufferAllocator;    ///< Shared byte-buffer pool used for packet allocation.
        std::shared_ptr<ppp::configurations::AppConfiguration>                      AppConfiguration;   ///< Application-wide runtime configuration snapshot.
        std::shared_ptr<ppp::app::protocol::VirtualEthernetLogger>                  Logger;             ///< Diagnostic and audit event logger.
        uint16_t                                                                    Vlan;               ///< VLAN identifier assigned to this session.
        std::shared_ptr<ppp::net::Firewall>                                         Firewall;           ///< Optional firewall rule evaluator.

        typedef std::shared_ptr<vmux_skt>                                           vmux_skt_ptr;
        /**
         * @brief Pair of vmux protocol connection and server-side transport wrapper.
         */
        typedef struct vmux_linklayer {
            IMuxTransportPtr                                                        connection;
            uint16_t                                                                id_ = 0; ///< Server-assigned carrier-link id used by MUXON handshake; 0 means unassigned. Protected by syncobj_ (written by the carrier handshake under it).
            std::atomic<uint64_t>                                                   last_active_{0}; ///< Tick of the most recent inbound frame on this link; turbo's approximate "best link" signal (recency, NOT RTT). Atomic: written by both the vmux strand and the carrier forwarding coroutine.
            size_t                                                                  queued_bytes_ = 0; ///< Outstanding local write bytes (not peer ACK). Strand-affine.
            uint64_t                                                                total_sent_bytes_ = 0; ///< Lifetime bytes accepted by local write path. Strand-affine.
            ppp::app::mux::MuxLinkDrainState                                        drain_;            ///< Strand-affine in-flight write and retirement state.
            std::atomic<bool>                                                       handshake_complete_{false}; ///< True only after the carrier handshake succeeds. Atomic: written by the carrier handshake (under syncobj_), read lock-free on the vmux strand.

            // Per-link path state (strand-affine, same domain as queued_bytes_).
            // Updated from packet_input_ack on the vmux strand; used by PTO and
            // fast-retransmit path-awareness. All in ms-tick units.
            uint64_t                                                                srtt_ms_ = 0;       ///< Smoothed RTT (EWMA 7/8).
            uint64_t                                                                rttvar_ms_ = 0;     ///< RTT variance (EWMA 3/4).
            uint64_t                                                                min_rtt_ms_ = 0;    ///< Minimum observed RTT (floor).
            bool                                                                    has_rtt_sample_ = false; ///< True after first RTT sample.

            /** Unified "can this link accept new work?" predicate. All schedulability
             *  checks (count_live_carriers, turbo, shrink, scheduler) MUST use this
             *  instead of ad-hoc handshake/retiring combos. */
            bool schedulable() const noexcept {
                return handshake_complete_.load(std::memory_order_acquire) && !drain_.retiring();
            }
        }                                                                           vmux_linklayer;

        typedef std::shared_ptr<vmux_linklayer>                                     vmux_linklayer_ptr;
        /** @brief Callback executed before finalizing successful link-layer add. */
        typedef ppp::function<bool()>                                               vmux_native_add_linklayer_after_success_before_callback;
        /** @brief Atomic integer alias used for state flags. */
        typedef std::atomic<int>                                                    atomic_int;
        /** @brief Atomic boolean alias represented by integer semantics. */
        typedef atomic_int                                                          atomic_boolean;

#if defined(_LINUX)
    public:
        typedef std::shared_ptr<ppp::net::ProtectorNetwork>                         ProtectorNetworkPtr;

    public:
        ProtectorNetworkPtr                                                         ProtectorNetwork;
#endif

    private:
        friend class                                                                vmux_skt;
        friend struct                                                               vmux_net_test_access;

        template <typename _Tp>
        struct packet_less {
            /**
             * @brief Compare wrapped 32-bit sequence values.
             * @param seq1 Left sequence number.
             * @param seq2 Right sequence number.
             * @return true when @p seq1 is considered before @p seq2.
             * @details Uses signed subtraction on explicitly-cast values to
             * avoid implementation-defined behavior during wrap handling.
             */
            static constexpr bool                                                   before(uint32_t seq1, uint32_t seq2) noexcept {
                return static_cast<int32_t>(seq1) - static_cast<int32_t>(seq2) < 0;
            }

            /**
             * @brief Compare wrapped 32-bit sequence values in reverse order.
             */
            static constexpr bool                                                   after(uint32_t seq2, uint32_t seq1) noexcept {
                return before(seq1, seq2);
            }

            /** @brief Functor adapter for ordered containers. */
            constexpr bool                                                          operator()(const _Tp& __x, const _Tp& __y) const noexcept {
                return before(__x, __y);
            }
        };

#pragma pack(push, 1)
        /**
         * @brief Packed vmux packet header prepended to every vmux frame.
         *
         * Layout (9 bytes, no padding):
         *   - seq           (4 bytes) – monotonically increasing frame sequence number.
         *   - cmd           (1 byte)  – vmux command identifier (see anonymous enum below).
         *   - connection_id (4 bytes) – logical connection this frame belongs to.
         *
         * @note Multi-byte fields (seq, connection_id) are stored in NETWORK byte
         *       order on the wire: senders apply htonl when framing and receivers
         *       apply ntohl on parse (see post_internal / packet_input_unorder).
         */
        typedef struct
#if defined(__GNUC__) || defined(__clang__)
            __attribute__((packed))
#endif
        {
            uint32_t                                                                seq;           ///< Frame sequence number used for ordered delivery.
            uint8_t                                                                 cmd;           ///< vmux command byte (one of the cmd_* constants).
            uint32_t                                                                connection_id; ///< Logical connection identifier within this session.
        }                                                                           vmux_hdr;
#pragma pack(pop)

        /**
         * @brief vmux protocol command byte constants and packet-size limits.
         *
         * Command values are contiguous starting from `('E' - 1)` so that the
         * wire protocol is trivially distinguishable from arbitrary byte streams.
         */
        enum {
            cmd_none         = ('E' - 1), ///< Sentinel — no command / uninitialized.
            cmd_syn,                      ///< SYN — request to open a new logical connection.
            cmd_syn_ok,                   ///< SYN-OK — server acknowledges the connection request.
            cmd_push,                     ///< PUSH — carry application payload.
            cmd_fin,                      ///< FIN — close the logical connection gracefully.
            cmd_keep_alived,              ///< KEEP-ALIVE — heartbeat probe frame.
            cmd_acceleration,             ///< ACCELERATION — enable/disable fast-path flag.
            cmd_mux_mode_set,             ///< MUX-MODE-SET — debug-only request to switch the peer's scheduler mode.
            cmd_ack,                      ///< ACK — reliability feedback (received-sequence ranges); negotiated, unordered, never retransmitted.
            cmd_fec,                      ///< FEC — XOR parity over a group of reliable data frames; negotiated, unordered, never retransmitted.
            cmd_max,                      ///< Sentinel — one past the last valid command.

            max_buffers_size = UINT16_MAX - sizeof(vmux_hdr), ///< Maximum payload bytes per vmux frame.
        };

        /** @brief Internal completion callback for post operations. */
        typedef ppp::function<void(bool)>                                           PostInternalAsynchronousCallback;

        /**
         * @brief Exactly-once completion shared by queue, transport, and shutdown paths.
         * @details The callback is extracted under the local mutex and invoked after
         * releasing it, so a close request may race a carrier completion safely.
         */
        class tx_completion final {
        public:
            explicit tx_completion(const PostInternalAsynchronousCallback& callback) noexcept
                : callback_(callback) {}

            void                                                                    Finish(bool successed) noexcept {
                PostInternalAsynchronousCallback callback;
                {
                    std::lock_guard<std::mutex> scope(mutex_);
                    if (finished_) {
                        return;
                    }
                    finished_ = true;
                    callback = std::move(callback_);
                    callback_ = NULLPTR;
                }
                if (NULLPTR != callback) {
                    callback(successed);
                }
            }

        private:
            std::mutex                                                              mutex_;
            bool                                                                    finished_ = false;
            PostInternalAsynchronousCallback                                        callback_;
        };
        typedef std::shared_ptr<tx_completion>                                      tx_completion_ptr;
        typedef vmux::list<tx_completion_ptr>                                       tx_completion_list;

        /**
         * @brief Receive packet holder used by the ordered RX reorder queue.
         *
         * Buffers a single vmux payload fragment identified by its sequence number.
         */
        struct rx_packet {
            std::shared_ptr<Byte>                                                   buffer; ///< Shared byte buffer holding the raw payload.
            int                                                                     length = 0; ///< Valid payload length in bytes.
        };

        /**
         * @brief Transmit packet holder with an optional exactly-once completion.
         *
         * Extends @ref rx_packet with a shared post-send acknowledgment state.
         */
        struct tx_packet : rx_packet {
            tx_completion_ptr                                                       completion;
        };

        typedef vmux::list<vmux_linklayer_ptr>                                      vmux_linklayer_list;
        typedef vmux::vector<vmux_linklayer_ptr>                                    vmux_linklayer_vector;

        typedef vmux::list<tx_packet>                                               tx_packet_ssqueue;
        typedef vmux::map_pr<uint32_t, rx_packet, packet_less<uint32_t>>            rx_packet_ssqueue;

        /**
         * @brief Per-connection receive ordering context (flow v2).
         *
         * Holds one connection's independent DSN delivery state: the next
         * expected per-flow DSN, a bounded reorder buffer keyed by DSN, the
         * tick the oldest buffered frame was queued (gap timeout base), the
         * current buffered byte total (memory bound), a priming flag, and a
         * fin-seen flag used to release the context after the FIN is delivered.
         */
        struct flow_rx_context {
            uint32_t                                                                flow_rx_next_         = 0;     ///< Next expected per-flow DSN.
            ppp::app::mux::MuxFlowReorderBuffer<rx_packet>                         flow_reorder_;                ///< Strictly bounded reorder buffer for this flow only.
            uint64_t                                                                oldest_buffered_tick_ = 0;     ///< Tick the oldest buffered frame was queued; 0 = no active gap timer.
            bool                                                                    primed_               = false; ///< True once the initial expected DSN (1) has been established.
            bool                                                                    fin_seen_             = false; ///< True once a cmd_fin has been delivered for this connection.
        };

        /**
         * @brief Per-connection transmit queue for byte-based DRR fairness.
         * @details Deficit Round-Robin: each active flow gets a byte quantum per
         *          round; large flows cannot monopolize the global send path.
         *          Strand-affine — only touched on the vmux strand.
         */
        struct flow_tx_context {
            tx_packet_ssqueue                                                       queue;                 ///< Pending frames for this connection_id.
            size_t                                                                  bytes = 0;             ///< Sum of packet lengths in queue.
            int64_t                                                                  deficit = 0;           ///< DRR deficit (bytes of send credit remaining this round).
            bool                                                                    quantum_due = true;     ///< Add a quantum before the next turn.
            bool                                                                    active = false;        ///< True while this cid is in active_tx_flows_.
            uint32_t                                                                visit_count = 0;       ///< Frames popped from this flow in the current DRR visit (reset when requeued to back).
        };

        typedef vmux::unordered_map<uint32_t, vmux_skt_ptr>                         vmux_skt_map;
        typedef vmux::unordered_map<uint32_t, flow_rx_context>                      vmux_flow_map;
        typedef vmux::unordered_map<uint32_t, flow_tx_context>                      vmux_tx_flow_map;
        typedef vmux::list<uint32_t>                                                vmux_tx_active_list;
    public:
        enum mux_mode {
            mux_mode_compat  = 0,
            mux_mode_flow    = 1,
            mux_mode_balance = 2,
            mux_mode_stripe  = 3,
        };

        /**
         * @brief Negotiated receiver-side ordering mode (flow v2).
         *
         * ordering_compat keeps the existing single global tx_seq_/rx_ack_
         * delivery (today's behavior). ordering_flow_v2 delivers each
         * connection independently (per-flow DSN) so one slow link cannot
         * head-of-line block other connections. Negotiated via the MUX frame's
         * ordering_caps byte; defaults to compat and never upgrades unless both
         * peers explicitly agree.
         */
        enum receiver_ordering_mode {
            ordering_compat  = 0,
            ordering_flow_v2 = 1,
        };

        /** @brief MUX capability bit advertised in the handshake (bit0 = FLOW_V2). */
        enum {
            ordering_caps_flow_v2 = 0x01,
            ordering_caps_reliability = 0x02, ///< RELIABILITY — ACK feedback + retransmission sub-protocol.
            ordering_caps_fec = 0x04,         ///< FEC — XOR parity groups (implies RELIABILITY when agreed).
        };

    public:
        /**
         * @brief Construct a vmux network session.
         * @param context Execution context.
         * @param strand Serialized execution strand.
         * @param max_connections Maximum logical socket count.
         * @param server_mode true for server-side role.
         * @param acceleration true to enable acceleration by default.
         */
        vmux_net(const ContextPtr& context, const StrandPtr strand, uint16_t max_connections, bool server_mode, bool acceleration, mux_mode mode = mux_mode_compat) noexcept;
        /** @brief Destroy the session and release all managed resources. */
        ~vmux_net() noexcept;

    public:
        const StrandPtr&                                                            get_strand()          noexcept { return strand_; }
        const ContextPtr&                                                           get_context()         noexcept { return context_; }
        uint16_t                                                                    get_max_connections() noexcept { return status_.max_connections; }
        uint64_t                                                                    get_last()            noexcept { return status_.last_; }
        mux_mode                                                                    get_mode()            noexcept { return mode_; }
        /** @brief Current absolute carrier-link ceiling (turbo dynamic pool). */
        uint16_t                                                                    get_pool_hard_max()   noexcept { return status_.pool_hard_max; }
        /** @brief Raise the carrier-link ceiling for turbo before establishment.
         *  @param hard_max New ceiling; clamped to be >= max_connections. No-op after
         *         establishment (the base/ceiling are fixed once links are built). */
        void                                                                        set_pool_hard_max(uint16_t hard_max) noexcept;
        /**
         * @brief Consume the turbo controller's pending "add N carrier links" request.
         * @return Number of links the exchanger should connect+ConnectMux+add now
         *         through add_linklayer's established-session path. Resets the
         *         pending counter to 0.
         * @note Strand-affine; called by the client exchanger's periodic mux pump.
         */
        int                                                                         take_turbo_pending_grow() noexcept;
        static mux_mode                                                             parse_mode(const ppp::string& mode) noexcept;
        /** @brief Map a wire mode byte to a valid scheduler mode (unknown -> compat). */
        static mux_mode                                                             parse_mode_byte(Byte mode_value) noexcept;
        static const char*                                                          mode_name(mux_mode mode) noexcept;
        /** @brief Switch the active scheduler mode at runtime (strand-affine). */
        void                                                                        set_mode(mux_mode mode) noexcept;
        /** @brief Returns the negotiated receiver-side ordering mode. */
        receiver_ordering_mode                                                      get_ordering_mode()   noexcept { return ordering_mode_; }
        /**
         * @brief Set the negotiated receiver ordering mode (flow v2).
         * @param m Negotiated mode.
         * @note Only takes effect before the session is established; a call
         *       after establishment is a no-op (no hot compat<->flow-v2 switch).
         */
        void                                                                        set_ordering_mode(receiver_ordering_mode m) noexcept;
        /** @brief Applies peer capability negotiation before establishment. */
        void                                                                        apply_negotiation(bool local_supports_flow_v2, bool peer_supports_flow_v2, bool local_reliability, bool peer_reliability, bool local_fec, bool peer_fec) noexcept;
        /** @brief Applies the peer's authoritative negotiation result on the client. */
        void                                                                        apply_agreed_ordering(bool agreed_flow_v2, bool agreed_reliability, bool agreed_fec) noexcept;
        /** @brief True when the reliability sub-protocol (ACK + retransmit) was negotiated. */
        bool                                                                        reliability_agreed() const noexcept { return reliability_on_; }
        /** @brief True when XOR parity FEC was negotiated (implies reliability_agreed). */
        bool                                                                        fec_agreed() const noexcept { return fec_on_; }
        /** @brief Returns the latest observable scheduler/link state. */
        ppp::app::mux::MuxRuntimeState                                               get_runtime_state() const noexcept;
        /** @brief True for session-level control frames (keep-alive / mux-mode-set). */
        static bool                                                                 is_session_control(Byte cmd) noexcept {
            return cmd == cmd_keep_alived || cmd == cmd_mux_mode_set;
        }
        /** @brief True for connection-level control frames (syn / syn-ok / acceleration). */
        static bool                                                                 is_connection_control(Byte cmd) noexcept {
            return cmd == cmd_syn || cmd == cmd_syn_ok || cmd == cmd_acceleration;
        }
        /**
         * @brief True for reliability control frames (ack / fec).
         * @details These are unordered: they carry seq=0, are delivered inline by
         *          the receiver in BOTH ordering modes, and are themselves never
         *          ACKed, retransmitted, or FEC-protected (no ack-of-ack).
         */
        static bool                                                                 is_reliability_control(Byte cmd) noexcept {
            return cmd == cmd_ack || cmd == cmd_fec;
        }
        /** @brief True for per-flow data frames carrying a per-connection DSN (push / fin). */
        static bool                                                                 is_per_flow_data(Byte cmd) noexcept {
            return cmd == cmd_push || cmd == cmd_fin;
        }
        /**
         * @brief True when this scheduler configuration uses negotiated per-flow
         *        receiver ordering (flow v2 / per-flow DSN).
         * @details balance spreads one session's frames across links by competition
         *          (any free link sends any frame) and relies on the receiver
         *          reordering each connection independently by per-flow DSN, so
         *          cross-link reordering is not mistaken for loss. stripe (legacy,
         *          experimental) likewise needs per-flow reordering. flow only needs
         *          it when turbo is enabled, so turbo can add best-link-first and
         *          prewarmed carriers without reintroducing cross-flow HoL blocking.
         */
        static bool                                                                 mode_requires_flow_v2(mux_mode mode, bool turbo) noexcept {
            return mode == mux_mode_balance || mode == mux_mode_stripe || (mode == mux_mode_flow && turbo);
        }
        static bool                                                                 mode_requires_flow_v2(mux_mode mode) noexcept {
            return mode_requires_flow_v2(mode, false);
        }
        /**
         * @brief Push a debug-only mux-mode change request to the peer.
         * @param mode  Desired scheduler mode for the remote endpoint.
         * @return true when the control frame was queued for transmit.
         * @note No-op unless a non-empty `mux.debug.key` is configured locally.
         */
        bool                                                                        post_mux_mode_set(mux_mode mode) noexcept;
        const uint32_t&                                                             get_tx_seq()          noexcept { return status_.tx_seq_; }
        const uint32_t&                                                             get_rx_ack()          noexcept { return status_.rx_ack_; }
        bool                                                                        is_disposed()         noexcept { return base_.disposed_.load(std::memory_order_acquire); }
        bool                                                                        is_established()      noexcept { return !base_.disposed_.load(std::memory_order_acquire) && base_.established_; }

        /** @brief Handle fast transport training/control frame. */
        bool                                                                        ftt(uint32_t seq, uint32_t ack) noexcept;
        /** @brief Generate pseudo-random aid value in given range. */
        static uint32_t                                                             ftt_random_aid(int min, int max) noexcept;

        /** @brief Close the session in executor context. */
        void                                                                        close_exec() noexcept;
        /** @brief Drive periodic maintenance and heartbeat updates. */
        bool                                                                        update() noexcept;
        /**
         * @brief Add a new link-layer endpoint.
         * @param connection Underlying virtual ethernet connection.
         * @param linklayer Receives created link-layer object on success.
         * @param cb Callback executed before final commit.
         */
        bool                                                                        add_linklayer(
            const IMuxTransportPtr&                                                 connection,
            vmux_linklayer_ptr&                                                     linklayer,
            const vmux_native_add_linklayer_after_success_before_callback&          cb) noexcept;

        /**
         * @brief Begin retiring one carrier link at runtime (turbo dynamic pool
         *        shrink, C-B4). Strand-affine.
         * @return true when a link was marked for retirement.
         * @details Picks the least-recently-active non-retiring link, marks it
         *          retiring_ and removes it from tx_links_ so it takes no new frames.
         *          The link object stays in rx_links_ until its in-flight writes
         *          drain to 0, at which point reap_retired_linklayers() disposes it.
         *          Never retires below max_connections (the base must always stand).
         */
        bool                                                                        retire_linklayer_runtime() noexcept;
        /** @brief Dispose links that finished retiring (inflight_ == 0). Strand-affine; called from update(). */
        void                                                                        reap_retired_linklayers() noexcept;
        /** @brief Container-only reap; caller holds syncobj_. Reaped links are collected for disposal after the lock is released. */
        void                                                                        reap_retired_linklayers_locked(vmux_linklayer_vector& reaped) noexcept;
        /**
         * @brief Turbo pool controller step (C-B5). Strand-affine; called from update().
         * @param now Current tick.
         * @details Derives a target pool size from link quality (a recency/backlog
         *          proxy — worse quality => larger pool, per the design) within
         *          [max_connections, pool_hard_max], then moves the live pool one
         *          step toward it (grow via turbo_pending_grow_ for the exchanger to
         *          act on; shrink via retire_linklayer_runtime), rate-limited by a
         *          cooldown for hysteresis. No-op unless turbo is on.
         */
        void                                                                        turbo_controller_tick(uint64_t now) noexcept;

        /**
         * @brief Connect to a remote host and return logical vmux socket.
         */
        bool                                                                        connect_yield(
            ppp::coroutines::YieldContext&                                          y,
            const ContextPtr&                                                       context,
            const StrandPtr&                                                        strand,
            const std::shared_ptr<boost::asio::ip::tcp::socket>&                    sk,
            const template_string&                                                  host,
            int                                                                     port,
            const std::shared_ptr<vmux_skt_ptr>&                                    return_connection) noexcept;

    public:
        template <typename YieldHandler>
        /**
         * @brief Execute handler on vmux strand and wait via coroutine yield.
         * @tparam YieldHandler Callable type returning bool-compatible value.
         * @param y Coroutine yield context.
         * @param h Handler executed on vmux executor.
         * @return Handler result.
         */
        bool                                                                        do_yield(ppp::coroutines::YieldContext& y, YieldHandler&& h) noexcept {
            bool ok = false;

            // Guard Suspend() behind the post result: if the executor is unavailable the
            // lambda (and the y.R() inside it) will never run, so calling Suspend() would
            // park the coroutine with no future Resume() – a permanent coroutine leak.
            bool posted = vmux_post_exec(context_, strand_,
                [&y, &ok, h]() noexcept {
                    ok = h();
                    y.R();
                });

            if (!posted) {
                return false;
            }

            y.Suspend();
            return ok;
        }

        /**
         * @brief Allocate a shared byte array through the configured allocator.
         */
        std::shared_ptr<Byte>                                                       make_byte_array(int array_size) noexcept {
            return ppp::threading::BufferswapAllocator::MakeByteArray(BufferAllocator, array_size);
        }
        
        /** @brief Generate a globally unique vmux connection identifier. */
        uint32_t                                                                    generate_id() noexcept;

        /** @brief Return current monotonic tick count in milliseconds. */
        static uint64_t                                                             now_tick() noexcept { return ppp::threading::Executors::GetTickCount(); }

    private:
        /** @brief Attach one validated carrier to the scheduling containers. Caller holds syncobj_. */
        bool                                                                        attach_linklayer_locked(
            const IMuxTransportPtr&                                                 connection,
            vmux_linklayer_ptr&                                                     linklayer) noexcept;
        /** @brief Create an optional exactly-once completion for one accepted post. */
        tx_completion_ptr                                                           make_tx_completion(const PostInternalAsynchronousCallback& callback) noexcept;
        /** @brief Register a completion unless shutdown has already been requested. */
        bool                                                                        track_tx_completion(const tx_completion_ptr& completion) noexcept;
        /** @brief Finish one completion and remove it from the pending registry. */
        void                                                                        finish_tx_completion(const tx_completion_ptr& completion, bool successed) noexcept;
        /** @brief Finish a detached completion list without holding VMUX state locks. */
        static void                                                                 finish_tx_completions(tx_completion_list& completions, bool successed) noexcept;
        /** @brief Fail every accepted TX completion that has not finished yet. */
        void                                                                        fail_pending_tx_completions() noexcept;
        /** @brief Begin terminal close once and fail outstanding user completions. */
        bool                                                                        begin_close() noexcept;
        /** @brief True once external close has prevented new work from registering. */
        bool                                                                        close_requested() const noexcept;
        /** @brief True only while executing on this session's mandatory strand. */
        bool                                                                        is_strand_thread() const noexcept {
            return NULLPTR != strand_ && strand_->running_in_this_thread();
        }

        /** @brief Send packet to one specific underlying link-layer endpoint. */
        bool                                                                        underlyin_sent(const vmux_linklayer_ptr& linklayer, const std::shared_ptr<Byte>& packet, int packet_length, const tx_completion_ptr& completion) noexcept;

        /** @brief Find logical socket by connection id. */
        vmux_skt_ptr                                                                get_connection(uint32_t connection_id) noexcept;
        /** @brief Remove and return connection when pointer identity matches. */
        vmux_skt_ptr                                                                release_connection(uint32_t connection_id, vmux_skt* refer_pointer) noexcept;

        /** @brief Insert or process out-of-order inbound packet (zero-copy variant when owner is provided). */
        bool                                                                        packet_input_unorder(const vmux_linklayer_ptr& linklayer, vmux_hdr* h, int length, uint64_t now, const std::shared_ptr<Byte>& owner = NULLPTR) noexcept;
        /** @brief Parse and dispatch one inbound vmux command payload (zero-copy variant when owner is provided). */
        bool                                                                        packet_input(Byte cmd, Byte* buffer, int buffer_size, uint64_t now, const std::shared_ptr<Byte>& owner = NULLPTR) noexcept;

        /** @brief Route inbound payload to target logical connection. */
        void                                                                        packet_input_read(uint32_t connection_id, Byte* buffer, int buffer_size, uint64_t now, const std::shared_ptr<Byte>& owner = NULLPTR) noexcept;

        /** @brief Validate and apply a debug-only cmd_mux_mode_set control frame. */
        void                                                                        packet_input_mux_mode_set(const Byte* buffer, int buffer_size) noexcept;

        /** @brief Per-flow (flow v2) receive path: independent per-connection DSN delivery (zero-copy variant when owner is provided). */
        bool                                                                        packet_input_flow(const vmux_linklayer_ptr& linklayer, vmux_hdr* h, int length, uint64_t now, const std::shared_ptr<Byte>& owner = NULLPTR) noexcept;
        /** @brief Deliver one framed packet (push/fin) to its logical connection (zero-copy variant when owner is provided). */
        bool                                                                        deliver_one(Byte cmd, vmux_hdr* h, int length, uint64_t now, const std::shared_ptr<Byte>& owner = NULLPTR) noexcept;
        /** @brief Periodically fail per-flow contexts whose gap timed out. */
        void                                                                        flow_evict_expired(uint64_t now) noexcept;
        /** @brief Fail the session when a compat global reorder gap timed out. */
        void                                                                        compat_evict_expired(uint64_t now) noexcept;
        /** @brief Fail one logical flow without delivering past an unrecovered gap. */
        void                                                                        fail_flow(uint32_t connection_id, const char* reason) noexcept;
        flow_rx_context*                                                            try_get_or_create_flow(uint32_t connection_id) noexcept;
        void                                                                        note_flow_buffered(size_t bytes) noexcept;
        void                                                                        note_flow_unbuffered(size_t bytes) noexcept;
        /** @brief Release a flow context once its FIN was delivered and buffer drained. */
        void                                                                        maybe_release_flow(uint32_t connection_id, flow_rx_context& fx) noexcept;

        /**
         * @brief Reliability sub-protocol (negotiated; strand-affine).
         * @details ACK feedback + retransmission: the receiver records received
         *          sequences per sequence space (global under compat, per-flow
         *          DSN under flow_v2) and periodically emits cmd_ack frames; the
         *          sender retains frames in rtx_ until acked and re-sends holes
         *          (fast retransmit on dup-ACK distance, PTO as backstop) on any
         *          live carrier with the ORIGINAL sequence number.
         */
        /** @brief Record one received reliable frame for ACK generation (strand-affine). */
        void                                                                        note_ack_pending(uint32_t connection_id, uint32_t seq, uint64_t now) noexcept;
        /** @brief Emit a cmd_ack frame when the delayed-ACK policy says so (strand-affine). */
        void                                                                        maybe_send_ack(uint64_t now, bool force) noexcept;
        /** @brief Process an inbound cmd_ack payload: release acked frames, drive fast retransmit. */
        void                                                                        packet_input_ack(Byte* buffer, int buffer_size, uint64_t now) noexcept;
        /** @brief Process an inbound cmd_fec payload: cache the group, attempt single-loss recovery. */
        void                                                                        packet_input_fec(const vmux_linklayer_ptr& linklayer, Byte* buffer, int buffer_size, uint64_t now) noexcept;
        /** @brief Retain a just-sent reliable frame in the retransmit buffer (strand-affine). @return true when this was the first send of the frame. */
        bool                                                                        track_sent_frame(const std::shared_ptr<Byte>& packet, int packet_length, uint64_t now, uint16_t link_id = 0) noexcept;
        /** @brief Record ACK/FEC state for one inbound frame before dispatch (strand-affine). */
        void                                                                        note_inbound_reliability_frame(const vmux_linklayer_ptr& linklayer, const std::shared_ptr<Byte>& frame, vmux_hdr* h, int length, uint64_t now) noexcept;
        /** @brief Latch the negotiated reliability/FEC flags and their config bounds (pre-establishment). */
        void                                                                        latch_reliability(bool agreed_reliability, bool agreed_fec) noexcept;
        /** @brief Re-send scheduled lost frames on live carriers, bounded per turn (strand-affine). */
        void                                                                        retransmit_pending(uint64_t now) noexcept;
        /** @brief Current probe-timeout derived from the smoothed RTT estimate (session-level fallback). */
        uint64_t                                                                    current_pto() const noexcept;
        /** @brief Per-link probe-timeout using QUIC-style SRTT+4*RTTVAR (falls back to session PTO when no sample). */
        uint64_t                                                                    current_pto(const vmux_linklayer_ptr& linklayer) const noexcept;
        /** @brief Periodic reliability maintenance: ACK delay flush, PTO scan, FEC flush (strand-affine). */
        void                                                                        reliability_tick() noexcept;
        /** @brief Arm the reliability maintenance timer (no-op unless negotiated). */
        void                                                                        start_reliability_timer() noexcept;
        /** @brief Drop reliability state of one connection space (flow reset / release). */
        void                                                                        release_flow_reliability_state(uint32_t connection_id) noexcept;
        /** @brief Fold one sent data frame into the running FEC group (strand-affine). */
        void                                                                        fec_note_sent(const std::shared_ptr<Byte>& packet, int packet_length, uint64_t now) noexcept;
        /** @brief Cache one received data frame and advance pending FEC groups (strand-affine). */
        void                                                                        fec_note_received(const vmux_linklayer_ptr& linklayer, uint32_t connection_id, uint32_t seq, const std::shared_ptr<Byte>& buffer, int length, uint64_t now) noexcept;
        /** @brief Emit the running FEC group as a cmd_fec frame when non-empty (strand-affine). */
        void                                                                        fec_flush_group() noexcept;
        /** @brief Attempt single-loss recovery for every group that references (cid, seq). */
        void                                                                        fec_try_recover_groups(const vmux_linklayer_ptr& linklayer, uint32_t connection_id, uint32_t seq, uint64_t now) noexcept;

        /** @brief Process SYN request and create connecting vmux socket state. */
        bool                                                                        process_rx_connecting(std::shared_ptr<vmux_skt>& skt, uint32_t connection_id, const char* host, int host_size) noexcept;

        /** @brief Refresh activity timestamp when session is alive. */
        void                                                                        active(uint64_t now) noexcept { 
            if (!base_.disposed_.load(std::memory_order_acquire)) {
                status_.last_ = now; 
            }
        }

        /** @brief Refresh activity timestamp using current tick. */
        void                                                                        active() noexcept { 
            uint64_t now = now_tick();
            active(now);
        }

        /** @brief Post a vmux command using default acceleration behavior. */
        bool                                                                        post(Byte cmd, const void* packet, int packet_length, uint32_t connection_id) noexcept {
            return post(cmd, packet, packet_length, connection_id, true);
        }
        /** @brief Post a vmux command with explicit acceleration switch. */
        bool                                                                        post(Byte cmd, const void* packet, int packet_length, uint32_t connection_id, bool acceleration) noexcept {
            PostInternalAsynchronousCallback null_expr;
            return post(cmd, packet, packet_length, connection_id, acceleration, null_expr);
        }
        /** @brief Post a vmux command with optional completion callback. */
        bool                                                                        post(Byte cmd, const void* packet, int packet_length, uint32_t connection_id, bool acceleration, const PostInternalAsynchronousCallback& posted_ac) noexcept {
            bool successing = post_internal(cmd, packet, packet_length, connection_id, acceleration, posted_ac);
            if (!successing) {
                close_exec();
            }

            return successing;
        }
        /** @brief Build and enqueue one vmux framed packet; synchronously requires the mux strand. */
        bool                                                                        post_internal(Byte cmd, const void* packet, int packet_length, uint32_t connection_id, bool acceleration, const PostInternalAsynchronousCallback& posted_ac) noexcept;
        /** @brief Enqueue a prebuilt frame; synchronously requires the mux strand. */
        bool                                                                        post_internal(const std::shared_ptr<Byte>& packet, int packet_length, bool acceleration, const PostInternalAsynchronousCallback& posted_ac) noexcept;
        /** @brief True when an underlying link-layer endpoint is usable. */
        static bool                                                                 is_linklayer_active(const vmux_linklayer_ptr& linklayer) noexcept;
        /** @brief Pick the next active link-layer round-robin (stripe distribution). */
        vmux_linklayer_ptr                                                          select_striped_linklayer() noexcept;
        /** @brief Pick the most-recently-active link for a turbo first packet.
         *  @details Approximate "best link" by recency of inbound traffic
         *           (last_active_), NOT RTT — a cheap signal that reuses existing
         *           per-link activity with no extra control frames. Used only for a
         *           new connection's first packet under turbo; the connection is NOT
         *           bound to this link (later frames return to the competition pool). */
        vmux_linklayer_ptr                                                          select_turbo_linklayer() noexcept;
        /** @brief Return true when a carrier id is already assigned to another link. */
        bool                                                                        linklayer_id_in_use(uint16_t id, const vmux_linklayer_ptr& except) noexcept;
        /** @brief Allocate a non-zero carrier id in [1, pool_hard_max], reusing retired ids. */
        uint16_t                                                                    allocate_linklayer_id(const vmux_linklayer_ptr& linklayer) noexcept;
        /** @brief Read the connection_id stored in a queued vmux frame buffer. */
        static uint32_t                                                             peek_connection_id(const std::shared_ptr<Byte>& packet, int packet_length) noexcept;

        /** @brief Drain queued transmit packets using the legacy scheduler. */
        bool                                                                        process_tx_compat_packets() noexcept;
        /** @brief Drain the high-priority control-frame queue first (flow v2).
         *  @return false on a hard send failure, true otherwise.
         *  @details Control frames (syn/syn_ok/acceleration/keep_alived/mux_mode_set)
         *           carry seq=0 under flow v2 and are delivered inline by the
         *           receiver (not DSN-gated), so they may be sent ahead of data on
         *           any free link. This keeps new-connection setup and heartbeats
         *           alive even when data TX is backlogged. No-op under compat,
         *           where global ordering forbids reordering control ahead of data. */
        bool                                                                        process_tx_ctrl_packets() noexcept;
        /** @brief Drain queued transmit packets through one primary link. */
        bool                                                                        process_tx_flow_packets() noexcept;
        /** @brief Drain queued transmit packets using the competition scheduler
         *  for balance mode. Identical send-side policy to compat (any free link
         *  sends the next queued frame — no per-connection binding); the difference
         *  is that balance negotiates per-flow receiver ordering (flow v2) so each
         *  connection is reordered independently on receive, removing cross-flow
         *  head-of-line blocking without pinning connections to links. */
        bool                                                                        process_tx_balance_packets() noexcept;
        /** @brief Drain queued transmit packets striped round-robin across links. */
        bool                                                                        process_tx_stripe_packets() noexcept;

        
        /** @brief Drain all queued transmit packets to available link layers. */
        bool                                                                        process_tx_all_packets() noexcept;
        /** @brief Final cleanup routine for session shutdown. */
        void                                                                        finalize() noexcept;

        /** @brief Get one active underlying virtual-ethernet connection. */
        IMuxTransportPtr                                                            get_linklayer() noexcept;
        /** @brief Remove one link-layer endpoint from scheduling tables. */
        void                                                                        remove_linklayer(const vmux_linklayer_ptr& linklayer) noexcept;
        /** @brief Container-only link removal; caller holds syncobj_ (no callbacks/IO). */
        void                                                                        remove_linklayer_locked(const vmux_linklayer_ptr& linklayer) noexcept;
        /**
         * @brief Handle one carrier exit on the vmux strand.
         * @details Removes the link. If no other live carriers remain, closes the
         *          session; otherwise isolates the failure and continues draining.
         *          Multi-link is throughput/latency, not HA — in-flight frames on
         *          the dead link are lost without VMUX-layer replay.
         */
        void                                                                        on_link_exit(const vmux_linklayer_ptr& linklayer, const char* reason) noexcept;
        /** @brief Count handshake-complete non-retiring carriers (strand-affine). */
        size_t                                                                      count_live_carriers(const vmux_linklayer_ptr& except = NULLPTR) const noexcept;
        /** @brief True when the link still has room under the per-link byte high-water. */
        static bool                                                                 link_has_byte_credit(const vmux_linklayer_ptr& linklayer, int packet_length) noexcept;
        /** @brief Enqueue one data frame into the per-flow DRR queue (strand-affine). */
        void                                                                        enqueue_flow_tx(uint32_t connection_id, tx_packet&& packet) noexcept;
        /** @brief Total queued data frames across all per-flow TX queues. */
        size_t                                                                      tx_data_depth() const noexcept;
        /** @brief Total queued data bytes across all per-flow TX queues. */
        size_t                                                                      tx_data_bytes() const noexcept;
        /** @brief Pop next data frame via deficit round-robin; false if none/credit. */
        bool                                                                        drr_pop_next(tx_packet& out) noexcept;
        /** @brief Return a frame to the front of its flow queue (send failed). */
        void                                                                        drr_requeue_front(tx_packet&& packet) noexcept;
        /** @brief Drop all per-flow TX state (finalize). */
        void                                                                        clear_flow_tx() noexcept;
        /** @brief Publish a lock-free runtime snapshot (call on strand or under mutex). */
        void                                                                        publish_runtime_snapshot_locked() noexcept;

        /** @brief Validate and post outgoing connect request command. */
        bool                                                                        connect_require(
            const std::shared_ptr<boost::asio::ip::tcp::socket>&                    sk, 
            const template_string&                                                  host, 
            int                                                                     port) noexcept;

        /** @brief Perform protocol handshake on specified link-layer. */
        bool                                                                        handshake(const vmux_linklayer_ptr& linklayer, uint16_t connection_id, ppp::coroutines::YieldContext& y) noexcept;
        /** @brief Forward frames between network link-layer and vmux core. */
        bool                                                                        forwarding(const vmux_linklayer_ptr& linklayer, ppp::coroutines::YieldContext& y) noexcept;
        
        /** @brief Recompute and schedule next heartbeat timeout threshold. */
        void                                                                        switch_to_next_heartbeat_timeout() noexcept;
        /** @brief Mark at least one link-layer as established. */
        void                                                                        linklayer_established() noexcept;
        /** @brief Touch/update link-layer usage order for load balancing. */
        void                                                                        linklayer_update(const vmux_linklayer_ptr& linklayer) noexcept;
        void                                                                        refresh_runtime_active_links() noexcept;

        /** @brief Connect helper that reports result through callback. */
        bool                                                                        connect(const ContextPtr& context, const StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& sk, const template_string& host, int port, const ConnectAsynchronousCallback& ac) noexcept;

    private:
        /** @brief Core boolean state flags for vmux session lifecycle. */
        struct {
            bool                                                                    ftt_               : 1; ///< Fast transport training frame received.
            bool                                                                    server_or_client_  : 1; ///< true = server role; false = client role.
            bool                                                                    acceleration_      : 4; ///< Acceleration enabled flags (multi-bit).

            /**
             * @brief Session-established flag (atomic).
             *
             * Written by the carrier handshake path (under syncobj_) and read
             * lock-free from the vmux strand, user threads, and exchanger
             * getters (is_established). Kept as a standalone std::atomic<bool> —
             * NOT a bit-field — so a load never tears against the carrier-side
             * store and writing it never read-modify-writes neighbouring flags.
             */
            std::atomic<bool>                                                       established_;          ///< At least one link-layer is established.

            /**
             * @brief Session-finalized flag (atomic).
             *
             * Read from multiple threads (the per-link forwarding strands, the
             * vmux strand drain, and send/read completion callbacks) and written
             * by finalize(). Kept as a standalone std::atomic<bool> — NOT a
             * bit-field — so the teardown guard has a well-defined happens-before
             * and writing it never read-modify-writes the neighbouring flags.
             */
            std::atomic<bool>                                                       disposed_;             ///< Set when session is finalized.
        }                                                                           base_;

        /** @brief Runtime counters, sequence values, and heartbeat timestamps. */
        struct {
            uint16_t                                                                max_connections    = 0; ///< Initial/established carrier-link target (= --tun-mux base). Established fires at this count; unchanged on the wire.
            uint16_t                                                                pool_hard_max      = 0; ///< Absolute upper bound on carrier links (turbo dynamic pool). Equals max_connections when turbo is off; base*factor when on. add_linklayer quota uses this.
            uint16_t                                                                pool_current       = 0; ///< Current runtime target pool size (turbo controller), in [max_connections, pool_hard_max]. Equals max_connections when turbo off.
            uint16_t                                                                opened_connections = 0; ///< Successful base-pool handshakes used to mark initial establishment; runtime carrier ids are allocated from free slots, not by incrementing this counter.

            uint32_t                                                                rx_ack_            = 0; ///< Last acknowledged inbound sequence number.
            uint32_t                                                                tx_seq_            = 0; ///< Next outbound sequence number to use.

            std::atomic<uint64_t>                                                   last_              {0}; ///< Monotonic tick of last received packet. Atomic: written by carrier handshake and vmux strand; read via get_last() from any thread.
            std::atomic<uint64_t>                                                   last_heartbeat_    {0}; ///< Monotonic tick of last heartbeat sent. Atomic: written by carrier handshake and vmux strand.

            std::atomic<uint64_t>                                                   heartbeat_timeout_ {0}; ///< Deadline tick beyond which session is considered dead. Atomic: written by carrier handshake and vmux strand.
        }                                                                           status_;

        SynchronizationObject                                                       syncobj_;           ///< Mutex protecting shared connection map and the link containers (rx_links_/tx_links_) against the carrier handshake strand.
        /**
         * @brief Cross-thread terminal state for accepted TX completions only.
         * @details This deliberately does not protect scheduler containers: those
         * remain VMUX-strand-affine. It lets a stop/close caller fail waiters without
         * touching queues, links, maps, or socket state off strand.
         */
        mutable std::mutex                                                          tx_completion_mutex_;
        tx_completion_list                                                          pending_tx_completions_;
        bool                                                                        close_requested_ = false;
        mutable std::mutex                                                          runtime_state_mutex_; ///< Guards runtime_state_ writes; prefer strand.
        ppp::app::mux::MuxRuntimeState                                               runtime_state_;       ///< Authoritative runtime facts.
        mutable std::shared_ptr<const ppp::app::mux::MuxRuntimeState>               runtime_snapshot_;    ///< Lock-free published copy for cross-thread reads.

        vmux_skt_map                                                                skts_;              ///< Active logical socket map keyed by connection_id.
        ContextPtr                                                                  context_;           ///< ASIO execution context; outlives strand_.
        StrandPtr                                                                   strand_;            ///< Serialized strand for vmux event loop.

        vmux_tx_flow_map                                                            tx_flows_;          ///< connection_id -> per-flow TX queue + DRR deficit (strand-affine).
        vmux_tx_active_list                                                         active_tx_flows_;   ///< RR ring of cids with non-empty TX queues (strand-affine).
        size_t                                                                      tx_data_frames_ = 0; ///< Aggregate data frame count across tx_flows_ (for high-water / turbo).
        size_t                                                                      tx_data_bytes_total_ = 0; ///< Aggregate data byte count across tx_flows_.
        tx_packet_ssqueue                                                           tx_ctrl_queue_;     ///< High-priority control-frame queue (flow v2 only); drained before data so SYN / heartbeats are never starved.
        rx_packet_ssqueue                                                           rx_queue_;          ///< Out-of-order inbound packet reorder queue.

        mux_mode                                                                    mode_               = mux_mode_compat; ///< Transmit scheduler policy.
        bool                                                                        mux_mode_set_pushed_ = false; ///< One-shot guard for the debug mux-mode-set push.
        uint64_t                                                                    mux_mode_set_last_accept_ = 0; ///< Tick of last accepted mux-mode-set (rate limit).
        int                                                                         mux_mode_set_reject_streak_ = 0; ///< Consecutive rejected mux-mode-set frames (rate-limit log spam).
        uint32_t                                                                    next_connection_id_ = 0; ///< Session-local connection_id allocator (never reuses within a session until wrap).
        bool                                                                        connection_id_wrap_ = false; ///< True after connection id space exhausted; refuse new logical connects.
        size_t                                                                      stripe_cursor_ = 0; ///< Round-robin cursor over rx_links_ (stripe mode).

        receiver_ordering_mode                                                      ordering_mode_ = ordering_compat; ///< Negotiated receiver ordering mode (flow v2).
        vmux_flow_map                                                               flows_;             ///< connection_id -> per-flow receive context (flow v2 only).
        vmux::unordered_map<uint32_t, uint32_t>                                     tx_flow_seq_;       ///< connection_id -> next per-flow DSN to send (flow v2 only).
        size_t                                                                      flow_reorder_cap_bytes_ = 0; ///< Per-connection reorder buffer byte cap (from config).
        size_t                                                                      session_reorder_cap_bytes_ = 0; ///< Session-wide reorder byte cap (from config).
        size_t                                                                      session_reorder_bytes_ = 0; ///< Current session-wide buffered reorder bytes.
        size_t                                                                      flow_context_cap_       = 0; ///< Max concurrent flow receive contexts (DoS bound).
        size_t                                                                      flow_aggregate_cap_bytes_ = 0; ///< Aggregate reorder bytes across all flow contexts.
        size_t                                                                      flow_aggregate_bytes_   = 0; ///< Live sum of buffered reorder bytes across flows_.
        size_t                                                                      max_open_flows_ = 0; ///< Max open logical flows (from config).
        size_t                                                                      tx_ctrl_budget_frames_ = (size_t)PPP_MUX_TX_CTRL_BUDGET_FRAMES; ///< Ctrl frames per drain turn.
        uint64_t                                                                    flow_reorder_timeout_   = 0; ///< Gap wait timeout in ms (flow_v2 per-flow; compat global rx_queue_).
        uint64_t                                                                    rx_gap_oldest_tick_     = 0; ///< Compat: tick of oldest buffered OOO frame (0 = no global gap).
        uint64_t                                                                    tx_backlog_since_       = 0; ///< Tick the data tx queue first stayed at/over high-water (0 = not backlogged); drives the D11 stall watchdog.
        size_t                                                                      tx_queue_high_water_    = (size_t)PPP_MUX_TX_QUEUE_HIGH_WATER; ///< Aggregate data-frame high-water (tx_data_frames_) for D11 backpressure.
        uint64_t                                                                    tx_backlog_stall_ms_    = (uint64_t)PPP_MUX_TX_BACKLOG_STALL_TIMEOUT; ///< Backlog stall timeout in ms (from config; D11 watchdog).
        bool                                                                        turbo_                  = false; ///< flow-mode turbo enabled (from config; best-link-first first packet).
        uint64_t                                                                    turbo_last_adjust_      = 0;     ///< Tick of the last turbo pool grow/shrink step (cooldown base).
        uint64_t                                                                    turbo_grow_hold_since_  = 0;     ///< When backlog first crossed grow threshold (0 = not armed).
        uint64_t                                                                    turbo_shrink_hold_since_ = 0;    ///< When backlog first crossed shrink threshold (0 = not armed).
        int                                                                         turbo_pending_grow_     = 0;     ///< Carrier links the turbo controller wants the exchanger to add (consumed by client DoMuxEvents). Strand-affine.

        vmux_linklayer_vector                                                       rx_links_;          ///< All link-layer endpoints available for inbound.
        vmux_linklayer_list                                                         tx_links_;          ///< Link-layer endpoints ordered by transmit usage.

        /** @brief One pending receive-side FEC group (parity + slots for covered frames). */
        struct fec_rx_group {
            ppp::app::mux::MuxFecFrameView                                        view;               ///< Parsed parity frame (entries + parity block).
            vmux::vector<std::shared_ptr<Byte>>                                   frames;             ///< Received frames aligned with view.entries (null = missing).
            vmux::vector<int>                                                     lengths;            ///< Frame lengths aligned with view.entries.
            int                                                                   missing = 0;        ///< Slots not yet received/recovered.
        };
        /** @brief One cached received data frame kept for FEC single-loss recovery. */
        struct fec_cached_frame {
            std::shared_ptr<Byte>                                                 buffer;
            int                                                                   length = 0;
        };

        bool                                                                        reliability_on_ = false;   ///< Negotiated reliability sub-protocol active.
        bool                                                                        fec_on_ = false;           ///< Negotiated FEC active (implies reliability_on_).
        size_t                                                                      rtx_cap_bytes_ = (size_t)PPP_MUX_RELIABILITY_RTX_BYTES;   ///< Retransmit buffer byte cap (from config).
        uint32_t                                                                    rtx_max_attempts_ = (uint32_t)PPP_MUX_RELIABILITY_RTX_MAX_ATTEMPTS; ///< Per-frame retransmit attempt cap (from config).
        uint64_t                                                                    ack_delay_ms_ = (uint64_t)PPP_MUX_RELIABILITY_ACK_DELAY;  ///< Delayed-ACK wait in ms (from config).
        uint64_t                                                                    reliability_gap_timeout_ms_ = (uint64_t)PPP_MUX_RELIABILITY_GAP_TIMEOUT; ///< Gap timeout when reliability is active (from config).
        int                                                                         fec_group_k_ = PPP_MUX_FEC_GROUP;       ///< Data frames per FEC parity group (from config).
        uint64_t                                                                    fec_flush_ms_ = (uint64_t)PPP_MUX_FEC_FLUSH;            ///< Partial-group flush delay in ms (from config).
        bool                                                                        fec_flush_due_ = false;   ///< Full FEC group awaiting deferred emission on the maintenance tick.

        ppp::app::mux::MuxRetransmitBuffer                                          rtx_;               ///< Sender-side retransmit buffer (strand-affine).
        vmux::unordered_map<uint32_t, size_t>                                       rtx_flow_bytes_;    ///< Per-flow RTX byte usage (strand-affine, flow v2 only).
        vmux::unordered_map<uint32_t, ppp::app::mux::MuxAckTracker>                 ack_trackers_;      ///< Received-sequence trackers; cid 0 = compat global space (strand-affine).
        uint32_t                                                                    ack_pending_count_ = 0;      ///< Reliable frames received since the last emitted ACK.
        uint64_t                                                                    ack_first_pending_tick_ = 0; ///< Tick the oldest un-ACKed frame arrived (delayed-ACK base).
        uint64_t                                                                    ack_last_sent_tick_ = 0;    ///< Tick the last ACK frame was emitted (suppresses redundant immediate ACKs).
        uint64_t                                                                    srtt_ms_ = 0;              ///< Smoothed RTT estimate in ms (0 = no sample yet).
        std::vector<uint64_t>                                                       rtx_pending_;       ///< Retransmit-buffer keys scheduled for re-send.
        std::shared_ptr<boost::asio::steady_timer>                                  reliability_timer_; ///< Maintenance timer (ACK delay / PTO / FEC flush).

        ppp::app::mux::MuxFecEncoder                                                fec_encoder_;       ///< Send-side running parity group (strand-affine).
        vmux::list<fec_rx_group>                                                    fec_groups_;        ///< Receive-side pending parity groups (strand-affine).
        vmux::unordered_map<uint64_t, fec_cached_frame>                             fec_frame_cache_;   ///< Recent received data frames keyed by (cid, seq) (strand-affine).
        vmux::list<uint64_t>                                                        fec_frame_cache_order_; ///< FIFO eviction order for fec_frame_cache_.
        size_t                                                                      fec_frame_cache_bytes_ = 0; ///< Byte total of fec_frame_cache_ (bound enforcement).
    };
}
