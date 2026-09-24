#pragma once

/**
 * @file vmux_skt.h
 * @brief vmux socket endpoint abstraction for one multiplexed connection.
 * @license GPL-3.0
 */

#include "vmux.h"
#include "vmux_net.h"

namespace vmux {
    /**
     * @brief Represents a logical stream carried by a vmux session.
     * @details A vmux socket bridges local TCP I/O and vmux framed packets.
     */
    class vmux_skt final : public std::enable_shared_from_this<vmux_skt> {
        friend class                                    vmux_net;
        friend struct                                   vmux_net_test_access;

        /** @brief Shared packet buffer pointer type. */
        typedef std::shared_ptr<Byte>                   buffer_array_ptr;
        /** @brief Intrusive list type for packet buffers. */
        typedef vmux::list<buffer_array_ptr>            buffer_array_list;

        /**
         * @brief Buffered payload item queued for local socket writes.
         */
        struct packet {
            std::shared_ptr<Byte>                       buffer;
            int                                         buffer_size = 0;
        };
        /** @brief FIFO queue of pending payload packets. */
        typedef vmux::list<packet>                      packet_queue;

    public:
        /** @brief Callback signature for connect-like state changes. */
        typedef ppp::function<void(vmux_skt*, bool)>    ConnectAsynchronousCallback;
        /** @brief Callback signature for connection liveness updates. */
        typedef ConnectAsynchronousCallback             ActiveEventHandler;
        /** @brief Callback signature for async send completion. */
        typedef ConnectAsynchronousCallback             SendAsynchronousCallback;
        /** @brief Callback signature fired when the socket is disposed. */
        typedef ppp::function<void(vmux_skt*)>          DisposedEventHandler;

    public:
        ActiveEventHandler                              active_event;
        DisposedEventHandler                            disposed_event;

    public:
        /**
         * @brief Construct a vmux socket bound to a parent multiplexer.
         * @param mux Parent multiplexer instance.
         * @param connection_id Non-zero logical connection identifier.
         */
        vmux_skt(const std::shared_ptr<vmux_net>& mux, uint32_t connection_id) noexcept;
        /** @brief Destroy the socket and release owned resources. */
        ~vmux_skt() noexcept;

    public:
        /** @brief Asynchronously close and finalize this logical connection. */
        void                                            close() noexcept;
        /** @brief Query whether this object has been disposed. */
        bool                                            is_disposed() noexcept { return status_.disposed_; }
        /** @brief Query whether the local and remote ends are established. */
        bool                                            is_connected() noexcept { return !status_.disposed_ && status_.connected_; }
        /** @brief Start reading from local socket and forwarding to peer. */
        bool                                            run() noexcept;
        /**
         * @brief Send data to peer and suspend coroutine until completion.
         * @param packet Payload buffer.
         * @param packet_length Payload size.
         * @param y Coroutine yield context.
         * @return true on success.
         */
        bool                                            send_to_peer_yield(const void* packet, int packet_length, ppp::coroutines::YieldContext& y) noexcept;

    private:
        /** @brief Final shutdown routine; idempotent and noexcept-safe. */
        void                                            finalize() noexcept;

        /** @brief Accept remote connect request using host and port. */
        bool                                            accept(const template_string& host, int port) noexcept;
        /** @brief Accept remote connect request from combined host:port text. */
        bool                                            accept(const template_string& host_and_port) noexcept;

        /** @brief Resolve, validate, and connect local TCP socket. */
        bool                                            do_accept(const template_string& host, int remote_port, ppp::coroutines::YieldContext& y) noexcept;

        /** @brief Initiate vmux-level connect handshake. */
        bool                                            connect(const ContextPtr& context, const StrandPtr& strand, const template_string& host, int port, const ConnectAsynchronousCallback& ac) noexcept;
        /** @brief Complete connect transition after SYN-ACK processing. */
        bool                                            connect_ok(bool successed) noexcept;

        /** @brief Push peer payload into local output queue. */
        bool                                            input(Byte* payload, int payload_size) noexcept;
        /** @brief Zero-copy variant: queue inbound peer payload backed by owner shared_ptr. */
        bool                                            input(const std::shared_ptr<Byte>& owner, Byte* payload, int payload_size) noexcept;
        /** @brief Send local payload to peer; synchronously rejects calls outside the mux strand. */
        bool                                            send_to_peer(const void* packet, int packet_length, const SendAsynchronousCallback& ac) noexcept;
        
        /** @brief Update activity timestamp using provided tick value. */
        void                                            active(uint64_t now) noexcept;
        /** @brief Update activity timestamp using current tick count. */
        void                                            active() noexcept {
            uint64_t now = mux_->now_tick();
            active(now);
        }

        /** @brief Invoke pending connect callback once. */
        void                                            on_connected(bool ok) noexcept;

        /** @brief Extract and clear one-shot connect callback. */
        ConnectAsynchronousCallback                     clear_event() noexcept;

        /** @brief Track receive-side congestion and notify acceleration state. */
        bool                                            rx_congestions(int64_t value) noexcept;

        /** @brief Enable or disable transmit acceleration mode. */
        bool                                            tx_acceleration(bool acceleration) noexcept;

        /** @brief Forward data from local TCP socket to vmux peer. */
        bool                                            forward_to_rx_socket() noexcept;
        /** @brief Forward data from vmux queue to local TCP socket. */
        bool                                            forward_to_tx_socket(const std::shared_ptr<Byte>& payload, int payload_size, packet_queue::iterator* packet_tail) noexcept;

    private:
        /**
         * @brief Compact socket state flags and async transfer guards.
         *
         * Bit-fields are packed into a single byte to minimize memory footprint.
         * The two atomic integers prevent concurrent re-entry into the send and
         * forward coroutine paths respectively.
         */
        struct vmux_status {
            struct {
                bool                                    disposed_        : 1; ///< Set when the socket has been finalized.
                bool                                    connected_       : 1; ///< Set when the remote peer acknowledged the connection.
                bool                                    fin_             : 1; ///< Set when a FIN command was received from peer.
                bool                                    tx_acceleration_ : 1; ///< Transmit acceleration mode is active.
                bool                                    rx_acceleration_ : 1; ///< Receive acceleration mode is active.
                bool                                    connecton_       : 3; ///< Reserved / connection-phase sub-state.
            };
            std::atomic<int>                            sending_    = false; ///< Non-zero while an async send to peer is in flight.
            std::atomic<int>                            forwarding_ = false; ///< Non-zero while local-socket forwarding is in progress.
        }                                               status_;

#if defined(_WIN32)
        std::shared_ptr<ppp::net::QoSS>                 qoss_;              ///< Windows QoS socket service handle.
#endif

        std::shared_ptr<vmux_net>                       mux_;               ///< Parent multiplexer owning this logical socket.

        uint64_t                                        last_          = 0; ///< Monotonic tick of last activity (used for idle detection).
        uint32_t                                        connection_id_ = 0; ///< Immutable logical connection identifier within the mux session.

        packet_queue                                    rx_queue_;          ///< Inbound payload queue pending delivery to local socket.
        int64_t                                         rx_congestions_;    ///< Signed congestion counter; negative means backpressure applied.

        std::shared_ptr<boost::asio::ip::tcp::socket>   tx_socket_;         ///< Local TCP socket to which inbound data is forwarded.
        std::shared_ptr<Byte>                           tx_buffer_;         ///< Persistent receive buffer for the local socket read loop.
        
        ContextPtr                                      tx_context_;        ///< ASIO execution context for the local socket operations.
        StrandPtr                                       tx_strand_;         ///< Optional strand serializing local socket callbacks.

        ConnectAsynchronousCallback                     connect_ac_;        ///< One-shot callback fired when the connect result is known.

        /**
         * @brief Weak self-reference used to safely re-acquire the socket from
         *        callbacks that may fire while the object is being destroyed.
         * @note  `finalize()` can invoke the connect callback from inside the
         *        destructor. `shared_from_this()` on a dying object throws
         *        `bad_weak_ptr` (std::terminate); locking this weak reference
         *        instead yields an empty pointer without throwing.
         */
        std::weak_ptr<vmux_skt>                         self_weak_;
    };
}
