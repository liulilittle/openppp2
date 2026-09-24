#include "vmux_skt.h"
#include "vmux_net.h"
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/diagnostics/DatapathPerfJson.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file vmux_skt.cpp
 * @brief Implementation of vmux logical socket bridging and forwarding.
 * @license GPL-3.0
 */

namespace vmux {
    static constexpr int kTransmissionBinaryHeaderSize = 3;
    static constexpr int kPlaintextBase94MaxWriteSize = (PPP_BUFFER_SIZE / 2) - kTransmissionBinaryHeaderSize;

    /**
     * @brief Initialize a vmux logical socket state.
     * @param mux Parent vmux multiplexer instance.
     * @param connection_id Non-zero logical connection id.
     */
    vmux_skt::vmux_skt(const std::shared_ptr<vmux_net>& mux, uint32_t connection_id) noexcept {
        assert(connection_id != 0 && "The connect_id cannot be set to 0.");

        vmux_skt* const skt           = this;
        skt->status_.disposed_        = false;
        skt->status_.connected_       = false;
        skt->status_.fin_             = false;
        skt->status_.sending_         = false;
        skt->status_.forwarding_      = false;
        skt->status_.connecton_       = false;
        skt->status_.rx_acceleration_ = true;
        skt->status_.tx_acceleration_ = true;

        uint64_t now                  = mux->now_tick();
        skt->mux_                     = mux;
        skt->last_                    = now;
      
        skt->connection_id_           = connection_id;
        skt->tx_strand_               = mux_->strand_;
        skt->tx_context_              = mux_->context_;
    }

    /** @brief Finalize vmux socket resources on destruction. */
    vmux_skt::~vmux_skt() noexcept {
        finalize();
    }

    /**
     * @brief Release runtime resources and notify close state once.
     * @details This function is idempotent and can be called from multiple
     * closure paths; internal flags guard against duplicated FIN behavior.
     */
    void vmux_skt::finalize() noexcept {
        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket;
        bool fin = false;

        if (!status_.fin_) { 
            fin = true;
            status_.connected_ = false;
        }

        status_.fin_ = true;
        status_.disposed_ = true;

#if defined(_WIN32)
        qoss_.reset();
#endif

        rx_queue_.clear();
        tx_socket = std::move(tx_socket_);

        if (ActiveEventHandler event = std::move(active_event); event) {
            active_event = NULLPTR;
            event(this, false);
        }

        mux_->release_connection(connection_id_, this);
        if (fin) {
            mux_->post(vmux_net::cmd_fin, NULLPTR, 0, connection_id_);
        }

        if (NULLPTR != tx_socket) {
            auto tx_context = tx_context_;
            auto tx_strand = tx_strand_;

            vmux_post_exec(tx_context_, tx_strand_,
                [tx_context, tx_strand, tx_socket]() noexcept {
                    ppp::net::Socket::Closesocket(tx_socket);
                });
        }

        on_connected(false);
        if (DisposedEventHandler event = std::move(disposed_event); event) {
            disposed_event = NULLPTR;
            event(this);
        }
    }

    /** @brief Schedule socket finalization on vmux executor. */
    void vmux_skt::close() noexcept {
        std::shared_ptr<vmux_skt> self = shared_from_this();
        vmux_post_exec(mux_->context_, mux_->strand_,
            [self, this]() noexcept {
                finalize();
            });
    }

    /**
     * @brief Take and clear the one-shot connect callback.
     * @return Stored callback when available; otherwise empty callback.
     */
    vmux_skt::ConnectAsynchronousCallback vmux_skt::clear_event() noexcept {
        ConnectAsynchronousCallback cb;
        if (!status_.connecton_) {
            status_.connecton_ = true;
            cb = std::move(connect_ac_);
        }

        connect_ac_ = NULLPTR;
        return cb;
    }

    /**
     * @brief Notify connect completion callback.
     * @param ok true when connect path succeeded.
     */
    void vmux_skt::on_connected(bool ok) noexcept {
        ConnectAsynchronousCallback connect_ac = clear_event();
        if (NULLPTR != connect_ac) {
            connect_ac(this, ok);
        }
    }

    /**
     * @brief Validate target and start asynchronous local TCP connect.
     * @param host Destination hostname or IP.
     * @param port Destination TCP port.
     * @return true if coroutine task is spawned.
     */
    bool vmux_skt::accept(const template_string& host, int port) noexcept {
        if (status_.disposed_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket = tx_socket_;
        if (NULLPTR != tx_socket) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketAcceptSocketAlreadyExists);
            return false;
        }
        else {
            Byte err = '\x0'; 
            if (host.empty()) {
                err = 'H';
            }
            elif(port <= 0 || port > UINT16_MAX) {
                err = 'P';
            }

            if (err != '\x0') {
                bool success = mux_->post(vmux_net::cmd_syn_ok, &err, 1, connection_id_);
                if (!success) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
                    return false;
                }

                return true;
            }
            else {
                if (NULLPTR != tx_strand_) {
                    tx_socket = ppp::make_shared_object<boost::asio::ip::tcp::socket>(*tx_strand_);
                }
                else {
                    tx_socket = ppp::make_shared_object<boost::asio::ip::tcp::socket>(*tx_context_);
                }

                tx_buffer_ = mux_->make_byte_array(vmux_net::max_buffers_size);
                tx_socket_ = tx_socket;

                if (NULLPTR == tx_socket || NULLPTR == tx_buffer_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketAcceptBufferAllocFailed);
                    return false;
                }
            }
        }

        std::shared_ptr<vmux_skt> self = shared_from_this();
        int remote_port = port;
        
        vmux::StrandPtr strand = mux_->strand_;
        vmux::ContextPtr context = mux_->context_;

        auto process =
            [self, this, host, remote_port, context, strand](ppp::coroutines::YieldContext& y) noexcept -> bool {
                return do_accept(host, remote_port, y);
            };

        if (!ppp::coroutines::YieldContext::Spawn(mux_->BufferAllocator.get(), *context, strand.get(), process)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineSpawnFailed);
            return false;
        }

        return true;
    }

    /**
     * @brief Start forwarding from local socket to remote peer.
     * @return true if forward scheduling succeeds.
     */
    bool vmux_skt::run() noexcept {
        if (status_.disposed_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }
        
        std::shared_ptr<vmux_skt> self = shared_from_this();
        return vmux_post_exec(mux_->context_, mux_->strand_,
            [self, this]() noexcept {
                if (!status_.connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketRunNotConnected);
                    return false;
                }

                bool success = forward_to_rx_socket();
                if (success) {
                    active();
                }
                else {
                    close();
                }

                return success;
            });
    }

    /**
     * @brief Adjust receive congestion window and advertise acceleration state.
     * @param value Positive to increase queued bytes, negative to decrease.
     * @return true if state update and optional signaling succeed.
     */
    bool vmux_skt::rx_congestions(int64_t value) noexcept {
        if (value == 0) {
            return true;
        }

        int max_congestions = mux_->AppConfiguration->mux.congestions;
        if (max_congestions < 1) {
            return true;
        }
        else {
            rx_congestions_ += value;
        }
        
        if (rx_congestions_ <= 0) {
            rx_congestions_ = 0;
            if (status_.rx_acceleration_) {
                return true;
            }
            
            Byte acceleration = TRUE;
            status_.rx_acceleration_ = true;

            return mux_->post(vmux_net::cmd_acceleration, &acceleration, sizeof(acceleration), connection_id_);
        }

        if (rx_congestions_ >= max_congestions) {
            if (status_.rx_acceleration_) {
                Byte acceleration = FALSE;
                status_.rx_acceleration_ = false;

                return mux_->post(vmux_net::cmd_acceleration, &acceleration, sizeof(acceleration), connection_id_);
            }
        }

        return true;
    }

    /**
     * @brief Parse host:port text and dispatch to structured accept overload.
     * @param host_and_port Host and port text, including IPv6 bracket form.
     * @return true if parsing and accept start succeed.
     */
    bool vmux_skt::accept(const template_string& host_and_port) noexcept {
        if (host_and_port.empty()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketAddressParseInputEmpty);
            return false;
        }

        template_string host;
        int port = 0;
        char* endptr = NULLPTR;
        long parsed_port = 0;

        const char* sdata = host_and_port.data();
        size_t slen = host_and_port.size();
        if (slen > 0 && sdata[0] == '[') {
            const char* right = strchr(sdata + 1, ']');
            if (NULLPTR == right || right[1] != ':') {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketAddressParseBracketMismatch);
                return false;
            }

            host = host_and_port.substr(1, right - (sdata + 1));
            
            /**
             * @brief Validate port number using strtol.
             * @note Port must be in valid range.
             */
            endptr = NULLPTR;
            parsed_port = strtol(right + 2, &endptr, 10);
            if (NULLPTR == endptr || endptr == (right + 2) || *endptr != '\x0') {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketAddressParseInvalidPort);
                return false;
            }
            port = static_cast<int>(parsed_port);
        }
        else {
            const char* colon = strrchr(sdata, ':');
            if (NULLPTR == colon) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketAddressParseMissingPortSeparator);
                return false;
            }

            host = host_and_port.substr(0, colon - sdata);
            
            /**
             * @brief Validate port number using strtol.
             * @note Port must be in valid range.
             */
            endptr = NULLPTR;
            parsed_port = strtol(colon + 1, &endptr, 10);
            if (NULLPTR == endptr || endptr == (colon + 1) || *endptr != '\x0') {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketAddressParseInvalidPort);
                return false;
            }
            port = static_cast<int>(parsed_port);
        }

        if (host.empty()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketAddressParseHostEmpty);
            return false;
        }

        return accept(host, port);
    }

    /**
     * @brief Send vmux SYN command and register async connect callback.
     * @param context Target execution context for local socket operations.
     * @param strand Optional strand for serialized local socket operations.
     * @param host Destination host.
     * @param port Destination port.
     * @param ac Completion callback.
     * @return true when SYN is posted successfully.
     */
    bool vmux_skt::connect(const ContextPtr& context, const StrandPtr& strand, const template_string& host, int port, const ConnectAsynchronousCallback& ac) noexcept {
        if (NULLPTR == ac || NULLPTR == context) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketConnectNullCallbackOrContext);
            return false;
        }

        if (status_.disposed_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        if (host.empty()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketConnectHostEmpty);
            return false;
        }

        if (port <= 0 || port > UINT16_MAX) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket = tx_socket_;
        if (NULLPTR == tx_socket) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketConnectSocketMissing);
            return false;
        }

        tx_buffer_ = mux_->make_byte_array(vmux_net::max_buffers_size);
        if (NULLPTR == tx_buffer_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketConnectSendBufferAllocFailed);
            return false;
        }

        template_string host_and_port_string = host;
        if (host.find(':') != template_string::npos && (host.front() != '[' || host.back() != ']')) {
            host_and_port_string = "[" + host + "]";
        }

        host_and_port_string.append(":" + vmux_to_string(port));
        if (!mux_->post(vmux_net::cmd_syn, host_and_port_string.data(), (int)host_and_port_string.size(), connection_id_)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
            return false;
        }

        connect_ac_ = ac;
        status_.fin_ = true;
        
        tx_strand_ = strand;
        tx_context_ = context;
        return true;
    }

    /**
     * @brief Finalize connect result after receiving SYN-ACK status.
     * @param successed true when peer reports accepted connection.
     * @return true when post-connect forwarding can continue.
     */
    bool vmux_skt::connect_ok(bool successed) noexcept {
        if (status_.disposed_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        if (!successed) {
            status_.fin_ = true;
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketConnectFailed);
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket = tx_socket_;
        if (NULLPTR == tx_socket) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketConnectAckSocketMissing);
            return false;
        }
        
        if (status_.connected_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketConnectAckAlreadyConnected);
            return false;
        }

        status_.fin_ = false;
        status_.connected_ = true;

        on_connected(true);
        if (!tx_socket->is_open()) {
            return true;
        }

        return forward_to_rx_socket();
    }

    /**
     * @brief Queue inbound peer payload and flush to local socket.
     *
     * Legacy 2-arg overload — delegates to the zero-copy 3-arg variant with a
     * null owner, preserving the original alloc+memcpy behavior.
     *
     * @param payload Payload bytes from vmux frame.
     * @param payload_size Payload size in bytes.
     * @return true when payload is accepted for forwarding.
     */
    bool vmux_skt::input(Byte* payload, int payload_size) noexcept {
        return input(nullptr, payload, payload_size);
    }

    /**
     * @brief Zero-copy variant of @ref input.
     * @param owner Shared pointer that owns the memory region of @p payload.
     *              When non-null, the payload is referenced via wrap_shared_pointer
     *              instead of being copied into a freshly allocated buffer.
     * @param payload Payload bytes from vmux frame.
     * @param payload_size Payload size in bytes.
     * @return true when payload is accepted for forwarding.
     */
    bool vmux_skt::input(const std::shared_ptr<Byte>& owner, Byte* payload, int payload_size) noexcept {
        if (status_.disposed_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        std::shared_ptr<Byte> buffer;
        if (payload_size > 0) {
            if (NULLPTR != owner) {
                // Zero-copy: alias the owner buffer to reference the payload region.
                buffer = ppp::wrap_shared_pointer(payload, owner);
            }
            else {
                buffer = mux_->make_byte_array(payload_size);
                if (NULLPTR != buffer) {
                    memcpy(buffer.get(), payload, payload_size);
                }
            }

            if (NULLPTR == buffer) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketInputBufferAllocFailed);
                return false;
            }

            if (!rx_congestions(payload_size)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
                return false;
            }
        }

        rx_queue_.emplace_back(packet{ buffer,  payload_size });
        if (payload_size > 0) {
            ppp::diagnostics::datapath_perf::RecordVmuxAccepted(payload_size);
        }
        if (status_.sending_) {
            return true;
        }

        packet_queue::iterator packet_tail = rx_queue_.begin();
        packet_queue::iterator packet_endl = rx_queue_.end();
        if (packet_tail == packet_endl) {
            return true;
        }

        packet fpacket = *packet_tail;
        return forward_to_tx_socket(fpacket.buffer, fpacket.buffer_size, &packet_tail);
    }

    /**
     * @brief Send local payload to remote vmux peer.
     * @param packet Payload pointer.
     * @param packet_length Payload length.
     * @param ac Completion callback for post status.
     * @return true when frame posting starts successfully.
     */
    bool vmux_skt::send_to_peer(const void* packet, int packet_length, const SendAsynchronousCallback& ac) noexcept {
        if (NULLPTR == mux_ || !mux_->is_strand_thread()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEventDispatchFailed);
            return false;
        }

        if (NULLPTR == packet || packet_length < 1) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketSendInvalidPayload);
            return false;
        }

        if (status_.disposed_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        // Open barrier: do not post PUSH until local open completes (syn_ok / connected_).
        if (!status_.connected_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketSendContextNotReady);
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket = tx_socket_;
        if (NULLPTR == tx_socket || NULLPTR == tx_buffer_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketSendContextNotReady);
            return false;
        }

        auto self = shared_from_this();
        bool sending = mux_->post(vmux_net::cmd_push, packet, packet_length, connection_id_, status_.tx_acceleration_,
            [self, this, ac](bool ok) noexcept {
                if (ac) {
                    ac(this, ok);
                }
            });

        if (sending) {
            active();
            return true;
        }
        else {
            close();
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
            return false;
        }
    }

    /**
     * @brief Coroutine wrapper for @ref send_to_peer.
     * @param packet Payload pointer.
     * @param packet_length Payload length.
     * @param y Yield context.
     * @return true on successful send completion.
     */
    bool vmux_skt::send_to_peer_yield(const void* packet, int packet_length, ppp::coroutines::YieldContext& y) noexcept {
        using atomic_boolean = std::atomic<int>;

        if (NULLPTR == packet || packet_length < 1) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketSendYieldInvalidPayload);
            return false;
        }

        std::shared_ptr<vmux_net::atomic_int> status = ppp::make_shared_object<vmux_net::atomic_int>(-1);
        if (NULLPTR == status) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketSendYieldStatusAllocFailed);
            return false;
        }

        auto self = shared_from_this();

        // Guard Suspend() behind the post result: if the executor is unavailable the
        // lambda (and every ppp::coroutines::asio::R() inside it) will never run, so
        // calling Suspend() would park the coroutine with no future Resume() – a
        // permanent coroutine leak.
        bool posted = vmux_post_exec(mux_->context_, mux_->strand_,
            [self, this, packet, packet_length, status, &y]() noexcept {
                bool forwarding = 
                    send_to_peer(packet, packet_length, 
                        [status, &y](vmux_skt* skt, bool successed) noexcept {
                            ppp::coroutines::asio::R(y, *status, successed);
                        });

                if (!forwarding) {
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
     * @brief Resolve address, apply policy checks, and connect local TCP socket.
     * @param host Destination host.
     * @param remote_port Destination port.
     * @param y Yield context for asynchronous steps.
     * @return true when local connect succeeds and vmux is notified.
     */
    bool vmux_skt::do_accept(const template_string& host, int remote_port, ppp::coroutines::YieldContext& y) noexcept {
        if (status_.disposed_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        Byte err = 'U'; // Unknow.
        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket = tx_socket_;
        std::shared_ptr<ppp::net::Firewall> firewall = mux_->Firewall;

        /**
         * @brief Connection pipeline.
         * @details Performs DNS resolution, firewall validation, socket setup,
         * optional platform protections, async connect, and logging.
         */
        while (NULLPTR != tx_socket) {

            boost::system::error_code ec;
            boost::asio::ip::address remote_ip = ppp::StringToAddress(host.data(), ec);
            if (ec) {
                if (NULLPTR != firewall && firewall->IsDropNetworkDomains(host)) {
                    err = 'F'; // Firewall limits.
                    break;
                }

                remote_ip = ppp::coroutines::asio::GetAddressByHostName<boost::asio::ip::tcp>(host.data(), remote_port, y).address();
            }

            // Apply segment filtering after both IP-literal parsing and DNS resolution.
            if (NULLPTR != firewall && firewall->IsDropNetworkSegment(remote_ip)) {
                err = 'F'; // Firewall limits.
                break;
            }

            boost::asio::ip::tcp::endpoint remote_endpoint(remote_ip, remote_port);
            if (remote_port <= 0 || remote_port > UINT16_MAX) {
                err = 'P'; // Port Errors.
                break;
            }

            if (NULLPTR != firewall && firewall->IsDropNetworkPort(remote_port, true)) {
                err = 'F'; // Firewall limits.
                break;
            }

            if (remote_ip.is_multicast()) {
                err = 'M'; // Multicast Limit.
                break;
            }

            if (remote_ip.is_unspecified()) {
                err = 'Z'; // Address Errors.
                break;
            }
            else {
                boost::asio::post(tx_socket->get_executor(),
                    [&tx_socket, &ec, &remote_endpoint, &y]() noexcept {
                        tx_socket->open(remote_endpoint.protocol(), ec);
                        y.R();
                    });

                y.Suspend();
            }

            if (ec) {
                err = 'N'; // Open Errors.
                break;
            }

            std::shared_ptr<ppp::configurations::AppConfiguration>& configuration = mux_->AppConfiguration;
            ppp::net::Socket::AdjustSocketOptional(*tx_socket,
                remote_ip.is_v4(),
                configuration->tcp.fast_open,
                configuration->tcp.turbo);
            ppp::net::Socket::SetWindowSizeIfNotZero(tx_socket->native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);

#if defined(_WIN32)
            // Advanced QoS control.
            if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                qoss_ = ppp::net::QoSS::New(tx_socket->native_handle(), remote_ip, remote_port);
            }
#elif defined(_LINUX)
            // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter. 
            // IPV6 does not need to be linked, because VPN is IPV4, 
            // And IPV6 does not affect the physical layer network communication of the VPN.
            if (!remote_ip.is_loopback()) {
                auto protector_network = mux_->ProtectorNetwork;
                if (NULLPTR != protector_network) {
                    if (!protector_network->Protect(tx_socket->native_handle(), y)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed);
                        return false;
                    }
                }
            }
#endif        

            boost::asio::post(tx_socket->get_executor(), 
                [&tx_socket, &ec, &remote_endpoint, &y]() noexcept {
                    tx_socket->async_connect(remote_endpoint,
                        [&y, &ec](const boost::system::error_code& err) noexcept {
                            ec = err;
                            y.R();
                        });
                });

            y.Suspend(); 
            if (ec) {
                if (ec == boost::system::errc::operation_canceled) {
                    err = 'T'; // Timeout.
                }
                else {
                    err = 'R'; // Unable to remote host.
                }
            }
            else {
                // Record log.
                std::shared_ptr<ppp::app::protocol::VirtualEthernetLogger> logger = mux_->Logger;
                if (NULLPTR != logger) {
                    vmux_net::IMuxTransportPtr connection = mux_->get_linklayer();
                    if (NULLPTR != connection) {
                        vmux_net::ITransmissionPtr transmission = connection->GetTransmission();
                        if (NULLPTR != transmission) {
                            logger->Connect(connection->GetId(), transmission, tx_socket->local_endpoint(ec), remote_endpoint, host);
                        }
                    }
                }

                err = 'A'; // A endian is opened.
            }

            active();
            break;
        }

        /** @brief Final handshake response dispatch: reset or opened state. */
        if (mux_->post(vmux_net::cmd_syn_ok, &err, 1, connection_id_)) {
            if (connect_ok(err == 'A')) {
                return true;
            }
        }
        else {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
        }

        if ('A' != err) {
            switch (err) {
            case 'F':
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkFirewallBlocked);
                break;
            case 'P':
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                break;
            case 'M':
            case 'Z':
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                break;
            case 'N':
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                break;
            case 'T':
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpConnectTimeout);
                break;
            case 'R':
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketConnectFailed);
                break;
            default:
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                break;
            }
        }

        close();
        return false;
    }

    /**
     * @brief Post async write on socket executor.
     * @tparam T1 Socket type.
     * @tparam T2 Buffer sequence type.
     * @tparam T3 Completion handler type.
     */
    template <class T1, class T2, class T3>
    static inline void vmux_skt_async_write(const std::shared_ptr<T1>& socket, const T2& buffers, T3&& handler) noexcept {
        if (NULLPTR == socket) {
            return;
        }

        boost::asio::post(socket->get_executor(),
            [socket, buffers, handler]() noexcept {
                boost::asio::async_write(*socket, buffers, handler);
            });
    }

    /**
     * @brief Post async read_some on socket executor.
     * @tparam T1 Socket type.
     * @tparam T2 Mutable buffer sequence type.
     * @tparam T3 Completion handler type.
     */
    template <class T1, class T2, class T3>
    static inline void vmux_skt_async_read_some(const std::shared_ptr<T1>& socket, const T2& buffers, T3&& handler) noexcept {
        if (NULLPTR == socket) {
            return;
        }

        boost::asio::post(socket->get_executor(),
            [socket, buffers, handler]() noexcept {
                socket->async_read_some(buffers, handler);
            });
    }

    /**
     * @brief Read local socket payload and push it to remote vmux peer.
     * @return true when read pipeline remains active.
     */
    bool vmux_skt::forward_to_rx_socket() noexcept {
        if (status_.disposed_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }
        
        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket = tx_socket_;
        if (NULLPTR == tx_socket || NULLPTR == tx_buffer_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketForwardRxContextInvalid);
            return false;
        }

        if (!tx_socket->is_open()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
            return false;
        }

        if (!status_.tx_acceleration_) {
            return true;
        }
        
        int location = FALSE;
        if (!status_.forwarding_.compare_exchange_strong(location, TRUE)) {
            return true;
        }

        std::shared_ptr<vmux_skt> self = shared_from_this();
        auto reading_cb =
            [self, this, tx_socket](const boost::system::error_code& ec, std::size_t bytes_transferred) noexcept {
                vmux_post_exec(mux_->context_, mux_->strand_, 
                    [self, this, ec, bytes_transferred]() noexcept {
                        int location = TRUE; 
                        if (status_.forwarding_.compare_exchange_strong(location, FALSE)) {
                            active();
                        }
                        else {
                            return true;
                        }

                        if (ec == boost::system::errc::success) {
                            // Open barrier: no data until connected_ (syn_ok observed).
                            if (!status_.connected_) {
                                close();
                                return false;
                            }
                            bool forwarding = 
                                mux_->post(vmux_net::cmd_push, tx_buffer_.get(), bytes_transferred, connection_id_, status_.tx_acceleration_,
                                    [self, this](bool successed) noexcept {
                                        if (successed) {
                                            if (forward_to_rx_socket()) {
                                                return true;
                                            }
                                        }
                                        
                                        close();
                                        return false;
                                    });

                            if (forwarding) {
                                return true;
                            }
                        }
                        elif(ec == boost::system::errc::resource_unavailable_try_again) {
                            if (forward_to_rx_socket()) {
                                return true;
                            }
                        }

                        close();
                        return false;
                    });
            };
        
        int read_size = vmux_net::max_buffers_size;
        if (mux_->AppConfiguration->key.plaintext) {
            read_size = std::min<int>(read_size, kPlaintextBase94MaxWriteSize - static_cast<int>(sizeof(vmux_net::vmux_hdr)));
        }

        int bytes_transferred = ppp::BufferSkateboarding(mux_->AppConfiguration->key.sb, read_size, vmux_net::max_buffers_size);
        vmux_skt_async_read_some(tx_socket, boost::asio::buffer(tx_buffer_.get(), bytes_transferred), reading_cb);
        return true;
    }

    /**
     * @brief Toggle transmit acceleration behavior.
     * @param acceleration true to continue active reads from local socket.
     * @return true when state transition is applied.
     */
    bool vmux_skt::tx_acceleration(bool acceleration) noexcept {
        if (status_.disposed_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        status_.tx_acceleration_ = acceleration;
        return acceleration ? forward_to_rx_socket() : true;
    }

    /**
     * @brief Write queued vmux payload into local TCP socket.
     * @param payload Payload buffer.
     * @param payload_size Payload size.
     * @param packet_tail Optional queue iterator consumed on send start.
     * @return true when write pipeline remains active.
     */
    bool vmux_skt::forward_to_tx_socket(const std::shared_ptr<Byte>& payload, int payload_size, packet_queue::iterator* packet_tail) noexcept {
        if (NULLPTR == payload || payload_size < 1) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketForwardTxInvalidPayload);
            return false;
        }

        if (status_.disposed_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket = tx_socket_;
        if (NULLPTR == tx_socket) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxSocketForwardTxSocketMissing);
            return false;
        }

        if (!tx_socket->is_open()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
            return false;
        }

        if (NULLPTR != packet_tail) {
            int location = FALSE;
            if (status_.sending_.compare_exchange_strong(location, TRUE)) {
                rx_queue_.erase(*packet_tail);
            }
            else {
                return true;
            }
        }

        std::shared_ptr<vmux_skt> self = shared_from_this();
        active();

        ppp::diagnostics::datapath_perf::Scope socket_write_scope;
        auto writing_cb =
            [self, this, tx_socket, payload, payload_size, socket_write_scope](const boost::system::error_code& ec, std::size_t bytes_transferred) noexcept {
                if (!ec && bytes_transferred == static_cast<std::size_t>(payload_size)) {
                    ppp::diagnostics::datapath_perf::RecordVmuxSocketWriteCompleted(payload_size, socket_write_scope.Elapsed());
                }
                vmux_post_exec(mux_->context_, mux_->strand_, 
                    [self, this, ec, payload, payload_size, bytes_transferred]() noexcept {
                        if (ec == boost::system::errc::success && rx_congestions(-static_cast<int>(bytes_transferred))) {
                            int location = TRUE; 
                            if (status_.sending_.compare_exchange_strong(location, FALSE)) {
                                active();
                            }
                            else {
                                return true;
                            }

                            packet_queue::iterator packet_tail = rx_queue_.begin();
                            packet_queue::iterator packet_endl = rx_queue_.end();

                            if (packet_tail == packet_endl) {
                                return true;
                            }

                            packet fpacket = *packet_tail;
                            if (forward_to_tx_socket(fpacket.buffer, fpacket.buffer_size, &packet_tail)) {
                                return true;
                            }
                        }
                        elif(ec == boost::system::errc::resource_unavailable_try_again) {
                            constexpr packet_queue::iterator* const null_expr = NULLPTR;
                            if (forward_to_tx_socket(payload, payload_size, null_expr)) {
                                return true;
                            }
                        }

                        close();
                        return false;
                    });
            };

        vmux_skt_async_write(tx_socket, boost::asio::buffer(payload.get(), payload_size), writing_cb);
        return true;
    }

    /**
     * @brief Notify activity and propagate tick update to parent mux.
     * @param now Current tick value.
     */
    void vmux_skt::active(uint64_t now) noexcept {
        ActiveEventHandler h = active_event; 
        if (NULLPTR != h) {
            h(this, !status_.disposed_);
        }

        last_ = now;
        mux_->active(now);
    }
}
