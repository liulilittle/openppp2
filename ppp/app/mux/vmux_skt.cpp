#include "vmux_skt.h"
#include "vmux_net.h"

namespace vmux {
    vmux_skt::vmux_skt(const std::shared_ptr<vmux_net>& mux, uint32_t connection_id) noexcept {
        assert(connection_id != 0 && "The connect_id cannot be set to 0.");

        status_.disposed_ = false;
        status_.connected_ = false;
        status_.fin_ = false;
        status_.forwarding = false;
        status_.sending_ = false;
        status_.connecton_ = false;

        uint64_t now = mux->now_tick();
        mux_ = mux;
        last_ = now;

        connection_id_ = connection_id;
        tx_strand_ = mux_->strand_;
        tx_context_ = mux_->context_;
    }

    vmux_skt::~vmux_skt() noexcept {
        finalize();
    }

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
        active_event.reset();

        tx_socket = std::move(tx_socket_);
        tx_socket_.reset();

        mux_->release_connection(connection_id_, this);
        if (fin) {
            mux_->post(vmux_net::cmd_fin, NULL, 0, connection_id_);
        }

        if (NULL != tx_socket) {
            vmux_post_exec(tx_context_, tx_strand_,
                [tx_context = tx_context_, tx_strand = tx_strand_, tx_socket]() noexcept {
                    ppp::net::Socket::Closesocket(tx_socket);
                });
        }

        on_connected(false);
    }

    void vmux_skt::close() noexcept {
        std::shared_ptr<vmux_skt> self = shared_from_this();
        vmux_post_exec(mux_->context_, mux_->strand_,
            [self, this]() noexcept {
                finalize();
            });
    }

    vmux_skt::ConnectAsynchronousCallback vmux_skt::clear_event() noexcept {
        ConnectAsynchronousCallback cb;
        for (SynchronizationObjectScope scope(syncobj_);;) {
            if (!status_.connecton_.exchange(true)) {
                cb = std::move(connect_ac_);
            }

            connect_ac_.reset();
            break;
        }

        return cb;
    }

    void vmux_skt::on_connected(bool ok) noexcept {
        ConnectAsynchronousCallback connect_ac = clear_event();
        if (NULL != connect_ac) {
            connect_ac(this, ok);
        }
    }

    bool vmux_skt::accept(const template_string& host, int port) noexcept {
        if (status_.disposed_) {
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket = tx_socket_;
        if (NULL != tx_socket) {
            return false;
        }
        else {
            Byte err = 0; 
            if (host.empty()) {
                err = 'H';
            }
            else if (port <= 0 || port > UINT16_MAX) {
                err = 'P';
            }

            if (err) {
                bool success = mux_->post(vmux_net::cmd_syn_ok, &err, 1, connection_id_);
                if (!success) {
                    return false;
                }
            }
            else {
                if (NULL != tx_strand_) {
                    tx_socket = ppp::make_shared_object<boost::asio::ip::tcp::socket>(*tx_strand_);
                }
                else {
                    tx_socket = ppp::make_shared_object<boost::asio::ip::tcp::socket>(*tx_context_);
                }

                tx_buffer_ = mux_->make_byte_array(vmux_net::max_buffers_size);
                tx_socket_ = tx_socket;

                if (NULL == tx_socket || NULL == tx_buffer_) {
                    return false;
                }
            }
        }

        std::shared_ptr<vmux_skt> self = shared_from_this();
        int remote_port = port;
        
        vmux::StrandPtr& strand = mux_->strand_;
        vmux::ContextPtr& context = mux_->context_;

        auto process =
            [self, this, host, remote_port, context, strand](ppp::coroutines::YieldContext& y) noexcept -> bool {
                return do_accept(host, remote_port, y);
            };

        return ppp::coroutines::YieldContext::Spawn(mux_->BufferAllocator.get(), *context, strand.get(), process);
    }

    bool vmux_skt::run() noexcept {
        if (status_.disposed_) {
            return false;
        }
        
        std::shared_ptr<vmux_skt> self = shared_from_this();
        return vmux_post_exec(mux_->context_, mux_->strand_,
            [self, this]() noexcept {
                if (!status_.connected_) {
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

    bool vmux_skt::accept(const template_string& host_and_port) noexcept {
        if (host_and_port.empty()) {
            return false;
        }

        const char* sdata = host_and_port.data();
        const char* colon = strchr(sdata, ':');
        if (NULL == colon) {
            return false;
        }

        template_string host = host_and_port.substr(0, colon - sdata);
        int port = atoi(colon + 1);

        return accept(host, port);
    }

    bool vmux_skt::connect(const ContextPtr& context, const StrandPtr& strand, const template_string& host, int port, const ConnectAsynchronousCallback& ac) noexcept {
        if (status_.disposed_ || NULL == ac || NULL == context) {
            return false;
        }

        if (host.empty() || port <= 0 || port > UINT16_MAX) {
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket = tx_socket_;
        if (NULL == tx_socket) {
            return false;
        }

        tx_buffer_ = mux_->make_byte_array(vmux_net::max_buffers_size);
        if (NULL == tx_buffer_) {
            return false;
        }

        template_string host_and_port_string = host + ":" + vmux_to_string(port);
        if (!mux_->post(vmux_net::cmd_syn, host_and_port_string.data(), (int)host_and_port_string.size(), connection_id_)) {
            return false;
        }
        
        connect_ac_ = ac;
        status_.fin_ = true;
        tx_strand_ = strand;
        tx_context_ = context;
        return true;
    }

    bool vmux_skt::connect_ok(bool successed) noexcept {
        if (status_.disposed_) {
            return false;
        }

        if (!successed) {
            status_.fin_ = true;
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket = tx_socket_;
        if (NULL == tx_socket) {
            return false;
        }
        else if (status_.connected_) {
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

    bool vmux_skt::input(Byte* payload, int payload_size) noexcept {
        std::shared_ptr<Byte> buffer = mux_->make_byte_array(payload_size);
        if (NULL != buffer) {
            memcpy(buffer.get(), payload, payload_size);
        }
        else if (payload_size > 0) {
            return false;
        }

        if (status_.disposed_) {
            return false;
        }

        rx_queue_.emplace_back(packet{ buffer,  payload_size });
        if (status_.sending_) {
            return true;
        }

        packet_queue::iterator packet_tail = rx_queue_.begin();
        packet_queue::iterator packet_endl = rx_queue_.end();
        if (packet_tail == packet_endl) {
            return true;
        }

        packet packet = *packet_tail;
        rx_queue_.erase(packet_tail);

        return forward_to_tx_socket(packet.buffer, packet.buffer_size);
    }

    bool vmux_skt::send_to_peer(const void* packet, int packet_length, const SendAsynchronousCallback& ac) noexcept {
        if (NULL == packet || packet_length < 1) {
            return false;
        }

        if (status_.disposed_) {
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket = tx_socket_;
        if (NULL == tx_socket || NULL == tx_buffer_) {
            return false;
        }

        auto self = shared_from_this();
        bool sending = mux_->post(vmux_net::cmd_push, packet, packet_length, connection_id_,
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
            return false;
        }
    }

    bool vmux_skt::send_to_peer_yield(const void* packet, int packet_length, ppp::coroutines::YieldContext& y) noexcept {
        using atomic_boolean = std::atomic<int>;

        if (NULL == packet || packet_length < 1) {
            return false;
        }

        bool ok = false;
        auto self = shared_from_this();

        std::shared_ptr<vmux_net::atomic_int> completed = ppp::make_shared_object<vmux_net::atomic_int>(false);
        if (NULL == completed) {
            return false;
        }

        vmux_post_exec(mux_->context_, mux_->strand_,
            [self, this, packet, packet_length, completed, &y, &ok]() noexcept {
                bool forwarding = 
                    send_to_peer(packet, packet_length, 
                        [completed, &ok, &y](vmux_skt* skt, bool successed) noexcept {
                            if (!completed->exchange(true) ){
                                ok = successed;
                                y.R();
                            }
                        });

                if (!forwarding && !completed->exchange(true)) {
                    y.R();
                }
            });

        y.Suspend();
        return ok;
    }

    bool vmux_skt::do_accept(const template_string& host, int remote_port, ppp::coroutines::YieldContext& y) noexcept {
        if (status_.disposed_) {
            return false;
        }

        Byte err = 'U'; // Unknow.
        std::shared_ptr<boost::asio::ip::tcp::resolver> tx_resolver = mux_->tx_resolver_;
        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket = tx_socket_;
        std::shared_ptr<ppp::net::Firewall> firewall = mux_->Firewall;

        while (NULL != tx_resolver && NULL != tx_socket) {

            boost::system::error_code ec;
            boost::asio::ip::address remote_ip = ppp::StringToAddress(host.data(), ec);
            if (ec) {
                if (NULL != firewall && firewall->IsDropNetworkDomains(host)) {
                    err = 'F'; // Firewall limits.
                    break;
                }

                remote_ip = ppp::coroutines::asio::GetAddressByHostName(*tx_resolver, host.data(), remote_port, y).address();
            }
            else if (NULL != firewall && firewall->IsDropNetworkSegment(remote_ip)) {
                err = 'F'; // Firewall limits.
                break;
            }

            boost::asio::ip::tcp::endpoint remote_endpoint(remote_ip, remote_port);
            if (remote_port <= 0 || remote_port > UINT16_MAX) {
                err = 'P'; // Port Errors.
                break;
            }

            if (NULL != firewall && firewall->IsDropNetworkPort(remote_port, true)) {
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

#if defined(_WIN32)
            // Advanced QoS control.
            if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                qoss_ = ppp::net::QoSS::New(tx_socket->native_handle(), remote_ip, remote_port);
            }
#elif defined(_LINUX)
            // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter. 
            // IPV6 does not need to be linked, because VPN is IPV4, 
            // And IPV6 does not affect the physical layer network communication of the VPN.
            if (remote_ip.is_v4() && !remote_ip.is_loopback()) {
                auto protector_network = mux_->ProtectorNetwork;
                if (NULL != protector_network) {
                    if (!protector_network->Protect(tx_socket->native_handle(), y)) {
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
                if (NULL != logger) {
                    vmux_net::VirtualEthernetTcpipConnectionPtr connection = mux_->get_linklayer();
                    if (NULL != connection) {
                        vmux_net::ITransmissionPtr transmission = connection->GetTransmission();
                        if (NULL != transmission) {
                            logger->Connect(connection->GetId(), transmission, tx_socket->local_endpoint(ec), remote_endpoint, host);
                        }
                    }
                }

                err = 'A'; // A endian is opened.
            }

            active();
            break;
        }

        // FUNC AFTER: RST or OPENED.
        if (mux_->post(vmux_net::cmd_syn_ok, &err, 1, connection_id_)) {
            if (connect_ok(err == 'A')) {
                return true;
            }
        }

        close();
        return false;
    }

    template <class T1, class T2, class T3>
    static inline void vmux_skt_async_write(T1& socket, const T2& buffers, T3&& handler) noexcept {
        boost::asio::post(socket.get_executor(),
            [&socket, buffers, handler]() noexcept {
                boost::asio::async_write(socket, buffers, handler);
            });
    }

    template <class T1, class T2, class T3>
    static inline void vmux_skt_async_read_some(T1& socket, const T2& buffers, T3&& handler) noexcept {
        boost::asio::post(socket.get_executor(),
            [&socket, buffers, handler]() noexcept {
                socket.async_read_some(buffers, handler);
            });
    }

    void vmux_skt::on_send_to_peer_completely(bool successed) noexcept {
        if (successed) {
            int location = TRUE; 
            if (status_.forwarding.compare_exchange_strong(location, FALSE)) {
                active();
            }

            successed = forward_to_rx_socket();
        }

        if (!successed) {
            close();
        }
    }

    bool vmux_skt::forward_to_rx_socket() noexcept {
        if (status_.disposed_) {
            return false;
        }
        
        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket = tx_socket_;
        if (NULL == tx_socket || NULL == tx_buffer_) {
            return false;
        }

        if (!tx_socket->is_open()) {
            return false;
        }

        int location = FALSE;
        if (status_.forwarding.compare_exchange_strong(location, TRUE)) {
            active();
        }
        else {
            return true;
        }

        std::shared_ptr<vmux_skt> self = shared_from_this();
        auto reading_cb =
            [self, this, tx_socket](const boost::system::error_code& ec, std::size_t sz) noexcept {
                int bytes_transferred = std::max<int>(-1, ec ? -1 : (int)sz);
                vmux_post_exec(mux_->context_, mux_->strand_, 
                    [self, this, bytes_transferred]() noexcept {
                        if (bytes_transferred > 0) {
                            bool forwarding = 
                                mux_->post(vmux_net::cmd_push, tx_buffer_.get(), bytes_transferred, connection_id_,
                                    [self, this](bool successed) noexcept {
                                        on_send_to_peer_completely(successed);
                                    });

                            if (forwarding) {
                                return true;
                            }
                        }

                        close();
                        return false;
                    });
            };
        
        int bytes_transferred = ppp::BufferSkateboarding(mux_->AppConfiguration->key.sb, vmux_net::max_buffers_size, vmux_net::max_buffers_size);
        vmux_skt_async_read_some(*tx_socket, boost::asio::buffer(tx_buffer_.get(), bytes_transferred), reading_cb);
        return true;
    }

    bool vmux_skt::forward_to_tx_socket(const std::shared_ptr<Byte>& payload, int payload_size) noexcept {
        if (NULL == payload || payload_size < 1) {
            return false;
        }

        if (status_.disposed_) {
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> tx_socket = tx_socket_;
        if (NULL == tx_socket) {
            return false;
        }

        if (!tx_socket->is_open()) {
            return false;
        }

        int location = FALSE;
        if (status_.sending_.compare_exchange_strong(location, TRUE)) {
            active();
        }
        else {
            return true;
        }
        
        std::shared_ptr<vmux_skt> self = shared_from_this();
        auto writing_cb =
            [self, this, tx_socket, payload, payload_size](const boost::system::error_code& ec, std::size_t sz) noexcept {
                vmux_post_exec(mux_->context_, mux_->strand_, 
                    [self, this, ec]() noexcept {
                        if (ec == boost::system::errc::success) {
                            int location = TRUE; 
                            if (status_.sending_.compare_exchange_strong(location, FALSE)) {
                                active();
                            }

                            packet_queue::iterator packet_tail = rx_queue_.begin();
                            packet_queue::iterator packet_endl = rx_queue_.end();

                            if (packet_tail == packet_endl) {
                                return true;
                            }

                            packet fpacket = *packet_tail;
                            rx_queue_.erase(packet_tail);

                            if (forward_to_tx_socket(fpacket.buffer, fpacket.buffer_size)) {
                                return true;
                            }
                        }

                        close();
                        return false;
                    });
            };

        vmux_skt_async_write(*tx_socket, boost::asio::buffer(payload.get(), payload_size), writing_cb);
        return true;
    }

    void vmux_skt::active(uint64_t now) noexcept {
        ActiveEventHandler h = active_event; 
        if (NULL != h) {
            h(this, !status_.disposed_);
        }

        last_ = now;
        mux_->active(now);
    }
}