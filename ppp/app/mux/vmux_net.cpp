#include "vmux.h"
#include "vmux_net.h"
#include "vmux_skt.h"

#include "ppp/app/client/VEthernetNetworkTcpipConnection.h"
#include "ppp/app/server/VirtualEthernetNetworkTcpipConnection.h"
#include "ppp/collections/Dictionary.h"

namespace vmux {
    vmux_net::vmux_net(const ContextPtr& context, const StrandPtr strand, uint16_t max_connections, bool server_mode, bool acceleration) noexcept {
        assert(max_connections > 0 && "The value of max_connections must be greater than 0.");

        vmux_net* const vmux             = this;
        vmux->Vlan                       = 0;
   
        vmux->base_.server_or_client_    = server_mode;
        vmux->base_.disposed_            = false;
        vmux->base_.ftt_                 = false;
        vmux->base_.established_         = false;
        vmux->base_.acceleration_        = acceleration;
        
        vmux->status_.max_connections    = max_connections;
        vmux->status_.opened_connections = 0;

        vmux->status_.rx_ack_            = 0;
        vmux->status_.tx_seq_            = 0;

        uint64_t now                     = now_tick();
        vmux->status_.last_              = now;
        vmux->status_.last_heartbeat_    = now;
        vmux->status_.heartbeat_timeout_ = 0;

        vmux->strand_                    = strand;
        vmux->context_                   = context;
    }

    vmux_net::~vmux_net() noexcept {
        finalize();
    }

    void vmux_net::finalize() noexcept {
        vmux_linklayer_vector rx_links;
        tx_packet_ssqueue tx_queue;
        rx_packet_ssqueue rx_queue;
        vmux_skt_map skts;
        std::shared_ptr<boost::asio::ip::tcp::resolver> tx_resolver;

        for (;;) {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            if (!base_.disposed_) {
                base_.disposed_ = true;
                status_.last_ = now_tick(); 
            }

            rx_links = std::move(rx_links_);
            tx_queue = std::move(tx_queue_);
            rx_queue = std::move(rx_queue_);

            skts = std::move(skts_);
            skts_.clear();

            tx_queue_.clear();
            rx_queue_.clear();
            rx_links_.clear();
            tx_links_.clear();
            break;
        }

        for (const std::pair<uint32_t, vmux_skt_ptr>& kv : skts) {
            const vmux_skt_ptr& skt = kv.second;
            skt->close(); // There is no need to send any data because the underlying link will be interrupted.
        }

        for (vmux_linklayer_ptr& linklayer : rx_links) {
            VirtualEthernetTcpipConnectionPtr& connection = linklayer->connection;
            connection->Dispose();

            if (auto server = linklayer->server; NULL != server) {
                server->Dispose();
                linklayer->server.reset();
            }
        }

        if (NULL != tx_resolver) {
            vmux_post_exec(context_, strand_,
                [tx_resolver]() noexcept {
                    ppp::net::Socket::Cancel(*tx_resolver);
                });
        }
    }

    vmux_net::VirtualEthernetTcpipConnectionPtr vmux_net::get_linklayer() noexcept {
        vmux_linklayer_vector::iterator tail = rx_links_.begin();
        vmux_linklayer_vector::iterator endl = rx_links_.end();
        return tail != endl ? (*tail)->connection : NULL;
    }

    bool vmux_net::ftt(uint32_t seq, uint32_t ack) noexcept {
        SynchronizationObjectScope __SCOPE__(syncobj_);
        if (base_.disposed_) {
            return false;
        }
        
        if (!base_.ftt_) {
            base_.ftt_ = true;
            status_.tx_seq_ = seq;
            status_.rx_ack_ = ack;
        }

        return (status_.tx_seq_ == seq) && (status_.rx_ack_ == ack);
    }

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

    void vmux_net::close_exec() noexcept {
        std::shared_ptr<vmux_net> self = shared_from_this();
        vmux_post_exec(context_, strand_,
            [self, this]() noexcept {
                finalize();
            });
    }

    static bool transmission_write(
        std::shared_ptr<vmux_net>                                           self,
        const vmux_net::ITransmissionPtr&                                   transmission, 
        const std::shared_ptr<Byte>&                                        packet, 
        int                                                                 packet_length,
        const ppp::transmissions::ITransmission::AsynchronousWriteCallback& ac) noexcept {

        ContextPtr context = transmission->GetContext();
        StrandPtr strand = transmission->GetStrand();

        const ppp::function<void(bool)> on_completely = 
            [self, ac](bool successed) noexcept {
                vmux_post_exec(self->get_context(), self->get_strand(), 
                    [self, successed, ac]() noexcept {
                        ac(successed);
                    });
            };

        return vmux_post_exec(context, strand,
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
    }
    
    bool vmux_net::underlyin_sent(const vmux_linklayer_ptr& linklayer, const std::shared_ptr<Byte>& packet, int packet_length, const PostInternalAsynchronousCallback& posted_ac) noexcept {
        if (NULL == packet || packet_length < sizeof(vmux_hdr)) {
            return false;
        }
        
        if (base_.disposed_) {
            return false;
        }

        VirtualEthernetTcpipConnectionPtr& connection = linklayer->connection;
        if (!connection->IsLinked()) {
            return false;
        }

        ITransmissionPtr transmission = connection->GetTransmission();
        if (NULL == transmission) {
            return false;
        }

        std::shared_ptr<vmux_net> self = shared_from_this();
        return transmission_write(self, transmission, packet, packet_length, 
            [self, this, linklayer, posted_ac](bool ok) noexcept {
                if (NULL != posted_ac) {
                    posted_ac(ok);
                }

                if (ok) {
                    tx_packet_ssqueue::iterator packet_tail = tx_queue_.begin();
                    tx_packet_ssqueue::iterator packet_endl = tx_queue_.end();
                    if (packet_tail == packet_endl) {
                        tx_links_.emplace_back(linklayer);
                    }
                    else {
                        tx_packet packet = *packet_tail;
                        tx_queue_.erase(packet_tail);

                        ok = underlyin_sent(linklayer, packet.buffer, packet.length, packet.ac);
                    }
                }

                if (!ok) {
                    close_exec();
                }
            });
    }

    bool vmux_net::update() noexcept {
        if (base_.disposed_) {
            return false;
        }

        std::shared_ptr<vmux_net> self = shared_from_this();
        return vmux_post_exec(context_, strand_,
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

                uint64_t max_mux_inactive_timeout = ((uint64_t)AppConfiguration->mux.inactive.timeout) * 1000ULL;
                uint64_t max_mux_connect_timeout = ((uint64_t)AppConfiguration->mux.connect.timeout) * 1000ULL;

                if ((now - status_.last_) >= (base_.established_ ? max_mux_inactive_timeout : max_mux_connect_timeout)) {
                    close_exec();
                }
                elif(base_.established_ && (now - status_.last_heartbeat_) >= status_.heartbeat_timeout_) {
                    if (post(cmd_keep_alived, NULL, 0, ftt_random_aid(1, INT32_MAX))) {
                        status_.last_heartbeat_ = now;
                        switch_to_next_heartbeat_timeout();
                    }
                }

                for (vmux_skt_ptr& skt : release_skts) {
                    skt->close();
                }
            });
    }

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

    bool vmux_net::packet_input_unorder(const vmux_linklayer_ptr& linklayer, vmux_hdr* h, int length, uint64_t now) noexcept {
        // Prepare the ack frames.
        if (base_.disposed_) {
            return false;
        }

        uint32_t seq = ntohl(h->seq);
        if (status_.rx_ack_ == seq) {
            if (packet_input(h->cmd, (Byte*)h, length, now)) {
                status_.rx_ack_++;
            }
            else {
                return false;
            }

            for (;;) {
                rx_packet_ssqueue::iterator packet_tail = rx_queue_.begin();
                rx_packet_ssqueue::iterator packet_endl = rx_queue_.end();
                if (packet_tail != packet_endl && status_.rx_ack_ == packet_tail->first) {
                    rx_packet i = packet_tail->second;
                    vmux_hdr* p = (vmux_hdr*)i.buffer.get();
                    rx_queue_.erase(packet_tail);

                    if (packet_input(p->cmd, (Byte*)p, i.length, now)) {
                        status_.rx_ack_++;
                    }
                    else {
                        return false;
                    }
                }
                else {
                    break;
                }
            }

            active(now);
            linklayer_update(linklayer);
            return true;
        }
        elif(packet_less<uint32_t>::after(seq, status_.rx_ack_)) {
            std::shared_ptr<Byte> buf = make_byte_array(length);
            if (NULL == buf) {
                return false;
            }

            rx_packet packet = { buf, length };
            memcpy(buf.get(), h, length);

            return rx_queue_.emplace(std::make_pair(seq, packet)).second;
        }
        else {
            return false;
        }
    }

    void vmux_net::packet_input_read(uint32_t connection_id, Byte* buffer, int buffer_size, uint64_t now) noexcept {
        vmux_skt_ptr skt = get_connection(connection_id);
        if (NULL != skt) {
            if (skt->input(buffer, buffer_size)) {
                skt->active(now);
            }
            else {
                skt->close();
            }
        }
    }

    bool vmux_net::packet_input(Byte cmd, Byte* buffer, int buffer_size, uint64_t now) noexcept {
        buffer_size -= sizeof(vmux_hdr);
        if (buffer_size < 0) {
            return false;
        }

        vmux_hdr* h = (vmux_hdr*)buffer;
        buffer = (Byte*)(h + 1);

        uint32_t connection_id = ntohl(h->connection_id);
        if (cmd == cmd_push) {
            packet_input_read(connection_id, buffer, buffer_size, now);
        }
        elif(cmd == cmd_fin) {
            packet_input_read(connection_id, NULL, 0, now);
        }
        elif(cmd == cmd_syn) {
            std::shared_ptr<vmux_skt> sk;
            bool successed = process_rx_connecting(sk, connection_id, (char*)buffer, buffer_size);

            if (NULL != sk) {
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
            if (NULL != skt) {
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
            if (NULL != skt) {
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
        else {
            return false;
        }

        return true;
    }
    
    bool vmux_net::process_rx_connecting(std::shared_ptr<vmux_skt>& skt, uint32_t connection_id, const char* host, int host_size) noexcept {
        if (base_.disposed_) {
            return false;
        }

        vmux_skt_map::iterator tail = skts_.find(connection_id);
        vmux_skt_map::iterator endl = skts_.end();
        if (tail != endl) {
            skt = tail->second;
            if (NULL != skt) {
                return false;
            }
        }

        std::shared_ptr<vmux_net> self = shared_from_this();
        skt = ppp::make_shared_object<vmux_skt>(self, connection_id);

        if (NULL == skt) {
            return false;
        }

        skts_[connection_id] = skt;
        return skt->accept(template_string(host, host_size));
    }

    uint32_t vmux_net::generate_id() noexcept {
        static std::atomic<uint32_t> aid = ftt_random_aid(1, INT32_MAX);

        for (;;) {
            uint32_t n = ++aid;
            if (n != 0) {
                return n;
            }
        }
    }

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

    vmux_net::vmux_skt_ptr vmux_net::release_connection(uint32_t connection_id, vmux_skt* refer_pointer) noexcept {
        vmux_skt_ptr skt;
        if (connection_id != 0) {
            vmux_skt_map::iterator tail = skts_.find(connection_id);
            vmux_skt_map::iterator endl = skts_.end();
            if (tail != endl) {
                skt = tail->second;
                if (skt.get() == refer_pointer) {
                    skts_.erase(tail);
                }
            }
        }

        return skt;
    }

    bool vmux_net::post_internal(const std::shared_ptr<Byte>& packet, int packet_length, bool acceleration, const PostInternalAsynchronousCallback& posted_ac) noexcept {
        if (NULL == packet || packet_length < sizeof(vmux_hdr)) {
            return false;
        }
        
        if (base_.disposed_ || !base_.established_) {
            return false;
        }

        vmux_hdr* h = (vmux_hdr*)packet.get();
        h->seq = htonl(status_.tx_seq_++);

        if (acceleration && base_.acceleration_) {
            vmux_linklayer_list::iterator linklayer_tail = tx_links_.begin();
            vmux_linklayer_list::iterator linklayer_endl = tx_links_.end();

            if (linklayer_tail != linklayer_endl) {
                tx_queue_.emplace_back(tx_packet{ packet, packet_length });
                if (NULL != posted_ac) {
                    vmux_post_exec(context_, strand_,
                        [posted_ac]() noexcept {
                            posted_ac(true);
                        });
                }

                return process_tx_all_packets();
            }
        }

        tx_queue_.emplace_back(tx_packet{ packet, packet_length, posted_ac });
        return process_tx_all_packets();
    }

    bool vmux_net::process_tx_all_packets() noexcept {
        vmux_linklayer_list::iterator linklayer_tail = tx_links_.begin();
        vmux_linklayer_list::iterator linklayer_endl = tx_links_.end();

        while (linklayer_tail != linklayer_endl) {

            tx_packet_ssqueue::iterator packet_tail = tx_queue_.begin();
            tx_packet_ssqueue::iterator packet_endl = tx_queue_.end();

            if (packet_tail == packet_endl) {
                break;
            }

            vmux_linklayer_ptr linklayer = *linklayer_tail;
            linklayer_tail = tx_links_.erase(linklayer_tail);

            tx_packet nexting_packet = *packet_tail;
            tx_queue_.erase(packet_tail);

            bool forwarding = underlyin_sent(linklayer, nexting_packet.buffer, nexting_packet.length, nexting_packet.ac);
            if (!forwarding) {
                return false;
            }
        }

        return true;
    }

    bool vmux_net::post_internal(Byte cmd, const void* buffer, int buffer_size, uint32_t connection_id, bool acceleration, const PostInternalAsynchronousCallback& posted_ac) noexcept {
        if (NULL != buffer && buffer_size < 0) {
            return false;
        }

        if (base_.disposed_ || !base_.established_) {
            return false;
        }

        int packet_length = sizeof(vmux_hdr) + buffer_size;
        std::shared_ptr<Byte> packet_managed = make_byte_array(packet_length);

        if (NULL == packet_managed) {
            return false;
        }

        Byte* packet_memory = packet_managed.get();
        if (NULL != buffer) {
            memcpy(packet_memory + sizeof(vmux_hdr), buffer, buffer_size);
        }

        vmux_hdr* h = (vmux_hdr*)packet_memory;
        h->cmd = cmd;
        h->connection_id = htonl(connection_id);
        
        return post_internal(packet_managed, packet_length, acceleration, posted_ac);
    }

    bool vmux_net::add_linklayer(const VirtualEthernetTcpipConnectionPtr& connection, vmux_linklayer_ptr& linklayer, const vmux_native_add_linklayer_after_success_before_callback& cb) noexcept {
        if (NULL == connection) {
            return false;
        }

        SynchronizationObjectScope __SCOPE__(syncobj_);
        if (base_.disposed_) {
            return false;
        }

        if (!connection->IsLinked()) {
            return false;
        }

        if (rx_links_.size() >= status_.max_connections) {
            return false;
        }

        linklayer = ppp::make_shared_object<vmux_linklayer>();
        if (NULL == linklayer) {
            return false;
        }

        std::shared_ptr<Byte> buffer = make_byte_array(max_buffers_size);
        if (NULL == buffer) {
            return false;
        }

        linklayer->connection = connection;
        tx_links_.emplace_back(linklayer);
        rx_links_.emplace_back(linklayer);

        bool unlimited = rx_links_.size() < status_.max_connections;
        if (unlimited) {
            if (NULL != cb && !cb()) {
                return false;
            }

            return true;
        }
        elif(NULL != cb && !cb()) {
            return false;
        }

        uint64_t now = now_tick();
        active(now);

        std::shared_ptr<vmux_net> self = shared_from_this();
        for (vmux_linklayer_ptr& linklayer : rx_links_) {

            uint16_t connection_id = 0;
            if (base_.server_or_client_) {
                connection_id = ++status_.opened_connections;
            }

            auto& connection = linklayer->connection;
            ContextPtr connection_context = connection->GetContext();
            StrandPtr connection_strand = connection->GetStrand();

            auto process =
                [self, this, linklayer, connection_id, connection_context, connection_strand](ppp::coroutines::YieldContext& y) noexcept {
                    if (handshake(linklayer, connection_id, y)) {
                        forwarding(linklayer, y);
                    }

                    close_exec();
                };

            if (!ppp::coroutines::YieldContext::Spawn(BufferAllocator.get(), *connection_context, connection_strand.get(), process)) {
                return false;
            }

            linklayer_update(linklayer);
        }

        return true;
    }

    bool vmux_net::handshake(const vmux_linklayer_ptr& linklayer, uint16_t connection_id, ppp::coroutines::YieldContext& y) noexcept {
        if (base_.disposed_) {
            return false;
        }

        VirtualEthernetTcpipConnectionPtr& linklayer_socket = linklayer->connection;
        if (!linklayer_socket->IsLinked()) {
            return false;
        }

        ITransmissionPtr linklayer_transmission = linklayer_socket->GetTransmission();
        if (NULL == linklayer_transmission) {
            return false;
        }

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
            vmux_linlayer_add_ack_packet packet;
            packet.receive_id = htons(connection_id);

            if (!linklayer_transmission->Write(y, &packet, sizeof(vmux_linlayer_add_ack_packet))) {
                return false;
            }
        }
        else {
            int buffer_size = 0;
            std::shared_ptr<Byte> packet_memory = linklayer_transmission->Read(y, buffer_size);
            if (NULL == packet_memory || buffer_size < sizeof(vmux_linlayer_add_ack_packet)) {
                return false;
            }

            vmux_linlayer_add_ack_packet* packet = (vmux_linlayer_add_ack_packet*)packet_memory.get();
            uint32_t receive_id = ntohs(packet->receive_id);

            if (receive_id == 0 && receive_id <= rx_links_.size()) {
                return false;
            }

            SynchronizationObjectScope __SCOPE__(syncobj_);
            status_.opened_connections++;
        }

        linklayer_established();
        return true;
    }

    void vmux_net::linklayer_established() noexcept {
        SynchronizationObjectScope __SCOPE__(syncobj_);
        if (!base_.established_) {
            base_.established_ = 
                status_.opened_connections >= status_.max_connections;

            uint64_t now = now_tick();
            status_.last_heartbeat_ = now;

            active(now);
            switch_to_next_heartbeat_timeout();
        }
    }

    bool vmux_net::forwarding(const vmux_linklayer_ptr& linklayer, ppp::coroutines::YieldContext& y) noexcept {
        if (base_.disposed_) {
            return false;
        }

        VirtualEthernetTcpipConnectionPtr& linklayer_socket = linklayer->connection;
        if (!linklayer_socket->IsLinked()) {
            return false;
        }

        ITransmissionPtr linklayer_transmission = linklayer_socket->GetTransmission();
        if (NULL == linklayer_transmission) {
            return false;
        }

        int buffer_size = 0;
        boost::system::error_code ec;

        bool any = false;
        std::shared_ptr<vmux_net> self = shared_from_this();

        linklayer_update(linklayer);
        for (;;) {
            if (base_.disposed_) {
                break;
            }

            if (!linklayer_socket->IsLinked()) {
                break;
            }

            std::shared_ptr<Byte> buffer_memory = linklayer_transmission->Read(y, buffer_size);
            if (NULL == buffer_memory || buffer_size < sizeof(vmux_hdr)) {
                break;
            }

            vmux_hdr* h = (vmux_hdr*)buffer_memory.get();
            Byte cmd = h->cmd;
            if (cmd <= cmd_none || cmd >= cmd_max) {
                break;
            }

            any |= vmux_post_exec(context_, strand_,
                [self, this, linklayer, buffer_memory, h, buffer_size]() noexcept {
                    uint64_t now = now_tick();
                    if (packet_input_unorder(linklayer, h, buffer_size, now)) {
                        return true;
                    }
                    else {
                        close_exec();
                        return false;
                    }
                });
        }
        
        return any;
    }

    void vmux_net::linklayer_update(const vmux_linklayer_ptr& linklayer) noexcept {
        VirtualEthernetTcpipConnectionPtr& connection = linklayer->connection;
        if (connection->IsLinked()) {
            connection->Update();
        }
    }

    bool vmux_net::connect_require(
        const std::shared_ptr<boost::asio::ip::tcp::socket>& sk,
        const template_string&                               host,
        int                                                  port) noexcept {

        if (base_.disposed_ || !base_.established_) {
            return false;
        }

        if (host.empty() || port <= 0 || port > UINT16_MAX) {
            return false;
        }

        if (NULL == sk) {
            return false;
        }

        return true;
    }

    bool vmux_net::connect_yield(
        ppp::coroutines::YieldContext&                       y,
        const ContextPtr&                                    context,
        const StrandPtr&                                     strand,
        const std::shared_ptr<boost::asio::ip::tcp::socket>& sk,
        const template_string&                               host,
        int                                                  port,
        const std::shared_ptr<vmux_skt_ptr>&                 return_connection) noexcept {

        if (!y || !return_connection) {
            return false;
        }

        if (NULL == context) {
            return false;
        }

        if (!connect_require(sk, host, port)) {
            return false;
        }

        std::shared_ptr<vmux_net::atomic_int> status = ppp::make_shared_object<vmux_net::atomic_int>(-1);
        if (NULL == status) {
            return false;
        }

        vmux_post_exec(context_, strand_,
            [this, sk, host, port, status, context, strand, return_connection, &y]() noexcept {
                bool ok = connect(context, strand, sk, host, port,
                    [status, return_connection, &y](vmux_skt* sender, bool success) noexcept {

                        ppp::coroutines::asio::R(y, *status, success, 
                            [return_connection, sender]() noexcept {
                                *return_connection = sender->shared_from_this();
                            });
                    });

                if (!ok) {
                    ppp::coroutines::asio::R(y, *status, false);
                }
            });

        y.Suspend();
        return status->load() > 0;
    }

    bool vmux_net::connect(const ContextPtr& context, const StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& sk, const template_string& host, int port, const ConnectAsynchronousCallback& ac) noexcept {
        if (NULL == context || !connect_require(sk, host, port)) {
            return false;
        }

        vmux_skt_ptr skt;
        std::shared_ptr<vmux_net> self = shared_from_this();

        for (;;) {
            uint32_t connection_id = generate_id();
            if (connection_id == 0) {
                continue;
            }

            vmux_skt_map::iterator skt_tail = skts_.find(connection_id);
            vmux_skt_map::iterator skt_endl = skts_.end();
            if (skt_tail != skt_endl) {
                continue;
            }

            skt = ppp::make_shared_object<vmux_skt>(self, connection_id);
            if (NULL == skt) {
                return false;
            }

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
            return false;
        }
    }
}