#include "netstack.h"

#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <lwip/sys.h>
#include <lwip/timeouts.h>
#include <lwip/priv/tcp_priv.h>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace lwip {
    struct netstack_tcp_socket {
        typedef struct {
            std::shared_ptr<char>                       p;
            int                                         sz;
        } buffer_chunk;

        typedef struct {
            buffer_chunk                                buf;
            ppp::function<void(struct tcp_pcb*)>        cb;
        } send_context;
        typedef std::shared_ptr<send_context>           send_context_ptr;

        typedef enum {
            ENETSTACK_TCP_SENT_LWIP,
            ENETSTACK_TCP_SENT_SOCK,
            ENETSTACK_TCP_SENT_MAX
        } ENETSTACK_TCP_SENT_BUFS;

        ppp::list<send_context_ptr>                     sents[ENETSTACK_TCP_SENT_MAX];
        std::shared_ptr<boost::asio::ip::tcp::socket>   socket;
        bool                                            open;
        int                                             pnat;

        struct tcp_pcb*                                 pcb;
        ip_addr_t                                       local_ip;
        u16_t                                           local_port;
        ip_addr_t                                       remote_ip;
        u16_t                                           remote_port;
        u8_t                                            buf[1400];
    };

    typedef std::shared_ptr<netstack_tcp_socket>        NetstackSocket;
    typedef ppp::unordered_map<void*, NetstackSocket>   Ptr2Socket;
    typedef ppp::unordered_map<int, NetstackSocket>     Nat2Socket;
    typedef std::mutex                                  SynchronizedObject;
    typedef std::lock_guard<SynchronizedObject>         SynchronizedObjectScope;

    LIBTCPIP_CLOSE_EVENT                                netstack::close_event = NULL;
    LIBTCPIP_IPV4_OUTPUT                                netstack::output      = NULL;
    uint32_t                                            netstack::IP          = 0;
    uint32_t                                            netstack::GW          = 0;
    uint32_t                                            netstack::MASK        = 0;
    int                                                 netstack::Localhost   = 0;
    boost::asio::io_context                             netstack::Executor;

    static boost::asio::io_context&                     context_            = netstack::Executor;
    static std::shared_ptr<boost::asio::deadline_timer> timeout_;
    static struct netif*                                netif_              = NULL;
    static struct tcp_pcb*                              pcb_                = NULL;
    static Ptr2Socket                                   p2ss_;
    static Nat2Socket                                   n2ss_;
    static SynchronizedObject                           lockobj_;
    static class Netstack final {
    public:
        Netstack() noexcept;

    public:
        void                                            run() noexcept;
        void                                            stop() noexcept;
    }                                                   netstack_;

    Netstack::Netstack() noexcept {
        ppp::SetThreadPriorityToMaxLevel();
        ppp::SetProcessPriorityToMaxLevel();
        ppp::SetThreadName("pppd");
    }

    void Netstack::run() noexcept {
        auto thread_start = []() noexcept {
                ppp::SetThreadPriorityToMaxLevel();
                ppp::SetThreadName("vnet");

                boost::system::error_code ec_;
                boost::asio::io_context::work work_(context_);
                context_.restart();
                context_.run(ec_);
            };
        std::thread(thread_start).detach();
    }

    void Netstack::stop() noexcept {
        context_.stop();
    }

    static void* netstack_tcp_linksocket(struct tcp_pcb* pcb, const std::shared_ptr<netstack_tcp_socket>& socket) noexcept {
        if (!pcb || !socket) {
            return NULL;
        }

        SynchronizedObjectScope scope_(lockobj_);
        std::pair<Ptr2Socket::iterator, bool> r_ = p2ss_.emplace(pcb, socket);
        return r_.second ? pcb : NULL;
    }

    static std::shared_ptr<netstack_tcp_socket> netstack_tcp_getsocket(void* p) noexcept {
        if (!p) {
            return NULL;
        }

        SynchronizedObjectScope scope_(lockobj_);
        Ptr2Socket::iterator tail_ = p2ss_.find(p);
        Ptr2Socket::iterator endl_ = p2ss_.end();
        return tail_ != endl_ ? tail_->second : NULL;
    }

    static std::shared_ptr<netstack_tcp_socket> netstack_tcp_releasesocket(void* p) noexcept {
        if (!p) {
            return NULL;
        }

        std::shared_ptr<netstack_tcp_socket> socket;
        do {
            SynchronizedObjectScope scope_(lockobj_);
            Ptr2Socket::iterator tail_ = p2ss_.find(p);
            Ptr2Socket::iterator endl_ = p2ss_.end();
            if (tail_ != endl_) {
                socket = std::move(tail_->second);
                p2ss_.erase(tail_);
            }
        } while (false);
        return std::move(socket);
    }

    static int netstack_tcp_linksocket(int nat, const std::shared_ptr<netstack_tcp_socket>& socket) noexcept {
        if (nat < 1 || nat > UINT16_MAX || !socket) {
            return 0;
        }

        SynchronizedObjectScope scope_(lockobj_);
        std::pair<Nat2Socket::iterator, bool> r_ = n2ss_.emplace(nat, socket);
        return r_.second ? nat : 0;
    }

    static std::shared_ptr<netstack_tcp_socket> netstack_tcp_getsocket(int nat) noexcept {
        if (nat < 1 || nat > UINT16_MAX) {
            return NULL;
        }

        SynchronizedObjectScope scope_(lockobj_);
        Nat2Socket::iterator tail_ = n2ss_.find(nat);
        Nat2Socket::iterator endl_ = n2ss_.end();
        return tail_ != endl_ ? tail_->second : NULL;
    }

    static std::shared_ptr<netstack_tcp_socket> netstack_tcp_releasesocket(int nat) noexcept {
        if (nat < 1 || nat > UINT16_MAX) {
            return NULL;
        }

        std::shared_ptr<netstack_tcp_socket> socket;
        {
            SynchronizedObjectScope scope_(lockobj_);
            Nat2Socket::iterator tail_ = n2ss_.find(nat);
            Nat2Socket::iterator endl_ = n2ss_.end();
            if (tail_ != endl_) {
                socket = std::move(tail_->second);
                n2ss_.erase(tail_);
            }
        } 
        return std::move(socket);
    }

    static err_t netstack_tcp_closesocket(struct tcp_pcb* pcb) noexcept;

    static bool netstack_tcp_closesocket(const std::shared_ptr<netstack_tcp_socket>& socket_) noexcept;

    static err_t netstack_tcp_send(struct tcp_pcb* pcb, void* data, u16_t len, const ppp::function<void(struct tcp_pcb*)>& callback) noexcept {
        if (!pcb) {
            return ERR_ARG;
        }

        std::shared_ptr<netstack_tcp_socket> socket_ = netstack_tcp_getsocket(pcb->callback_arg);
        if (!socket_) {
            return ERR_ABRT;
        }

        if (!data || !len) {
            return ERR_ARG;
        }

        static auto tcp_enqueue_ =
            [](netstack_tcp_socket* socket_, struct tcp_pcb* pcb, void* data, u16_t len, const ppp::function<void(struct tcp_pcb*)>& callback) noexcept {
            std::shared_ptr<char> chunk_ = std::shared_ptr<char>((char*)malloc(len), free);
            memcpy(chunk_.get(), data, len);

            netstack_tcp_socket::send_context_ptr context_ =
                std::make_shared<netstack_tcp_socket::send_context>();
            context_->buf.p = std::move(chunk_);
            context_->buf.sz = len;
            context_->cb = callback;
            socket_->sents[netstack_tcp_socket::ENETSTACK_TCP_SENT_LWIP].emplace_back(std::move(context_));
            return ERR_OK;
        };
        if (!socket_->sents[netstack_tcp_socket::ENETSTACK_TCP_SENT_LWIP].empty()) {
            return tcp_enqueue_(socket_.get(), pcb, data, len, callback);
        }

        err_t err = tcp_write(pcb, data, len, TCP_WRITE_FLAG_COPY);
        if (err == ERR_OK) {
            tcp_output(pcb);
            if (callback) {
                callback(pcb);
            }
            return err;
        }
        else if (err == ERR_MEM) {
            return tcp_enqueue_(socket_.get(), pcb, data, len, callback);
        }
        return err;
    }

    static void netstack_tcp_arg(struct tcp_pcb* pcb, void* arg) noexcept {
        if (pcb) {
            tcp_arg(pcb, arg);
        }
    }

    static void netstack_tcp_event(struct tcp_pcb* pcb, tcp_recv_fn recv, tcp_sent_fn sent, tcp_err_fn errf, tcp_poll_fn poll) noexcept {
        if (pcb) {
            tcp_recv(pcb, recv ? recv : tcp_recv_null);
            tcp_sent(pcb, sent);
            tcp_err(pcb, errf);
            tcp_poll(pcb, poll, poll ? 8 : 0);
        }
    }

    static void netstack_tcp_closesocket(boost::asio::ip::tcp::socket& socket) noexcept {
        if (socket.is_open()) {
            boost::system::error_code ec;
            try {
                socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
            }
            catch (const std::exception&) {}

            try {
                socket.close(ec);
            }
            catch (const std::exception&) {}
        }
    }

    static void netstack_tcp_closesocket(std::shared_ptr<boost::asio::ip::tcp::socket> socket) noexcept {
        if (socket) {
            netstack_tcp_closesocket(*socket.get());
        }
    }

    static bool netstack_tcp_closesocket(const std::shared_ptr<netstack_tcp_socket>& socket_) noexcept {
        if (!socket_) {
            return false;
        }

        netstack_tcp_closesocket(std::move(socket_->socket));
        for (int i = netstack_tcp_socket::ENETSTACK_TCP_SENT_LWIP; i < netstack_tcp_socket::ENETSTACK_TCP_SENT_MAX; i++) {
            socket_->sents[i].clear();
        }

        struct tcp_pcb* pcb = socket_->pcb;
        if (pcb) {
            socket_->pcb = NULL;
            netstack_tcp_releasesocket(pcb->callback_arg);
        }

        netstack_tcp_releasesocket(socket_->pnat);
        netstack_tcp_closesocket(pcb);
        return true;
    }

    static err_t netstack_tcp_closesocket(struct tcp_pcb* pcb) noexcept {
        if (!pcb) {
            return ERR_ARG;
        }

        std::shared_ptr<netstack_tcp_socket> socket_ = netstack_tcp_releasesocket(pcb->callback_arg);
        netstack_tcp_arg(pcb, NULL);
        netstack_tcp_event(pcb, NULL, NULL, NULL, NULL);

        if (socket_) {
            socket_->pcb = NULL;
            netstack_tcp_closesocket(socket_);
        }
        return tcp_close(pcb);
    }

    struct pbuf* netstack_pbuf_alloc(uint16_t len) noexcept {
        if (!len) {
            return NULL;
        }
        else {
            return pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
        }
    }

    void netstack_pbuf_free(struct pbuf* buf) noexcept {
        if (buf) {
            pbuf_free(buf);
        }
    }

    static bool netstack_tunnel_send(const std::shared_ptr<netstack_tcp_socket>& socket_, void* data, int len, bool unsafe_) noexcept;

    static err_t netstack_tcp_dorecv(void* arg, struct tcp_pcb* pcb, struct pbuf* p, err_t err) noexcept {
        LWIP_UNUSED_ARG(arg);

        if (p) {
            std::shared_ptr<netstack_tcp_socket> socket = netstack_tcp_getsocket(pcb->callback_arg);
            for (struct pbuf* q = p; p; p = p->next) {
                tcp_recved(pcb, q->len);
                netstack_tunnel_send(socket, p->payload, p->len, true);
            }

            netstack_pbuf_free(p);
            if (!socket) {
                tcp_abort(pcb);
                return ERR_ABRT;
            }
        }
        else if (err == ERR_OK) {
            return netstack_tcp_closesocket(pcb);
        }
        return ERR_OK;
    }

    static err_t netstack_tcp_dosent(void* arg, struct tcp_pcb* pcb, u16_t len) noexcept {
        LWIP_UNUSED_ARG(arg);

        std::shared_ptr<netstack_tcp_socket> socket_ = netstack_tcp_getsocket(pcb->callback_arg);
        if (socket_) {
            ppp::list<netstack_tcp_socket::send_context_ptr>& sents = socket_->sents[netstack_tcp_socket::ENETSTACK_TCP_SENT_LWIP];
            while (!sents.empty()) { // tcp_sndbuf
                err_t err_ = ERR_ABRT;
                do {
                    netstack_tcp_socket::send_context_ptr context_ = sents.front();
                    err_ = tcp_write(pcb,
                        context_->buf.p.get(),
                        context_->buf.sz, TCP_WRITE_FLAG_COPY);
                    if (err_ == ERR_OK) {
                        tcp_output(pcb);
                        if (context_->cb) {
                            context_->cb(pcb);
                        }
                        sents.pop_front();
                    }
                } while (false);

                if (err_) {
                    if (err_ == ERR_MEM) {
                        break;
                    }

                    netstack_tcp_closesocket(socket_);
                    return ERR_ABRT;
                }
            }
            return ERR_OK;
        }
        else {
            tcp_abort(pcb);
            return ERR_ABRT;
        }
    }

    static void netstack_tcp_doerrf(void* arg, err_t err) noexcept {
        std::shared_ptr<netstack_tcp_socket> socket_ = netstack_tcp_getsocket(arg);
        if (socket_) {
            netstack_tcp_closesocket(socket_);
        }
    }

    static err_t netstack_tcp_dopoll(void* arg, struct tcp_pcb* pcb) noexcept {
        std::shared_ptr<netstack_tcp_socket> socket = netstack_tcp_getsocket(pcb->callback_arg);
        if (socket) {
            std::shared_ptr<boost::asio::ip::tcp::socket> p = socket->socket;
            if (p) {
                if (p->is_open()) {
                    return ERR_OK;
                }
            }
            return ERR_ABRT;
        }
        else {
            tcp_abort(pcb);
            return ERR_ABRT;
        }
    }

    static bool netstack_socket_connect(const std::shared_ptr<netstack_tcp_socket>& socket_, const boost::asio::ip::tcp::endpoint& remoteEP_) noexcept;
    static bool netstack_tunnel_open(const std::shared_ptr<netstack_tcp_socket>& socket_, boost::asio::ip::tcp::endpoint& remoteEP_) noexcept;

    static err_t netstack_tcp_doaccept(void* arg, struct tcp_pcb* pcb, err_t err) noexcept {
        LWIP_UNUSED_ARG(arg);
        LWIP_UNUSED_ARG(err);

        std::shared_ptr<netstack_tcp_socket> socket_ = std::make_shared<netstack_tcp_socket>();
        socket_->pcb = pcb;
        socket_->pnat = 0;
        socket_->open = false;
        socket_->socket = std::make_shared<boost::asio::ip::tcp::socket>(context_);
        socket_->local_ip = pcb->remote_ip;
        socket_->local_port = pcb->remote_port;
        socket_->remote_ip = pcb->local_ip;
        socket_->remote_port = pcb->local_port;

        void* callback_arg = netstack_tcp_linksocket(pcb, socket_);
        if (callback_arg) {
            netstack_tcp_arg(pcb, callback_arg);
        }
        else {
            netstack_tcp_closesocket(socket_);
            return ERR_ABRT;
        }

        boost::asio::ip::tcp::endpoint remoteEP_;
        if (callback_arg && netstack_tunnel_open(socket_, remoteEP_) && netstack_socket_connect(socket_, remoteEP_)) {
            netstack_tcp_event(pcb, netstack_tcp_dorecv, netstack_tcp_dosent, netstack_tcp_doerrf, netstack_tcp_dopoll);
            return ERR_OK;
        }
        else {
            netstack_tcp_closesocket(socket_);
            return ERR_ABRT;
        }
    }

    static bool netstack_tunnel_send(const std::shared_ptr<netstack_tcp_socket>& socket_, void* data, int len, bool unsafe_) noexcept {
        if (!socket_ || !data || len < 1) {
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket>& socket = socket_->socket;
        if (!socket || !socket->is_open()) {
            return false;
        }

        if (!socket_->open) {
            std::shared_ptr<char> chunk_ = std::shared_ptr<char>((char*)malloc(len), free);
            memcpy(chunk_.get(), data, len);

            netstack_tcp_socket::send_context_ptr context_ =
                std::make_shared<netstack_tcp_socket::send_context>();
            context_->buf.p = std::move(chunk_);
            context_->buf.sz = len;

            socket_->sents[netstack_tcp_socket::ENETSTACK_TCP_SENT_SOCK].emplace_back(std::move(context_));
            return true;
        }

        std::shared_ptr<char> chunk_;
        if (unsafe_) {
            chunk_ = std::shared_ptr<char>((char*)malloc(len), free);
            memcpy(chunk_.get(), data, len);
        }
        else {
            chunk_ = *(std::shared_ptr<char>*)data;
        }

        std::shared_ptr<netstack_tcp_socket> socket__ = socket_;
        boost::asio::async_write(*socket, boost::asio::buffer(chunk_.get(), len), [socket__, chunk_](const boost::system::error_code& ec, size_t sz) noexcept {
            if (ec) {
                netstack_tcp_closesocket(socket__);
            }
        });
        return true;
    }

    static bool netstack_tunnel_dorecv(const std::shared_ptr<netstack_tcp_socket>& socket_) noexcept {
        if (!socket_) {
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket>& socket = socket_->socket;
        if (!socket || !socket->is_open()) {
            return false;
        }

        std::shared_ptr<netstack_tcp_socket> socket__ = socket_;
        socket->async_read_some(boost::asio::buffer(socket_->buf, sizeof(socket_->buf)), [socket__](const boost::system::error_code& ec, size_t sz) {
            int by = std::max<int>(-1, ec ? -1 : (int)sz);
            if (by < 1) {
                netstack_tcp_closesocket(socket__);
            }
            else {
                netstack_tcp_send(socket__->pcb, socket__->buf, by, [socket__](struct tcp_pcb*) {
                    netstack_tunnel_dorecv(socket__);
                });
            }
        });
        return true;
    }

    static bool nestack_tunnel_post_all_unsent(const std::shared_ptr<netstack_tcp_socket>& socket_) noexcept {
        if (!socket_) {
            return false;
        }

        ppp::list<netstack_tcp_socket::send_context_ptr>& sents = socket_->sents[netstack_tcp_socket::ENETSTACK_TCP_SENT_SOCK];
        while (!sents.empty()) {
            netstack_tcp_socket::send_context_ptr context_ = sents.front();
            sents.pop_front();
            netstack_tunnel_send(socket_, std::addressof(context_->buf.p), context_->buf.sz, false);
        }
        return true;
    }

    static bool netstack_socket_connect(const std::shared_ptr<netstack_tcp_socket>& socket_, const boost::asio::ip::tcp::endpoint& remoteEP_) noexcept {
        if (!socket_) {
            return false;
        }
        
        std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_->socket;
        if (!socket) {
            return false;
        }

        socket->async_connect(remoteEP_, [socket_](const boost::system::error_code& ec) noexcept {
            if (ec) {
                netstack_tcp_closesocket(socket_);
                return;
            }

            if (socket_->open) {
                netstack_tcp_closesocket(socket_);
                return;
            }
            else {
                socket_->open = true;
            }

            bool ok = netstack_tunnel_dorecv(socket_) && nestack_tunnel_post_all_unsent(socket_);
            if (!ok) {
                netstack_tcp_closesocket(socket_);
                return;
            }
        });
        return true;
    }

    static bool netstack_tunnel_open(const std::shared_ptr<netstack_tcp_socket>& socket_, boost::asio::ip::tcp::endpoint& remoteEP_) noexcept {
        std::shared_ptr<boost::asio::ip::tcp::socket>& socket = socket_->socket;
        if (!socket || socket->is_open()) {
            return false;
        }

        if (IP_IS_V4_VAL(socket_->remote_ip)) {
            remoteEP_ = boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), netstack::Localhost);
        }
        else {
            return false;
        }

        boost::system::error_code ec;
        try {
            socket->open(remoteEP_.protocol(), ec);
            if (ec) {
                return false;
            }

            socket->set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec);
            socket->bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), 0), ec);
            if (ec) {
                return false;
            }

            boost::asio::ip::tcp::endpoint localEP = socket->local_endpoint(ec);
            if (ec) {
                return false;
            }
            
            socket_->pnat = netstack_tcp_linksocket(localEP.port(), socket_);
            if (!socket_->pnat) {
                return false;
            }

            return true;
        }
        catch (const std::exception&) {
            return false;
        }
    }

    static err_t netstack_ip_output(struct pbuf* p) noexcept {
        if (!p || !p->len) {
            return ERR_BUF;
        }

        // pbuf_copy_partial
        LIBTCPIP_IPV4_OUTPUT f = netstack::output;
        if (NULL == f) {
            return ERR_IF;
        }
        return f(p->payload, p->len) ? ERR_OK : ERR_IF;
    }

    static err_t netstack_ip_output_v4(struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr) noexcept {
        LWIP_UNUSED_ARG(netif);
        LWIP_UNUSED_ARG(ipaddr);

        return netstack_ip_output(p);
    }

    static bool netstack_tcp_init() noexcept {
        struct tcp_pcb* pcb_acceptor = tcp_new();
        if (NULL == pcb_acceptor) {
            return false;
        }
        else {
            tcp_bind(pcb_acceptor, IP_ADDR_ANY, 0);
        }

        struct tcp_pcb* pcb = tcp_listen(pcb_acceptor);
        if (NULL == pcb) {
            tcp_close(pcb_acceptor);
            return false;
        }
        else {
            tcp_arg(pcb, NULL);
            tcp_accept(pcb, netstack_tcp_doaccept);

            pcb_ = pcb;
            return pcb_ != NULL;
        }
    }

    static void netstack_check_timeouts() noexcept {
        timeout_->expires_from_now(boost::posix_time::milliseconds(250));
        timeout_->async_wait([](const boost::system::error_code& ec) noexcept {
            sys_check_timeouts();
            netstack_check_timeouts();
        });
    }

    struct pbuf* netstack_pbuf_copy(const void* packet, int size) noexcept {
        if (!packet || size < 1 || !netif_) {
            return NULL;
        }

        struct pbuf* pbuf = netstack_pbuf_alloc(size);
        if (!pbuf) {
            return NULL;
        }
        
        memcpy(pbuf->payload, packet, size);
        return pbuf;
    }

    bool netstack::input(const void* packet, int size) noexcept {
        struct pbuf* pbuf = netstack_pbuf_copy(packet, size);
        if (!pbuf) {
            return false;
        }

        return netstack::input(pbuf);
    }

    bool netstack::input(struct pbuf* pbuf) noexcept {
        if (NULL == pbuf) {
            return false;
        }

        context_.dispatch(
            [pbuf]() noexcept {
                struct netif* netif = netif_;
                if (netif) {
                    if (netif->input(pbuf, netif) == ERR_OK) {
                        return true;
                    }
                }

                pbuf_free(pbuf);
                return true;
            });
        return true;
    }

    bool netstack::open() noexcept {
        if (timeout_) {
            return false;
        }
        else {
            timeout_ = std::make_shared<boost::asio::deadline_timer>(context_);
        }

#ifdef _WIN32
        sys_init();
#endif
        lwip_init();

        struct netif* netif = netif_list;
        netif->input = netif->input ? netif->input : ::ip_input;
        netif->output = netstack_ip_output_v4; /*netif_loop_output_ipv4*/

        ip4_addr_t ips[] = { netstack::IP, netstack::MASK, netstack::IP };
        netif_set_ipaddr(netif, ips + 0);
        netif_set_netmask(netif, ips + 1);
        netif_set_gw(netif, ips + 2);

        netif_ = netif;
        netif_default = netif;
        if (!netstack_tcp_init()) {
            return false;
        }

        netstack_.run();
        return true;
    }

    void netstack::close() noexcept {
        context_.post(
            []() noexcept {
                struct tcp_pcb* pcb = pcb_;
                pcb_ = NULL;
                netif_ = NULL;

                boost::system::error_code ec;
                std::shared_ptr<boost::asio::deadline_timer> timeout = std::move(timeout_);
                if (timeout) {
                    timeout_.reset();
                    try {
                        timeout->cancel(ec);
                    }
                    catch (const std::exception&) {}
                }

                ppp::unordered_set<NetstackSocket> sockets; {
                    SynchronizedObjectScope scope_(lockobj_);
                    Ptr2Socket::iterator tail_ = p2ss_.begin();
                    Ptr2Socket::iterator endl_ = p2ss_.end();
                    for (; tail_ != endl_; ++tail_) {
                        sockets.emplace(std::move(tail_->second));
                    }
                    p2ss_.clear();
                }

                for (NetstackSocket socket : sockets) {
                    netstack_tcp_closesocket(socket);
                }

                sockets.clear();
                if (pcb) {
                    tcp_close(pcb);
                }

                LIBTCPIP_CLOSE_EVENT close_event_ = netstack::close_event;
                if (close_event_) {
                    close_event_();
                }

                netstack_.stop();
            });
    }

    bool netstack::link(int nat, uint32_t& srcAddr, int& srcPort, uint32_t& dstAddr, int& dstPort) noexcept {
        dstAddr = 0;
        dstPort = 0;
        srcAddr = 0;
        srcPort = 0;

        std::shared_ptr<netstack_tcp_socket> socket = netstack_tcp_getsocket(nat);
        if (!socket) {
            return false;
        }

        if (IP_IS_V4_VAL(socket->remote_ip)) {
            dstAddr = ip_addr_get_ip4_u32(&socket->remote_ip);
            dstPort = socket->remote_port;
        }
        else {
            return false;
        }

        if (IP_IS_V4_VAL(socket->local_ip)) {
            srcAddr = ip_addr_get_ip4_u32(&socket->local_ip);
            srcPort = socket->local_port;
            return true;
        }
        else {
            return false;
        }
    }
}

#ifdef __cplusplus 
extern "C" { 
#endif

void* lwip_netstack_malloc(size_t sz) noexcept {
    return ppp::Malloc(sz);
}

void lwip_netstack_free(void* p) noexcept {
    ppp::Mfree(p);
}

void* lwip_netstack_calloc(size_t __nmemb, size_t __size) noexcept {
    return ppp::Malloc(__nmemb * __size);
}

#ifdef __cplusplus 
}
#endif