#include <common/aggligator/aggligator.h>

#include <ppp/net/native/checksum.h>
#include <ppp/net/Socket.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/threading/Executors.h>

#if defined(_WIN32)
#define IPTOS_TOS_MASK      0x1E
#define IPTOS_TOS(tos)      ((tos) & IPTOS_TOS_MASK)
#define IPTOS_LOWDELAY      0x10
#define IPTOS_THROUGHPUT    0x08
#define IPTOS_RELIABILITY   0x04
#define IPTOS_MINCOST       0x02

#include <windows/ppp/net/QoSS.h>

using ppp::net::QoSS;
#endif

using namespace ppp;
using namespace ppp::coroutines;
using namespace ppp::net;
using namespace ppp::net::native;

namespace aggligator
{
    /* Refer:
     * https://github.com/torvalds/linux/blob/977b1ef51866aa7170409af80740788d4f9c4841/include/net/tcp.h#L287
     * https://lore.kernel.org/netdev/87pronqq04.fsf@chdir.org/T/
     * https://android.googlesource.com/kernel/mediatek/+/android-mtk-3.18/include/net/tcp.h?autodive=0%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F
     * https://elixir.bootlin.com/linux/v2.6.27-rc7/source/include/net/tcp.h
     *
     * The next routines deal with comparing 32 bit unsigned ints
     * and worry about wraparound (automatic with unsigned arithmetic).
     */    

    static inline bool                                                  before(uint32_t seq1, uint32_t seq2) noexcept
    {
        return (int32_t)(seq1 - seq2) < 0;
    }
    
    static inline bool                                                  after(uint32_t seq2, uint32_t seq1) noexcept
    {
        return before(seq1, seq2);
    }

    class aggligator::server
    {
    public:
        ~server() noexcept
        {
            close();
        }

        void                                                            close() noexcept
        {
            for (auto&& kv : acceptors_)
            {
                acceptor& acceptor = kv.second;
                boost::system::error_code ec;
                acceptor->cancel(ec);
                acceptor->close(ec);
            }

            acceptors_.clear();
        }

        boost::asio::ip::udp::endpoint                                  server_endpoint_;
        unordered_map<int, acceptor>                                    acceptors_;
        unordered_map<int, client_ptr>                                  clients_;
    };

    class aggligator::client : public std::enable_shared_from_this<client>
    {
    public:
        client(const std::shared_ptr<aggligator>& aggligator) noexcept
            : socket_(aggligator->context_)
            , app_(aggligator)
            , server_mode_(false)
            , local_port_(0)
            , remote_port_(0)
            , established_num_(0)
            , connections_num_(0)
            , handshakeds_num_(0)
            , last_(0)
        {

        }
        ~client() noexcept
        {
            close();
        }

        void                                                            close() noexcept;
        bool                                                            send(Byte* packet, int packet_length) noexcept;
        bool                                                            open(int connections, unordered_set<boost::asio::ip::tcp::endpoint>& servers) noexcept;
        bool                                                            loopback() noexcept;
        bool                                                            timeout() noexcept;
        bool                                                            update(uint32_t now_seconds) noexcept;

        boost::asio::ip::udp::endpoint                                  source_endpoint_;
        boost::asio::ip::udp::socket                                    socket_;
        std::shared_ptr<aggligator>                                     app_;
        std::shared_ptr<convergence>                                    convergence_;
        deadline_timer                                                  timeout_;
        unordered_set<boost::asio::ip::tcp::endpoint>                   server_endpoints_;

        list<connection_ptr>                                            connections_;
        bool                                                            server_mode_     = false;
        int                                                             local_port_      = 0;
        uint16_t                                                        remote_port_     = 0;
        uint32_t                                                        established_num_ = 0;
        uint32_t                                                        connections_num_ = 0;
        uint32_t                                                        handshakeds_num_ = 0;
        uint32_t                                                        last_            = 0;
    };

    class aggligator::convergence
    {
    public:
        struct recv_packet
        {
            uint32_t                                                    seq    = 0;
            int                                                         length = 0;
            std::shared_ptr<Byte>                                       packet;
            boost::asio::ip::udp::endpoint                              dst;
        };

        template <typename _Tp>
        struct packet_less 
        {
            constexpr bool                                              operator()(const _Tp& __x, const _Tp& __y) const noexcept 
            {
                return before(__x, __y);
            }
        };

        queue<send_packet>                                              send_queue_;
        map_pr<uint32_t, recv_packet, packet_less<uint32_t>>            recv_queue_;
        uint32_t                                                        seq_no_         = 0;
        uint32_t                                                        ack_no_         = 1;
        std::shared_ptr<client>                                         client_;
        std::shared_ptr<aggligator>                                     app_;

        convergence(const std::shared_ptr<aggligator>& aggligator, const std::shared_ptr<client>& client) noexcept
            : client_(client)
            , app_(aggligator)
        {
            seq_no_ = (uint32_t)RandomNext(UINT16_MAX, INT32_MAX);
            ack_no_ = 0;
        }
        ~convergence() noexcept
        {
            close();
        }

        void                                                            close() noexcept;
        std::shared_ptr<Byte>                                           pack(Byte* packet, int packet_length, uint32_t seq, int& out) noexcept;
        bool                                                            input(Byte* packet, int packet_length) noexcept;
        bool                                                            output(Byte* packet, int packet_length) noexcept;
    };

    class aggligator::connection : public std::enable_shared_from_this<connection>
    {
    public:
        connection(const std::shared_ptr<aggligator>& aggligator, const client_ptr& client, const convergence_ptr& convergence) noexcept
            : app_(aggligator)
            , convergence_(convergence)
            , client_(client)
            , sending_(false)
            , next_(0)
        {

        }
        ~connection() noexcept
        {
            close();
        }

        void                                                            close() noexcept
        {
#if defined(_WIN32)
            qoss_.reset();
#endif

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::move(socket_);
            socket_.reset();

            if (socket)
            {
                aggligator::socket_close(*socket);
            }

            std::shared_ptr<aggligator> aggligator = app_;
            app_.reset();

            convergence_ptr convergence = std::move(convergence_);
            convergence_.reset();

            next_packet_.reset();
            if (convergence)
            {
                convergence->close();
            }

            client_ptr client = std::move(client_);
            client_.reset();

            if (client)
            {
                client->close();
            }
        }
        bool                                                            sent(const std::shared_ptr<Byte>& packet, int length) noexcept
        {
            ptr aggligator = app_;
            if (!aggligator)
            {
                return false;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
            if (!socket)
            {
                return false;
            }

            bool opened = socket->is_open();
            if (!opened)
            {
                return false;
            }

            auto self = shared_from_this();
            boost::asio::async_write(*socket, boost::asio::buffer(packet.get(), length),
                [self, this, packet, length](boost::system::error_code ec, std::size_t sz) noexcept
                {
                    bool processed = false;
                    sending_ = false;

                    if (ec == boost::system::errc::success)
                    {
                        ptr aggligator = app_;
                        if (aggligator)
                        {
                            aggligator->tx_ += sz;
                            aggligator->tx_pps_++;
                            processed = next();
                        }
                    }

                    if (!processed)
                    {
                        close();
                    }
                });

            sending_ = true;
            return true;
        }
        bool                                                            next() noexcept
        {
            convergence_ptr convergence = convergence_;
            if (!convergence)
            {
                return false;
            }
            else
            {
                std::shared_ptr<Byte> next_packet = std::move(next_packet_);
                next_packet_.reset();

                if (next_packet)
                {
                    return sent(next_packet, 2);
                }
            }

            auto tail = convergence->send_queue_.begin();
            auto endl = convergence->send_queue_.end();
            if (tail == endl)
            {
                return true;
            }

            send_packet context = *tail;
            convergence->send_queue_.erase(tail);

            return sent(context.packet, context.length);
        }
        bool                                                            recv() noexcept
        {
            std::shared_ptr<aggligator> aggligator = app_;
            if (!aggligator)
            {
                close();
                return false;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
            if (!socket)
            {
                close();
                return false;
            }

            bool opened = socket->is_open();
            if (!opened)
            {
                close();
                return false;
            }

            auto self = shared_from_this();
            boost::asio::async_read(*socket, boost::asio::buffer(buffer_, 2),
                [self, this, socket](boost::system::error_code ec, std::size_t sz) noexcept
                {
                    do 
                    {
                        ptr aggligator = app_;
                        if (!aggligator)
                        {
                            close();
                            break;
                        }

                        aggligator->rx_ += sz;
                        if (sz != 2)
                        {
                            close();
                            break;
                        }

                        client_ptr client = client_;
                        if (!client)
                        {
                            close();
                            break;
                        }

                        std::size_t length = buffer_[0] << 8 | buffer_[1];
                        if (length == 0)
                        {
                            if (!recv())
                            {
                                close();
                                break;
                            }
                            else
                            {
                                aggligator->rx_pps_++;
                            }

                            client->last_ = (uint32_t)(aggligator->now() / 1000);
                            break;
                        }

                        boost::asio::async_read(*socket, boost::asio::buffer(buffer_, length),
                            [self, this, length](boost::system::error_code ec, std::size_t sz) noexcept
                            {
                                do 
                                {
                                    ptr aggligator = app_;
                                    if (!aggligator)
                                    {
                                        close();
                                        break;
                                    }

                                    aggligator->rx_ += sz;
                                    if (length != sz)
                                    {
                                        close();
                                        break;
                                    }

                                    client_ptr client = client_;
                                    if (!client)
                                    {
                                        close();
                                        break;
                                    }

                                    convergence_ptr convergence = convergence_;
                                    if (!convergence)
                                    {
                                        close();
                                        break;
                                    }
                                    else
                                    {
                                        aggligator->rx_pps_++;
                                    }

                                    bool ok = convergence->input(buffer_, length) && recv();
                                    if (ok)
                                    {
                                        client->last_ = (uint32_t)(aggligator->now() / 1000);
                                    }
                                    else
                                    {
                                        close();
                                        break;
                                    }
                                } while (false);
                            });
                    } while (false);
                });
            return true;
        }
        bool                                                            open(YieldContext& y, const boost::asio::ip::tcp::endpoint& server, const ppp::function<void(connection*)>& established) noexcept
        {
            std::shared_ptr<aggligator> aggligator = app_;
            if (!aggligator)
            {
                return false;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
            if (!socket)
            {
                socket = make_shared_object<boost::asio::ip::tcp::socket>(aggligator->context_);
                if (!socket)
                {
                    return false;
                }
            }

            if (socket->is_open())
            {
                return false;
            }

            boost::system::error_code ec;
            if (!ppp::coroutines::asio::async_open(y, *socket, server.protocol()))
            {
                return false;
            }
            else
            {
                aggligator->socket_adjust(*socket);
            }

#if defined(_LINUX)
            boost::asio::ip::address server_ip = server.address();
            if (server_ip.is_v4() && !server_ip.is_loopback())
            {
                ProtectorNetworkPtr protector_network = aggligator->ProtectorNetwork; 
                if (NULL != protector_network) 
                {
                    if (!protector_network->Protect(socket->native_handle(), y)) 
                    {
                        return false;
                    }
                }
            }
#elif defined(_WIN32)
            qoss_ = QoSS::New(socket->native_handle(), server.address(), server.port());
#endif
            socket_ = socket;

            connection_ptr self = shared_from_this();
            boost::asio::post(socket->get_executor(), 
                [self, this, established, socket, server]() noexcept 
                {
                    socket->async_connect(server,
                        [self, this, established](boost::system::error_code ec) noexcept
                        {
                            ptr aggligator = app_;
                            if (!aggligator)
                            {
                                close();
                                return false;
                            }

                            if (ec)
                            {
                                close();
                                return false;
                            }

                            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                            if (!socket)
                            {
                                close();
                                return false;
                            }

                            boost::asio::spawn(
                                [self, this, established](const boost::asio::yield_context& y) noexcept
                                {
                                    if (!establish(y, established))
                                    {
                                        close();
                                    }
                                });

                            return true;
                        });
                });
            return true;
        }
        bool                                                            establish(const boost::asio::yield_context& y, const ppp::function<void(connection*)>& established) noexcept;
        bool                                                            update(uint32_t now) noexcept
        {
            std::shared_ptr<Byte> packet;
            if (next_ == 0)
            {
            next:
                int32_t rnd = RandomNext(1, std::min<int>(AGGLIGATOR_INACTIVE_TIMEOUT >> 1, std::max<int>(AGGLIGATOR_CONNECT_TIMEOUT, AGGLIGATOR_RECONNECT_TIMEOUT) << 2));
                next_ = now + (uint32_t)rnd;
            }
            elif(now >= next_)
            {
                std::shared_ptr<aggligator> aggligator = app_;
                if (!aggligator)
                {
                    return false;
                }

                packet = aggligator->make_shared_bytes(2);
                if (!packet)
                {
                    return false;
                }

                Byte* memory = packet.get();
                memory[0] = 0;
                memory[1] = 0;

                if (sending_)
                {
                    next_packet_ = packet;
                    goto next;
                }
                elif(sent(packet, 2))
                {
                    if (sending_)
                    {
                        goto next;
                    }
                }

                return false;
            }

            return true;
        }

        std::shared_ptr<aggligator>                                     app_;
        convergence_ptr                                                 convergence_;
        client_ptr                                                      client_;
        std::shared_ptr<boost::asio::ip::tcp::socket>                   socket_;
        bool                                                            sending_;
        uint32_t                                                        next_;
        std::shared_ptr<Byte>                                           next_packet_;
#if defined(_WIN32)
        std::shared_ptr<QoSS>                                           qoss_;
#endif
        Byte                                                            buffer_[UINT16_MAX]; /* MAX:65507 */
    };

    aggligator::aggligator(boost::asio::io_context& context, const std::shared_ptr<Byte>& buffer, int buffer_size, int congestions) noexcept
        : context_(context)
        , buffer_(buffer)
        , buffer_size_(buffer_size)
        , congestions_(congestions)
        , server_mode_(false)
        , last_(0)
        , now_(ppp::threading::Executors::GetTickCount())
        , rx_(0)
        , tx_(0)
        , rx_pps_(0)
        , tx_pps_(0)
    {
        if (NULL == buffer)
        {
            buffer_size = 0;
        }
        elif(buffer_size < 1)
        {
            buffer_ = NULL;
            buffer_size = 0;
        }
    }

    aggligator::~aggligator() noexcept
    {
        close();
    }

    void aggligator::close() noexcept
    {
        client_ptr client = std::move(client_);
        server_ptr server = std::move(server_);
        ppp::function<void()> exit = std::move(Exit);

        deadline_timer_cancel(reopen_);
        deadline_timer_cancel(timeout_);

        if (server)
        {
            server_.reset();
            server->close();
        }

        if (client)
        {
            client_.reset();
            client->close();
        }

        if (exit)
        {
            Exit = NULL;
            exit();
        }
    }

    void aggligator::update(uint64_t now) noexcept
    {
        uint32_t now_seconds = (uint32_t)(now / 1000);
        for (;;)
        {
            client_ptr pclient = client_;
            if (pclient && pclient->last_ != 0 && !pclient->update(now_seconds))
            {
                pclient->close();
            }

            break;
        }

        for (;;)
        {
            server_ptr pserver = server_;
            if (!pserver)
            {
                break;
            }

            list<client_ptr> releases;
            for (auto&& kv : pserver->clients_)
            {
                client_ptr& pclient = kv.second;
                if (pclient->last_ != 0 && !pclient->update(now_seconds))
                {
                    releases.emplace_back(pclient);
                }
            }

            for (client_ptr& pclient : releases)
            {
                pclient->close();
            }

            break;
        }
    }

    bool aggligator::create_timeout() noexcept
    {
        deadline_timer timeout_ptr = timeout_;
        if (timeout_ptr)
        {
            return true;
        }

        timeout_ptr = make_shared_object<boost::asio::deadline_timer>(context_);
        if (!timeout_ptr)
        {
            return false;
        }

        timeout_ = timeout_ptr;
        return nawait_timeout();
    }

    bool aggligator::nawait_timeout() noexcept
    {
        deadline_timer t = timeout_;
        if (t)
        {
            auto self = shared_from_this();
            t->expires_from_now(boost::posix_time::milliseconds(10));
            t->async_wait(
                [self, this](boost::system::error_code ec) noexcept
                {
                    if (ec == boost::system::errc::operation_canceled)
                    {
                        close();
                        return false;
                    }

                    uint64_t now = ppp::threading::Executors::GetTickCount();
                    uint32_t now_seconds = (uint32_t)(now / 1000);

                    now_ = now;
                    if (last_ != now_seconds)
                    {
                        last_ = now_seconds;
                        update(now);

                        ppp::function<void(uint64_t)> tick = Tick;
                        if (tick)
                        {
                            tick(now);
                        }
                    }

                    return nawait_timeout();
                });
            return true;
        }

        return false;
    }

    void aggligator::deadline_timer_cancel(deadline_timer& t) noexcept
    {
        deadline_timer p = std::move(t);
        t.reset();

        boost::system::error_code ec;
        if (p)
        {
            p->cancel(ec);
        }
    }

    void aggligator::socket_adjust(int sockfd, bool in4) noexcept
    {
        AppConfigurationPtr configuration = AppConfiguration;
        if (NULL != configuration)
        {
            auto& cfg = configuration->udp;
            Socket::SetWindowSizeIfNotZero(sockfd, cfg.cwnd, cfg.rwnd);
        }

        Socket::AdjustDefaultSocketOptional(sockfd, in4);
        Socket::SetTypeOfService(sockfd);
    }

    void aggligator::socket_close(boost::asio::ip::udp::socket& socket) noexcept
    {
        if (socket.is_open())
        {
            boost::system::error_code ec;
            socket.cancel(ec);
            socket.close(ec);
        }
    }

    void aggligator::socket_close(boost::asio::ip::tcp::socket& socket) noexcept
    {
        if (socket.is_open())
        {
            boost::system::error_code ec;
            socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
            socket.cancel(ec);
            socket.close(ec);
        }
    }

    bool aggligator::server_accept(const acceptor& acceptor) noexcept
    {
        bool opened = acceptor->is_open();
        if (!opened)
        {
            close();
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(context_);
        if (!socket)
        {
            close();
            return false;
        }

        auto self = shared_from_this();
        acceptor->async_accept(*socket, 
            [self, this, acceptor, socket](boost::system::error_code ec) noexcept
            {
                if (ec == boost::system::errc::operation_canceled)
                {
                    close();
                    return false;
                }
                elif(ec == boost::system::errc::success)
                {
                    YieldContext::Spawn(context_,
                        [self, this, socket](YieldContext& y) noexcept
                        {
                            socket_adjust(*socket);
                            if (!(socket->is_open() && server_accept(socket, y)))
                            {
                                socket_close(*socket);
                            }
                        });
                }

                if (server_accept(acceptor))
                {
                    return true;
                }
                else
                {
                    close();
                    return false;
                }
            });
        return true;
    }

    bool aggligator::server_accept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, YieldContext& y) noexcept
    {
        boost::system::error_code ec;
        server_ptr server = server_;
        if (!server)
        {
            return false;
        }

        deadline_timer timeout = make_shared_object<boost::asio::deadline_timer>(context_);
        if (!timeout)
        {
            return false;
        }
        else
        {
            timeout->expires_from_now(boost::posix_time::seconds(AGGLIGATOR_CONNECT_TIMEOUT));
            timeout->async_wait(
                [socket](boost::system::error_code ec) noexcept
                {
                    if (ec != boost::system::errc::operation_canceled)
                    {
                        socket_close(*socket);
                    }
                });
        }

        Byte data[128];
        uint16_t remote_port = 0;

        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 8), y))
        {
            return false;
        }
        else
        {
            rx_ += 8;
            uint32_t m = *(uint32_t*)data;
            *(uint32_t*)(data + 4) ^= m;
            uint16_t* pchecksum = (uint16_t*)(data + 6);
            uint16_t checksum = *pchecksum;

            *pchecksum = 0;
            remote_port = ntohs(*(uint16_t*)(data + 4));

            uint16_t chksum = inet_chksum(data, 8);
            if (chksum != checksum)
            {
                return false;
            }
        }

        connection_ptr pconnection;
        client_ptr pclient;
        convergence_ptr pconvergence;
        unordered_map<int, client_ptr>& clients = server->clients_;

        std::shared_ptr<aggligator> my = shared_from_this();
        if (remote_port == 0)
        {
            pclient = make_shared_object<client>(my);
            if (!pclient)
            {
                return false;
            }

            pconvergence = make_shared_object<convergence>(my, pclient);
            if (!pconvergence)
            {
                return false;
            }

            boost::asio::ip::udp::socket& socket_dgram = pclient->socket_;
            if (!ppp::coroutines::asio::async_open(y, socket_dgram, boost::asio::ip::udp::v6()))
            {
                return false;
            }
            else
            {
                socket_adjust(socket_dgram);
            }

            socket_dgram.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6::any(), 0), ec);
            if (ec)
            {
                return false;
            }

            boost::asio::ip::udp::endpoint local_endpoint = socket_dgram.local_endpoint(ec);
            if (ec)
            {
                return false;
            }

            remote_port = local_endpoint.port();
            pclient->server_mode_ = true;
            pclient->established_num_ = 1;
            pclient->connections_num_ = 1;
            pclient->remote_port_ = remote_port;
            pclient->convergence_ = pconvergence;

            pconnection = make_shared_object<connection>(my, pclient, pconvergence);
            if (!pconnection)
            {
                return false;
            }

            clients[remote_port] = pclient;
            pconnection->socket_ = socket;
            pclient->connections_.emplace_back(pconnection);

            if (!pclient->timeout())
            {
                return false;
            }
        }
        else
        {
            auto client_tail = clients.find(remote_port);
            auto client_endl = clients.end();
            if (client_tail == client_endl)
            {
                return false;
            }

            pclient = client_tail->second;
            if (!pclient)
            {
                clients.erase(client_tail);
                return false;
            }

            pconvergence = pclient->convergence_;
            if (!pconvergence)
            {
                return false;
            }

            pconnection = make_shared_object<connection>(my, pclient, pconvergence);
            if (!pconnection)
            {
                return false;
            }

            pconnection->socket_ = socket;
            pclient->established_num_++;
            pclient->connections_num_++;
            pclient->connections_.emplace_back(pconnection);
        }

#if defined(_WIN32)
        if (Socket::IsDefaultFlashTypeOfService())
        {
            pconnection->qoss_ = QoSS::New(socket->native_handle());
        }
#endif
        data[0] = (Byte)(remote_port >> 8);
        data[1] = (Byte)(remote_port);
        *(uint32_t*)(data + 2) = htonl(pconvergence->seq_no_);

        if (!ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(data, 6), y))
        {
            return false;
        }
        else
        {
            tx_ += 6;
        }

        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 8), y))
        {
            return false;
        }

        rx_ += 8;
        if (*data != 0)
        {
            return false;
        }

        uint32_t connections_num = ntohl(*(uint32_t*)data);
        if (++pclient->handshakeds_num_ < connections_num)
        {
            return true;
        }

        uint32_t ack = ntohl(*(uint32_t*)(data + 4)) + 1;
        pconvergence->ack_no_ = ack;

        pclient->last_ = (uint32_t)(now() / 1000);
        for (connection_ptr& connection : pclient->connections_)
        {
            if (!connection->recv())
            {
                return false;
            }
        }

        deadline_timer_cancel(timeout);
        deadline_timer_cancel(pclient->timeout_);
        return pclient->loopback();
    }

    bool aggligator::server_open(const unordered_set<int>& bind_ports, const boost::asio::ip::address& destination_ip, int destination_port) noexcept
    {
        if (bind_ports.empty())
        {
            return false;
        }
        
        if (server_ || client_) 
        {
            return false;
        }

        server_ptr server = make_shared_object<aggligator::server>();
        if (NULL == server)
        {
            return false;
        }

        if (destination_port <= 0 || destination_port > UINT16_MAX)
        {
            return false;
        }

        if (ip_is_invalid(destination_ip))
        {
            return false;
        }

        bool any = false;
        for (int bind_port : bind_ports)
        {
            if (bind_port <= 0 || bind_port > UINT16_MAX)
            {
                continue;
            }
            else
            {
                auto tail = server->acceptors_.find(bind_port);
                auto endl = server->acceptors_.end();
                if (tail != endl)
                {
                    continue;
                }
            }

            auto acceptor = make_shared_object<boost::asio::ip::tcp::acceptor>(context_);
            if (NULL == acceptor)
            {
                break;
            }

            boost::system::error_code ec;
            acceptor->open(boost::asio::ip::tcp::v6(), ec);
            if (ec)
            {
                continue;
            }
            else
            {
                socket_adjust(*acceptor);
            }

            acceptor->bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::any(), bind_port), ec);
            if (ec && bind_port != 0)
            {
                acceptor->bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::any(), 0), ec);
                if (ec)
                {
                    continue;
                }
            }

            acceptor->listen(UINT16_MAX, ec);
            if (ec)
            {
                continue;
            }

            if (server_accept(acceptor))
            {
                any |= true;
                server->acceptors_[bind_port] = acceptor;
            }
        }

        server->server_endpoint_ = boost::asio::ip::udp::endpoint(destination_ip, destination_port);
        server->server_endpoint_ = ip_v4_to_v6(server->server_endpoint_);
        if (any)
        {
            server_ = server;
            server_mode_ = true;
        }

        return any && create_timeout();
    }

    bool aggligator::client_open(
        int                                                                 connections,
        const unordered_set<boost::asio::ip::tcp::endpoint>&                servers) noexcept
    {
        if (servers.empty())
        {
            return false;
        }

        if (connections < 1)
        {
            connections = 1;
        }

        if (server_ || client_)
        {
            return false;
        }

        unordered_set<boost::asio::ip::tcp::endpoint> connect_servers;
        for (const boost::asio::ip::tcp::endpoint& ep : servers)
        {
            int server_port = ep.port();
            if (server_port <= 0 || server_port > UINT16_MAX)
            {
                continue;
            }

            boost::asio::ip::address server_ip = ep.address();
            if (ip_is_invalid(server_ip))
            {
                continue;
            }

            connect_servers.emplace(ep);
        }

        if (connect_servers.empty())
        {
            return false;
        }

        client_ptr pclient = make_shared_object<client>(shared_from_this());
        if (!pclient)
        {
            return false;
        }

        client_ = pclient;
        server_mode_ = false;
        return create_timeout() && pclient->open(connections, connect_servers);
    }

    bool aggligator::ip_is_invalid(const boost::asio::ip::address& address) noexcept
    {
        if (address.is_v4())
        {
            boost::asio::ip::address_v4 in = address.to_v4();
            if (in.is_multicast() || in.is_unspecified())
            {
                return true;
            }

            uint32_t ip = htonl(in.to_uint());
            return ip == INADDR_ANY || ip == INADDR_NONE;
        }
        elif(address.is_v6())
        {
            boost::asio::ip::address_v6 in = address.to_v6();
            if (in.is_multicast() || in.is_unspecified())
            {
                return true;
            }

            return false;
        }
        else
        {
            return true;
        }
    }

    bool aggligator::server_closed(client* client) noexcept
    {
        if (client->server_mode_)
        {
            server_ptr server = server_;
            if (server)
            {
                auto& clients = server->clients_;
                auto tail = clients.find(client->remote_port_);
                auto endl = clients.end();
                if (tail != endl)
                {
                    client_ptr p = std::move(tail->second);
                    clients.erase(tail);

                    if (p)
                    {
                        p->close();
                    }
                }
            }
        }

        return false;
    }

    void aggligator::client_fetch_concurrency(int& servers, int& channels) noexcept
    {
        servers = 0;
        channels = 0;

        client_ptr client = client_;
        if (NULL != client && !client->server_mode_) 
        {
            servers = (int)client->server_endpoints_.size();
            if (servers > 0) 
            {
                channels = (int)client->connections_num_ / servers;
            }
        }
    }

    bool aggligator::client_reopen(client* client) noexcept
    {
        if (client->server_mode_ || client != client_.get())
        {
            return false;
        }

        client_ptr pclient = std::move(client_);
        client_.reset();

        if (pclient)
        {
            pclient->close();
        }
        else
        {
            close();
            return false;
        }

        deadline_timer t = make_shared_object<boost::asio::deadline_timer>(context_);
        if (!t)
        {
            close();
            return false;
        }

        unordered_set<boost::asio::ip::tcp::endpoint> servers = pclient->server_endpoints_;
        uint32_t connections = pclient->connections_num_ / servers.size();
        int bind_port = pclient->local_port_;

        auto self = shared_from_this();
        t->expires_from_now(boost::posix_time::seconds(AGGLIGATOR_RECONNECT_TIMEOUT));
        t->async_wait(
            [self, this, connections, bind_port, servers](boost::system::error_code ec) noexcept
            {
                deadline_timer_cancel(reopen_);
                if (ec == boost::system::errc::operation_canceled)
                {
                    close();
                    return false;
                }
                elif(ec)
                {
                    close();
                    return false;
                }

                bool opened = client_open(connections, servers);
                if (!opened)
                {
                    close();
                    return false;
                }

                return true;
            });

        reopen_ = t;
        return true;
    }

    std::shared_ptr<Byte> aggligator::make_shared_bytes(int length) noexcept
    {
        if (length > 0)
        {
            BufferswapAllocatorPtr allocator = BufferswapAllocator;
            return ppp::threading::BufferswapAllocator::MakeByteArray(allocator, length);
        }
        else 
        {
            return NULL;
        }
    }

    bool aggligator::client::update(uint32_t now_seconds) noexcept
    {
        if (now_seconds >= (last_ + AGGLIGATOR_INACTIVE_TIMEOUT))
        {
            return false;
        }

        std::shared_ptr<aggligator> aggligator = app_;
        if (!aggligator)
        {
            return false;
        }

        std::shared_ptr<convergence> pconvergence = convergence_;
        if (!pconvergence)
        {
            return false;
        }

        int rq_congestions = (int)pconvergence->recv_queue_.size();
        if (rq_congestions >= aggligator->congestions_)
        {
            return false;
        }

        for (connection_ptr& connection : connections_)
        {
            if (!connection->update(now_seconds))
            {
                return false;
            }
        }

        return true;
    }

    void aggligator::client::close() noexcept
    {
        std::shared_ptr<aggligator> aggligator = std::move(app_);
        app_.reset();

        convergence_ptr convergence = std::move(convergence_);
        convergence_.reset();

        if (convergence)
        {
            convergence->close();
        }

        list<connection_ptr> connections = std::move(connections_);
        connections_.clear();

        for (connection_ptr& connection : connections)
        {
            connection->close();
        }

        deadline_timer_cancel(timeout_);
        aggligator::socket_close(socket_);

        if (aggligator)
        {
            aggligator->server_closed(this);
            aggligator->client_reopen(this);
        }
    }

    bool aggligator::client::send(Byte* packet, int packet_length) noexcept
    {
        if (NULL == packet || packet_length < 1)
        {
            return false;
        }

        convergence_ptr convergence = convergence_;
        if (NULL == convergence)
        {
            return false;
        }

        auto tail = connections_.begin();
        auto endl = connections_.end();
        if (tail == endl)
        {
            return false;
        }

        int message_length;
        uint32_t seq = ++convergence->seq_no_;

        std::shared_ptr<Byte> message = convergence->pack(packet, packet_length, seq, message_length);
        if (NULL == message || message_length < 1)
        {
            return false;
        }

        queue<send_packet>& send_queue = convergence->send_queue_;
        send_queue.emplace_back(send_packet{ message, message_length });

        for (;;)
        {
            auto sqt = send_queue.begin();
            if (sqt == send_queue.end())
            {
                return true;
            }

            connection_ptr connection;
            for (; tail != endl; tail++)
            {
                connection_ptr& i = *tail;
                if (!i->sending_)
                {
                    connection = i;
                    break;
                }
            }

            if (connection)
            {
                send_packet messages = *sqt;
                send_queue.erase(sqt);

                bool ok = connection->sent(messages.packet, messages.length);
                if (ok)
                {
                    if (connection->sending_ && connections_num_ > 1)
                    {
                        connections_.erase(tail);
                        connections_.emplace_back(connection);
                    }

                    return true;
                }

                return false;
            }
            else
            {
                return true;
            }
        }
    }

    bool aggligator::client::timeout() noexcept
    {
        ptr aggligator = app_;
        if (!aggligator)
        {
            close();
            return false;
        }

        deadline_timer timeout = make_shared_object<boost::asio::deadline_timer>(aggligator->context_);
        if (!timeout)
        {
            close();
            return false;
        }

        auto self = shared_from_this();
        timeout->expires_from_now(boost::posix_time::seconds(AGGLIGATOR_CONNECT_TIMEOUT));
        timeout->async_wait(
            [self, this](boost::system::error_code ec) noexcept
            {
                if (ec == boost::system::errc::operation_canceled)
                {
                    return false;
                }
                else
                {
                    close();
                    return true;
                }
            });

        timeout_ = timeout;
        return true;
    }

    bool aggligator::client::loopback() noexcept
    {
        ptr aggligator = app_;
        if (!aggligator)
        {
            close();
            return false;
        }

        std::shared_ptr<Byte> buffer = aggligator->buffer_;
        if (!buffer)
        {
            close();
            return false;
        }

        boost::system::error_code ec;
        if (!socket_.is_open())
        {
            socket_.open(boost::asio::ip::udp::v6(), ec);
            if (ec)
            {
                close();
                return false;
            }
            else
            {
                aggligator->socket_adjust(socket_);
            }

            socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6::any(), local_port_), ec);
            if (ec)
            {
                close();
                return false;
            }

            if (local_port_ == 0)
            {
                boost::asio::ip::udp::endpoint localEP = socket_.local_endpoint(ec);
                local_port_ = localEP.port();
            }
        }

        auto self = shared_from_this();
        socket_.async_receive_from(boost::asio::buffer(buffer.get(), aggligator->buffer_size_), source_endpoint_,
            [self, this](boost::system::error_code ec, std::size_t sz) noexcept
            {
                ptr aggligator = app_;
                if (!aggligator)
                {
                    close();
                    return false;
                }

                int bytes_transferred = static_cast<int>(sz);
                if (bytes_transferred > 0 && ec == boost::system::errc::success)
                {
                    std::shared_ptr<Byte> buffer = aggligator->buffer_;
                    if (!buffer)
                    {
                        close();
                        return false;
                    }

                    bool bok = send(buffer.get(), bytes_transferred);
                    if (!bok)
                    {
                        close();
                        return false;
                    }
                }

                return loopback();
            });
        return true;
    }

    bool aggligator::client::open(int connections, unordered_set<boost::asio::ip::tcp::endpoint>& servers) noexcept
    {
        using tcp_endpoint_list = list<boost::asio::ip::tcp::endpoint>;

        std::shared_ptr<aggligator> aggligator = app_;
        if (NULL == aggligator)
        {
            return false;
        }

        std::shared_ptr<tcp_endpoint_list> list = make_shared_object<tcp_endpoint_list>();
        if (NULL == list)
        {
            return false;
        }

        client_ptr self = shared_from_this();
        convergence_ptr pconvergence = make_shared_object<convergence>(aggligator, self);
        if (NULL == pconvergence)
        {
            return false;
        }

        convergence_ = pconvergence;
        server_mode_ = false;
        local_port_ = 0;
        server_endpoints_ = servers;

        auto connect_to_server = 
            [self, this, aggligator, pconvergence](const boost::asio::ip::tcp::endpoint& server, const ppp::function<void(connection*)>& established) noexcept
            {
                connection_ptr pconnection = make_shared_object<connection>(aggligator, self, pconvergence);
                if (!pconnection)
                {
                    return false;
                }

                YieldContext::Spawn(aggligator->context_,
                    [self, this, pconnection, server, established](YieldContext& y) noexcept 
                    {
                        bool ok = pconnection->open(y, server, established);
                        if (ok)
                        {
                            connections_.emplace_back(pconnection);
                        }
                    });
                return true;
            };

        for (int i = 0; i < connections; i++)
        {
            for (const boost::asio::ip::tcp::endpoint& server : servers)
            {
                connections_num_++;
                list->emplace_back(server);
            }
        }

        boost::asio::ip::tcp::endpoint master_node = list->front();
        list->pop_front();
        if (list->begin() == list->end())
        {
            list.reset();
        }

        return timeout() && connect_to_server(master_node,
            [this, list, connect_to_server](connection* connection) noexcept
            {
                if (NULL == list)
                {
                    return false;
                }

                bool any = false;
                for (const boost::asio::ip::tcp::endpoint& server : *list)
                {
                    any |= connect_to_server(server, NULL);
                }

                return any;
            });
    }

    std::shared_ptr<Byte> aggligator::convergence::pack(Byte* packet, int packet_length, uint32_t seq, int& out) noexcept
    {
        out = 0;
        if (NULL == packet || packet_length < 1)
        {
            return NULL;
        }

        int message_length = 4 + packet_length;
        int final_length = 2 + message_length;

        std::shared_ptr<aggligator> aggligator = app_;
        if (NULL == aggligator)
        {
            return NULL;
        }

        std::shared_ptr<Byte> message = aggligator->make_shared_bytes(final_length);
        if (NULL == message)
        {
            return NULL;
        }

        Byte* stream = message.get();
        *stream++ = (Byte)(message_length >> 8);
        *stream++ = (Byte)(message_length);

        *stream++ = (Byte)(seq >> 24);
        *stream++ = (Byte)(seq >> 16);
        *stream++ = (Byte)(seq >> 8);
        *stream++ = (Byte)(seq);

        out = final_length;
        memcpy(stream, packet, packet_length);
        return message;
    }

    bool aggligator::convergence::input(Byte* packet, int packet_length) noexcept
    {
        if (NULL == packet || packet_length < 4)
        {
            return false;
        }

        std::shared_ptr<aggligator> aggligator = app_;
        if (NULL == aggligator)
        {
            return false;
        }

        uint32_t seq = htonl(*(uint32_t*)packet);
        packet += 4;
        packet_length -= 4;

        int max_congestions = aggligator->congestions_;
        if (max_congestions < 1)
        {
            if (output(packet, packet_length))
            {
                ack_no_++;
                return true;
            }
            else
            {
                return false;
            }
        }
        else
        {
            if (seq < ack_no_)
            {
                bool wraparound = before(ack_no_, seq);
                if (!wraparound)
                {
                    return true;
                }
            }

            int rq_congestions = (int)recv_queue_.size();
            if (rq_congestions >= max_congestions)
            {
                return false;
            }
        }

        if (ack_no_ == seq)
        {
            if (output(packet, packet_length))
            {
                ack_no_++;
            }
            else
            {
                return false;
            }

            auto tail = recv_queue_.begin();
            auto endl = recv_queue_.end();
            while (tail != endl)
            {
                if (ack_no_ != tail->first)
                {
                    break;
                }
                else
                {
                    recv_packet& pr = tail->second;
                    if (output(pr.packet.get(), pr.length))
                    {
                        ack_no_++;
                    }
                    else
                    {
                        return false;
                    }
                }

                tail = recv_queue_.erase(tail);
            }

            return true;
        }

        recv_packet r;
        r.seq = seq;
        r.length = packet_length;
        r.packet = aggligator->make_shared_bytes(packet_length);
        if (r.packet)
        {
            memcpy(r.packet.get(), packet, packet_length);
            return recv_queue_.emplace(std::make_pair(seq, r)).second;
        }
        else
        {
            return false;
        }
    }

    void aggligator::convergence::close() noexcept
    {
        std::shared_ptr<client> client = std::move(client_);
        client_.reset();

        std::shared_ptr<aggligator> aggligator = std::move(app_);
        app_.reset();

        send_queue_.clear();
        recv_queue_.clear();

        if (client)
        {
            client->close();
        }
    }

    bool aggligator::convergence::output(Byte* packet, int packet_length) noexcept
    {
        std::shared_ptr<aggligator> aggligator = app_;
        if (!aggligator)
        {
            return false;
        }

        std::shared_ptr<client> client = client_;
        if (!client)
        {
            return false;
        }

        boost::asio::ip::udp::socket& socket = client->socket_;
        if (!socket.is_open())
        {
            return false;
        }

        boost::system::error_code ec;
        if (client->server_mode_)
        {
            server_ptr server = aggligator->server_;
            if (!server)
            {
                return false;
            }

            socket.send_to(boost::asio::buffer(packet, packet_length), server->server_endpoint_, boost::asio::socket_base::message_end_of_record, ec);
        }
        else
        {
            socket.send_to(boost::asio::buffer(packet, packet_length), client->source_endpoint_, boost::asio::socket_base::message_end_of_record, ec);
        }

        return true;
    }

    bool aggligator::socket_adjust(boost::asio::ip::udp::socket& socket) noexcept
    {
        if (aggligator_socket_adjust(socket))
        {
            boost::system::error_code ec;
            socket.set_option(boost::asio::ip::udp::socket::reuse_address(true), ec);
            return true;
        }

        return false;
    }

    bool aggligator::socket_adjust(boost::asio::ip::tcp::socket& socket) noexcept
    {
        return aggligator_tcp_socket_adjust(socket);
    }

    bool aggligator::socket_adjust(boost::asio::ip::tcp::acceptor& socket) noexcept
    {
        return aggligator_tcp_socket_adjust(socket);
    }

    boost::asio::ip::udp::endpoint aggligator::client_endpoint(const boost::asio::ip::address& interface_ip) noexcept
    {
        client_ptr client = client_;
        if (client)
        {
            return boost::asio::ip::udp::endpoint(interface_ip, client->local_port_);
        }
        else
        {
            return boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6::loopback(), 0);
        }
    }

    bool aggligator::info(information& i) noexcept
    {
        i.server_endpoints.clear();
        i.bind_ports.clear();
        i.client_count = 0;
        i.connection_count = 0;
        i.establish_count = 0;
        i.rx = rx_;
        i.tx = tx_;
        i.rx_pps = rx_pps_;
        i.tx_pps = tx_pps_;

        server_ptr server = server_;
        client_ptr client = client_;
        if (server)
        {
            i.client_count = server->clients_.size();
            for (auto&& kv : server->acceptors_)
            {
                i.bind_ports.emplace(kv.first);
            }

            for (auto&& kv : server->clients_)
            {
                client_ptr& pclient = kv.second;
                i.establish_count += pclient->established_num_;
                i.connection_count += pclient->connections_num_;
            }
        }
        elif(client)
        {
            boost::asio::ip::udp::socket& dgram_socket = client->socket_;
            if (dgram_socket.is_open())
            {
                i.bind_ports.emplace(client->local_port_);
            }

            i.client_count = 1;
            i.connection_count = client->connections_num_;
            i.establish_count = client->established_num_;
            i.server_endpoints = client->server_endpoints_;
        }
        
        return true;
    }

    boost::asio::ip::udp::endpoint aggligator::ip_v6_to_v4(const boost::asio::ip::udp::endpoint& ep) noexcept
    {
        return Ipep::V6ToV4(ep);
    }

    boost::asio::ip::udp::endpoint aggligator::ip_v4_to_v6(const boost::asio::ip::udp::endpoint& ep) noexcept
    {
        return Ipep::V4ToV6(ep);
    }

    boost::asio::ip::tcp::endpoint aggligator::ip_v6_to_v4(const boost::asio::ip::tcp::endpoint& ep) noexcept
    {
        auto r = ip_v6_to_v4(boost::asio::ip::udp::endpoint(ep.address(), ep.port()));
        return boost::asio::ip::tcp::endpoint(r.address(), r.port());
    }

    boost::asio::ip::tcp::endpoint aggligator::ip_v4_to_v6(const boost::asio::ip::tcp::endpoint& ep) noexcept
    {
        auto r = ip_v4_to_v6(boost::asio::ip::udp::endpoint(ep.address(), ep.port()));
        return boost::asio::ip::tcp::endpoint(r.address(), r.port());
    }

    aggligator::link_status aggligator::status(information& i) noexcept
    {
        if (server_mode())
        {
            return link_status_none;
        }

        if (i.bind_ports.empty())
        {
            return i.client_count > 0 ? link_status_connecting : link_status_reconnecting;
        }
        
        if (i.establish_count < i.connection_count)
        {
            return link_status_connecting;
        }
        else 
        {
            return link_status_established;
        }
    }

    aggligator::link_status aggligator::status() noexcept
    {
        information i;
        if (info(i))
        {
            return status(i);
        }

        return link_status_unknown;
    }

    bool aggligator::connection::establish(const boost::asio::yield_context& y, const ppp::function<void(connection*)>& established) noexcept
    {
        std::shared_ptr<aggligator> aggligator = app_;
        if (!aggligator)
        {
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
        if (!socket)
        {
            return false;
        }

        if (!socket->is_open())
        {
            return false;
        }

        std::shared_ptr<client> client = aggligator->client_;
        if (!client)
        {
            return false;
        }

        Byte data[128];
        std::shared_ptr<convergence> convergence = client->convergence_;
        if (!convergence)
        {
            return false;
        }
        else
        {
            Byte* p = data;
            uint32_t m = (uint32_t)RandomNext(1, INT32_MAX);
            *(uint32_t*)p = m;
            p += 4;

            uint16_t remote_port = 0;
            if (client->established_num_ != 0)
            {
                remote_port = client->remote_port_;
            }

            *(uint16_t*)p = htons(remote_port);
            p += 2;

            *(uint16_t*)p = 0;
            *(uint16_t*)p = inet_chksum(data, 8);
            *(uint32_t*)(data + 4) ^= m;
        }

        boost::system::error_code ec;
        boost::asio::async_write(*socket, boost::asio::buffer(data, 8), y[ec]);
        if (ec)
        {
            return false;
        }
        else
        {
            aggligator->tx_ += 8;
        }

        boost::asio::async_read(*socket, boost::asio::buffer(data, 6), y[ec]);
        if (ec)
        {
            return false;
        }
        else
        {
            aggligator->rx_ += 6;
        }

        uint16_t remote_port = (uint16_t)(data[0] << 8 | data[1]);
        if (remote_port < 1)
        {
            return false;
        }

        uint32_t ack = ntohl(*(uint32_t*)(data + 2)) + 1;
        if (client->established_num_ == 0)
        {
            convergence->ack_no_ = ack;
        }
        elif(convergence->ack_no_ != ack)
        {
            return false;
        }

        client->remote_port_ = remote_port;
        client->established_num_++;
        if (established)
        {
            established(this);
        }

        if (client->established_num_ < client->connections_num_)
        {
            return true;
        }

        *(uint32_t*)data = htonl(client->connections_num_);
        *(uint32_t*)(data + 4) = htonl(convergence->seq_no_);

        for (connection_ptr& connection : client->connections_)
        {
            std::shared_ptr<boost::asio::ip::tcp::socket> connection_socket = connection->socket_;
            if (NULL == connection_socket)
            {
                return false;
            }

            if (!connection_socket->is_open())
            {
                return false;
            }

            boost::asio::async_write(*connection_socket, boost::asio::buffer(data, 8), y[ec]);
            if (ec)
            {
                return false;
            }

            aggligator->tx_ += 8;
        }

        client->last_ = (uint32_t)(aggligator->now() / 1000);
        for (connection_ptr& connection : client->connections_)
        {
            if (!connection->recv())
            {
                return false;
            }
        }

        std::shared_ptr<connection> self = shared_from_this();
        deadline_timer_cancel(client->timeout_);

        boost::asio::io_context& context = aggligator->context_;
        boost::asio::post(context, 
            [self, this, aggligator, client]() noexcept
            {
                bool ok = client->loopback();
                if (!ok)
                {
                    close();
                }
            });
        return true;
    }
}