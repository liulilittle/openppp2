#include <common/aggligator/aggligator.h>                                   // Include corresponding header

#include <ppp/net/native/checksum.h>                                        // Internet checksum computation
#include <ppp/net/Socket.h>                                                 // Socket helper functions
#include <ppp/coroutines/asio/asio.h>                                       // ASIO coroutine wrappers
#include <ppp/threading/Executors.h>                                        // GetTickCount and threading utilities

#if defined(_WIN32)                                                         // Windows-specific code for QoS
#define IPTOS_TOS_MASK      0x1E                                            // TOS field mask
#define IPTOS_TOS(tos)      ((tos) & IPTOS_TOS_MASK)                        // Extract TOS
#define IPTOS_LOWDELAY      0x10                                            // Low delay TOS
#define IPTOS_THROUGHPUT    0x08                                            // Throughput TOS
#define IPTOS_RELIABILITY   0x04                                            // Reliability TOS
#define IPTOS_MINCOST       0x02                                            // Minimum cost TOS

#include <windows/ppp/net/QoSS.h>                                           // Windows QoS helper

using ppp::net::QoSS;                                                       // Alias for QoS
#endif

using namespace ppp;                                                        // Use ppp namespace
using namespace ppp::coroutines;                                            // Use coroutine namespace
using namespace ppp::net;                                                   // Use network namespace
using namespace ppp::net::native;                                           // Use native network helpers

namespace aggligator
{
    // Helper functions for 32-bit sequence number comparison (handles wrap-around)
    // Returns true if seq1 is strictly before seq2 in modulo 2^32 space.
    static inline bool before(uint32_t seq1, uint32_t seq2) noexcept
    {
        return (int32_t)(seq1 - seq2) < 0;                                  // Cast to signed to detect wrap
    }

    // Returns true if seq2 is after seq1 (same as before(seq1, seq2))
    static inline bool after(uint32_t seq2, uint32_t seq1) noexcept
    {
        return before(seq1, seq2);
    }

    //----------------------------------------------------------------------------
    // Server class implementation
    //----------------------------------------------------------------------------
    class aggligator::server
    {
    public:
        ~server() noexcept                                                   // Destructor
        {
            close();                                                        // Clean up all acceptors
        }

        void                            close() noexcept                     // Close all TCP acceptors
        {
            for (auto&& kv : acceptors_)                                    // Iterate over all bound ports
            {
                acceptor& acceptor = kv.second;                             // Get the acceptor shared_ptr
                boost::system::error_code ec;                               // Ignored error code
                acceptor->cancel();                                         // Cancel pending async_accept
                acceptor->close(ec);                                        // Close the acceptor socket
            }

            acceptors_.clear();                                             // Remove all entries
        }

        boost::asio::ip::udp::endpoint  server_endpoint_;                    // Destination UDP endpoint (where to send decapsulated packets)
        unordered_map<int, acceptor>    acceptors_;                          // Port -> TCP acceptor
        unordered_map<int, client_ptr>  clients_;                            // Remote port -> client instance (for multiplexing)
    };

    //----------------------------------------------------------------------------
    // Client class implementation
    //----------------------------------------------------------------------------
    class aggligator::client : public std::enable_shared_from_this<client>
    {
    public:
        client(const std::shared_ptr<aggligator>& aggligator) noexcept      // Constructor
            : socket_(aggligator->context_)                                 // UDP socket associated with same io_context
            , app_(aggligator)                                              // Keep reference to parent aggregator
            , server_mode_(false)                                           // Initially not server mode
            , local_port_(0)                                                // Local UDP port (to be determined)
            , remote_port_(0)                                               // Remote TCP port used as client identifier
            , established_num_(0)                                           // Number of TCP connections that completed handshake
            , connections_num_(0)                                           // Total number of TCP connections we expect
            , handshakeds_num_(0)                                           // Number of connections that have sent handshake complete
            , last_(0)                                                      // Last activity timestamp (seconds)
        {

        }

        ~client() noexcept                                                  // Destructor
        {
            close();                                                        // Release all resources
        }

        void                                            close() noexcept;                                              // Close client (declared)
        bool                                            send(Byte* packet, int packet_length) noexcept;                // Send UDP packet through aggregator
        bool                                            open(int connections, unordered_set<boost::asio::ip::tcp::endpoint>& servers) noexcept; // Establish TCP connections
        bool                                            loopback() noexcept;                                           // Start receiving UDP packets from external source
        bool                                            timeout() noexcept;                                            // Start connection timeout timer
        bool                                            update(uint32_t now_seconds) noexcept;                         // Update idle timeout and heartbeats
            
        boost::asio::ip::udp::endpoint                  source_endpoint_;   // Source endpoint of last received UDP packet (for reply)
        boost::asio::ip::udp::socket                    socket_;            // UDP socket for external communication
        std::shared_ptr<aggligator>                     app_;               // Parent aggregator
        std::shared_ptr<convergence>                    convergence_;        // Convergence layer (sequencing, queueing)
        deadline_timer                                  timeout_;           // Timer for initial connection timeout
        unordered_set<boost::asio::ip::tcp::endpoint>   server_endpoints_;   // List of remote TCP servers we connect to

        list<connection_ptr>                            connections_;           // All TCP connections belonging to this client
        bool                                            server_mode_ = false;   // True if this client was created by server (i.e., incoming)
        int                                             local_port_ = 0;        // Local UDP port (bound or automatically assigned)
        uint16_t                                        remote_port_ = 0;       // Remote TCP port (used as key in server mode)
        uint32_t                                        established_num_ = 0;   // Counter of fully established TCP connections
        uint32_t                                        connections_num_ = 0;   // Target total number of TCP connections
        uint32_t                                        handshakeds_num_ = 0;   // Number of connections that have completed handshake (server side)
        uint32_t                                        last_ = 0;              // Last activity timestamp (seconds since epoch)
    };

    //----------------------------------------------------------------------------
    // Convergence class implementation (sequencing, retransmission, reassembly)
    //----------------------------------------------------------------------------
    class aggligator::convergence
    {
    public:
        struct recv_packet                                                  // Received packet waiting for ordering
        {
            uint32_t                        seq = 0;                        // Sequence number of this packet
            int                             length = 0;                     // Length of data (after sequence header)
            std::shared_ptr<Byte>           packet;                         // Data buffer (without length/seq headers)
            boost::asio::ip::udp::endpoint  dst;                            // Destination endpoint (unused, kept for compatibility)
        };

        // Comparison functor for maps that respects 32-bit wrap-around using before()
        template <typename _Tp>
        struct packet_less
        {
            constexpr bool operator()(const _Tp& __x, const _Tp& __y) const noexcept
            {
                return before(__x, __y);                                    // Use before() for correct ordering
            }
        };

        // Send queue: sorted by sequence number (seq) using red-black tree. Key = seq, Value = send_packet
        map_pr<uint32_t, send_packet, packet_less<uint32_t>> send_queue_;   // Packets ready to be sent over TCP
        // Receive queue: sorted by sequence number for out-of-order reassembly
        map_pr<uint32_t, recv_packet, packet_less<uint32_t>> recv_queue_;   // Out-of-order packets waiting for missing predecessors
        uint32_t                                             seq_no_ = 0;   // Next sequence number to use for outgoing packets
        uint32_t                                             ack_no_ = 1;   // Next expected sequence number from remote side
        std::shared_ptr<client>                              client_;       // Client that owns this convergence
        std::shared_ptr<aggligator>                          app_;          // Parent aggregator

        convergence(const std::shared_ptr<aggligator>& aggligator, const std::shared_ptr<client>& client) noexcept
            : client_(client)                                               // Store client reference (may be weak later)
            , app_(aggligator)                                              // Store aggregator reference
        {
            seq_no_ = (uint32_t)RandomNext(UINT16_MAX, INT32_MAX);          // Random initial sequence number
            ack_no_ = 0;                                                    // No packet acknowledged yet
        }

        ~convergence() noexcept                                             // Destructor
        {
            close();                                                        // Clean up
        }

        void                                                close() noexcept;                                              // Close convergence (clear queues)
        std::shared_ptr<Byte>                               pack(Byte* packet, int packet_length, uint32_t seq, int& out) noexcept; // Add length+seq headers
        bool                                                input(Byte* packet, int packet_length, const std::shared_ptr<Byte>& owner = NULLPTR) noexcept;               // Process received TCP data (reassembly)
        bool                                                output(Byte* packet, int packet_length) noexcept;              // Send decapsulated UDP packet to external destination
    };

    //----------------------------------------------------------------------------
    // Connection class implementation (per-TCP stream)
    //----------------------------------------------------------------------------
    class aggligator::connection : public std::enable_shared_from_this<connection>
    {
    public:
        connection(const std::shared_ptr<aggligator>& aggligator, const client_ptr& client, const convergence_ptr& convergence) noexcept
            : app_(aggligator)                                              // Keep aggregator reference
            , convergence_(convergence)                                     // Keep convergence reference
            , client_(client)                                               // Keep client reference
            , sending_(false)                                               // No ongoing async_write
            , next_(0)                                                      // Next heartbeat time (seconds)
        {
            buffer_ = aggligator->make_shared_bytes(UINT16_MAX);            // Allocate per-connection receive buffer
        }

        ~connection() noexcept                                              // Destructor
        {
            close();                                                        // Release all resources
        }

        void close() noexcept                                               // Close TCP connection and cleanup
        {
#if defined(_WIN32)                                                         // Windows QoS cleanup
            qoss_.reset();
#endif

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::move(socket_); // Take ownership
            if (socket)                                                     // If socket exists, close it properly
            {
                aggligator::socket_close(*socket);
            }

            std::shared_ptr<aggligator> aggligator = std::move(app_);       // Release aggregator reference
            convergence_ptr convergence = std::move(convergence_);          // Release convergence reference

            next_packet_.reset();                                           // Discard pending heartbeat packet
            if (convergence)                                                // Convergence may still be referenced elsewhere
            {
                convergence->close();                                       // It will close its queues but may not delete itself
            }

            client_ptr client = std::move(client_);                         // Release client reference
            if (client)                                                     // If client exists, close it (may trigger reconnection)
            {
                client->close();
            }
        }

        // Asynchronously send a packet over this TCP connection
        bool sent(const std::shared_ptr<Byte>& packet, int length) noexcept
        {
            ptr aggligator = app_;                                          // Get aggregator (may be expired)
            if (!aggligator)                                                // Already closed
            {
                return false;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_; // Get TCP socket
            if (!socket)                                                    // No socket
            {
                return false;
            }

            bool opened = socket->is_open();                                // Check if still open
            if (!opened)                                                    // Closed
            {
                return false;
            }

            auto self = shared_from_this();                                 // Keep connection alive during async operation
            boost::asio::async_write(*socket, boost::asio::buffer(packet.get(), length), // Start async write
                [self, this, packet, length](boost::system::error_code ec, std::size_t sz) noexcept
                {
                    bool processed = false;                                 // Whether we should continue sending
                    sending_ = false;                                       // Write finished, clear flag

                    if (ec == boost::system::errc::success)                 // Write succeeded
                    {
                        ptr aggligator = app_;                              // Check aggregator again
                        if (aggligator)                                     // Still alive
                        {
                            aggligator->tx_ += sz;                          // Update statistics
                            aggligator->tx_pps_++;
                            processed = next();                             // Try to send next packet from queue
                        }
                    }

                    if (!processed)                                         // If no more packets or error, close connection
                    {
                        close();
                    }
                });

            sending_ = true;                                                // Mark as busy
            return true;
        }

        // Called after a write completes to fetch next packet from convergence send queue
        bool next() noexcept
        {
            convergence_ptr convergence = convergence_;                     // Get convergence
            if (!convergence)                                               // No convergence -> cannot proceed
            {
                return false;
            }
            else                                                            // Convergence exists
            {
                std::shared_ptr<Byte> next_packet = std::move(next_packet_); // Check if we have a pending heartbeat
                if (next_packet)                                            // Yes, send it now
                {
                    return sent(next_packet, 2);
                }
            }

            // Get the packet with smallest sequence number from send queue (ordered by seq)
            auto tail = convergence->send_queue_.begin();                   // Iterator to first element (lowest seq)
            auto endl = convergence->send_queue_.end();                     // End iterator
            if (tail == endl)                                               // Queue empty
            {
                return true;                                                // Nothing to send, but connection remains healthy
            }

            send_packet context = tail->second;                             // Copy packet info
            convergence->send_queue_.erase(tail);                           // Remove from queue (we will send it now)

            return sent(context.packet, context.length);                    // Send asynchronously
        }

        // Start receiving TCP data (length header then payload)
        bool recv() noexcept
        {
            std::shared_ptr<aggligator> aggligator = app_;                  // Get aggregator
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

            auto self = shared_from_this();                                 // Keep alive during async read
            // Read the 2-byte length prefix (big-endian)
            boost::asio::async_read(*socket, boost::asio::buffer(buffer_.get(), 2),
                [self, this, socket](boost::system::error_code ec, std::size_t sz) noexcept
                {
                    do
                    {
                        ptr aggligator = app_;
                        if (!aggligator)                                    // Aggregator destroyed
                        {
                            close();
                            break;
                        }

                        aggligator->rx_ += sz;                              // Count received bytes
                        if (sz != 2)                                        // Incomplete length header
                        {
                            close();
                            break;
                        }

                        client_ptr client = client_;                        // Get client
                        if (!client)
                        {
                            close();
                            break;
                        }

                        Byte* buf = buffer_.get();                                               // Raw pointer to receive buffer
                        std::size_t length = buf[0] << 8 | buf[1];          // Compute payload length
                        if (length == 0)                                    // Heartbeat packet (zero length)
                        {
                            if (!recv())                                    // Continue to next packet
                            {
                                close();
                                break;
                            }
                            else
                            {
                                aggligator->rx_pps_++;                      // Count heartbeat as a packet
                            }

                            client->last_ = (uint32_t)(aggligator->now() / 1000); // Update activity timestamp
                            break;
                        }

                        // Read the payload of specified length
                        boost::asio::async_read(*socket, boost::asio::buffer(buffer_.get(), length),
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
                                    if (length != sz)                       // Incomplete payload
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

                                    // Feed the received data into convergence for reassembly
                                    bool ok = convergence->input(buffer_.get(), length, buffer_) && recv();
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

        // Establish TCP connection and perform handshake (asynchronous coroutine)
        bool open(YieldContext& y, const boost::asio::ip::tcp::endpoint& server, const ppp::function<void(connection*)>& established) noexcept
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

            if (socket->is_open())                                          // Already connected (should not happen)
            {
                return false;
            }

            boost::system::error_code ec;
            if (!ppp::coroutines::asio::async_open(y, *socket, server.protocol())) // Open socket with correct protocol
            {
                return false;
            }
            else
            {
                aggligator->socket_adjust(*socket);                         // Apply socket options
            }

#if defined(_LINUX)                                                         // Linux VPN protection (if configured)
            boost::asio::ip::address server_ip = server.address();
            if (server_ip.is_v4() && !server_ip.is_loopback())
            {
                ProtectorNetworkPtr protector_network = aggligator->ProtectorNetwork;
                if (NULLPTR != protector_network)
                {
                    if (!protector_network->Protect(socket->native_handle(), y))
                    {
                        return false;
                    }
                }
            }
#elif defined(_WIN32)                                                       // Windows QoS tagging
            qoss_ = QoSS::New(socket->native_handle(), server.address(), server.port());
#endif
            socket_ = socket;                                               // Store socket

            connection_ptr self = shared_from_this();                       // Keep reference
            // Post connect operation to avoid deep recursion
            boost::asio::post(socket->get_executor(),
                [self, this, established, socket, server]() noexcept
                {
                    socket->async_connect(server,                           // Initiate connection
                        [self, this, established](boost::system::error_code ec) noexcept
                        {
                            ptr aggligator = app_;
                            if (!aggligator)
                            {
                                close();
                                return false;
                            }

                            if (ec)                                         // Connection failed
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

                            // Handshake in a separate coroutine
#if BOOST_VERSION >= 108000
                            boost::asio::spawn(socket->get_executor(),
                                [self, this, established](const boost::asio::yield_context& y) noexcept
                                {
                                    if (!establish(y, established))
                                    {
                                        close();
                                    }
                                }, boost::asio::detached);
#else
                            boost::asio::spawn(socket->get_executor(),
                                [self, this, established](const boost::asio::yield_context& y) noexcept
                                {
                                    if (!establish(y, established))
                                    {
                                        close();
                                    }
                                });
#endif

                            return true;
                        });
                });
            return true;
        }

        // Perform cryptographic-like handshake (xor checksum) and exchange sequence numbers
        bool establish(const boost::asio::yield_context& y, const ppp::function<void(connection*)>& established) noexcept;
        // Send heartbeat or keepalive when idle
        bool update(uint32_t now) noexcept
        {
            std::shared_ptr<Byte> packet;
            if (next_ == 0)                                                 // First time, schedule heartbeat
            {
            next:                                                           // Label for recomputing next_ after sending
                int32_t rnd = RandomNext(1, std::min<int>(AGGLIGATOR_INACTIVE_TIMEOUT >> 1, std::max<int>(AGGLIGATOR_CONNECT_TIMEOUT, AGGLIGATOR_RECONNECT_TIMEOUT) << 2));
                next_ = now + (uint32_t)rnd;                                // Random offset to avoid thundering herd
            }
            else if (now >= next_)                                          // Time to send heartbeat
            {
                std::shared_ptr<aggligator> aggligator = app_;
                if (!aggligator)
                {
                    return false;
                }

                packet = aggligator->make_shared_bytes(2);                  // Allocate 2-byte zero-length packet
                if (!packet)
                {
                    return false;
                }

                Byte* memory = packet.get();
                memory[0] = 0;                                              // Length high byte = 0
                memory[1] = 0;                                              // Length low byte = 0 (heartbeat)

                if (sending_)                                               // Already sending something, postpone
                {
                    next_packet_ = packet;                                  // Store for later
                    goto next;                                              // Recompute next_ time
                }
                else if (sent(packet, 2))                                   // Send heartbeat
                {
                    if (sending_)                                           // Sent started asynchronously
                    {
                        goto next;
                    }
                }

                return false;                                               // Send failed
            }

            return true;
        }

        std::shared_ptr<aggligator> app_;                                   // Parent aggregator
        convergence_ptr convergence_;                                       // Convergence layer
        client_ptr client_;                                                 // Client that owns this connection
        std::shared_ptr<boost::asio::ip::tcp::socket> socket_;              // TCP socket
        bool sending_;                                                      // True if async_write is pending
        uint32_t next_;                                                     // Next heartbeat timestamp (seconds)
        std::shared_ptr<Byte> next_packet_;                                 // Heartbeat packet pending because socket busy
#if defined(_WIN32)                                                         // Windows QoS object
        std::shared_ptr<QoSS> qoss_;
#endif
        std::shared_ptr<Byte> buffer_;                                         // Receive buffer (max 65507 bytes, shared for zero-copy)
    };

    //----------------------------------------------------------------------------
    // aggligator constructor
    //----------------------------------------------------------------------------
    aggligator::aggligator(boost::asio::io_context& context, const std::shared_ptr<Byte>& buffer, int buffer_size, int congestions) noexcept
        : context_(context)                                                 // Store io_context reference
        , buffer_(buffer)                                                   // Store UDP receive buffer
        , buffer_size_(buffer_size)                                         // Store buffer size
        , congestions_(congestions)                                         // Congestion threshold (max out-of-order packets)
        , server_mode_(false)                                               // Not determined yet
        , last_(0)                                                          // No last tick
        , now_(ppp::threading::Executors::GetTickCount())                   // Current time in ms
        , rx_(0)                                                            // Zero counters
        , tx_(0)
        , rx_pps_(0)
        , tx_pps_(0)
    {
        if (NULLPTR == buffer)                                              // Invalid buffer pointer
        {
            buffer_size = 0;                                                // Disable buffer usage
        }
        else if (buffer_size < 1)                                           // Zero or negative size
        {
            buffer_ = NULLPTR;                                              // Clear buffer
            buffer_size = 0;
        }
    }

    //----------------------------------------------------------------------------
    // aggligator destructor
    //----------------------------------------------------------------------------
    aggligator::~aggligator() noexcept
    {
        close();                                                            // Clean everything
    }

    //----------------------------------------------------------------------------
    // Close the entire aggregator, cancel all timers, close all connections
    //----------------------------------------------------------------------------
    void aggligator::close() noexcept
    {
        client_ptr client = std::move(client_);                             // Take ownership of client
        server_ptr server = std::move(server_);                             // Take ownership of server
        ppp::function<void()> exit = std::move(Exit);                       // Move exit callback

        deadline_timer_cancel(reopen_);                                     // Cancel and reset reconnect timer
        deadline_timer_cancel(timeout_);                                    // Cancel and reset main tick timer

        if (server)                                                         // If server exists, close its acceptors
        {
            server->close();
        }

        if (client)                                                         // If client exists, close it (will also close connections)
        {
            client->close();
        }

        if (exit)                                                           // Invoke exit callback if set
        {
            Exit = NULLPTR;                                                 // Clear to avoid recursion
            exit();
        }
    }

    //----------------------------------------------------------------------------
    // Update activity and timeouts (called periodically from timer)
    //----------------------------------------------------------------------------
    void aggligator::update(uint64_t now) noexcept
    {
        uint32_t now_seconds = (uint32_t)(now / 1000);                      // Convert to seconds
        for (;;)                                                            // Single iteration (for break convenience)
        {
            client_ptr pclient = client_;                                   // Get client (if in client mode)
            if (pclient && pclient->last_ != 0 && !pclient->update(now_seconds)) // Check inactivity
            {
                pclient->close();                                           // Close and trigger reconnect
            }

            break;
        }

        for (;;)                                                            // Server mode: check all clients
        {
            server_ptr pserver = server_;
            if (!pserver)                                                   // Not a server
            {
                break;
            }

            list<client_ptr> releases;                                      // Clients to be closed
            for (auto&& kv : pserver->clients_)                             // Iterate over all clients
            {
                client_ptr& pclient = kv.second;
                if (pclient->last_ != 0 && !pclient->update(now_seconds))   // Inactive
                {
                    releases.emplace_back(pclient);                         // Schedule for removal
                }
            }

            for (client_ptr& pclient : releases)                            // Actually close them
            {
                pclient->close();
            }

            break;
        }
    }

    //----------------------------------------------------------------------------
    // Create the main tick timer if not already created
    //----------------------------------------------------------------------------
    bool aggligator::create_timeout() noexcept
    {
        deadline_timer timeout_ptr = timeout_;
        if (timeout_ptr)                                                    // Already exists
        {
            return true;
        }

        timeout_ptr = make_shared_object<boost::asio::steady_timer>(context_); // Create new timer
        if (!timeout_ptr)                                                   // Allocation failed
        {
            return false;
        }

        timeout_ = timeout_ptr;
        return nawait_timeout();                                            // Start the periodic loop
    }

    //----------------------------------------------------------------------------
    // Non-blocking timer loop (fires every 10ms)
    //----------------------------------------------------------------------------
    bool aggligator::nawait_timeout() noexcept
    {
        deadline_timer t = timeout_;                                        // Get current timer
        if (t)                                                              // Timer exists
        {
            auto self = shared_from_this();                                 // Keep aggregator alive
            t->expires_after(std::chrono::milliseconds(10));             // Short interval for responsiveness
            t->async_wait(
                [self, this](boost::system::error_code ec) noexcept
                {
                    if (ec == boost::system::errc::operation_canceled)      // Timer cancelled (closing)
                    {
                        close();
                        return false;
                    }

                    uint64_t now = ppp::threading::Executors::GetTickCount(); // Get current time
                    uint32_t now_seconds = (uint32_t)(now / 1000);

                    now_ = now;                                             // Update timestamp
                    if (last_ != now_seconds)                               // Only update once per second
                    {
                        last_ = now_seconds;
                        update(now);                                        // Check timeouts

                        ppp::function<void(uint64_t)> tick = Tick;          // External tick callback
                        if (tick)
                        {
                            tick(now);
                        }
                    }

                    return nawait_timeout();                                // Continue loop
                });
            return true;
        }

        return false;
    }

    //----------------------------------------------------------------------------
    // Cancel a deadline timer safely
    //----------------------------------------------------------------------------
    void aggligator::deadline_timer_cancel(deadline_timer& t) noexcept
    {
        deadline_timer p = std::move(t);                                    // Take ownership
        if (p)
        {
            p->cancel();                                                    // Cancel any pending wait
        }
    }

    //----------------------------------------------------------------------------
    // Apply low-level socket options to native socket (TCP or UDP)
    //----------------------------------------------------------------------------
    void aggligator::socket_adjust(int sockfd, bool in4) noexcept
    {
        AppConfigurationPtr configuration = AppConfiguration;               // Get configuration
        if (NULLPTR != configuration)
        {
            auto& cfg = configuration->udp;                                 // UDP specific settings
            Socket::SetWindowSizeIfNotZero(sockfd, cfg.cwnd, cfg.rwnd);     // Set send/recv window if non-zero
        }

        Socket::AdjustDefaultSocketOptional(sockfd, in4);                   // Set TCP_NODELAY, SO_REUSEADDR, etc.
        Socket::SetTypeOfService(sockfd);                                   // Set IP_TOS for QoS
    }

    //----------------------------------------------------------------------------
    // Close UDP socket safely
    //----------------------------------------------------------------------------
    void aggligator::socket_close(boost::asio::ip::udp::socket& socket) noexcept
    {
        if (socket.is_open())
        {
            boost::system::error_code ec;
            socket.cancel();                                               // Cancel pending async ops
            socket.close(ec);                                               // Close descriptor
        }
    }

    //----------------------------------------------------------------------------
    // Close TCP socket safely (shutdown send first)
    //----------------------------------------------------------------------------
    void aggligator::socket_close(boost::asio::ip::tcp::socket& socket) noexcept
    {
        if (socket.is_open())
        {
            boost::system::error_code ec;
            socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec); // Send FIN
            socket.cancel();                                                // Cancel pending reads/writes
            socket.close(ec);                                               // Close socket
        }
    }

    //----------------------------------------------------------------------------
    // Server accept loop: accept new TCP connections on given acceptor
    //----------------------------------------------------------------------------
    bool aggligator::server_accept(const acceptor& acceptor) noexcept
    {
        bool opened = acceptor->is_open();
        if (!opened)                                                        // Acceptor closed
        {
            close();
            return false;
        }

        std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(context_); // Create new socket
        if (!socket)                                                        // Allocation failed
        {
            close();
            return false;
        }

        auto self = shared_from_this();                                     // Keep aggregator alive
        acceptor->async_accept(*socket,                                     // Start async accept
            [self, this, acceptor, socket](boost::system::error_code ec) noexcept
            {
                if (ec == boost::system::errc::operation_canceled)          // Acceptor cancelled (shutdown)
                {
                    close();
                    return false;
                }
                else if (ec == boost::system::errc::success)                // New connection accepted
                {
                    YieldContext::Spawn(context_,                           // Spawn coroutine to handle handshake
                        [self, this, socket](YieldContext& y) noexcept
                        {
                            socket_adjust(*socket);                         // Apply socket options
                            if (!(socket->is_open() && server_accept(socket, y))) // Perform handshake
                            {
                                socket_close(*socket);                      // Failed, close socket
                            }
                        });
                }

                if (server_accept(acceptor))                                // Continue accepting further connections
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

    //----------------------------------------------------------------------------
    // Process newly accepted TCP connection: handshake and attach to client
    //----------------------------------------------------------------------------
    bool aggligator::server_accept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, YieldContext& y) noexcept
    {
        boost::system::error_code ec;
        server_ptr server = server_;
        if (!server)                                                        // Server object missing
        {
            return false;
        }

        // Set a timeout for the handshake phase
        deadline_timer timeout = make_shared_object<boost::asio::steady_timer>(context_);
        if (!timeout)
        {
            return false;
        }
        else
        {
            timeout->expires_after(std::chrono::seconds(AGGLIGATOR_CONNECT_TIMEOUT));
            timeout->async_wait(                                            // If handshake not completed, close socket
                [socket](boost::system::error_code ec) noexcept
                {
                    if (ec != boost::system::errc::operation_canceled)
                    {
                        socket_close(*socket);
                    }
                });
        }

        Byte data[128];                                                     // Temporary buffer
        uint16_t remote_port = 0;                                           // Port from client (0 for first connection)

        // Read 8-byte handshake header
        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 8), y))
        {
            return false;
        }
        else
        {
            rx_ += 8;
            uint32_t m = *(uint32_t*)data;                                  // Random mask
            *(uint32_t*)(data + 4) ^= m;                                    // Decrypt port field
            uint16_t* pchecksum = (uint16_t*)(data + 6);
            uint16_t checksum = *pchecksum;

            *pchecksum = 0;                                                 // Zero before checksum calculation
            remote_port = ntohs(*(uint16_t*)(data + 4));                    // Get remote port

            uint16_t chksum = inet_chksum(data, 8);                         // Compute internet checksum
            if (chksum != checksum)                                         // Checksum mismatch
            {
                return false;
            }
        }

        connection_ptr pconnection;                                         // New connection object
        client_ptr pclient;                                                 // Client (new or existing)
        convergence_ptr pconvergence;                                       // Convergence layer
        unordered_map<int, client_ptr>& clients = server->clients_;         // Map from remote port to client

        std::shared_ptr<aggligator> my = shared_from_this();                // Keep aggregator alive
        if (remote_port == 0)                                               // First connection of this client (port 0 indicates new client)
        {
            pclient = make_shared_object<client>(my);                       // Create client
            if (!pclient)
            {
                return false;
            }

            pconvergence = make_shared_object<convergence>(my, pclient);    // Create convergence
            if (!pconvergence)
            {
                return false;
            }

            // Open UDP socket for this client
            boost::asio::ip::udp::socket& socket_dgram = pclient->socket_;
            if (!ppp::coroutines::asio::async_open(y, socket_dgram, boost::asio::ip::udp::v6()))
            {
                return false;
            }
            else
            {
                socket_adjust(socket_dgram);                                // Apply UDP options
            }

            // Bind to any IPv6 address, port 0 (OS will assign)
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

            remote_port = local_endpoint.port();                            // Use the assigned port as identifier
            pclient->server_mode_ = true;                                   // Mark as server-side client
            pclient->established_num_ = 1;                                  // One connection established so far
            pclient->connections_num_ = 1;                                  // Expected total connections (will be updated later)
            pclient->remote_port_ = remote_port;                            // Store remote port for lookup
            pclient->convergence_ = pconvergence;                           // Attach convergence

            pconnection = make_shared_object<connection>(my, pclient, pconvergence); // Create connection
            if (!pconnection)
            {
                return false;
            }

            clients[remote_port] = pclient;                                 // Register client in map
            pconnection->socket_ = socket;                                  // Assign TCP socket
            pclient->connections_.emplace_back(pconnection);                // Add to list

            if (!pclient->timeout())                                        // Start connection timeout timer
            {
                return false;
            }
        }
        else                                                                // Subsequent connection for existing client
        {
            auto client_tail = clients.find(remote_port);                   // Lookup by remote port
            auto client_endl = clients.end();
            if (client_tail == client_endl)                                 // No such client
            {
                return false;
            }

            pclient = client_tail->second;
            if (!pclient)                                                   // Client pointer invalid
            {
                clients.erase(client_tail);
                return false;
            }

            pconvergence = pclient->convergence_;
            if (!pconvergence)                                              // Convergence missing
            {
                return false;
            }

            pconnection = make_shared_object<connection>(my, pclient, pconvergence);
            if (!pconnection)
            {
                return false;
            }

            pconnection->socket_ = socket;
            pclient->established_num_++;                                    // Increment established count
            pclient->connections_num_++;                                    // Increment total connections
            pclient->connections_.emplace_back(pconnection);                // Add to list
        }

#if defined(_WIN32)                                                         // Windows QoS tagging for this TCP socket
        if (Socket::IsDefaultFlashTypeOfService())
        {
            pconnection->qoss_ = QoSS::New(socket->native_handle());
        }
#endif

        // Send handshake response: remote port (again) and local sequence number
        data[0] = (Byte)(remote_port >> 8);
        data[1] = (Byte)(remote_port);
        *(uint32_t*)(data + 2) = htonl(pconvergence->seq_no_);              // Send our initial sequence number

        if (!ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(data, 6), y))
        {
            return false;
        }
        else
        {
            tx_ += 6;
        }

        // Read final handshake confirmation (8 bytes)
        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 8), y))
        {
            return false;
        }

        rx_ += 8;
        if (*data != 0)                                                     // First byte must be zero
        {
            return false;
        }

        uint32_t connections_num = ntohl(*(uint32_t*)data);                 // Total number of TCP connections from client
        if (++pclient->handshakeds_num_ < connections_num)                  // Not all connections have completed handshake yet
        {
            return true;                                                    // Wait for more connections
        }

        uint32_t ack = ntohl(*(uint32_t*)(data + 4)) + 1;                   // Acknowledge client's sequence number
        pconvergence->ack_no_ = ack;                                        // Set expected next sequence

        pclient->last_ = (uint32_t)(now() / 1000);                          // Update activity timestamp
        // Start receiving data on all connections
        for (connection_ptr& connection : pclient->connections_)
        {
            if (!connection->recv())
            {
                return false;
            }
        }

        deadline_timer_cancel(timeout);                                     // Handshake completed, cancel timeout
        deadline_timer_cancel(pclient->timeout_);                           // Cancel connection timeout
        return pclient->loopback();                                         // Start UDP receive loop
    }

    //----------------------------------------------------------------------------
    // Start server mode: listen on given ports and forward to destination IP:port
    //----------------------------------------------------------------------------
    bool aggligator::server_open(const unordered_set<int>& bind_ports, const boost::asio::ip::address& destination_ip, int destination_port) noexcept
    {
        if (bind_ports.empty())                                             // No ports to bind
        {
            return false;
        }

        if (server_ || client_)                                             // Already running
        {
            return false;
        }

        server_ptr server = make_shared_object<aggligator::server>();
        if (NULLPTR == server)
        {
            return false;
        }

        if (destination_port <= 0 || destination_port > UINT16_MAX)         // Invalid destination port
        {
            return false;
        }

        if (ip_is_invalid(destination_ip))                                  // Invalid destination IP
        {
            return false;
        }

        bool any = false;                                                   // At least one acceptor created
        for (int bind_port : bind_ports)                                    // Iterate over requested ports
        {
            if (bind_port <= 0 || bind_port > UINT16_MAX)                   // Skip invalid
            {
                continue;
            }
            else
            {
                auto tail = server->acceptors_.find(bind_port);
                auto endl = server->acceptors_.end();
                if (tail != endl)                                           // Already listening on this port
                {
                    continue;
                }
            }

            auto acceptor = make_shared_object<boost::asio::ip::tcp::acceptor>(context_); // Create acceptor
            if (NULLPTR == acceptor)
            {
                break;
            }

            boost::system::error_code ec;
            acceptor->open(boost::asio::ip::tcp::v6(), ec);                 // Open IPv6 TCP (dual-stack)
            if (ec)
            {
                continue;
            }
            else
            {
                socket_adjust(*acceptor);                                   // Apply options
            }

            acceptor->bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::any(), bind_port), ec); // Bind to port
            if (ec && bind_port != 0)                                       // Binding failed and port was specified, try with port 0
            {
                acceptor->bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v6::any(), 0), ec);
                if (ec)
                {
                    continue;
                }
            }

            acceptor->listen(UINT16_MAX, ec);                               // Start listening
            if (ec)
            {
                continue;
            }

            if (server_accept(acceptor))                                    // Begin async accept loop
            {
                any |= true;
                server->acceptors_[bind_port] = acceptor;                   // Store acceptor
            }
        }

        server->server_endpoint_ = boost::asio::ip::udp::endpoint(destination_ip, destination_port); // Set UDP forward destination
        server->server_endpoint_ = ip_v4_to_v6(server->server_endpoint_);   // Convert to IPv6 for consistency
        if (any)                                                            // At least one listening socket
        {
            server_ = server;
            server_mode_ = true;
        }

        return any && create_timeout();                                     // Start main timer
    }

    //----------------------------------------------------------------------------
    // Start client mode: connect to multiple servers using multiple TCP connections
    //----------------------------------------------------------------------------
    bool aggligator::client_open(
        int connections,
        const unordered_set<boost::asio::ip::tcp::endpoint>& servers) noexcept
    {
        if (servers.empty())                                                // No servers to connect
        {
            return false;
        }

        if (connections < 1)                                                // At least one connection per server
        {
            connections = 1;
        }

        if (server_ || client_)                                             // Already active
        {
            return false;
        }

        unordered_set<boost::asio::ip::tcp::endpoint> connect_servers;      // Valid servers after filtering
        for (const boost::asio::ip::tcp::endpoint& ep : servers)            // Validate each endpoint
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

        if (connect_servers.empty())                                        // No valid servers
        {
            return false;
        }

        client_ptr pclient = make_shared_object<client>(shared_from_this()); // Create client
        if (!pclient)
        {
            return false;
        }

        client_ = pclient;
        server_mode_ = false;
        return create_timeout() && pclient->open(connections, connect_servers); // Open TCP connections
    }

    //----------------------------------------------------------------------------
    // Check if IP address is unusable (unspecified, multicast, loopback sometimes allowed)
    //----------------------------------------------------------------------------
    bool aggligator::ip_is_invalid(const boost::asio::ip::address& address) noexcept
    {
        if (address.is_v4())
        {
            boost::asio::ip::address_v4 in = address.to_v4();
            if (in.is_multicast() || in.is_unspecified())                   // Multicast or 0.0.0.0
            {
                return true;
            }

            uint32_t ip = htonl(in.to_uint());
            return ip == INADDR_ANY || ip == INADDR_NONE;                   // Also any address or none
        }
        else if (address.is_v6())
        {
            boost::asio::ip::address_v6 in = address.to_v6();
            if (in.is_multicast() || in.is_unspecified())                   // Multicast or ::
            {
                return true;
            }

            return false;                                                   // All other IPv6 addresses considered valid
        }
        else
        {
            return true;
        }
    }

    //----------------------------------------------------------------------------
    // Called when a server-mode client is closed (cleanup map entry)
    //----------------------------------------------------------------------------
    bool aggligator::server_closed(client* client) noexcept
    {
        if (client->server_mode_)                                           // Only for server-side clients
        {
            server_ptr server = server_;
            if (server)
            {
                auto& clients = server->clients_;
                auto tail = clients.find(client->remote_port_);
                auto endl = clients.end();
                if (tail != endl)
                {
                    client_ptr p = std::move(tail->second);                 // Remove from map
                    clients.erase(tail);

                    if (p)                                                  // Close client (already closing, but ensure)
                    {
                        p->close();
                    }
                }
            }
        }

        return false;
    }

    //----------------------------------------------------------------------------
    // Retrieve concurrency parameters (number of servers and channels per server)
    //----------------------------------------------------------------------------
    void aggligator::client_fetch_concurrency(int& servers, int& channels) noexcept
    {
        servers = 0;
        channels = 0;

        client_ptr client = client_;
        if (NULLPTR != client && !client->server_mode_)
        {
            servers = (int)client->server_endpoints_.size();                // Number of remote server addresses
            if (servers > 0)
            {
                channels = (int)client->connections_num_ / servers;         // Connections per server (round robin)
            }
        }
    }

    //----------------------------------------------------------------------------
    // Reconnect after client failure (called from client::close)
    //----------------------------------------------------------------------------
    bool aggligator::client_reopen(client* client) noexcept
    {
        if (client->server_mode_ || client != client_.get())                // Not the active client
        {
            return false;
        }

        client_ptr pclient = std::move(client_);                            // Discard current client
        if (pclient)
        {
            pclient->close();                                               // Fully close it
        }
        else
        {
            close();                                                        // No client to reopen, shut down
            return false;
        }

        deadline_timer t = make_shared_object<boost::asio::steady_timer>(context_);
        if (!t)
        {
            close();
            return false;
        }

        unordered_set<boost::asio::ip::tcp::endpoint> servers = pclient->server_endpoints_; // Remember original servers
        uint32_t connections = pclient->connections_num_ / servers.size();  // Connections per server
        int bind_port = pclient->local_port_;                               // Local UDP port (if any)

        auto self = shared_from_this();
        t->expires_after(std::chrono::seconds(AGGLIGATOR_RECONNECT_TIMEOUT));
        t->async_wait(
            [self, this, connections, bind_port, servers](boost::system::error_code ec) noexcept
            {
                deadline_timer_cancel(reopen_);                             // Clear reopen timer reference
                if (ec == boost::system::errc::operation_canceled)
                {
                    close();
                    return false;
                }
                else if (ec)
                {
                    close();
                    return false;
                }

                bool opened = client_open(connections, servers);            // Attempt to reopen
                if (!opened)
                {
                    close();
                    return false;
                }

                return true;
            });

        reopen_ = t;                                                        // Store timer for cancellation
        return true;
    }

    //----------------------------------------------------------------------------
    // Allocate shared byte array using the configured allocator
    //----------------------------------------------------------------------------
    std::shared_ptr<Byte> aggligator::make_shared_bytes(int length) noexcept
    {
        if (length > 0)
        {
            BufferswapAllocatorPtr allocator = BufferswapAllocator;         // Get allocator (may be null)
            return ppp::threading::BufferswapAllocator::MakeByteArray(allocator, length); // Allocate
        }
        else
        {
            return NULLPTR;
        }
    }

    //----------------------------------------------------------------------------
    // Client::update: check inactivity and propagate update to connections
    //----------------------------------------------------------------------------
    bool aggligator::client::update(uint32_t now_seconds) noexcept
    {
        if (now_seconds >= (last_ + AGGLIGATOR_INACTIVE_TIMEOUT))           // Idle too long
        {
            return false;                                                   // Signal close
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

        int rq_congestions = (int)pconvergence->recv_queue_.size();         // Current out-of-order queue size
        if (rq_congestions >= aggligator->congestions_)                     // Congestion threshold exceeded
        {
            return false;                                                   // Stop receiving (drop new packets)
        }

        for (connection_ptr& connection : connections_)                     // Update each connection (send heartbeat)
        {
            if (!connection->update(now_seconds))
            {
                return false;
            }
        }

        return true;
    }

    //----------------------------------------------------------------------------
    // Client::close: close all TCP connections, UDP socket, and notify aggregator
    //----------------------------------------------------------------------------
    void aggligator::client::close() noexcept
    {
        std::shared_ptr<aggligator> aggligator = std::move(app_);           // Release aggregator reference
        convergence_ptr convergence = std::move(convergence_);

        if (convergence)                                                    // Close convergence (clears queues)
        {
            convergence->close();
        }

        list<connection_ptr> connections = std::move(connections_);         // Take ownership of connections list
        connections_.clear();

        for (connection_ptr& connection : connections)                      // Close each TCP connection
        {
            connection->close();
        }

        deadline_timer_cancel(timeout_);                                    // Cancel connection timeout timer
        aggligator::socket_close(socket_);                                  // Close UDP socket

        if (aggligator)                                                     // Notify aggregator to cleanup mapping and possibly reconnect
        {
            aggligator->server_closed(this);
            aggligator->client_reopen(this);
        }
    }

    //----------------------------------------------------------------------------
    // Client::send: take a UDP packet, add headers, and queue for transmission over TCP
    //----------------------------------------------------------------------------
    bool aggligator::client::send(Byte* packet, int packet_length) noexcept
    {
        if (NULLPTR == packet || packet_length < 1)                         // Invalid packet
        {
            return false;
        }

        convergence_ptr convergence = convergence_;
        if (NULLPTR == convergence)
        {
            return false;
        }

        auto tail = connections_.begin();                                   // Start from first connection
        auto endl = connections_.end();
        if (tail == endl)                                                   // No active TCP connections
        {
            return false;
        }

        int message_length;                                                 // Length after adding sequence header
        uint32_t seq = ++convergence->seq_no_;                              // Increment sequence number (mod 2^32)

        std::shared_ptr<Byte> message = convergence->pack(packet, packet_length, seq, message_length); // Add length+seq headers
        if (NULLPTR == message || message_length < 1)
        {
            return false;
        }

        // Build send packet structure
        send_packet sp;
        sp.seq = seq;                                                       // Sequence number for ordering
        sp.packet = message;                                                // Packet data
        sp.length = message_length;                                         // Total length

        // Insert into send queue (automatically sorted by seq using map)
        convergence->send_queue_.emplace(std::make_pair(seq, sp));

        for (;;)                                                            // Try to send immediately if there is an idle connection
        {
            auto sqt = convergence->send_queue_.begin();                    // Get the packet with smallest seq
            if (sqt == convergence->send_queue_.end())                      // Queue empty
            {
                return true;
            }

            connection_ptr connection;                                      // Find an idle connection
            for (; tail != endl; tail++)
            {
                connection_ptr& i = *tail;
                if (!i->sending_)                                           // Not currently writing
                {
                    connection = i;
                    break;
                }
            }

            if (connection)                                                 // Found idle connection
            {
                send_packet messages = sqt->second;                         // Copy packet
                convergence->send_queue_.erase(sqt);                        // Remove from queue

                bool ok = connection->sent(messages.packet, messages.length); // Send asynchronously
                if (ok)
                {
                    if (connection->sending_ && connections_num_ > 1)       // If write started, move connection to end for round-robin
                    {
                        connections_.erase(tail);
                        connections_.emplace_back(connection);
                    }

                    return true;
                }

                return false;                                               // Send failed
            }
            else                                                            // All connections busy, packet stays in queue
            {
                return true;
            }
        }
    }

    //----------------------------------------------------------------------------
    // Client::timeout: start a timer that will close the client if handshake not finished
    //----------------------------------------------------------------------------
    bool aggligator::client::timeout() noexcept
    {
        ptr aggligator = app_;
        if (!aggligator)
        {
            close();
            return false;
        }

        deadline_timer timeout = make_shared_object<boost::asio::steady_timer>(aggligator->context_);
        if (!timeout)
        {
            close();
            return false;
        }

        auto self = shared_from_this();                                     // Keep client alive
        timeout->expires_after(std::chrono::seconds(AGGLIGATOR_CONNECT_TIMEOUT));
        timeout->async_wait(
            [self, this](boost::system::error_code ec) noexcept
            {
                if (ec == boost::system::errc::operation_canceled)
                {
                    return false;
                }
                else
                {
                    close();                                                // Timeout expired, abort client
                    return true;
                }
            });

        timeout_ = timeout;
        return true;
    }

    //----------------------------------------------------------------------------
    // Client::loopback: start receiving UDP packets from external source and forward through aggregator
    //----------------------------------------------------------------------------
    bool aggligator::client::loopback() noexcept
    {
        ptr aggligator = app_;
        if (!aggligator)
        {
            close();
            return false;
        }

        std::shared_ptr<Byte> buffer = aggligator->buffer_;                 // Shared buffer for UDP receive
        if (!buffer)
        {
            close();
            return false;
        }

        boost::system::error_code ec;
        if (!socket_.is_open())                                             // Open UDP socket if not already
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

            // Bind to any IPv6 address, using local_port_ (0 means OS chooses)
            socket_.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6::any(), local_port_), ec);
            if (ec)
            {
                close();
                return false;
            }

            if (local_port_ == 0)                                           // Retrieve assigned port
            {
                boost::asio::ip::udp::endpoint localEP = socket_.local_endpoint(ec);
                local_port_ = localEP.port();
            }
        }

        auto self = shared_from_this();                                     // Keep client alive
        socket_.async_receive_from(boost::asio::buffer(buffer.get(), aggligator->buffer_size_), source_endpoint_, // Receive UDP
            [self, this](boost::system::error_code ec, std::size_t sz) noexcept
            {
                ptr aggligator = app_;
                if (!aggligator)
                {
                    close();
                    return false;
                }

                int bytes_transferred = static_cast<int>(sz);
                if (bytes_transferred > 0 && ec == boost::system::errc::success) // Valid packet
                {
                    std::shared_ptr<Byte> buffer = aggligator->buffer_;
                    if (!buffer)
                    {
                        close();
                        return false;
                    }

                    bool bok = send(buffer.get(), bytes_transferred);       // Send via aggregator
                    if (!bok)
                    {
                        close();
                        return false;
                    }
                }

                return loopback();                                          // Continue receiving
            });
        return true;
    }

    //----------------------------------------------------------------------------
    // Client::open: establish multiple TCP connections to servers (round-robin)
    //----------------------------------------------------------------------------
    bool aggligator::client::open(int connections, unordered_set<boost::asio::ip::tcp::endpoint>& servers) noexcept
    {
        using tcp_endpoint_list = list<boost::asio::ip::tcp::endpoint>;

        std::shared_ptr<aggligator> aggligator = app_;
        if (NULLPTR == aggligator)
        {
            return false;
        }

        std::shared_ptr<tcp_endpoint_list> list = make_shared_object<tcp_endpoint_list>();
        if (NULLPTR == list)
        {
            return false;
        }

        client_ptr self = shared_from_this();                               // Keep client alive
        convergence_ptr pconvergence = make_shared_object<convergence>(aggligator, self);
        if (NULLPTR == pconvergence)
        {
            return false;
        }

        convergence_ = pconvergence;
        server_mode_ = false;
        local_port_ = 0;
        server_endpoints_ = servers;

        // Lambda to initiate a connection to a single server
        auto connect_to_server =
            [self, this, aggligator, pconvergence](const boost::asio::ip::tcp::endpoint& server, const ppp::function<void(connection*)>& established) noexcept
            {
                connection_ptr pconnection = make_shared_object<connection>(aggligator, self, pconvergence);
                if (!pconnection)
                {
                    return false;
                }

                YieldContext::Spawn(aggligator->context_,                   // Spawn coroutine for connection
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

        // Build a list of endpoints: each server repeated 'connections' times
        for (int i = 0; i < connections; i++)
        {
            for (const boost::asio::ip::tcp::endpoint& server : servers)
            {
                connections_num_++;
                list->emplace_back(server);
            }
        }

        // The first endpoint is the "master" node (will carry the final handshake)
        boost::asio::ip::tcp::endpoint master_node = list->front();
        list->pop_front();

        if (list->begin() == list->end())                                   // Only one server and one connection
        {
            list.reset();
        }

        // Start connection timeout timer, then connect master node first
        return timeout() && connect_to_server(master_node,
            [this, list, connect_to_server](connection* connection) noexcept
            {
                if (NULLPTR == list)                                        // No more connections to establish
                {
                    return false;
                }

                bool any = false;
                for (const boost::asio::ip::tcp::endpoint& server : *list)  // Connect the rest
                {
                    any |= connect_to_server(server, NULLPTR);
                }

                return any;
            });
    }

    //----------------------------------------------------------------------------
    // Convergence::pack: add 2-byte length header and 4-byte sequence number
    //----------------------------------------------------------------------------
    std::shared_ptr<Byte> aggligator::convergence::pack(Byte* packet, int packet_length, uint32_t seq, int& out) noexcept
    {
        out = 0;
        if (NULLPTR == packet || packet_length < 1)
        {
            return NULLPTR;
        }

        int message_length = 4 + packet_length;                             // Sequence number (4) + payload
        int final_length = 2 + message_length;                              // Length prefix (2) + message

        std::shared_ptr<aggligator> aggligator = app_;
        if (NULLPTR == aggligator)
        {
            return NULLPTR;
        }

        std::shared_ptr<Byte> message = aggligator->make_shared_bytes(final_length);
        if (NULLPTR == message)
        {
            return NULLPTR;
        }

        Byte* stream = message.get();
        *stream++ = (Byte)(message_length >> 8);                            // Length high byte
        *stream++ = (Byte)(message_length);                                 // Length low byte

        *stream++ = (Byte)(seq >> 24);                                      // Sequence number (big-endian)
        *stream++ = (Byte)(seq >> 16);
        *stream++ = (Byte)(seq >> 8);
        *stream++ = (Byte)(seq);

        out = final_length;
        memcpy(stream, packet, packet_length);                              // Copy original payload
        return message;
    }

    //----------------------------------------------------------------------------
    // Convergence::input: process received TCP data (reassemble in order)
    //----------------------------------------------------------------------------
    bool aggligator::convergence::input(Byte* packet, int packet_length, const std::shared_ptr<Byte>& owner) noexcept
    {
        if (NULLPTR == packet || packet_length < 4)                         // Need at least sequence number
        {
            return false;
        }

        std::shared_ptr<aggligator> aggligator = app_;
        if (NULLPTR == aggligator)
        {
            return false;
        }

        uint32_t seq = htonl(*(uint32_t*)packet);                           // Extract sequence number (network to host)
        packet += 4;                                                        // Skip seq
        packet_length -= 4;

        int max_congestions = aggligator->congestions_;
        if (max_congestions < 1)                                            // Congestion control disabled
        {
            if (output(packet, packet_length))                              // Directly output to UDP
            {
                ack_no_++;                                                  // Increase expected seq
                return true;
            }
            else
            {
                return false;
            }
        }
        else                                                                // Congestion control enabled
        {
            // Handle 32-bit wrap-around: if seq < ack_no_, it might be a future packet due to wrap
            if (seq < ack_no_)                                              // seq appears smaller
            {
                bool wraparound = before(ack_no_, seq);                     // Check if ack_no is actually before seq (wrap)
                if (!wraparound)                                            // It's an old duplicate packet
                {
                    return true;                                            // Silently ignore
                }
                // Otherwise, it's a future packet (seq wrapped), continue processing
            }

            int rq_congestions = (int)recv_queue_.size();                   // Current out-of-order queue size
            if (rq_congestions >= max_congestions)                          // Too many pending packets
            {
                return false;                                               // Drop this packet (congestion)
            }
        }

        if (ack_no_ == seq)                                                 // This is the expected next packet
        {
            if (output(packet, packet_length))                              // Send to UDP
            {
                ack_no_++;                                                  // Move window forward
            }
            else
            {
                return false;
            }

            // Check if any subsequent packets are now in order (due to this delivery)
            auto tail = recv_queue_.begin();
            auto endl = recv_queue_.end();
            while (tail != endl)
            {
                if (ack_no_ != tail->first)                                 // Not the next expected
                {
                    break;
                }
                else                                                        // Next expected packet is in queue
                {
                    recv_packet& pr = tail->second;
                    if (output(pr.packet.get(), pr.length))                 // Output it
                    {
                        ack_no_++;
                    }
                    else
                    {
                        return false;
                    }
                }

                tail = recv_queue_.erase(tail);                             // Remove delivered packet
            }

            return true;
        }

        // Out-of-order packet: store in receive queue (sorted by seq)
        recv_packet r;
        r.seq = seq;
        r.length = packet_length;
        if (owner) {
            r.packet = ppp::wrap_shared_pointer(packet, owner);              // Zero-copy slice
        } else {
            r.packet = aggligator->make_shared_bytes(packet_length);         // Copy data
            if (r.packet) {
                memcpy(r.packet.get(), packet, packet_length);
            }
        }
        if (r.packet)
        {
            return recv_queue_.emplace(std::make_pair(seq, r)).second;      // Insert into map
        }
        else
        {
            return false;
        }
    }

    //----------------------------------------------------------------------------
    // Convergence::close: clear queues and release references
    //----------------------------------------------------------------------------
    void aggligator::convergence::close() noexcept
    {
        std::shared_ptr<client> client = std::move(client_);                // Release client
        std::shared_ptr<aggligator> aggligator = std::move(app_);           // Release aggregator

        send_queue_.clear();                                                // Clear send queue (map)
        recv_queue_.clear();                                                // Clear receive queue (map)

        if (client)                                                         // Client may still be referenced elsewhere
        {
            client->close();                                                // Ensure client closes
        }
    }

    //----------------------------------------------------------------------------
    // Convergence::output: send decapsulated UDP packet to the external destination
    //----------------------------------------------------------------------------
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
        if (client->server_mode_)                                           // Server mode: send to preconfigured destination
        {
            server_ptr server = aggligator->server_;
            if (!server)
            {
                return false;
            }

            socket.send_to(boost::asio::buffer(packet, packet_length), server->server_endpoint_, boost::asio::socket_base::message_end_of_record, ec);
        }
        else                                                                // Client mode: send back to the source endpoint we received from
        {
            socket.send_to(boost::asio::buffer(packet, packet_length), client->source_endpoint_, boost::asio::socket_base::message_end_of_record, ec);
        }

        // Ignore errors (best effort)
        return true;
    }

    //----------------------------------------------------------------------------
    // Socket adjustment wrappers (UDP, TCP, Acceptor)
    //----------------------------------------------------------------------------
    bool aggligator::socket_adjust(boost::asio::ip::udp::socket& socket) noexcept
    {
        if (aggligator_socket_adjust(socket))                               // Common adjustments
        {
            boost::system::error_code ec;
            socket.set_option(boost::asio::ip::udp::socket::reuse_address(true), ec); // Allow address reuse
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

    //----------------------------------------------------------------------------
    // Get client UDP endpoint for external use (e.g., to send data to client)
    //----------------------------------------------------------------------------
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

    //----------------------------------------------------------------------------
    // Fill information structure with current statistics
    //----------------------------------------------------------------------------
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
        if (server)                                                         // Server mode
        {
            i.client_count = server->clients_.size();                       // Number of clients
            for (auto&& kv : server->acceptors_)                            // Listening ports
            {
                i.bind_ports.emplace(kv.first);
            }

            for (auto&& kv : server->clients_)                              // Aggregate client stats
            {
                client_ptr& pclient = kv.second;
                i.establish_count += pclient->established_num_;
                i.connection_count += pclient->connections_num_;
            }
        }
        else if (client)                                                    // Client mode
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

    //----------------------------------------------------------------------------
    // IP version conversion helpers
    //----------------------------------------------------------------------------
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

    //----------------------------------------------------------------------------
    // Determine link status based on information structure
    //----------------------------------------------------------------------------
    aggligator::link_status aggligator::status(information& i) noexcept
    {
        if (server_mode())                                                  // Server mode has no "link" concept
        {
            return link_status_none;
        }

        if (i.bind_ports.empty())                                           // No UDP port (still binding)
        {
            return i.client_count > 0 ? link_status_connecting : link_status_reconnecting;
        }

        if (i.establish_count < i.connection_count)                         // Not all TCP connections ready
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

    //----------------------------------------------------------------------------
    // Connection::establish: perform handshake over TCP (called after TCP connected)
    //----------------------------------------------------------------------------
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
            uint32_t m = (uint32_t)RandomNext(1, INT32_MAX);                // Random mask
            *(uint32_t*)p = m;                                              // Store mask
            p += 4;

            uint16_t remote_port = 0;
            if (client->established_num_ != 0)                              // Not first connection, use existing remote port
            {
                remote_port = client->remote_port_;
            }

            *(uint16_t*)p = htons(remote_port);                             // Port (0 for first)
            p += 2;

            *(uint16_t*)p = 0;                                              // Placeholder for checksum
            *(uint16_t*)p = inet_chksum(data, 8);                           // Compute checksum
            *(uint32_t*)(data + 4) ^= m;                                    // XOR mask to obscure port
        }

        boost::system::error_code ec;
        // Send 8-byte handshake initiation
        boost::asio::async_write(*socket, boost::asio::buffer(data, 8), y[ec]);
        if (ec)
        {
            return false;
        }
        else
        {
            aggligator->tx_ += 8;
        }

        // Read 6-byte response (remote port + server sequence number)
        boost::asio::async_read(*socket, boost::asio::buffer(data, 6), y[ec]);
        if (ec)
        {
            return false;
        }
        else
        {
            aggligator->rx_ += 6;
        }

        uint16_t remote_port = (uint16_t)(data[0] << 8 | data[1]);          // Server-assigned port
        if (remote_port < 1)
        {
            return false;
        }

        uint32_t ack = ntohl(*(uint32_t*)(data + 2)) + 1;                   // Server's sequence number + 1
        if (client->established_num_ == 0)                                  // First connection, set expected ack_no
        {
            convergence->ack_no_ = ack;
        }
        else if (convergence->ack_no_ != ack)                               // Subsequent connections must match
        {
            return false;
        }

        client->remote_port_ = remote_port;
        client->established_num_++;
        if (established)
        {
            established(this);
        }

        if (client->established_num_ < client->connections_num_)            // Not all connections ready yet
        {
            return true;
        }

        // All connections established: send final confirmation (total connections and local seq)
        *(uint32_t*)data = htonl(client->connections_num_);
        *(uint32_t*)(data + 4) = htonl(convergence->seq_no_);

        for (connection_ptr& connection : client->connections_)
        {
            std::shared_ptr<boost::asio::ip::tcp::socket> connection_socket = connection->socket_;
            if (NULLPTR == connection_socket)
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

        client->last_ = (uint32_t)(aggligator->now() / 1000);               // Mark active
        // Start receive loops on all connections
        for (connection_ptr& connection : client->connections_)
        {
            if (!connection->recv())
            {
                return false;
            }
        }

        std::shared_ptr<connection> self = shared_from_this();
        deadline_timer_cancel(client->timeout_);                            // Handshake complete, cancel timeout

        boost::asio::io_context& context = aggligator->context_;
        boost::asio::post(context,                                          // Start UDP loop on client
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