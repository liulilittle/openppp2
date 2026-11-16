#pragma once

/**
 * @file UserspaceSubnetBridge.h
 * @brief Bridges a local proxy socket to a virtual-subnet peer through the in-process stack.
 */

#include <ppp/coroutines/YieldContext.h>

#include <atomic>

namespace lwip {
    class netstack_outbound;
}

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                /**
                 * @brief Proxy-only fallback when no host adapter can carry the virtual subnet.
                 *
                 * The peer connection is opened by the in-process TCP/IP stack from the local
                 * virtual IP, so its packets enter the tunnel (relay or P2P) like adapter traffic.
                 * All bridge state runs on the local socket's executor. Flow control follows
                 * both sides: peer data is acknowledged to the stack only after it reached the
                 * local socket, and the next local read starts only after the stack accepted the
                 * previous chunk.
                 */
                class UserspaceSubnetBridge final : public std::enable_shared_from_this<UserspaceSubnetBridge> {
                public:
                    typedef ppp::function<void()>                                   ActivityHandler;
                    typedef ppp::function<void()>                                   ClosedHandler;

                public:
                    UserspaceSubnetBridge(const std::shared_ptr<boost::asio::ip::tcp::socket>& local_socket,
                        int connect_timeout_seconds) noexcept;
                    ~UserspaceSubnetBridge() noexcept;

                public:
                    ActivityHandler                                                 OnActivity;
                    ClosedHandler                                                   OnClosed;

                public:
                    /** @brief Connects to the peer; suspends the coroutine until connected, failed or timed out. */
                    bool                                                            Connect(const boost::asio::ip::tcp::endpoint& remote,
                        ppp::coroutines::YieldContext& y) noexcept;
                    /** @brief Queues bytes the proxy handshake already read from the local socket. */
                    bool                                                            Send(const void* data, int size) noexcept;
                    /** @brief Starts forwarding in both directions. */
                    bool                                                            Run() noexcept;
                    bool                                                            IsLinked() noexcept;
                    void                                                            Dispose() noexcept;

                private:
                    struct Chunk {
                        std::shared_ptr<Byte>                                       data;
                        int                                                         size = 0;
                    };

                    void                                                            OnPeerData(const std::shared_ptr<Byte>& data, int size) noexcept;
                    void                                                            WriteNext() noexcept;
                    void                                                            ReadNext() noexcept;
                    void                                                            Activity() noexcept;
                    void                                                            Finalize() noexcept;

                private:
                    std::shared_ptr<boost::asio::ip::tcp::socket>                   local_socket_;
                    std::shared_ptr<lwip::netstack_outbound>                        outbound_;
                    std::shared_ptr<Byte>                                           read_buffer_;
                    ppp::list<Chunk>                                                pending_;
                    int                                                             connect_timeout_seconds_ = 0;
                    bool                                                            connected_ = false;
                    bool                                                            running_ = false;
                    bool                                                            writing_ = false;
                    std::atomic<bool>                                               disposed_{ false };
                };
            }
        }
    }
}
