#pragma once

/**
 * @file VEthernetLocalProxyConnection.h
 * @brief Declares the per-client local proxy connection abstraction.
 * @author OpenPPP Contributors
 * @license GPL-3.0
 */

#include <ppp/transmissions/ITransmission.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/io/Stream.h>
#include <ppp/io/MemoryStream.h>

#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/net/rinetd/RinetdConnection.h>
#include <ppp/app/client/proxys/UserspaceSubnetBridge.h>

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

#include <ppp/app/mux/vmux_net.h>
#include <ppp/app/mux/vmux_skt.h>

#include <atomic>

namespace ppp::configurations { class AppConfiguration; }

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace proxys {
                class VEthernetLocalProxySwitcher;

                /**
                 * @brief Handles the lifecycle of one accepted local proxy client connection.
                 */
                class VEthernetLocalProxyConnection : public std::enable_shared_from_this<VEthernetLocalProxyConnection> {
                public:
                    typedef ppp::net::rinetd::RinetdConnection                          RinetdConnection;
                    typedef ppp::configurations::AppConfiguration                       AppConfiguration;
                    typedef std::shared_ptr<AppConfiguration>                           AppConfigurationPtr;
                    typedef ppp::threading::Executors                                   Executors;
                    typedef std::shared_ptr<boost::asio::io_context>                    ContextPtr;
                    typedef ppp::transmissions::ITransmission                           ITransmission;
                    typedef std::shared_ptr<ITransmission>                              ITransmissionPtr;
                    typedef ITransmission::AsynchronousWriteCallback                    AsynchronousWriteCallback;
                    typedef ppp::coroutines::YieldContext                               YieldContext;
                    typedef std::shared_ptr<VEthernetExchanger>                         VEthernetExchangerPtr;
                    typedef std::shared_ptr<VEthernetLocalProxySwitcher>                VEthernetLocalProxySwitcherPtr;
                    typedef ppp::app::protocol::VirtualEthernetTcpipConnection          VirtualEthernetTcpipConnection;
                    typedef std::shared_ptr<VirtualEthernetTcpipConnection>             VirtualEthernetTcpipConnectionPtr;

                public:
                    /**
                     * @brief Constructs a local proxy connection bound to runtime resources.
                     * @param proxy Owning proxy switcher.
                     * @param exchanger Exchanger used to establish remote data paths.
                     * @param context I/O context for asynchronous execution.
                     * @param strand Strand for serialized callbacks.
                     * @param socket Accepted local client socket.
                     */
                    VEthernetLocalProxyConnection(const VEthernetLocalProxySwitcherPtr& proxy,
                        const VEthernetExchangerPtr&                                    exchanger,
                        const std::shared_ptr<boost::asio::io_context>&                 context,
                        const ppp::threading::Executors::StrandPtr&                     strand,
                        const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept;
                    /**
                     * @brief Destroys the local proxy connection and releases resources.
                     */
                    virtual ~VEthernetLocalProxyConnection() noexcept;

                public:
                    bool                                                                IsDisposed()         noexcept { return disposed_.load(std::memory_order_acquire); }
                    VEthernetExchangerPtr&                                              GetExchanger()       noexcept { return exchanger_; }
                    ContextPtr&                                                         GetContext()         noexcept { return context_; }
                    ppp::threading::Executors::StrandPtr&                               GetStrand()          noexcept { return strand_; }
                    AppConfigurationPtr&                                                GetConfiguration()   noexcept { return configuration_; }
                    VEthernetLocalProxySwitcherPtr&                                     GetProxy()           noexcept { return proxy_; }
                    std::shared_ptr<boost::asio::ip::tcp::socket>&                      GetSocket()          noexcept { return socket_; }
                    std::shared_ptr<ppp::threading::BufferswapAllocator>&               GetBufferAllocator() noexcept { return allocator_; }
                    std::shared_ptr<VEthernetLocalProxyConnection>                      GetReference()       noexcept { return shared_from_this(); }

                public:
                    /**
                     * @brief Runs handshake and data forwarding for this connection.
                     * @param y Coroutine yield context.
                     * @return true if the connection run completes successfully.
                     */
                    virtual bool                                                        Run(YieldContext& y) noexcept;
                    /**
                     * @brief Refreshes the inactivity/connect timeout according to link state.
                     */
                    virtual void                                                        Update() noexcept;
                    /**
                     * @brief Schedules asynchronous disposal on the appropriate executor.
                     */
                    virtual void                                                        Dispose() noexcept;
                    bool                                                                IsPortAging(uint64_t now) noexcept { return disposed_.load(std::memory_order_acquire) || now >= timeout_; }
                    /**
                     * @brief Converts host/port text into a protocol endpoint descriptor.
                     * @param host Host, IP literal, or endpoint text.
                     * @param port Default destination port.
                     * @return Parsed endpoint descriptor, or null on validation failure.
                     */
                    static std::shared_ptr<ppp::app::protocol::AddressEndPoint>         GetAddressEndPointByProtocol(const ppp::string& host, int port) noexcept;

                private:
                    /**
                     * @brief Performs idempotent internal cleanup and deregistration.
                     */
                    void                                                                Finalize() noexcept;

                protected:
                    /**
                     * @brief Performs protocol-specific handshake with the local client.
                     * @param y Coroutine yield context.
                     * @return true when handshake succeeds.
                     */
                    virtual bool                                                        Handshake(YieldContext& y) noexcept = 0;
                    /**
                     * @brief Handles protocol modes that complete handshake without creating a TCP bridge.
                     * @param y Coroutine yield context.
                     * @return true if the derived protocol handled the no-bridge mode.
                     */
                    virtual bool                                                        RunAfterHandshakeWithoutBridge(YieldContext& y) noexcept;
                    /**
                     * @brief Establishes a bridge from the local socket to a remote peer.
                     * @param destinationEP Target remote endpoint descriptor.
                     * @param y Coroutine yield context.
                     * @return true if a bridge path is established.
                     */
                    bool                                                                ConnectBridgeToPeer(const std::shared_ptr<ppp::app::protocol::AddressEndPoint>& destinationEP, YieldContext& y) noexcept;
                    /** @brief Reaches a virtual-subnet peer through the in-process stack (proxy-only without a host adapter). */
                    bool                                                                ConnectUserspaceSubnet(const boost::asio::ip::address& address, int port, YieldContext& y) noexcept;
                    /**
                     * @brief Sends raw bytes from local side to the active peer bridge.
                     * @param y Coroutine yield context.
                     * @param messages Buffer pointer.
                     * @param messages_size Buffer size in bytes.
                     * @return true if write succeeds on the active channel.
                     */
                    bool                                                                SendBufferToPeer(YieldContext& y, const void* messages, int messages_size) noexcept;

                private:
                    std::atomic_bool                                                    disposed_{false};
                    std::shared_ptr<boost::asio::io_context>                            context_;
                    ppp::threading::Executors::StrandPtr                                strand_;
                    UInt64                                                              timeout_  = 0;
                    VEthernetExchangerPtr                                               exchanger_;
                    std::shared_ptr<boost::asio::ip::tcp::socket>                       socket_;
                    VirtualEthernetTcpipConnectionPtr                                   connection_;
                    AppConfigurationPtr                                                 configuration_;
                    VEthernetLocalProxySwitcherPtr                                      proxy_;
                    std::shared_ptr<ppp::threading::BufferswapAllocator>                allocator_;
                    std::shared_ptr<RinetdConnection>                                   connection_rinetd_;
                    std::shared_ptr<vmux::vmux_skt>                                     connection_mux_;
                    std::shared_ptr<UserspaceSubnetBridge>                              connection_userspace_;
#if defined(_IPHONE)
                    bool                                                                ios_child_transmission_slot_held_ = false;
                    uint64_t                                                            ios_child_transmission_slot_generation_ = 0;
#endif
                };
            }
        }
    }
}
