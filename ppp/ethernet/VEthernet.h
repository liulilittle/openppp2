#pragma once

/**
 * @file VEthernet.h
 * @brief Declares the virtual Ethernet endpoint abstraction and packet flow hooks.
 */

#include <ppp/ethernet/VNetstack.h>

struct pbuf;

namespace ppp {
    namespace threading {
        class Timer;
        class BufferswapAllocator;
    }
    namespace net {
        namespace native {
            struct ip_hdr;
        }
        namespace packet {
            class IPFragment;
            class IPFrame;
            class UdpFrame;
            class IcmpFrame;
        }
    }
}

namespace ppp
{
    namespace ethernet
    {
        /**
         * @brief Owns a TAP-backed virtual Ethernet pipeline.
         *
         * The object wires TAP input/output with the virtual TCP/IP stack, packet
         * fragmentation, and periodic maintenance callbacks.
         */
        class VEthernet : public std::enable_shared_from_this<VEthernet>
        {
            friend class                                                    VETHERNET_INTERNAL;
            
        public:
            typedef ppp::tap::ITap                                          ITap;
            typedef ppp::net::packet::IPFragment                            IPFragment;
            typedef ppp::net::packet::IPFrame                               IPFrame;
            typedef ppp::net::packet::UdpFrame                              UdpFrame;
            typedef ppp::net::packet::IcmpFrame                             IcmpFrame;
            typedef std::mutex                                              SynchronizedObject;
            typedef std::lock_guard<SynchronizedObject>                     SynchronizedObjectScope;

        public:
            /**
             * @brief Constructs a virtual Ethernet endpoint.
             * @param context Asio execution context used for async operations.
             * @param lwip Enables lwIP mode when true.
             * @param vnet Enables virtual network packet interception mode when true.
             * @param mta Enables multi-threaded acceleration mode when true.
             */
            VEthernet(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet, bool mta) noexcept;
            /**
             * @brief Releases runtime resources.
             */
            virtual ~VEthernet() noexcept;

        public:
            /**
             * @brief Returns a shared reference to this object.
             */
            std::shared_ptr<VEthernet>                                      GetReference()          noexcept { return shared_from_this(); }
            /**
             * @brief Returns the bound TAP device.
             * @note  netstack_ is cross-thread; obtain via atomic_load, then read Tap.
             */
            std::shared_ptr<ITap>                                           GetTap()                noexcept
            {
                std::shared_ptr<VNetstack> netstack = std::atomic_load(&netstack_);
                return NULLPTR != netstack ? netstack->Tap : NULLPTR;
            }
            /**
             * @brief Returns the execution context.
             */
            std::shared_ptr<boost::asio::io_context>                        GetContext()            noexcept { return context_; }
            /**
             * @brief Returns the active virtual network stack object.
             * @note  netstack_ is written on the open/close path and read from any thread;
             *        use std::atomic_load to prevent a data race.
             */
            std::shared_ptr<VNetstack>                                      GetNetstack()           noexcept { return std::atomic_load(&netstack_); }
            /**
             * @brief Returns the synchronization object guarding shared state.
             */
            SynchronizedObject&                                             GetSynchronizedObject() noexcept { return syncobj_; }
            /**
             * @brief Returns the buffer allocator used for packet allocations.
             */
            virtual std::shared_ptr<ppp::threading::BufferswapAllocator>    GetBufferAllocator()    noexcept;

        public:
            /**
             * @brief Opens the endpoint and binds it to a TAP device.
             * @param tap TAP device instance.
             * @return true if initialization succeeds; otherwise false.
             */
            virtual bool                                                    Open(const std::shared_ptr<ITap>& tap) noexcept;
            /**
             * @brief Requests asynchronous disposal of this endpoint.
             */
            virtual void                                                    Dispose()                              noexcept;
            /**
             * @brief Returns whether lwIP mode is enabled.
             */
            bool                                                            IsLwip()                               noexcept { return lwip_; }
            /**
             * @brief Returns whether virtual-network interception mode is enabled.
             */
            bool                                                            IsVNet()                               noexcept { return vnet_; }
#ifdef SYSNAT
            /**
             * @brief Returns whether SYSNAT mode is active.
             */
            bool                                                            IsSysnat()                             noexcept;
#endif
            /**
             * @brief Returns whether this endpoint has been disposed.
             */
            virtual bool                                                    IsDisposed()                           noexcept;

        public:
            /**
             * @brief Sends an IP frame through the TAP output path.
             * @param packet Parsed IP frame object.
             * @return true if the packet is dispatched; otherwise false.
             */
            bool                                                            Output(IPFrame* packet) noexcept;
            /**
             * @brief Sends a raw packet through the TAP output path.
             * @param packet Raw packet bytes.
             * @param packet_length Packet size in bytes.
             * @return true if the packet is dispatched; otherwise false.
             */
            virtual bool                                                    Output(const void* packet, int packet_length) noexcept;
            /**
             * @brief Sends a shared raw packet through the TAP output path.
             * @param packet Shared packet buffer.
             * @param packet_length Packet size in bytes.
             * @return true if the packet is dispatched; otherwise false.
             */
            virtual bool                                                    Output(const std::shared_ptr<Byte>& packet, int packet_length) noexcept;
            /** @brief Returns whether the bound TAP supports explicit TCPv4 GSO output. */
            bool                                                            SupportsTxGso() noexcept;
            /** @brief Sends a shared super-packet only through the explicit TAP GSO path. */
            virtual bool                                                    OutputGso(const std::shared_ptr<Byte>& packet, int packet_length, ppp::tap::TxGsoMetadata metadata) noexcept;

        protected:
            /**
             * @brief Returns whether this endpoint can synchronously consume a complete TCPv4 GSO frame.
             * @note The default is false so non-XTCP paths use the TAP backend's per-MSS fallback.
             */
            virtual bool                                                    CanConsumeTcpV4Gso() noexcept;
            /**
             * @brief Creates an IP fragment reassembly helper.
             */
            virtual std::shared_ptr<IPFragment>                             NewFragment() noexcept;
            /**
             * @brief Creates the concrete virtual network stack implementation.
             */
            virtual std::shared_ptr<VNetstack>                              NewNetstack() noexcept = 0;

        protected:
                /**
                 * @brief Called once per second while the endpoint is active.
                 * @param now Current monotonic tick in milliseconds.
                 */
                virtual bool                                                    OnTick(uint64_t now) noexcept;
                /**
                 * @brief Called periodically by the timer loop.
                 * @param now Current monotonic tick in milliseconds.
                 */
                virtual bool                                                    OnUpdate(uint64_t now) noexcept;
                /**
                 * @brief Handles fully parsed IP frame input.
                 * @param packet Parsed frame.
                 */
                virtual bool                                                    OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept;
                /**
                 * @brief Handles native IP header input.
                 * @param packet Native IP header pointer.
                 * @param packet_length Total packet size in bytes.
                 * @param header_length Header size in bytes.
                 * @param proto Transport protocol id.
                 * @param vnet Whether packet is handled in vnet mode.
                 */
                virtual bool                                                    OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept;
                /**
                 * @brief Handles raw packet input.
                 * @param packet Packet bytes.
                 * @param packet_length Packet size in bytes.
                 * @param vnet Whether packet is handled in vnet mode.
                 */
                virtual bool                                                    OnPacketInput(Byte* packet, int packet_length, bool vnet) noexcept;

        private:
            /** @brief Finalizes and releases all owned resources. */
            void                                                            Finalize() noexcept;
            /** @brief Releases network stack, fragmenter, TAP, and callbacks. */
            void                                                            ReleaseAllObjects() noexcept;
            /** @brief Arms the periodic timer callback loop. */
            bool                                                            NextTimeout() noexcept;
            /** @brief Stops the periodic timer callback loop. */
            void                                                            StopTimeout() noexcept;

#if !defined(_WIN32)
        public:
            /**
             * @brief Gets or sets the SSMT worker count.
             * @param ssmt Optional input value to update worker count.
             * @return Previous worker count.
             */
            int                                                             Ssmt(int* ssmt) noexcept;
#if defined(_LINUX)
            /**
             * @brief Gets or sets Linux TAP multi-queue SSMT mode.
             * @param mq Optional input value to update mode.
             * @return Previous mode value.
             */
            bool                                                            SsmtMQ(bool* mq) noexcept;
#endif

        private:
            /** @brief Stops all SSMT worker executors. */
            void                                                            StopAllSsmt() noexcept;
            /** @brief Creates and starts all configured SSMT workers. */
            bool                                                            ForkAllSsmt() noexcept;
#endif

        private:
            /**
             * @brief Dispatches an incoming packet by protocol.
             * @return Status code consumed by caller-owned pbuf lifecycle.
             */
            int                                                             PacketInput(ppp::net::native::ip_hdr* iphdr, int iphdr_hlen, int proto, struct pbuf* packet, int packet_length, bool allocated) noexcept;

        private:
            /**
             * @brief Disposal flag.
             * @note  Written inside syncobj_ lock in Finalize(); read lock-free from timer
             *        callbacks, Output(), OnTick() etc.  Must be std::atomic<bool> to prevent
             *        a data race between the finalizer and concurrent readers.
             */
            std::atomic<bool>                                               disposed_ = { false };
            /** @brief Enables lwIP-based virtual TCP/IP stack when true. */
            bool                                                            lwip_     = false;
            /** @brief Enables virtual-network packet interception mode when true. */
            bool                                                            vnet_     = false;
            /** @brief Enables multi-threaded acceleration (SSMT) mode when true. */
            bool                                                            mta_      = false;
#if !defined(_WIN32)
            /** @brief Number of SSMT worker executor threads currently running. */
            int                                                             ssmt_     = 0;
#if defined(_LINUX)
            /**
             * @brief Desired Linux TAP multi-queue (MQ) SSMT mode.
             * @note  Written inside syncobj_ in SsmtMQ(); read lock-free from ForkAllSsmt().
             *        Must be std::atomic<bool> to prevent a data race between the writer
             *        and the concurrent lock-free reader.
             */
            std::atomic<bool>                                               ssmt_mq_                = { false };
#endif
            /**
             * @brief Signals that MQ mode has taken effect.
             * @note  Written under syncobj_ in ForkAllSsmt()/StopAllSsmt(); read lock-free
             *        from SSMT packet-input threads.  Must be std::atomic<bool> to prevent
             *        a data race between the writer and concurrent SSMT readers.
             *        Declared unconditionally in the !_WIN32 block because StopAllSsmt()
             *        references it without a _LINUX guard; on non-Linux platforms the flag
             *        simply stays false.
             */
            std::atomic<bool>                                               ssmt_mq_to_take_effect_ = { false };
            /** @brief SSMT worker io_context instances (one per SSMT thread). */
            std::vector<std::shared_ptr<boost::asio::io_context>/**/>       sssmt_;
#endif
            /** @brief Mutex guarding open/close lifecycle and shared object tables. */
            SynchronizedObject                                              syncobj_;
            /** @brief IP fragment reassembly helper. */
            std::shared_ptr<IPFragment>                                     fragment_;
            /** @brief Active virtual TCP/IP network stack instance. */
            std::shared_ptr<VNetstack>                                      netstack_;
            /** @brief Asio context shared with the virtual stack and packet pipeline. */
            std::shared_ptr<boost::asio::io_context>                        context_;
            /**
             * @brief Periodic timer driving OnTick()/OnUpdate() callbacks.
             * @note  Accessed exclusively via std::atomic_load / std::atomic_store /
             *        std::atomic_exchange free functions (C++17 pattern): StopTimeout()
             *        exchanges it from the finalizer thread while the timer callback
             *        re-arms it through NextTimeout() on an IO worker thread.
             */
            std::shared_ptr<ppp::threading::Timer>                          timeout_;
            /** @brief Millisecond timestamp of the last OnTick() invocation. */
            std::atomic<uint64_t>                                           lasttickts_ = { 0 };
        };
    }
}
