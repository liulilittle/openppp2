#include <ppp/ethernet/VEthernet.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/DatapathPerfJson.h>
#include <ppp/diagnostics/TelemetryFwd.h>
/**
 * @file VEthernet.cpp
 * @brief Implements TAP-facing virtual Ethernet packet dispatch and timers.
 */
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/tcp.h>
#include <ppp/net/packet/IPFragment.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>

#include <libtcpip/netstack.h>
#include <lwip/pbuf.h>

#if defined(_LINUX)
#include <linux/ppp/tap/TapLinux.h>
#endif

using ppp::threading::Timer;
using ppp::threading::Executors;
using ppp::net::IPEndPoint;
using ppp::net::native::ip_hdr;
using ppp::net::native::tcp_hdr;
using ppp::net::packet::IPFlags;
using ppp::net::packet::IPFrame;
using ppp::net::packet::BufferSegment;

namespace ppp
{
    namespace threading
    {
        bool Executors_NetstackTryExit() noexcept;
    }

    namespace ethernet
    {
        /**
         * @brief Initializes VEthernet runtime flags and context.
         */
        VEthernet::VEthernet(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet, bool mta) noexcept
            : disposed_(false)
            , lwip_(lwip)
            , vnet_(vnet)
            , mta_(mta)
            , context_(context)
        {
#if !defined(_WIN32)
            ssmt_ = 0;
#if defined(_LINUX)
            ssmt_mq_.store(false, std::memory_order_relaxed);
            ssmt_mq_to_take_effect_.store(false, std::memory_order_relaxed);
#endif
#endif
            assert(NULLPTR != context);
        }

        /**
         * @brief Finalizes VEthernet and releases all resources.
         */
        VEthernet::~VEthernet() noexcept
        {
            Finalize();
        }

        /**
         * @brief Marks object disposed and performs final cleanup.
         */
        void VEthernet::Finalize() noexcept
        {
            VEthernet* ethernet = this;
            if (ethernet)
            {
                SynchronizedObjectScope scope(syncobj_);
                disposed_.store(true, std::memory_order_release);
            }

            if (ethernet)
            {
                ethernet->ReleaseAllObjects();
            }
        }

        /**
         * @brief Releases fragmenter, netstack, TAP callbacks, workers, and timer.
         */
        void VEthernet::ReleaseAllObjects() noexcept
        {
            std::shared_ptr<IPFragment> fragment = std::atomic_exchange(&fragment_, std::shared_ptr<IPFragment>());
            if (NULLPTR != fragment)
            {
                fragment->Release();
            }

            std::shared_ptr<ITap> tap = NULLPTR;
            std::shared_ptr<VNetstack> netstack = std::atomic_exchange(&netstack_, std::shared_ptr<VNetstack>());
            if (NULLPTR != netstack)
            {
                std::shared_ptr<ITap>& netstack_tap = constantof(netstack->Tap);
                tap = std::move(netstack_tap);

                netstack->Release();
            }

            lwip::netstack::output = NULLPTR;
            lwip::netstack::accept = NULLPTR;

            if (NULLPTR != tap)
            {
                tap->SetPacketInput(NULLPTR);
                tap->Dispose();
            }

#if !defined(_WIN32)
            StopAllSsmt();
#endif
            StopTimeout();
        }

        /**
         * @brief Stops and destroys the periodic timeout timer.
         */
        void VEthernet::StopTimeout() noexcept
        {
            std::shared_ptr<ppp::threading::Timer> timeout = std::atomic_exchange(&timeout_, std::shared_ptr<ppp::threading::Timer>());
            if (NULLPTR != timeout)
            {
                timeout->Dispose();
            }
        }

        /**
         * @brief Schedules finalization on the owning io_context.
         */
        void VEthernet::Dispose() noexcept
        {
            auto self = shared_from_this();
            boost::asio::dispatch(*context_, 
                [self, this]() noexcept
                {
                    Finalize();
                });
        }

        /**
         * @brief Periodic lightweight update hook.
         */
        bool VEthernet::OnUpdate(uint64_t now) noexcept
        {
            return !disposed_.load(std::memory_order_acquire);
        }

        /**
         * @brief Periodic second-level maintenance hook.
         */
        bool VEthernet::OnTick(uint64_t now) noexcept
        {
            if (disposed_.load(std::memory_order_acquire))
            {
                return false;
            }

            std::shared_ptr<IPFragment> fragment = std::atomic_load(&fragment_);
            if (NULLPTR != fragment)
            {
                fragment->Update(now);
            }

            std::shared_ptr<VNetstack> netstack = std::atomic_load(&netstack_);
            if (NULLPTR != netstack)
            {
                netstack->Update(now);
            }

            return true;
        }

        /**
         * @brief Returns current dispose state.
         */
        bool VEthernet::IsDisposed() noexcept
        {
            return disposed_.load(std::memory_order_acquire);
        }

        /**
         * @brief Internal helper methods for packet bridge entry points.
         */
        class VETHERNET_INTERNAL final
        {
        public:
            /**
             * @brief Dispatches pbuf-backed packet into VEthernet protocol path.
             */
            static int  PacketInput(VEthernet* my, struct pbuf* packet, int packet_length, bool allocated) noexcept
            {
                struct ip_hdr* iphdr = (struct ip_hdr*)packet->payload;
                int iphdr_hlen = ip_hdr::IPH_HL(iphdr) << 2;
                int proto = ip_hdr::IPH_PROTO(iphdr);
                return my->PacketInput(iphdr, iphdr_hlen, proto, packet, packet_length, allocated);
            }
            /**
             * @brief Wraps raw ip_hdr memory into temporary pbuf and dispatches input.
             */
            static int  PacketInput(VEthernet* my, struct ip_hdr* iphdr, int packet_length) noexcept
            {
                struct pbuf packet;
                packet.flags = 0;
                packet.if_idx = UINT8_MAX;
                packet.ref = 0;
                packet.type_internal = 0;

                packet.payload = iphdr;
                packet.next = NULLPTR;
                packet.len = packet_length;
                packet.tot_len = packet_length;

                return VETHERNET_INTERNAL::PacketInput(my, &packet, packet_length, true);
            }

#if !defined(_WIN32)
        public:
            /**
             * @brief Processes SSMT TCP packet in target worker context.
             */
            static bool PacketSsmtInput(VEthernet* my, struct ip_hdr* iphdr, int iphdr_hlen, tcp_hdr* tcphdr, int tcp_len, int packet_length) noexcept 
            {
                if (my->OnPacketInput(iphdr, packet_length, iphdr_hlen, ip_hdr::IP_PROTO_TCP, my->vnet_))
                {
                    return true;
                }

                std::shared_ptr<VNetstack> netstack = std::atomic_load(&my->netstack_);
                if (NULLPTR != netstack)
                {
                    return netstack->Input(iphdr, tcphdr, tcp_len);
                }

                return false;
            }
            /**
             * @brief Routes TCP packet to one SSMT worker by flow hash.
             */
            static bool PacketSsmtInput(VEthernet* my, struct ip_hdr* iphdr, int packet_length) noexcept
            {
                using SynchronizedObjectScope = VEthernet::SynchronizedObjectScope;

                int iphdr_hlen = ip_hdr::IPH_HL(iphdr) << 2;
                int proto = ip_hdr::IPH_PROTO(iphdr);
                if (proto != ip_hdr::IP_PROTO_TCP)
                {
                    return false;
                }

                int tcp_len = packet_length - iphdr_hlen;
                Byte* ip_payload = (Byte*)iphdr + iphdr_hlen;
                tcp_hdr* tcphdr = tcp_hdr::Parse(iphdr, ip_payload, tcp_len);
                if (NULLPTR == tcphdr)
                {
                    return true;
                }

#if defined(_LINUX)
                if (my->ssmt_mq_to_take_effect_.load(std::memory_order_acquire))
                {
                    return PacketSsmtInput(my, iphdr, iphdr_hlen, tcphdr, tcp_len, packet_length);
                }
#endif

                uint64_t t = (uint64_t)(MAKE_QWORD(iphdr->dest, tcphdr->dest) + MAKE_QWORD(iphdr->src, tcphdr->src));
                uint32_t h = GetHashCode((char*)&t, sizeof(t));

                std::shared_ptr<boost::asio::io_context> context;
                for (SynchronizedObjectScope scope(my->syncobj_);;)
                {
                    std::size_t max_fork = my->sssmt_.size();
                    if (max_fork > 0) 
                    {
                        context = my->sssmt_[h % max_fork];
                        break;
                    }
                    else 
                    {
                        return false;
                    }
                }

                Byte* packet = (Byte*)Malloc(packet_length);
                if (NULLPTR == packet)
                {
                    return true;
                }
                else
                {
                    memcpy(packet, iphdr, packet_length);
                    tcphdr = (tcp_hdr*)(packet + ((Byte*)tcphdr - (Byte*)iphdr));
                    iphdr = (ip_hdr*)(packet);
                }

                auto self = my->shared_from_this();
#if defined(_LINUX)
                boost::asio::dispatch(*context, 
                    [self, my, iphdr, iphdr_hlen, tcphdr, tcp_len, packet_length, tun_fd = ppp::tap::TapLinux::GetLastHandle()]() noexcept
                    {
                        int last_fd = ppp::tap::TapLinux::SetLastHandle(tun_fd);
                        PacketSsmtInput(my, iphdr, iphdr_hlen, tcphdr, tcp_len, packet_length);
                        Mfree(iphdr);

                        if (last_fd == -1 && tun_fd != last_fd) 
                        {
                            ppp::tap::TapLinux::SetLastHandle(-1);
                        }
                    });
#else
                boost::asio::dispatch(*context, 
                    [self, my, iphdr, iphdr_hlen, tcphdr, tcp_len, packet_length]() noexcept
                    {
                        PacketSsmtInput(my, iphdr, iphdr_hlen, tcphdr, tcp_len, packet_length);
                        Mfree(iphdr);
                    });

#endif
                return true;
            }
#endif
        };

        /**
         * @brief Opens VEthernet with TAP bindings and callback pipeline.
         */
        bool VEthernet::Open(const std::shared_ptr<ITap>& tap) noexcept
        {
            if (NULLPTR == tap)
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VEthernetOpenNullTap);
            }

            if (disposed_.load(std::memory_order_acquire))
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
            }

            if (!tap->IsOpen() && !tap->Open())
            {
                return false;
            }

            std::shared_ptr<IPFragment> fragment = NewFragment();
            if (NULLPTR == fragment)
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
            }

            /**
             * @brief Ensures global lwIP loopback stack is opened once.
             */
            static class netstack_loopback final
            {
            public:
                netstack_loopback(const std::shared_ptr<ITap>& tap) noexcept
                    : opened_(false) 
                {

                }
                ~netstack_loopback() noexcept
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (exchangeof(opened_, false))
                    {
                        ppp::threading::Executors_NetstackTryExit();
                    }
                }

            public:
                /** @brief Attempts one-time netstack loopback initialization. */
                bool                            try_open_loopback() noexcept
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (opened_)
                    {
                        return true;
                    }

                    opened_ = lwip::netstack::open();
                    return opened_;
                }

            private:
                bool                            opened_;
                SynchronizedObject              syncobj_;
            } static_netstack_loopback(tap);

            std::shared_ptr<VEthernet> self = shared_from_this();
            lwip::netstack::GW              = tap->GatewayServer;
            lwip::netstack::IP              = tap->IPAddress;
            lwip::netstack::MASK            = tap->SubmaskAddress;
            lwip::netstack::Localhost       = IPEndPoint::MinPort;
            lwip::netstack::accept          = 
                [self, this](
                    boost::asio::ip::tcp::endpoint& dest, 
                    boost::asio::ip::tcp::endpoint& src,
                    uint32_t                        seq,
                    uint32_t                        ack,    
                    uint16_t                        wnd) noexcept 
                {
                    std::shared_ptr<VNetstack> netstack = std::atomic_load(&netstack_);
                    return NULLPTR != netstack ? netstack->LwIpBeginAccept(dest, src, seq, ack, wnd) : 0;
                };

            /**
             * @brief Open the process-wide loopback stack once.
             */
            if (!static_netstack_loopback.try_open_loopback())
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelLoopbackSetupFailed);
            }

            /**
             * @brief Enforces immutable lwIP addressing after stack startup.
             */
            if (lwip::netstack::GW != tap->GatewayServer ||
                lwip::netstack::IP != tap->IPAddress ||
                lwip::netstack::MASK != tap->SubmaskAddress) 
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
            }

            /** @brief Instantiate and open concrete virtual network stack. */
            std::shared_ptr<VNetstack> netstack = NewNetstack();
            if (NULLPTR == netstack)
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
            }
            else
            {
                std::shared_ptr<ITap>& netstack_tap = constantof(netstack->Tap);
                netstack_tap = tap;

                if (!netstack->Open(lwip_, 0))
                {
                    netstack->Release();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceOpenFailed);
                }
            }
 
            /** @brief Bind TAP and fragment callbacks to packet handlers. */
            auto TAP_PACKET_INPUT_EVENT = 
                [self, this](ppp::tap::ITap*, ppp::tap::ITap::PacketInputEventArgs& e) noexcept
                {
                    if (!ITap::ShouldDeliverWholeTcpV4Gso(e, CanConsumeTcpV4Gso()))
                    {
                        return false;
                    }
                    int packet_length = e.PacketLength;
                    struct ip_hdr* iphdr = ip_hdr::Parse(e.Packet, packet_length);
                    if (NULLPTR == iphdr) // INVALID IS (Destination & Mask) != Destination;
                    {
                        return OnPacketInput((Byte*)e.Packet, packet_length, vnet_);
                    }
#if !defined(_WIN32)
                    elif(mta_)
                    {
                        /** @brief Use SSMT sharding when enabled for TCP inputs. */
                        if (ssmt_ > 0 && VETHERNET_INTERNAL::PacketSsmtInput(this, iphdr, packet_length))
                        {
                            return true;
                        }

                        std::shared_ptr<boost::asio::io_context> executor = lwip::netstack::Executor;
                        if (NULLPTR == executor)
                        {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                        }

                        /**
                         * @brief Post packet processing to netstack executor in MTA mode.
                         */
                        const bool handoff_telemetry_enabled = ppp::diagnostics::datapath_perf::IsEnabled();
                        std::chrono::steady_clock::time_point t0;
                        if (handoff_telemetry_enabled)
                        {
                            t0 = std::chrono::steady_clock::now();
                        }
                        pbuf* packet = lwip::netstack_pbuf_copy(iphdr, packet_length);
                        if (NULLPTR == packet)
                        {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        }

                        std::shared_ptr<ppp::diagnostics::datapath_perf::MtaHandoffObservation> handoff_observation;
                        if (handoff_telemetry_enabled)
                        {
                            std::shared_ptr<boost::asio::io_context> producer_context = Executors::GetCurrent(false);
                            handoff_observation = std::make_shared<ppp::diagnostics::datapath_perf::MtaHandoffObservation>();
                            handoff_observation->enabled = true;
                            handoff_observation->producer_thread_id = GetCurrentThreadId();
                            handoff_observation->producer_context_token = reinterpret_cast<uintptr_t>(producer_context.get());
                            handoff_observation->target_context_token = reinterpret_cast<uintptr_t>(executor.get());
                            handoff_observation->bytes = packet_length < 0 ? 0 : packet_length;
                            handoff_observation->t0 = t0;
                            handoff_observation->timeline = std::make_shared<ppp::diagnostics::datapath_perf::MtaHandoffTimeline>();
                            ppp::diagnostics::datapath_perf::RecordVnetMtaPacketPosted();
                            handoff_observation->t1 = std::chrono::steady_clock::now();
                        }
                        auto self = shared_from_this();
                        boost::asio::post(*executor, 
                            [self, this, packet, packet_length, handoff_observation]() noexcept
                            {
                                if (handoff_observation)
                                {
                                    const std::shared_ptr<ppp::diagnostics::datapath_perf::MtaHandoffTimeline>& timeline = handoff_observation->timeline;
                                    // The target can start before asio::post returns. Publish T2 with release/acquire
                                    // instead of serializing every laboratory observation through a mutex.
                                    while (!timeline->post_returned.load(std::memory_order_acquire)) {}
                                    const std::chrono::steady_clock::time_point t2 = timeline->t2;
                                    const std::chrono::steady_clock::time_point t3 = std::chrono::steady_clock::now();
                                    int status = VETHERNET_INTERNAL::PacketInput(this, packet, packet_length, false);
                                    if (status < 1)
                                    {
                                        lwip::netstack_pbuf_free(packet);
                                    }
                                    const std::chrono::steady_clock::time_point t4 = std::chrono::steady_clock::now();
                                    ppp::diagnostics::datapath_perf::RecordVnetMtaHandoffCompleted(
                                        *handoff_observation, GetCurrentThreadId(), {
                                            ppp::diagnostics::datapath_perf::ElapsedMicroseconds(handoff_observation->t0, handoff_observation->t1),
                                            ppp::diagnostics::datapath_perf::ElapsedMicroseconds(handoff_observation->t1, t2),
                                            ppp::diagnostics::datapath_perf::ElapsedMicroseconds(t2, t3),
                                            ppp::diagnostics::datapath_perf::ElapsedMicroseconds(t3, t4)
                                        });
                                }
                                else
                                {
                                    int status = VETHERNET_INTERNAL::PacketInput(this, packet, packet_length, false);
                                    if (status < 1)
                                    {
                                        lwip::netstack_pbuf_free(packet);
                                    }
                                }
                            });
                        if (handoff_observation)
                        {
                            handoff_observation->timeline->t2 = std::chrono::steady_clock::now();
                            handoff_observation->timeline->post_returned.store(true, std::memory_order_release);
                        }
                        return true;
                    }
#endif
                    else
                    {
                        VETHERNET_INTERNAL::PacketInput(this, iphdr, packet_length);
                        return true;
                    }
                };
            auto FRAGMENT_PACKET_INPUT_EVENT = 
                [self, this](IPFragment*, IPFragment::PacketInputEventArgs& e) noexcept
                {
                    OnPacketInput(e.Packet);
                };

            auto FRAGEMENT_PACKET_OUTPUT_EVENT = 
                [self, this](IPFragment*, IPFragment::PacketOutputEventArgs& e) noexcept
                {
                    Output(e.Packet, e.PacketLength);
                };

            /** @brief Publish packet output callback used by lwIP stack. */
            lwip::netstack::output = [self, this](void* packet, int size) noexcept
            {
                return Output(packet, size);
            };
            
            std::atomic_store(&netstack_, netstack);
            std::atomic_store(&fragment_, fragment);

            tap->SetPacketInput(TAP_PACKET_INPUT_EVENT);
            fragment->PacketInput  = FRAGMENT_PACKET_INPUT_EVENT;
            fragment->PacketOutput = FRAGEMENT_PACKET_OUTPUT_EVENT;

#if !defined(_WIN32)
            if (!ForkAllSsmt())
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeThreadStartFailed);
            }
#endif  
            NextTimeout();
            return true;
        }

#if !defined(_WIN32)
        /**
         * @brief Gets previous and optionally updates SSMT worker count.
         */
        int VEthernet::Ssmt(int* ssmt) noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            int snow = ssmt_;
            if (NULLPTR != ssmt)
            {
                ssmt_ = std::max<int>(0, *ssmt);
            }

            return snow;
        }

#if defined(_LINUX)
        /**
         * @brief Gets previous and optionally updates Linux multi-queue SSMT mode.
         */
        bool VEthernet::SsmtMQ(bool* mq) noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            bool snow = ssmt_mq_.load(std::memory_order_acquire);
            if (NULLPTR != mq)
            {
                ssmt_mq_.store(*mq, std::memory_order_release);
            }

            return snow;
        }
#endif

        /**
         * @brief Stops all SSMT worker io_context instances.
         */
        void VEthernet::StopAllSsmt() noexcept
        {
            std::vector<std::shared_ptr<boost::asio::io_context>/**/> stop_ssmts;
            for (SynchronizedObjectScope scope(syncobj_);;)
            {
                ssmt_mq_to_take_effect_.store(false, std::memory_order_release);
                stop_ssmts = std::move(sssmt_);
                sssmt_.clear();
                break;
            }

            for (std::shared_ptr<boost::asio::io_context>& i : stop_ssmts)
            {
                i->stop();
            }
        }
#endif

        /**
         * @brief Routes packet by protocol to TCP stack or fragment pipeline.
         */
        int VEthernet::PacketInput(ppp::net::native::ip_hdr* iphdr, int iphdr_hlen, int proto, struct pbuf* packet, int packet_length, bool allocated) noexcept
        {
            if (OnPacketInput(iphdr, packet_length, iphdr_hlen, proto, vnet_))
            {
                return 0;
            }

            if (iphdr->dest == ip_hdr::IP_ADDR_BROADCAST_VALUE)
            {
                return -1;
            }

            if (proto == ip_hdr::IP_PROTO_TCP)
            {
                std::shared_ptr<VNetstack> netstack = std::atomic_load(&netstack_);
                if (NULLPTR != netstack)
                {
                    int tcp_len = packet_length - iphdr_hlen;
                    if (lwip_)
                    {
                        if (allocated)
                        {
                            lwip::netstack::input(iphdr, packet_length);
                        }
                        elif(lwip::netstack::input(packet))
                        {
                            return 1;
                        }
                    }
                    else
                    {
                        struct tcp_hdr* tcphdr = tcp_hdr::Parse(iphdr, (Byte*)iphdr + iphdr_hlen, tcp_len); 
                        if (NULLPTR != tcphdr)
                        {
                            netstack->Input(iphdr, tcphdr, tcp_len);
                        }
                    }
                }

                return 0;
            }
            
            if (proto == ip_hdr::IP_PROTO_UDP || proto == ip_hdr::IP_PROTO_ICMP)
            {
                std::shared_ptr<IPFragment> fragment = std::atomic_load(&fragment_);
                if (NULLPTR != fragment)
                {
                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                    std::shared_ptr<IPFrame> packet = IPFrame::Parse(allocator, iphdr, packet_length);
                    if (NULLPTR != packet && !fragment->Input(packet))
                    {
                        OnPacketInput(packet);
                    }
                }

                return 0;
            }

            return -1;
        }

#if !defined(_WIN32)
        /**
         * @brief Creates and starts SSMT worker threads for TCP processing.
         */
        bool VEthernet::ForkAllSsmt() noexcept
        {
            using Awaitable = ppp::threading::Executors::Awaitable;

            /**
             * @brief Skip worker startup when lwIP is enabled or MTA is disabled.
             */
            if (lwip_ || !mta_)
            {
                return true;
            }

            /**
             * @brief Read the worker count under the lock, then release immediately.
             *
             *        The blocking Awaitable::Await() call and the Linux TAP ioctl
             *        (TapLinux::Ssmt) MUST NOT execute while syncobj_ is held.
             *        Holding syncobj_ across a blocking wait would prevent any other
             *        thread from accessing Ssmt(), SsmtMQ(), PacketSsmtInput(), or
             *        StopAllSsmt() for the entire duration of SSMT startup — a
             *        significant stall window that can appear as a deadlock to callers.
             */
            int worker_count = 0;
            {
                SynchronizedObjectScope scope(syncobj_);
                worker_count = ssmt_;
            }

            /**
             * @brief Spawn detached worker contexts and await startup readiness.
             *
             *        Each iteration:
             *          1. Creates context + awaitable (no shared state).
             *          2. Appends context to sssmt_ under a brief lock window.
             *          3. Launches the detached SSMT thread.
             *          4. Awaits thread-ready signal WITHOUT holding syncobj_.
             *          5. Performs optional Linux TAP multi-queue attachment WITHOUT
             *             holding syncobj_.
             *          6. On failure, removes the last entry from sssmt_ under lock.
             */
            for (int i = 0; i < worker_count; i++)
            {
                std::shared_ptr<boost::asio::io_context> context = make_shared_object<boost::asio::io_context>();
                if (NULLPTR == context)
                {
                    break;
                }

                std::shared_ptr<Awaitable> awaitable = std::make_shared<Awaitable>();
                if (NULLPTR == awaitable)
                {
                    break;
                }

                /**
                 * @brief Register the context into sssmt_ before launching the thread
                 *        so that StopAllSsmt() can stop it even if Await() has not yet
                 *        returned.  The lock window is intentionally minimal.
                 */
                {
                    SynchronizedObjectScope scope(syncobj_);
                    sssmt_.emplace_back(context);
                }

                std::weak_ptr<Awaitable> awaitable_weak = awaitable;
                auto process_wt = 
                    [context, awaitable_weak]() noexcept
                    {
                        if (ppp::RT) 
                        {
                            SetThreadPriorityToMaxLevel();
                        }

                        SetThreadName("ssmt");

                        auto work = boost::asio::make_work_guard(*context);
                        context->restart();

                        boost::asio::post(*context, 
                            [awaitable_weak]() noexcept 
                            {
                                std::shared_ptr<Awaitable> awaitable = awaitable_weak.lock();
                                if (NULLPTR != awaitable)
                                {
                                    awaitable->Processed();
                                }
                            });
                        try
                        {
                            context->run();
                        }
                        catch (...)
                        {
                            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "vnetstack", "ssmt worker terminated with exception");
                        }
                    };

                std::thread ssmt_thread(process_wt);
                ssmt_thread.detach();

                /**
                 * @brief Block until the SSMT thread signals readiness — WITHOUT
                 *        holding syncobj_.  This is the critical fix: previously
                 *        Await() was called inside the outer SynchronizedObjectScope,
                 *        which held syncobj_ for the entire multi-thread startup
                 *        window and could stall or deadlock concurrent callers.
                 */
                bool await_ok = awaitable->Await();
                if (!await_ok) 
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (!sssmt_.empty())
                    {
                        sssmt_.pop_back();
                    }
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeThreadStartFailed);
                }

#if defined(_LINUX)
                /** @brief Optionally attach each worker to Linux TAP multi-queue. */
                std::shared_ptr<VNetstack> netstack = std::atomic_load(&netstack_); 
                if (NULLPTR == netstack)
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }

                auto tap = netstack->Tap; 
                if (NULLPTR == tap)
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
                }

                auto linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get()); 
                if (NULLPTR == linux_tap)
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceUnsupported);
                }
                
                /**
                 * @brief TAP ioctl is also performed WITHOUT syncobj_ held.
                 *        The ioctl may block briefly on kernel round-trip; keeping
                 *        it lock-free avoids stalling concurrent packet-input threads.
                 */
                bool ssmt_ok = linux_tap->Ssmt(context);
                if (!ssmt_ok)
                {
                    context->stop();
                    
                    SynchronizedObjectScope scope(syncobj_);
                    if (!sssmt_.empty())
                    {
                        sssmt_.pop_back();
                    }
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeThreadStartFailed);
                }

                if (ssmt_mq_.load(std::memory_order_acquire))
                {
                    /**
                     * @brief ssmt_mq_to_take_effect_ is now std::atomic<bool>; the store
                     *        is lock-free and does not require syncobj_ to be held.
                     *        The release ordering ensures the flag is visible to concurrent
                     *        SSMT packet-input threads that load it with acquire.
                     */
                    ssmt_mq_to_take_effect_.store(true, std::memory_order_release);
                }
#endif
            }

            return true;
        }
#endif

        /**
         * @brief Schedules the periodic 10 ms timer loop.
         */
        bool VEthernet::NextTimeout() noexcept
        {
            std::shared_ptr<VEthernet> self = shared_from_this();
            StopTimeout();

            if (disposed_.load(std::memory_order_acquire))
            {
                return false;
            }

            std::atomic_store(&timeout_, Timer::Timeout(context_, 10,
                [self, this](Timer*) noexcept
                {
                    if (disposed_.load(std::memory_order_acquire))
                    {
                        return false;
                    }

                    uint64_t now = Executors::GetTickCount();
                    uint64_t now_seconds = now / 1000;
                    if (lasttickts_.load(std::memory_order_acquire) != now_seconds)
                    {
                        lasttickts_.store(now_seconds, std::memory_order_release);
                        OnTick(now);
                    }

                    OnUpdate(now);
                    return NextTimeout();
                }));
            return true;
        }

#ifdef SYSNAT
        /**
         * @brief Returns whether underlying VNetstack currently uses SYSNAT.
         */
        bool VEthernet::IsSysnat()                             noexcept
        {   
            std::shared_ptr<VNetstack> stack = std::atomic_load(&netstack_);
            if (stack)
            {
                return stack->sysnat_;
            }
            return false;
        }
#endif

        /** @brief Rejects whole TCPv4 GSO frames unless a derived endpoint explicitly supports them. */
        bool VEthernet::CanConsumeTcpV4Gso() noexcept
        {
            return false;
        }

        /**
         * @brief Creates default IP fragment helper.
         */
        std::shared_ptr<VEthernet::IPFragment> VEthernet::NewFragment() noexcept
        {
            return make_shared_object<IPFragment>();
        }

        /**
         * @brief Returns netstack-managed buffer allocator.
         */
        std::shared_ptr<ppp::threading::BufferswapAllocator> VEthernet::GetBufferAllocator() noexcept
        {
            std::shared_ptr<VNetstack> netstack = std::atomic_load(&netstack_);
            if (NULLPTR == netstack)
            {
                return NULLPTR;
            }
            else
            {
                return netstack->GetBufferAllocator();
            }
        }

        /**
         * @brief Default parsed packet hook implementation.
         */
        bool VEthernet::OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept
        {
            return true;
        }

        /**
         * @brief Default native packet hook implementation.
         */
        bool VEthernet::OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept
        {
            return false;
        }

        /**
         * @brief Default raw packet hook implementation.
         */
        bool VEthernet::OnPacketInput(Byte* packet, int packet_length, bool vnet) noexcept
        {
            return false;
        }

        /**
         * @brief Serializes and outputs parsed IP frame.
         *
         * @details Large IP frames (e.g. UDP datagrams reassembled from the tunnel that
         *          exceed the TAP MTU) are split into MTU-sized IPv4 fragments before
         *          output. Without this, Windows (Wintun) and macOS/iOS utun reject any
         *          write larger than ITap::Mtu and the datagram is silently dropped.
         *          IPFrame::Subpackages() is a no-op for frames that already fit the MTU.
         */
        bool VEthernet::Output(IPFrame* packet) noexcept
        {
            if (NULLPTR == packet)
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VEthernetOutputFrameNullPacket);
            }

            if (disposed_.load(std::memory_order_acquire)) 
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
            }

            std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();

            ppp::vector<IPFrame::IPFramePtr> fragments;
            int fragment_count = IPFrame::Subpackages(fragments, std::shared_ptr<IPFrame>(packet, [](const IPFrame*) noexcept {}));
            if (fragment_count <= 0)
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
            }

            if (fragment_count == 1)
            {
                std::shared_ptr<BufferSegment> messages = IPFrame::ToArray(allocator, packet);
                if (NULLPTR == messages)
                {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                }

                return Output(messages->Buffer, messages->Length);
            }

            bool any = false;
            for (const IPFrame::IPFramePtr& fragment : fragments)
            {
                if (NULLPTR == fragment)
                {
                    continue;
                }

                std::shared_ptr<BufferSegment> messages = IPFrame::ToArray(allocator, fragment.get());
                if (NULLPTR == messages)
                {
                    continue;
                }

                if (Output(messages->Buffer, messages->Length))
                {
                    any = true;
                }
            }

            return any;
        }

        /**
         * @brief Outputs raw packet memory through TAP.
         */
        bool VEthernet::Output(const void* packet, int packet_length) noexcept
        {
            if (NULLPTR == packet || packet_length < 1)
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VEthernetOutputRawInvalidArguments);
            }

            if (disposed_.load(std::memory_order_acquire))
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
            }

            std::shared_ptr<ITap> tap = GetTap();
            if (NULLPTR == tap)
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
            }

            return tap->Output(packet, packet_length);
        }

        bool VEthernet::SupportsTxGso() noexcept
        {
            if (disposed_.load(std::memory_order_acquire))
            {
                return false;
            }
            std::shared_ptr<ITap> tap = GetTap();
            return tap && tap->SupportsTxGso();
        }

        bool VEthernet::OutputGso(const std::shared_ptr<Byte>& packet, int packet_length,
            ppp::tap::TxGsoMetadata metadata) noexcept
        {
            if (NULLPTR == packet || packet_length < 1 ||
                disposed_.load(std::memory_order_acquire))
            {
                return false;
            }
            std::shared_ptr<ITap> tap = GetTap();
            return tap && tap->OutputGso(packet, packet_length, metadata);
        }

        /**
         * @brief Outputs shared packet buffer through TAP.
         */
        bool VEthernet::Output(const std::shared_ptr<Byte>& packet, int packet_length) noexcept
        {
            if (NULLPTR == packet || packet_length < 1)
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VEthernetOutputSharedInvalidArguments);
            }
            
            if (disposed_.load(std::memory_order_acquire))
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
            }

            std::shared_ptr<ITap> tap = GetTap();
            if (NULLPTR == tap)
            {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
            }

            return tap->Output(packet, packet_length);
        }
    }
}
