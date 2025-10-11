#include <ppp/ethernet/VEthernet.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
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
        void Executors_NetstackAllocExitAwaitable() noexcept;
        bool Executors_NetstackTryExit() noexcept;
    }

    namespace ethernet
    {
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
            ssmt_mq_ = false;
            ssmt_mq_to_take_effect_ = false;
#endif
#endif
            assert(NULL != context);
        }

        VEthernet::~VEthernet() noexcept
        {
            Finalize();
        }

        void VEthernet::Finalize() noexcept
        {
            VEthernet* ethernet = this;
            if (ethernet)
            {
                SynchronizedObjectScope scope(syncobj_);
                disposed_ = true;
            }

            if (ethernet)
            {
                ethernet->ReleaseAllObjects();
            }
        }

        void VEthernet::ReleaseAllObjects() noexcept
        {
            std::shared_ptr<IPFragment> fragment = std::move(fragment_);
            fragment_.reset();

            if (NULL != fragment)
            {
                fragment->Release();
            }

            std::shared_ptr<ITap> tap = NULL;
            std::shared_ptr<VNetstack> netstack = std::move(netstack_);
            if (NULL != netstack)
            {
                std::shared_ptr<ITap>& netstack_tap = constantof(netstack->Tap);
                tap = std::move(netstack_tap);
                
                netstack_.reset();
                netstack_tap.reset();

                netstack->Release();
            }

            lwip::netstack::output = NULL;
            if (NULL != tap)
            {
                tap->PacketInput.reset();
                tap->Dispose();
            }

#if !defined(_WIN32)
            StopAllSsmt();
#endif
            StopTimeout();
        }

        void VEthernet::StopTimeout() noexcept
        {
            std::shared_ptr<ppp::threading::Timer> timeout = std::move(timeout_);
            timeout_.reset();

            if (NULL != timeout)
            {
                timeout->Dispose();
            }
        }

        void VEthernet::Dispose() noexcept
        {
            auto self = shared_from_this();
            boost::asio::dispatch(*context_, 
                [self, this]() noexcept
                {
                    Finalize();
                });
        }

        bool VEthernet::OnUpdate(uint64_t now) noexcept
        {
            return !disposed_;
        }

        bool VEthernet::OnTick(uint64_t now) noexcept
        {
            if (disposed_)
            {
                return false;
            }

            std::shared_ptr<IPFragment> fragment = fragment_;
            if (NULL != fragment)
            {
                fragment->Update(now);
            }

            std::shared_ptr<VNetstack> netstack = netstack_;
            if (NULL != netstack)
            {
                netstack->Update(now);
            }

            return true;
        }

        bool VEthernet::IsDisposed() noexcept
        {
            return disposed_;
        }

        class VETHERNET_INTERNAL final
        {
        public:
            static int  PacketInput(VEthernet* my, struct pbuf* packet, int packet_length, bool allocated) noexcept
            {
                struct ip_hdr* iphdr = (struct ip_hdr*)packet->payload;
                int iphdr_hlen = ip_hdr::IPH_HL(iphdr) << 2;
                int proto = ip_hdr::IPH_PROTO(iphdr);
                return my->PacketInput(iphdr, iphdr_hlen, proto, packet, packet_length, allocated);
            }
            static int  PacketInput(VEthernet* my, struct ip_hdr* iphdr, int packet_length) noexcept
            {
                struct pbuf packet;
                packet.flags = 0;
                packet.if_idx = UINT8_MAX;
                packet.ref = 0;
                packet.type_internal = 0;

                packet.payload = iphdr;
                packet.next = NULL;
                packet.len = packet_length;
                packet.tot_len = packet_length;

                return VETHERNET_INTERNAL::PacketInput(my, &packet, packet_length, true);
            }

#if !defined(_WIN32)
        public:
            static bool PacketSsmtInput(VEthernet* my, struct ip_hdr* iphdr, int iphdr_hlen, tcp_hdr* tcphdr, int tcp_len, int packet_length) noexcept 
            {
                if (my->OnPacketInput(iphdr, packet_length, iphdr_hlen, ip_hdr::IP_PROTO_TCP, my->vnet_))
                {
                    return true;
                }

                std::shared_ptr<VNetstack> netstack = my->netstack_;
                if (NULL != netstack)
                {
                    return netstack->Input(iphdr, tcphdr, tcp_len);
                }

                return false;
            }
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
                if (NULL == tcphdr)
                {
                    return true;
                }

#if defined(_LINUX)
                if (my->ssmt_mq_to_take_effect_)
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
                if (NULL == packet)
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

        bool VEthernet::Open(const std::shared_ptr<ITap>& tap) noexcept
        {
            if (NULL == tap)
            {
                return false;
            }

            if (disposed_)
            {
                return false;
            }

            if (!tap->IsReady())
            {
                return false;
            }

            std::shared_ptr<IPFragment> fragment = NewFragment();
            if (NULL == fragment)
            {
                return false;
            }

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
                bool                            try_open_loopback() noexcept
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (opened_)
                    {
                        return true;
                    }

                    opened_ = lwip::netstack::open();
                    if (opened_)
                    {
                        ppp::threading::Executors_NetstackAllocExitAwaitable();
                    }
                    
                    return opened_;
                }

            private:
                bool                            opened_;
                SynchronizedObject              syncobj_;
            } static_netstack_loopback(tap);

            lwip::netstack::GW = tap->GatewayServer;
            lwip::netstack::IP = tap->IPAddress;
            lwip::netstack::MASK = tap->SubmaskAddress;
            lwip::netstack::Localhost = IPEndPoint::MinPort;

            // An attempt has been made to open the local loop of the virtual network card.  
            // If the virtual network card is opened or has been opened before, the operation succeeds. 
            // If the virtual network card cannot be opened, a failure is returned.
            if (!static_netstack_loopback.try_open_loopback())
            {
                return false;
            }

            // If the virtual network stack is already running, you cannot change the IP, MASK, and GW address of the virtual network card, 
            // Because the LWIP-@C network stack is difficult to support such behavior, 
            // Which is handled here to ensure the compatibility of the project code.
            if (lwip::netstack::GW != tap->GatewayServer ||
                lwip::netstack::IP != tap->IPAddress ||
                lwip::netstack::MASK != tap->SubmaskAddress) 
            {
                return false;
            }

            // Instantiate and construct a new Netstack processing object.
            std::shared_ptr<VNetstack> netstack = NewNetstack();
            if (NULL == netstack)
            {
                return false;
            }
            else
            {
                std::shared_ptr<ITap>& netstack_tap = constantof(netstack->Tap);
                netstack_tap = tap;

                if (!netstack->Open(lwip_, 0))
                {
                    netstack->Release();
                    return false;
                }
            }
 
            // The following are the associations between various resources and EAP events.
            std::shared_ptr<VEthernet> self = shared_from_this();
            auto TAP_PACKET_INPUT_EVENT = 
                [self, this](ppp::tap::ITap*, ppp::tap::ITap::PacketInputEventArgs& e) noexcept
                {
                    int packet_length = e.PacketLength;
                    struct ip_hdr* iphdr = ip_hdr::Parse(e.Packet, packet_length);
                    if (NULL == iphdr) // INVALID IS (Destination & Mask) != Destination;
                    {
                        return false;
                    }
#if !defined(_WIN32)
                    elif(mta_)
                    {
                        // If tcp/ip synchronization is enabled in the case of multithreading.
                        if (ssmt_ > 0 && VETHERNET_INTERNAL::PacketSsmtInput(this, iphdr, packet_length))
                        {
                            return true;
                        }

                        std::shared_ptr<boost::asio::io_context> executor = lwip::netstack::Executor;
                        if (NULL == executor)
                        {
                            return false;
                        }

                        // If the concurrency is greater than 1, it means that you want to use multi-core, 
                        // Then the IP packet is delivered to the NIO worker thread, otherwise it is single-core, 
                        // In which case multi-threading will bring unnecessary thread switching and reduce efficiency.
                        pbuf* packet = lwip::netstack_pbuf_copy(iphdr, packet_length);
                        if (NULL == packet)
                        {
                            return false;
                        }

                        auto self = shared_from_this();
                        boost::asio::post(*executor, 
                            [self, this, packet, packet_length]() noexcept
                            {
                                int status = VETHERNET_INTERNAL::PacketInput(this, packet, packet_length, false);
                                if (status < 1)
                                {
                                    lwip::netstack_pbuf_free(packet);
                                }
                            });
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

            // Check whether all callback event objects are allocated successfully.
            lwip::netstack::output = [self, this](void* packet, int size) noexcept
            {
                return Output(packet, size);
            };
            
            netstack_              = netstack;
            fragment_              = fragment;

            tap->PacketInput       = TAP_PACKET_INPUT_EVENT;
            fragment->PacketInput  = FRAGMENT_PACKET_INPUT_EVENT;
            fragment->PacketOutput = FRAGEMENT_PACKET_OUTPUT_EVENT;
            
            // If the TAP virtual NIC object is unopened, open the TAP virtual NIC object otherwise.
            bool ok = tap->IsOpen() || tap->Open();
#if !defined(_WIN32)
            ok = ok && ForkAllSsmt();
#endif
            if (ok)
            {
                NextTimeout();
            }
            return ok;
        }

#if !defined(_WIN32)
        int VEthernet::Ssmt(int* ssmt) noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            int snow = ssmt_;
            if (NULL != ssmt)
            {
                ssmt_ = std::max<int>(0, *ssmt);
            }

            return snow;
        }

#if defined(_LINUX)
        bool VEthernet::SsmtMQ(bool* mq) noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            bool snow = ssmt_mq_;
            if (NULL != mq)
            {
                ssmt_mq_ = *mq;
            }

            return snow;
        }
#endif

        void VEthernet::StopAllSsmt() noexcept
        {
            std::vector<std::shared_ptr<boost::asio::io_context>/**/> stop_ssmts;
            for (SynchronizedObjectScope scope(syncobj_);;)
            {
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
                std::shared_ptr<VNetstack> netstack = netstack_;
                if (NULL != netstack)
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
                        if (NULL != tcphdr)
                        {
                            netstack->Input(iphdr, tcphdr, tcp_len);
                        }
                    }
                }

                return 0;
            }
            
            if (proto == ip_hdr::IP_PROTO_UDP || proto == ip_hdr::IP_PROTO_ICMP)
            {
                std::shared_ptr<IPFragment> fragment = fragment_;
                if (NULL != fragment)
                {
                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                    std::shared_ptr<IPFrame> packet = IPFrame::Parse(allocator, iphdr, packet_length);
                    if (NULL != packet && !fragment->Input(packet))
                    {
                        OnPacketInput(packet);
                    }
                }

                return 0;
            }

            return -1;
        }

#if !defined(_WIN32)
        bool VEthernet::ForkAllSsmt() noexcept
        {
            using Awaitable = ppp::threading::Executors::Awaitable;

            // In the case of allowing multi-threaded concurrent processing, 
            // Open the vnet hyper-threading technology, improve the virtual NIC I/O network throughput, 
            // Maximize the drain of hardware resources, which is very effective on very low configuration devices.
            if (lwip_ || !mta_)
            {
                return true;
            }

            // This code has been tested on the "Player Cloud Amlogic S805 chip", the original maximum is only 150Mbps, 
            // And now it can achieve a larger network throughput and use all the CPU resources.
            SynchronizedObjectScope scope(syncobj_);
            for (int i = 0; i < ssmt_; i++)
            {
                std::shared_ptr<boost::asio::io_context> context = make_shared_object<boost::asio::io_context>();
                if (NULL == context)
                {
                    break;
                }

                std::shared_ptr<Awaitable> awaitable = std::make_shared<Awaitable>();
                if (NULL == awaitable)
                {
                    break;
                }

                std::weak_ptr<Awaitable> awaitable_weak = awaitable;
                sssmt_.emplace_back(context);

                auto process = 
                    [context, awaitable_weak]() noexcept
                    {
                        SetThreadPriorityToMaxLevel();
                        SetThreadName("ssmt");

                        boost::asio::io_context::work work(*context);
                        boost::system::error_code ec;

                        context->restart();
                        boost::asio::post(*context, 
                            [awaitable_weak]() noexcept 
                            {
                                std::shared_ptr<Awaitable> awaitable = awaitable_weak.lock();
                                if (NULL != awaitable)
                                {
                                    awaitable->Processed();
                                }
                            });
                        context->run(ec);
                    };
                std::thread(process).detach();

                bool await_ok = awaitable->Await();
                if (!await_ok) 
                {
                    return false;
                }

#if defined(_LINUX)
                // On Linux platforms, tun/tap multi-queue mode can be turned on to squeeze the hardware cpu power as much as possible.
                std::shared_ptr<VNetstack> netstack = netstack_; 
                if (NULL == netstack)
                {
                    return false;
                }

                auto tap = netstack->Tap; 
                if (NULL == tap)
                {
                    return false;
                }

                auto linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get()); 
                if (NULL == linux_tap)
                {
                    return false;
                }
                
                bool ssmt_ok = linux_tap->Ssmt(context);
                if (ssmt_mq_)
                {
                    ssmt_mq_to_take_effect_ |= ssmt_ok;
                }
#endif
            }

            return true;
        }
#endif

        bool VEthernet::NextTimeout() noexcept
        {
            std::shared_ptr<VEthernet> self = shared_from_this();
            StopTimeout();

            if (disposed_)
            {
                return false;
            }

            timeout_ = Timer::Timeout(context_, 10, 
                [self, this](Timer*) noexcept
                {
                    if (disposed_)
                    {
                        return false;
                    }

                    uint64_t now = Executors::GetTickCount();
                    uint64_t now_seconds = now / 1000; 
                    if (lasttickts_ != now_seconds)
                    {
                        lasttickts_ = now_seconds;
                        OnTick(now);
                    }

                    OnUpdate(now);
                    return NextTimeout();
                });
            return true;
        }

        std::shared_ptr<VEthernet::IPFragment> VEthernet::NewFragment() noexcept
        {
            return make_shared_object<IPFragment>();
        }

        std::shared_ptr<ppp::threading::BufferswapAllocator> VEthernet::GetBufferAllocator() noexcept
        {
            std::shared_ptr<VNetstack> netstack = netstack_;
            if (NULL == netstack)
            {
                return NULL;
            }
            else
            {
                return netstack->GetBufferAllocator();
            }
        }

        bool VEthernet::OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept
        {
            return true;
        }

        bool VEthernet::OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept
        {
            return false;
        }

        bool VEthernet::Output(IPFrame* packet) noexcept
        {
            if (NULL == packet)
            {
                return false;
            }

            if (disposed_) 
            {
                return false;
            }

            std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
            std::shared_ptr<BufferSegment> messages = IPFrame::ToArray(allocator, packet);
            if (NULL == messages) 
            {
                return false;
            }

            return Output(messages->Buffer, messages->Length);
        }

        bool VEthernet::Output(const void* packet, int packet_length) noexcept
        {
            if (NULL == packet || packet_length < 1)
            {
                return false;
            }

            if (disposed_)
            {
                return false;
            }

            std::shared_ptr<ITap> tap = GetTap();
            if (NULL == tap)
            {
                return false;
            }

            return tap->Output(packet, packet_length);
        }

        bool VEthernet::Output(const std::shared_ptr<Byte>& packet, int packet_length) noexcept
        {
            if (NULL == packet || packet_length < 1)
            {
                return false;
            }
            
            if (disposed_)
            {
                return false;
            }

            std::shared_ptr<ITap> tap = GetTap();
            if (NULL == tap)
            {
                return false;   
            }

            return tap->Output(packet, packet_length);
        }
    }
}