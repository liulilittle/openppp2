#include <ppp/ethernet/VEthernet.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>

#include <libtcpip/netstack.h>
#include <lwip/pbuf.h>

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
    }

    namespace ethernet
    {
        VEthernet::VEthernet(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet) noexcept
            : disposed_(false)
            , lwip_(lwip)
            , vnet_(vnet)
            , context_(context)
            , concurrency_(ppp::threading::Executors::GetMaxConcurrency())
        {
            assert(NULL != context);
        }

        VEthernet::~VEthernet() noexcept
        {
            Finalize();
        }

        void VEthernet::Finalize() noexcept
        {
            disposed_ = true;
            Release();
        }

        void VEthernet::Release() noexcept
        {
            std::shared_ptr<IPFragment> fragment = std::move(fragment_);
            if (NULL != fragment)
            {
                fragment_.reset();
                fragment->Release();
            }

            std::shared_ptr<ITap> tap = NULL;
            std::shared_ptr<VNetstack> netstack = std::move(netstack_);
            if (NULL != netstack)
            {
                std::shared_ptr<ITap>& netstack_tap = const_cast<std::shared_ptr<ITap>&>(netstack->Tap);
                tap = std::move(netstack_tap);
                if (NULL != tap)
                {
                    netstack_tap.reset();
                }

                netstack_.reset();
                netstack->Release();
            }

            lwip::netstack::output = NULL;
            if (NULL != tap)
            {
                tap->PacketInput.reset();
                tap->Dispose();
            }

            StopTimeout();
        }

        bool VEthernet::IsLwip() noexcept
        {
            return lwip_;
        }

        bool VEthernet::IsVNet() noexcept
        {
            return vnet_;
        }

        void VEthernet::StopTimeout() noexcept
        {
            std::shared_ptr<ppp::threading::Timer> timeout = std::move(timeout_);
            if (NULL != timeout)
            {
                timeout_.reset();
                timeout->Dispose();
            }
        }

        void VEthernet::Dispose() noexcept
        {
            auto self = shared_from_this();
            std::shared_ptr<boost::asio::io_context> context = GetContext();
            context->dispatch(
                [self, this]() noexcept
                {
                    Finalize();
                });
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

            concurrency_ = ppp::threading::Executors::GetMaxConcurrency();
            return true;
        }

        std::shared_ptr<VEthernet> VEthernet::GetReference() noexcept
        {
            return shared_from_this();
        }

        std::shared_ptr<VEthernet::ITap> VEthernet::GetTap() noexcept
        {
            std::shared_ptr<VNetstack> netstack = netstack_;
            if (NULL == netstack)
            {
                return NULL;
            }
            else
            {
                return netstack->Tap;
            }
        }

        std::shared_ptr<boost::asio::io_context> VEthernet::GetContext() noexcept
        {
            return context_;
        }

        std::shared_ptr<VNetstack> VEthernet::GetNetstack() noexcept 
        {
            return netstack_;
        }

        VEthernet::SynchronizedObject& VEthernet::GetSynchronizedObject() noexcept
        {
            return syncobj_;
        }

        bool VEthernet::IsDisposed() noexcept
        {
            return disposed_;
        }

        bool VEthernet::Constructor(const std::shared_ptr<ITap>& tap) noexcept
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
                    lwip::netstack::GW = tap->GatewayServer;
                    lwip::netstack::IP = tap->IPAddress;
                    lwip::netstack::MASK = tap->SubmaskAddress;
                    lwip::netstack::Localhost = IPEndPoint::MinPort;
                    try_open_loopback();
                }
                ~netstack_loopback() noexcept 
                {
                    lwip::netstack::close();
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
                std::shared_ptr<ITap>& netstack_tap = const_cast<std::shared_ptr<ITap>&>(netstack->Tap);
                netstack_tap = tap;

                if (!netstack->Constructor(lwip_, 0))
                {
                    netstack->Release();
                    return false;
                }
            }

            // Frees all junk data generated by the last TAP object currently held by VEthernet (if it was originally held).
            std::shared_ptr<VEthernet> self = shared_from_this();
            Release();

            // The following are the associations between various resources and EAP events.
            std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
            auto TAP_PACKET_INPUT_EVENT = make_shared_object<ppp::tap::ITap::PacketInputEventHandler>(
                [self, this, allocator](ppp::tap::ITap*, ppp::tap::ITap::PacketInputEventArgs& e) noexcept
                {
                    int packet_length = e.PacketLength;
                    struct ip_hdr* iphdr = ip_hdr::Parse(e.Packet, packet_length);
                    if (NULL == iphdr) // INVALID IS (Destination & Mask) != Destination;
                    {
                        return false;
                    }
                    else
                    // If the concurrency is greater than 1, it means that you want to use multi-core, 
                    // Then the IP packet is delivered to the NIO worker thread, otherwise it is single-core, 
                    // In which case multi-threading will bring unnecessary thread switching and reduce efficiency.
#ifndef _WIN32
                    if (concurrency_ > 1)
                    {
                        struct pbuf* packet = lwip::netstack_pbuf_copy(iphdr, packet_length);
                        if (NULL == packet)
                        {
                            return false;
                        }

                        static boost::asio::io_context& executor = lwip::netstack::Executor;
                        executor.dispatch(
                            [self, this, packet, packet_length]() noexcept 
                            {
                                int status = PacketInput(packet, packet_length, false);
                                if (status < 1)
                                {
                                    lwip::netstack_pbuf_free(packet);
                                }
                            });
                        return true;
                    }
                    else 
#endif
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

#ifdef _WIN32
                        PacketInput(&packet, packet_length);
#else
                        PacketInput(&packet, packet_length, true);
#endif
                        return true;
                    }
                });

            auto FRAGMENT_PACKET_INPUT_EVENT = make_shared_object<IPFragment::PacketInputEventHandler>(
                [self, this](IPFragment*, IPFragment::PacketInputEventArgs& e) noexcept
                {
                    OnPacketInput(e.Packet);
                });

            auto FRAGEMENT_PACKET_OUTPUT_EVENT = make_shared_object<IPFragment::PacketOutputEventHandler>(
                [self, this](IPFragment*, IPFragment::PacketOutputEventArgs& e) noexcept
                {
                    Output(e.Packet, e.PacketLength);
                });

            // Check whether all callback event objects are allocated successfully.
            if (NULL == TAP_PACKET_INPUT_EVENT || NULL == FRAGMENT_PACKET_INPUT_EVENT || NULL == FRAGEMENT_PACKET_OUTPUT_EVENT)
            {
                netstack->Release();
                return false;
            }

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
            if (ok)
            {
                NextTimeout();
            }
            return ok;
        }

#ifdef _WIN32
        int VEthernet::PacketInput(struct pbuf* packet, int packet_length) noexcept
#else
        int VEthernet::PacketInput(struct pbuf* packet, int packet_length, bool allocated) noexcept
#endif
        {
            struct ip_hdr* iphdr = (struct ip_hdr*)packet->payload;
            int iphdr_hlen = ip_hdr::IPH_HL(iphdr) << 2;
            int proto = ip_hdr::IPH_PROTO(iphdr);
            if (OnPacketInput(iphdr, packet_length, iphdr_hlen, proto, vnet_))
            {
                return 0;
            }
            elif(proto == ip_hdr::IP_PROTO_TCP)
            {
                std::shared_ptr<VNetstack> netstack = netstack_;
                if (NULL != netstack)
                {
                    int tcp_len = packet_length - iphdr_hlen;
                    if (lwip_)
                    {
#ifdef _WIN32
                        lwip::netstack::input(iphdr, packet_length);
#else
                        if (allocated)
                        {
                            lwip::netstack::input(iphdr, packet_length);
                        }
                        elif(lwip::netstack::input(packet))
                        {
                            return 1;
                        }
#endif
                    }
                    else
                    {
                        Byte* ip_payload = (Byte*)iphdr + iphdr_hlen;
                        struct tcp_hdr* tcphdr = tcp_hdr::Parse(iphdr, ip_payload, tcp_len);
                        if (NULL != tcphdr)
                        {
                            netstack->Input(iphdr, tcphdr, tcp_len);
                        }
                    }
                }

                return 0;
            }
            elif(proto == ip_hdr::IP_PROTO_UDP || proto == ip_hdr::IP_PROTO_ICMP)
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
            else
            {
                return -1;
            }
        }

        void VEthernet::NextTimeout() noexcept
        {
            std::shared_ptr<VEthernet> self = shared_from_this();
            StopTimeout();

            auto cb = make_shared_object<Timer::TimeoutEventHandler>(
                [self, this]() noexcept
                {
                    bool b = disposed_;
                    if (!b)
                    {
                        uint64_t now = Executors::GetTickCount();
                        OnTick(now);
                        NextTimeout();
                    }
                });
            timeout_ = Timer::Timeout(context_, 1000, cb);
        }

        std::shared_ptr<VEthernet::IPFragment> VEthernet::NewFragment() noexcept
        {
            return make_shared_object<IPFragment>();
        }

        std::shared_ptr<VNetstack> VEthernet::NewNetstack() noexcept
        {
            return make_shared_object<VNetstack>();
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

            std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
            std::shared_ptr<BufferSegment> messages = IPFrame::ToArray(allocator, packet);
            if (NULL == messages) {
                return false;
            }

            return Output(messages->Buffer, messages->Length);
        }

        bool VEthernet::Output(const void* packet, int packet_length) noexcept
        {
            std::shared_ptr<ITap> tap = GetTap();
            if (NULL != tap)
            {
                return tap->Output(packet, packet_length);
            }
            else
            {
                return false;
            }
        }

        bool VEthernet::Output(const std::shared_ptr<Byte>& packet, int packet_length) noexcept
        {
            std::shared_ptr<ITap> tap = GetTap();
            if (NULL != tap)
            {
                return tap->Output(packet, packet_length);
            }
            else
            {
                return false;
            }
        }
    }
}