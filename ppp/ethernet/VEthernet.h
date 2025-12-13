#pragma once

#include <ppp/threading/Timer.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/tap/ITap.h>
#include <ppp/ethernet/VNetstack.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/tcp.h>
#include <ppp/net/packet/IPFragment.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IcmpFrame.h>

struct pbuf;

namespace ppp
{
    namespace ethernet
    {
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
            VEthernet(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet, bool mta) noexcept;
            virtual ~VEthernet() noexcept;

        public:
            std::shared_ptr<VEthernet>                                      GetReference()          noexcept { return shared_from_this(); }
            std::shared_ptr<ITap>                                           GetTap()                noexcept
            {
                std::shared_ptr<VNetstack> netstack = netstack_;
                return NULL != netstack ? netstack->Tap : NULL;
            }
            std::shared_ptr<boost::asio::io_context>                        GetContext()            noexcept { return context_; }
            std::shared_ptr<VNetstack>                                      GetNetstack()           noexcept { return netstack_; }
            SynchronizedObject&                                             GetSynchronizedObject() noexcept { return syncobj_; }
            virtual std::shared_ptr<ppp::threading::BufferswapAllocator>    GetBufferAllocator()    noexcept;

        public:
            virtual bool                                                    Open(const std::shared_ptr<ITap>& tap) noexcept;
            virtual void                                                    Dispose()                              noexcept;
            bool                                                            IsLwip()                               noexcept { return lwip_; }
            bool                                                            IsVNet()                               noexcept { return vnet_; }
            virtual bool                                                    IsDisposed()                           noexcept;

        public:
            bool                                                            Output(IPFrame* packet) noexcept;
            virtual bool                                                    Output(const void* packet, int packet_length) noexcept;
            virtual bool                                                    Output(const std::shared_ptr<Byte>& packet, int packet_length) noexcept;

        protected:
            virtual std::shared_ptr<IPFragment>                             NewFragment() noexcept;
            virtual std::shared_ptr<VNetstack>                              NewNetstack() noexcept = 0;

        protected:
            virtual bool                                                    OnTick(uint64_t now) noexcept;
            virtual bool                                                    OnUpdate(uint64_t now) noexcept;
            virtual bool                                                    OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept;
            virtual bool                                                    OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept;

        private:
            void                                                            Finalize() noexcept;
            void                                                            ReleaseAllObjects() noexcept;
            bool                                                            NextTimeout() noexcept;
            void                                                            StopTimeout() noexcept;

#if !defined(_WIN32)
        public:
            int                                                             Ssmt(int* ssmt) noexcept;
#if defined(_LINUX)
            bool                                                            SsmtMQ(bool* mq) noexcept;
#endif

        private:
            void                                                            StopAllSsmt() noexcept;
            bool                                                            ForkAllSsmt() noexcept;
#endif

        private:
            int                                                             PacketInput(ppp::net::native::ip_hdr* iphdr, int iphdr_hlen, int proto, struct pbuf* packet, int packet_length, bool allocated) noexcept;

        private:
            struct 
            {
                bool                                                        disposed_ : 1;
                bool                                                        lwip_     : 1;
                bool                                                        vnet_     : 1;
                bool                                                        mta_      : 5;
            };
#if !defined(_WIN32)
            int                                                             ssmt_     = 0;
#if defined(_LINUX)
            struct {
                bool                                                        ssmt_mq_                : 1;
                bool                                                        ssmt_mq_to_take_effect_ : 7;
            };
#endif
            std::vector<std::shared_ptr<boost::asio::io_context>/**/>       sssmt_;
#endif
            SynchronizedObject                                              syncobj_;
            std::shared_ptr<IPFragment>                                     fragment_;
            std::shared_ptr<VNetstack>                                      netstack_;
            std::shared_ptr<boost::asio::io_context>                        context_;
            std::shared_ptr<ppp::threading::Timer>                          timeout_;
            uint64_t                                                        lasttickts_ = 0;
        };
    }
}