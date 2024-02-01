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
        public:
            typedef ppp::tap::ITap                                          ITap;
            typedef ppp::net::packet::IPFragment                            IPFragment;
            typedef ppp::net::packet::IPFrame                               IPFrame;
            typedef ppp::net::packet::UdpFrame                              UdpFrame;
            typedef ppp::net::packet::IcmpFrame                             IcmpFrame;
            typedef std::mutex                                              SynchronizedObject;
            typedef std::lock_guard<SynchronizedObject>                     SynchronizedObjectScope;

        public:
            VEthernet(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet) noexcept;
            virtual ~VEthernet() noexcept;

        public:
            std::shared_ptr<VEthernet>                                      GetReference() noexcept;
            std::shared_ptr<ITap>                                           GetTap() noexcept;
            std::shared_ptr<boost::asio::io_context>                        GetContext() noexcept;
            std::shared_ptr<VNetstack>                                      GetNetstack() noexcept;
            SynchronizedObject&                                             GetSynchronizedObject() noexcept;
            virtual std::shared_ptr<ppp::threading::BufferswapAllocator>    GetBufferAllocator() noexcept;

        public:
            virtual bool                                                    Constructor(const std::shared_ptr<ITap>& tap) noexcept;
            virtual void                                                    Dispose() noexcept;
            bool                                                            IsLwip() noexcept;
            bool                                                            IsVNet() noexcept;
            virtual bool                                                    IsDisposed() noexcept;

        public:
            bool                                                            Output(IPFrame* packet) noexcept;
            virtual bool                                                    Output(const void* packet, int packet_length) noexcept;
            virtual bool                                                    Output(const std::shared_ptr<Byte>& packet, int packet_length) noexcept;

        protected:
            virtual std::shared_ptr<IPFragment>                             NewFragment() noexcept;
            virtual std::shared_ptr<VNetstack>                              NewNetstack() noexcept;
            virtual bool                                                    OnTick(uint64_t now) noexcept;
            virtual bool                                                    OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept;
            virtual bool                                                    OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept;

        private:
            void                                                            Finalize() noexcept;
            void                                                            Release() noexcept;
            void                                                            NextTimeout() noexcept;
            void                                                            StopTimeout() noexcept;
#ifdef _WIN32
            int                                                             PacketInput(struct pbuf* packet, int packet_length) noexcept;
#else
            int                                                             PacketInput(struct pbuf* packet, int packet_length, bool allocated) noexcept;
#endif

        private:
            struct {
                bool                                                        disposed_ : 1;
                bool                                                        lwip_ : 1;
                bool                                                        vnet_ : 6;
            };
            int                                                             concurrency_;
            SynchronizedObject                                              syncobj_;
            std::shared_ptr<IPFragment>                                     fragment_;
            std::shared_ptr<VNetstack>                                      netstack_;
            std::shared_ptr<boost::asio::io_context>                        context_;
            std::shared_ptr<ppp::threading::Timer>                          timeout_;
        };
    }
}