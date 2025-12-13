#pragma once

#include <ppp/threading/Timer.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace net {
        namespace asio {
            class InternetControlMessageProtocol_EchoAsynchronousContext;

            // ICMP on Internet Control Message Protocol.
            class InternetControlMessageProtocol : public std::enable_shared_from_this<InternetControlMessageProtocol> {
                friend class                                                    InternetControlMessageProtocol_EchoAsynchronousContext;

            public:
                typedef ppp::threading::Timer                                   Timer;
                typedef Timer::TimeoutEventHandler                              TimeoutEventHandler;
                typedef std::weak_ptr<TimeoutEventHandler>                      TimeoutEventHandlerWeakPtr;
                typedef ppp::unordered_map<void*, TimeoutEventHandlerWeakPtr>   TimeoutEventHandlerTable;
                typedef ppp::net::packet::IPFrame                               IPFrame;
                typedef ppp::net::packet::IcmpFrame                             IcmpFrame;
                typedef ppp::net::IPEndPoint                                    IPEndPoint;

            public:
                static constexpr int MAX_ICMP_TIMEOUT                           = 3000;

            public:
                const std::shared_ptr<ppp::threading::BufferswapAllocator>      BufferAllocator;

            public:
                InternetControlMessageProtocol(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<boost::asio::io_context>& context) noexcept;
                virtual ~InternetControlMessageProtocol() noexcept;

            public:
                std::shared_ptr<boost::asio::io_context>                        GetContext() noexcept;
                std::shared_ptr<InternetControlMessageProtocol>                 GetReference() noexcept;

            public:
                virtual bool                                                    Echo(
                    const std::shared_ptr<IPFrame>&                             packet, 
                    const std::shared_ptr<IcmpFrame>&                           frame, 
                    const IPEndPoint&                                           destinationEP) noexcept;
                virtual void                                                    Dispose() noexcept;

            public:
                static std::shared_ptr<IPFrame>                                 ER(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, int ttl, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                static std::shared_ptr<IPFrame>                                 TE(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, UInt32 source, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;

            protected: 
                virtual bool                                                    Output(
                    const IPFrame*                                              packet,
                    const IPEndPoint&                                           destinationEP) noexcept = 0;

            private:
                void                                                            Finalize() noexcept;

            private:
                bool                                                            disposed_ = false;
                boost::asio::ip::udp::endpoint                                  ep_;
                std::shared_ptr<Byte>                                           buffer_;
                std::shared_ptr<boost::asio::io_context>                        executor_;
                TimeoutEventHandlerTable                                        timeouts_;
            };
        }
    }
}