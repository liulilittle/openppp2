#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/tcp.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/SocketAcceptor.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>

namespace ppp {
    namespace ethernet {
        class VNetstack : public std::enable_shared_from_this<VNetstack> {
        public:
            class                                                           TapTcpClient;

        private:
            struct TapTcpLink {
            public:
                UInt32                                                      dstAddr;
                UInt16                                                      dstPort;
                UInt32                                                      srcAddr;
                UInt16                                                      srcPort;
                UInt16                                                      natPort;
                bool                                                        lwip;
                Byte                                                        state;
                std::shared_ptr<TapTcpClient>                               socket;
                UInt64                                                      lastTime;

            public:
                TapTcpLink() noexcept;
                ~TapTcpLink() noexcept;

            public:
                void                                                        Update() noexcept;
                void                                                        Release() noexcept;
                void                                                        Dispose() noexcept;

            public:
                typedef std::shared_ptr<TapTcpLink>                         Ptr;
            };
            typedef ppp::unordered_map<int, TapTcpLink::Ptr>                WAN2LANTABLE;
            typedef ppp::unordered_map<Int128, TapTcpLink::Ptr>             LAN2WANTABLE;

        public:
            typedef ppp::tap::ITap                                          ITap;
            typedef ppp::threading::Executors                               Executors;
            typedef ppp::net::IPEndPoint                                    IPEndPoint;
            typedef ppp::net::native::ip_hdr                                ip_hdr;
            typedef ppp::net::native::tcp_hdr                               tcp_hdr;
            typedef ppp::net::SocketAcceptor                                SocketAcceptor;
            typedef ppp::coroutines::YieldContext                           YieldContext;

        public:
            class TapTcpClient : public std::enable_shared_from_this<TapTcpClient>
            {
                friend class VNetstack;

            public:
                TapTcpClient(const std::shared_ptr<boost::asio::io_context>& context) noexcept;
                virtual ~TapTcpClient() noexcept;

            public:
                virtual void                                                Constructor(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept;
                virtual void                                                Dispose() noexcept;
                virtual bool                                                IsDisposed() noexcept;
                virtual bool                                                Update() noexcept;

            public:
                const boost::asio::ip::tcp::endpoint&                       GetLocalEndPoint() const noexcept;
                const boost::asio::ip::tcp::endpoint&                       GetNatEndPoint() const noexcept;
                const boost::asio::ip::tcp::endpoint&                       GetRemoteEndPoint() const noexcept;

            public:
                std::shared_ptr<boost::asio::ip::tcp::socket>               GetSocket() noexcept;
                std::shared_ptr<boost::asio::io_context>&                   GetContext() noexcept;

            protected:
                virtual bool                                                BeginAccept() noexcept;
                virtual bool                                                EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept;
                virtual bool                                                Establish() noexcept;

            private:
                std::shared_ptr<boost::asio::ip::tcp::socket>               NewAsynchronousSocket(int sockfd, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept;
                void                                                        Finalize() noexcept;

            private:
                struct {
                    bool                                                    lwip_ : 1;
                    bool                                                    disposed_ : 7;
                };
                std::shared_ptr<boost::asio::io_context>                    context_;
                std::shared_ptr<boost::asio::ip::tcp::socket>               socket_;
                std::shared_ptr<TapTcpLink>                                 link_;
                boost::asio::ip::tcp::endpoint                              natEP_;
                boost::asio::ip::tcp::endpoint                              localEP_;
                boost::asio::ip::tcp::endpoint                              remoteEP_;
            };

        public:
            const std::shared_ptr<ITap>                                     Tap;

        public:
            uint64_t                                                        MaxConnectTimeout = 10 * 1000;
            uint64_t                                                        MaxFinalizeTimeout = 20 * 1000;
            uint64_t                                                        MaxEstablishedTimeout = 72 * 1000;

        public:
            VNetstack() noexcept;
            virtual ~VNetstack() noexcept;

        public:
            std::shared_ptr<ppp::threading::BufferswapAllocator>            GetBufferAllocator() noexcept;
            std::shared_ptr<VNetstack>                                      GetReference() noexcept;
            virtual bool                                                    Constructor(bool lwip, const int& localPort) noexcept;
            virtual void                                                    Release() noexcept;
            virtual bool                                                    Input(ip_hdr* ip, tcp_hdr* tcp, int tcp_len) noexcept;
            virtual bool                                                    Update(uint64_t now) noexcept;

        protected:
            virtual std::shared_ptr<TapTcpClient>                           BeginAcceptClient(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept;

        private:
            bool                                                            RST(ip_hdr* ip, tcp_hdr* tcp, int tcp_len) noexcept;
            bool                                                            Output(bool lan2wan, ip_hdr* ip, tcp_hdr* tcp, int tcp_len) noexcept;
            bool                                                            ProcessAcceptSocket(int sockfd) noexcept;
            void                                                            ReleaseAllResources() noexcept;

        private:
            bool                                                            CloseTcpLink(const std::shared_ptr<TapTcpLink>& link, bool fin = false) noexcept;
            std::shared_ptr<TapTcpLink>                                     FindTcpLink(int key) noexcept;
            std::shared_ptr<TapTcpLink>                                     FindTcpLink(const Int128& key) noexcept;
            std::shared_ptr<TapTcpLink>                                     AcceptTcpLink(int key) noexcept;
            int                                                             AllocVirtualPort() noexcept;
            std::shared_ptr<TapTcpLink>                                     AllocTcpLink(UInt32 src_ip, int src_port, UInt32 dst_ip, int dst_port) noexcept;

        private:
            int                                                             ap_;
            bool                                                            lwip_;
            IPEndPoint                                                      listenEP_;
            WAN2LANTABLE                                                    wan2lan_;
            LAN2WANTABLE                                                    lan2wan_;
            std::shared_ptr<SocketAcceptor>                                 acceptor_;
        };
    }
}