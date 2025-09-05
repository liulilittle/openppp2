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
                UInt32                                                      dstAddr = 0;
                UInt16                                                      dstPort = 0;
                UInt32                                                      srcAddr = 0;
                UInt16                                                      srcPort = 0;
                UInt16                                                      natPort = 0;
                struct {
                    bool                                                    lwip   : 1;
                    bool                                                    closed : 1;
                    Byte                                                    state  : 6;
                };
                std::shared_ptr<TapTcpClient>                               socket;
                UInt64                                                      lastTime = 0;

            public:
                TapTcpLink() noexcept;
                ~TapTcpLink() noexcept { this->Release(); }

            public:
                void                                                        Update() noexcept { this->lastTime = ppp::threading::Executors::GetTickCount(); };
                void                                                        Release() noexcept;
                void                                                        Closing() noexcept;
                void                                                        Dispose() noexcept { this->Release(); };

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
            typedef std::mutex                                              SynchronizedObject;
            typedef std::lock_guard<SynchronizedObject>                     SynchronizedObjectScope;
            
        public:
            class TapTcpClient : public std::enable_shared_from_this<TapTcpClient>
            {
                friend class                                                VNetstack;

            public:
                TapTcpClient(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand) noexcept;
                virtual ~TapTcpClient() noexcept;

            public:
                virtual void                                                Open(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept;
                virtual bool                                                Update() noexcept;
                virtual void                                                Dispose() noexcept;
                bool                                                        IsLwip() noexcept     { return lwip_ != 0; }
                bool                                                        IsDisposed() noexcept { return disposed_.load() != FALSE; }

            public:
                const boost::asio::ip::tcp::endpoint&                       GetLocalEndPoint() const noexcept  { return this->localEP_; }
                const boost::asio::ip::tcp::endpoint&                       GetNatEndPoint() const noexcept    { return this->natEP_; }
                const boost::asio::ip::tcp::endpoint&                       GetRemoteEndPoint() const noexcept { return this->remoteEP_; }

            public:
                std::shared_ptr<boost::asio::ip::tcp::socket>               GetSocket() noexcept  { return socket_; }
                std::shared_ptr<boost::asio::io_context>&                   GetContext() noexcept { return context_; }
                ppp::threading::Executors::StrandPtr&                       GetStrand() noexcept  { return strand_; }

            protected:
                virtual bool                                                BeginAccept() noexcept = 0;
                virtual bool                                                AckAccept() noexcept;
                virtual bool                                                Establish() noexcept = 0;
                virtual bool                                                EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept;

            private:
                void                                                        Finalize() noexcept;
                std::shared_ptr<boost::asio::ip::tcp::socket>               NewAsynchronousSocket(int sockfd, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept;

            private:
                int                                                         lwip_                = 0;
                std::atomic<int>                                            disposed_            = FALSE;
                std::shared_ptr<boost::asio::io_context>                    context_;
                ppp::threading::Executors::StrandPtr                        strand_;
                std::shared_ptr<boost::asio::ip::tcp::socket>               socket_;
                std::shared_ptr<TapTcpLink>                                 link_;
                std::shared_ptr<ITap>                                       sync_ack_tap_driver_;
                std::shared_ptr<Byte>                                       sync_ack_byte_array_;
                int                                                         sync_ack_bytes_size_ = 0;
                boost::asio::ip::tcp::endpoint                              natEP_;
                boost::asio::ip::tcp::endpoint                              localEP_;
                boost::asio::ip::tcp::endpoint                              remoteEP_;
            };

        public:
            const std::shared_ptr<ITap>                                     Tap;

        public:
            VNetstack() noexcept;
            virtual ~VNetstack() noexcept;

        public:
            std::shared_ptr<ppp::threading::BufferswapAllocator>            GetBufferAllocator() noexcept
            {
                std::shared_ptr<ITap> tap = this->Tap;
                return NULL != tap ? tap->BufferAllocator : NULL;
            }
            std::shared_ptr<VNetstack>                                      GetReference() noexcept { return shared_from_this(); }
            SynchronizedObject&                                             GetSynchronizedObject() noexcept { return syncobj_; }
            virtual bool                                                    Open(bool lwip, const int& localPort) noexcept;
            virtual void                                                    Release() noexcept;
            virtual bool                                                    Input(ip_hdr* ip, tcp_hdr* tcp, int tcp_len) noexcept;
            virtual bool                                                    Update(uint64_t now) noexcept;

        protected:
            virtual std::shared_ptr<TapTcpClient>                           BeginAcceptClient(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept = 0;
            virtual uint64_t                                                GetMaxConnectTimeout() noexcept;
            virtual uint64_t                                                GetMaxFinalizeTimeout() noexcept;
            virtual uint64_t                                                GetMaxEstablishedTimeout() noexcept;

        private:
            bool                                                            RST(ip_hdr* ip, tcp_hdr* tcp, int tcp_len) noexcept;
            bool                                                            Output(bool lan2wan, ip_hdr* ip, tcp_hdr* tcp, int tcp_len, TapTcpClient* c) noexcept;
            void                                                            ReleaseAllResources() noexcept;
            bool                                                            ProcessAcceptSocket(int sockfd) noexcept;

        private:
            bool                                                            CloseTcpLink(const std::shared_ptr<TapTcpLink>& link, bool fin = false) noexcept;
            std::shared_ptr<TapTcpLink>                                     FindTcpLink(int key) noexcept;
            std::shared_ptr<TapTcpLink>                                     FindTcpLink(const Int128& key) noexcept;
            std::shared_ptr<TapTcpLink>                                     AcceptTcpLink(int key) noexcept;
            std::shared_ptr<TapTcpLink>                                     AllocTcpLink(UInt32 src_ip, int src_port, UInt32 dst_ip, int dst_port) noexcept;

        private:
            SynchronizedObject                                              syncobj_;
            int                                                             ap_   = 0;
            bool                                                            lwip_ = false;
            IPEndPoint                                                      listenEP_;
            WAN2LANTABLE                                                    wan2lan_;
            LAN2WANTABLE                                                    lan2wan_;
            std::shared_ptr<SocketAcceptor>                                 acceptor_;
        };
    }
}