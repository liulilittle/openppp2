#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace net {
        class Socket final {
        public:
            class SOCKET_RESTRICTIONS final {
            public:
                struct {
                    bool                                                                                    IPV6_TCLASS_ON       : 1;
                    bool                                                                                    IP_TOS_ON            : 1;
                    bool                                                                                    IP_TOS_DEFAULT_FLASH : 7;
                };

            public:
                SOCKET_RESTRICTIONS() noexcept;

#if defined(_LINUX)
            private:
                bool                                                                                    ValidV4(int sockfd) noexcept;
                bool                                                                                    ValidV6(int sockfd) noexcept;
#endif
            };
            typedef std::shared_ptr<boost::asio::ip::tcp::socket>                                       AsioTcpSocket;
            typedef std::shared_ptr<boost::asio::io_context>                                            AsioContext;
            typedef boost::asio::strand<boost::asio::io_context::executor_type>                         AsioStrand;
            typedef std::shared_ptr<AsioStrand>                                                         AsioStrandPtr;
            typedef std::shared_ptr<boost::asio::ip::tcp::acceptor>                                     AsioTcpAcceptor;
            typedef std::shared_ptr<boost::asio::ip::udp::socket>                                       AsioUdpSocket;
            typedef ppp::function<AsioContext()>                                                        GetContextCallback;
            typedef ppp::function<bool(const std::shared_ptr<Byte>&, int)>                              ReceiveFromLoopbackCallback;
            typedef ppp::function<bool(const AsioContext&, const AsioTcpSocket&)>                       AcceptLoopbackCallback;
            typedef ppp::function<bool(const AsioContext&, const AsioStrandPtr&, const AsioTcpSocket&)> AcceptLoopbackSchedulerCallback;

        public:
            enum SelectMode {
                SelectMode_SelectRead,
                SelectMode_SelectWrite,
                SelectMode_SelectError,
            };
            static bool                                                                                 PolH(int s, int64_t microSeconds, SelectMode mode) noexcept;
            static bool                                                                                 Poll(int s, int milliSeconds, SelectMode mode) noexcept;

        public:
            static void                                                                                 Shutdown(int fd) noexcept;
            static void                                                                                 Closesocket(int fd) noexcept;
            static boost::asio::ip::tcp::endpoint                                                       GetLocalEndPoint(int fd) noexcept;
            static boost::asio::ip::tcp::endpoint                                                       GetRemoteEndPoint(int fd) noexcept;
            static bool                                                                                 SetNonblocking(int fd, bool nonblocking) noexcept;
            static bool                                                                                 AdjustDefaultSocketOptional(boost::asio::ip::tcp::socket& socket, bool turbo) noexcept;

        public:
            static bool                                                                                 AcceptLoopbackAsync(
                const AsioTcpAcceptor&                                                                  acceptor,
                const AcceptLoopbackCallback&                                                           callback,
                const GetContextCallback&                                                               context = NULL) noexcept;
            static bool                                                                                 AcceptLoopbackAsync(
                const boost::asio::ip::tcp::acceptor&                                                   acceptor,
                const AcceptLoopbackCallback&                                                           callback,
                const GetContextCallback&                                                               context = NULL) noexcept;
            static bool                                                                                 AcceptLoopbackSchedulerAsync(
                const boost::asio::ip::tcp::acceptor&                                                   acceptor,
                const AcceptLoopbackSchedulerCallback&                                                  callback) noexcept;
            static bool                                                                                 OpenAcceptor(
                const boost::asio::ip::tcp::acceptor&                                                   acceptor,
                const boost::asio::ip::address&                                                         listenIP,
                int                                                                                     listenPort,
                int                                                                                     backlog,
                bool                                                                                    fastOpen,
                bool                                                                                    noDelay) noexcept;
            static bool                                                                                 OpenSocket(
                const boost::asio::ip::udp::socket&                                                     socket,
                const boost::asio::ip::address&                                                         listenIP,
                int                                                                                     listenPort) noexcept { return OpenSocket(socket, listenIP, listenPort, false); }
            static bool                                                                                 OpenSocket(
                const boost::asio::ip::udp::socket&                                                     socket,
                const boost::asio::ip::address&                                                         listenIP,
                int                                                                                     listenPort,
                bool                                                                                    opened) noexcept;

        public:
            static void                                                                                 Cancel(const boost::asio::deadline_timer& socket) noexcept;
            static void                                                                                 Cancel(const boost::asio::ip::udp::socket& socket) noexcept;
            static void                                                                                 Cancel(const boost::asio::ip::tcp::socket& socket) noexcept;
            static void                                                                                 Cancel(const boost::asio::ip::tcp::acceptor& acceptor) noexcept;
            static void                                                                                 Cancel(const boost::asio::ip::udp::resolver& resolver) noexcept;
            static void                                                                                 Cancel(const boost::asio::ip::tcp::resolver& resolver) noexcept;
            
        public:
            static void                                                                                 Cancel(const std::shared_ptr<boost::asio::ip::udp::socket>& socket) noexcept;
            static void                                                                                 Cancel(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
            static void                                                                                 Cancel(const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) noexcept;

        public:
            static bool                                                                                 Closestream(boost::asio::posix::stream_descriptor* stream) noexcept;
            static bool                                                                                 Closestream(const std::shared_ptr<boost::asio::posix::stream_descriptor>& stream) noexcept { return Closestream(stream.get()); }

        public:
            static bool                                                                                 Closesocket(const std::shared_ptr<boost::asio::ip::udp::socket>& socket) noexcept;
            static bool                                                                                 Closesocket(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
            static bool                                                                                 Closesocket(const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) noexcept;

        public:
            template <class TSocket>
            static int                                                                                  LocalPort(const TSocket& socket) noexcept {
                boost::system::error_code ec;
                auto ep = constantof(socket).local_endpoint(ec);
                return ec ? 0 : ep.port();
            }
            
            template <class TSocket>
            static int                                                                                  RemotePort(const TSocket& socket) noexcept {
                boost::system::error_code ec;
                auto ep = constantof(socket).remote_endpoint(ec);
                return ec ? 0 : ep.port();
            }

            static uint32_t                                                                             GetBestInterfaceIP(uint32_t destination) noexcept;

        public:
            static void                                                                                 AdjustDefaultSocketOptional(int sockfd, bool in4) noexcept;
            static void                                                                                 AdjustSocketOptional(const boost::asio::ip::tcp::socket& socket, bool in4, bool fastOpen, bool noDealy) noexcept;
            static void                                                                                 AdjustSocketOptional(const boost::asio::ip::udp::socket& socket, bool in4) noexcept;
            static bool                                                                                 SetWindowSizeIfNotZero(int sockfd, int cwnd, int rwnd) noexcept;

        public:
            static int                                                                                  GetDefaultTTL() noexcept;
            static int                                                                                  GetTcpMss(int fd) noexcept;
            static bool                                                                                 SetTcpMss(int fd, int mss) noexcept;
            static bool                                                                                 IsDefaultFlashTypeOfService() noexcept { return SOCKET_RESTRICTIONS_.IP_TOS_DEFAULT_FLASH; }
            static void                                                                                 SetDefaultFlashTypeOfService(bool value) noexcept { SOCKET_RESTRICTIONS_.IP_TOS_DEFAULT_FLASH = value; } 
            static bool                                                                                 SetTypeOfService(int fd, int tos = ~0) noexcept;
            static bool                                                                                 SetSignalPipeline(int fd, bool sigpipe) noexcept;
            static bool                                                                                 ReuseSocketAddress(int fd, bool reuse) noexcept;

        public:
            static int                                                                                  GetHandle(const boost::asio::ip::tcp::acceptor& acceptor) noexcept;
            static int                                                                                  GetHandle(const boost::asio::ip::tcp::socket& socket) noexcept;
            static int                                                                                  GetHandle(const boost::asio::ip::udp::socket& socket) noexcept;

        public:
            static bool                                                                                 Closesocket(const boost::asio::ip::tcp::acceptor& acceptor) noexcept;
            static bool                                                                                 Closesocket(const boost::asio::ip::tcp::socket& socket) noexcept;
            static bool                                                                                 Closesocket(const boost::asio::ip::udp::socket& socket) noexcept;
        
        private:
            static SOCKET_RESTRICTIONS                                                                  SOCKET_RESTRICTIONS_; 
        };
    }
}