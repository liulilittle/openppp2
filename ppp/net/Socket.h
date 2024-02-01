#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace net {
        class Socket final {
        public:
            typedef std::shared_ptr<boost::asio::ip::tcp::socket>                       AsioTcpSocket;
            typedef std::shared_ptr<boost::asio::io_context>                            AsioContext;
            typedef std::shared_ptr<boost::asio::ip::tcp::acceptor>                     AsioTcpAcceptor;
            typedef std::shared_ptr<boost::asio::ip::udp::socket>                       AsioUdpSocket;
            typedef ppp::function<AsioContext()>                                        GetContextCallback;
            typedef ppp::function<bool(const AsioContext&, const AsioTcpSocket&)>       AcceptLoopbackCallback;
            typedef ppp::function<bool(const std::shared_ptr<Byte>&, int)>              ReceiveFromLoopbackCallback;

        public:
            enum SelectMode {
                SelectMode_SelectRead,
                SelectMode_SelectWrite,
                SelectMode_SelectError,
            };
            static bool                                                                 PolH(int s, int64_t microSeconds, SelectMode mode) noexcept;
            static bool                                                                 Poll(int s, int milliSeconds, SelectMode mode) noexcept;

        public:
            static void                                                                 Shutdown(int fd) noexcept;
            static void                                                                 Closesocket(int fd) noexcept;
            static boost::asio::ip::tcp::endpoint                                       GetLocalEndPoint(int fd) noexcept;
            static boost::asio::ip::tcp::endpoint                                       GetRemoteEndPoint(int fd) noexcept;
            static bool                                                                 SetNonblocking(int fd, bool nonblocking) noexcept;

        public:
            static bool                                                                 AcceptLoopbackAsync(
                const AsioTcpAcceptor&                                                  acceptor,
                const std::shared_ptr<AcceptLoopbackCallback>&                          callback,
                const std::shared_ptr<GetContextCallback>&                              context = NULL) noexcept;
            static bool                                                                 AcceptLoopbackAsync(
                const boost::asio::ip::tcp::acceptor&                                   acceptor,
                const std::shared_ptr<AcceptLoopbackCallback>&                          callback,
                const std::shared_ptr<GetContextCallback>&                              context = NULL) noexcept;
            static bool                                                                 OpenAcceptor(
                const boost::asio::ip::tcp::acceptor&                                   acceptor,
                const boost::asio::ip::address&                                         listenIP,
                int                                                                     listenPort,
                int                                                                     backlog,
                bool                                                                    fastOpen,
                bool                                                                    noDelay) noexcept;
            static bool                                                                 OpenSocket(
                const boost::asio::ip::udp::socket&                                     socket,
                const boost::asio::ip::address&                                         listenIP,
                int                                                                     listenPort) noexcept;

        public:
            static void                                                                 Cancel(const boost::asio::deadline_timer& socket) noexcept;
            static void                                                                 Cancel(const boost::asio::ip::udp::socket& socket) noexcept;
            static void                                                                 Cancel(const boost::asio::ip::tcp::socket& socket) noexcept;
            static void                                                                 Cancel(const boost::asio::ip::tcp::acceptor& acceptor) noexcept;
            static void                                                                 Cancel(const boost::asio::ip::udp::resolver& resolver) noexcept;
            static void                                                                 Cancel(const boost::asio::ip::tcp::resolver& resolver) noexcept;
            
        public:
            static void                                                                 Cancel(const std::shared_ptr<boost::asio::ip::udp::socket>& socket) noexcept;
            static void                                                                 Cancel(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
            static void                                                                 Cancel(const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) noexcept;

        public:
            static bool                                                                 Closestream(const std::shared_ptr<boost::asio::posix::stream_descriptor>& stream) noexcept;
            static bool                                                                 Closesocket(const std::shared_ptr<boost::asio::ip::udp::socket>& socket) noexcept;
            static bool                                                                 Closesocket(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
            static bool                                                                 Closesocket(const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) noexcept;

        public:
            template<class TSocket>
            static int                                                                  LocalPort(const TSocket& socket) noexcept {
                boost::system::error_code ec;
                int port = const_cast<TSocket&>(socket).local_endpoint(ec).port();
                return ec ? 0 : port;
            }
            
            template<class TSocket>
            static int                                                                  RemotePort(const TSocket& socket) noexcept {
                boost::system::error_code ec;
                int port = const_cast<TSocket&>(socket).remote_endpoint(ec).port();
                return ec ? 0 : port;
            }

        public:
            static void                                                                 AdjustDefaultSocketOptional(int sockfd, bool in4) noexcept;
            static void                                                                 AdjustSocketOptional(const boost::asio::ip::tcp::socket& socket, bool in4, bool fastOpen, bool noDealy) noexcept;
            static void                                                                 AdjustSocketOptional(const boost::asio::ip::udp::socket& socket, bool in4) noexcept;

        public:
            static int                                                                  GetDefaultTTL() noexcept;
            static bool                                                                 SetTypeOfService(int fd, int tos = ~0) noexcept;
            static bool                                                                 SetSignalPipeline(int fd, bool sigpipe) noexcept;
            static bool                                                                 ReuseSocketAddress(int fd, bool reuse) noexcept;

        public:
            static int                                                                  GetHandle(const boost::asio::ip::tcp::acceptor& acceptor) noexcept;
            static int                                                                  GetHandle(const boost::asio::ip::tcp::socket& socket) noexcept;
            static int                                                                  GetHandle(const boost::asio::ip::udp::socket& socket) noexcept;

        public:
            static bool                                                                 Closesocket(const boost::asio::ip::tcp::acceptor& acceptor) noexcept;
            static bool                                                                 Closesocket(const boost::asio::ip::tcp::socket& socket) noexcept;
            static bool                                                                 Closesocket(const boost::asio::ip::udp::socket& socket) noexcept;
        };
    }
}