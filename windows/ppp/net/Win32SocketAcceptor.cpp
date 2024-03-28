#include <ppp/net/SocketAcceptor.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>

#include <windows/ppp/win32/Win32Native.h>
#include <windows/ppp/net/Win32SocketAcceptor.h>

#include <Windows.h>
#include <Iphlpapi.h>

typedef ppp::net::IPEndPoint IPEndPoint;

static struct WINDOWS_SOCKET_INITIALIZATION
{
public:
    WINDOWS_SOCKET_INITIALIZATION() noexcept
    {
        int err = WSAStartup(MAKEWORD(2, 2), &wsadata_);
        assert(err == ERROR_SUCCESS);
    }
    ~WINDOWS_SOCKET_INITIALIZATION() noexcept
    {
        WSACleanup();
    }

private:
    WSADATA                             wsadata_;
}                                       __WINDOWS_SOCKET_INITIALIZATION__;

namespace ppp
{
    namespace net
    {
        Win32SocketAcceptor::Win32SocketAcceptor(const std::shared_ptr<boost::asio::io_context>& context) noexcept
            : listenfd_(INVALID_SOCKET)
            , hEvent_(NULL)
            , in_(false)
            , afo_(NULL)
            , context_(context)
        {

        }

        Win32SocketAcceptor::Win32SocketAcceptor() noexcept
            : Win32SocketAcceptor(ppp::threading::Executors::GetDefault()) {

        }

        Win32SocketAcceptor::~Win32SocketAcceptor() noexcept
        {
            Finalize();
        }

        bool Win32SocketAcceptor::IsOpen() noexcept
        {
            bool b = NULL != hEvent_ && NULL != afo_ && NULL != context_;
            if (b)
            {
                b = listenfd_ != INVALID_SOCKET;
            }
            return b;
        }

        bool Win32SocketAcceptor::Open(const char* localIP, int localPort, int backlog) noexcept
        {
            if (localPort < IPEndPoint::MinPort || localPort > IPEndPoint::MaxPort)
            {
                return false;
            }

            if (NULL == localIP || *localIP == '\x0')
            {
                return false;
            }

            if (listenfd_ != INVALID_SOCKET)
            {
                return false;
            }

            if (NULL != hEvent_)
            {
                return false;
            }

            if (NULL != afo_)
            {
                return false;
            }

            if (NULL == context_)
            {
                return false;
            }

            boost::system::error_code ec;
            boost::asio::ip::address bindIP = StringToAddress(localIP, ec);
            if (ec)
            {
                return false;
            }

            if (backlog < 1)
            {
                backlog = PPP_LISTEN_BACKLOG;
            }

            if (bindIP.is_v6())
            {
                struct sockaddr_in6 in6;
                memset(&in6, 0, sizeof(in6));

                in6.sin6_family = AF_INET6;
                in6.sin6_port = htons(localPort);
                if (inet_pton(AF_INET6, localIP, &in6.sin6_addr) < 1)
                {
                    return false;
                }

                listenfd_ = WSASocket(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
                if (listenfd_ == INVALID_SOCKET)
                {
                    return false;
                }

                if (!ppp::net::Socket::ReuseSocketAddress(listenfd_, true))
                {
                    return false;
                }

                BOOL bEnable = FALSE;
                if (setsockopt(listenfd_, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&bEnable), sizeof(bEnable)) < 0)
                {
                    return false;
                }

                if (bind(listenfd_, reinterpret_cast<sockaddr*>(&in6), sizeof(in6)) < 0)
                {
                    return false;
                }
            }
            elif(bindIP.is_v4())
            {
                struct sockaddr_in in4;
                memset(&in4, 0, sizeof(in4));

                in4.sin_family = AF_INET;
                in4.sin_port = htons(localPort);
                if (inet_pton(AF_INET, localIP, &in4.sin_addr) < 1)
                {
                    return false;
                }

                listenfd_ = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
                if (listenfd_ == INVALID_SOCKET)
                {
                    return false;
                }

                if (!ppp::net::Socket::ReuseSocketAddress(listenfd_, true))
                {
                    return false;
                }

                if (bind(listenfd_, reinterpret_cast<sockaddr*>(&in4), sizeof(in4)) < 0)
                {
                    return false;
                }
            }
            else
            {
                return false;
            }

            in_ = bindIP.is_v4();
            if (listen(listenfd_, backlog) < 0)
            {
                return false;
            }

            hEvent_ = WSACreateEvent();
            if (hEvent_ == WSA_INVALID_EVENT)
            {
                return false;
            }

            if (WSAEventSelect(listenfd_, hEvent_, FD_ACCEPT | FD_CLOSE) != NOERROR)
            {
                return false;
            }

            afo_ = make_shared_void_pointer<boost::asio::windows::object_handle>(*context_, hEvent_);
            return Next();
        }

        void Win32SocketAcceptor::Dispose() noexcept
        {
            std::shared_ptr<boost::asio::io_context> context = context_;
            if (NULL != context)
            {
                auto self = shared_from_this();
                context->post(
                    [self, this]() noexcept
                    {
                        Finalize();
                    });
            }
        }

        bool Win32SocketAcceptor::Next() noexcept
        {
            boost::asio::windows::object_handle* afo = reinterpret_cast<boost::asio::windows::object_handle*>(afo_.get());
            if (NULL == afo)
            {
                return false;
            }

            int listenfd = listenfd_;
            if (listenfd == INVALID_SOCKET)
            {
                return false;
            }

            void* hEvent = hEvent_;
            if (NULL == hEvent)
            {
                return false;
            }

            std::shared_ptr<SocketAcceptor> self = shared_from_this();
            afo->async_wait(
                [self, this, hEvent, listenfd](const boost::system::error_code& ec) noexcept
                {
                    if (ec == boost::system::errc::operation_canceled) /* WSAWaitForMultipleEvents */
                    {
                        return;
                    }

                    WSANETWORKEVENTS events;
                    if (WSAEnumNetworkEvents(listenfd, hEvent, &events) == NOERROR)
                    {
                        if (events.lNetworkEvents & FD_ACCEPT)
                        {
                            if (events.iErrorCode[FD_ACCEPT_BIT] == 0)
                            {
                                struct sockaddr address = { 0 };
                                int address_size = sizeof(address);
                                int sockfd = accept(listenfd_, &address, &address_size);
                                if (sockfd != INVALID_SOCKET)
                                {
                                    Socket::AdjustDefaultSocketOptional(sockfd, in_);
                                    Socket::SetTypeOfService(sockfd);
                                    Socket::SetSignalPipeline(sockfd, false);
                                    Socket::ReuseSocketAddress(sockfd, true);

                                    AcceptSocketEventArgs e = { sockfd };
                                    OnAcceptSocket(e);
                                }
                            }
                        }
                        elif(events.lNetworkEvents & FD_CLOSE)
                        {
                            if (events.iErrorCode[FD_ACCEPT_BIT] == 0) /* event is operation_canceled. */
                            {
                                return;
                            }
                        }
                    }

                    Next();
                });
            return true;
        }

        int Win32SocketAcceptor::GetHandle() noexcept
        {
            return listenfd_;
        }

        void Win32SocketAcceptor::Finalize() noexcept
        {
            boost::asio::windows::object_handle* afo = reinterpret_cast<boost::asio::windows::object_handle*>(afo_.get());
            if (NULL != afo)
            {
                boost::system::error_code ec;
                try
                {
                    afo->cancel(ec);
                }
                catch (const std::exception&) {}

                try
                {
                    afo->close(ec);
                }
                catch (const std::exception&) {}

                afo_ = NULL;
                hEvent_ = NULL;
            }

            void* hEvent = hEvent_;
            if (NULL != hEvent)
            {
                ppp::win32::Win32Native::WSACloseEvent(hEvent);
            }

            int listenfd = listenfd_;
            if (listenfd != INVALID_SOCKET)
            {
                closesocket(listenfd);
            }

            AcceptSocket.reset();
            afo_ = NULL;
            hEvent_ = NULL;
            context_ = NULL;
            listenfd_ = INVALID_SOCKET;
        }
    }
}