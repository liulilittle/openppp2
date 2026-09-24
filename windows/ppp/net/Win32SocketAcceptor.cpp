#include <ppp/net/SocketAcceptor.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>
#include <ppp/diagnostics/Error.h>

#include <windows/ppp/win32/Win32Native.h>
#include <windows/ppp/net/Win32SocketAcceptor.h>

#include <Windows.h>
#include <Iphlpapi.h>

typedef ppp::net::AddressFamily     AddressFamily;
typedef ppp::net::IPEndPoint        IPEndPoint;
typedef ppp::net::Socket            Socket;

static struct WINDOWS_SOCKET_INITIALIZATION final
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
            , hEvent_(NULLPTR)
            , in_(false)
            , afo_(NULLPTR)
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
            bool b = NULLPTR != hEvent_ && NULLPTR != afo_ && NULLPTR != context_;
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
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                return false;
            }

            if (NULLPTR == localIP || *localIP == '\x0')
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return false;
            }

            if (listenfd_ != INVALID_SOCKET)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32SocketAcceptorOpenSocketAlreadyInitialized);
                return false;
            }

            if (NULLPTR != hEvent_)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32SocketAcceptorOpenEventAlreadyInitialized);
                return false;
            }

            if (NULLPTR != afo_)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32SocketAcceptorOpenHandleAlreadyInitialized);
                return false;
            }

            if (NULLPTR == context_)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                return false;
            }

            boost::system::error_code ec;
            boost::asio::ip::address bindIP = StringToAddress(localIP, ec);
            if (ec)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return false;
            }

            if (backlog < 1)
            {
                backlog = PPP_LISTEN_BACKLOG;
            }

            in_ = bindIP.is_v4();
            if (bindIP.is_v6())
            {
                struct sockaddr_in6 in6;
                memset(&in6, 0, sizeof(in6));

                in6.sin6_family = AF_INET6;
                in6.sin6_port = htons(localPort);
                if (inet_pton(AF_INET6, localIP, &in6.sin6_addr) < 1)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }

                listenfd_ = WSASocket(AF_INET6, SOCK_STREAM, IPPROTO_TCP, NULLPTR, 0, WSA_FLAG_OVERLAPPED);
                if (listenfd_ == INVALID_SOCKET)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketCreateFailed);
                    return false;
                }

                Adjust(listenfd_);
                if (!Socket::ReuseSocketAddress(listenfd_, true))
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOptionSetFailed);
                    return false;
                }

                BOOL bEnable = FALSE;
                if (setsockopt(listenfd_, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char*>(&bEnable), sizeof(bEnable)) < 0)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOptionSetFailed);
                    return false;
                }

                if (bind(listenfd_, reinterpret_cast<sockaddr*>(&in6), sizeof(in6)) < 0)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketBindFailed);
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
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }

                listenfd_ = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULLPTR, 0, WSA_FLAG_OVERLAPPED);
                if (listenfd_ == INVALID_SOCKET)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketCreateFailed);
                    return false;
                }

                Adjust(listenfd_);
                if (!Socket::ReuseSocketAddress(listenfd_, true))
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOptionSetFailed);
                    return false;
                }

                if (bind(listenfd_, reinterpret_cast<sockaddr*>(&in4), sizeof(in4)) < 0)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketBindFailed);
                    return false;
                }
            }
            else
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressFamilyMismatch);
                return false;
            }

            if (listen(listenfd_, backlog) < 0)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketListenFailed);
                return false;
            }

            hEvent_ = WSACreateEvent();
            if (hEvent_ == WSA_INVALID_EVENT)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32SocketEventCreateFailed);
                return false;
            }

            if (WSAEventSelect(listenfd_, hEvent_, FD_ACCEPT | FD_CLOSE) != NOERROR)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32SocketEventSelectFailed);
                return false;
            }

            afo_ = make_shared_void_pointer<boost::asio::windows::object_handle>(*context_, hEvent_);
            return Next();
        }

        void Win32SocketAcceptor::Dispose() noexcept
        {
            std::shared_ptr<boost::asio::io_context> context = context_;
            if (NULLPTR != context)
            {
                auto self = shared_from_this();
                boost::asio::post(*context, 
                    [self, this, context]() noexcept
                    {
                        Finalize();
                    });
            }
        }

        int Win32SocketAcceptor::Adjust(int sockfd) noexcept
        {
            if (sockfd != -1)
            {
                Socket::AdjustDefaultSocketOptional(sockfd, in_);
                Socket::SetTypeOfService(sockfd);
                Socket::SetSignalPipeline(sockfd, false);
            }

            return sockfd;
        }

        bool Win32SocketAcceptor::Next() noexcept
        {
            std::lock_guard<std::mutex> scope(syncobj_);

            boost::asio::windows::object_handle* afo = reinterpret_cast<boost::asio::windows::object_handle*>(afo_.get());
            if (NULLPTR == afo)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32SocketAcceptorNextHandleUnavailable);
                return false;
            }

            int listenfd = listenfd_;
            if (listenfd == INVALID_SOCKET)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32SocketAcceptorNextSocketUnavailable);
                return false;
            }

            void* hEvent = hEvent_;
            if (NULLPTR == hEvent)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32SocketAcceptorNextEventUnavailable);
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
                                struct sockaddr_in6 address = { 0 };
                                int address_size = sizeof(address);

                                int sockfd = WSAAccept(listenfd, (sockaddr*)&address, &address_size, NULLPTR, NULL);
                                if (sockfd != INVALID_SOCKET)
                                {
                                    AcceptSocketEventArgs e = { Adjust(sockfd) };
                                    OnAcceptSocket(e);
                                }
                                else
                                {
                                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketAcceptFailed);
                                }
                            }
                            else
                            {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketAcceptFailed);
                            }
                        }
                        elif(events.lNetworkEvents & FD_CLOSE)
                        {
                            if (events.iErrorCode[FD_ACCEPT_BIT] == 0) /* event is operation_canceled. */
                            {
                                return;
                            }

                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketAcceptFailed);
                        }
                    }
                    else
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32SocketEventEnumFailed);
                    }

                    Next();
                });
            return true;
        }

        int Win32SocketAcceptor::GetHandle() noexcept
        {
            std::lock_guard<std::mutex> scope(syncobj_);
            return listenfd_;
        }

        void Win32SocketAcceptor::Finalize() noexcept
        {
            std::lock_guard<std::mutex> scope(syncobj_);

            /**
             * @brief Snapshot hEvent_ BEFORE clearing any member: the previous code
             *        nulled hEvent_ inside the afo branch and then read it back, so
             *        WSACloseEvent() never ran and the event handle leaked.
             */
            void* hEvent = hEvent_;

            boost::asio::windows::object_handle* afo = reinterpret_cast<boost::asio::windows::object_handle*>(afo_.get());
            if (NULLPTR != afo)
            {
                ppp::win32::Win32Native::CloseHandle(afo);
                afo_ = NULLPTR;
            }

            if (NULLPTR != hEvent)
            {
                ppp::win32::Win32Native::WSACloseEvent(hEvent);
                hEvent_ = NULLPTR;
            }

            int listenfd = listenfd_;
            if (listenfd != INVALID_SOCKET)
            {
                closesocket(listenfd);
            }

            AcceptSocket = NULL;
            afo_ = NULLPTR;
            hEvent_ = NULLPTR;
            context_ = NULLPTR;
            listenfd_ = INVALID_SOCKET;
        }
    }
}
