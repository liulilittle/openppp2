// https://www-numi.fnal.gov/offline_software/srt_public_context/WebDocs/Errors/unix_system_errors.html
// #define ENOENT           2      /* No such file or directory */
// #define EAGAIN          11      /* Try again */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>
#include <assert.h>
#include <ppp/diagnostics/Error.h>

#include <sys/types.h>

#if defined(_WIN32)
#include <stdint.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#else
#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <netinet/tcp.h>

#if defined(__MUSL__) || defined(__BIONIC__) || defined(_ANDROID)
#include <err.h>
#include <poll.h>
#else
#if defined(_MACOS)
#include <errno.h>
#elif defined(_LINUX)
#include <error.h>
#endif

#include <sys/poll.h>
#endif
#endif

#include <fcntl.h>
#include <errno.h>

#include <ppp/stdafx.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/threading/Executors.h>

#include "ProtectorNetwork.h"
#include "ancillary/ancillary.h"

#include <common/unix/UnixAfx.h>

#if defined(_ANDROID)
#include <android/OpenPPP2VpnProtectBridge.h>
#endif

using ppp::net::Socket;

namespace ppp
{
    namespace net
    {
        ProtectorNetwork::ProtectorNetwork(const ppp::string& dev) noexcept
            : dev_(dev)
        {
        }

        int ProtectorNetwork::Recvfd(const char* unix_path, int milliSecondsTimeout, bool sync, int& fd) noexcept
        {
            fd = -1;
            if (NULLPTR == unix_path)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtectorNetworkRecvfdNullUnixPath);
                return -1011;
            }

            int sock = socket(AF_UNIX, SOCK_STREAM, 0);
            if (sock == -1)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketCreateFailed);
                return -1012;
            }

            int flags = fcntl(sock, F_GETFL, 0);
            if (flags == -1)
            {
                Socket::Closesocket(sock);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOptionGetFailed);
                return -1013;
            }

            if (milliSecondsTimeout > 0)
            {
                if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
                {
                    Socket::Closesocket(sock);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOptionSetFailed);
                    return -1014;
                }
            }

            unlink(unix_path);

            struct sockaddr_un addr;
            memset(&addr, 0, sizeof(addr));

            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, unix_path, sizeof(addr.sun_path) - 1);

            if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
            {
                Socket::Closesocket(sock);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketBindFailed);
                return -1015;
            }

            if (listen(sock, PPP_LISTEN_BACKLOG) < 0)
            {
                Socket::Closesocket(sock);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketListenFailed);
                return -1016;
            }

            for (; ;)
            {
                if (milliSecondsTimeout > 0)
                {
                    if (!Socket::Poll(sock, milliSecondsTimeout * 1000, Socket::SelectMode_SelectRead))
                    {
                        Socket::Closesocket(sock);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketTimeout);
                        return -1017;
                    }
                }

                struct sockaddr_un remoteEP;
                memset(&remoteEP, 0, sizeof(remoteEP));

                socklen_t size = sizeof(remoteEP);
                int connection = accept(sock, (struct sockaddr*)&remoteEP, &size);
                if (connection == -1)
                {
                    Socket::Closesocket(sock);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketAcceptFailed);
                    return -1018;
                }

                if (ancil_recv_fd(connection, &fd))
                {
                    Socket::Closesocket(connection);
                    Socket::Closesocket(sock);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                    return -1019;
                }

                ppp::unix__::UnixAfx::set_fd_cloexec(fd);
                if (sync)
                {
                    int fl = fcntl(connection, F_GETFL, 0);
                    if (fl == -1)
                    {
                        Socket::Closesocket(connection);
                        Socket::Closesocket(sock);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOptionGetFailed);
                        return -1021;
                    }

                    if (fcntl(connection, F_SETFL, fl & ~O_NONBLOCK) < 0)
                    {
                        Socket::Closesocket(connection);
                        Socket::Closesocket(sock);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOptionSetFailed);
                        return -1022;
                    }

                    char err = 0;
                    if (send(connection, &err, 1, MSG_NOSIGNAL) < 0)
                    {
                        Socket::Closesocket(connection);
                        Socket::Closesocket(sock);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                        return -1023;
                    }
                }

                Socket::Closesocket(connection);
                Socket::Closesocket(sock);
                return fd;
            }
        }

        int ProtectorNetwork::Recvfd(const char* unix_path, int milliSecondsTimeout, bool sync) noexcept
        {
            int fd;
            int err = Recvfd(unix_path, milliSecondsTimeout, sync, fd);
            return err;
        }

        int ProtectorNetwork::Sendfd(const char* unix_path, int fd, int milliSecondsTimeout, bool sync) noexcept
        {
            char r;
            int err = Sendfd2(unix_path, fd, milliSecondsTimeout, sync, r);
            return err;
        }

        int ProtectorNetwork::Sendfd2(const char* unix_path, int fd, int milliSecondsTimeout, bool sync, char& r) noexcept
        {
            r = 0;
            if (NULLPTR == unix_path || milliSecondsTimeout < 1)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtectorNetworkSendfdInvalidArguments);
                return -1001;
            }

            int sock = socket(AF_UNIX, SOCK_STREAM, 0);
            if (sock == -1)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketCreateFailed);
                return -1002;
            }

            struct timeval tv;
            tv.tv_sec = (milliSecondsTimeout / 1000);
            tv.tv_usec = (milliSecondsTimeout % 1000) * 1000;

            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(struct timeval));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(struct timeval));

            struct sockaddr_un addr;
            memset(&addr, 0, sizeof(addr));

            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, unix_path, sizeof(addr.sun_path) - 1);

            if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
            {
                Socket::Closesocket(sock);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketConnectFailed);
                return -1003;
            }

            ppp::unix__::UnixAfx::set_fd_cloexec(fd);
            if (ancil_send_fd(sock, fd))
            {
                Socket::Closesocket(sock);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                return -1004;
            }

            char err = 0;
            if (recv(sock, &err, 1, MSG_NOSIGNAL) < 0)
            {
                Socket::Closesocket(sock);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                return -1005;
            }

            if (sync)
            {
                r = err;
                if (err)
                {
                    Socket::Closesocket(sock);
                    return err;
                }

                if (recv(sock, &err, 1, MSG_NOSIGNAL) < 0)
                {
                    Socket::Closesocket(sock);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                    return -1006;
                }
            }

            r = err;
            Socket::Closesocket(sock);
            return err;
        }

#if defined(_ANDROID)
        bool ProtectorNetwork::ProtectJNI(JNIEnv* env, jint fd) noexcept
        {
            (void)env;
            if (fd == -1) /* https://blog.csdn.net/u010126792/article/details/82348438 */
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtectorNetworkProtectInvalidSocket);
                ppp::telemetry::Count("protect.android.fail.invalid_fd", 1);
                return false;
            }

            const bool result = ppp::android::ProtectSocketFd(static_cast<int>(fd));
            if (!result) {
                ppp::telemetry::Count("protect.android.fail.false", 1);
            }
            else {
                ppp::telemetry::Count("protect.android.success", 1);
            }
            return result;
        }

        bool ProtectorNetwork::JoinJNI(const std::shared_ptr<boost::asio::io_context>& context, JNIEnv* env) noexcept
        {
            if (NULLPTR == context || NULLPTR == env)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
                ppp::telemetry::Count("protect.android.join.fail", 1);
                return false;
            }

            SynchronizedObjectScope scope(syncobj_);
            std::shared_ptr<JniSession> replacement;
            try
            {
                const std::uint64_t generation = next_generation_ + 1;
                replacement = std::make_shared<JniSession>(generation, context, env);
                next_generation_ = generation;
            }
            catch (...)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                ppp::telemetry::Count("protect.android.join.fail", 1);
                return false;
            }

            // JNIEnv is thread-affine. Until the JNI owner is migrated to JavaVM,
            // this context must be driven by exactly the thread that called JoinJNI.
            // Serialize lifecycle changes until the previous generation drains.
            std::shared_ptr<JniSession> previous = std::move(session_);
            if (previous)
            {
                previous->requests.Deactivate();
                ppp::threading::Executors::Exit(previous->context);
            }
            session_ = std::move(replacement);
            return true;
        }

        bool ProtectorNetwork::DetachJNI() noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            std::shared_ptr<JniSession> session = std::move(session_);
            if (!session)
            {
                return false;
            }

            // The object is already inactive for new admission. Cancel and wake
            // pending requests, then wait for any in-flight JNI call to leave.
            session->requests.Deactivate();
            ppp::threading::Executors::Exit(session->context);
            return true;
        }

        bool ProtectorNetwork::ProtectJNI(const std::shared_ptr<boost::asio::io_context>& context, int sockfd, YieldContext& y) noexcept
        {
            std::shared_ptr<JniSession> session;
            {
                SynchronizedObjectScope scope(syncobj_);
                if (session_ && session_->context == context)
                {
                    session = session_;
                }
            }
            return ProtectJNISession(session, sockfd, y);
        }

        bool ProtectorNetwork::ProtectJNISession(const std::shared_ptr<JniSession>& session, int sockfd, YieldContext& y) noexcept
        {
            if (!session || !session->context || session->context->stopped())
            {
                return false;
            }

            std::shared_ptr<ProtectorNetworkRequest> request =
                session->requests.Create([yield = &y]() noexcept { yield->R(); });
            if (!request)
            {
                return false;
            }

            std::weak_ptr<JniSession> weak_session = session;
            std::weak_ptr<ProtectorNetworkRequest> weak_request = request;
            try
            {
                boost::asio::post(*session->context,
                    [weak_session, weak_request, sockfd]() noexcept
                    {
                        std::shared_ptr<JniSession> own_session = weak_session.lock();
                        std::shared_ptr<ProtectorNetworkRequest> own_request = weak_request.lock();
                        if (!own_request)
                        {
                            return;
                        }
                        if (!own_session || !own_session->requests.Begin(own_request))
                        {
                            own_request->Cancel();
                            return;
                        }

                        // Use only the immutable token captured for this generation;
                        // never consult the ProtectorNetwork object's current session.
                        const bool result = ProtectorNetwork::ProtectJNI(own_session->env, sockfd);
                        own_request->Complete(result);
                        own_session->requests.Finish(own_request);
                    });

                // Asio accepts work on a stopped context. Convert an observed stop
                // into cancellation instead of suspending with no runnable handler.
                if (session->context->stopped())
                {
                    session->requests.Cancel(request);
                }
            }
            catch (...)
            {
                session->requests.Cancel(request);
            }

            y.Suspend();
            return request->Result();
        }
#endif

        bool ProtectorNetwork::Protect(int sockfd, YieldContext& y) noexcept
        {
            if (sockfd == -1)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtectorNetworkProtectInvalidSocket);
                return false;
            }

            ProtectEventHandler e = ProtectEvent;
            if (NULLPTR != e)
            {
                return e(sockfd);
            }

#if defined(_ANDROID)
            // Snapshot one immutable generation; posted work must never re-read
            // whichever JNI session JoinJNI may install later.
            std::shared_ptr<JniSession> session;
            {
                SynchronizedObjectScope scope(syncobj_);
                session = session_;
            }
            if (session)
            {
                return ProtectJNISession(session, sockfd, y);
            }
#endif

            if (dev_.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                return false;
            }

#if defined(_ANDROID)
            return ProtectorNetwork::Sendfd(dev_.data(), sockfd);
#else
            if (::setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, dev_.data(), dev_.size()) > -1)
            {
                return true;
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOptionSetFailed);
            return false;
#endif
        }

        bool ProtectorNetwork::ProtectSync(int sockfd) noexcept
        {
            if (sockfd == -1)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtectorNetworkProtectInvalidSocket);
                return false;
            }

            ProtectEventHandler e = ProtectEvent;
            if (NULLPTR != e)
            {
                return e(sockfd);
            }

#if defined(_ANDROID)
            // On Android without ProtectEvent, we cannot protect synchronously
            // without a JNI environment or YieldContext.  Return false so the
            // caller can fall back to route-based protection.
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtectorNetworkProtectInvalidSocket);
            return false;
#else
            if (dev_.empty())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                return false;
            }
            if (::setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, dev_.data(), dev_.size()) > -1)
            {
                return true;
            }
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOptionSetFailed);
            return false;
#endif
        }
    }
}
