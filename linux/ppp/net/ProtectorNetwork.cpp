// https://www-numi.fnal.gov/offline_software/srt_public_context/WebDocs/Errors/unix_system_errors.html
// #define ENOENT           2      /* No such file or directory */
// #define EAGAIN          11      /* Try again */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>
#include <assert.h>

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
#include <error.h>
#include <sys/poll.h>
#endif

#include <fcntl.h>
#include <errno.h>

#include <ppp/stdafx.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Executors.h>

#include "ProtectorNetwork.h"
#include "ancillary/ancillary.h"

#include <common/unix/UnixAfx.h>

using ppp::net::Socket;

namespace ppp
{
    namespace net
    {
        ProtectorNetwork::ProtectorNetwork(const ppp::string& dev) noexcept
            : dev_(dev)
        {
#if defined(_ANDROID)
            env_ = NULL;
            jni_ = NULL;
#endif
        }

        int ProtectorNetwork::Recvfd(const char* unix_path, int milliSecondsTimeout, bool sync, int& fd) noexcept
        {
            fd = -1;
            if (NULL == unix_path)
            {
                return -1011;
            }

            int sock = socket(AF_UNIX, SOCK_STREAM, 0);
            if (sock == -1)
            {
                return -1012;
            }

            int flags = fcntl(sock, F_GETFL, 0);
            if (flags == -1)
            {
                return -1013;
            }

            if (milliSecondsTimeout > 0)
            {
                if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
                {
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
                return -1015;
            }

            if (listen(sock, PPP_LISTEN_BACKLOG) < 0)
            {
                Socket::Closesocket(sock);
                return -1016;
            }

            for (; ;)
            {
                if (milliSecondsTimeout > 0)
                {
                    if (!Socket::Poll(sock, milliSecondsTimeout * 1000, Socket::SelectMode_SelectRead))
                    {
                        Socket::Closesocket(sock);
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
                    return -1018;
                }

                if (ancil_recv_fd(connection, &fd))
                {
                    Socket::Closesocket(connection);
                    Socket::Closesocket(sock);
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
                        return -1021;
                    }

                    if (fcntl(connection, F_SETFL, fl & ~O_NONBLOCK) < 0)
                    {
                        Socket::Closesocket(connection);
                        Socket::Closesocket(sock);
                        return -1022;
                    }

                    char err = 0;
                    if (send(connection, &err, 1, MSG_NOSIGNAL) < 0)
                    {
                        Socket::Closesocket(connection);
                        Socket::Closesocket(sock);
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
            if (NULL == unix_path || milliSecondsTimeout < 1)
            {
                return -1001;
            }

            int sock = socket(AF_UNIX, SOCK_STREAM, 0);
            if (sock == -1)
            {
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
                return -1003;
            }

            ppp::unix__::UnixAfx::set_fd_cloexec(fd);
            if (ancil_send_fd(sock, fd))
            {
                Socket::Closesocket(sock);
                return -1004;
            }

            char err = 0;
            if (recv(sock, &err, 1, MSG_NOSIGNAL) < 0)
            {
                Socket::Closesocket(sock);
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
            // Java class function signature, you can see the header file of this function, 
            // There are specific Java code examples and descriptions, 
            // The signature is roughly: public static boolean protect(int sockfd) { return false; }
            if (fd == -1) /* https://blog.csdn.net/u010126792/article/details/82348438 */
            {
                return false;
            }

            if (NULL == env)
            {
                return false;
            }

            jclass clazz = env->FindClass(LIBOPENPPP2_CLASSNAME);
            if (NULL != env->ExceptionOccurred())
            {
                env->ExceptionClear();
            }

            if (NULL == clazz)
            {
                return false;
            }

            jboolean result = false;
            jmethodID method = env->GetStaticMethodID(clazz, "protect", "(I)Z");
            if (NULL != env->ExceptionOccurred())
            {
                env->ExceptionClear();
            }
            else if (NULL != method)
            {
                result = env->CallStaticBooleanMethod(clazz, method, fd);
                if (env->ExceptionCheck())
                {
                    env->ExceptionDescribe();
                    env->ExceptionClear();
                    result = false;
                }
            }

            env->DeleteLocalRef(clazz);
            return result;
        }

        bool ProtectorNetwork::JoinJNI(const std::shared_ptr<boost::asio::io_context>& context, JNIEnv* env) noexcept
        {
            if (NULL == context || NULL == env)
            {
                return false;
            }
            
            std::shared_ptr<boost::asio::io_context> jni;
            {
                SynchronizedObjectScope scope(syncobj_);
                jni = std::move(jni_);
                env_ = env;
                jni_ = context;
            }

            if (NULL != jni)
            {
                ppp::threading::Executors::Exit(jni);
            }
            return true;
        }

        void ProtectorNetwork::DetachJNI() noexcept
        {
            std::shared_ptr<boost::asio::io_context> jni;
            {
                SynchronizedObjectScope scope(syncobj_);
                jni = std::move(jni_);
                env_ = NULL;
                jni_ = NULL;
            }

            if (NULL != jni)
            {
                ppp::threading::Executors::Exit(jni);
            }
        }
        
        bool ProtectorNetwork::ProtectJNI(const std::shared_ptr<boost::asio::io_context>& context, int sockfd, YieldContext& y) noexcept
        {
            bool ok = false;
            auto self = shared_from_this();
            context->post(
                [self, this, &ok, &y, sockfd]() noexcept
                {
                    // Reverse-calling the Java class member static function protects the socket without passing through VPNService / Android-Ko.
                    std::shared_ptr<boost::asio::io_context> jni;
                    {
                        SynchronizedObjectScope scope(syncobj_);
                        jni = jni_;
                        if (NULL != jni)
                        {
                            JNIEnv* env = env_;
                            if (NULL != env)
                            {
                                ok = ProtectorNetwork::ProtectJNI(env, sockfd);
                            }
                        }
                    }

                    // Wake up the coroutine waiting for this protect network socket service to prevent coroutines from getting stuck.
                    boost::asio::io_context& context = y.GetContext();
                    context.dispatch(std::bind(&YieldContext::Resume, y.GetPtr()));
                });

            y.Suspend();
            return ok;
        }
#endif

        bool ProtectorNetwork::Protect(int sockfd, YieldContext& y) noexcept
        {
            if (sockfd == -1)
            {
                return false;
            }

            ProtectEventHandler e = ProtectEvent;
            if (NULL != e)
            {
                return e(sockfd);
            }

#if defined(_ANDROID)
            // If JNIEnv is set, it means that PPP PRIVATE NETWORK™ 2 is embedded in the Android application as a DLL/SO, 
            // In the form of a JNI reverse call to the JAVA class member static function protect, otherwise it is a sendfd/recvfd structures.
            std::shared_ptr<boost::asio::io_context> context = jni_;
            if (NULL != context)
            {
                return ProtectJNI(context, sockfd, y);
            }
#endif

            if (dev_.empty())
            {
                return false;
            }

#if defined(_ANDROID)
            return ProtectorNetwork::Sendfd(dev_.data(), sockfd);
#else
            return ::setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, dev_.data(), dev_.size()) > -1;
#endif
        }
    }
}