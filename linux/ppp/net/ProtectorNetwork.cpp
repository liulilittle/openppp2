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

#ifdef _WIN32
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

#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>

#include "ProtectorNetwork.h"
#include "ancillary/ancillary.h"

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

        int ProtectorNetwork::Sendfd(const char* unix_path, int fd, int milliSecondsTimeout, bool sync, char& r) noexcept
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

#ifdef ANDROID
        static bool Android_Protect(const ppp::string& unix_url, int sockfd) noexcept
        {
            return Sendfd(protectUri.data(), socket);
        }

        bool ProtectorNetwork::ProtectJNI(JNIEnv* env, jint fd, const char* class_name, const char* method_name) noexcept
        {
            if (fd == -1) /* https://blog.csdn.net/u010126792/article/details/82348438 */ 
            {
                return false;
            }

            if (NULL == env)
            {
                return true;
            }

            if (NULL == class_name || *class_name == '\x0') 
            {
                class_name = "supersocksr/ppp/android/c/libcor32";
            }

            if (NULL == method_name || *method_name == '\x0') 
            {
                method_name = "protect";
            }

            jclass clazz = env->FindClass(class_name);
            if (NULL != env->ExceptionOccurred())
            {
                env->ExceptionClear();
            }

            if (NULL == clazz)
            {
                return true;
            }

            jmethodID method = env->GetStaticMethodID(clazz, method_name, "(I)Z");
            if (NULL != env->ExceptionOccurred())
            {
                env->ExceptionClear();
            }

            if (NULL == method)
            {
                return true;
            }

            jboolean result = env->CallStaticBooleanMethod(clazz, method, fd);
            return result ? true : false;
        }
#else
        static bool Linux_Protect(const ppp::string& device, int sockfd) noexcept
        {
            int err = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, device.data(), device.size());
            return err == 0;
        }
#endif

        bool ProtectorNetwork::Protect(int sockfd) noexcept
        {
            if (sockfd == -1)
            {
                return false;
            }

            if (dev_.empty())
            {
                return true;
            }

            ProtectEventHandler e = ProtectEvent;
            if (NULL != e)
            {
                return e(sockfd);
            }

#ifdef ANDROID
            return Android_Protect(dev_, sockfd);
#else
            return Linux_Protect(dev_, sockfd);
#endif
        }
    }
}