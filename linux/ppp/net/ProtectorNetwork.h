#pragma once

#include <ppp/stdafx.h>

#ifdef ANDROID
#include <android/log.h>
#include <jni.h>
#endif

namespace ppp 
{
    namespace net
    {
        class ProtectorNetwork
        {
        public:
            typedef ppp::function<bool(int)>        ProtectEventHandler;

        public:
            ProtectorNetwork(const ppp::string& dev) noexcept;

        public:
            ProtectEventHandler                     ProtectEvent;

        public:
            virtual bool                            Protect(int sockfd) noexcept;
#ifdef ANDROID
            // If PPP is used as the embedded layer of an apps, 
            // It is recommended not to rely on the sendfd/recvfd model for Java layer to protect network sockets.  
            // Instead of using a VPN virtual loopback network, 
            // It is preferable to utilize the C/C++ layer to invoke Java/Dex layer's class functions through JNI interface for protection.
            // Java class:
            // public final class libcor32 {
            //      static {
            //          System.loadLibrary("ppp");
            //      }
            //
            //      public static boolean protect(int sockfd) {
            //          Network network = PppVpnNetworkManager.getActiveNetwork(application);
            //          if (network != null) {
            //              bind(network, sockfd);
            //          }
            //          return true;
            //      }
            //
            //      public static int bind(Network network, int fd) {
            //          if (network == null) {
            //              return -1;
            //          }
            //
            //          FileDescriptor fileDescriptor = Files.newFileDescriptor(fd);
            //          try {
            //              InetAddress inetAddress = ((InetSocketAddress) Os.getpeername(fileDescriptor)).getAddress();
            //              if (!inetAddress.isAnyLocalAddress()) {
            //                  return 1;
            //              }
            //          } catch (ErrnoException e) {
            //              if (e.errno != OsConstants.ENOTCONN) {
            //                  return e.errno;
            //              }
            //          }
            // 
            //          try {
            //              if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            //                  network.bindSocket(fileDescriptor);
            //              }
            //              return 0;
            //          } catch (Throwable e) {
            //              Throwable cause = e.getCause();
            //              if (cause != null) {
            //                  if (cause instanceof ErrnoException) {
            //                      ErrnoException ee = (ErrnoException) e.getCause();
            //                      if (ee.errno == Marco.ENONET) {
            //                          return ee.errno;
            //                      }
            //                  }
            //              }
            //              e.printStackTrace();
            //          }
            //          return -1;
            //      }
            // }
            static bool                             ProtectJNI(JNIEnv* env, jint fd, const char* class_name, const char* method_name) noexcept;
#endif
            static int                              Sendfd(const char* unix_path, int fd, int milliSecondsTimeout = 3000, bool sync = true) noexcept 
            {
                char r;
                int err = Sendfd(unix_path, fd, milliSecondsTimeout, sync, r);
                return err;
            }
            static int                              Sendfd(const char* unix_path, int fd, int milliSecondsTimeout, bool sync, char& r) noexcept;
            static int                              Recvfd(const char* unix_path, int milliSecondsTimeout = 3000, bool sync = true) noexcept 
            {
                int fd;
                int err = Recvfd(unix_path, milliSecondsTimeout, sync, fd);
                return err;
            }
            static int                              Recvfd(const char* unix_path, int milliSecondsTimeout, bool sync, int& fd) noexcept;

        private:
            const ppp::string                       dev_;
        };
    }
}