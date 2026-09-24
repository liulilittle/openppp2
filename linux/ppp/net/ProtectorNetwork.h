#pragma once

#include <ppp/stdafx.h>
#include <ppp/coroutines/YieldContext.h>
#include <linux/ppp/net/ProtectorNetworkRequest.h>

#if defined(_ANDROID)
#include <android/log.h>
#include <jni.h>
#endif

namespace ppp 
{
    namespace net
    {
        class ProtectorNetwork : public std::enable_shared_from_this<ProtectorNetwork>
        {
        public:
            typedef ppp::function<bool(int)>                        ProtectEventHandler;
            typedef ppp::coroutines::YieldContext                   YieldContext;
            typedef std::mutex                                      SynchronizedObject;
            typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;

        public:
            ProtectorNetwork(const ppp::string& dev) noexcept;
            virtual ~ProtectorNetwork() = default;

        public:
            ProtectEventHandler                                     ProtectEvent;

        public:             
            virtual bool                                            Protect(int sockfd, YieldContext& y) noexcept;

            /**
             * @brief Synchronous socket-protection overload that does not require a YieldContext.
             *
             * @details This method is intended for use in non-coroutine async contexts
             *          (e.g. DnsResolver's pure-async callbacks) where fabricating a
             *          YieldContext is not possible.
             *
             *          Behaviour per platform:
             *          - If ProtectEvent is set, delegates to it (synchronous, identical
             *            to the coroutine Protect() path).
             *          - Non-Android Linux: falls back to SO_BINDTODEVICE.
             *          - Android without ProtectEvent: returns false (caller must handle).
             *
             * @param sockfd  Socket file descriptor to protect.
             * @return true if the socket was protected; false on error.
             */
            bool                                                    ProtectSync(int sockfd) noexcept;

        public:             
            static int                                              Recvfd(const char* unix_path, int milliSecondsTimeout = 3000, bool sync = true) noexcept;
            static int                                              Recvfd(const char* unix_path, int milliSecondsTimeout, bool sync, int& fd) noexcept;

        public:             
            static int                                              Sendfd2(const char* unix_path, int fd, int milliSecondsTimeout, bool sync, char& r) noexcept;
            static int                                              Sendfd(const char* unix_path, int fd, int milliSecondsTimeout = 3000, bool sync = true) noexcept;

#if defined(_ANDROID)               

        private:
            struct JniSession;

        public:
            // When Java/Kotlin creates a new thread and calls the root Loopback function, 
            // The JVM needs to pass in a JNIEnv environment pointer assigned to the current thread by the JVM, 
            // Including a loop to block the current thread boost::asio::context.
            bool                                                    JoinJNI(const std::shared_ptr<boost::asio::io_context>& context, JNIEnv* env) noexcept;
            // Execute when the destination thread exits, because the thread may be exiting, 
            // To prevent security problems caused by multithreading.
            bool                                                    DetachJNI() noexcept;
            bool                                                    ProtectJNI(const std::shared_ptr<boost::asio::io_context>& context, int sockfd, YieldContext& y) noexcept;

        private:
            bool                                                    ProtectJNISession(const std::shared_ptr<JniSession>& session, int sockfd, YieldContext& y) noexcept;

        public:
            // If PPP is used as the embedded layer of an apps, 
            // It is recommended not to rely on the sendfd/recvfd model for Java layer to protect network sockets.  
            // Instead of using a VPN virtual loopback network, 
            // It is preferable to utilize the C/C++ layer to invoke Java/Dex layer's class functions through JNI interface for protection.
            //
            // Java class:
            // public final class libopenpppp2 {
            //      static {
            //          System.loadLibrary("openppp2");
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
            static bool                                             ProtectJNI(JNIEnv* env, jint fd) noexcept;
            
        public:
            std::shared_ptr<boost::asio::io_context>                GetContext() noexcept
            {
                SynchronizedObjectScope scope(syncobj_);
                return session_ ? session_->context : NULLPTR;
            }
            JNIEnv*                                                 GetEnvironment() noexcept
            {
                SynchronizedObjectScope scope(syncobj_);
                return session_ ? session_->env : NULLPTR;
            }
#endif

        private:                
#if defined(_ANDROID)
            struct JniSession final
            {
                JniSession(std::uint64_t generation_, const std::shared_ptr<boost::asio::io_context>& context_, JNIEnv* env_)
                    : generation(generation_)
                    , context(context_)
                    , env(env_)
                    , requests(generation_)
                {
                }

                const std::uint64_t                                  generation;
                const std::shared_ptr<boost::asio::io_context>        context;
                JNIEnv* const                                         env;
                ProtectorNetworkRequestSession                        requests;
            };

            SynchronizedObject                                      syncobj_;
            std::uint64_t                                           next_generation_ = 0;
            std::shared_ptr<JniSession>                             session_;
#endif
            const ppp::string                                       dev_;
        };
    }
}
