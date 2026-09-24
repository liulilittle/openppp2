#pragma once

/**
 * @file P2PSocketProtector.h
 * @brief Platform-adaptive socket protection for P2P UDP channels.
 *
 * Prevents routing loops on Android (VpnService.protect) and Linux
 * (SO_MARK / policy routing). Unsupported platforms fail closed.
 *
 * Implementations:
 * - Android: JNI VpnService.protect(fd) — guarded by _ANDROID macro.
 * - Linux: setsockopt SO_MARK with P2P firmware mark — guarded by _LINUX.
 * - Windows/macOS: unavailable for direct P2P until a real adapter exists.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PDefs.h>
#include <ppp/stdafx.h>
#include <boost/asio.hpp>
#include <memory>

namespace ppp {
    namespace p2p {

        /**
         * @brief Abstract socket protector interface.
         *
         * Passed to the P2P UDP channel factory. The protect() call is made
         * immediately after socket creation and before any sendto().
         */
        class ISocketProtector {
        public:
            virtual ~ISocketProtector() noexcept = default;
            virtual bool IsReady() const noexcept = 0;

            /**
             * @brief Protects a socket so that its traffic bypasses the VPN tunnel.
             *
             * @param fd Native socket file descriptor.
             * @return true if protection was applied successfully.
             */
            virtual bool Protect(int fd) noexcept = 0;
        };

        /**
         * @brief Fail-closed placeholder for unsupported platforms.
         */
        class NoOpSocketProtector final : public ISocketProtector {
        public:
            bool IsReady() const noexcept override { return false; }
            bool Protect(int /*fd*/) noexcept override { return true; }
        };

#if defined(_LINUX) && !defined(_ANDROID)
        /**
         * @brief Linux SO_MARK socket protector.
         *
         * Sets SO_MARK on the socket with a dedicated firmware mark (0x5032)
         * so that policy routing can direct P2P traffic outside the VPN tunnel.
         */
        class LinuxSocketProtector final : public ISocketProtector {
        public:
            explicit LinuxSocketProtector(uint32_t mark = SOCKET_MARK_P2P) noexcept : mark_(mark) {}
            bool IsReady() const noexcept override { return true; }
            bool Protect(int fd) noexcept override;

        private:
            uint32_t mark_;
        };
#endif

#if defined(_ANDROID)
        /**
         * @brief Android VpnService.protect() socket protector via JNI.
         *
         * Calls VpnService.protect(fd) through JNI to prevent traffic
         * from looping back into the VPN tunnel. Requires the JNI
         * environment and VpnService reference to be set before use.
         */
        class AndroidSocketProtector final : public ISocketProtector {
        public:
            AndroidSocketProtector() noexcept = default;
            bool IsReady() const noexcept override;
            bool Protect(int fd) noexcept override;
        };
#endif

        /**
         * @brief Factory: creates the platform-appropriate socket protector.
         *
         * @return Shared pointer to the protector instance.
         */
        inline std::shared_ptr<ISocketProtector> CreateSocketProtector() noexcept {
#if defined(_ANDROID)
            return std::make_shared<AndroidSocketProtector>();
#elif defined(_LINUX)
            return std::make_shared<LinuxSocketProtector>();
#else
            return std::make_shared<NoOpSocketProtector>();
#endif
        }

        inline bool ProtectP2PSocket(const std::shared_ptr<ISocketProtector>& protector,
                                     int fd) noexcept {
            return protector && protector->IsReady() && protector->Protect(fd);
        }

        /**
         * @brief Hot socket pool for reusing pre-protected UDP sockets.
         *
         * Maintains a small pool of sockets that have already been protected,
         * avoiding the protect() syscall overhead on every new channel.
         */
        class P2PSocketPool final {
        public:
            /**
             * @brief Constructs the socket pool.
             * @param protector Socket protector to apply to new sockets.
             * @param io_ctx    Boost.Asio io_context for socket creation.
             * @param pool_size Maximum number of pooled sockets.
             */
            P2PSocketPool(const std::shared_ptr<ISocketProtector>& protector,
                          boost::asio::io_context& io_ctx,
                          int pool_size = HOT_SOCKET_POOL_SIZE) noexcept;

            ~P2PSocketPool() noexcept;

            /**
             * @brief Acquires a pre-protected UDP socket from the pool.
             *
             * If the pool is empty, creates and protects a new socket.
             * Returns a unique_ptr that returns the socket to the pool on destruction.
             *
             * @return Boost UDP socket (may be invalid if creation failed).
             */
            std::unique_ptr<boost::asio::ip::udp::socket> Acquire() noexcept;

        private:
            void Return(std::unique_ptr<boost::asio::ip::udp::socket> socket) noexcept;

            std::shared_ptr<ISocketProtector>       protector_;
            boost::asio::io_context*                io_ctx_;
            int                                     pool_size_;
            ppp::vector<std::unique_ptr<boost::asio::ip::udp::socket>> available_;
        };

    }
}
