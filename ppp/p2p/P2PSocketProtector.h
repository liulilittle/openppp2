#pragma once

/**
 * @file P2PSocketProtector.h
 * @brief Platform-adaptive socket protection for P2P UDP channels.
 *
 * Prevents routing loops on Android (VpnService.protect), Linux
 * (SO_BINDTODEVICE), Windows (IP_UNICAST_IF / IPV6_UNICAST_IF), and macOS
 * (IP_BOUND_IF / IPV6_BOUND_IF).
 * Unsupported platforms fail closed.
 *
 * Implementations:
 * - Android: JNI VpnService.protect(fd) — guarded by _ANDROID macro.
 * - Linux: binds to the physical interface with SO_BINDTODEVICE. The legacy
 *   mark is retained for compatibility but is not used as readiness proof.
 * - Windows: binds sockets to the physical interface with IP_UNICAST_IF
 *   (IPv4) or IPV6_UNICAST_IF (IPv6).
 * - macOS: binds sockets to the physical interface with IP_BOUND_IF (IPv4)
 *   or IPV6_BOUND_IF (IPv6).
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PDefs.h>
#include <ppp/stdafx.h>
#include <boost/asio.hpp>
#include <memory>
#include <string>
#include <utility>

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
         * @brief Linux physical-interface socket protector.
         *
         * Binds the socket to the physical interface so P2P traffic bypasses
         * the TUN route without requiring a separately managed ip rule/table.
         */
        class LinuxSocketProtector final : public ISocketProtector {
        public:
            explicit LinuxSocketProtector(
                uint32_t mark = SOCKET_MARK_P2P,
                std::string interface_name = {}) noexcept
                : mark_(mark), interface_name_(std::move(interface_name)) {}
            // SO_MARK alone is not sufficient: no ip-rule/table is installed by
            // the client. Require an explicit physical interface binding.
            bool IsReady() const noexcept override { return !interface_name_.empty(); }
            bool Protect(int fd) noexcept override;

        private:
            uint32_t mark_;
            std::string interface_name_;
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

#if defined(_WIN32)
        /** Binds P2P sockets to a Windows interface index. */
        class WindowsSocketProtector final : public ISocketProtector {
        public:
            explicit WindowsSocketProtector(int interface_index) noexcept
                : interface_index_(interface_index) {}
            bool IsReady() const noexcept override { return interface_index_ > 0; }
            bool Protect(int fd) noexcept override;

        private:
            int interface_index_;
        };
#endif

#if defined(_MACOS) && !defined(_IPHONE) && !defined(IPHONE)
        /** Binds P2P sockets to a macOS interface index. */
        class MacSocketProtector final : public ISocketProtector {
        public:
            explicit MacSocketProtector(int interface_index) noexcept
                : interface_index_(interface_index) {}
            bool IsReady() const noexcept override { return interface_index_ > 0; }
            bool Protect(int fd) noexcept override;

        private:
            int interface_index_;
        };
#endif

        /**
         * @brief Factory: creates the platform-appropriate socket protector.
         *
         * @return Shared pointer to the protector instance.
         */
        inline std::shared_ptr<ISocketProtector> CreateSocketProtector(
            int interface_index = -1,
            const std::string& interface_name = {}) noexcept {
#if defined(_ANDROID)
            return std::make_shared<AndroidSocketProtector>();
#elif defined(_LINUX)
            (void)interface_index;
            return std::make_shared<LinuxSocketProtector>(SOCKET_MARK_P2P, interface_name);
#elif defined(_WIN32)
            return std::make_shared<WindowsSocketProtector>(interface_index);
#elif defined(_MACOS) && !defined(_IPHONE) && !defined(IPHONE)
            return std::make_shared<MacSocketProtector>(interface_index);
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
