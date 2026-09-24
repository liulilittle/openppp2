/**
 * @file P2PSocketProtector.cpp
 * @brief Platform-specific socket protection implementations.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PSocketProtector.h>

#if defined(_LINUX) && !defined(_ANDROID)
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#if defined(_ANDROID)
#include <android/OpenPPP2VpnProtectBridge.h>
#endif

namespace ppp {
    namespace p2p {

        // -------------------------------------------------------------------------
        // Linux SO_MARK protector
        // -------------------------------------------------------------------------

#if defined(_LINUX) && !defined(_ANDROID)
        bool LinuxSocketProtector::Protect(int fd) noexcept {
            if (fd < 0) {
                return false;
            }
            int ret = setsockopt(fd, SOL_SOCKET, SO_MARK, &mark_, sizeof(mark_));
            return ret == 0;
        }
#endif

        // -------------------------------------------------------------------------
        // Android VpnService.protect() protector
        // -------------------------------------------------------------------------

#if defined(_ANDROID)
        bool AndroidSocketProtector::IsReady() const noexcept {
            return ppp::android::IsProtectBridgeReady();
        }

        bool AndroidSocketProtector::Protect(int fd) noexcept {
            return ppp::android::ProtectSocketFd(fd);
        }
#endif

        // -------------------------------------------------------------------------
        // Hot socket pool
        // -------------------------------------------------------------------------

        P2PSocketPool::P2PSocketPool(const std::shared_ptr<ISocketProtector>& protector,
                                     boost::asio::io_context& io_ctx,
                                     int pool_size) noexcept
            : protector_(protector)
            , io_ctx_(&io_ctx)
            , pool_size_(pool_size) {
        }

        P2PSocketPool::~P2PSocketPool() noexcept {
            available_.clear();
        }

        std::unique_ptr<boost::asio::ip::udp::socket> P2PSocketPool::Acquire() noexcept {
            // Try pool first.
            if (!available_.empty()) {
                auto socket = std::move(available_.back());
                available_.pop_back();
                if (socket && socket->is_open()) {
                    return socket;
                }
                // Stale socket in pool — discard and create new.
            }

            // Create new socket and protect it.
            auto socket = std::make_unique<boost::asio::ip::udp::socket>(*io_ctx_,
                boost::asio::ip::udp::v4());
            if (!socket || !socket->is_open()) {
                return nullptr;
            }

            int fd = static_cast<int>(socket->native_handle());
            if (!ProtectP2PSocket(protector_, fd)) {
                // H1: Protection failed — do not return an unprotected socket.
                boost::system::error_code ec;
                socket->close(ec);
                return nullptr;
            }

            return socket;
        }

        void P2PSocketPool::Return(std::unique_ptr<boost::asio::ip::udp::socket> socket) noexcept {
            if (!socket || !socket->is_open()) {
                return;
            }
            if (static_cast<int>(available_.size()) < pool_size_) {
                available_.emplace_back(std::move(socket));
            }
            // Otherwise, let the unique_ptr destructor close it.
        }

    }
}
