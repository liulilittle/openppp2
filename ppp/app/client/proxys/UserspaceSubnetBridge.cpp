#include <ppp/app/client/proxys/UserspaceSubnetBridge.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/net/Socket.h>

#include <libtcpip/netstack_outbound.h>

#include <cstring>

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                // One read in flight at a time; lwIP copies it before the next read starts.
                static constexpr int kUserspaceSubnetReadSize = 16384;

                UserspaceSubnetBridge::UserspaceSubnetBridge(const std::shared_ptr<boost::asio::ip::tcp::socket>& local_socket,
                    int connect_timeout_seconds) noexcept
                    : local_socket_(local_socket)
                    , connect_timeout_seconds_(connect_timeout_seconds > 0 ? connect_timeout_seconds : 5) {
                }

                UserspaceSubnetBridge::~UserspaceSubnetBridge() noexcept {
                    Finalize();
                }

                bool UserspaceSubnetBridge::Connect(const boost::asio::ip::tcp::endpoint& remote, ppp::coroutines::YieldContext& y) noexcept {
                    if (disposed_.load(std::memory_order_acquire) || NULLPTR == local_socket_ || !remote.address().is_v4()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    }

                    std::shared_ptr<lwip::netstack_outbound> outbound = ppp::make_shared_object<lwip::netstack_outbound>();
                    if (NULLPTR == outbound) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    const ppp::coroutines::YieldContext::Anchor anchor = y.Arm();
                    if (!anchor) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                    }

                    // Shared because the stack's callback or the timer may fire after the
                    // coroutine resumed; only the first outcome counts.
                    std::shared_ptr<std::atomic<int>> outcome = ppp::make_shared_object<std::atomic<int>>(0);
                    std::shared_ptr<boost::asio::steady_timer> timer = ppp::make_shared_object<boost::asio::steady_timer>(y.GetContext());
                    if (NULLPTR == outcome || NULLPTR == timer) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    std::weak_ptr<UserspaceSubnetBridge> weak = shared_from_this();
                    boost::asio::any_io_executor executor = local_socket_->get_executor();
                    bool posted = outbound->connect(
                        htonl(remote.address().to_v4().to_uint()), remote.port(),
                        [outcome, anchor](bool established) noexcept {
                            int expected = 0;
                            if (outcome->compare_exchange_strong(expected, established ? 1 : -1)) {
                                anchor.R();
                            }
                        },
                        [weak, executor](const void* data, int size) noexcept {
                            std::shared_ptr<Byte> copy = ppp::make_shared_alloc<Byte>(size);
                            if (NULLPTR == copy) {
                                return;
                            }

                            memcpy(copy.get(), data, size);
                            boost::asio::post(executor,
                                [weak, copy, size]() noexcept {
                                    if (std::shared_ptr<UserspaceSubnetBridge> self = weak.lock(); NULLPTR != self) {
                                        self->OnPeerData(copy, size);
                                    }
                                });
                        },
                        [weak, executor]() noexcept {
                            boost::asio::post(executor,
                                [weak]() noexcept {
                                    if (std::shared_ptr<UserspaceSubnetBridge> self = weak.lock(); NULLPTR != self) {
                                        self->Dispose();
                                    }
                                });
                        });
                    if (!posted) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelLoopbackSetupFailed);
                    }

                    outbound_ = outbound;
                    timer->expires_after(std::chrono::seconds(connect_timeout_seconds_));
                    timer->async_wait(
                        [outcome, anchor](const boost::system::error_code& ec) noexcept {
                            int expected = 0;
                            if (!ec && outcome->compare_exchange_strong(expected, -1)) {
                                anchor.R();
                            }
                        });

                    y.Suspend(anchor);
                    timer->cancel();

                    connected_ = outcome->load() > 0;
                    if (!connected_) {
                        outbound->close();
                        outbound_.reset();
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TcpConnectFailed);
                    }

                    return true;
                }

                bool UserspaceSubnetBridge::Send(const void* data, int size) noexcept {
                    std::shared_ptr<lwip::netstack_outbound> outbound = outbound_;
                    if (NULLPTR == data || size < 1 || NULLPTR == outbound || disposed_.load(std::memory_order_acquire)) {
                        return false;
                    }

                    std::shared_ptr<Byte> copy = ppp::make_shared_alloc<Byte>(size);
                    if (NULLPTR == copy) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    memcpy(copy.get(), data, size);
                    return outbound->send(copy, size, NULLPTR);
                }

                bool UserspaceSubnetBridge::Run() noexcept {
                    if (!connected_ || disposed_.load(std::memory_order_acquire) || NULLPTR == local_socket_) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                    }

                    read_buffer_ = ppp::make_shared_alloc<Byte>(kUserspaceSubnetReadSize);
                    if (NULLPTR == read_buffer_) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    std::shared_ptr<UserspaceSubnetBridge> self = shared_from_this();
                    boost::asio::post(local_socket_->get_executor(),
                        [self, this]() noexcept {
                            running_ = true;
                            ReadNext();
                            WriteNext();
                        });
                    return true;
                }

                bool UserspaceSubnetBridge::IsLinked() noexcept {
                    return connected_ && !disposed_.load(std::memory_order_acquire);
                }

                void UserspaceSubnetBridge::OnPeerData(const std::shared_ptr<Byte>& data, int size) noexcept {
                    if (disposed_.load(std::memory_order_acquire)) {
                        return;
                    }

                    Chunk chunk;
                    chunk.data = data;
                    chunk.size = size;
                    pending_.emplace_back(std::move(chunk));
                    if (running_ && !writing_) {
                        WriteNext();
                    }
                }

                /** @brief Writes peer data to the local socket in order, acknowledging each chunk after it lands. */
                void UserspaceSubnetBridge::WriteNext() noexcept {
                    if (disposed_.load(std::memory_order_acquire) || pending_.empty()) {
                        writing_ = false;
                        return;
                    }

                    writing_ = true;
                    Chunk chunk = pending_.front();
                    std::shared_ptr<UserspaceSubnetBridge> self = shared_from_this();
                    boost::asio::async_write(*local_socket_, boost::asio::buffer(chunk.data.get(), chunk.size),
                        [self, this, chunk](const boost::system::error_code& ec, std::size_t) noexcept {
                            if (ec) {
                                Dispose();
                                return;
                            }

                            pending_.pop_front();
                            if (std::shared_ptr<lwip::netstack_outbound> outbound = outbound_; NULLPTR != outbound) {
                                outbound->ack(chunk.size);
                            }

                            Activity();
                            WriteNext();
                        });
                }

                /** @brief Reads the local socket; the next read waits until the stack accepted this one. */
                void UserspaceSubnetBridge::ReadNext() noexcept {
                    if (disposed_.load(std::memory_order_acquire)) {
                        return;
                    }

                    std::shared_ptr<UserspaceSubnetBridge> self = shared_from_this();
                    local_socket_->async_read_some(boost::asio::buffer(read_buffer_.get(), kUserspaceSubnetReadSize),
                        [self, this](const boost::system::error_code& ec, std::size_t length) noexcept {
                            std::shared_ptr<lwip::netstack_outbound> outbound = outbound_;
                            if (ec || length < 1 || NULLPTR == outbound) {
                                Dispose();
                                return;
                            }

                            Activity();
                            std::weak_ptr<UserspaceSubnetBridge> weak = self;
                            boost::asio::any_io_executor executor = local_socket_->get_executor();
                            bool queued = outbound->send(read_buffer_, static_cast<int>(length),
                                [weak, executor]() noexcept {
                                    boost::asio::post(executor,
                                        [weak]() noexcept {
                                            if (std::shared_ptr<UserspaceSubnetBridge> bridge = weak.lock(); NULLPTR != bridge) {
                                                bridge->ReadNext();
                                            }
                                        });
                                });
                            if (!queued) {
                                Dispose();
                            }
                        });
                }

                void UserspaceSubnetBridge::Activity() noexcept {
                    ActivityHandler handler = OnActivity;
                    if (NULLPTR != handler) {
                        handler();
                    }
                }

                void UserspaceSubnetBridge::Dispose() noexcept {
                    if (disposed_.exchange(true, std::memory_order_acq_rel)) {
                        return;
                    }

                    Finalize();
                    ClosedHandler closed = std::move(OnClosed);
                    OnActivity = NULLPTR;
                    if (NULLPTR != closed) {
                        closed();
                    }
                }

                void UserspaceSubnetBridge::Finalize() noexcept {
                    disposed_.store(true, std::memory_order_release);
                    if (std::shared_ptr<lwip::netstack_outbound> outbound = std::move(outbound_); NULLPTR != outbound) {
                        outbound->close();
                    }

                    ppp::net::Socket::Closesocket(local_socket_);
                }
            }
        }
    }
}
