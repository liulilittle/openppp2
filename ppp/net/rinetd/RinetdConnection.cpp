/**
 * @file RinetdConnection.cpp
 * @brief Implements socket lifecycle and forwarding for rinetd relay sessions.
 */

#include <ppp/net/rinetd/RinetdConnection.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>

#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace net {
        namespace rinetd {
            /**
             * @brief Initializes relay state and optional platform QoS helpers.
             */
            RinetdConnection::RinetdConnection(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& local_socket) noexcept
                : disposed_(false)
                , connected_(false)
                , timeout_(0)
                , context_(context)
                , strand_(strand)
                , local_socket_(local_socket)
                , configuration_(configuration) {
#if defined(_WIN32)
                if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                    qoss_[0] = ppp::net::QoSS::New(local_socket->native_handle());
                }
#endif

                Update();
            }

            /**
             * @brief Destructor that enforces final cleanup.
             */
            RinetdConnection::~RinetdConnection() noexcept {
                Finalize();
            }

            /**
             * @brief Schedules finalization onto the configured execution context.
             */
            void RinetdConnection::Dispose() noexcept {
                auto self = shared_from_this();
                ppp::threading::Executors::ContextPtr context = context_;
                ppp::threading::Executors::StrandPtr strand = strand_;

                ppp::threading::Executors::Post(context, strand,
                    [self, this, context, strand]() noexcept {
                        Finalize();
                    });
            }

            /**
             * @brief Updates absolute timeout for connect or inactivity phase.
             */
            void RinetdConnection::Update() noexcept {
                uint64_t now = ppp::threading::Executors::GetTickCount();
                if (remote_buffer_) {
                    timeout_ = now + (UInt64)configuration_->tcp.inactive.timeout * 1000;
                }
                else {
                    timeout_ = now + (UInt64)configuration_->tcp.connect.timeout * 1000;
                }
            }

            /**
             * @brief Releases QoS objects and closes both relay sockets.
             */
            void RinetdConnection::Finalize() noexcept {
#if defined(_WIN32)
                for (std::shared_ptr<ppp::net::QoSS>& qoss : qoss_) {
                    qoss.reset();
                }
#endif

                disposed_ = true;
                ppp::net::Socket::Closesocket(local_socket_);
                ppp::net::Socket::Closesocket(remote_socket_);
            }
 
            /**
             * @brief Opens and connects the remote socket endpoint.
             */
            bool RinetdConnection::Open(const boost::asio::ip::tcp::endpoint& remoteEP, ppp::coroutines::YieldContext& y) noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (remote_socket_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RinetdConnectionOpenSocketAlreadyAllocated);
                    return false;
                }

                boost::asio::ip::address remoteIP = remoteEP.address();
                if (remoteIP.is_unspecified()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }

                if (remoteIP.is_multicast()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }

                if (ppp::net::IPEndPoint::IsInvalid(remoteIP)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return false;
                }

                int remotePort = remoteEP.port();
                if (remotePort <= ppp::net::IPEndPoint::MinPort || remotePort > ppp::net::IPEndPoint::MaxPort) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = strand_ ?
                    make_shared_object<boost::asio::ip::tcp::socket>(*strand_) : make_shared_object<boost::asio::ip::tcp::socket>(*context_);
                remote_socket_= socket;
                
                if (NULLPTR == socket) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                bool opened = ppp::coroutines::asio::async_open(y, *socket, remoteEP.protocol());
                if (!opened) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                    return false;
                }

                RemoteSocketProtector remote_socket_protector = ProtectRemoteSocket;
                if (RemoteSocketProtectorRequired && !remote_socket_protector) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                    return false;
                }
                if (remote_socket_protector && !remote_socket_protector(socket->native_handle(), y)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                    return false;
                }

                /**
                 * @brief Linux-specific physical-network protection for non-loopback peers.
                 *
                 * IPv4 remote sockets may be protected to avoid routing loops with virtual
                 * adapters, while IPv6 is intentionally excluded by original design notes.
                 */
#if defined(_WIN32)
                if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                    qoss_[1] = ppp::net::QoSS::New(socket->native_handle(), remoteIP, remotePort);
                }
#elif defined(_LINUX)
                // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter. 
                // IPV6 does not need to be linked, because VPN is IPV4, 
                // And IPV6 does not affect the physical layer network communication of the VPN.
                if (!remote_socket_protector && !remoteIP.is_loopback()) {
                    auto protector_network = ProtectorNetwork; 
                    if (NULLPTR != protector_network) {
                        if (!protector_network->Protect(socket->native_handle(), y)) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                            return false;
                        }
                    }
                }
#endif

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);
                ppp::net::Socket::AdjustSocketOptional(*socket, remoteIP.is_v4(), configuration->tcp.fast_open, configuration->tcp.turbo);

                bool connect_ok = ppp::coroutines::asio::async_connect(*socket, remoteEP, y);
                if (connect_ok) {
                    connected_ = true;
                    Update();
                }

                return connect_ok;
            }

            /**
             * @brief Allocates forwarding buffers and starts both relay directions.
             */
            bool RinetdConnection::Run() noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (NULLPTR == configuration) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                    return false;
                }

                local_buffer_ = ppp::threading::BufferswapAllocator::MakeByteArray(configuration->GetBufferAllocator(), PPP_BUFFER_SIZE);
                if (NULLPTR == local_buffer_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                remote_buffer_ = ppp::threading::BufferswapAllocator::MakeByteArray(configuration->GetBufferAllocator(), PPP_BUFFER_SIZE);
                if (NULLPTR == remote_buffer_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                bool ok = ForwardXToY(local_socket_.get(), remote_socket_.get(), local_buffer_.get()) && ForwardXToY(remote_socket_.get(), local_socket_.get(), remote_buffer_.get());
                if (ok) {
                    Update();
                }

                return ok;
            }

            /**
             * @brief Starts one asynchronous forwarding loop.
             *
             * The callback chain performs read->write recursion and disposes the whole
             * connection whenever either direction encounters EOF or an I/O error.
             */
            bool RinetdConnection::ForwardXToY(boost::asio::ip::tcp::socket* socket, boost::asio::ip::tcp::socket* to, Byte* buffer) noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                bool opened = socket->is_open();
                if (!opened) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
                    return false;
                }

                std::shared_ptr<RinetdConnection> self = shared_from_this();
                socket->async_receive(boost::asio::buffer(buffer, PPP_BUFFER_SIZE),
                    [self, this, socket, to, buffer](const boost::system::error_code& ec, uint32_t sz) noexcept {
                        int bytes_transferred = std::max<int>(-1, ec ? -1 : static_cast<int>(sz));
                        if (bytes_transferred < 1) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpReceiveFailed);
                            Dispose();
                            return false;
                        }

                        boost::asio::async_write(*to, boost::asio::buffer(buffer, bytes_transferred),
                            [self, this, socket, to, buffer](const boost::system::error_code& ec, uint32_t sz) noexcept {
                                bool ok = ec == boost::system::errc::success;
                                if (ok) {
                                    ok = ForwardXToY(socket, to, buffer);
                                }

                                if (ok) {
                                    Update();
                                }
                                else {
                                    Dispose();
                                }
                            });
                        return true;
                    });
                return true;
            }

#if defined(_IPHONE) || defined(IPHONE)
            bool RinetdConnection::WriteRemote(const void* data, size_t len) noexcept {
                if (disposed_ || NULLPTR == data || len < 1) {
                    return len == 0;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> remote = remote_socket_;
                if (NULLPTR == remote || !remote->is_open()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketNotOpen);
                    return false;
                }

                boost::system::error_code ec;
                boost::asio::write(*remote, boost::asio::buffer(data, len), ec);
                if (ec) {
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "rinetd", "native inject write remote failed bytes=%zu error=%s",
                        len, ec.message().c_str());
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                    return false;
                }

                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "rinetd", "native inject write remote bytes=%zu", len);
                Update();
                return true;
            }

            void RinetdConnection::StartRemoteToTapRelay(const ppp::function<void(const void*, size_t)>& on_data) noexcept {
                if (disposed_ || !on_data) {
                    return;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> remote = remote_socket_;
                if (NULLPTR == remote || !remote->is_open()) {
                    return;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (NULLPTR == configuration) {
                    return;
                }

                if (NULLPTR == remote_buffer_) {
                    remote_buffer_ = ppp::threading::BufferswapAllocator::MakeByteArray(configuration->GetBufferAllocator(), PPP_BUFFER_SIZE);
                    if (NULLPTR == remote_buffer_) {
                        return;
                    }
                }

                std::shared_ptr<RinetdConnection> self = shared_from_this();
                remote->async_receive(boost::asio::buffer(remote_buffer_.get(), PPP_BUFFER_SIZE),
                    [self, this, on_data](const boost::system::error_code& ec, std::size_t bytes) noexcept {
                        if (ec || bytes < 1) {
                            if (ec && ec != boost::asio::error::operation_aborted) {
                                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "rinetd", "native inject read end bytes=%zu error=%s",
                                    bytes, ec.message().c_str());
                            }
                            return;
                        }

                        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "rinetd", "native inject read remote bytes=%zu", bytes);
                        on_data(remote_buffer_.get(), bytes);
                        Update();
                        StartRemoteToTapRelay(on_data);
                    });
            }
#endif
        }
    }
}
