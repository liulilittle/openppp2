#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/diagnostics/DatapathPerfJson.h>

/**
 * @file ITcpipTransmission.cpp
 * @brief Implements TCP socket-based transmission read/write and lifecycle logic.
 */
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>

#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

using ppp::net::Socket;
using ppp::net::IPEndPoint;

namespace ppp {
    namespace transmissions {
        using ppp::telemetry::Level;

        namespace {
            const char* TcpTransmissionRoleName(TcpTransmissionRole role) noexcept {
                switch (role) {
                case TcpTransmissionRole::Main:
                    return "main";
                case TcpTransmissionRole::Server:
                    return "server";
                case TcpTransmissionRole::Child:
                default:
                    return "child";
                }
            }

            const char* TcpTransmissionConnectMetric(TcpTransmissionRole role) noexcept {
                switch (role) {
                case TcpTransmissionRole::Main:
                    return "tcpip.connect.main";
                case TcpTransmissionRole::Server:
                    return "tcpip.connect.server";
                case TcpTransmissionRole::Child:
                default:
                    return "tcpip.connect.child";
                }
            }

            const char* TcpTransmissionCloseMetric(TcpTransmissionRole role) noexcept {
                switch (role) {
                case TcpTransmissionRole::Main:
                    return "tcpip.close.main";
                case TcpTransmissionRole::Server:
                    return "tcpip.close.server";
                case TcpTransmissionRole::Child:
                default:
                    return "tcpip.close.child";
                }
            }
        }

        /**
         * @brief Constructs a TCP/IP transmission and caches the remote endpoint.
         */
        ITcpipTransmission::ITcpipTransmission(
            const ContextPtr&                                       context,
            const StrandPtr&                                        strand,
            const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
            const AppConfigurationPtr&                              configuration,
            TcpTransmissionRole                                     role) noexcept
            : ITransmission(context, strand, configuration)
            , disposed_(FALSE)
            , socket_(socket)
            , role_(role) {
            boost::system::error_code ec;
            remoteEP_ = ppp::net::Ipep::V6ToV4(socket->remote_endpoint(ec));
            ppp::telemetry::Log(Level::kInfo, "tcpip", "socket established role=%s remote=%s:%u",
                TcpTransmissionRoleName(role_),
                remoteEP_.address().to_string().c_str(),
                remoteEP_.port());
            ppp::telemetry::Count(TcpTransmissionConnectMetric(role_), 1);

#if defined(_WIN32)
            if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                qoss_ = ppp::net::QoSS::New(socket->native_handle());
            }
#endif
        }

        ITcpipTransmission::~ITcpipTransmission() noexcept {
            Finalize();
        }

        /**
         * @brief Finalizes the transmission by closing the socket and releasing QoS state.
         * @note Uses atomic exchange to prevent data races - returns previous value to detect double-dispose.
         */
        void ITcpipTransmission::Finalize() noexcept {
            int disposed = disposed_.exchange(TRUE);  // Atomic swap: set true, get previous value
            if (disposed == TRUE) {
                return;  // Already disposed, avoid double cleanup
            }

            ppp::telemetry::Log(Level::kInfo, "tcpip", "socket closed role=%s remote=%s:%u",
                TcpTransmissionRoleName(role_),
                remoteEP_.address().to_string().c_str(),
                remoteEP_.port());
            ppp::telemetry::Count(TcpTransmissionCloseMetric(role_), 1);

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::atomic_load(&socket_);
            std::atomic_store(&socket_, std::shared_ptr<boost::asio::ip::tcp::socket>());

            if (socket) {
                Socket::Closesocket(socket);
            }

#if defined(_WIN32)
            qoss_.reset();
#endif
        }

        /**
         * @brief Schedules asynchronous disposal on the configured executor and strand.
         */
        void ITcpipTransmission::Dispose() noexcept {
            auto self = shared_from_this();
            ppp::threading::Executors::ContextPtr context = GetContext();
            ppp::threading::Executors::StrandPtr strand = GetStrand();

            ppp::threading::Executors::Post(context, strand,
                [self, this, context, strand]() noexcept {
                    Finalize();
                });
            ITransmission::Dispose();
        }

        /**
         * @brief Returns the cached remote endpoint.
         * @return Peer TCP endpoint.
         */
        boost::asio::ip::tcp::endpoint ITcpipTransmission::GetRemoteEndPoint() noexcept {
            return remoteEP_;
        }

        bool ITcpipTransmission::SupportsSendHalfClose() const noexcept {
            return role_ == TcpTransmissionRole::Child;
        }

        bool ITcpipTransmission::ShutdownSend() noexcept {
            if (!SupportsSendHalfClose() || disposed_.load() != FALSE) {
                return false;
            }
            bool expected = false;
            if (!send_shutdown_.compare_exchange_strong(expected, true)) {
                return true;
            }
            std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::atomic_load(&socket_);
            if (!socket || !socket->is_open()) {
                send_shutdown_.store(false);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                return false;
            }
            boost::system::error_code ec;
            socket->shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
            if (!ec) {
                ppp::telemetry::Count("tcpip.shutdown_send.child", 1);
                return true;
            }
            send_shutdown_.store(false);
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
            ppp::telemetry::Log(Level::kInfo, "tcpip", "shutdown send failed role=%s ec=%d msg=%s",
                TcpTransmissionRoleName(role_), ec.value(), ec.message().c_str());
            return false;
        }

        bool ITcpipTransmission::IsReceiveClosed() const noexcept {
            return receive_closed_.load();
        }

        /**
         * @brief Reads bytes through the QoS-managed path.
         * @param y Coroutine yield context.
         * @param length Number of bytes to read.
         * @return Read buffer on success; null on failure.
         */
        std::shared_ptr<Byte> ITcpipTransmission::DoReadBytes(YieldContext& y, int length) noexcept {
            if (disposed_.load() != FALSE) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionClosing, NULLPTR);
            }

            auto self = shared_from_this();
            return ITransmissionQoS::DoReadBytes(y, length, self, *this, this->QoS);
        }

        /**
         * @brief Migrates the socket to another scheduler when requested by Executors.
         * @return true if migration succeeds; otherwise false.
         */
        bool ITcpipTransmission::ShiftToScheduler() noexcept {
            std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::atomic_load(&socket_);
            if (!socket || !socket->is_open()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                return false;
            }

            if (disposed_.load() != FALSE) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
                return false;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket_new;
            ContextPtr scheduler;
            StrandPtr strand;

            bool ok = ppp::threading::Executors::ShiftToScheduler(*socket, socket_new, scheduler, strand);
            if (ok) {
                std::atomic_store(&socket_, socket_new);
                GetStrand() = strand;
                GetContext() = scheduler;
            }

            if (!ok) {
                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeSchedulerUnavailable);
                }
            }

            return ok;
        }

        /**
         * @brief Performs an exact-length asynchronous read from the TCP socket.
         * @param y Coroutine yield context.
         * @param length Number of bytes required.
         * @return Read buffer on success; null on failure.
         */
        std::shared_ptr<Byte> ITcpipTransmission::ReadBytes(YieldContext& y, int length) noexcept {
            std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::atomic_load(&socket_);
            if (!socket || !socket->is_open()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketOpenFailed, NULLPTR);
            }

            if (disposed_.load() != FALSE) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionClosing, NULLPTR);
            }

            if (length < 1) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TcpipTransmissionReadBytesLengthInvalid, NULLPTR);
            }

            std::shared_ptr<BufferswapAllocator> allocator = this->BufferAllocator;
            std::shared_ptr<Byte> packet = BufferswapAllocator::MakeByteArray(allocator, length);
            if (NULLPTR == packet) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed, NULLPTR);
            }

            boost::system::error_code read_ec;
            std::size_t bytes_transferred = 0;
            auto buffer = boost::asio::buffer(packet.get(), length);
            // Lab-only JSONL: exact carrier receive post-to-completion duration.
            ppp::diagnostics::datapath_perf::Scope receive_scope;
            boost::asio::post(socket->get_executor(),
                [socket, buffer, &y, &read_ec, &bytes_transferred, length, receive_scope]() noexcept {
                    boost::asio::async_read(*socket, buffer,
                        [&y, &read_ec, &bytes_transferred, length, receive_scope](const boost::system::error_code& ec, std::size_t sz) noexcept {
                            read_ec = ec;
                            bytes_transferred = sz;
                            if (!ec && sz == (std::size_t)length) {
                                ppp::diagnostics::datapath_perf::RecordCarrierReceive((int)sz, receive_scope.Elapsed());
                            }
                            y.R();
                        });
                });

            y.Suspend();
            bool ok = !read_ec && bytes_transferred == (std::size_t)length;
            if (!ok) {
                if (read_ec == boost::asio::error::eof &&
                    role_ == TcpTransmissionRole::Child) {
                    receive_closed_.store(true);
                    ppp::telemetry::Count("tcpip.receive_eof.child", 1);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketReadFailed, NULLPTR);
                }
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                ppp::telemetry::Log(Level::kInfo,
                    "tcpip",
                    "ReadBytes failed role=%s length=%d transferred=%zu disposed=%s error=%d asio_ec=%d asio_message=%s",
                    TcpTransmissionRoleName(role_),
                    length,
                    bytes_transferred,
                    disposed_.load() != FALSE ? "yes" : "no",
                    (int)ppp::diagnostics::GetLastErrorCode(),
                    read_ec.value(),
                    read_ec.message().c_str());
                Dispose();
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketReadFailed, NULLPTR);
            }

            std::shared_ptr<ITransmissionStatistics> statistics = this->Statistics;
            if (statistics) {
                statistics->AddIncomingTraffic(length);
            }

            return packet;
        }

        /**
         * @brief Queues an asynchronous socket write on the transmission executor.
         * @param packet Buffer that owns payload memory.
         * @param offset Offset to the first byte to send.
         * @param packet_length Number of bytes to send.
         * @param cb Completion callback receiving success state.
         * @return true if the write task is posted; otherwise false.
         */
        bool ITcpipTransmission::DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
            std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::atomic_load(&socket_);
            if (!socket || !socket->is_open()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                return false;
            }

            if (disposed_.load() != FALSE || send_shutdown_.load()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
                return false;
            }

            std::shared_ptr<IAsynchronousWriteIoQueue> self = shared_from_this();
            auto context = GetContext();
            auto strand = GetStrand();
            // Lab-only JSONL: physical carrier send post-to-completion duration.
            ppp::diagnostics::datapath_perf::Scope send_scope;

            auto complete_do_write_bytes_async_callback = [self, this, socket, context, strand, packet, offset, packet_length, cb, send_scope]() noexcept {
                boost::asio::async_write(*socket, boost::asio::buffer((Byte*)packet.get() + offset, packet_length),
                    [self, this, context, strand, packet, packet_length, cb, send_scope](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        bool ok = ec == boost::system::errc::success;
                        if (ok) {
                            ppp::diagnostics::datapath_perf::RecordCarrierSend((int)sz, send_scope.Elapsed());
                            std::shared_ptr<ITransmissionStatistics> statistics = this->Statistics;
                            if (statistics) {
                                statistics->AddOutgoingTraffic(packet_length);
                            }
                        }
	                        else {
	                            ppp::telemetry::Log(Level::kInfo,
	                                "tcpip",
	                                "DoWriteBytes failed role=%s ec=%d msg=%s requested=%d transferred=%zu",
	                                TcpTransmissionRoleName(role_),
	                                ec.value(),
	                                ec.message().c_str(),
	                                packet_length,
	                                sz);
	                            bool disconnected = boost::asio::error::eof == ec ||
	                                boost::asio::error::operation_aborted == ec ||
	                                boost::asio::error::connection_reset == ec ||
                                boost::asio::error::broken_pipe == ec ||
                                boost::asio::error::not_connected == ec;
                            if (!disconnected) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                            }

                            Dispose();
                        }

                        if (cb) {
                            cb(ok);
                        }
                    });
                };

            bool posted = ppp::threading::Executors::Post(context, strand, complete_do_write_bytes_async_callback);
            if (!posted) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
            }

            return posted;
        }
    }
}
