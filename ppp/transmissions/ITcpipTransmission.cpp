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

        bool ITcpipTransmission::EnableReceiveHalfClose() noexcept {
            receive_half_close_.store(true);
            return true;
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
            if (!receive_half_close_.load()) {
                return ITransmissionQoS::DoReadBytes(y, length, self, *this, this->QoS);
            }

            // Receive half-close opt-in: same QoS read as ITransmissionQoS::DoReadBytes,
            // but a clean peer FIN leaves the carrier alive so its owner can still send.
            if (length < 1) {
                return NULLPTR;
            }
            std::shared_ptr<ITransmissionQoS> qos = this->QoS;
            std::shared_ptr<Byte> packet;
            if (NULLPTR != qos) {
                packet = qos->ReadBytes(y, length,
                    [self, this, qos](YieldContext& y, int* length) noexcept {
                        return ReadBytes(y, *length);
                    });
            }
            else {
                packet = ReadBytes(y, length);
            }
            if (NULLPTR == packet && !receive_closed_.load()) {
                Dispose();
            }
            return packet;
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
                SetStrand(strand);
                SetContext(scheduler);
            }

            if (!ok) {
                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeSchedulerUnavailable);
                }
            }

            return ok;
        }

        /**
         * @brief Suspends @p y until at least @p minimum bytes are read into @p buffer.
         */
        void ITcpipTransmission::ReadAtLeast(YieldContext& y, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
            Byte* buffer, std::size_t capacity, std::size_t minimum, std::size_t& transferred, boost::system::error_code& read_ec) noexcept {
            transferred = 0;
            auto destination = boost::asio::buffer(buffer, capacity);
            // Lab-only JSONL: carrier receive post-to-completion duration.
            ppp::diagnostics::datapath_perf::Scope receive_scope;
            const YieldContext::Anchor anchor = y.Arm();
            if (!anchor) {
                read_ec = boost::asio::error::operation_aborted;
                return;
            }

            const bool posted = ppp::coroutines::asio::PostIfRunning(socket->get_executor(),
                [socket, destination, minimum, anchor, &read_ec, &transferred, receive_scope]() noexcept {
                    boost::asio::async_read(*socket, destination, boost::asio::transfer_at_least(minimum),
                        [anchor, &read_ec, &transferred, minimum, receive_scope](const boost::system::error_code& ec, std::size_t sz) noexcept {
                            read_ec = ec;
                            transferred = sz;
                            if (!ec && sz >= minimum) {
                                ppp::diagnostics::datapath_perf::RecordCarrierReceive((int)sz, receive_scope.Elapsed());
                            }
                            anchor.R();
                        });
                });

            if (!posted) {
                read_ec = boost::asio::error::operation_aborted;
                return;
            }

            y.Suspend(anchor);
            if (!read_ec && transferred < minimum) {
                read_ec = boost::asio::error::eof;
            }
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

            // Serve what an earlier read-ahead already buffered.
            std::size_t bytes_transferred = 0;
            std::size_t buffered = read_buffered_end_ - read_buffered_begin_;
            if (buffered > 0) {
                std::size_t n = std::min<std::size_t>(buffered, (std::size_t)length);
                memcpy(packet.get(), read_buffer_.get() + read_buffered_begin_, n);
                read_buffered_begin_ += n;
                bytes_transferred = n;
            }

            if (read_buffered_begin_ == read_buffered_end_) {
                read_buffered_begin_ = 0;
                read_buffered_end_ = 0;
            }

            boost::system::error_code read_ec;
            while (!read_ec && bytes_transferred < (std::size_t)length) {
                std::size_t remaining = (std::size_t)length - bytes_transferred;
                if (NULLPTR == read_buffer_ && remaining < kReadAheadDirectThreshold) {
                    read_buffer_ = BufferswapAllocator::MakeByteArray(allocator, kReadAheadBufferSize);
                }

                if (NULLPTR == read_buffer_ || remaining >= kReadAheadDirectThreshold) {
                    // Large remainder: read it straight into the caller's buffer.
                    std::size_t sz = 0;
                    ReadAtLeast(y, socket, packet.get() + bytes_transferred, remaining, remaining, sz, read_ec);
                    bytes_transferred += sz;
                }
                else {
                    // Small remainder (typically a frame header): one read pulls in whatever
                    // the socket has, so the following payload is usually served from memory.
                    std::size_t sz = 0;
                    ReadAtLeast(y, socket, read_buffer_.get(), kReadAheadBufferSize, remaining, sz, read_ec);
                    std::size_t n = std::min<std::size_t>(sz, remaining);
                    memcpy(packet.get() + bytes_transferred, read_buffer_.get(), n);
                    bytes_transferred += n;
                    read_buffered_begin_ = n;
                    read_buffered_end_ = sz;
                }
            }

            bool ok = !read_ec && bytes_transferred == (std::size_t)length;
            if (!ok) {
                if (read_ec == boost::asio::error::eof &&
                    (role_ == TcpTransmissionRole::Child || receive_half_close_.load())) {
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
         * @return true if the write was started or posted; otherwise false.
         */
        bool ITcpipTransmission::DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
            Byte* data = packet.get() + offset;
            return StartWrite(boost::asio::buffer(data, packet_length), packet, packet_length, cb);
        }

        /**
         * @brief Writes queued frames back to back with one gathered socket write.
         *
         * The carrier is a byte stream, so the peer reads exactly the bytes that
         * consecutive DoWriteBytes() calls would have produced.
         */
        bool ITcpipTransmission::DoWriteBytesGather(const WriteSegments& segments, const AsynchronousWriteBytesCallback& cb) noexcept {
            std::shared_ptr<WriteSegments> owner = make_shared_object<WriteSegments>(segments);
            if (NULLPTR == owner) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return false;
            }

            ppp::vector<boost::asio::const_buffer> buffers;
            buffers.reserve(owner->size());

            int total = 0;
            for (const WriteSegment& segment : *owner) {
                buffers.emplace_back(segment.first.get(), static_cast<std::size_t>(segment.second));
                total += segment.second;
            }

            return StartWrite(buffers, owner, total, cb);
        }

        template <typename TBuffers, typename TOwner>
        bool ITcpipTransmission::StartWrite(const TBuffers& buffers, const TOwner& owner, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
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

            auto complete_do_write_bytes_async_callback = [self, this, socket, context, strand, buffers, owner, packet_length, cb, send_scope]() noexcept {
                // async_write is a composed operation that only references the socket and
                // reads it again (executor, follow-up writes) until it completes. Dispose()
                // drops socket_ while a write can still be in flight, so the completion must
                // keep the socket alive (ASan: heap-use-after-free in write_op on carrier exit).
                boost::asio::async_write(*socket, buffers,
                    [self, this, socket, context, strand, owner, packet_length, cb, send_scope](const boost::system::error_code& ec, std::size_t sz) noexcept {
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

            // The write queue starts at most one write at a time, so when the caller is
            // already on the socket's executor the write can start inline instead of
            // paying a handler allocation and an extra event-loop turn per frame.
            bool inline_start = NULLPTR != strand ? strand->running_in_this_thread() :
                (NULLPTR != context && context->get_executor().running_in_this_thread());
            if (inline_start) {
                complete_do_write_bytes_async_callback();
                return true;
            }

            bool posted = ppp::threading::Executors::Post(context, strand, complete_do_write_bytes_async_callback);
            if (!posted) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
            }

            return posted;
        }
    }
}
