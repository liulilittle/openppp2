#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>
#include <ppp/diagnostics/Error.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>

/**
 * @file websocket_ssl_write_websocket.cpp
 * @brief Implements asynchronous write dispatch for SSL WebSocket sessions.
 */

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Queues an asynchronous write operation on the SSL WebSocket.
             * @param buffer Source buffer that contains bytes to send.
             * @param offset Zero-based byte offset into @p buffer where sending starts.
             * @param length Number of bytes to send.
             * @param cb Completion callback that receives whether sending succeeded.
             * @return true if the operation is posted to the executor; otherwise false.
             */
            bool sslwebsocket::Write(const void* buffer, int offset, int length, const AsynchronousWriteCallback& cb) noexcept {
                if (NULLPTR == buffer || 0 > offset || 1 > length) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SslWebSocketWriteInvalidArguments);
                    return false;
                }

                if (NULLPTR == cb) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SslWebSocketWriteNullCallback);
                    return false;
                }

                if (IsDisposed()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                const std::shared_ptr<SslvWebSocket> ssl_websocket = ssl_websocket_;
                if (NULLPTR == ssl_websocket || !ssl_websocket->is_open()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
                    return false;
                }

                /**
                 * @brief Takes ownership of the payload before dispatching; the caller is
                 *        free to release or overwrite @p buffer as soon as this call returns.
                 */
                std::shared_ptr<Byte> payload = ppp::make_shared_alloc<Byte>(length);
                if (NULLPTR == payload) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }
                memcpy(payload.get(), (const Byte*)buffer + offset, length);

                const std::shared_ptr<sslwebsocket> self = shared_from_this();
                ppp::threading::Executors::ContextPtr context = context_;
                ppp::threading::Executors::StrandPtr strand = strand_;

                /**
                 * @brief Enqueues the write on the serialized executor strand; the Beast
                 *        async_write chain itself is driven by DoWriteAsync() so that at
                 *        most one write is ever in flight on the stream.
                 */
                auto complete_do_async_write_callback = [self, this, cb, payload, length, ssl_websocket, context, strand]() noexcept {
                    {
                        std::lock_guard<std::mutex> scope(write_mutex_);

                        AsynchronousWriteContext message;
                        message.buffer = payload;
                        message.length = length;
                        message.cb     = cb;
                        write_queue_.emplace_back(std::move(message));
                        if (write_in_progress_) {
                            return;
                        }

                        write_in_progress_ = true;
                    }

                    DoWriteAsync();
                };

                bool ok = ppp::threading::Executors::Post(context, strand, complete_do_async_write_callback);
                if (false == ok && ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
                }

                return ok;
            }

            /**
             * @brief Starts the next queued asynchronous write, if any.
             *
             * Pops one message from the write queue and issues Beast async_write for it;
             * the completion handler re-enters this method, so queued writes are emitted
             * strictly one at a time as required by Boost.Beast.  When the TLS stream is
             * already gone the remaining queue is failed and drained instead.
             */
            void sslwebsocket::DoWriteAsync() noexcept {
                for (;;) {
                    AsynchronousWriteContext message;
                    {
                        std::lock_guard<std::mutex> scope(write_mutex_);
                        if (write_queue_.empty()) {
                            write_in_progress_ = false;
                            return;
                        }

                        message = std::move(write_queue_.front());
                        write_queue_.pop_front();
                    }

                    const std::shared_ptr<sslwebsocket> self = shared_from_this();
                    const std::shared_ptr<SslvWebSocket> ssl_websocket = ssl_websocket_;
                    const std::shared_ptr<Byte> payload = message.buffer;
                    const AsynchronousWriteCallback cb = message.cb;
                    if (NULLPTR == ssl_websocket) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
                        if (NULLPTR != cb) {
                            cb(false); /* The TLS stream is gone; fail this write and drain the rest. */
                        }
                        continue;
                    }

                    ssl_websocket->async_write(boost::asio::buffer(payload.get(), message.length),
                        [self, this, payload, cb](const boost::system::error_code& ec, size_t sz) noexcept {
                            bool ok = ec == boost::system::errc::success;
                            if (false == ok &&
                                boost::asio::error::operation_aborted != ec &&
                                boost::beast::websocket::error::closed != ec)
                            {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketWriteFailed);
                            }

                            if (NULLPTR != cb) {
                                cb(ok); /* b is boost::system::errc::success. */
                            }

                            /* Drains the next queued write; keeps at most one async_write in flight. */
                            DoWriteAsync();
                        });
                    return;
                }
            }
        }
    }
}
