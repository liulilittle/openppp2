#pragma once

/**
 * @file SharedBufferReceive.h
 * @brief Datagram receive helper for buffers shared by several sockets on one io_context.
 */

#include <boost/asio.hpp>

#include <cstddef>
#include <utility>

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Receives one datagram into a buffer that other sockets on the same
             *        io_context may also use (for example Executors::GetCachedBuffer()).
             *
             * A plain async_receive_from() lets bytes land in the buffer before the
             * completion handler runs: IOCP writes into it when the datagram arrives, and
             * Asio's epoll reactor performs a speculative read when the operation starts.
             * With two sockets sharing one buffer, the second write overwrites the first
             * socket's datagram while its completion is still queued.
             *
             * This helper waits for readability and then reads synchronously inside the
             * completion, so the buffer is filled immediately before @p handler runs on the
             * context thread. @p handler must finish using the buffer before it returns.
             *
             * @param socket Datagram socket; switched to non-blocking mode on first use.
             * @param buffer Receive buffer, possibly shared with other sockets.
             * @param size Buffer capacity in bytes.
             * @param source Receives the sender endpoint; must outlive the operation.
             * @param handler Called as handler(const boost::system::error_code&, std::size_t).
             */
            template <typename TSocket, typename TEndpoint, typename THandler>
            void AsyncReceiveFromSharedBuffer(TSocket& socket, void* buffer, std::size_t size, TEndpoint& source, THandler&& handler) noexcept {
                socket.async_wait(TSocket::wait_read,
                    [&socket, buffer, size, &source, handler = std::forward<THandler>(handler)](const boost::system::error_code& ec) mutable noexcept {
                        if (ec) {
                            handler(ec, 0);
                            return;
                        }

                        boost::system::error_code receive_ec;
                        if (!socket.non_blocking()) {
                            socket.non_blocking(true, receive_ec);
                        }

                        std::size_t bytes_transferred = 0;
                        if (!receive_ec) {
                            bytes_transferred = socket.receive_from(boost::asio::buffer(buffer, size), source, 0, receive_ec);
                        }

                        // Readiness can be spurious (for example a datagram dropped after a
                        // checksum failure); wait again instead of reporting an error.
                        if (receive_ec == boost::asio::error::would_block ||
                            receive_ec == boost::asio::error::try_again ||
                            receive_ec == boost::asio::error::interrupted) {
                            AsyncReceiveFromSharedBuffer(socket, buffer, size, source, std::move(handler));
                            return;
                        }

                        handler(receive_ec, bytes_transferred);
                    });
            }
        }
    }
}
