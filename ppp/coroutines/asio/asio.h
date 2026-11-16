#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/Timer.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/asio/vdns.h>
#include <ppp/net/Ipep.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/coroutines/asio/post_if_running.h>

namespace ppp {
    namespace coroutines {
        namespace asio {
            /**
             * @file asio.h
             * @brief Provides coroutine-friendly Boost.Asio helper wrappers.
             */

#if defined(_WIN32)
#pragma optimize("", off)
#pragma optimize("gsyb2", on) /* /O1 = /Og /Os /Oy /Ob2 /GF /Gy */
#else
// TRANSMISSIONO1 compiler macros are defined to perform O1 optimizations, 
// Otherwise gcc compiler version If <= 7.5.X, 
// The O1 optimization will also be applied, 
// And the other cases will not be optimized, 
// Because this will cause the program to crash, 
// Which is a fatal BUG caused by the gcc compiler optimization. 
// Higher-version compilers should not optimize the code for gcc compiling this section.
#if defined(__clang__)
#pragma clang optimize off
#else
#pragma GCC push_options
#if defined(TRANSMISSION_O1) || (__GNUC__ < 7) || (__GNUC__ == 7 && __GNUC_MINOR__ <= 5) /* __GNUC_PATCHLEVEL__ */
#pragma GCC optimize("O1")
#else
#pragma GCC optimize("O0")
#endif
#endif
#endif
            template <typename Handler = std::nullptr_t>
            /**
             * @brief Atomically sets completion state, runs callback, and resumes coroutine.
             * @tparam Handler Optional callback type.
             * @param anchor Wakeup credential armed for the suspension being completed.
             * @param status Shared atomic state initialized to `-1`.
             * @param b Result value written as `1` or `0`.
             * @param handler Optional completion callback.
             */
            static void                                                         R(const YieldContext::Anchor& anchor, std::atomic<int>& status, bool b, const Handler& handler = NULLPTR) noexcept {
                int k = -1;
                int v = b ? 1 : 0;

                if (status.compare_exchange_strong(k, v)) {
                    if constexpr (!std::is_same<Handler, std::nullptr_t>::value) {
                        handler();
                    }

                    anchor.R();
                }
            }

            template <typename AsyncWriteStream, typename MutableBufferSequence>
            /**
             * @brief Performs `boost::asio::async_read` and blocks the coroutine until completion.
             * @return `true` when exactly the requested byte count is read.
             */
            bool                                                                async_read(AsyncWriteStream& stream, const MutableBufferSequence& buffers, YieldContext& y) noexcept {
                if (!buffers.data() || !buffers.size()) {
                    return false;
                }

                const YieldContext::Anchor anchor = y.Arm();
                if (!anchor) {
                    return false;
                }

                int len = -1;
                const bool posted = PostIfRunning(stream.get_executor(),
                    [&stream, &buffers, anchor, &len]() noexcept {
                        boost::asio::async_read(stream, constantof(buffers),
                            [anchor, &len](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                len = std::max<int>(ec ? -1 : sz, -1);
                                anchor.R();
                            });
                    });

                if (!posted) {
                    return false;
                }

                y.Suspend(anchor);
                return len == buffers.size();
            }

            template <typename AsyncWriteStream, typename ConstBufferSequence>
            /**
             * @brief Performs `boost::asio::async_write` and blocks the coroutine until completion.
             * @return `true` on success.
             */
            bool                                                                async_write(AsyncWriteStream& stream, const ConstBufferSequence& buffers, YieldContext& y) noexcept {
                if (!buffers.data() || !buffers.size()) {
                    return false;
                }

                const YieldContext::Anchor anchor = y.Arm();
                if (!anchor) {
                    return false;
                }

                bool ok = false;
                const bool posted = PostIfRunning(stream.get_executor(),
                    [&stream, &buffers, anchor, &ok]() noexcept {
                        boost::asio::async_write(stream, constantof(buffers),
                            [anchor, &ok](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                ok = ec == boost::system::errc::success; /* b is boost::system::errc::success. */
                                anchor.R();
                            });
                    });

                if (!posted) {
                    return false;
                }

                y.Suspend(anchor);
                return ok;
            }

            template <typename AsyncWriteStream, typename MutableBufferSequence>
            /**
             * @brief Performs `async_read_some` and blocks the coroutine until completion.
             * @return Number of bytes read, or `-1` on failure.
             */
            int                                                                 async_read_some(AsyncWriteStream& stream, const MutableBufferSequence& buffers, YieldContext& y) noexcept {
                int len = -1;
                if (!buffers.data() || !buffers.size()) {
                    return len;
                }

                const YieldContext::Anchor anchor = y.Arm();
                if (!anchor) {
                    return len;
                }

                const bool posted = PostIfRunning(stream.get_executor(),
                    [&stream, &buffers, anchor, &len]() noexcept {
                        stream.async_read_some(constantof(buffers),
                            [anchor, &len](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                len = std::max<int>(ec ? -1 : sz, -1);
                                anchor.R();
                            });
                    });

                if (!posted) {
                    return -1;
                }

                y.Suspend(anchor);
                return len;
            }

            /**
             * @brief Suspends the coroutine for the requested duration.
             * @param y Yield context.
             * @param milliseconds Sleep duration in milliseconds.
             * @return `true` when timeout scheduling succeeds.
             */
            inline bool                                                         async_sleep(YieldContext& y, int milliseconds) noexcept {
                return ppp::threading::Timer::Timeout(milliseconds, y);
            }

            /**
             * @brief Asynchronously connects a TCP socket and waits in coroutine style.
             * @param socket Target TCP socket.
             * @param remoteEP Remote endpoint.
             * @param y Yield context.
             * @return `true` on successful connect.
             */
            inline bool                                                         async_connect(boost::asio::ip::tcp::socket& socket, const boost::asio::ip::tcp::endpoint& remoteEP, YieldContext& y) noexcept {
                boost::asio::ip::address address = remoteEP.address();
                if (ppp::net::IPEndPoint::IsInvalid(address)) {
                    return false;
                }

                int port = remoteEP.port();
                if (port <= ppp::net::IPEndPoint::MinPort || port > ppp::net::IPEndPoint::MaxPort) {
                    return false;
                }

                const YieldContext::Anchor anchor = y.Arm();
                if (!anchor) {
                    return false;
                }

                bool ok = false;
                const bool posted = PostIfRunning(socket.get_executor(), 
                    [&socket, &remoteEP, anchor, &ok]() noexcept {
                        socket.async_connect(remoteEP,
                            [anchor, &ok](const boost::system::error_code& ec) noexcept {
                                ok = ec == boost::system::errc::success; /* b is boost::system::errc::success. */
                                anchor.R();
                            });
                        });

                if (!posted) {
                    return false;
                }

                y.Suspend(anchor);
                return ok;
            }

            template <class AsyncSocket, class TProtocol>
            /**
             * @brief Opens a socket protocol with platform-specific safety handling.
             * @return `true` when the socket opens successfully.
             */
            bool                                                                async_open(YieldContext& y, AsyncSocket& socket, const TProtocol& protocol) noexcept {
                /**
                 * @brief Android-specific workaround.
                 *
                 * Some Android platform versions can crash when `socket.open` is
                 * executed directly inside stackful coroutine context. To avoid this,
                 * open is delegated to the framework-driven executor thread.
                 */
#if defined(_ANDROID)
                const YieldContext::Anchor anchor = y.Arm();
                if (!anchor) {
                    return false;
                }

                bool ok = false;
                const bool posted = PostIfRunning(socket.get_executor(),
                    [&socket, &protocol, &ok, anchor]() noexcept {
                        boost::system::error_code ec;
                        socket.open(protocol, ec);

                        if (ec == boost::system::errc::success) {
                            ok = true;
                        }

                        anchor.R();
                    });

                if (!posted) {
                    return false;
                }

                y.Suspend(anchor);
                return ok;
#else
                boost::system::error_code ec;
                socket.open(protocol, ec);

                return ec == boost::system::errc::success;
#endif
            }
            
            template <class TProtocol>
            /**
             * @brief Resolves a host name to endpoint and waits coroutine-style.
             * @param hostname Host name to resolve.
             * @param port Target port.
             * @param y Yield context.
             * @return Resolved endpoint, or wildcard endpoint when resolve fails.
             */
            boost::asio::ip::basic_endpoint<TProtocol>                          GetAddressByHostName(const char* hostname, int port, YieldContext& y) noexcept {
                typedef boost::asio::ip::basic_resolver<TProtocol>              protocol_resolver;
                typedef ppp::net::IPEndPoint                                    IPEndPoint;
                typedef ppp::net::Ipep                                          Ipep;
                typedef std::atomic<bool>                                       atomic_bool;

                if (NULLPTR == hostname || *hostname == '\x0') {
                    return IPEndPoint::AnyAddressV4<TProtocol>(IPEndPoint::MinPort);
                }

                if (!y) {
                    return IPEndPoint::AnyAddressV4<TProtocol>(IPEndPoint::MinPort);
                }

                std::shared_ptr<atomic_bool> status = make_shared_object<atomic_bool>(false);
                if (NULLPTR == status) {
                    return IPEndPoint::AnyAddressV4<TProtocol>(IPEndPoint::MinPort);
                }

                const YieldContext::Anchor anchor = y.Arm();
                if (!anchor) {
                    return IPEndPoint::AnyAddressV4<TProtocol>(IPEndPoint::MinPort);
                }

                boost::asio::ip::basic_endpoint<TProtocol> results = IPEndPoint::AnyAddressV4<TProtocol>(IPEndPoint::MinPort);
                boost::asio::io_context& context = y.GetContext();
                boost::asio::strand<boost::asio::io_context::executor_type>* strand = y.GetStrand();

                /**
                 * @brief Resolve deadline. `status` is the single-wakeup latch shared by the
                 *        resolver callback, the failure path and this timer, so whichever
                 *        side wins wakes the coroutine exactly once. A late resolver result
                 *        finds the latch set and does nothing (the internal resolver of
                 *        Ipep::GetAddressByHostName is not externally cancellable).
                 */
                std::shared_ptr<boost::asio::steady_timer> deadline = strand ?
                    make_shared_object<boost::asio::steady_timer>(*strand) :
                    make_shared_object<boost::asio::steady_timer>(context);

                auto processing =
                    [status, &results, anchor, deadline](const std::shared_ptr<IPEndPoint>& ep) noexcept {
                        if (!status->exchange(true)) {
                            if (NULLPTR != deadline) {
                                try { deadline->cancel(); } catch (...) {}
                            }

                            if (NULLPTR != ep) {
                                results = IPEndPoint::ToEndPoint<TProtocol>(*ep);
                            }

                            anchor.R();
                        }
                    };

                const bool posted = ppp::threading::Executors::Post(addressof(context), strand, 
                    [anchor, &context, hostname, port, &processing, status, deadline]() noexcept {
                        if (NULLPTR != deadline) {
                            deadline->expires_after(std::chrono::milliseconds(PPP_RESOLVE_DNS_TIMEOUT));
                            deadline->async_wait(
                                [deadline, status, anchor](const boost::system::error_code& ec) noexcept {
                                    if (!ec && !status->exchange(true)) {
                                        anchor.R();
                                    }
                                });
                        }

                        if (!Ipep::GetAddressByHostName(context, hostname, port, processing)) {
                            if (!status->exchange(true)) {
                                if (NULLPTR != deadline) {
                                    try { deadline->cancel(); } catch (...) {}
                                }

                                anchor.R();
                            }
                        }
                    });

                if (!posted) {
                    return results;
                }

                y.Suspend(anchor);
                return results;
            }
#if defined(_WIN32)
#pragma optimize("", on)
#else
#if defined(__clang__)
#pragma clang optimize on
#else
#pragma GCC pop_options
#endif
#endif
        }
    }
}
