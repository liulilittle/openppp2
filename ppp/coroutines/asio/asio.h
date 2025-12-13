#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/Timer.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/asio/vdns.h>
#include <ppp/net/Ipep.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace coroutines {
        namespace asio {
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
            static void                                                         R(YieldContext& y, std::atomic<int>& status, bool b, const Handler& handler = NULL) noexcept {
                int k = -1;
                int v = b ? 1 : 0;

                if (status.compare_exchange_strong(k, v)) {
                    if constexpr (!std::is_same<Handler, std::nullptr_t>::value) {
                        handler();
                    }

                    y.R();
                }
            }

            template <typename AsyncWriteStream, typename MutableBufferSequence>
            bool                                                                async_read(AsyncWriteStream& stream, const MutableBufferSequence& buffers, YieldContext& y) noexcept {
                if (!buffers.data() || !buffers.size()) {
                    return false;
                }

                int len = -1;
                boost::asio::post(stream.get_executor(),
                    [&stream, &buffers, &y, &len]() noexcept {
                        boost::asio::async_read(stream, constantof(buffers),
                            [&y, &len](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                len = std::max<int>(ec ? -1 : sz, -1);
                                y.R();
                            });
                    });

                y.Suspend();
                return len == buffers.size();
            }

            template <typename AsyncWriteStream, typename ConstBufferSequence>
            bool                                                                async_write(AsyncWriteStream& stream, const ConstBufferSequence& buffers, YieldContext& y) noexcept {
                if (!buffers.data() || !buffers.size()) {
                    return false;
                }

                bool ok = false;
                boost::asio::post(stream.get_executor(),
                    [&stream, &buffers, &y, &ok]() noexcept {
                        boost::asio::async_write(stream, constantof(buffers),
                            [&y, &ok](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                ok = ec == boost::system::errc::success; /* b is boost::system::errc::success. */
                                y.R();
                            });
                    });

                y.Suspend();
                return ok;
            }

            template <typename AsyncWriteStream, typename MutableBufferSequence>
            int                                                                 async_read_some(AsyncWriteStream& stream, const MutableBufferSequence& buffers, YieldContext& y) noexcept {
                int len = -1;
                if (!buffers.data() || !buffers.size()) {
                    return len;
                }

                boost::asio::post(stream.get_executor(),
                    [&stream, &buffers, &y, &len]() noexcept {
                        stream.async_read_some(constantof(buffers),
                            [&y, &len](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                len = std::max<int>(ec ? -1 : sz, -1);
                                y.R();
                            });
                    });

                y.Suspend();
                return len;
            }

            inline bool                                                         async_sleep(YieldContext& y, int milliseconds) noexcept {
                return ppp::threading::Timer::Timeout(milliseconds, y);
            }

            inline bool                                                         async_connect(boost::asio::ip::tcp::socket& socket, const boost::asio::ip::tcp::endpoint& remoteEP, YieldContext& y) noexcept {
                boost::asio::ip::address address = remoteEP.address();
                if (ppp::net::IPEndPoint::IsInvalid(address)) {
                    return false;
                }

                int port = remoteEP.port();
                if (port <= ppp::net::IPEndPoint::MinPort || port > ppp::net::IPEndPoint::MaxPort) {
                    return false;
                }

                bool ok = false;
                boost::asio::post(socket.get_executor(), 
                    [&socket, &remoteEP, &y, &ok]() noexcept {
                        socket.async_connect(remoteEP,
                            [&y, &ok](const boost::system::error_code& ec) noexcept {
                                ok = ec == boost::system::errc::success; /* b is boost::system::errc::success. */
                                y.R();
                            });
                        });

                y.Suspend();
                return ok;
            }

            template <class AsyncSocket, class TProtocol>
            bool                                                                async_open(YieldContext& y, AsyncSocket& socket, const TProtocol& protocol) noexcept {
                // Android platform fatal system network underlying library bug, if in stackful coroutine, call socket, connect function will crash directly, 
                // In order to solve this problem, need to delegate to the android framework thread (Fwmark) to call, 
                // Will ensure that the program does not crash. It's just... Inexplicable.
                // 
                // Refer:
                //  https://android.googlesource.com/platform/frameworks/base.git/+/android-4.2.2_r1/core/jni/AndroidRuntime.cpp
                //  https://android.googlesource.com/platform/system/netd/+/master/client/FwmarkClient.cpp
#if defined(_ANDROID)
                bool ok = false;
                boost::asio::post(socket.get_executor(),
                    [&socket, &protocol, &ok, &y]() noexcept {
                        boost::system::error_code ec;
                        socket.open(protocol, ec);

                        if (ec == boost::system::errc::success) {
                            ok = true;
                        }

                        y.R();
                    });

                y.Suspend();
                return ok;
#else
                boost::system::error_code ec;
                socket.open(protocol, ec);

                return ec == boost::system::errc::success;
#endif
            }
            
            template <class TProtocol>
            boost::asio::ip::basic_endpoint<TProtocol>                          GetAddressByHostName(const char* hostname, int port, YieldContext& y) noexcept {
                typedef boost::asio::ip::basic_resolver<TProtocol>              protocol_resolver;
                typedef ppp::net::IPEndPoint                                    IPEndPoint;
                typedef ppp::net::Ipep                                          Ipep;
                typedef std::atomic<bool>                                       atomic_bool;

                if (NULL == hostname || *hostname == '\x0') {
                    return IPEndPoint::AnyAddressV4<TProtocol>(IPEndPoint::MinPort);
                }

                if (!y) {
                    return IPEndPoint::AnyAddressV4<TProtocol>(IPEndPoint::MinPort);
                }

                std::shared_ptr<atomic_bool> status = make_shared_object<atomic_bool>(false);
                if (NULL == status) {
                    return IPEndPoint::AnyAddressV4<TProtocol>(IPEndPoint::MinPort);
                }

                boost::asio::ip::basic_endpoint<TProtocol> results = IPEndPoint::AnyAddressV4<TProtocol>(IPEndPoint::MinPort);
                auto processing =
                    [status, &results, &y](IPEndPoint* ep) noexcept {
                        if (!status->exchange(true)) {
                            if (NULL != ep) {
                                results = IPEndPoint::ToEndPoint<TProtocol>(*ep);
                            }

                            y.R();
                        }
                    };

                boost::asio::io_context& context = y.GetContext();
                boost::asio::strand<boost::asio::io_context::executor_type>* strand = y.GetStrand();

                ppp::threading::Executors::Post(addressof(context), strand, 
                    [&y, &context, hostname, port, &processing, status]() noexcept {
                        if (!Ipep::GetAddressByHostName(context, hostname, port, processing)) {
                            if (!status->exchange(true)) {
                                y.R();
                            }
                        }
                    });

                y.Suspend();
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