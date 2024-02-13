#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/Timer.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace coroutines {
        namespace asio {
            template <typename AsyncWriteStream, typename MutableBufferSequence>
            bool                                                                async_read_post(AsyncWriteStream& stream, const MutableBufferSequence& buffers, ppp::coroutines::YieldContext& y) noexcept {
                if (!buffers.data() || !buffers.size()) {
                    return false;
                }

                int len = -1;
                boost::asio::post(stream.get_executor(),
                    [&stream, &buffers, &y, &len]() noexcept {
                        boost::asio::async_read(stream, constantof(buffers),
                            [&y, &len](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                auto& context = y.GetContext();
                                len = std::max<int>(ec ? -1 : sz, -1);
                                context.dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, y.GetPtr()));
                            });
                    });

                y.Suspend();
                return len == buffers.size();
            }

            template <typename AsyncWriteStream, typename MutableBufferSequence>
            bool                                                                async_read(AsyncWriteStream& stream, const MutableBufferSequence& buffers, YieldContext& y) noexcept {
                if (!buffers.data() || !buffers.size()) {
                    return false;
                }

                int len = -1;
                boost::asio::async_read(stream, constantof(buffers),
                    [&y, &len](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        auto& context = y.GetContext();
                        len = std::max<int>(ec ? -1 : sz, -1);
                        context.dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, y.GetPtr()));
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
                boost::asio::async_write(stream, constantof(buffers),
                    [&y, &ok](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        auto& context = y.GetContext();
                        ok = ec == boost::system::errc::success; /* b is boost::system::errc::success. */
                        context.dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, y.GetPtr()));
                    });

                y.Suspend();
                return ok;
            }

            template <typename AsyncWriteStream, typename MutableBufferSequence>
            int                                                                 async_read_some_post(AsyncWriteStream& stream, const MutableBufferSequence& buffers, YieldContext& y) noexcept {
                int len = -1;
                if (!buffers.data() || !buffers.size()) {
                    return len;
                }

                boost::asio::post(stream.get_executor(),
                    [&stream, &buffers, &y, &len]() noexcept {
                        stream.async_read_some(constantof(buffers),
                            [&y, &len](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                auto& context = y.GetContext();
                                len = std::max<int>(ec ? -1 : sz, -1);
                                context.dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, y.GetPtr()));
                            });
                    });

                y.Suspend();
                return len;
            }

            template <typename AsyncWriteStream, typename MutableBufferSequence>
            int                                                                 async_read_some(AsyncWriteStream& stream, const MutableBufferSequence& buffers, YieldContext& y) noexcept {
                int len = -1;
                if (!buffers.data() || !buffers.size()) {
                    return len;
                }

                stream.async_read_some(constantof(buffers),
                    [&y, &len](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        auto& context = y.GetContext();
                        len = std::max<int>(ec ? -1 : sz, -1);
                        context.dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, y.GetPtr()));
                    });

                y.Suspend();
                return len;
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
                socket.async_connect(remoteEP,
                    [&y, &ok](const boost::system::error_code& ec) noexcept {
                        auto& context = y.GetContext();
                        ok = ec == boost::system::errc::success; /* b is boost::system::errc::success. */
                        context.dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, y.GetPtr()));
                    });

                y.Suspend();
                return ok;
            }

            inline bool                                                         async_sleep(YieldContext& y, const std::shared_ptr<boost::asio::io_context>& context, int milliseconds) noexcept {
                return ppp::threading::Timer::Timeout(context, milliseconds, y);
            }

            template <class TProtocol>
            boost::asio::ip::basic_endpoint<TProtocol>                          GetAddressByHostName(boost::asio::ip::basic_resolver<TProtocol>& resolver, const char* hostname, int port, YieldContext& y) noexcept {
                typedef boost::asio::ip::basic_resolver<TProtocol> protocol_resolver;

                auto fx = [&y](protocol_resolver& resolver, typename protocol_resolver::query& q, boost::system::error_code& ec) noexcept {
#if !defined(_WIN32)
                    using results_iterator = typename protocol_resolver::iterator;

                    results_iterator r{};
                    resolver.async_resolve(q,
                        [&y, &ec, &r](const boost::system::error_code& e_, const results_iterator& i_) noexcept {
                            auto& context = y.GetContext();
                            ec = e_;
                            r = i_;

                            context.dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, y.GetPtr()));
                        });
#else
                    using results_type = typename protocol_resolver::results_type;

                    results_type r{};
                    resolver.async_resolve(q,
                        [&y, &ec, &r](const boost::system::error_code& e_, const results_type& i_) noexcept {
                            auto& context = y.GetContext();
                            ec = e_;
                            r = i_;
                            
                            context.dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, y.GetPtr()));
                        });
#endif
                    y.Suspend();
                    return r;
                };
                return ppp::net::asio::internal::GetAddressByHostName(resolver, hostname, port, fx);
            }
        }
    }
}