#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/Timer.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace coroutines {
        namespace asio {
            template<typename AsyncWriteStream, typename MutableBufferSequence>
            inline bool                                                         async_read(AsyncWriteStream& stream, const MutableBufferSequence& buffers, YieldContext& y) noexcept {
                if (!buffers.data() || !buffers.size()) {
                    return false;
                }

                int len = -1;
                YieldContext* p = y.GetPtr();
                boost::asio::async_read(stream, constantof(buffers),
                    [p, &len](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        len = std::max<int>(ec ? -1 : sz, -1);
                        p->GetContext().dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, p));
                    });

                y.Suspend();
                return len == buffers.size();
            }

            template<typename AsyncWriteStream, typename ConstBufferSequence>
            inline bool                                                         async_write(AsyncWriteStream& stream, const ConstBufferSequence& buffers, YieldContext& y) noexcept {
                if (!buffers.data() || !buffers.size()) {
                    return false;
                }

                bool ok = false;
                YieldContext* p = y.GetPtr();
                boost::asio::async_write(stream, constantof(buffers),
                    [p, &ok](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        ok = ec == boost::system::errc::success; /* b is boost::system::errc::success. */
                        p->GetContext().dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, p));
                    });

                y.Suspend();
                return ok;
            }

            template<typename AsyncWriteStream, typename MutableBufferSequence>
            inline int                                                          async_read_some(AsyncWriteStream& stream, const MutableBufferSequence& buffers, YieldContext& y) noexcept {
                int len = -1;
                if (!buffers.data() || !buffers.size()) {
                    return len;
                }

                YieldContext* p = y.GetPtr();
                stream.async_read_some(constantof(buffers),
                    [p, &len](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        len = std::max<int>(ec ? -1 : sz, -1);
                        p->GetContext().dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, p));
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
                YieldContext* p = y.GetPtr();
                socket.async_connect(remoteEP,
                    [p, &ok](const boost::system::error_code& ec) noexcept {
                        ok = ec == boost::system::errc::success; /* b is boost::system::errc::success. */
                        p->GetContext().dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, p));
                    });

                y.Suspend();
                return ok;
            }

            inline bool                                                         async_sleep(YieldContext& y, const std::shared_ptr<boost::asio::io_context>& context, int milliseconds) noexcept {
                return ppp::threading::Timer::Timeout(context, milliseconds, y);
            }

            template<class TProtocol>
            inline boost::asio::ip::basic_endpoint<TProtocol>                   GetAddressByHostName(boost::asio::ip::basic_resolver<TProtocol>& resolver, const char* hostname, int port, YieldContext& y) noexcept {
                typedef boost::asio::ip::basic_resolver<TProtocol> protocol_resolver;

                YieldContext* p = y.GetPtr();
                auto f = [p](protocol_resolver& resolver, typename protocol_resolver::query& q, boost::system::error_code& ec) noexcept {
#ifndef _WIN32
                    using results_iterator = typename protocol_resolver::iterator;

                    results_iterator r{};
                    resolver.async_resolve(q,
                        [p, &ec, &r](const boost::system::error_code& e_, const results_iterator& i_) noexcept {
                            if (ec == boost::system::errc::success) {
                                ec = e_;
                                r = i_;
                            }

                            p->GetContext().dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, p));
                        });
#else
                    using results_type = typename protocol_resolver::results_type;

                    results_type r{};
                    resolver.async_resolve(q,
                        [p, &ec, &r](const boost::system::error_code& e_, const results_type& i_) noexcept {
                            if (ec == boost::system::errc::success) {
                                ec = e_;
                                r = i_;
                            }

                            p->GetContext().dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, p));
                        });
#endif
                    p->Suspend();
                    return r;
                };
                return ppp::net::asio::internal::GetAddressByHostName(resolver, hostname, port, f);
            }
        }
    }
}