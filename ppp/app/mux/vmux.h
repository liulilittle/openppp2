#pragma once

#include <ppp/stdafx.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Firewall.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/threading/Thread.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

#if defined(_WIN32)
#include <windows/ppp/net/QoSS.h>
#elif defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace vmux {
    typedef uint8_t                                                             Byte;
    typedef std::mutex                                                          SynchronizationObject;
    typedef std::lock_guard< SynchronizationObject>                             SynchronizationObjectScope;

    typedef boost::asio::io_context                                             Context;
    typedef std::shared_ptr<Context>                                            ContextPtr;
    typedef boost::asio::strand<boost::asio::io_context::executor_type>         Strand;
    typedef std::shared_ptr<Strand>                                             StrandPtr;

    typedef ppp::string                                                         template_string;

    template <typename _Ty>
    using list                                                                  = ppp::list<_Ty>;

    template <typename _Ty>
    using vector                                                                = ppp::vector<_Ty>;

    template <typename TValue>
    using unordered_set                                                         = ppp::unordered_set<TValue>;

    template <typename _TKey, typename _TValue>
    using map                                                                   = ppp::map<_TKey, _TValue>;

    template <typename _TKey, typename _TValue, typename _Pr>
    using map_pr                                                                = std::map<_TKey, _TValue, _Pr, ppp::allocator<std::pair<const _TKey, _TValue>>>;

    template <typename _TKey, typename _TValue>
    using unordered_map                                                         = ppp::unordered_map<_TKey, _TValue>;

    // https://original.boost.org/doc/libs/1_80_0/doc/html/boost_asio/overview/composition/spawn.html
    // https://original.boost.org/doc/libs/1_79_0/doc/html/boost_asio/overview/composition/spawn.html
#if BOOST_VERSION >= 108000
#define vmux_spawn(context_ptr, strand_ptr, fx) \
    if (NULL != strand_ptr) {                   \
        boost::asio::spawn(*strand_ptr,         \
            fx,                                 \
            boost::asio::detached);             \
    }                                           \
    else {                                      \
        boost::asio::spawn(*context_ptr,        \
            fx,                                 \
            boost::asio::detached);             \
    }
#else
#define vmux_spawn(context_ptr, strand_ptr, fx) \
    if (NULL != strand_ptr) {                   \
        boost::asio::spawn(*strand_ptr, fx);    \
    }                                           \
    else {                                      \
        boost::asio::spawn(*context_ptr, fx);   \
    }
#endif

    template <typename T>
    template_string                                                             vmux_to_string(const T& v) noexcept {
        return stl::to_string<template_string>(v);
    }

    template <typename TContextPtr, typename TStrandPtr, typename LegacyCompletionHandler>
    bool                                                                        vmux_post_exec(const TContextPtr& context, const TStrandPtr& strand, LegacyCompletionHandler&& handler) noexcept {
        return ppp::threading::Executors::Post(context, strand, std::move(handler));
    }

    template <class TProtocol>
    static boost::asio::ip::basic_endpoint<TProtocol>                           vmux_any_address_v4(int port) noexcept {
        return ppp::net::IPEndPoint::AnyAddressV4<TProtocol>(port);
    }
}