#pragma once

/**
 * @file vmux.h
 * @brief Shared types and helpers for the virtual multiplexer subsystem.
 * @license GPL-3.0
 */

#include <ppp/stdafx.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>

namespace ppp::configurations { class AppConfiguration; }
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

#if defined(_WIN32)
#include <windows/ppp/net/QoSS.h>
#elif defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace vmux {
    /** @brief Byte alias used by vmux packet buffers. */
    typedef uint8_t                                                             Byte;
    /** @brief Mutex type used for vmux internal synchronization. */
    typedef std::mutex                                                          SynchronizationObject;
    /** @brief RAII lock guard for @ref SynchronizationObject. */
    typedef std::lock_guard< SynchronizationObject>                             SynchronizationObjectScope;

    /** @brief Alias of the asio I/O context used by vmux. */
    typedef boost::asio::io_context                                             Context;
    /** @brief Shared pointer wrapper for @ref Context. */
    typedef std::shared_ptr<Context>                                            ContextPtr;
    /** @brief Serialized execution strand used by vmux tasks. */
    typedef boost::asio::strand<boost::asio::io_context::executor_type>         Strand;
    /** @brief Shared pointer wrapper for @ref Strand. */
    typedef std::shared_ptr<Strand>                                             StrandPtr;

    /** @brief Text type used by vmux public and internal APIs. */
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

    /**
     * @brief Spawn a coroutine on strand when available, otherwise on context.
     * @details The detached form is selected for newer Boost versions.
     * @see https://original.boost.org/doc/libs/1_80_0/doc/html/boost_asio/overview/composition/spawn.html
     * @see https://original.boost.org/doc/libs/1_79_0/doc/html/boost_asio/overview/composition/spawn.html
     */
#if BOOST_VERSION >= 108000
#define vmux_spawn(context_ptr, strand_ptr, fx) \
    if (NULLPTR != strand_ptr) {                   \
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
    if (NULLPTR != strand_ptr) {                   \
        boost::asio::spawn(*strand_ptr, fx);    \
    }                                           \
    else {                                      \
        boost::asio::spawn(*context_ptr, fx);   \
    }
#endif

    template <typename T>
    /**
     * @brief Convert a value to vmux string type.
     * @tparam T Source value type.
     * @param v Value to convert.
     * @return Converted string value.
     */
    template_string                                                             vmux_to_string(const T& v) noexcept {
        return stl::to_string<template_string>(v);
    }

    template <typename TContextPtr, typename TStrandPtr, typename LegacyCompletionHandler>
    /**
     * @brief Post a handler to the vmux executor pipeline.
     * @tparam TContextPtr Context pointer type.
     * @tparam TStrandPtr Strand pointer type.
     * @tparam LegacyCompletionHandler Callable handler type.
     * @param context Target context.
     * @param strand Optional strand for serialized execution.
     * @param handler Handler to execute.
     * @return true if posting succeeds; otherwise false.
     */
    bool                                                                        vmux_post_exec(const TContextPtr& context, const TStrandPtr& strand, LegacyCompletionHandler&& handler) noexcept {
        // A stopped io_context never runs a posted handler again; reporting
        // success here would let callers Suspend() a coroutine that is never
        // resumed, or queue cleanup work that silently never executes.
        if (NULLPTR == context || context->stopped()) {
            return false;
        }
        return ppp::threading::Executors::Post(context, strand, std::move(handler));
    }

    template <class TProtocol>
    /**
     * @brief Build an IPv4 any-address endpoint for a protocol.
     * @tparam TProtocol asio protocol type.
     * @param port Endpoint port.
     * @return Endpoint bound to 0.0.0.0:port.
     */
    static boost::asio::ip::basic_endpoint<TProtocol>                           vmux_any_address_v4(int port) noexcept {
        return ppp::net::IPEndPoint::AnyAddressV4<TProtocol>(port);
    }
}
