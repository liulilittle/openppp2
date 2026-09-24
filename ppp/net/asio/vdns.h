#pragma once

/**
 * @file vdns.h
 * @brief Virtual DNS asynchronous resolver and cache interfaces.
 *
 * Overview
 * --------
 * The virtual DNS (vdns) subsystem intercepts DNS queries originating from clients
 * tunneled through the virtual NIC and applies the following logic:
 *
 *  1. If the queried hostname is present in the in-process cache, the cached
 *     addresses are returned immediately without touching upstream resolvers.
 *  2. If the cache misses, the query is forwarded to the configured upstream DNS
 *     servers (@ref servers) via UDP.  The response is parsed, cached under the
 *     returned TTL (capped by @ref ttl), and delivered to the caller.
 *  3. Reverse-lookup queries (.in-addr.arpa / .ip6.arpa) bypass vdns and are
 *     forwarded directly; @ref IsReverseQuery identifies them.
 *
 * Global state
 * ------------
 * - @ref servers  — upstream DNS UDP endpoints used by @ref ResolveAsync / @ref ResolveAsync2.
 * - @ref ttl      — maximum cache lifetime in seconds.
 * - @ref enabled  — master switch; when false callers should use OS resolver directly.
 *
 * Cache management
 * ----------------
 * - @ref AddCache inserts a parsed DNS response into the cache.
 * - @ref QueryCache / @ref QueryCache2 perform non-blocking cache lookups.
 * - @ref UpdateAsync expires stale entries and should be called periodically.
 *
 * Async resolution
 * ----------------
 * - @ref ResolveAsync returns one (preferred IPv4) address via callback.
 * - @ref ResolveAsync2 returns the full set of resolved addresses.
 *
 * Thread safety
 * -------------
 * All functions in this namespace acquire an internal cache mutex before
 * reading or writing shared cache state.  The global variables @ref ttl and
 * @ref enabled are atomics and may be read or written from any thread; the
 * @ref servers shared_ptr is published with std::atomic_store and read with
 * std::atomic_load, so the server list can also be swapped at runtime.
 */

#include <ppp/stdafx.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>

#include <common/dnslib/message.h>

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Virtual DNS subsystem namespace.
             *
             * All functions operate on shared global state (cache + server list) and are
             * designed to be called from within a Boost.Asio executor thread.
             */
            namespace vdns {

                /** @brief Vector of upstream DNS server UDP endpoints. */
                typedef ppp::vector<boost::asio::ip::udp::endpoint>                             IPEndPointVector;
                /** @brief Shared pointer to the upstream DNS server endpoint vector. */
                typedef std::shared_ptr<IPEndPointVector>                                       IPEndPointVectorPtr;

                /**
                 * @brief Global list of upstream DNS server endpoints.
                 *
                 * Set once during application initialization.  @ref ResolveAsync and
                 * @ref ResolveAsync2 use this list when the cache does not contain an answer.
                 * An empty list disables upstream forwarding.
                 *
                 * @note Writers must publish a new vector with `std::atomic_store(&servers, p)`
                 *       and readers must take a local snapshot with `std::atomic_load(&servers)`
                 *       before dereferencing it; the pointed-to vector is treated as immutable.
                 */
                extern IPEndPointVectorPtr                                                      servers;

                /**
                 * @brief Maximum cache TTL in seconds.
                 *
                 * Cached entries are never retained longer than this value regardless of
                 * the TTL returned by the upstream DNS server.  Set to 0 to disable caching.
                 * Atomic so runtime configuration updates are safe from any thread.
                 */
                extern std::atomic<int>                                                         ttl;

                /**
                 * @brief Global switch for the virtual DNS feature.
                 *
                 * When false, callers should bypass vdns entirely and fall back to the
                 * OS resolver.  Atomic so it may be toggled at runtime from any thread.
                 */
                extern std::atomic<bool>                                                        enabled;

                /**
                 * @brief DNS address record family selector.
                 *
                 * Used by @ref QueryCache2 to determine which record types to include
                 * in a synthesised DNS response message.
                 */
                enum AddressFamily {
                    kNone = 0, ///< Unspecified / undefined.
                    kA    = 1, ///< IPv4 A record.
                    kAAAA = 2  ///< IPv6 AAAA record.
                };

                /**
                 * @brief Queries the cache and returns a single resolved address.
                 *
                 * Performs a non-blocking, mutex-protected lookup.  IPv4 addresses are
                 * preferred over IPv6 when both are present.
                 *
                 * @param hostname  Null-terminated domain name to query (e.g. "example.com").
                 * @param address   Receives the best cached address when the function returns true.
                 * @return          true when a valid, non-expired cache entry is found.
                 */
                bool                                                                            QueryCache(const char* hostname, boost::asio::ip::address& address) noexcept;

                /**
                 * @brief Builds DNS response answer records from the cache for a given family.
                 *
                 * Populates @p messsage with A or AAAA answer records found in the cache for
                 * @p hostname.  This is used by the DNS intercept path to return a locally
                 * synthesised DNS response without touching upstream resolvers.
                 *
                 * @param hostname  Null-terminated domain name to resolve.
                 * @param messsage  DNS message object to receive the answer records.
                 * @param af        Record family filter: @ref kA (IPv4) or @ref kAAAA (IPv6).
                 * @return          Normalized hostname string on cache hit; empty string on miss.
                 * @note            The parameter name typo "messsage" (three 's') is preserved
                 *                  to match the existing ABI.
                 */
                ppp::string                                                                     QueryCache2(const char* hostname, ::dns::Message& messsage, AddressFamily af) noexcept;

                /**
                 * @brief Inserts a DNS response packet into the cache.
                 *
                 * Parses the raw DNS wire-format response, extracts A and AAAA records,
                 * and stores them in the internal cache keyed by the normalized hostname.
                 * Existing entries for the same hostname are replaced.
                 *
                 * @param packet       Pointer to the raw DNS response packet bytes.
                 * @param packet_size  Length of the packet in bytes.
                 * @return             true when the packet was successfully parsed and at least
                 *                     one record was cached; false on parse error.
                 */
                bool                                                                            AddCache(const Byte* packet, int packet_size) noexcept;

                /**
                 * @brief Clears all process-wide vdns cache entries immediately.
                 *
                 * Used when DNS configuration changes or a client session starts, so
                 * stale mobile-network answers cannot leak across reconnects.
                 */
                void                                                                            ClearCache() noexcept;

                /**
                 * @brief Checks whether a hostname represents a reverse DNS lookup domain.
                 *
                 * Reverse queries for IPv4 (.in-addr.arpa) and IPv6 (.ip6.arpa) should not
                 * be intercepted by vdns; this helper identifies them so callers can bypass
                 * the cache and forward directly to upstream.
                 *
                 * @param hostname  Null-terminated domain name to test.
                 * @return          true when the hostname ends with ".in-addr.arpa" (case-insensitive)
                 *                  or ".ip6.arpa" (case-insensitive).
                 */
                bool                                                                            IsReverseQuery(const char* hostname) noexcept;

                /**
                 * @brief Resolves a hostname asynchronously, returning one preferred address.
                 *
                 * Posts a DNS query to each endpoint in @p destinations, waits up to
                 * @p timeout milliseconds for the first valid response, inserts the result
                 * into the cache via @ref AddCache, and invokes @p cb with one address
                 * (IPv4 preferred).
                 *
                 * @param context       IO context driving the async UDP send/receive.
                 * @param hostname      Domain name or IP literal to resolve.
                 * @param timeout       Query timeout in milliseconds; 0 uses a platform default.
                 * @param destinations  Upstream DNS server endpoints to query.
                 * @param cb            Callback receiving the resolved address; called with an
                 *                      unspecified address on timeout or failure.
                 * @return              true if the async query was successfully initiated;
                 *                      false when @p hostname is null or @p destinations is empty.
                 */
                bool                                                                            ResolveAsync(
                    boost::asio::io_context& context,
                    const char* hostname,
                    int                                                                         timeout,
                    const ppp::vector<boost::asio::ip::udp::endpoint>& destinations,
                    const ppp::function<void(const boost::asio::ip::address&)>& cb) noexcept;

                /**
                 * @brief Resolves a hostname asynchronously, returning all resolved addresses.
                 *
                 * Similar to @ref ResolveAsync but collects all A and AAAA records from the
                 * DNS response instead of returning only one address.
                 *
                 * @param context       IO context driving the async UDP send/receive.
                 * @param hostname      Domain name or IP literal to resolve.
                 * @param timeout       Query timeout in milliseconds.
                 * @param destinations  Upstream DNS server endpoints to query.
                 * @param cb            Callback receiving an unordered set of all resolved
                 *                      addresses; empty set on failure or timeout.
                 * @return              true if the async query was successfully initiated.
                 */
                bool                                                                            ResolveAsync2(
                    boost::asio::io_context& context,
                    const char* hostname,
                    int                                                                         timeout,
                    const ppp::vector<boost::asio::ip::udp::endpoint>& destinations,
                    const ppp::function<void(const ppp::unordered_set<boost::asio::ip::address>&)>& cb) noexcept;

                /**
                 * @brief Removes expired entries from the DNS cache.
                 *
                 * Iterates the cache and evicts any entry whose TTL has elapsed.  Should
                 * be called periodically (e.g. once per second from a timer callback) to
                 * prevent unbounded cache growth.
                 *
                 * @note  This function acquires the internal cache mutex; it is safe to call
                 *        from any thread.
                 */
                void                                                                            UpdateAsync() noexcept;

            } // namespace vdns
        } // namespace asio
    } // namespace net
} // namespace ppp
