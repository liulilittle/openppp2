#include <ppp/stdafx.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/collections/LinkedList.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/Timer.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/VdnsRequestCompletion.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/checksum.h>
#include <ppp/diagnostics/Error.h>

#include <common/dnslib/message.h>
#include <cctype>   // for tolower
#include <new>      // for std::bad_alloc

/**
 * @file vdns.cpp
 * @brief Virtual DNS resolver implementation with async querying and in-memory cache.
 */

namespace ppp {
    namespace net {
        namespace asio {
            namespace vdns {

                // -----------------------------------------------------------------------------
                // Constants (defined in stdafx.h, referenced here for clarity)
                // -----------------------------------------------------------------------------
                static constexpr int                                                                PPP_MAX_HOSTNAME_SIZE_LIMIT        = 64;
                static constexpr int                                                                PPP_IP_DNS_MERGE_WAIT              = 100;
                // Linux  : systemd-resolved set 50ms               
                // glibc  : getaddrinfo set 500ms               
                // MacOS  : 50 ~ 100ms              
                // Windows: 100 ~ 300ms        
                static constexpr int                                                                PPP_MAX_DNS_PACKET_BUFFER_SIZE     = 512;   // Must match stdafx definition

                // -----------------------------------------------------------------------------
                // Type aliases for internal use
                // -----------------------------------------------------------------------------
                typedef ppp::collections::Dictionary                                                Dictionary;
                typedef std::mutex                                                                  SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                                         SynchronizedObjectScope;
                typedef ppp::function<void(bool, ppp::unordered_set<boost::asio::ip::address>&)>    DNSRequestAsynchronousCallback;
                typedef ppp::net::Socket                                                            Socket;
                typedef ppp::threading::Timer                                                       Timer;
                typedef ppp::threading::Executors                                                   Executors;

                // Forward declaration for DNS_RequestContext
                struct DNS_RequestContext;

                // -----------------------------------------------------------------------------
                // Helper: case-insensitive string comparison for DNS domain names.
                // Returns true if strings are equal ignoring ASCII case.
                // -----------------------------------------------------------------------------
                /**
                 * @brief Compares two strings using ASCII case-insensitive rules.
                 * @tparam TStringA Left string type exposing size/operator[].
                 * @tparam TStringB Right string type exposing size/operator[].
                 * @param a Left operand.
                 * @param b Right operand.
                 * @return True when both strings are equal ignoring case.
                 */
                template <typename TStringA, typename TStringB>
                static bool CaseInsensitiveEqual(const TStringA& a, const TStringB& b) noexcept {
                    if (a.size() != b.size()) {
                        return false;
                    }

                    for (size_t i = 0; i < a.size(); ++i) {
                        if (std::tolower(static_cast<unsigned char>(a[i])) !=
                            std::tolower(static_cast<unsigned char>(b[i]))) {
                            return false;
                        }
                    }
                    return true;
                }

                // -----------------------------------------------------------------------------
                // Helper: parse a DNS response, extract A/AAAA records, and fill the address set.
                // Returns true on success and writes the transaction ID into 'ack'.
                // If 'expected_hostname' is provided, the response's question section must match it
                // (case-insensitive). If 'out_hostname' is provided, the normalized (lowercase)
                // hostname is written.
                // -----------------------------------------------------------------------------
                /**
                 * @brief Parses DNS response packet and extracts A/AAAA addresses.
                 * @param packet Raw DNS packet bytes.
                 * @param packet_size Packet length in bytes.
                 * @param addresses Output set that receives extracted addresses.
                 * @param ack Output transaction ID from DNS message.
                 * @param expected_hostname Optional expected hostname for question validation.
                 * @param out_hostname Optional normalized hostname output.
                 * @param out_ipv4_or_ipv6 Optional family hint (true: A, false: AAAA).
                 * @return True when packet decoding succeeds.
                 */
                static bool DNS_ProcessAResponseAddresses(Byte*     packet,
                    int                                             packet_size,
                    ppp::unordered_set<boost::asio::ip::address>&   addresses,
                    uint16_t&                                       ack,
                    const char*                                     expected_hostname = NULLPTR,
                    ppp::string*                                    out_hostname = NULLPTR,
                    bool*                                           out_ipv4_or_ipv6 = NULLPTR,
                    uint32_t*                                       out_min_positive_ttl = NULLPTR) noexcept {

                    using IPEndPoint = ppp::net::IPEndPoint;
                    using AddressFamily = ppp::net::AddressFamily;

                    ack = 0;
                    if (NULLPTR != out_min_positive_ttl) {
                        *out_min_positive_ttl = 0;
                    }
                    if (NULLPTR == packet || packet_size < 1) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsPacketInvalid);
                        return false;
                    }

                    ::dns::Message m;
                    if (::dns::BufferResult::NoError != m.decode(packet, packet_size)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsPacketInvalid);
                        return false;
                    }

                    if (!m.mQr || m.mRCode != static_cast<uint16_t>(::dns::ResponseCode::kNOERROR)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsResponseInvalid);
                        return false;
                    }

                    // Verify the question section matches the expected hostname (if provided)
                    if (NULLPTR != expected_hostname) {
                        if (m.questions.empty()) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsResponseInvalid);
                            return false; // No question section to match
                        }

                        const ::dns::QuestionSection& q = m.questions[0];
                        if (IsReverseQuery(q.mName.data())) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsResponseInvalid);
                            return false;
                        }

                        // Case-insensitive comparison per DNS specification
                        if (!CaseInsensitiveEqual(q.mName, ppp::string(expected_hostname))) {
                            return false; // Domain mismatch – ignore this response
                        }

                        if (NULLPTR != out_hostname) {
                            *out_hostname = q.mName;
                            
                            // Convert to lowercase for internal consistency
                            for (char& ch : *out_hostname) {
                                ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
                            }
                        }

                        if (NULLPTR != out_ipv4_or_ipv6) {
                            *out_ipv4_or_ipv6 = (::dns::RecordType::kA == q.mType);
                        }
                    }
                    else {
                        // No expected hostname: just extract hostname from the question if requested
                        if (NULLPTR != out_hostname && !m.questions.empty()) {
                            const ::dns::QuestionSection& q = m.questions[0];
                            if (!IsReverseQuery(q.mName.data())) {
                                *out_hostname = q.mName;

                                // Convert to lowercase
                                for (char& ch : *out_hostname) {
                                    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
                                }

                                if (NULLPTR != out_ipv4_or_ipv6) {
                                    *out_ipv4_or_ipv6 = (::dns::RecordType::kA == q.mType);
                                }
                            }
                        }
                    }

                    // Iterate over answer records (non-const because getRData returns shared_ptr)
                    bool has_cacheable_terminal = false;
                    uint32_t min_positive_ttl = UINT32_MAX;
                    for (::dns::ResourceRecord& rr : m.answers) {
                        if (::dns::RecordClass::kIN != rr.mClass) {
                            continue;
                        }

                        IPEndPoint ep;
                        if (::dns::RecordType::kA == rr.mType) {
                            auto rdata = rr.getRData<::dns::RDataA>();
                            if (NULLPTR != rdata) {
                                if (rr.mTtl < 1) {
                                    min_positive_ttl = 0;
                                }
                                elif(min_positive_ttl != 0) {
                                    min_positive_ttl = std::min<uint32_t>(min_positive_ttl, rr.mTtl);
                                    has_cacheable_terminal = true;
                                }

                                ep = IPEndPoint(AddressFamily::InterNetwork,
                                    rdata->getAddress(), 4, IPEndPoint::MinPort);

                                // emplace may throw bad_alloc; catch and ignore this address.
                                try {
                                    addresses.emplace(IPEndPoint::ToEndPoint<boost::asio::ip::udp>(ep).address());
                                }
                                catch (const std::bad_alloc&) {
                                    // Ignore memory allocation failure for this address
                                }
                            }
                        }
                        elif (::dns::RecordType::kAAAA == rr.mType) {
                            auto rdata = rr.getRData<::dns::RDataAAAA>();
                            if (NULLPTR != rdata) {
                                if (rr.mTtl < 1) {
                                    min_positive_ttl = 0;
                                }
                                elif(min_positive_ttl != 0) {
                                    min_positive_ttl = std::min<uint32_t>(min_positive_ttl, rr.mTtl);
                                    has_cacheable_terminal = true;
                                }

                                ep = IPEndPoint(AddressFamily::InterNetworkV6,
                                    rdata->getAddress(), 16, IPEndPoint::MinPort);

                                try {
                                    addresses.emplace(IPEndPoint::ToEndPoint<boost::asio::ip::udp>(ep).address());
                                }
                                catch (const std::bad_alloc&) {
                                    // Ignore memory allocation failure for this address
                                }
                            }
                        }
                        elif (::dns::RecordType::kCNAME == rr.mType) {
                            if (rr.mTtl < 1) {
                                min_positive_ttl = 0;
                            }
                            elif(min_positive_ttl != 0) {
                                min_positive_ttl = std::min<uint32_t>(min_positive_ttl, rr.mTtl);
                            }
                        }
                    }

                    if (NULLPTR != out_min_positive_ttl && has_cacheable_terminal && min_positive_ttl != UINT32_MAX) {
                        *out_min_positive_ttl = min_positive_ttl;
                    }

                    ack = m.mId;
                    return true;
                }

                // -----------------------------------------------------------------------------
                // Cache record: stores a set of IP addresses, their expiry, and which families exist.
                // All public methods are thread-safe.
                // -----------------------------------------------------------------------------
                /** @brief Thread-safe DNS cache entry for one normalized hostname. */
                struct NamespaceRecord {
                    bool                                            ipv4 : 1;       // True if at least one IPv4 address is present
                    bool                                            ipv6 : 7;       // True if at least one IPv6 address is present
                    uint64_t                                        expired_time;   // Absolute tick count when this entry expires
                    mutable SynchronizedObject                      lockobj;        // Protects 'addresses' and the flags (mutable for const methods)
                    ppp::string                                     hostname;
                    ppp::unordered_set<boost::asio::ip::address>    addresses;

                    NamespaceRecord() noexcept : ipv4(false), ipv6(false), expired_time(0) {}

                    // Thread-safe insertion of a new address (returns true if inserted)
                    /**
                     * @brief Inserts an address into this record.
                     * @param ip Address to insert.
                     * @return True when the address was newly inserted.
                     */
                    bool Emplace(const boost::asio::ip::address& ip) noexcept {
                        SynchronizedObjectScope lock(lockobj);
                        try {
                            return addresses.emplace(ip).second;
                        }
                        catch (const std::bad_alloc&) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                            return false;
                        }
                    }

                    // Thread-safe check for emptiness
                    /** @brief Checks whether this record contains no addresses. */
                    bool Empty() const noexcept {
                        SynchronizedObjectScope lock(lockobj);
                        return addresses.empty();
                    }

                    // Thread-safe copy of all addresses
                    /**
                     * @brief Copies all cached addresses into an output container.
                     * @param out Destination set.
                     */
                    void CopyAddresses(ppp::unordered_set<boost::asio::ip::address>& out) const noexcept {
                        SynchronizedObjectScope lock(lockobj);
                        try {
                            out = addresses;
                        }
                        catch (const std::bad_alloc&) {
                            // Leave out empty on allocation failure
                        }
                    }
                };
                typedef ppp::collections::LinkedListNode<NamespaceRecord>                       NamespaceRecordNode;
                typedef std::shared_ptr<NamespaceRecordNode>                                    NamespaceRecordNodePtr;

                // -----------------------------------------------------------------------------
                // Global cache container – uses a hash map for fast lookup and a linked list
                // for expiration ordering (LRU). All operations are protected by lockobj.
                // -----------------------------------------------------------------------------
                /** @brief Process-wide DNS cache state and transaction-id generator. */
                struct internal final {
                    SynchronizedObject                                      lockobj;                                    // Guards all members
                    std::atomic<uint16_t>                                   identification = RandomNext(1, UINT16_MAX); // DNS transaction ID generator
                    ppp::unordered_map<ppp::string, NamespaceRecordNodePtr> nr_hmap;                                    // Hostname → cache node
                    ppp::collections::LinkedList<NamespaceRecord>           nr_list;                                    // List for expiration

                    /** @brief Returns singleton internal cache state. */
                    static internal&                                        c() noexcept {
                        static internal i;
                        return i;
                    }
                };

                // -----------------------------------------------------------------------------
                // DNS_RequestContext – manages a single asynchronous resolution.
                // Socket and timers are bound to a per-request strand so the receive,
                // timeout, and merge handlers never run concurrently on multi-threaded
                // io_context workers; the request state below needs no extra locking.
                // -----------------------------------------------------------------------------
                /** @brief Per-query asynchronous DNS request state machine. */
                struct DNS_RequestContext final : public std::enable_shared_from_this<DNS_RequestContext> {
                    boost::asio::ip::udp::endpoint                                              source;
                    boost::asio::io_context&                                                    executor;
                    boost::asio::strand<boost::asio::io_context::executor_type>                 strand;   // Request-level serialization domain
                    std::shared_ptr<boost::asio::ip::udp::socket>                               socket;
                    boost::asio::steady_timer                                                   timeout_timer;
                    std::shared_ptr<boost::asio::steady_timer>                                  merge_timer;
                    SynchronizedObject                                                          merge_timer_mutex; // Protects merge_timer creation/destruction

                    // Per-address-family state
                    struct {
                        bool                                                                    received = false;
                        uint16_t                                                                id = 0;
                    } a_state, aaaa_state;

                    ppp::unordered_set<boost::asio::ip::address>                                addresses;   // Collected IPs
                    DNSRequestAsynchronousCallback                                              callback;    // User callback
                    ppp::string                                                                 hostname;    // Normalised hostname (lowercase)
                    uint32_t                                                                    min_response_ttl = 0;
                    bool                                                                        uncacheable_response_seen = false;

                    Byte                                                                        packet[PPP_MAX_DNS_PACKET_BUFFER_SIZE]; // Temporary buffer

                    VdnsRequestCompletion                                                       completion; // Arbitrates response/timeout/cancel

                    // -------------------------------------------------------------------------
                    // Constructor – creates an independent UDP socket (dual-stack).
                    // -------------------------------------------------------------------------
                    /**
                     * @brief Creates request context and initializes UDP socket resources.
                     * @param context IO context used for async send/receive operations.
                     */
                    explicit DNS_RequestContext(boost::asio::io_context& context) noexcept
                        : executor(context)
                        , strand(boost::asio::make_strand(context))
                        , timeout_timer(strand) {
                        socket = make_shared_object<boost::asio::ip::udp::socket>(strand);
                        if (NULLPTR != socket) {
                            boost::system::error_code ec;
                            socket->open(boost::asio::ip::udp::v6(), ec);
                            if (ec) {
                                socket.reset();
                            }
                            else {
                                // Set socket options for better performance.
                                int handle = socket->native_handle();
                                Socket::AdjustDefaultSocketOptional(handle, true);
                                Socket::SetTypeOfService(handle);
                                Socket::SetSignalPipeline(handle, false);
                                Socket::ReuseSocketAddress(handle, true);
                            }
                        }
                    }

                    // -------------------------------------------------------------------------
                    // Destructor – cancels all pending operations without invoking the callback.
                    // -------------------------------------------------------------------------
                    /** @brief Ensures outstanding async operations are cancelled safely. */
                    ~DNS_RequestContext() noexcept {
                        cancel();
                    }

                    // -------------------------------------------------------------------------
                    // Cancel all timers and close the socket. The callback is never called.
                    // -------------------------------------------------------------------------
                    /** @brief Cancels timers/socket and suppresses callback invocation. */
                    void cancel() noexcept {
                        completion.TryComplete(VdnsRequestCompletion::State::Cancelled, [this]() noexcept {
                            {
                                SynchronizedObjectScope lock(merge_timer_mutex);
                                if (NULLPTR != merge_timer) {
                                    Socket::Cancel(*merge_timer);
                                    merge_timer.reset();
                                }
                            }

                            // Cancel timeout timer – it will not fire after this point.
                            timeout_timer.expires_after(std::chrono::seconds(0));

                            Socket::Cancel(timeout_timer);
                            if (NULLPTR != socket) {
                                Socket::Closesocket(socket);
                                socket.reset();
                            }

                            callback = NULLPTR; // Release callback to avoid any accidental invocation
                        });
                    }

                    // -------------------------------------------------------------------------
                    // Finish the request – either because all responses arrived or a timeout occurred.
                    // Invokes the user callback exactly once and stores the result in the cache.
                    // -------------------------------------------------------------------------
                    /**
                     * @brief Completes a request, dispatches callback, and optionally caches result.
                     * @param is_timeout True when completion is triggered by timeout.
                     */
                    void finish(bool is_timeout) noexcept {
                        VdnsRequestCompletion::State terminal_state = is_timeout
                            ? VdnsRequestCompletion::State::TimedOut
                            : VdnsRequestCompletion::State::Finished;
                        completion.TryComplete(terminal_state, [this, is_timeout]() noexcept {
                            {
                                // Stop the merge timer if it is still pending.
                                SynchronizedObjectScope lock(merge_timer_mutex);
                                if (NULLPTR != merge_timer) {
                                    Socket::Cancel(*merge_timer);
                                    merge_timer.reset();
                                }
                            }

                            // Invoke the user callback (if any) with the collected addresses.
                            if (NULLPTR != callback) {
                                callback(a_state.received || aaaa_state.received, addresses);
                                callback = NULLPTR;
                            }

                            // Cache the result only if we have at least one address and this is not a reverse query.
                            if (!is_timeout && (a_state.received || aaaa_state.received) && !IsReverseQuery(hostname.data())) {
                                cache();
                            }

                            // Close the socket.
                            if (NULLPTR != socket) {
                                Socket::Closesocket(socket);
                                socket.reset();
                            }

                            // Ensure the timeout timer is also cancelled.
                            Socket::Cancel(timeout_timer);
                        });
                    }

                    // -------------------------------------------------------------------------
                    // Called when a DNS response is received.
                    // Updates the address set and checks whether the request is complete.
                    // This method may be called from multiple threads if io_context runs with >1 thread.
                    // -------------------------------------------------------------------------
                    /**
                     * @brief Handles a single inbound DNS response packet.
                     * @param data Packet payload buffer.
                     * @param len Packet length in bytes.
                     */
                    void on_response(const Byte* data, size_t len) noexcept {
                        if (!completion.IsPending()) {
                            return;
                        }

                        uint16_t ack = 0;
                        ppp::unordered_set<boost::asio::ip::address> new_addrs;
                        uint32_t response_ttl = 0;

                        // Verify that the response matches the expected hostname (case-insensitive)
                        if (DNS_ProcessAResponseAddresses(const_cast<Byte*>(data), static_cast<int>(len), new_addrs, ack, hostname.data(), NULLPTR, NULLPTR, &response_ttl)) {
                            // Merge the newly received addresses.
                            for (const auto& addr : new_addrs) {
                                try {
                                    addresses.emplace(addr);
                                }
                                catch (const std::bad_alloc&) {
                                    // Ignore memory allocation failure for this address
                                }
                            }

                            if (response_ttl > 0) {
                                if (min_response_ttl < 1) {
                                    min_response_ttl = response_ttl;
                                }
                                else {
                                    min_response_ttl = std::min<uint32_t>(min_response_ttl, response_ttl);
                                }
                            }
                            elif(!new_addrs.empty()) {
                                uncacheable_response_seen = true;
                            }

                            if (ack == a_state.id) {
                                a_state.received = true;
                            }
                            elif (ack == aaaa_state.id) {
                                aaaa_state.received = true;
                            }
                        }

                        // Determine whether both expected responses have been received.
                        bool need_a = (0 != a_state.id);
                        bool need_aaaa = (0 != aaaa_state.id);
                        if ((!need_a || a_state.received) && (!need_aaaa || aaaa_state.received)) {
                            finish(false); // All answers received
                            return;
                        }
                        else {
                            // Not all answers yet – start the merge timer only once (thread-safe).
                            //
                            // DEADLOCK FIX (Pattern D): Previously, async_wait() was registered while
                            // merge_timer_mutex was held.  The registered callback invokes finish(),
                            // which at its top also acquires merge_timer_mutex -> ABBA deadlock risk.
                            //
                            // Fix: create and arm the timer (expires_from_now) under the lock so the
                            // timer object is owned atomically, capture a local copy of the shared_ptr,
                            // then call async_wait() AFTER the lock is released so the callback can
                            // safely re-acquire merge_timer_mutex inside finish().
                            std::shared_ptr<boost::asio::steady_timer> pending_timer;
                            {
                                SynchronizedObjectScope lock(merge_timer_mutex);
                                if (NULLPTR == merge_timer) {
                                    merge_timer = make_shared_object<boost::asio::steady_timer>(strand);
                                    if (NULLPTR != merge_timer) {
                                        merge_timer->expires_after(Timer::DurationTime(PPP_IP_DNS_MERGE_WAIT));
                                        pending_timer = merge_timer; // capture before releasing lock
                                    }
                                }
                            } // merge_timer_mutex released here, BEFORE async_wait

                            // Register the handler only after the lock is released so the callback
                            // can safely re-acquire merge_timer_mutex when it calls finish().
                            if (NULLPTR != pending_timer) {
                                std::weak_ptr<DNS_RequestContext> weak_self = weak_from_this();
                                pending_timer->async_wait(
                                    [weak_self](const boost::system::error_code& ec) noexcept {
                                        std::shared_ptr<DNS_RequestContext> self = weak_self.lock();
                                        if (NULLPTR != self && ec != boost::asio::error::operation_aborted && self->completion.IsPending()) {
                                            self->finish(false);
                                        }
                                    });
                            }
                        }
                    }

                    // -------------------------------------------------------------------------
                    // Store the collected IP addresses into the global cache.
                    // This function is called only after the request has successfully finished.
                    // -------------------------------------------------------------------------
                    /** @brief Merges resolved addresses into global DNS cache. */
                    void cache() noexcept {
                        int ttl_cap = vdns::ttl;
                        if (ttl_cap < 1 || min_response_ttl < 1 || addresses.empty() || uncacheable_response_seen) {
                            return;
                        }

                        uint32_t ttl_seconds = std::min<uint32_t>(
                            min_response_ttl,
                            static_cast<uint32_t>(ttl_cap));
                        if (ttl_seconds < 1) {
                            return;
                        }

                        uint64_t expire_time = Executors::GetTickCount() + static_cast<uint64_t>(ttl_seconds) * 1000;

                        internal& c = internal::c();
                        SynchronizedObjectScope lock(c.lockobj); // Protect global cache structures

                        NamespaceRecordNodePtr node;
                        if (Dictionary::TryGetValue(c.nr_hmap, hostname, node) && NULLPTR != node) {
                            // Existing cache entry – merge new addresses and update expiry.
                            NamespaceRecord& nr = node->Value;
                            {
                                SynchronizedObjectScope nr_lock(nr.lockobj);
                                for (const auto& addr : addresses) {
                                    try {
                                        nr.addresses.emplace(addr);
                                    }
                                    catch (const std::bad_alloc&) {
                                        // Ignore memory allocation failure for this address
                                    }
                                }

                                nr.expired_time = expire_time;
                                nr.ipv4 = nr.ipv4 || a_state.received;
                                nr.ipv6 = nr.ipv6 || aaaa_state.received;
                            }

                            // Move the node to the tail of the LRU list (most recent).
                            c.nr_list.Remove(node);
                            c.nr_list.AddLast(node);
                        }
                        else {
                            // Create a new cache entry.
                            node = make_shared_object<NamespaceRecordNode>();
                            if (NULLPTR == node) {
                                return;
                            }

                            NamespaceRecord& nr = node->Value;
                            nr.hostname = hostname;

                            try {
                                nr.addresses = addresses;      // Copy the set (addresses is local, no lock needed)
                            }
                            catch (const std::bad_alloc&) {
                                return; // Cannot allocate cache entry
                            }

                            nr.expired_time = expire_time;
                            nr.ipv4 = a_state.received;
                            nr.ipv6 = aaaa_state.received;
                            if (!Dictionary::TryAdd(c.nr_hmap, hostname, node)) {
                                return;
                            }

                            c.nr_list.AddLast(node);
                        }
                    }

                    // -------------------------------------------------------------------------
                    // Build and send A and AAAA requests to all configured DNS servers.
                    // Returns true if at least one request was sent successfully.
                    // -------------------------------------------------------------------------
                    /**
                     * @brief Sends A and AAAA queries to all destination DNS servers.
                     * @param destinations DNS server endpoints.
                     * @param timeout_ms Request timeout in milliseconds.
                     * @return True when at least one query is sent successfully.
                     */
                    bool send_requests(const ppp::vector<boost::asio::ip::udp::endpoint>& destinations, int timeout_ms) noexcept {
                        if (NULLPTR == socket) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                            return false;
                        }

                        internal& c = internal::c();
                        bool any_sent = false;
                        bool any_encode_failed = false;
                        bool any_send_failed = false;

                        // Two queries: A (IPv4) and AAAA (IPv6)
                        struct QueryInfo {
                            uint16_t*           id_ptr;
                            bool*               received_ptr;
                            ::dns::RecordType   rt;
                        } queries[2] = {
                            {&a_state.id, &a_state.received, ::dns::RecordType::kA},
                            {&aaaa_state.id, &aaaa_state.received, ::dns::RecordType::kAAAA}
                        };

                        for (int i = 0; i < 2; ++i) {
                            QueryInfo& q = queries[i];

                            // Generate a unique transaction ID (avoid conflict with the other query).
                            uint16_t new_id;
                            do {
                                new_id = ++c.identification;
                                if (0 == new_id) {
                                    new_id = ++c.identification;
                                }
                            } while (i == 1 && new_id == a_state.id); // Ensure A and AAAA IDs differ
                            *q.id_ptr = new_id;

                            ::dns::Message msg;
                            msg.mRD = 1;  // Recursion desired
                            msg.mId = *q.id_ptr;
                            msg.questions.emplace_back(::dns::QuestionSection(stl::transform<std::string>(hostname), q.rt, ::dns::RecordClass::kIN));

                            size_t msg_len = 0;
                            if (::dns::BufferResult::NoError != msg.encode(packet, PPP_MAX_DNS_PACKET_BUFFER_SIZE, msg_len)) {
                                any_encode_failed = true;
                                continue;
                            }

                            // Send the same query to every destination server.
                            for (const boost::asio::ip::udp::endpoint& ep : destinations) {
                                boost::system::error_code ec;
                                socket->send_to(boost::asio::buffer(packet, msg_len),
                                    ppp::net::Ipep::V4ToV6(ep),
                                    boost::asio::ip::udp::socket::message_end_of_record,
                                    ec);
                                if (!ec) {
                                    any_sent = true;
                                }
                                else {
                                    any_send_failed = true;
                                }
                            }
                        }

                        if (!any_sent) {
                            if (any_send_failed) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpSendFailed);
                            }
                            elif (any_encode_failed) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                            }
                            else {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsResolveFailed);
                            }
                            return false;
                        }

                        // Set the overall timeout for this request.
                        std::weak_ptr<DNS_RequestContext> weak_self = weak_from_this();
                        timeout_timer.expires_after(Timer::DurationTime(timeout_ms));
                        timeout_timer.async_wait(
                            [weak_self](const boost::system::error_code& ec) noexcept {
                                std::shared_ptr<DNS_RequestContext> self = weak_self.lock();
                                if (NULLPTR != self && ec != boost::asio::error::operation_aborted && self->completion.IsPending()) {
                                    self->finish(true);
                                }
                            });

                        // Start the asynchronous receive loop.
                        start_receive_loop();
                        return true;
                    }

                private:
                    // -------------------------------------------------------------------------
                    // Asynchronous receive loop – posts a new async_receive_from after each
                    // successful receive, until the request is completed.
                    // -------------------------------------------------------------------------
                    /** @brief Starts or continues asynchronous UDP receive loop for this request. */
                    void start_receive_loop() noexcept {
                        if (NULLPTR == socket || !completion.IsPending()) {
                            return;
                        }

                        auto self = shared_from_this();
                        socket->async_receive_from(
                            boost::asio::buffer(packet, PPP_MAX_DNS_PACKET_BUFFER_SIZE), source,
                            [self](boost::system::error_code ec, size_t len) noexcept {
                                if (ec || !self->completion.IsPending()) {
                                    return;
                                }

                                if (len > 0) {
                                    self->on_response(self->packet, len);
                                }

                                // Continue the loop only if the request is still alive and the socket is open.
                                if (self->completion.IsPending() && NULLPTR != self->socket && self->socket->is_open()) {
                                    self->start_receive_loop();
                                }
                            });
                    }
                };

                // -----------------------------------------------------------------------------
                // Global configuration variables
                // -----------------------------------------------------------------------------
                IPEndPointVectorPtr                                                         servers; // Publish via std::atomic_store; read via std::atomic_load
                std::atomic<bool>                                                           enabled{ false };
                std::atomic<int>                                                            ttl{ PPP_DEFAULT_DNS_TTL };

                // -----------------------------------------------------------------------------
                // Initialisation function – must be called early in main().
                // -----------------------------------------------------------------------------
                /** @brief Initializes default DNS servers and resets TTL to default. */
                void vdns_ctor() noexcept {
                    boost::system::error_code ec;
                    ttl = PPP_DEFAULT_DNS_TTL;

                    auto dns_servers = make_shared_object<IPEndPointVector>();
                    dns_servers->emplace_back(boost::asio::ip::udp::endpoint(StringToAddress(PPP_PREFERRED_DNS_SERVER_1, ec), PPP_DNS_SYS_PORT));
                    dns_servers->emplace_back(boost::asio::ip::udp::endpoint(StringToAddress(PPP_PREFERRED_DNS_SERVER_2, ec), PPP_DNS_SYS_PORT));

                    // Publish only after the vector is fully populated; readers treat it as immutable.
                    std::atomic_store(&servers, dns_servers);
                }

                // -----------------------------------------------------------------------------
                // Internal helper: normalise hostname and try to look it up in the cache.
                // Returns true if the hostname is valid; out_node may be null or point to a cache node.
                // -----------------------------------------------------------------------------
                /**
                 * @brief Normalizes hostname and looks up cache node by key.
                 * @param hostname Input hostname.
                 * @param out_hostname Normalized lowercase hostname.
                 * @param out_node Cache node when present.
                 * @return True when input hostname is valid.
                 */
                static bool DNS_ResolveFromCache(const char*    hostname,
                    ppp::string&                                out_hostname,
                    NamespaceRecordNodePtr&                     out_node) noexcept {
                    if (NULLPTR == hostname || '\x0' == *hostname) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VdnsResolveFromCacheHostnameInvalid);
                        return false;
                    }

                    size_t len = strnlen(hostname, PPP_MAX_HOSTNAME_SIZE_LIMIT + 1);
                    if (len >= PPP_MAX_HOSTNAME_SIZE_LIMIT) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsAddressInvalid);
                        return false;
                    }

                    out_hostname = ATrim(ppp::string(hostname, len));
                    if (out_hostname.empty()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsAddressInvalid);
                        return false;
                    }

                    out_hostname = ToLower(out_hostname);

                    internal& c = internal::c();
                    SynchronizedObjectScope lock(c.lockobj);
                    if (Dictionary::TryGetValue(c.nr_hmap, out_hostname, out_node) && NULLPTR == out_node) {
                        Dictionary::TryRemove(c.nr_hmap, out_hostname); // Clean up null entry
                        out_node.reset();
                    }
                    elif(NULLPTR != out_node) {
                        bool expired = false;
                        {
                            SynchronizedObjectScope record_lock(out_node->Value.lockobj);
                            expired = Executors::GetTickCount() >= out_node->Value.expired_time;
                        }

                        if (expired) {
                            Dictionary::TryRemove(c.nr_hmap, out_hostname);
                            c.nr_list.Remove(out_node);
                            out_node.reset();
                        }
                    }
                    return true;
                }

                // -----------------------------------------------------------------------------
                // Internal callback dispatcher – respects IPv4 preference and returns either
                // a single address or the whole set.
                // -----------------------------------------------------------------------------
                /**
                 * @brief Dispatches resolve result as first-address or all-address callback.
                 * @param addresses Resolved/cached address set.
                 * @param one_cb Optional callback for single preferred address.
                 * @param all_cb Optional callback for full address set.
                 */
                static void DNS_ResolveEventCallback(const ppp::unordered_set<boost::asio::ip::address>&    addresses,
                    const ppp::function<void(const boost::asio::ip::address&)>&                             one_cb,
                    const ppp::function<void(const ppp::unordered_set<boost::asio::ip::address>&)>&         all_cb) noexcept {
                    if (NULLPTR != one_cb) {
                        if (addresses.empty()) {
                            one_cb(boost::asio::ip::address_v4::any()); // No address -> return any address (0.0.0.0)
                            return;
                        }

                        // Prefer IPv4 addresses.
                        for (const boost::asio::ip::address& ip : addresses) {
                            if (ip.is_v4()) {
                                one_cb(ip);
                                return;
                            }
                        }

                        // Fallback to IPv6.
                        for (const boost::asio::ip::address& ip : addresses) {
                            if (ip.is_v6()) {
                                one_cb(ip);
                                return;
                            }
                        }
                    }
                    elif (NULLPTR != all_cb) {
                        all_cb(addresses);
                    }
                }

                // -----------------------------------------------------------------------------
                // Core asynchronous sending routine – creates a request context and starts transmission.
                // -----------------------------------------------------------------------------
                /**
                 * @brief Allocates and starts a DNS request context.
                 * @param context IO context that owns async operations.
                 * @param hostname Normalized hostname to query.
                 * @param timeout_ms Query timeout in milliseconds.
                 * @param destinations DNS server endpoints.
                 * @param cb Completion callback from request context.
                 * @return True when request context starts successfully.
                 */
                static bool DNS_SendToARequestAsync(boost::asio::io_context&    context,
                    const ppp::string&                                          hostname,
                    int                                                         timeout_ms,
                    const ppp::vector<boost::asio::ip::udp::endpoint>&          destinations,
                    const DNSRequestAsynchronousCallback&                       cb) noexcept {

                    if (hostname.empty() || destinations.empty()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VdnsSendRequestInvalidArguments);
                    }

                    auto ctx = std::make_shared<DNS_RequestContext>(context);
                    if (NULLPTR == ctx || NULLPTR == ctx->socket) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketCreateFailed);
                    }

                    ctx->callback = cb;
                    ctx->hostname = hostname;
                    return ctx->send_requests(destinations, timeout_ms);
                }

                // -----------------------------------------------------------------------------
                // Public API: ResolveAsync – returns the first IP address (IPv4 preferred).
                // -----------------------------------------------------------------------------
                /**
                 * @brief Resolves hostname asynchronously and returns one preferred address.
                 * @param context IO context used for callback posting.
                 * @param hostname Domain name or literal IP address.
                 * @param timeout Timeout in milliseconds.
                 * @param destinations DNS server endpoints.
                 * @param cb Completion callback.
                 * @return True when resolve request is accepted.
                 */
                bool ResolveAsync(boost::asio::io_context&                      context,
                    const char*                                                 hostname,
                    int                                                         timeout,
                    const ppp::vector<boost::asio::ip::udp::endpoint>&          destinations,
                    const ppp::function<void(const boost::asio::ip::address&)>& cb) noexcept {

                    if (NULLPTR == cb) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VdnsResolveAsyncNullCallback);
                    }

                    ppp::string hostname_str;
                    NamespaceRecordNodePtr node;
                    if (!DNS_ResolveFromCache(hostname, hostname_str, node)) {
                        return false;
                    }

                    if (NULLPTR != node) {
                        // Cache hit – return immediately via post.
                        boost::asio::post(context,
                            [node, cb]() noexcept {
                                ppp::unordered_set<boost::asio::ip::address> addrs;
                                node->Value.CopyAddresses(addrs);
                                DNS_ResolveEventCallback(addrs, cb, NULLPTR);
                            });
                        return true;
                    }

                    // Check whether the input is already a literal IP address.
                    boost::system::error_code ec;
                    boost::asio::ip::address addr = StringToAddress(hostname_str, ec);
                    if (!ec) {
                        boost::asio::post(context,
                            [addr, cb]() noexcept {
                                ppp::unordered_set<boost::asio::ip::address> addrs = { addr };
                                DNS_ResolveEventCallback(addrs, cb, NULLPTR);
                            });
                        return true;
                    }

                    // Perform network resolution.
                    int timeout_ms = (timeout > 0) ? timeout : PPP_RESOLVE_DNS_TIMEOUT;
                    return DNS_SendToARequestAsync(context, hostname_str, timeout_ms, destinations,
                        [cb](bool, ppp::unordered_set<boost::asio::ip::address>& addrs) noexcept {
                            DNS_ResolveEventCallback(addrs, cb, NULLPTR);
                        });
                }

                // -----------------------------------------------------------------------------
                // Public API: ResolveAsync2 – returns all IP addresses.
                // -----------------------------------------------------------------------------
                /**
                 * @brief Resolves hostname asynchronously and returns all discovered addresses.
                 * @param context IO context used for callback posting.
                 * @param hostname Domain name or literal IP address.
                 * @param timeout Timeout in milliseconds.
                 * @param destinations DNS server endpoints.
                 * @param cb Completion callback.
                 * @return True when resolve request is accepted.
                 */
                bool ResolveAsync2(boost::asio::io_context&                                         context,
                    const char*                                                                     hostname,
                    int                                                                             timeout,
                    const ppp::vector<boost::asio::ip::udp::endpoint>&                              destinations,
                    const ppp::function<void(const ppp::unordered_set<boost::asio::ip::address>&)>& cb) noexcept {

                    if (NULLPTR == cb) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VdnsResolveAsync2NullCallback);
                    }

                    ppp::string hostname_str;
                    NamespaceRecordNodePtr node;
                    if (!DNS_ResolveFromCache(hostname, hostname_str, node)) {
                        return false;
                    }
                    
                    if (NULLPTR != node) {
                        boost::asio::post(context, 
                            [node, cb]() noexcept {
                                ppp::unordered_set<boost::asio::ip::address> addrs;
                                node->Value.CopyAddresses(addrs);
                                DNS_ResolveEventCallback(addrs, NULLPTR, cb);
                            });
                        return true;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::address addr = StringToAddress(hostname_str, ec);
                    if (!ec) {
                        boost::asio::post(context, 
                            [addr, cb]() noexcept {
                                ppp::unordered_set<boost::asio::ip::address> addrs = { addr };
                                DNS_ResolveEventCallback(addrs, NULLPTR, cb);
                            });
                        return true;
                    }

                    int timeout_ms = (timeout > 0) ? timeout : PPP_RESOLVE_DNS_TIMEOUT;
                    return DNS_SendToARequestAsync(context, hostname_str, timeout_ms, destinations,
                        [cb](bool, ppp::unordered_set<boost::asio::ip::address>& addrs) noexcept {
                            DNS_ResolveEventCallback(addrs, NULLPTR, cb);
                        });
                }

                // -----------------------------------------------------------------------------
                // Public API: QueryCache – retrieve a single cached IP address (IPv4 preferred).
                // -----------------------------------------------------------------------------
                /**
                 * @brief Retrieves a single preferred address from cache.
                 * @param hostname Domain key.
                 * @param address Output address.
                 * @return True when a valid cached address is returned.
                 */
                bool QueryCache(const char* hostname, boost::asio::ip::address& address) noexcept {
                    ppp::string hostname_str;
                    NamespaceRecordNodePtr node;
                    if (!DNS_ResolveFromCache(hostname, hostname_str, node)) {
                        return false;
                    }

                    if (NULLPTR == node) {
                        return false;
                    }

                    ppp::unordered_set<boost::asio::ip::address> addrs;
                    node->Value.CopyAddresses(addrs);

                    DNS_ResolveEventCallback(addrs,
                        [&address](const boost::asio::ip::address& ip) noexcept { 
                            address = ip; 
                        },
                        NULLPTR);
                    if (IPEndPoint::IsInvalid(address)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsCacheFailed);
                        return false;
                    }

                    return true;
                }

                // -----------------------------------------------------------------------------
                // Public API: QueryCache2 – build a DNS response message from cached records.
                // -----------------------------------------------------------------------------
                /**
                 * @brief Populates DNS answer section from cache for selected record family.
                 * @param hostname Domain key.
                 * @param message Output DNS message object.
                 * @param af Address family selector.
                 * @return Normalized hostname on cache hit, otherwise empty.
                 */
                ppp::string QueryCache2(const char* hostname, ::dns::Message& message, AddressFamily af) noexcept {
                    bool want_v4 = (AddressFamily::kA == af);
                    bool want_v6 = (AddressFamily::kAAAA == af);
                    if (!want_v4 && !want_v6) {
                        return ppp::string();
                    }

                    ppp::string hostname_str;
                    NamespaceRecordNodePtr node;
                    if (!DNS_ResolveFromCache(hostname, hostname_str, node) || NULLPTR == node) {
                        return ppp::string();
                    }

                    NamespaceRecord& record = node->Value;
                    bool any = false;
                    uint32_t remaining_ttl = 0;
                    {
                        SynchronizedObjectScope lock(record.lockobj);
                        uint64_t now = Executors::GetTickCount();
                        if (now >= record.expired_time) {
                            return ppp::string();
                        }

                        uint64_t remaining_ms = record.expired_time - now;
                        remaining_ttl = static_cast<uint32_t>(std::max<uint64_t>(1, (remaining_ms + 999) / 1000));

                        // Quick check inside lock to avoid reading stale flags
                        if ((want_v4 && !record.ipv4) || (want_v6 && !record.ipv6)) {
                            return ppp::string();
                        }

                        for (const boost::asio::ip::address& ip : record.addresses) {
                            if (want_v4 && ip.is_v4()) {
                                auto rd_a = make_shared_object<::dns::RDataA>();
                                if (NULLPTR == rd_a) {
                                    break;
                                }

                                rd_a->setAddress(const_cast<uint8_t*>(ip.to_v4().to_bytes().data()));

                                ::dns::ResourceRecord rr;
                                rr.mName = hostname_str;
                                rr.mClass = ::dns::RecordClass::kIN;
                                rr.mType = ::dns::RecordType::kA;
                                rr.mTtl = remaining_ttl;
                                rr.setRData(rd_a);

                                try {
                                    message.answers.emplace_back(rr);
                                }
                                catch (const std::bad_alloc&) {
                                    break;
                                }

                                any = true;
                            }
                            elif (want_v6 && ip.is_v6()) {
                                auto rd_aaaa = make_shared_object<::dns::RDataAAAA>();
                                if (NULLPTR == rd_aaaa) {
                                    break;
                                }

                                rd_aaaa->setAddress(const_cast<uint8_t*>(ip.to_v6().to_bytes().data()));

                                ::dns::ResourceRecord rr;
                                rr.mName = hostname_str;
                                rr.mClass = ::dns::RecordClass::kIN;
                                rr.mType = ::dns::RecordType::kAAAA;
                                rr.mTtl = remaining_ttl;
                                rr.setRData(rd_aaaa);

                                try {
                                    message.answers.emplace_back(rr);
                                }
                                catch (const std::bad_alloc&) {
                                    break;
                                }

                                any = true;
                            }
                        }
                    }

                    message.mQr = 1;
                    message.mRA = 1;
                    message.mRCode = any ? static_cast<uint16_t>(::dns::ResponseCode::kNOERROR)
                        : static_cast<uint16_t>(::dns::ResponseCode::kNXDOMAIN);
                    return hostname_str;
                }

                // -----------------------------------------------------------------------------
                // Public API: UpdateAsync – remove expired cache entries.
                // Called periodically (e.g., every minute) from a maintenance thread.
                // -----------------------------------------------------------------------------
                /** @brief Removes expired entries from the in-memory DNS cache. */
                void UpdateAsync() noexcept {
                    uint64_t now = Executors::GetTickCount();
                    internal& c = internal::c();
                    
                    SynchronizedObjectScope lock(c.lockobj);
                    NamespaceRecordNodePtr node = c.nr_list.First();

                    while (NULLPTR != node) {
                        NamespaceRecordNodePtr next = node->Next;
                        if (now >= node->Value.expired_time) {
                            Dictionary::TryRemove(c.nr_hmap, node->Value.hostname);
                            c.nr_list.Remove(node);
                        }

                        node = next;
                    }
                }

                void ClearCache() noexcept {
                    internal& c = internal::c();
                    SynchronizedObjectScope lock(c.lockobj);
                    c.nr_hmap.clear();
                    c.nr_list.Clear();
                }

                // -----------------------------------------------------------------------------
                // Public API: AddCache – manually insert a DNS response packet into the cache.
                // -----------------------------------------------------------------------------
                /**
                 * @brief Adds or merges cache entry from a raw DNS response packet.
                 * @param packet DNS packet bytes.
                 * @param packet_size Packet length in bytes.
                 * @return True when cache update succeeds.
                 */
                bool AddCache(const Byte* packet, int packet_size) noexcept {
                    if (NULLPTR == packet || packet_size < 1) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsPacketInvalid);
                        return false;
                    }

                    uint16_t ack = 0;
                    ppp::string hostname;
                    bool ipv4_or_ipv6 = false;
                    uint32_t response_ttl = 0;
                    ppp::unordered_set<boost::asio::ip::address> addresses;

                    // No expected hostname verification for manual cache addition – trust the packet.
                    if (!DNS_ProcessAResponseAddresses(const_cast<Byte*>(packet), packet_size,
                        addresses, ack, NULLPTR, &hostname, &ipv4_or_ipv6, &response_ttl)) {
                        return false;
                    }

                    if (hostname.empty() || IsReverseQuery(hostname.data()) || addresses.empty() || response_ttl < 1) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsResponseInvalid);
                        return false;
                    }

                    int ttl_cap = vdns::ttl;
                    if (ttl_cap < 1) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsCacheFailed);
                        return false;
                    }

                    uint32_t ttl_seconds = std::min<uint32_t>(
                        response_ttl,
                        static_cast<uint32_t>(ttl_cap));
                    if (ttl_seconds < 1) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsCacheFailed);
                        return false;
                    }

                    uint64_t expire_time = Executors::GetTickCount() + static_cast<uint64_t>(ttl_seconds) * 1000;

                    internal& c = internal::c();
                    SynchronizedObjectScope lock(c.lockobj);

                    NamespaceRecordNodePtr node;
                    if (Dictionary::TryGetValue(c.nr_hmap, hostname, node) && NULLPTR != node) {
                        // Existing entry – merge new addresses and refresh expiry.
                        NamespaceRecord& nr = node->Value;
                        {
                            SynchronizedObjectScope nr_lock(nr.lockobj);
                            for (const boost::asio::ip::address& ip : addresses) {
                                try {
                                    nr.addresses.emplace(ip);
                                }
                                catch (const std::bad_alloc&) {
                                    // Ignore memory allocation failure for this address
                                }
                            }

                            nr.expired_time = expire_time;
                            if (ipv4_or_ipv6) {
                                nr.ipv4 = true;
                            }
                            else {
                                nr.ipv6 = true;
                            }
                        }

                        // Move to the tail of the LRU list.
                        c.nr_list.Remove(node);
                        c.nr_list.AddLast(node);
                        return true;
                    }
                    else {
                        // Create a new entry.
                        node = make_shared_object<NamespaceRecordNode>();
                        if (NULLPTR == node) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                            return false;
                        }

                        NamespaceRecord& nr = node->Value;
                        nr.hostname = hostname;
                        try {
                            nr.addresses = std::move(addresses);
                        }
                        catch (const std::bad_alloc&) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                            return false;
                        }

                        nr.expired_time = expire_time;
                        nr.ipv4 = ipv4_or_ipv6;
                        nr.ipv6 = !ipv4_or_ipv6;
                        if (!Dictionary::TryAdd(c.nr_hmap, hostname, node)) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsCacheFailed);
                            return false;
                        }

                        c.nr_list.AddLast(node);
                        return true;
                    }
                }

                // -----------------------------------------------------------------------------
                // Public API: IsReverseQuery – detect PTR queries for .arpa domains.
                // -----------------------------------------------------------------------------
                /**
                 * @brief Detects reverse-DNS names under ARPA zones.
                 * @param hostname Hostname to test.
                 * @return True when hostname matches IPv4/IPv6 reverse-query suffix.
                 */
                bool IsReverseQuery(const char* hostname) noexcept {
                    static constexpr char PPP_DNS_ARPA_QEURY_IPV6[] = ".ip6.arpa";
                    static constexpr char PPP_DNS_ARPA_QEURY_IPV4[] = ".in-addr.arpa";
                    if (NULLPTR == hostname || '\x0' == *hostname) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VdnsIsReverseQueryHostnameInvalid);
                        return false;
                    }

                    size_t len = strnlen(hostname, PPP_MAX_HOSTNAME_SIZE_LIMIT + 1);
                    if (len >= PPP_MAX_HOSTNAME_SIZE_LIMIT) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsAddressInvalid);
                        return false;
                    }

                    if (len >= sizeof(PPP_DNS_ARPA_QEURY_IPV6)) {
                        const char* p = hostname + (len - sizeof(PPP_DNS_ARPA_QEURY_IPV6) + 1);
                        if (0 == strcmp(p, PPP_DNS_ARPA_QEURY_IPV6)) {
                            return true;
                        }
                    }

                    if (len >= sizeof(PPP_DNS_ARPA_QEURY_IPV4)) {
                        const char* p = hostname + (len - sizeof(PPP_DNS_ARPA_QEURY_IPV4) + 1);
                        if (0 == strcmp(p, PPP_DNS_ARPA_QEURY_IPV4)) {
                            return true;
                        }
                    }

                    return false;
                }

            } // namespace vdns
        } // namespace asio
    } // namespace net
} // namespace ppp
