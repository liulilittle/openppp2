#include <ppp/stdafx.h>
#include <ppp/dns/DnsResolver.h>
#include <ppp/dns/DnsProviderCatalog.h>
#include <ppp/dns/DnsWireValidation.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/ssl/SSL.h>
#include <ppp/diagnostics/TelemetryFwd.h>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>

namespace ppp {
    namespace dns {

        static constexpr int PPP_DNS_RESOLVER_UDP_BUFFER_SIZE   = 4096;
        static constexpr int PPP_DNS_RESOLVER_TCP_MAX_SIZE      = 65535;
        /**
         * @brief Per-protocol upstream timeouts (milliseconds).
         *
         * @details The original implementation used a single 5 s timeout for every
         *          protocol. That meant a single failing DoH endpoint stalled the
         *          fallback chain for 5 s before the next protocol was tried, and
         *          UDP queries — which should normally complete in under 100 ms —
         *          would also block their callers for 5 s on packet loss. The
         *          values below give faster fallback while keeping enough headroom
         *          for the slowest legitimate path (TLS handshake on lossy links).
         */
        static constexpr int PPP_DNS_RESOLVER_UDP_TIMEOUT_MS    = 2000;  ///< Plain UDP: short, retried via fallback.
        static constexpr int PPP_DNS_RESOLVER_TCP_TIMEOUT_MS    = 3000;  ///< Plain TCP / DoT length-prefixed.
        static constexpr int PPP_DNS_RESOLVER_TLS_TIMEOUT_MS    = 4000;  ///< DoH / DoT (TLS handshake + request).
        static constexpr int PPP_DNS_RESOLVER_STUN_TIMEOUT_MS   = 3000;
        static constexpr int PPP_DNS_RESOLVER_STUN_CACHE_SECONDS = 600;
        static constexpr int PPP_DNS_RESOLVER_STUN_NEGATIVE_CACHE_SECONDS = 15;

        using ppp::telemetry::Level;

        typedef boost::asio::ip::udp udp;
        typedef boost::asio::ip::tcp tcp;

        static constexpr std::size_t PPP_DNS_TLS_SESSION_CACHE_LIMIT = 32;

        enum class DnsTransportStage {
            Attempt,
            Success,
            Socket,
            Connect,
            Send,
            Recv,
            Parse,
            Tls,
            Http,
            Bootstrap,
            Timeout,
        };

        enum class DnsTransportReason {
            None,
            Failed,
            Invalid,
            Empty,
            AllocFailed,
            OpenFailed,
            ProtectFailed,
            BuildFailed,
            VerifyFailed,
            CacheHit,
            CacheMiss,
            ReuseAttempt,
            Reused,
            NotReused,
            BadStatus,
            Timeout,
        };

        static const char* DnsTransportToString(Protocol protocol) noexcept {
            switch (protocol) {
            case Protocol::UDP: return "udp";
            case Protocol::TCP: return "tcp";
            case Protocol::DoH: return "doh";
            case Protocol::DoT: return "dot";
            default:            return "unknown";
            }
        }

        static const char* DnsTransportStageToString(DnsTransportStage stage) noexcept {
            switch (stage) {
            case DnsTransportStage::Attempt:   return "attempt";
            case DnsTransportStage::Success:   return "success";
            case DnsTransportStage::Socket:    return "socket";
            case DnsTransportStage::Connect:   return "connect";
            case DnsTransportStage::Send:      return "send";
            case DnsTransportStage::Recv:      return "recv";
            case DnsTransportStage::Parse:     return "parse";
            case DnsTransportStage::Tls:       return "tls";
            case DnsTransportStage::Http:      return "http";
            case DnsTransportStage::Bootstrap: return "bootstrap";
            case DnsTransportStage::Timeout:   return "timeout";
            default:                           return "unknown";
            }
        }

        static const char* DnsTransportReasonToString(DnsTransportReason reason) noexcept {
            switch (reason) {
            case DnsTransportReason::None:         return "";
            case DnsTransportReason::Failed:       return "failed";
            case DnsTransportReason::Invalid:      return "invalid";
            case DnsTransportReason::Empty:        return "empty";
            case DnsTransportReason::AllocFailed:  return "alloc_failed";
            case DnsTransportReason::OpenFailed:   return "open_failed";
            case DnsTransportReason::ProtectFailed: return "protect_failed";
            case DnsTransportReason::BuildFailed:  return "build_failed";
            case DnsTransportReason::VerifyFailed: return "verify_failed";
            case DnsTransportReason::CacheHit:     return "cache_hit";
            case DnsTransportReason::CacheMiss:    return "cache_miss";
            case DnsTransportReason::ReuseAttempt: return "reuse_attempt";
            case DnsTransportReason::Reused:       return "reused";
            case DnsTransportReason::NotReused:    return "not_reused";
            case DnsTransportReason::BadStatus:    return "bad_status";
            case DnsTransportReason::Timeout:      return "timeout";
            default:                               return "unknown";
            }
        }

        static void CountDnsTransport(Protocol protocol, DnsTransportStage stage, DnsTransportReason reason = DnsTransportReason::None) noexcept {
            ppp::string metric = "dns.transport.";
            metric.append(DnsTransportToString(protocol)).append(".").append(DnsTransportStageToString(stage));
            if (reason != DnsTransportReason::None) {
                metric.append(".").append(DnsTransportReasonToString(reason));
            }
            ppp::telemetry::Count(metric.c_str(), 1);
            ppp::telemetry::Log(Level::kTrace, "dns", "transport event transport=%s stage=%s reason=%s",
                DnsTransportToString(protocol), DnsTransportStageToString(stage), DnsTransportReasonToString(reason));
        }

        /* ========================================================================
         * STUN protocol constants (RFC 5389)
         * ======================================================================== */

        static constexpr uint16_t   kStunMsgTypeBindingRequest  = 0x0001;
        static constexpr uint16_t   kStunMsgTypeBindingResponse = 0x0101;
        static constexpr uint32_t   kStunMagicCookie            = 0x2112A442;
        static constexpr uint16_t   kStunAttrXorMappedAddr      = 0x0020;

        /* Default STUN candidate list — well-known public STUN servers.
         * IPs are hardcoded where possible to avoid DNS bootstrap dependency.
         * Hostname entries are resolved at runtime via bootstrap. */
        static const ppp::vector<StunCandidate>& DefaultStunCandidates() noexcept {
            static const ppp::vector<StunCandidate> candidates = [] {
                ppp::vector<StunCandidate> v;
                auto add = [&v](const char* ip, int port) noexcept {
                    boost::system::error_code ec;
                    boost::asio::ip::address a = StringToAddress(ip, ec);
                    if (!ec && !a.is_unspecified()) {
                        v.push_back({ a, port });
                    }
                };
                /* Google STUN servers */
                add("74.125.24.127",   19302);   /* stun.l.google.com:19302 */
                add("74.125.25.127",   19302);   /* stun2.l.google.com:19302 */
                add("173.194.76.127",  19302);   /* stun3.l.google.com:19302 */
                add("74.125.200.127",  19302);   /* stun4.l.google.com:19302 */
                /* Cloudflare STUN */
                add("162.159.200.123", 3478);    /* stun.cloudflare.com */
                /* Twilio STUN */
                add("54.241.125.61",   3478);    /* global.stun.twilio.com */
                add("35.155.227.88",   3478);    /* us1.stun.twilio.com */
                add("34.205.20.150",   3478);    /* us2.stun.twilio.com */
                add("54.169.62.43",    3478);    /* sg1.stun.twilio.com */
                add("13.115.118.38",   3478);    /* jp1.stun.twilio.com */
                return v;
            }();
            return candidates;
        }

        /* ========================================================================
         * DNS OPT RR constants (RFC 6891 / RFC 7871)
         * ======================================================================== */

        static constexpr std::size_t kDnsHeaderSize   = 12;
        static constexpr uint16_t    kOptType         = 41;
        static constexpr uint16_t    kEcsOptionCode   = 8;
        static constexpr std::size_t kEcsNewOptionLen = 8;    /* family(2) + prefix(1) + scope(1) + addr(4) */
        static constexpr std::size_t kEcsNewRdataLen  = 4 + kEcsNewOptionLen; /* opt-code(2) + opt-len(2) + data */
        static constexpr std::size_t kOptRrOverhead   = 11;   /* name(1) + type(2) + class(2) + ttl(4) + rdlen(2) */

        /* ========================================================================
         * DNS wire-format parsing helpers
         * ======================================================================== */

        /**
         * @brief Skips a DNS name (sequence of labels or a compression pointer)
         *        starting at position @p pos in @p data.
         *
         * @return Number of bytes consumed from position @p pos, or 0 on error.
         */
        static std::size_t SkipDnsName(const Byte* data, std::size_t size, std::size_t pos) noexcept {
            if (pos >= size) {
                return 0;
            }

            std::size_t consumed = 0;
            for (;;) {
                if (pos + consumed >= size) {
                    return 0;
                }

                Byte label = data[pos + consumed];
                if (label == 0x00) {
                    /* Root label — single null byte. */
                    return consumed + 1;
                }
                if ((label & 0xC0) == 0xC0) {
                    /* Compression pointer — two bytes. */
                    if (pos + consumed + 2 > size) {
                        return 0;
                    }
                    return consumed + 2;
                }

                /* Regular label: length byte + characters. */
                std::size_t label_len = static_cast<std::size_t>(label);
                if (label_len > 63) {
                    return 0; /* Invalid label length. */
                }

                consumed += 1 + label_len;
            }
        }

        /**
         * @brief Skips @p count DNS query (question) entries starting at @p pos.
         *
         * Each question entry consists of: name + QTYPE(2) + QCLASS(2).
         *
         * @return New position after skipping, or 0 on parse error.
         */
        static std::size_t SkipDnsQuestionSection(const Byte* data, std::size_t size, std::size_t pos, uint16_t count) noexcept {
            for (uint16_t i = 0; i < count; ++i) {
                std::size_t name_len = SkipDnsName(data, size, pos);
                if (name_len == 0) {
                    return 0;
                }
                pos += name_len;

                /* QTYPE(2) + QCLASS(2) = 4 bytes */
                if (pos + 4 > size) {
                    return 0;
                }
                pos += 4;
            }
            return pos;
        }

        /**
         * @brief Skips @p count DNS resource records (answers, authority, or additional).
         *
         * Each RR consists of: name + type(2) + class(2) + ttl(4) + rdlength(2) + RDATA(rdlength).
         *
         * @return New position after skipping, or 0 on parse error.
         */
        static std::size_t SkipDnsRrSection(const Byte* data, std::size_t size, std::size_t pos, uint16_t count) noexcept {
            for (uint16_t i = 0; i < count; ++i) {
                std::size_t name_len = SkipDnsName(data, size, pos);
                if (name_len == 0) {
                    return 0;
                }
                pos += name_len;

                /* type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes */
                if (pos + 10 > size) {
                    return 0;
                }

                uint16_t rdlength = (static_cast<uint16_t>(data[pos + 8]) << 8) |
                                     static_cast<uint16_t>(data[pos + 9]);
                pos += 10 + rdlength;
            }
            return pos;
        }

        /* ========================================================================
         * Original helper functions (unchanged)
         * ======================================================================== */

        static ppp::string NormalizeProviderName(const ppp::string& name) noexcept {
            return ToLower(ATrim(name));
        }

        static boost::asio::ip::address ParseAddressOnly(const ppp::string& address_text, boost::system::error_code& ec) noexcept {
            ppp::string text = ATrim(address_text);
            std::size_t colon = text.find(':');
            if (colon != ppp::string::npos && text.find(':', colon + 1) == ppp::string::npos) {
                text = text.substr(0, colon);
            }

            return StringToAddress(text, ec);
        }

        /**
         * @brief Returns true when @p address_text is an IP literal with optional port.
         */
        static bool IsAddressLiteral(const ppp::string& address_text) noexcept {
            boost::system::error_code ec;
            boost::asio::ip::address ip = ParseAddressOnly(address_text, ec);
            return !ec && !ip.is_unspecified();
        }

        /**
         * @brief Appends built-in provider entries when text is a provider short-name.
         */
        static bool AppendProviderEntries(ppp::vector<ServerEntry>& entries, const ppp::string& provider_name) noexcept {
            const ppp::vector<ServerEntry>* provider = DnsProviderCatalog::GetProvider(provider_name);
            if (NULLPTR == provider) {
                return false;
            }

            entries.insert(entries.end(), provider->begin(), provider->end());
            return true;
        }

        /**
         * @brief Expands structured entries that use provider shorthand addresses.
         *
         * Object/array dns.servers entries may use provider shorthand in the
         * address field. Without this expansion, ResolveAsyncWithEntries() treats
         * "cloudflare" or "doh.pub" as UDP address literals, exhausts immediately,
         * and unmatched domains can fail while system DNS has already been pointed
         * at the tunnel.
         */
        static ppp::vector<ServerEntry> ExpandResolverEntries(const ppp::vector<ServerEntry>& explicit_entries) noexcept {
            ppp::vector<ServerEntry> expanded;
            expanded.reserve(explicit_entries.size());

            for (const ServerEntry& entry : explicit_entries) {
                ppp::string provider_name = ATrim(entry.address);
                if (!provider_name.empty() && entry.url.empty() && entry.hostname.empty() && entry.bootstrap_ips.empty() && !IsAddressLiteral(provider_name)) {
                    if (AppendProviderEntries(expanded, provider_name)) {
                        continue;
                    }
                }

                expanded.emplace_back(entry);
            }

            return expanded;
        }

        static bool ResolveEntryBootstrapAddress(
            const ServerEntry& entry,
            boost::asio::ip::address& ip) noexcept {

            boost::system::error_code ec;
            ip = ParseAddressOnly(entry.address, ec);
            if (!ec && !ip.is_unspecified()) {
                return true;
            }

            for (const boost::asio::ip::address& bootstrap : entry.bootstrap_ips) {
                if (!bootstrap.is_unspecified() && !bootstrap.is_loopback() && !bootstrap.is_multicast()) {
                    ip = bootstrap;
                    return true;
                }
            }

            ip = boost::asio::ip::address();
            return false;
        }

        static int ParsePort(const ppp::string& address_text, int default_port) noexcept {
            ppp::string text = ATrim(address_text);
            std::size_t colon = text.find(':');
            if (colon == ppp::string::npos || text.find(':', colon + 1) != ppp::string::npos) {
                return default_port;
            }

            ppp::string port_text = ATrim(text.substr(colon + 1));
            if (port_text.empty()) {
                return default_port;
            }

            int port = atoi(port_text.data());
            return port > 0 && port <= UINT16_MAX ? port : default_port;
        }

        /* ========================================================================
         * CompletionState — atomic once-invocation guard
         * ======================================================================== */

        /**
         * @brief Per-query transient resource owner with single-shot completion.
         *
         * @details
         *  This struct centralises ownership of every async resource belonging
         *  to a single SendDoh/SendDot/SendUdp/SendTcp invocation: the deadline
         *  timer, the SSL stream (or raw socket), the SSL context, beast HTTP
         *  buffers, request/response payloads, and the user-supplied
         *  ResolveCallback.
         *
         *  All async lambdas in the chain capture **only** a single
         *  `std::shared_ptr<CompletionState>`; they never capture the timer,
         *  stream, socket, or buffers separately. Resource teardown happens
         *  exclusively inside `Complete()`, under a single CAS guard. This
         *  guarantees:
         *
         *    1. Sockets/timers are closed and cancelled exactly once, on the
         *       thread that wins the CAS.
         *    2. The internal shared_ptr<steady_timer>/shared_ptr<ssl::stream>
         *       objects are released exactly once, immediately after the user
         *       callback runs, on the same thread. No multi-level lambda
         *       destruction chain races to be the "last owner".
         *    3. Late-arriving completion lambdas (e.g. the timer's wait
         *       handler firing after a real response was already received)
         *       observe `completed=true`, take the early-return path, and
         *       merely release their reference to the (already drained)
         *       CompletionState. ~CompletionState then runs harmlessly with
         *       all transient slots already null.
         *
         *  This was added to fix a SIGSEGV observed on Android arm64 inside
         *  ~shared_ptr<steady_timer> at the tail of a DoH read completion.
         *  The crash signature was a virtual call through a freed/poisoned
         *  shared_ptr control block, caused by the steady_timer being
         *  destroyed across multiple racing lambda destruction frames in the
         *  multi-level DoH async chain.
         */
        struct CompletionState final {
            std::atomic<bool>                                                       completed{ false };
            DnsResolver::ResolveCallback                                            callback;

            // Transient resources owned by this query. Populated by SendDoh /
            // SendDot / SendUdp / SendTcp before any async op is started.
            std::shared_ptr<boost::asio::steady_timer>                              timer;
            std::shared_ptr<boost::asio::ssl::context>                              ssl_ctx;
            std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket> > tls_stream;
            std::shared_ptr<boost::asio::ip::tcp::socket>                           tcp_socket;
            std::shared_ptr<boost::asio::ip::udp::socket>                           udp_socket;

            // Generic byte/blob slots. Concrete identity (request/response/
            // length-prefix/HTTP request/HTTP response/flat_buffer/source EP)
            // is local to each Send* implementation. Storing them as
            // type-erased shared_ptr<void> keeps CompletionState protocol-
            // agnostic without splitting it into per-protocol subclasses.
            std::shared_ptr<void>                                                   slot0;
            std::shared_ptr<void>                                                   slot1;
            std::shared_ptr<void>                                                   slot2;
            std::shared_ptr<void>                                                   slot3;

            explicit CompletionState(const DnsResolver::ResolveCallback& cb) noexcept : callback(cb) {}

            /** @brief Returns true if Complete() has already fired. */
            bool                                                                    IsCompleted() const noexcept {
                return completed.load(std::memory_order_acquire);
            }

            /**
             * @brief Atomically signals "this query is done", closes the
             *        underlying I/O endpoints (so in-flight async ops
             *        abort), cancels the timer, then fires the user
             *        callback.
             *
             * @details Idempotent (CAS-guarded). Subsequent calls are
             *          no-ops.
             *
             *          IMPORTANT — what this method DOES NOT do:
             *          it does NOT reset() any of the internal shared_ptr
             *          slots. boost::asio's ssl/socket async ops do NOT
             *          hold a shared_ptr to the underlying stream/socket;
             *          they assume the user keeps it alive for the
             *          duration of the op. Resetting the stream here
             *          (while a handshake_op was in flight) caused the
             *          K70 fault-addr=0x68 null-deref crash inside
             *          ssl::detail::io_op completion: the SSL stream was
             *          destroyed before its in-flight op was delivered.
             *
             *          Lifetime model:
             *          - Every async lambda captures only [state].
             *          - state owns timer/streams/sockets/buffers.
             *          - close()+cancel() here causes every in-flight op
             *            to complete with operation_aborted on its own.
             *          - As each completion lambda runs and is destroyed,
             *            its [state] capture is released. When the LAST
             *            outstanding lambda is destroyed, ref-count on
             *            CompletionState drops to zero and
             *            ~CompletionState destroys timer/stream/socket
             *            members in declaration-reverse order on a stack
             *            frame that has no in-flight op against any of
             *            them. This is the standard asio idiom and is
             *            UAF-free by construction.
             *
             *          The user callback is moved out and invoked LAST,
             *          after close+cancel, so that re-entrant resolve
             *          attempts launched from inside the callback do not
             *          observe stale I/O state.
             */
            void                                                                    Complete(ppp::vector<Byte> response) noexcept {
                bool expected = false;
                if (!completed.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                    return;
                }

                boost::system::error_code ignored;
                if (NULLPTR != tls_stream) {
                    tls_stream->lowest_layer().close(ignored);
                }
                if (NULLPTR != tcp_socket) {
                    tcp_socket->close(ignored);
                }
                if (NULLPTR != udp_socket) {
                    udp_socket->close(ignored);
                }
                if (NULLPTR != timer) {
                    ignored = boost::system::error_code();
                    try {
                        timer->cancel();
                    }
                    catch (const boost::system::system_error& e) {
                        ignored = e.code();
                    }
                }

                DnsResolver::ResolveCallback cb = std::move(callback);
                callback = NULLPTR;

                if (NULLPTR != cb) {
                    cb(std::move(response));
                }
            }
        };

        /**
         * @brief STUN-flavour analogue of CompletionState.
         *
         * @details Same lifetime policy as CompletionState (centralised
         *          ownership, single-shot CAS-guarded teardown, lambdas
         *          capture only `[state]`). The callback signature is
         *          `void(boost::asio::ip::address)` instead of
         *          `void(ppp::vector<Byte>)`.
         *
         *          Added because TryStunCandidate exhibited the same
         *          ~shared_ptr<steady_timer> SIGSEGV signature as SendDoh
         *          on Android arm64 once the DoH/DoT chains were
         *          centralised: the multi-level [socket, timer, ...] lambda
         *          captures left the steady_timer to be torn down across
         *          racing destruction frames.
         */
        struct StunCompletionState final {
            std::atomic<bool>                                                       completed{ false };
            DnsResolver::ExitIpCallback                                             callback;

            std::shared_ptr<boost::asio::steady_timer>                              timer;
            std::shared_ptr<boost::asio::ip::udp::socket>                           udp_socket;
            std::shared_ptr<void>                                                   slot0;  // request packet
            std::shared_ptr<void>                                                   slot1;  // recv buffer
            std::shared_ptr<void>                                                   slot2;  // recv endpoint

            explicit StunCompletionState(const DnsResolver::ExitIpCallback& cb) noexcept : callback(cb) {}

            bool                                                                    IsCompleted() const noexcept {
                return completed.load(std::memory_order_acquire);
            }

            // See CompletionState::Complete() for the full lifetime
            // rationale. We close()+cancel() to signal in-flight ops, then
            // fire the user callback. We do NOT reset the internal
            // shared_ptr slots — natural ref-counting on [state] captures
            // tears them down once the last in-flight op finishes.
            void                                                                    Complete(boost::asio::ip::address addr) noexcept {
                bool expected = false;
                if (!completed.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                    return;
                }

                boost::system::error_code ignored;
                if (NULLPTR != udp_socket) {
                    udp_socket->close(ignored);
                }
                if (NULLPTR != timer) {
                    ignored = boost::system::error_code();
                    try {
                        timer->cancel();
                    }
                    catch (const boost::system::system_error& e) {
                        ignored = e.code();
                    }
                }

                DnsResolver::ExitIpCallback cb = std::move(callback);
                callback = NULLPTR;

                if (NULLPTR != cb) {
                    cb(addr);
                }
            }
        };

        static bool IsSameUdpEndpoint(const udp::endpoint& lhs, const udp::endpoint& rhs) noexcept {
            return lhs.address() == rhs.address() && lhs.port() == rhs.port();
        }

        static void StartDnsUdpReceive(
            const std::shared_ptr<CompletionState>& state,
            const std::shared_ptr<ppp::vector<Byte> >& packet,
            const udp::endpoint& remote) noexcept {

            if (NULLPTR == state || NULLPTR == packet || state->IsCompleted()) {
                return;
            }

            auto socket_local = state->udp_socket;
            auto buffer_local = std::static_pointer_cast<ppp::vector<Byte> >(state->slot0);
            auto source_local = std::static_pointer_cast<udp::endpoint>(state->slot1);
            if (NULLPTR == socket_local || NULLPTR == buffer_local || NULLPTR == source_local) {
                return;
            }

            socket_local->async_receive_from(boost::asio::buffer(buffer_local->data(), buffer_local->size()), *source_local,
                [state, packet, remote](const boost::system::error_code& recv_ec, std::size_t size) noexcept {
                    if (state->IsCompleted()) {
                        return;
                    }
                    if (recv_ec || size < 1) {
                        CountDnsTransport(Protocol::UDP, DnsTransportStage::Recv,
                            recv_ec ? DnsTransportReason::Failed : DnsTransportReason::Empty);
                        state->Complete(ppp::vector<Byte>());
                        return;
                    }

                    auto buffer_r = std::static_pointer_cast<ppp::vector<Byte> >(state->slot0);
                    auto source_r = std::static_pointer_cast<udp::endpoint>(state->slot1);
                    if (NULLPTR == buffer_r || NULLPTR == source_r) {
                        state->Complete(ppp::vector<Byte>());
                        return;
                    }

                    if (!IsSameUdpEndpoint(*source_r, remote) ||
                        !ppp::dns::detail::IsDnsResponseForQuery(packet->data(), packet->size(), buffer_r->data(), size)) {
                        CountDnsTransport(Protocol::UDP, DnsTransportStage::Recv, DnsTransportReason::Invalid);
                        StartDnsUdpReceive(state, packet, remote);
                        return;
                    }

                    try {
                        buffer_r->resize(size);
                        CountDnsTransport(Protocol::UDP, DnsTransportStage::Success);
                        state->Complete(std::move(*buffer_r));
                    }
                    catch (const std::exception&) {
                        CountDnsTransport(Protocol::UDP, DnsTransportStage::Parse, DnsTransportReason::Failed);
                        state->Complete(ppp::vector<Byte>());
                    }
                });
        }

        /* ========================================================================
         * DnsResolver — constructor and property setters
         * ======================================================================== */

        DnsResolver::DnsResolver(boost::asio::io_context& context) noexcept
            : context_(context) {
        }

        DnsResolver::~DnsResolver() noexcept {
            /* Release any cached SSL_SESSION references that survived to shutdown. */
            std::lock_guard<std::mutex> lk(tls_session_mutex_);
            for (auto& kv : tls_session_cache_) {
                if (kv.second.session != NULLPTR) {
                    SSL_SESSION_free(reinterpret_cast<SSL_SESSION*>(kv.second.session));
                }
            }
            tls_session_cache_.clear();
            tls_session_lru_.clear();
        }

        void DnsResolver::UpdateConfig(const ppp::function<void(Config&)>& mutate) noexcept {
            std::lock_guard<std::mutex> lk(config_mutex_);
            std::shared_ptr<const Config> current = std::atomic_load(&config_);
            auto next = make_shared_object<Config>(*current);
            if (NULLPTR == next) {
                return;
            }

            if (mutate) {
                mutate(*next);
            }
            std::atomic_store(&config_, std::shared_ptr<const Config>(std::move(next)));
        }

        void DnsResolver::SetTlsVerifyPeer(bool verify_peer) noexcept {
            bool clear_context = false;
            if (GetConfig()->tls_verify_peer != verify_peer) {
                UpdateConfig([verify_peer](Config& config) noexcept { config.tls_verify_peer = verify_peer; });
                clear_context = true;
            }

            if (clear_context) {
                std::lock_guard<std::mutex> lk(tls_context_mutex_);
                tls_client_ssl_ctx_.reset();
            }
        }

        /* ========================================================================
         * TLS session cache — used by SendDoh / SendDot to enable session
         * resumption (TLS 1.2 session ID or TLS 1.3 ticket) on subsequent queries
         * to the same upstream. Cuts the TLS handshake from a full 2-RTT to
         * roughly 1-RTT (resume) or 0-RTT depending on the peer.
         * ======================================================================== */

        ssl_session_st* DnsResolver::AcquireTlsSession(const ppp::string& host_key) noexcept {
            if (host_key.empty()) {
                return NULLPTR;
            }

            std::lock_guard<std::mutex> lk(tls_session_mutex_);
            auto it = tls_session_cache_.find(host_key);
            if (it == tls_session_cache_.end() || it->second.session == NULLPTR) {
                return NULLPTR;
            }

            SSL_SESSION* session = reinterpret_cast<SSL_SESSION*>(it->second.session);
            /* Up-ref so the cache keeps its reference; the caller now owns one
             * additional reference and is responsible for SSL_SESSION_free. */
            if (SSL_SESSION_up_ref(session) != 1) {
                /* Failed to up-ref — drop the cache entry to avoid double-free. */
                SSL_SESSION_free(session);
                tls_session_lru_.erase(it->second.lru);
                tls_session_cache_.erase(it);
                return NULLPTR;
            }
            tls_session_lru_.splice(tls_session_lru_.begin(), tls_session_lru_, it->second.lru);
            return reinterpret_cast<ssl_session_st*>(session);
        }

        void DnsResolver::StoreTlsSession(const ppp::string& host_key, ssl_session_st* session) noexcept {
            if (host_key.empty()) {
                if (session != NULLPTR) {
                    SSL_SESSION_free(reinterpret_cast<SSL_SESSION*>(session));
                }
                return;
            }
            if (session == NULLPTR) {
                return;
            }

            std::lock_guard<std::mutex> lk(tls_session_mutex_);
            auto it = tls_session_cache_.find(host_key);
            if (it != tls_session_cache_.end()) {
                if (it->second.session != NULLPTR) {
                    SSL_SESSION_free(reinterpret_cast<SSL_SESSION*>(it->second.session));
                }
                it->second.session = session;
                tls_session_lru_.splice(tls_session_lru_.begin(), tls_session_lru_, it->second.lru);
                return;
            }
            tls_session_lru_.push_front(host_key);
            TlsSessionCacheEntry entry;
            entry.session = session;
            entry.lru = tls_session_lru_.begin();
            tls_session_cache_.emplace(host_key, entry);
            while (tls_session_cache_.size() > PPP_DNS_TLS_SESSION_CACHE_LIMIT && !tls_session_lru_.empty()) {
                const ppp::string evict_key = tls_session_lru_.back();
                auto evict = tls_session_cache_.find(evict_key);
                if (evict != tls_session_cache_.end()) {
                    if (evict->second.session != NULLPTR) {
                        SSL_SESSION_free(reinterpret_cast<SSL_SESSION*>(evict->second.session));
                    }
                    tls_session_cache_.erase(evict);
                }
                tls_session_lru_.pop_back();
            }
        }

        void DnsResolver::SetProtectSocketCallback(const ProtectSocketCallback& cb) noexcept {
            UpdateConfig([&cb](Config& config) noexcept { config.protect_socket = cb; });
        }

        void DnsResolver::SetUdpFlowRegistry(
            const std::shared_ptr<DnsUdpFlowRegistry>& registry) noexcept {

            UpdateConfig([&registry](Config& config) noexcept { config.udp_flow_registry = registry; });
        }

        void DnsResolver::SetExitIP(const boost::asio::ip::address& ip) noexcept {
            UpdateConfig([&ip](Config& config) noexcept { config.exit_ip = ip; });
            ClearStunEcsCache();
        }

        void DnsResolver::SetEcsConfig(bool enabled, const ppp::string& override_ip) noexcept {
            UpdateConfig([enabled, &override_ip](Config& config) noexcept {
                config.ecs_enabled = enabled;
                config.ecs_override_ip = override_ip;
            });
            ClearStunEcsCache();
        }

        boost::asio::ip::address DnsResolver::GetEcsIp() const noexcept {
            std::shared_ptr<const Config> config = GetConfig();

            // Priority 1: manual override_ip from configuration.
            if (!config->ecs_override_ip.empty()) {
                boost::system::error_code ec;
                boost::asio::ip::address addr = StringToAddress(config->ecs_override_ip.data(), ec);
                if (!ec && addr.is_v4() && !addr.is_unspecified()) {
                    return addr;
                }
            }

            // Priority 2: exit_ip from server (ClientExitIP / SetExitIP).
            if (config->exit_ip.is_v4() && !config->exit_ip.is_unspecified()) {
                return config->exit_ip;
            }

            return boost::asio::ip::address();
        }

        void DnsResolver::SetDefaultProviders(const ppp::string& domestic, const ppp::string& foreign) noexcept {
            UpdateConfig([&domestic, &foreign](Config& config) noexcept {
                config.default_domestic = domestic;
                config.default_foreign  = foreign;
            });
        }

        void DnsResolver::SetStunCandidates(ppp::vector<StunCandidate> candidates) noexcept {
            UpdateConfig([&candidates](Config& config) noexcept { config.stun_candidates = std::move(candidates); });
            stun_rotation_.store(0, std::memory_order_relaxed);
            ClearStunEcsCache();
        }

        void DnsResolver::SetStunHostnameCandidates(ppp::vector<StunHostnameCandidate> candidates) noexcept {
            UpdateConfig([&candidates](Config& config) noexcept { config.stun_hostname_candidates = std::move(candidates); });
            stun_rotation_.store(0, std::memory_order_relaxed);
            ClearStunEcsCache();
        }

        std::shared_ptr<boost::asio::ssl::context> DnsResolver::AcquireClientSslContext(bool verify_peer) noexcept {
            std::lock_guard<std::mutex> lk(tls_context_mutex_);
            if (NULLPTR != tls_client_ssl_ctx_ && tls_client_ssl_ctx_verify_peer_ == verify_peer) {
                return tls_client_ssl_ctx_;
            }

            std::shared_ptr<boost::asio::ssl::context> ssl_ctx = ppp::ssl::SSL::CreateClientSslContext(
                ppp::ssl::SSL::SSL_METHOD::tlsv12, verify_peer, std::string());
            if (NULLPTR != ssl_ctx) {
                tls_client_ssl_ctx_ = ssl_ctx;
                tls_client_ssl_ctx_verify_peer_ = verify_peer;
            }
            return ssl_ctx;
        }

        void DnsResolver::ClearStunEcsCache() noexcept {
            std::lock_guard<std::mutex> lk(stun_ecs_mutex_);
            stun_ecs_ip_ = boost::asio::ip::address();
            stun_ecs_expires_at_ = std::chrono::steady_clock::time_point();
            stun_ecs_negative_expires_at_ = std::chrono::steady_clock::time_point();
        }

        void DnsResolver::GetOrDetectEcsIpViaStun(const ExitIpCallback& callback) noexcept {
            if (NULLPTR == callback) {
                return;
            }

            const auto now = std::chrono::steady_clock::now();
            {
                std::lock_guard<std::mutex> lk(stun_ecs_mutex_);
                if (stun_ecs_ip_.is_v4() && !stun_ecs_ip_.is_unspecified() && now < stun_ecs_expires_at_) {
                    boost::asio::ip::address cached_ip = stun_ecs_ip_;
                    boost::asio::post(context_, [callback, cached_ip]() noexcept { callback(cached_ip); });
                    return;
                }
                if (now < stun_ecs_negative_expires_at_) {
                    boost::asio::post(context_, [callback]() noexcept { callback(boost::asio::ip::address()); });
                    return;
                }
                try {
                    stun_ecs_pending_callbacks_.emplace_back(callback);
                }
                catch (const std::exception&) {
                    boost::asio::post(context_, [callback]() noexcept { callback(boost::asio::ip::address()); });
                    return;
                }
                if (stun_ecs_probe_inflight_) {
                    return;
                }
                stun_ecs_probe_inflight_ = true;
            }

            std::weak_ptr<DnsResolver> weak_self = weak_from_this();
            DetectExitIPViaStun([weak_self](const boost::asio::ip::address& stun_ip) noexcept {
                std::shared_ptr<DnsResolver> self = weak_self.lock();
                if (NULLPTR == self) {
                    return;
                }

                ppp::vector<ExitIpCallback> callbacks;
                {
                    std::lock_guard<std::mutex> lk(self->stun_ecs_mutex_);
                    self->stun_ecs_probe_inflight_ = false;
                    callbacks.swap(self->stun_ecs_pending_callbacks_);
                    const auto complete_at = std::chrono::steady_clock::now();
                    if (stun_ip.is_v4() && !stun_ip.is_unspecified()) {
                        self->stun_ecs_ip_ = stun_ip;
                        self->stun_ecs_expires_at_ = complete_at + std::chrono::seconds(PPP_DNS_RESOLVER_STUN_CACHE_SECONDS);
                        self->stun_ecs_negative_expires_at_ = std::chrono::steady_clock::time_point();
                    }
                    else {
                        self->stun_ecs_ip_ = boost::asio::ip::address();
                        self->stun_ecs_expires_at_ = std::chrono::steady_clock::time_point();
                        self->stun_ecs_negative_expires_at_ = complete_at + std::chrono::seconds(PPP_DNS_RESOLVER_STUN_NEGATIVE_CACHE_SECONDS);
                    }
                }

                for (const ExitIpCallback& cb : callbacks) {
                    if (NULLPTR != cb) {
                        cb(stun_ip);
                    }
                }
            });
        }

        /* ========================================================================
         * ResolveAsyncWithFallback — provider fallback chain
         * ======================================================================== */

        void DnsResolver::ResolveAsyncWithFallback(
            const ppp::string& provider_name,
            const ppp::string& fallback1,
            const ppp::string& fallback2,
            const Byte* packet,
            int length,
            const ResolveCallback& callback) noexcept {

            if (NULLPTR == callback) {
                return;
            }

            if (NULLPTR == packet || length <= 0) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            // Copy packet data once for the entire fallback chain.
            auto packet_copy = make_shared_object<ppp::vector<Byte> >();
            if (NULLPTR == packet_copy) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }
            try {
                packet_copy->assign(packet, packet + length);
            }
            catch (const std::exception&) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            // Build ordered list of non-empty, registered provider names.
            ppp::vector<ppp::string> candidates;
            auto add_candidate = [&candidates](const ppp::string& name) noexcept {
                if (name.empty() || !DnsResolver::HasProvider(name)) {
                    return;
                }

                ppp::string normalized = NormalizeProviderName(name);
                for (const ppp::string& existing : candidates) {
                    if (NormalizeProviderName(existing) == normalized) {
                        return;
                    }
                }

                candidates.emplace_back(name);
            };

            add_candidate(provider_name);
            add_candidate(fallback1);
            add_candidate(fallback2);

            if (candidates.empty()) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            // Build the fallback chain from last to first.
            //
            // Chain structure (bottom-up wrapping):
            //   layer[i] = try candidates[i], on success → callback, on fail → layer[i+1]
            //
            // We use shared_ptr<ResolveCallback> to keep each layer alive through
            // async hand-offs without dangling references.
            auto resolver_weak = weak_from_this();

            // Terminal: invoke the caller's callback.
            std::shared_ptr<ResolveCallback> chain = make_shared_object<ResolveCallback>(
                [callback](ppp::vector<Byte> response) noexcept {
                    callback(std::move(response));
                });
            if (NULLPTR == chain) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            for (int i = static_cast<int>(candidates.size()) - 1; i >= 0; --i) {
                ppp::string name = candidates[static_cast<std::size_t>(i)];
                std::shared_ptr<ResolveCallback> next = std::move(chain);
                chain = make_shared_object<ResolveCallback>();
                if (NULLPTR == chain) {
                    // Fallback: invoke callback with empty on allocation failure.
                    boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                    return;
                }

                *chain = [resolver_weak, name, packet_copy, next](ppp::vector<Byte> response) noexcept {
                    if (!response.empty()) {
                        (*next)(std::move(response));
                        return;
                    }

                    // Current provider failed; try via ResolveAsync which itself
                    // falls through all protocols (DoH→DoT→TCP→UDP) for this provider.
                    std::shared_ptr<DnsResolver> resolver = resolver_weak.lock();
                    if (NULLPTR == resolver) {
                        (*next)(ppp::vector<Byte>());
                        return;
                    }

                    // Preserve the domestic semantic across the fallback chain so
                    // ECS injection is applied for the domestic tier (per
                    // docs/DNS_MODULE_DESIGN.md).  The tier is classified as
                    // domestic when its provider short-name matches the value
                    // configured via SetDefaultProviders().  When SetDefaultProviders
                    // has not been called the default is empty and the comparison
                    // returns false, preserving prior behaviour.
                    bool tier_domestic = false;
                    std::shared_ptr<const Config> config = resolver->GetConfig();
                    if (!config->default_domestic.empty()) {
                        tier_domestic = NormalizeProviderName(name) ==
                                        NormalizeProviderName(config->default_domestic);
                    }

                    resolver->ResolveAsync(name, tier_domestic,
                        packet_copy->data(), static_cast<int>(packet_copy->size()),
                        [next](ppp::vector<Byte> inner_response) noexcept {
                            if (!inner_response.empty()) {
                                (*next)(std::move(inner_response));
                            }
                            else {
                                // All protocols for this provider failed.
                                (*next)(ppp::vector<Byte>());
                            }
                        });
                };
            }

            // Kick off: try the first candidate (chain[0]).
            (*chain)(ppp::vector<Byte>());
        }

        /* ========================================================================
         * Provider lookup
         * ======================================================================== */

        bool DnsResolver::HasProvider(const ppp::string& name) noexcept {
            return DnsProviderCatalog::HasProvider(name);
        }

        const ppp::vector<ServerEntry>* DnsResolver::GetProvider(const ppp::string& name) noexcept {
            return DnsProviderCatalog::GetProvider(name);
        }

        /* ========================================================================
         * AAAA short-circuit helpers
         *
         * Walk the DNS query header + question section to identify AAAA queries
         * (QTYPE == 28) and synthesize an empty NOERROR response that mirrors
         * the original question. This lets callers avoid an upstream round-trip
         * when the local data plane has no IPv6 connectivity.
         * ======================================================================== */

        /**
         * @brief Parses the question section to locate QTYPE/QCLASS offsets.
         * @return Offset just past QTYPE+QCLASS (i.e. end of question section), or 0 on failure.
         */
        static int LocateQuestionEnd(const Byte* packet, int length) noexcept {
            if (NULLPTR == packet || length < 12) {
                return 0;
            }
            int idx = 12;
            while (idx < length) {
                Byte label_len = packet[idx];
                if (label_len == 0) {
                    idx += 1;
                    if (idx + 4 > length) {
                        return 0;
                    }
                    return idx + 4; // QTYPE(2) + QCLASS(2)
                }
                if ((label_len & 0xC0) != 0) {
                    // Compression pointer in question section is unusual; not supported here.
                    return 0;
                }
                idx += 1 + label_len;
                if (idx > length) {
                    return 0;
                }
            }
            return 0;
        }

        bool DnsResolver::IsAaaaQuery(const Byte* packet, int length) noexcept {
            int qend = LocateQuestionEnd(packet, length);
            if (qend == 0) {
                return false;
            }
            // QDCOUNT must equal 1 to safely interpret a single question.
            int qdcount = (static_cast<int>(packet[4]) << 8) | static_cast<int>(packet[5]);
            if (qdcount != 1) {
                return false;
            }
            // QR bit must be 0 (it is a query, not a response).
            if ((packet[2] & 0x80) != 0) {
                return false;
            }
            int qtype_off = qend - 4;
            int qtype = (static_cast<int>(packet[qtype_off]) << 8) | static_cast<int>(packet[qtype_off + 1]);
            return qtype == 28; // AAAA
        }

        ppp::vector<Byte> DnsResolver::BuildAaaaBlockedResponse(const Byte* packet, int length) noexcept {
            int qend = LocateQuestionEnd(packet, length);
            if (qend == 0) {
                return ppp::vector<Byte>();
            }

            ppp::vector<Byte> response(static_cast<std::size_t>(qend));
            std::memcpy(response.data(), packet, static_cast<std::size_t>(qend));

            // Header rewrite: QR=1, AA=0, TC=0, RA=1, Z=0, RCODE=0 (NOERROR).
            // Preserve the original ID and the RD bit (bit 0 of byte 2).
            Byte rd = static_cast<Byte>(response[2] & 0x01);
            response[2] = static_cast<Byte>(0x80 | rd); // QR=1 + RD copied
            response[3] = 0x80;                          // RA=1, Z=0, RCODE=NOERROR

            // Counts: QDCOUNT=1 (echoed), ANCOUNT=NSCOUNT=ARCOUNT=0.
            response[4] = 0; response[5] = 1;
            response[6] = 0; response[7] = 0;
            response[8] = 0; response[9] = 0;
            response[10] = 0; response[11] = 0;

            return response;
        }

        /* ========================================================================
         * ResolveAsync — single-provider, protocol-cascading resolution
         *
         * When ECS is enabled and the query is domestic, the ECS OPT RR is
         * injected/merged.  If no exit IP is available yet, STUN detection
         * is attempted first (async) to discover the client's public IP.
         * ======================================================================== */

        void DnsResolver::ResolveAsync(const ppp::string& provider_name, bool domestic, const Byte* packet, int length, const ResolveCallback& callback) noexcept {
            if (NULLPTR == callback) {
                return;
            }

            if (NULLPTR == packet || length <= 0 || length > PPP_DNS_RESOLVER_TCP_MAX_SIZE) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            const ppp::vector<ServerEntry>* provider = GetProvider(provider_name);
            if (NULLPTR == provider || provider->empty()) {
                ppp::telemetry::Log(Level::kDebug, "dns", "provider not found: %s", provider_name.data());
                ppp::telemetry::Count("dns.resolve.provider_miss", 1);
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            ppp::telemetry::Log(Level::kDebug, "dns", "resolve start provider=%s domestic=%d", provider_name.data(), (int)domestic);
            ppp::telemetry::Count("dns.resolve.start", 1);

            std::shared_ptr<ppp::vector<Byte> > request = make_shared_object<ppp::vector<Byte> >();
            std::shared_ptr<ppp::vector<ServerEntry> > entries = make_shared_object<ppp::vector<ServerEntry> >();
            if (NULLPTR == request || NULLPTR == entries) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            try {
                request->assign(packet, packet + length);
                *entries = *provider;
            }
            catch (const std::exception&) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            // EDNS Client Subnet (ECS) injection for domestic queries.
            // When ECS is enabled and the query is domestic, append/merge
            // an OPT RR containing the ECS option so that authoritative servers
            // can return geo-optimised answers.
            if (GetConfig()->ecs_enabled && domestic) {
                boost::asio::ip::address ecs_ip = GetEcsIp();
                if (ecs_ip.is_v4() && !ecs_ip.is_unspecified()) {
                    InjectEcsOptRr(*request, ecs_ip);
                }
                else {
                    // No exit IP available yet — attempt STUN detection as a
                    // last-resort fallback before proceeding without ECS.
                    std::weak_ptr<DnsResolver> weak_self = weak_from_this();
                    GetOrDetectEcsIpViaStun(
                        [weak_self, request, entries, callback](const boost::asio::ip::address& stun_ip) noexcept {
                            if (stun_ip.is_v4() && !stun_ip.is_unspecified()) {
                                InjectEcsOptRr(*request, stun_ip);
                            }
                            std::shared_ptr<DnsResolver> self = weak_self.lock();
                            if (NULLPTR == self) {
                                callback(ppp::vector<Byte>());
                                return;
                            }
                            self->TryProtocols(entries, 0, request, callback, true);
                        });
                    return; /* TryProtocols is invoked inside the STUN callback. */
                }
            }

            TryProtocols(entries, 0, request, callback, domestic);
        }

        /* ========================================================================
         * ResolveAsyncWithEntries — resolve via explicit server entries (Phase A)
         * ======================================================================== */

        void DnsResolver::ResolveAsyncWithEntries(
            const ppp::vector<ServerEntry>& explicit_entries,
            bool domestic,
            const Byte* packet,
            int length,
            const ResolveCallback& callback) noexcept {

            if (NULLPTR == callback) {
                return;
            }

            if (NULLPTR == packet || length <= 0 || length > PPP_DNS_RESOLVER_TCP_MAX_SIZE) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            if (explicit_entries.empty()) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            ppp::telemetry::Log(Level::kDebug, "dns", "resolve entries start count=%d domestic=%d",
                (int)explicit_entries.size(), (int)domestic);
            ppp::telemetry::Count("dns.resolve.start", 1);

            auto request = make_shared_object<ppp::vector<Byte> >();
            auto entries = make_shared_object<ppp::vector<ServerEntry> >();
            if (NULLPTR == request || NULLPTR == entries) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            try {
                request->assign(packet, packet + length);
                *entries = ExpandResolverEntries(explicit_entries);
            }
            catch (const std::exception&) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            if (entries->empty()) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            // ECS injection for domestic queries.
            if (GetConfig()->ecs_enabled && domestic) {
                boost::asio::ip::address ecs_ip = GetEcsIp();
                if (ecs_ip.is_v4() && !ecs_ip.is_unspecified()) {
                    InjectEcsOptRr(*request, ecs_ip);
                }
                else {
                    std::weak_ptr<DnsResolver> weak_self = weak_from_this();
                    GetOrDetectEcsIpViaStun(
                        [weak_self, request, entries, callback](const boost::asio::ip::address& stun_ip) noexcept {
                            if (stun_ip.is_v4() && !stun_ip.is_unspecified()) {
                                InjectEcsOptRr(*request, stun_ip);
                            }
                            std::shared_ptr<DnsResolver> self = weak_self.lock();
                            if (NULLPTR == self) {
                                callback(ppp::vector<Byte>());
                                return;
                            }
                            self->TryProtocols(entries, 0, request, callback, true);
                        });
                    return;
                }
            }

            TryProtocols(entries, 0, request, callback, domestic);
        }

        /* ========================================================================
         * Socket protection helper
         * ======================================================================== */

        bool DnsResolver::ProtectSocket(int native_handle) noexcept {
            std::shared_ptr<const Config> config = GetConfig();
            if (NULLPTR == config->protect_socket) {
                return true;
            }

            try {
                return config->protect_socket(native_handle);
            }
            catch (const std::exception&) {
                return false;
            }
        }

        /* ========================================================================
         * TryProtocols — cascading protocol fallback for a single provider
         * ======================================================================== */

        void DnsResolver::TryProtocols(std::shared_ptr<ppp::vector<ServerEntry> > entries, std::size_t index, std::shared_ptr<ppp::vector<Byte> > packet, const ResolveCallback& callback, bool domestic) noexcept {
            if (NULLPTR == entries || NULLPTR == packet || index >= entries->size()) {
                ppp::telemetry::Log(Level::kDebug, "dns", "resolve failed: all entries exhausted");
                ppp::telemetry::Count("dns.resolve.failure", 1);
                callback(ppp::vector<Byte>());
                return;
            }

            const ServerEntry& entry = (*entries)[index];
            static const char* kProtoNames[] = { "UDP", "TCP", "DoH", "DoT" };
            ppp::telemetry::Log(Level::kTrace, "dns", "try protocol=%s entry=%zu/%zu",
                kProtoNames[static_cast<int>(entry.protocol)], index, entries->size());

            std::weak_ptr<DnsResolver> weak_self = weak_from_this();
            ResolveCallback next = [weak_self, entries, index, packet, callback, domestic](ppp::vector<Byte> response) noexcept {
                if (!response.empty()) {
                    ppp::telemetry::Log(Level::kDebug, "dns", "resolve success entry=%zu bytes=%zu", index, response.size());
                    ppp::telemetry::Count("dns.resolve.success", 1);
                    callback(std::move(response));
                    return;
                }

                ppp::telemetry::Log(Level::kTrace, "dns", "protocol fallback from entry=%zu", index);
                ppp::telemetry::Count("dns.resolve.fallback", 1);

                std::shared_ptr<DnsResolver> self = weak_self.lock();
                if (NULLPTR == self) {
                    callback(ppp::vector<Byte>());
                    return;
                }

                self->TryProtocols(entries, index + 1, packet, callback, domestic);
            };

            switch (entry.protocol) {
            case Protocol::UDP:
                SendUdp(entry, packet, next);
                break;
            case Protocol::TCP:
                SendTcp(entry, packet, next);
                break;
            case Protocol::DoH:
                SendDoh(entry, packet, next);
                break;
            case Protocol::DoT:
                SendDot(entry, packet, next);
                break;
            default:
                next(ppp::vector<Byte>());
                break;
            }
        }

        /* ========================================================================
         * SendDoh — DNS-over-HTTPS via Boost.Beast + TLS
         * ======================================================================== */

        void DnsResolver::SendDoh(const ServerEntry& entry, std::shared_ptr<ppp::vector<Byte> > packet, const ResolveCallback& callback) noexcept {
            CountDnsTransport(Protocol::DoH, DnsTransportStage::Attempt);
            /* Parse the DoH URL to extract host and path. */
            ppp::string url = ATrim(entry.url);
            if (url.empty()) {
                CountDnsTransport(Protocol::DoH, DnsTransportStage::Bootstrap, DnsTransportReason::Empty);
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            ppp::string host;
            ppp::string path;
            {
                /* Strip https:// prefix. */
                const char* https_prefix = "https://";
                std::size_t scheme_pos = url.find(https_prefix);
                if (scheme_pos == ppp::string::npos) {
                    CountDnsTransport(Protocol::DoH, DnsTransportStage::Bootstrap, DnsTransportReason::Invalid);
                    boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                    return;
                }
                ppp::string remainder = url.substr(scheme_pos + strlen(https_prefix));

                /* Split host and path. */
                std::size_t slash_pos = remainder.find('/');
                if (slash_pos == ppp::string::npos) {
                    host = remainder;
                    path = "/";
                }
                else {
                    host = remainder.substr(0, slash_pos);
                    path = remainder.substr(slash_pos);
                }

                /* Strip port from host if present (e.g. "dns.example.com:443"). */
                std::size_t colon_pos = host.find(':');
                if (colon_pos != ppp::string::npos) {
                    host = host.substr(0, colon_pos);
                }

                if (host.empty()) {
                    CountDnsTransport(Protocol::DoH, DnsTransportStage::Bootstrap, DnsTransportReason::Empty);
                    boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                    return;
                }
            }

            boost::asio::ip::address ip;
            if (!ResolveEntryBootstrapAddress(entry, ip)) {
                CountDnsTransport(Protocol::DoH, DnsTransportStage::Bootstrap, DnsTransportReason::Invalid);
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            tcp::endpoint remote(ip, static_cast<unsigned short>(ParsePort(entry.address, 443)));

            // Allocate the per-query state up-front. Every async resource is
            // owned by `state` so that all lambdas in the chain only need to
            // capture `[state]`. Resource teardown happens exclusively in
            // CompletionState::Complete() under a single CAS guard.
            std::shared_ptr<CompletionState> state = make_shared_object<CompletionState>(callback);
            std::shared_ptr<tcp::socket> socket = make_shared_object<tcp::socket>(context_);
            std::shared_ptr<boost::asio::steady_timer> timer = make_shared_object<boost::asio::steady_timer>(context_);
            if (NULLPTR == state || NULLPTR == socket || NULLPTR == timer) {
                CountDnsTransport(Protocol::DoH, DnsTransportStage::Socket, DnsTransportReason::AllocFailed);
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }
            state->timer = timer;

            boost::system::error_code ec;
            socket->open(remote.protocol(), ec);
            if (ec) {
                CountDnsTransport(Protocol::DoH, DnsTransportStage::Socket, DnsTransportReason::OpenFailed);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            ppp::net::Socket::AdjustDefaultSocketOptional(socket->native_handle(), ip.is_v4());
            ppp::net::Socket::SetTypeOfService(socket->native_handle());
            ppp::net::Socket::SetSignalPipeline(socket->native_handle(), false);
            ppp::net::Socket::ReuseSocketAddress(socket->native_handle(), true);
            if (!ProtectSocket(socket->native_handle())) {
                CountDnsTransport(Protocol::DoH, DnsTransportStage::Socket, DnsTransportReason::ProtectFailed);
                ppp::net::Socket::Closesocket(socket);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            /* Create TLS 1.2+ client context with system/bundled CA verification enabled. */
            const bool verify_peer = GetConfig()->tls_verify_peer;
            std::shared_ptr<boost::asio::ssl::context> ssl_ctx = AcquireClientSslContext(verify_peer);
            if (NULLPTR == ssl_ctx) {
                CountDnsTransport(Protocol::DoH, DnsTransportStage::Tls, DnsTransportReason::AllocFailed);
                ppp::net::Socket::Closesocket(socket);
                state->Complete(ppp::vector<Byte>());
                return;
            }
            state->ssl_ctx = ssl_ctx;

            std::shared_ptr<boost::asio::ssl::stream<tcp::socket> > stream =
                make_shared_object<boost::asio::ssl::stream<tcp::socket> >(std::move(*socket), *ssl_ctx);
            if (NULLPTR == stream) {
                CountDnsTransport(Protocol::DoH, DnsTransportStage::Tls, DnsTransportReason::AllocFailed);
                state->Complete(ppp::vector<Byte>());
                return;
            }
            state->tls_stream = stream;

            /* SNI: use the URL host (or entry.hostname fallback) for TLS Server Name Indication. */
            ppp::string sni_name = !entry.hostname.empty() ? entry.hostname : host;
            if (!sni_name.empty()) {
                SSL_set_tlsext_host_name(stream->native_handle(), sni_name.data());
                if (verify_peer) {
                    stream->set_verify_callback(boost::asio::ssl::host_name_verification(stl::transform<std::string>(sni_name)));
                }
            }

            /* Cache key composed from the SNI name and remote port. Used to look
             * up a previously stored TLS session for resumption (1-RTT instead
             * of a full 2-RTT handshake) and to remember the new session after
             * the handshake completes. */
            ppp::string host_key;
            if (!sni_name.empty()) {
                host_key.append(sni_name).append(":").append(stl::to_string<ppp::string>(static_cast<int>(remote.port())));
            }

            /* Apply a previously cached SSL_SESSION before the handshake. The
             * cache returns an up-ref'd pointer; SSL_set_session up-refs again
             * internally, so we still need to free our own reference. */
            if (!host_key.empty()) {
                if (SSL_SESSION* cached = reinterpret_cast<SSL_SESSION*>(AcquireTlsSession(host_key))) {
                    SSL_set_session(stream->native_handle(), cached);
                    SSL_SESSION_free(cached);
                    ppp::telemetry::Count("dns.tls.session_reuse_attempt", 1);
                    CountDnsTransport(Protocol::DoH, DnsTransportStage::Tls, DnsTransportReason::CacheHit);
                    CountDnsTransport(Protocol::DoH, DnsTransportStage::Tls, DnsTransportReason::ReuseAttempt);
                }
                else {
                    CountDnsTransport(Protocol::DoH, DnsTransportStage::Tls, DnsTransportReason::CacheMiss);
                }
            }

            // ---------------------------------------------------------------
            // Async chain. Every lambda captures ONLY [state]. Late-arriving
            // completions check state->IsCompleted() and bail without
            // touching any transient resource (which Complete() has already
            // released).
            // ---------------------------------------------------------------

            timer->expires_after(std::chrono::milliseconds(PPP_DNS_RESOLVER_TLS_TIMEOUT_MS));
            timer->async_wait([state](const boost::system::error_code& ec_) noexcept {
                if (ec_ || state->IsCompleted()) {
                    return;
                }
                CountDnsTransport(Protocol::DoH, DnsTransportStage::Timeout);
                state->Complete(ppp::vector<Byte>());
            });

            std::weak_ptr<DnsResolver> weak_self = weak_from_this();
            stream->lowest_layer().async_connect(remote,
                [weak_self, state, packet, host, path, sni_name, host_key](const boost::system::error_code& connect_ec) noexcept {
                    if (state->IsCompleted()) {
                        return;
                    }
                    if (connect_ec) {
                        CountDnsTransport(Protocol::DoH, DnsTransportStage::Connect, DnsTransportReason::Failed);
                        state->Complete(ppp::vector<Byte>());
                        return;
                    }

                    auto stream_local = state->tls_stream;
                    if (NULLPTR == stream_local) {
                        return;
                    }
                    stream_local->async_handshake(boost::asio::ssl::stream_base::client,
                        [weak_self, state, packet, host, path, sni_name, host_key](const boost::system::error_code& handshake_ec) noexcept {
                            if (state->IsCompleted()) {
                                return;
                            }
                            if (handshake_ec) {
                                CountDnsTransport(Protocol::DoH, DnsTransportStage::Tls,
                                    handshake_ec == boost::asio::error::operation_aborted ? DnsTransportReason::Failed : DnsTransportReason::VerifyFailed);
                                state->Complete(ppp::vector<Byte>());
                                return;
                            }

                            auto stream_inner = state->tls_stream;
                            if (NULLPTR == stream_inner) {
                                return;
                            }

                            /* Persist the negotiated session for the next query.
                             * SSL_get1_session up-refs the session; the cache
                             * takes ownership of that reference. */
                            if (std::shared_ptr<DnsResolver> self = weak_self.lock(); self != NULLPTR && !host_key.empty()) {
                                if (SSL_SESSION* fresh = SSL_get1_session(stream_inner->native_handle())) {
                                    self->StoreTlsSession(host_key, reinterpret_cast<ssl_session_st*>(fresh));
                                    if (SSL_session_reused(stream_inner->native_handle())) {
                                        ppp::telemetry::Count("dns.tls.session_reused", 1);
                                        CountDnsTransport(Protocol::DoH, DnsTransportStage::Tls, DnsTransportReason::Reused);
                                    }
                                    else {
                                        CountDnsTransport(Protocol::DoH, DnsTransportStage::Tls, DnsTransportReason::NotReused);
                                    }
                                }
                            }

                            /* Build HTTP/1.1 POST request with DNS wire-format body. */
                            typedef boost::beast::http::request<boost::beast::http::string_body> http_request_t;
                            typedef boost::beast::http::response<boost::beast::http::string_body> http_response_t;
                            typedef boost::beast::http::response_parser<boost::beast::http::string_body> http_response_parser_t;
                            std::shared_ptr<http_request_t> http_req = make_shared_object<http_request_t>();
                            std::shared_ptr<boost::beast::flat_buffer> read_buf = make_shared_object<boost::beast::flat_buffer>();
                            std::shared_ptr<http_response_parser_t> http_parser = make_shared_object<http_response_parser_t>();
                            if (NULLPTR == http_req || NULLPTR == read_buf || NULLPTR == http_parser) {
                                CountDnsTransport(Protocol::DoH, DnsTransportStage::Http, DnsTransportReason::AllocFailed);
                                state->Complete(ppp::vector<Byte>());
                                return;
                            }
                            http_parser->body_limit(PPP_DNS_RESOLVER_TCP_MAX_SIZE);
                            // Park the HTTP request/response/parse buffer on
                            // the state so they outlive each individual
                            // lambda in the chain without being captured
                            // separately.
                            state->slot0 = http_req;
                            state->slot1 = read_buf;
                            state->slot2 = http_parser;

                            try {
                                http_req->method(boost::beast::http::verb::post);
                                http_req->target(path);
                                http_req->version(11);
                                http_req->set(boost::beast::http::field::host, host);
                                http_req->set(boost::beast::http::field::content_type, "application/dns-message");
                                http_req->set(boost::beast::http::field::accept, "application/dns-message");
                                http_req->body().assign(packet->begin(), packet->end());
                                http_req->prepare_payload();
                            }
                            catch (const std::exception&) {
                                CountDnsTransport(Protocol::DoH, DnsTransportStage::Http, DnsTransportReason::BuildFailed);
                                state->Complete(ppp::vector<Byte>());
                                return;
                            }

                            /* Send HTTP request. */
                            boost::beast::http::async_write(*stream_inner, *http_req,
                                [state](const boost::system::error_code& write_ec, std::size_t) noexcept {
                                    if (state->IsCompleted()) {
                                        return;
                                    }
                                    if (write_ec) {
                                        CountDnsTransport(Protocol::DoH, DnsTransportStage::Send, DnsTransportReason::Failed);
                                        state->Complete(ppp::vector<Byte>());
                                        return;
                                    }

                                    auto stream_w = state->tls_stream;
                                    auto read_buf_w = std::static_pointer_cast<boost::beast::flat_buffer>(state->slot1);
                                    auto http_parser_w = std::static_pointer_cast<boost::beast::http::response_parser<boost::beast::http::string_body> >(state->slot2);
                                    if (NULLPTR == stream_w || NULLPTR == read_buf_w || NULLPTR == http_parser_w) {
                                        return;
                                    }

                                    /* Read HTTP response. read_buf and http_res are kept
                                     * alive via state->slot1 / state->slot2 for the entire
                                     * duration of async_read; beast holds them only by
                                     * reference. */
                                    boost::beast::http::async_read(*stream_w, *read_buf_w, *http_parser_w,
                                        [state](const boost::system::error_code& read_ec, std::size_t) noexcept {
                                            if (state->IsCompleted()) {
                                                return;
                                            }
                                            if (read_ec) {
                                                CountDnsTransport(Protocol::DoH, DnsTransportStage::Recv, DnsTransportReason::Failed);
                                                state->Complete(ppp::vector<Byte>());
                                                return;
                                            }

                                            auto http_parser_r = std::static_pointer_cast<boost::beast::http::response_parser<boost::beast::http::string_body> >(state->slot2);
                                            if (NULLPTR == http_parser_r) {
                                                state->Complete(ppp::vector<Byte>());
                                                return;
                                            }
                                            const http_response_t& http_res_r = http_parser_r->get();

                                            if (http_res_r.result_int() != 200 || http_res_r.body().empty()) {
                                                CountDnsTransport(Protocol::DoH, DnsTransportStage::Http,
                                                    http_res_r.result_int() != 200 ? DnsTransportReason::BadStatus : DnsTransportReason::Empty);
                                                state->Complete(ppp::vector<Byte>());
                                                return;
                                            }

                                            const std::string& body = http_res_r.body();
                                            try {
                                                ppp::vector<Byte> response(body.begin(), body.end());
                                                CountDnsTransport(Protocol::DoH, DnsTransportStage::Success);
                                                state->Complete(std::move(response));
                                            }
                                            catch (const std::exception&) {
                                                CountDnsTransport(Protocol::DoH, DnsTransportStage::Parse, DnsTransportReason::Failed);
                                                state->Complete(ppp::vector<Byte>());
                                            }
                                        });
                                });
                        });
                });
        }

        /* ========================================================================
         * SendDot — DNS-over-TLS via Boost.Asio SSL stream
         * ======================================================================== */

        void DnsResolver::SendDot(const ServerEntry& entry, std::shared_ptr<ppp::vector<Byte> > packet, const ResolveCallback& callback) noexcept {
            CountDnsTransport(Protocol::DoT, DnsTransportStage::Attempt);
            boost::asio::ip::address ip;
            if (!ResolveEntryBootstrapAddress(entry, ip)) {
                CountDnsTransport(Protocol::DoT, DnsTransportStage::Bootstrap, DnsTransportReason::Invalid);
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            tcp::endpoint remote(ip, static_cast<unsigned short>(ParsePort(entry.address, 853)));

            // Allocate the per-query state up-front. Same lifecycle policy as
            // SendDoh: every transient resource is owned by `state`, every
            // lambda captures only `[state]`, and Complete() is the sole
            // teardown point.
            std::shared_ptr<CompletionState> state = make_shared_object<CompletionState>(callback);
            std::shared_ptr<tcp::socket> socket = make_shared_object<tcp::socket>(context_);
            std::shared_ptr<boost::asio::steady_timer> timer = make_shared_object<boost::asio::steady_timer>(context_);
            std::shared_ptr<ppp::vector<Byte> > request = make_shared_object<ppp::vector<Byte> >();
            std::shared_ptr<std::array<Byte, 2> > length_buffer = make_shared_object<std::array<Byte, 2> >();
            if (NULLPTR == state || NULLPTR == socket || NULLPTR == timer || NULLPTR == request || NULLPTR == length_buffer) {
                CountDnsTransport(Protocol::DoT, DnsTransportStage::Socket, DnsTransportReason::AllocFailed);
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }
            state->timer = timer;
            state->slot0 = request;
            state->slot1 = length_buffer;

            /* Build DNS-over-TCP request: 2-byte big-endian length prefix + raw DNS query. */
            try {
                request->resize(packet->size() + 2);
                (*request)[0] = static_cast<Byte>((packet->size() >> 8) & 0xff);
                (*request)[1] = static_cast<Byte>(packet->size() & 0xff);
                memcpy(request->data() + 2, packet->data(), packet->size());
            }
            catch (const std::exception&) {
                CountDnsTransport(Protocol::DoT, DnsTransportStage::Parse, DnsTransportReason::BuildFailed);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            boost::system::error_code ec;
            socket->open(remote.protocol(), ec);
            if (ec) {
                CountDnsTransport(Protocol::DoT, DnsTransportStage::Socket, DnsTransportReason::OpenFailed);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            ppp::net::Socket::AdjustDefaultSocketOptional(socket->native_handle(), ip.is_v4());
            ppp::net::Socket::SetTypeOfService(socket->native_handle());
            ppp::net::Socket::SetSignalPipeline(socket->native_handle(), false);
            ppp::net::Socket::ReuseSocketAddress(socket->native_handle(), true);
            if (!ProtectSocket(socket->native_handle())) {
                CountDnsTransport(Protocol::DoT, DnsTransportStage::Socket, DnsTransportReason::ProtectFailed);
                ppp::net::Socket::Closesocket(socket);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            /* Create a TLS 1.2+ client context with system/bundled CA verification enabled. */
            const bool verify_peer = GetConfig()->tls_verify_peer;
            std::shared_ptr<boost::asio::ssl::context> ssl_ctx = AcquireClientSslContext(verify_peer);
            if (NULLPTR == ssl_ctx) {
                CountDnsTransport(Protocol::DoT, DnsTransportStage::Tls, DnsTransportReason::AllocFailed);
                ppp::net::Socket::Closesocket(socket);
                state->Complete(ppp::vector<Byte>());
                return;
            }
            state->ssl_ctx = ssl_ctx;

            std::shared_ptr<boost::asio::ssl::stream<tcp::socket> > stream =
                make_shared_object<boost::asio::ssl::stream<tcp::socket> >(std::move(*socket), *ssl_ctx);
            if (NULLPTR == stream) {
                CountDnsTransport(Protocol::DoT, DnsTransportStage::Tls, DnsTransportReason::AllocFailed);
                state->Complete(ppp::vector<Byte>());
                return;
            }
            state->tls_stream = stream;

            /* SNI: use entry.hostname for TLS Server Name Indication. */
            if (!entry.hostname.empty()) {
                SSL_set_tlsext_host_name(stream->native_handle(), entry.hostname.data());
                if (verify_peer) {
                    stream->set_verify_callback(boost::asio::ssl::host_name_verification(stl::transform<std::string>(entry.hostname)));
                }
            }

            /* Cache key for the TLS session cache. See SendDoh for the policy. */
            ppp::string host_key;
            if (!entry.hostname.empty()) {
                host_key.append(entry.hostname).append(":").append(stl::to_string<ppp::string>(static_cast<int>(remote.port())));
            }
            if (!host_key.empty()) {
                if (SSL_SESSION* cached = reinterpret_cast<SSL_SESSION*>(AcquireTlsSession(host_key))) {
                    SSL_set_session(stream->native_handle(), cached);
                    SSL_SESSION_free(cached);
                    ppp::telemetry::Count("dns.tls.session_reuse_attempt", 1);
                    CountDnsTransport(Protocol::DoT, DnsTransportStage::Tls, DnsTransportReason::CacheHit);
                    CountDnsTransport(Protocol::DoT, DnsTransportStage::Tls, DnsTransportReason::ReuseAttempt);
                }
                else {
                    CountDnsTransport(Protocol::DoT, DnsTransportStage::Tls, DnsTransportReason::CacheMiss);
                }
            }

            timer->expires_after(std::chrono::milliseconds(PPP_DNS_RESOLVER_TLS_TIMEOUT_MS));
            timer->async_wait([state](const boost::system::error_code& ec_) noexcept {
                if (ec_ || state->IsCompleted()) {
                    return;
                }
                CountDnsTransport(Protocol::DoT, DnsTransportStage::Timeout);
                state->Complete(ppp::vector<Byte>());
            });

            std::weak_ptr<DnsResolver> weak_self = weak_from_this();
            stream->lowest_layer().async_connect(remote,
                [weak_self, state, hostname = entry.hostname, host_key](const boost::system::error_code& connect_ec) noexcept {
                    if (state->IsCompleted()) {
                        return;
                    }
                    if (connect_ec) {
                        CountDnsTransport(Protocol::DoT, DnsTransportStage::Connect, DnsTransportReason::Failed);
                        state->Complete(ppp::vector<Byte>());
                        return;
                    }

                    auto stream_local = state->tls_stream;
                    if (NULLPTR == stream_local) {
                        return;
                    }
                    /* Protect the connected socket before TLS handshake. */
                    stream_local->async_handshake(boost::asio::ssl::stream_base::client,
                        [weak_self, state, host_key](const boost::system::error_code& handshake_ec) noexcept {
                            if (state->IsCompleted()) {
                                return;
                            }
                            if (handshake_ec) {
                                CountDnsTransport(Protocol::DoT, DnsTransportStage::Tls,
                                    handshake_ec == boost::asio::error::operation_aborted ? DnsTransportReason::Failed : DnsTransportReason::VerifyFailed);
                                state->Complete(ppp::vector<Byte>());
                                return;
                            }

                            auto stream_inner = state->tls_stream;
                            if (NULLPTR == stream_inner) {
                                return;
                            }

                            /* Persist negotiated session for the next query. */
                            if (std::shared_ptr<DnsResolver> self = weak_self.lock(); self != NULLPTR && !host_key.empty()) {
                                if (SSL_SESSION* fresh = SSL_get1_session(stream_inner->native_handle())) {
                                    self->StoreTlsSession(host_key, reinterpret_cast<ssl_session_st*>(fresh));
                                    if (SSL_session_reused(stream_inner->native_handle())) {
                                        ppp::telemetry::Count("dns.tls.session_reused", 1);
                                        CountDnsTransport(Protocol::DoT, DnsTransportStage::Tls, DnsTransportReason::Reused);
                                    }
                                    else {
                                        CountDnsTransport(Protocol::DoT, DnsTransportStage::Tls, DnsTransportReason::NotReused);
                                    }
                                }
                            }

                            auto request_inner = std::static_pointer_cast<ppp::vector<Byte> >(state->slot0);
                            if (NULLPTR == request_inner) {
                                state->Complete(ppp::vector<Byte>());
                                return;
                            }

                            /* Send: 2-byte length prefix + DNS query. */
                            boost::asio::async_write(*stream_inner, boost::asio::buffer(request_inner->data(), request_inner->size()),
                                [state](const boost::system::error_code& write_ec, std::size_t) noexcept {
                                    if (state->IsCompleted()) {
                                        return;
                                    }
                                    if (write_ec) {
                                        CountDnsTransport(Protocol::DoT, DnsTransportStage::Send, DnsTransportReason::Failed);
                                        state->Complete(ppp::vector<Byte>());
                                        return;
                                    }

                                    auto stream_w = state->tls_stream;
                                    auto length_buffer_w = std::static_pointer_cast<std::array<Byte, 2> >(state->slot1);
                                    if (NULLPTR == stream_w || NULLPTR == length_buffer_w) {
                                        return;
                                    }

                                    /* Read: 2-byte response length prefix. */
                                    boost::asio::async_read(*stream_w, boost::asio::buffer(length_buffer_w->data(), length_buffer_w->size()),
                                        [state](const boost::system::error_code& read_len_ec, std::size_t) noexcept {
                                            if (state->IsCompleted()) {
                                                return;
                                            }
                                            if (read_len_ec) {
                                                CountDnsTransport(Protocol::DoT, DnsTransportStage::Recv, DnsTransportReason::Failed);
                                                state->Complete(ppp::vector<Byte>());
                                                return;
                                            }

                                            auto length_buffer_r = std::static_pointer_cast<std::array<Byte, 2> >(state->slot1);
                                            if (NULLPTR == length_buffer_r) {
                                                state->Complete(ppp::vector<Byte>());
                                                return;
                                            }

                                            int response_size = (static_cast<int>((*length_buffer_r)[0]) << 8) | static_cast<int>((*length_buffer_r)[1]);
                                            if (response_size <= 0 || response_size > PPP_DNS_RESOLVER_TCP_MAX_SIZE) {
                                                CountDnsTransport(Protocol::DoT, DnsTransportStage::Parse, DnsTransportReason::Invalid);
                                                state->Complete(ppp::vector<Byte>());
                                                return;
                                            }

                                            std::shared_ptr<ppp::vector<Byte> > response = make_shared_object<ppp::vector<Byte> >(response_size);
                                            if (NULLPTR == response) {
                                                CountDnsTransport(Protocol::DoT, DnsTransportStage::Parse, DnsTransportReason::AllocFailed);
                                                state->Complete(ppp::vector<Byte>());
                                                return;
                                            }
                                            // Replace the request buffer slot with the response
                                            // buffer; we no longer need the request after the
                                            // length prefix has been received.
                                            state->slot0 = response;

                                            auto stream_b = state->tls_stream;
                                            if (NULLPTR == stream_b) {
                                                return;
                                            }

                                            /* Read: response body. */
                                            boost::asio::async_read(*stream_b, boost::asio::buffer(response->data(), response->size()),
                                                [state](const boost::system::error_code& read_body_ec, std::size_t) noexcept {
                                                    if (state->IsCompleted()) {
                                                        return;
                                                    }
                                                    if (read_body_ec) {
                                                        CountDnsTransport(Protocol::DoT, DnsTransportStage::Recv, DnsTransportReason::Failed);
                                                        state->Complete(ppp::vector<Byte>());
                                                        return;
                                                    }

                                                    auto response_r = std::static_pointer_cast<ppp::vector<Byte> >(state->slot0);
                                                    if (NULLPTR == response_r) {
                                                        state->Complete(ppp::vector<Byte>());
                                                        return;
                                                    }

                                                    CountDnsTransport(Protocol::DoT, DnsTransportStage::Success);
                                                    state->Complete(std::move(*response_r));
                                                });
                                        });
                                });
                        });
                });
        }

        /* ========================================================================
         * SendUdp — plain DNS over UDP
         * ======================================================================== */

        void DnsResolver::SendUdp(const ServerEntry& entry, std::shared_ptr<ppp::vector<Byte> > packet, const ResolveCallback& callback) noexcept {
            CountDnsTransport(Protocol::UDP, DnsTransportStage::Attempt);
            boost::asio::ip::address ip;
            if (!ResolveEntryBootstrapAddress(entry, ip)) {
                CountDnsTransport(Protocol::UDP, DnsTransportStage::Bootstrap, DnsTransportReason::Invalid);
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            udp::endpoint remote(ip, static_cast<unsigned short>(ParsePort(entry.address, PPP_DNS_SYS_PORT)));

            // Centralised state, [state]-only lambda captures, single-shot
            // teardown via state->Complete(). Same lifecycle policy as
            // SendDoh/SendDot.
            std::shared_ptr<CompletionState> state = make_shared_object<CompletionState>(callback);
            std::shared_ptr<udp::socket> socket = make_shared_object<udp::socket>(context_);
            std::shared_ptr<boost::asio::steady_timer> timer = make_shared_object<boost::asio::steady_timer>(context_);
            std::shared_ptr<ppp::vector<Byte> > buffer = make_shared_object<ppp::vector<Byte> >(PPP_DNS_RESOLVER_UDP_BUFFER_SIZE);
            std::shared_ptr<udp::endpoint> source = make_shared_object<udp::endpoint>();
            if (NULLPTR == state || NULLPTR == socket || NULLPTR == timer || NULLPTR == buffer || NULLPTR == source) {
                CountDnsTransport(Protocol::UDP, DnsTransportStage::Socket, DnsTransportReason::AllocFailed);
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }
            state->udp_socket = socket;
            state->timer = timer;
            state->slot0 = buffer;
            state->slot1 = source;

            boost::system::error_code ec;
            socket->open(remote.protocol(), ec);
            if (ec) {
                CountDnsTransport(Protocol::UDP, DnsTransportStage::Socket, DnsTransportReason::OpenFailed);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            ppp::net::Socket::AdjustDefaultSocketOptional(socket->native_handle(), ip.is_v4());
            ppp::net::Socket::SetTypeOfService(socket->native_handle());
            ppp::net::Socket::SetSignalPipeline(socket->native_handle(), false);
            ppp::net::Socket::ReuseSocketAddress(socket->native_handle(), true);
            if (!ProtectSocket(socket->native_handle())) {
                CountDnsTransport(Protocol::UDP, DnsTransportStage::Socket, DnsTransportReason::ProtectFailed);
                state->Complete(ppp::vector<Byte>());
                return;
            }
            socket->bind(udp::endpoint(remote.protocol(), 0), ec);
            if (ec) {
                CountDnsTransport(Protocol::UDP, DnsTransportStage::Socket, DnsTransportReason::OpenFailed);
                state->Complete(ppp::vector<Byte>());
                return;
            }
            std::shared_ptr<DnsUdpFlowRegistry> udp_flow_registry = GetConfig()->udp_flow_registry;
            if (udp_flow_registry) {
                const udp::endpoint local = socket->local_endpoint(ec);
                if (ec || !udp_flow_registry->Register(
                        local.port(), remote,
                        std::chrono::milliseconds(PPP_DNS_RESOLVER_UDP_TIMEOUT_MS))) {
                    CountDnsTransport(Protocol::UDP, DnsTransportStage::Socket, DnsTransportReason::Failed);
                    state->Complete(ppp::vector<Byte>());
                    return;
                }
            }

            timer->expires_after(std::chrono::milliseconds(PPP_DNS_RESOLVER_UDP_TIMEOUT_MS));
            timer->async_wait([state](const boost::system::error_code& ec_) noexcept {
                if (ec_ || state->IsCompleted()) {
                    return;
                }
                CountDnsTransport(Protocol::UDP, DnsTransportStage::Recv, DnsTransportReason::Timeout);
                CountDnsTransport(Protocol::UDP, DnsTransportStage::Timeout);
                state->Complete(ppp::vector<Byte>());
            });

            socket->async_send_to(boost::asio::buffer(packet->data(), packet->size()), remote,
                [state, packet, remote](const boost::system::error_code& send_ec, std::size_t) noexcept {
                    if (state->IsCompleted()) {
                        return;
                    }
                    if (send_ec) {
                        CountDnsTransport(Protocol::UDP, DnsTransportStage::Send, DnsTransportReason::Failed);
                        state->Complete(ppp::vector<Byte>());
                        return;
                    }

                    StartDnsUdpReceive(state, packet, remote);
                });
        }

        /* ========================================================================
         * SendTcp — plain DNS over TCP (with 2-byte length prefix)
         * ======================================================================== */

        void DnsResolver::SendTcp(const ServerEntry& entry, std::shared_ptr<ppp::vector<Byte> > packet, const ResolveCallback& callback) noexcept {
            CountDnsTransport(Protocol::TCP, DnsTransportStage::Attempt);
            boost::asio::ip::address ip;
            if (!ResolveEntryBootstrapAddress(entry, ip)) {
                CountDnsTransport(Protocol::TCP, DnsTransportStage::Bootstrap, DnsTransportReason::Invalid);
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            tcp::endpoint remote(ip, static_cast<unsigned short>(ParsePort(entry.address, PPP_DNS_SYS_PORT)));

            // Centralised state, [state]-only lambda captures, single-shot
            // teardown via state->Complete(). Same lifecycle policy as
            // SendDoh/SendDot.
            std::shared_ptr<CompletionState> state = make_shared_object<CompletionState>(callback);
            std::shared_ptr<tcp::socket> socket = make_shared_object<tcp::socket>(context_);
            std::shared_ptr<boost::asio::steady_timer> timer = make_shared_object<boost::asio::steady_timer>(context_);
            std::shared_ptr<ppp::vector<Byte> > request = make_shared_object<ppp::vector<Byte> >();
            std::shared_ptr<std::array<Byte, 2> > length_buffer = make_shared_object<std::array<Byte, 2> >();
            if (NULLPTR == state || NULLPTR == socket || NULLPTR == timer || NULLPTR == request || NULLPTR == length_buffer) {
                CountDnsTransport(Protocol::TCP, DnsTransportStage::Socket, DnsTransportReason::AllocFailed);
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }
            state->tcp_socket = socket;
            state->timer = timer;
            state->slot0 = request;
            state->slot1 = length_buffer;

            try {
                request->resize(packet->size() + 2);
                (*request)[0] = static_cast<Byte>((packet->size() >> 8) & 0xff);
                (*request)[1] = static_cast<Byte>(packet->size() & 0xff);
                memcpy(request->data() + 2, packet->data(), packet->size());
            }
            catch (const std::exception&) {
                CountDnsTransport(Protocol::TCP, DnsTransportStage::Parse, DnsTransportReason::BuildFailed);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            boost::system::error_code ec;
            socket->open(remote.protocol(), ec);
            if (ec) {
                CountDnsTransport(Protocol::TCP, DnsTransportStage::Socket, DnsTransportReason::OpenFailed);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            ppp::net::Socket::AdjustDefaultSocketOptional(socket->native_handle(), ip.is_v4());
            ppp::net::Socket::SetTypeOfService(socket->native_handle());
            ppp::net::Socket::SetSignalPipeline(socket->native_handle(), false);
            ppp::net::Socket::ReuseSocketAddress(socket->native_handle(), true);
            if (!ProtectSocket(socket->native_handle())) {
                CountDnsTransport(Protocol::TCP, DnsTransportStage::Socket, DnsTransportReason::ProtectFailed);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            timer->expires_after(std::chrono::milliseconds(PPP_DNS_RESOLVER_TCP_TIMEOUT_MS));
            timer->async_wait([state](const boost::system::error_code& ec_) noexcept {
                if (ec_ || state->IsCompleted()) {
                    return;
                }
                CountDnsTransport(Protocol::TCP, DnsTransportStage::Timeout);
                state->Complete(ppp::vector<Byte>());
            });

            socket->async_connect(remote, [state](const boost::system::error_code& connect_ec) noexcept {
                if (state->IsCompleted()) {
                    return;
                }
                if (connect_ec) {
                    CountDnsTransport(Protocol::TCP, DnsTransportStage::Connect, DnsTransportReason::Failed);
                    state->Complete(ppp::vector<Byte>());
                    return;
                }

                auto socket_local = state->tcp_socket;
                auto request_local = std::static_pointer_cast<ppp::vector<Byte> >(state->slot0);
                if (NULLPTR == socket_local || NULLPTR == request_local) {
                    return;
                }

                boost::asio::async_write(*socket_local, boost::asio::buffer(request_local->data(), request_local->size()),
                    [state](const boost::system::error_code& write_ec, std::size_t) noexcept {
                        if (state->IsCompleted()) {
                            return;
                        }
                        if (write_ec) {
                            CountDnsTransport(Protocol::TCP, DnsTransportStage::Send, DnsTransportReason::Failed);
                            state->Complete(ppp::vector<Byte>());
                            return;
                        }

                        auto socket_w = state->tcp_socket;
                        auto length_buffer_w = std::static_pointer_cast<std::array<Byte, 2> >(state->slot1);
                        if (NULLPTR == socket_w || NULLPTR == length_buffer_w) {
                            return;
                        }

                        boost::asio::async_read(*socket_w, boost::asio::buffer(length_buffer_w->data(), length_buffer_w->size()),
                            [state](const boost::system::error_code& read_len_ec, std::size_t) noexcept {
                                if (state->IsCompleted()) {
                                    return;
                                }
                                if (read_len_ec) {
                                    CountDnsTransport(Protocol::TCP, DnsTransportStage::Recv, DnsTransportReason::Failed);
                                    state->Complete(ppp::vector<Byte>());
                                    return;
                                }

                                auto length_buffer_r = std::static_pointer_cast<std::array<Byte, 2> >(state->slot1);
                                if (NULLPTR == length_buffer_r) {
                                    state->Complete(ppp::vector<Byte>());
                                    return;
                                }

                                int response_size = (static_cast<int>((*length_buffer_r)[0]) << 8) | static_cast<int>((*length_buffer_r)[1]);
                                if (response_size <= 0 || response_size > PPP_DNS_RESOLVER_TCP_MAX_SIZE) {
                                    CountDnsTransport(Protocol::TCP, DnsTransportStage::Parse, DnsTransportReason::Invalid);
                                    state->Complete(ppp::vector<Byte>());
                                    return;
                                }

                                std::shared_ptr<ppp::vector<Byte> > response = make_shared_object<ppp::vector<Byte> >(response_size);
                                if (NULLPTR == response) {
                                    CountDnsTransport(Protocol::TCP, DnsTransportStage::Parse, DnsTransportReason::AllocFailed);
                                    state->Complete(ppp::vector<Byte>());
                                    return;
                                }
                                state->slot0 = response;  // recycle slot0 (request no longer needed)

                                auto socket_b = state->tcp_socket;
                                if (NULLPTR == socket_b) {
                                    return;
                                }

                                boost::asio::async_read(*socket_b, boost::asio::buffer(response->data(), response->size()),
                                    [state](const boost::system::error_code& read_body_ec, std::size_t) noexcept {
                                        if (state->IsCompleted()) {
                                            return;
                                        }
                                        if (read_body_ec) {
                                            CountDnsTransport(Protocol::TCP, DnsTransportStage::Recv, DnsTransportReason::Failed);
                                            state->Complete(ppp::vector<Byte>());
                                            return;
                                        }

                                        auto response_r = std::static_pointer_cast<ppp::vector<Byte> >(state->slot0);
                                        if (NULLPTR == response_r) {
                                            state->Complete(ppp::vector<Byte>());
                                            return;
                                        }

                                        CountDnsTransport(Protocol::TCP, DnsTransportStage::Success);
                                        state->Complete(std::move(*response_r));
                                    });
                            });
                    });
            });
        }

        /* ========================================================================
         * InjectEcsOptRr — EDNS Client Subnet OPT RR injection / merge
         *
         * Behaviour:
         *   ARCOUNT == 0 : append a fresh OPT RR with ECS option.
         *   ARCOUNT >  0 : scan additional records for an existing OPT RR (TYPE=41
         *                  at root label).  If found, replace or append the ECS
         *                  option within its RDATA.  If the packet cannot be
         *                  safely parsed, return false (packet unchanged).
         * ======================================================================== */

        bool DnsResolver::InjectEcsOptRr(ppp::vector<Byte>& packet, const boost::asio::ip::address& ecs_ip) noexcept {
            if (packet.size() < kDnsHeaderSize) {
                return false;
            }

            // Only support IPv4 for ECS injection.
            if (!ecs_ip.is_v4()) {
                return false;
            }

            // Read ARCOUNT (big-endian at offset 10).
            uint16_t arcount = (static_cast<uint16_t>(packet[10]) << 8) | static_cast<uint16_t>(packet[11]);

            /* ---------------------------------------------------------------
             * Fast path: ARCOUNT == 0 — append a fresh OPT RR (original logic).
             * --------------------------------------------------------------- */
            if (arcount == 0) {
                // Total OPT RR size = overhead(11) + RDATA(kEcsNewRdataLen=12) = 23 bytes
                static constexpr std::size_t kFreshOptSize = kOptRrOverhead + kEcsNewRdataLen;

                // Ensure total size won't exceed the classic 512-byte UDP limit.
                if (packet.size() + kFreshOptSize > 512) {
                    return false;
                }

                try {
                    std::size_t old_size = packet.size();
                    packet.resize(old_size + kFreshOptSize);
                    Byte* p = packet.data() + old_size;

                    // OPT RR header
                    // Name: root (0x00)
                    *p++ = 0x00;
                    // Type: OPT (41 = 0x0029)
                    *p++ = 0x00; *p++ = 0x29;
                    // Class: UDP payload size (4096 = 0x1000)
                    *p++ = 0x10; *p++ = 0x00;
                    // TTL: extended-rcode(8) + version(8) + DO|Z(16) = all zero
                    *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
                    // RDLENGTH: 12 bytes of ECS RDATA
                    *p++ = 0x00; *p++ = 0x0C;

                    // ECS option RDATA (RFC 7871)
                    // Option Code: ECS (8 = 0x0008)
                    *p++ = 0x00; *p++ = 0x08;
                    // Option Length: 8 bytes (family + prefix + scope + address)
                    *p++ = 0x00; *p++ = 0x08;
                    // Address Family: IPv4 (1 = 0x0001)
                    *p++ = 0x00; *p++ = 0x01;
                    // Source Prefix-Length: 24 (for /24 subnet)
                    *p++ = 24;
                    // Scope Prefix-Length: 0 (no scope)
                    *p++ = 0;
                    // Client IPv4 address (4 bytes, last byte zeroed for /24)
                    boost::asio::ip::address_v4::bytes_type addr_bytes = ecs_ip.to_v4().to_bytes();
                    *p++ = addr_bytes[0];
                    *p++ = addr_bytes[1];
                    *p++ = addr_bytes[2];
                    *p++ = 0; // zero the last octet for /24 prefix

                    // Increment ARCOUNT (big-endian at offset 10-11).
                    arcount++;
                    packet[10] = static_cast<Byte>((arcount >> 8) & 0xff);
                    packet[11] = static_cast<Byte>(arcount & 0xff);

                    return true;
                }
                catch (const std::exception&) {
                    return false;
                }
            }

            /* ---------------------------------------------------------------
             * Merge path: ARCOUNT > 0 — attempt to find existing OPT RR and
             * replace/append the ECS option within its RDATA.
             *
             * We must safely parse through QDCOUNT + ANCOUNT + NSCOUNT
             * sections to reach the additional records, then scan for the
             * first OPT RR (TYPE=41 at root label).
             * --------------------------------------------------------------- */

            // Read section counts from the DNS header.
            uint16_t qdcount = (static_cast<uint16_t>(packet[4]) << 8) | static_cast<uint16_t>(packet[5]);
            uint16_t ancount = (static_cast<uint16_t>(packet[6]) << 8) | static_cast<uint16_t>(packet[7]);
            uint16_t nscount = (static_cast<uint16_t>(packet[8]) << 8) | static_cast<uint16_t>(packet[9]);

            const Byte* data = packet.data();
            std::size_t size  = packet.size();

            // Walk through QD section.
            std::size_t pos = SkipDnsQuestionSection(data, size, kDnsHeaderSize, qdcount);
            if (pos == 0) {
                return false; /* Parse error; leave packet unchanged. */
            }

            // Walk through AN section.
            pos = SkipDnsRrSection(data, size, pos, ancount);
            if (pos == 0) {
                return false;
            }

            // Walk through NS section.
            pos = SkipDnsRrSection(data, size, pos, nscount);
            if (pos == 0) {
                return false;
            }

            // Now `pos` points to the start of the additional records section.
            // Scan for an existing OPT RR (TYPE=41 at root label).
            for (uint16_t i = 0; i < arcount; ++i) {
                std::size_t rr_start = pos;

                // Verify the name is root (single 0x00 byte) — required for OPT RR.
                if (pos >= size || data[pos] != 0x00) {
                    // Not a root-label record; skip this RR normally.
                    std::size_t name_len = SkipDnsName(data, size, pos);
                    if (name_len == 0) {
                        return false;
                    }
                    pos += name_len;
                    if (pos + 10 > size) {
                        return false;
                    }
                    uint16_t rdlen = (static_cast<uint16_t>(data[pos + 8]) << 8) |
                                      static_cast<uint16_t>(data[pos + 9]);
                    pos += 10 + rdlen;
                    continue;
                }

                // Root label consumed (1 byte).
                pos += 1;
                if (pos + 10 > size) {
                    return false;
                }

                // Read TYPE (2 bytes).
                uint16_t rr_type = (static_cast<uint16_t>(data[pos]) << 8) |
                                    static_cast<uint16_t>(data[pos + 1]);

                if (rr_type != kOptType) {
                    // Not an OPT RR — skip the rest of this record.
                    uint16_t rdlen = (static_cast<uint16_t>(data[pos + 8]) << 8) |
                                      static_cast<uint16_t>(data[pos + 9]);
                    pos += 10 + rdlen;
                    continue;
                }

                /* Found an existing OPT RR.  Parse its RDATA and look for
                 * an existing ECS option (option-code 8). */

                // CLASS(2) + TTL(4) are at pos+2 .. pos+7.
                uint16_t rdlength = (static_cast<uint16_t>(data[pos + 8]) << 8) |
                                     static_cast<uint16_t>(data[pos + 9]);

                std::size_t rdata_start = pos + 10;
                if (rdata_start + rdlength > size) {
                    return false; /* RDATA extends beyond packet. */
                }

                // Scan EDNS options in the OPT RDATA to find ECS (option-code 8).
                std::size_t rdata_pos = 0;
                std::size_t ecs_option_offset = 0;  /* Offset within RDATA where ECS option starts. */
                std::size_t ecs_option_size   = 0;  /* Total size of existing ECS option (code+len+data). */
                bool found_ecs = false;

                while (rdata_pos + 4 <= rdlength) {
                    uint16_t opt_code = (static_cast<uint16_t>(data[rdata_start + rdata_pos]) << 8) |
                                         static_cast<uint16_t>(data[rdata_start + rdata_pos + 1]);
                    uint16_t opt_len  = (static_cast<uint16_t>(data[rdata_start + rdata_pos + 2]) << 8) |
                                         static_cast<uint16_t>(data[rdata_start + rdata_pos + 3]);

                    if (rdata_pos + 4 + opt_len > rdlength) {
                        return false; /* Option data extends beyond RDATA. */
                    }

                    if (opt_code == kEcsOptionCode) {
                        ecs_option_offset = rdata_pos;
                        ecs_option_size   = 4 + opt_len;
                        found_ecs = true;
                        /* Continue scanning to validate the rest of the options
                         * (we don't break because we need to verify the packet
                         * structure is intact). */
                    }

                    rdata_pos += 4 + opt_len;
                }

                /* Build the new ECS option data. */
                static constexpr std::size_t kNewEcsOptionSize = 4 + kEcsNewOptionLen; /* 4 (code+len) + 8 (data) */
                Byte new_ecs[kNewEcsOptionSize];
                {
                    Byte* q = new_ecs;
                    // Option Code: ECS (8)
                    *q++ = 0x00; *q++ = 0x08;
                    // Option Length: 8
                    *q++ = 0x00; *q++ = 0x08;
                    // Address Family: IPv4 (1)
                    *q++ = 0x00; *q++ = 0x01;
                    // Source Prefix-Length: 24
                    *q++ = 24;
                    // Scope Prefix-Length: 0
                    *q++ = 0;
                    // IPv4 address (last octet zeroed for /24)
                    boost::asio::ip::address_v4::bytes_type ab = ecs_ip.to_v4().to_bytes();
                    *q++ = ab[0];
                    *q++ = ab[1];
                    *q++ = ab[2];
                    *q++ = 0;
                }

                /* Calculate new RDLENGTH. */
                std::size_t new_rdlength;
                if (found_ecs) {
                    new_rdlength = rdlength - ecs_option_size + kNewEcsOptionSize;
                }
                else {
                    new_rdlength = rdlength + kNewEcsOptionSize;
                }

                if (new_rdlength > 65535) {
                    return false; /* Would overflow RDLENGTH field. */
                }

                /* Build the new RDATA in a temporary buffer. */
                try {
                    ppp::vector<Byte> new_rdata;
                    new_rdata.reserve(new_rdlength);

                    // Copy existing RDATA, skipping the old ECS option if present.
                    if (found_ecs) {
                        // Copy options before the ECS option.
                        if (ecs_option_offset > 0) {
                            new_rdata.insert(new_rdata.end(),
                                data + rdata_start,
                                data + rdata_start + ecs_option_offset);
                        }
                        // Copy options after the old ECS option.
                        std::size_t after_ecs = ecs_option_offset + ecs_option_size;
                        if (after_ecs < rdlength) {
                            new_rdata.insert(new_rdata.end(),
                                data + rdata_start + after_ecs,
                                data + rdata_start + rdlength);
                        }
                    }
                    else {
                        // No existing ECS — copy all existing options.
                        if (rdlength > 0) {
                            new_rdata.insert(new_rdata.end(),
                                data + rdata_start,
                                data + rdata_start + rdlength);
                        }
                    }

                    // Append the new ECS option.
                    new_rdata.insert(new_rdata.end(), new_ecs, new_ecs + kNewEcsOptionSize);

                    /* Resize the packet to replace the old RDATA region. */
                    std::size_t size_delta = new_rdata.size() - rdlength;
                    std::size_t old_packet_size = packet.size();
                    std::size_t after_rdata = rdata_start + rdlength;

                    if (size_delta > 0) {
                        // Packet grows — need to check size limit.
                        if (old_packet_size + size_delta > 65535) {
                            return false;
                        }
                        packet.resize(old_packet_size + size_delta);
                        // Shift trailing data right.
                        std::memmove(packet.data() + rdata_start + new_rdata.size(),
                                     packet.data() + after_rdata,
                                     old_packet_size - after_rdata);
                    }
                    else if (size_delta < 0) {
                        // Packet shrinks — shift trailing data left.
                        std::size_t abs_delta = static_cast<std::size_t>(-static_cast<ptrdiff_t>(size_delta));
                        std::memmove(packet.data() + rdata_start + new_rdata.size(),
                                     packet.data() + after_rdata,
                                     old_packet_size - after_rdata);
                        packet.resize(old_packet_size - abs_delta);
                    }
                    else {
                        // Same size — just overwrite in place.
                    }

                    // Write the new RDATA into the packet.
                    std::memcpy(packet.data() + rdata_start, new_rdata.data(), new_rdata.size());

                    // Update RDLENGTH in the OPT RR header.
                    packet[rr_start + 1 + 8] = static_cast<Byte>((new_rdlength >> 8) & 0xff);
                    packet[rr_start + 1 + 9] = static_cast<Byte>(new_rdlength & 0xff);

                    return true;
                }
                catch (const std::exception&) {
                    return false;
                }
            }

            /* No OPT RR found in additional section — conservatively skip. */
            return false;
        }

        /* ========================================================================
         * DetectExitIPViaStun — STUN Binding Request with multi-candidate rotation
         *
         * Tries candidates in round-robin order.  On each call, the starting
         * index is advanced so that repeated calls distribute load.
         * Falls back to the built-in default list when no candidates are set.
         * ======================================================================== */

        void DnsResolver::DetectExitIPViaStun(const ExitIpCallback& callback) noexcept {
            if (NULLPTR == callback) {
                return;
            }

            std::shared_ptr<const Config> config = GetConfig();
            const ppp::vector<StunCandidate>& candidates =
                config->stun_candidates.empty() ? DefaultStunCandidates() : config->stun_candidates;

            if (candidates.empty() && config->stun_hostname_candidates.empty()) {
                ppp::telemetry::Log(Level::kDebug, "dns", "STUN no candidates available");
                ppp::telemetry::Count("dns.stun.no_candidates", 1);
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            ppp::telemetry::Log(Level::kDebug, "dns", "STUN detection start ip_candidates=%zu hostname_candidates=%zu",
                candidates.size(), config->stun_hostname_candidates.size());
            ppp::telemetry::Count("dns.stun.start", 1);

            auto resolver_weak = weak_from_this();
            auto chain = make_shared_object<ExitIpCallback>(
                [callback](const boost::asio::ip::address& addr) noexcept {
                    callback(addr);
                });
            if (NULLPTR == chain) {
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            if (!candidates.empty()) {
                std::size_t start = stun_rotation_.fetch_add(1, std::memory_order_relaxed) % candidates.size();
                auto ordered = make_shared_object<ppp::vector<StunCandidate> >();
                if (NULLPTR == ordered) {
                    boost::asio::post(context_, [callback]() noexcept {
                        callback(boost::asio::ip::address());
                    });
                    return;
                }
                ordered->reserve(candidates.size());
                for (std::size_t i = 0; i < candidates.size(); ++i) {
                    ordered->push_back(candidates[(start + i) % candidates.size()]);
                }

                for (int i = static_cast<int>(ordered->size()) - 1; i >= 0; --i) {
                    StunCandidate cand = (*ordered)[static_cast<std::size_t>(i)];
                    std::shared_ptr<ExitIpCallback> next = std::move(chain);
                    chain = make_shared_object<ExitIpCallback>();
                    if (NULLPTR == chain) {
                        boost::asio::post(context_, [callback]() noexcept {
                            callback(boost::asio::ip::address());
                        });
                        return;
                    }

                    *chain = [resolver_weak, cand, next](const boost::asio::ip::address& prev_result) noexcept {
                        if (!prev_result.is_unspecified()) {
                            ppp::telemetry::Log(Level::kDebug, "dns", "STUN success ip=%s port=%d",
                                cand.ip.to_string().c_str(), cand.port);
                            ppp::telemetry::Count("dns.stun.success", 1);
                            (*next)(prev_result);
                            return;
                        }
                        std::shared_ptr<DnsResolver> resolver = resolver_weak.lock();
                        if (NULLPTR == resolver) {
                            (*next)(boost::asio::ip::address());
                            return;
                        }
                        ppp::telemetry::Log(Level::kTrace, "dns", "STUN trying candidate ip=%s:%d",
                            cand.ip.to_string().c_str(), cand.port);
                        resolver->TryStunCandidate(cand, *next);
                    };
                }
            }

            if (!config->stun_hostname_candidates.empty()) {
                std::size_t host_start =
                    stun_rotation_.fetch_add(1, std::memory_order_relaxed) % config->stun_hostname_candidates.size();
                for (std::size_t j = 0; j < config->stun_hostname_candidates.size(); ++j) {
                    StunHostnameCandidate hc =
                        config->stun_hostname_candidates[(host_start + j) % config->stun_hostname_candidates.size()];
                    std::shared_ptr<ExitIpCallback> next = std::move(chain);
                    chain = make_shared_object<ExitIpCallback>();
                    if (NULLPTR == chain) {
                        boost::asio::post(context_, [callback]() noexcept {
                            callback(boost::asio::ip::address());
                        });
                        return;
                    }

                    *chain = [resolver_weak, hc, next](const boost::asio::ip::address& prev_result) noexcept {
                        if (!prev_result.is_unspecified()) {
                            (*next)(prev_result);
                            return;
                        }
                        std::shared_ptr<DnsResolver> resolver = resolver_weak.lock();
                        if (NULLPTR == resolver) {
                            (*next)(boost::asio::ip::address());
                            return;
                        }
                        ppp::telemetry::Log(Level::kTrace, "dns", "STUN resolving hostname candidate host=%s port=%d",
                            hc.hostname.c_str(), hc.port);
                        resolver->ResolveHostnameAsync(hc.hostname,
                            [resolver_weak, hc, next](const boost::asio::ip::address& resolved_ip) noexcept {
                                if (resolved_ip.is_unspecified()) {
                                    (*next)(resolved_ip);
                                    return;
                                }
                                std::shared_ptr<DnsResolver> resolver_inner = resolver_weak.lock();
                                if (NULLPTR == resolver_inner) {
                                    (*next)(boost::asio::ip::address());
                                    return;
                                }
                                StunCandidate cand;
                                cand.ip = resolved_ip;
                                cand.port = hc.port;
                                resolver_inner->TryStunCandidate(cand, *next);
                            });
                    };
                }
            }

            (*chain)(boost::asio::ip::address());
        }

        /* ========================================================================
         * TryStunCandidate — STUN probe against a single candidate
         * ======================================================================== */

        void DnsResolver::TryStunCandidate(
            const StunCandidate& candidate,
            const ExitIpCallback& callback) noexcept {

            if (NULLPTR == callback) {
                return;
            }

            if (candidate.ip.is_unspecified()) {
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            udp::endpoint remote(candidate.ip, static_cast<unsigned short>(candidate.port));

            // Centralise every transient resource in `state`. Lambdas in the
            // chain capture only [state]; teardown is single-shot inside
            // StunCompletionState::Complete().
            std::shared_ptr<StunCompletionState> state = make_shared_object<StunCompletionState>(callback);
            std::shared_ptr<udp::socket> socket = make_shared_object<udp::socket>(context_);
            std::shared_ptr<boost::asio::steady_timer> timer = make_shared_object<boost::asio::steady_timer>(context_);
            std::shared_ptr<ppp::vector<Byte> > recv_buf = make_shared_object<ppp::vector<Byte> >(1024);
            std::shared_ptr<udp::endpoint> recv_ep = make_shared_object<udp::endpoint>();
            std::shared_ptr<ppp::vector<Byte> > request = make_shared_object<ppp::vector<Byte> >(20, 0);

            if (NULLPTR == state || NULLPTR == socket || NULLPTR == timer || NULLPTR == recv_buf || NULLPTR == recv_ep || NULLPTR == request) {
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }
            state->udp_socket = socket;
            state->timer = timer;
            state->slot0 = request;
            state->slot1 = recv_buf;
            state->slot2 = recv_ep;

            boost::system::error_code ec;
            socket->open(udp::v4(), ec);
            if (ec) {
                state->Complete(boost::asio::ip::address());
                return;
            }

            ppp::net::Socket::AdjustDefaultSocketOptional(socket->native_handle(), true);
            ppp::net::Socket::SetTypeOfService(socket->native_handle());
            ppp::net::Socket::SetSignalPipeline(socket->native_handle(), false);
            ppp::net::Socket::ReuseSocketAddress(socket->native_handle(), true);
            if (!ProtectSocket(socket->native_handle())) {
                state->Complete(boost::asio::ip::address());
                return;
            }

            /* Build the 20-byte STUN Binding Request (RFC 5389 §6). */
            Byte* pkt = request->data();
            // Message Type: Binding Request (0x0001)
            pkt[0] = 0x00; pkt[1] = 0x01;
            // Message Length: 0 (no attributes)
            pkt[2] = 0x00; pkt[3] = 0x00;
            // Magic Cookie (0x2112A442)
            pkt[4] = 0x21; pkt[5] = 0x12; pkt[6] = 0xA4; pkt[7] = 0x42;
            // Transaction ID: 12 random bytes.
            pkt[8]  = 0xAA; pkt[9]  = 0xBB; pkt[10] = 0xCC; pkt[11] = 0xDD;
            pkt[12] = 0xEE; pkt[13] = 0xFF; pkt[14] = 0x00; pkt[15] = 0x11;
            pkt[16] = 0x22; pkt[17] = 0x33; pkt[18] = 0x44; pkt[19] = 0x55;

            /* Timeout handler. */
            timer->expires_after(std::chrono::milliseconds(PPP_DNS_RESOLVER_STUN_TIMEOUT_MS));
            timer->async_wait([state](const boost::system::error_code& timer_ec) noexcept {
                if (timer_ec || state->IsCompleted()) {
                    return;
                }
                ppp::telemetry::Count("dns.stun.timeout", 1);
                state->Complete(boost::asio::ip::address());
            });

            /* Send the STUN request. */
            socket->async_send_to(boost::asio::buffer(request->data(), request->size()), remote,
                [state](const boost::system::error_code& send_ec, std::size_t) noexcept {
                    if (state->IsCompleted()) {
                        return;
                    }
                    if (send_ec) {
                        ppp::telemetry::Count("dns.stun.send_fail", 1);
                        state->Complete(boost::asio::ip::address());
                        return;
                    }

                    auto socket_local = state->udp_socket;
                    auto recv_buf_local = std::static_pointer_cast<ppp::vector<Byte> >(state->slot1);
                    auto recv_ep_local = std::static_pointer_cast<udp::endpoint>(state->slot2);
                    if (NULLPTR == socket_local || NULLPTR == recv_buf_local || NULLPTR == recv_ep_local) {
                        return;
                    }

                    /* Wait for the STUN response. */
                    socket_local->async_receive_from(
                        boost::asio::buffer(recv_buf_local->data(), recv_buf_local->size()), *recv_ep_local,
                        [state](const boost::system::error_code& recv_ec, std::size_t recv_size) noexcept {
                            if (state->IsCompleted()) {
                                return;
                            }

                            if (recv_ec || recv_size < 20) {
                                ppp::telemetry::Count("dns.stun.recv_fail", 1);
                                state->Complete(boost::asio::ip::address());
                                return;
                            }

                            auto recv_buf_r = std::static_pointer_cast<ppp::vector<Byte> >(state->slot1);
                            if (NULLPTR == recv_buf_r) {
                                state->Complete(boost::asio::ip::address());
                                return;
                            }
                            const Byte* resp = recv_buf_r->data();

                            /* Validate STUN header. */
                            uint16_t msg_type = (static_cast<uint16_t>(resp[0]) << 8) |
                                                 static_cast<uint16_t>(resp[1]);
                            uint16_t msg_len  = (static_cast<uint16_t>(resp[2]) << 8) |
                                                 static_cast<uint16_t>(resp[3]);
                            uint32_t cookie   = (static_cast<uint32_t>(resp[4]) << 24) |
                                                 (static_cast<uint32_t>(resp[5]) << 16) |
                                                 (static_cast<uint32_t>(resp[6]) << 8)  |
                                                  static_cast<uint32_t>(resp[7]);

                            if (msg_type != kStunMsgTypeBindingResponse ||
                                cookie   != kStunMagicCookie ||
                                msg_len  > recv_size - 20) {
                                ppp::telemetry::Count("dns.stun.invalid_response", 1);
                                state->Complete(boost::asio::ip::address());
                                return;
                            }

                            /* Scan attributes for XOR-MAPPED-ADDRESS (0x0020). */
                            const Byte* attrs = resp + 20;
                            std::size_t attrs_len = static_cast<std::size_t>(msg_len);
                            std::size_t attr_pos = 0;

                            while (attr_pos + 4 <= attrs_len) {
                                uint16_t attr_type = (static_cast<uint16_t>(attrs[attr_pos]) << 8) |
                                                      static_cast<uint16_t>(attrs[attr_pos + 1]);
                                uint16_t attr_len  = (static_cast<uint16_t>(attrs[attr_pos + 2]) << 8) |
                                                      static_cast<uint16_t>(attrs[attr_pos + 3]);

                                if (attr_pos + 4 + attr_len > attrs_len) {
                                    break; /* Malformed attribute. */
                                }

                                if (attr_type == kStunAttrXorMappedAddr && attr_len >= 8) {
                                    uint8_t family = attrs[attr_pos + 5];
                                    if (family == 0x01) { /* IPv4 */
                                        uint32_t xaddr = (static_cast<uint32_t>(attrs[attr_pos + 8]) << 24) |
                                                          (static_cast<uint32_t>(attrs[attr_pos + 9]) << 16) |
                                                          (static_cast<uint32_t>(attrs[attr_pos + 10]) << 8)  |
                                                           static_cast<uint32_t>(attrs[attr_pos + 11]);
                                        uint32_t addr = xaddr ^ kStunMagicCookie;

                                        boost::asio::ip::address_v4::bytes_type ab;
                                        ab[0] = static_cast<Byte>((addr >> 24) & 0xff);
                                        ab[1] = static_cast<Byte>((addr >> 16) & 0xff);
                                        ab[2] = static_cast<Byte>((addr >> 8)  & 0xff);
                                        ab[3] = static_cast<Byte>(addr & 0xff);

                                        state->Complete(boost::asio::ip::address_v4(ab));
                                        return;
                                    }
                                }

                                /* Advance to next attribute (4-byte aligned). */
                                attr_pos += 4 + ((attr_len + 3) & ~static_cast<std::size_t>(3));
                            }

                            /* No XOR-MAPPED-ADDRESS found. */
                            ppp::telemetry::Count("dns.stun.no_xmapped", 1);
                            state->Complete(boost::asio::ip::address());
                        });
                });
        }

        /* ========================================================================
         * ResolveHostnameAsync — bootstrap DNS helper (system UDP resolver)
         *
         * Sends a raw DNS A-record query to a well-known public resolver
         * (8.8.8.8) via UDP and returns the first A-record answer IP.
         * This is a reusable helper that does NOT depend on the provider
         * infrastructure and can be used during bootstrap when provider
         * hostnames need to be resolved before the full resolver is ready.
         *
         * Current usage: stub available for future bootstrap scenarios.
         * All providers already have hardcoded IP addresses, so this
         * method is not yet called in the normal resolution path.
         * ======================================================================== */

        /* Build a minimal DNS A-record query for a given hostname. */
        static bool BuildDnsAQuery(const ppp::string& hostname, ppp::vector<Byte>& out_packet) noexcept {
            /* DNS Header (12 bytes): ID=0, flags=standard query (0x0100),
             * QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0. */
            out_packet.clear();
            out_packet.resize(kDnsHeaderSize, 0);
            out_packet[0] = 0x00; out_packet[1] = 0x00; /* ID */
            out_packet[2] = 0x01; out_packet[3] = 0x00; /* Flags: standard query, RD=1 */
            out_packet[4] = 0x00; out_packet[5] = 0x01; /* QDCOUNT = 1 */
            /* ANCOUNT=0, NSCOUNT=0, ARCOUNT=0 (already zero). */

            /* Encode hostname as DNS labels. */
            ppp::string host = ATrim(hostname);
            if (host.empty() || host.size() > 253) {
                return false;
            }

            /* Split by '.' and write each label. */
            std::size_t pos = 0;
            while (pos < host.size()) {
                std::size_t dot = host.find('.', pos);
                ppp::string label;
                if (dot == ppp::string::npos) {
                    label = host.substr(pos);
                    pos = host.size();
                }
                else {
                    label = host.substr(pos, dot - pos);
                    pos = dot + 1;
                }

                if (label.empty() || label.size() > 63) {
                    return false;
                }

                out_packet.push_back(static_cast<Byte>(label.size()));
                for (std::size_t j = 0; j < label.size(); ++j) {
                    out_packet.push_back(static_cast<Byte>(label[j]));
                }
            }
            out_packet.push_back(0x00); /* Root label */

            /* QTYPE = A (1), QCLASS = IN (1). */
            out_packet.push_back(0x00); out_packet.push_back(0x01); /* QTYPE  */
            out_packet.push_back(0x00); out_packet.push_back(0x01); /* QCLASS */

            return true;
        }

        /* Parse a DNS response and extract the first A-record IP address. */
        static boost::asio::ip::address_v4 ParseFirstARecord(const Byte* data, std::size_t size) noexcept {
            if (size < kDnsHeaderSize) {
                return boost::asio::ip::address_v4();
            }

            uint16_t ancount = (static_cast<uint16_t>(data[6]) << 8) | static_cast<uint16_t>(data[7]);
            uint16_t qdcount = (static_cast<uint16_t>(data[4]) << 8) | static_cast<uint16_t>(data[5]);

            std::size_t pos = SkipDnsQuestionSection(data, size, kDnsHeaderSize, qdcount);
            if (pos == 0) {
                return boost::asio::ip::address_v4();
            }

            for (uint16_t i = 0; i < ancount; ++i) {
                std::size_t name_len = SkipDnsName(data, size, pos);
                if (name_len == 0) {
                    return boost::asio::ip::address_v4();
                }
                pos += name_len;

                if (pos + 10 > size) {
                    return boost::asio::ip::address_v4();
                }

                uint16_t rr_type   = (static_cast<uint16_t>(data[pos])     << 8) | static_cast<uint16_t>(data[pos + 1]);
                /* uint16_t rr_class  = (static_cast<uint16_t>(data[pos + 2]) << 8) | static_cast<uint16_t>(data[pos + 3]); */
                /* uint32_t rr_ttl    = ... ; */
                uint16_t rdlength  = (static_cast<uint16_t>(data[pos + 8]) << 8) | static_cast<uint16_t>(data[pos + 9]);

                pos += 10;

                if (pos + rdlength > size) {
                    return boost::asio::ip::address_v4();
                }

                if (rr_type == 1 && rdlength == 4) {
                    /* A record with 4-byte IPv4 address. */
                    boost::asio::ip::address_v4::bytes_type ab;
                    ab[0] = data[pos]; ab[1] = data[pos + 1];
                    ab[2] = data[pos + 2]; ab[3] = data[pos + 3];
                    return boost::asio::ip::address_v4(ab);
                }

                pos += rdlength;
            }

            return boost::asio::ip::address_v4();
        }

        static void StartBootstrapDnsReceive(
            const std::shared_ptr<udp::socket>& socket,
            const std::shared_ptr<boost::asio::steady_timer>& timer,
            const std::shared_ptr<ppp::vector<Byte> >& query,
            const std::shared_ptr<ppp::vector<Byte> >& recv_buf,
            const std::shared_ptr<udp::endpoint>& recv_ep,
            const std::shared_ptr<std::atomic<bool> >& done,
            const DnsResolver::ExitIpCallback& callback,
            const udp::endpoint& remote) noexcept {

            socket->async_receive_from(
                boost::asio::buffer(recv_buf->data(), recv_buf->size()), *recv_ep,
                [socket, timer, query, recv_buf, recv_ep, done, callback, remote](const boost::system::error_code& recv_ec, std::size_t recv_size) noexcept {
                    if (done->load(std::memory_order_acquire)) {
                        return;
                    }

                    if (!recv_ec && recv_size >= kDnsHeaderSize) {
                        bool source_ok = recv_ep->address() == remote.address() && recv_ep->port() == remote.port();
                        bool id_ok = ppp::dns::detail::IsDnsResponseForQuery(query->data(), query->size(), recv_buf->data(), recv_size);
                        if (!source_ok || !id_ok) {
                            StartBootstrapDnsReceive(socket, timer, query, recv_buf, recv_ep, done, callback, remote);
                            return;
                        }
                    }

                    bool expected = false;
                    if (!done->compare_exchange_strong(expected, true)) {
                        return;
                    }

                    ppp::net::Socket::Cancel(*timer);
                    ppp::net::Socket::Closesocket(socket);

                    if (recv_ec || recv_size < kDnsHeaderSize) {
                        callback(boost::asio::ip::address());
                        return;
                    }

                    boost::asio::ip::address_v4 result = ParseFirstARecord(recv_buf->data(), recv_size);
                    if (result.is_unspecified()) {
                        callback(boost::asio::ip::address());
                    }
                    else {
                        callback(boost::asio::ip::address(result));
                    }
                });
        }

        void DnsResolver::ResolveHostnameAsync(
            const ppp::string& hostname,
            const ExitIpCallback& callback) noexcept {

            if (NULLPTR == callback || hostname.empty()) {
                if (NULLPTR != callback) {
                    boost::asio::post(context_, [callback]() noexcept {
                        callback(boost::asio::ip::address());
                    });
                }
                return;
            }

            /* Build the DNS A-record query. */
            auto query = make_shared_object<ppp::vector<Byte> >();
            if (NULLPTR == query || !BuildDnsAQuery(hostname, *query)) {
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            /* Target: Google public DNS (8.8.8.8:53). */
            boost::system::error_code ec;
            boost::asio::ip::address dns_ip = boost::asio::ip::address_v4(0x08080808);
            udp::endpoint remote(dns_ip, PPP_DNS_SYS_PORT);

            std::shared_ptr<udp::socket> socket = make_shared_object<udp::socket>(context_);
            std::shared_ptr<boost::asio::steady_timer> timer = make_shared_object<boost::asio::steady_timer>(context_);
            std::shared_ptr<ppp::vector<Byte> > recv_buf = make_shared_object<ppp::vector<Byte> >(PPP_DNS_RESOLVER_UDP_BUFFER_SIZE);
            std::shared_ptr<udp::endpoint> recv_ep = make_shared_object<udp::endpoint>();
            std::shared_ptr<std::atomic<bool> > done = make_shared_object<std::atomic<bool> >(false);

            if (NULLPTR == socket || NULLPTR == timer || NULLPTR == recv_buf || NULLPTR == recv_ep || NULLPTR == done) {
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            socket->open(udp::v4(), ec);
            if (ec) {
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            ppp::net::Socket::AdjustDefaultSocketOptional(socket->native_handle(), true);
            ppp::net::Socket::SetTypeOfService(socket->native_handle());
            ppp::net::Socket::SetSignalPipeline(socket->native_handle(), false);
            ppp::net::Socket::ReuseSocketAddress(socket->native_handle(), true);
            socket->bind(udp::endpoint(remote.protocol(), 0), ec);
            if (ec) {
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }
            std::shared_ptr<DnsUdpFlowRegistry> udp_flow_registry = GetConfig()->udp_flow_registry;
            if (udp_flow_registry) {
                const udp::endpoint local = socket->local_endpoint(ec);
                if (ec || !udp_flow_registry->Register(
                        local.port(), remote,
                        std::chrono::milliseconds(PPP_DNS_RESOLVER_UDP_TIMEOUT_MS))) {
                    boost::asio::post(context_, [callback]() noexcept {
                        callback(boost::asio::ip::address());
                    });
                    return;
                }
            }

            /* Timeout. */
            timer->expires_after(std::chrono::milliseconds(PPP_DNS_RESOLVER_UDP_TIMEOUT_MS));
            timer->async_wait([socket, timer, done, callback](const boost::system::error_code& timer_ec) noexcept {
                (void)timer;
                if (!timer_ec) {
                    bool expected = false;
                    if (done->compare_exchange_strong(expected, true)) {
                        ppp::net::Socket::Closesocket(socket);
                        callback(boost::asio::ip::address());
                    }
                }
            });

            /* Send query. */
            socket->async_send_to(boost::asio::buffer(query->data(), query->size()), remote,
                [socket, timer, query, recv_buf, recv_ep, done, callback, remote](const boost::system::error_code& send_ec, std::size_t) noexcept {
                    if (send_ec) {
                        bool expected = false;
                        if (done->compare_exchange_strong(expected, true)) {
                            ppp::net::Socket::Cancel(*timer);
                            ppp::net::Socket::Closesocket(socket);
                            callback(boost::asio::ip::address());
                        }
                        return;
                    }

                    StartBootstrapDnsReceive(socket, timer, query, recv_buf, recv_ep, done, callback, remote);
                });
        }

    } // namespace dns
} // namespace ppp
