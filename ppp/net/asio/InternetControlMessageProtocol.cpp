#include <ppp/net/asio/InternetControlMessageProtocol.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/checksum.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/diagnostics/Error.h>

typedef ppp::net::Socket                        Socket;
typedef ppp::net::native::ip_hdr                ip_hdr;
typedef ppp::net::native::icmp_hdr              icmp_hdr;
typedef ppp::net::packet::IPFrame               IPFrame;
typedef ppp::net::packet::IcmpFrame             IcmpFrame;
typedef ppp::net::packet::IcmpType              IcmpType;
typedef ppp::net::packet::BufferSegment         BufferSegment;
typedef ppp::net::IPEndPoint                    IPEndPoint;
typedef ppp::net::AddressFamily                 AddressFamily;
typedef ppp::threading::Timer                   Timer;
typedef ppp::threading::Executors               Executors;
typedef ppp::collections::Dictionary            Dictionary;

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @file InternetControlMessageProtocol.cpp
             * @brief Implements asynchronous ICMP echo handling and response translation.
             */

            /** @brief Constructs protocol helper and initializes shared receive buffer. */
            InternetControlMessageProtocol::InternetControlMessageProtocol(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<boost::asio::io_context>& context) noexcept
                : BufferAllocator(allocator)
                , disposed_(false)
                , executor_(context) {

            }

            /** @brief Releases protocol resources and active timeout handlers. */
            InternetControlMessageProtocol::~InternetControlMessageProtocol() noexcept {
                Finalize();
            }

            /**
             * @brief Global state for ICMP request identification allocation.
             *
             * Provides synchronized allocation/deallocation and time-based sweeping of
             * stale identifiers to avoid collisions across concurrent echo requests.
             */
            class InternetControlMessageProtocol_Global final {
                typedef std::mutex                                      SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
                typedef ppp::unordered_set<UInt32>                      AllocatedIdUSet;
                typedef ppp::map<UInt64, AllocatedIdUSet>               AllocatedIdSMap;
                typedef ppp::unordered_map<UInt32, UInt64>              AllocatedIdXSet;

                static constexpr int    MAX_PROBES_COUNT               = 1 << 7;
                static constexpr UInt32 MIN_ALLOCATED_IDENTIFICATION   = 10000;

            public:
                /** @brief Initializes allocator seed for ICMP identification values. */
                InternetControlMessageProtocol_Global() noexcept
                    : aid_(RandomNext(MIN_ALLOCATED_IDENTIFICATION, INT32_MAX)) {

                }

            public:
                /**
                 * @brief Allocates a unique identification token for an echo request.
                 *
                 * @note LOCK DURATION FIX (MEDIUM-3): GetTickCount() was previously called
                 *       inside the syncobj_ critical section, extending lock hold time for
                 *       a potentially slow system call.  It is now computed once BEFORE
                 *       acquiring the lock and reused for every probe iteration.
                 */
                bool                                                    Allocated(UInt32& identification) noexcept {
                    // Compute timestamp once before entering the critical section to keep
                    // lock hold time as short as possible.
                    UInt64 now         = ppp::threading::Executors::GetTickCount();
                    UInt64 now_seconds = now / 1000;

                    SynchronizedObjectScope scope(syncobj_);
                    for (int i = 0; i <= MAX_PROBES_COUNT; i++) {
                        UInt32 n = ++aid_;
                        if (n < MIN_ALLOCATED_IDENTIFICATION) {
                            aid_ = RandomNext(MIN_ALLOCATED_IDENTIFICATION, INT32_MAX);
                            continue;
                        }


                        auto r = allocateds_.emplace(std::make_pair(n, now_seconds));
                        if (r.second) {
                            identification = n;
                            allocateds_map_[now_seconds].emplace(n);
                            return true;
                        }
                    }

                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ResourceExhaustedSockets);
                    return false;
                }
                /** @brief Releases a previously allocated identification token. */
                bool                                                    Deallocated(UInt32 identification) noexcept {
                    UInt64 seconds;
                    SynchronizedObjectScope scope(syncobj_);
                    for (;;) {
                        auto tail = allocateds_.find(identification);
                        auto endl = allocateds_.end();
                        if (tail == endl) {
                            return false;
                        }

                        seconds = tail->second;
                        allocateds_.erase(tail);
                        break;
                    }

                    for (;;) {
                        auto tail = allocateds_map_.find(seconds);
                        auto endl = allocateds_map_.end();
                        if (tail == endl) {
                            break;
                        }

                        auto& allocateds = tail->second;
                        auto tail_allocateds = allocateds.find(identification);
                        auto endl_allocateds = allocateds.end();
                        if (tail_allocateds == endl_allocateds) {
                            break;
                        }

                        allocateds.erase(tail_allocateds);
                        if (allocateds.empty()) {
                            allocateds_map_.erase(tail);
                        }

                        break;
                    }

                    return true;
                }
                /** @brief Sweeps expired identification allocations by timeout. */
                bool                                                    DoEvents() noexcept {
                    SynchronizedObjectScope scope(syncobj_);
                    auto tail = allocateds_map_.begin();
                    auto endl = allocateds_map_.end();
                    if (tail == endl) {
                        return true;
                    }

                    UInt64 now = ppp::threading::Executors::GetTickCount();
                    do {
                        UInt64 timeout = (static_cast<UInt64>(tail->first) * 1000ULL) +
                            static_cast<UInt64>(InternetControlMessageProtocol::MAX_ICMP_TIMEOUT);
                        if (now < timeout) {
                            break;
                        }

                        for (UInt32 identification : tail->second) {
                            auto allocateds_tail = allocateds_.find(identification);
                            auto allocateds_endl = allocateds_.end();
                            if (allocateds_tail != allocateds_endl) {
                                allocateds_.erase(allocateds_tail);
                            }
                        }

                        tail = allocateds_map_.erase(tail);
                    } while (tail != endl);

                    return true;
                }
                /** @brief Returns process-wide default identification allocator. */
                static InternetControlMessageProtocol_Global&           GetDefault() noexcept {
                    static InternetControlMessageProtocol_Global default_;
                    return default_;
                }

            private:
                SynchronizedObject                                      syncobj_;
                UInt32                                                  aid_;
                AllocatedIdXSet                                         allocateds_;
                AllocatedIdSMap                                         allocateds_map_;
            };

            /** @brief Triggers timeout-based sweeping of global ICMP identifications. */
            void InternetControlMessageProtocol_DoEvents() noexcept {
                InternetControlMessageProtocol_Global& g = InternetControlMessageProtocol_Global::GetDefault();
                g.DoEvents();
            }

            /**
             * @brief Per-request asynchronous ICMP echo context.
             *
             * Owns socket, timeout token, request metadata, and response matching logic for
             * a single outstanding ICMP echo transaction.
             */
            class InternetControlMessageProtocol_EchoAsynchronousContext final : public std::enable_shared_from_this<InternetControlMessageProtocol_EchoAsynchronousContext> {
            public:
                std::shared_ptr<boost::asio::ip::udp::socket>           socket_;
                std::shared_ptr<InternetControlMessageProtocol>         owner_;
                std::shared_ptr<Timer>                                  timeout_;
                IPEndPoint                                              destinationEP_;
                UInt32                                                  identification_;
                /**
                 * @brief Per-request receive buffer and source endpoint.
                 *
                 * Each in-flight echo owns its own receive target so concurrent echo
                 * requests never overwrite a shared owner-level buffer or endpoint.
                 */
                std::shared_ptr<Byte>                                   buffer_;
                boost::asio::ip::udp::endpoint                          ep_;

                struct {
                    std::shared_ptr<IPFrame>                            packet;
                    std::shared_ptr<IcmpFrame>                          frame;
                }                                                       request_;

            public:
                /** @brief Constructs asynchronous context with unique request identifier. */
                InternetControlMessageProtocol_EchoAsynchronousContext(UInt32 id) noexcept
                    : identification_(id) {

                }
                /** @brief Ensures socket, timer, and registration entries are released. */
                ~InternetControlMessageProtocol_EchoAsynchronousContext() noexcept { Release(); }

            public:
                /** @brief Starts one asynchronous receive operation for reply matching. */
                void                                                    RunOnce() noexcept {
                    if (NULLPTR == buffer_) {
                        buffer_ = ppp::make_shared_alloc<Byte>(PPP_BUFFER_SIZE);
                        if (NULLPTR == buffer_) {
                            Release();
                            return;
                        }
                    }

                    socket_->async_receive_from(boost::asio::buffer(buffer_.get(), PPP_BUFFER_SIZE), ep_,
                        std::bind(&InternetControlMessageProtocol_EchoAsynchronousContext::Process, shared_from_this(), std::placeholders::_1, std::placeholders::_2));
                }
                /**
                 * @brief Processes one receive completion and validates ICMP correlation.
                 *
                 * The method parses inbound IP/ICMP frames and matches request identity for
                 * both echo-reply and time-exceeded responses.
                 */
                int                                                     Process(const boost::system::error_code& ec, size_t bytes_transferred) noexcept {
                    if (ec == boost::system::errc::success || ec == boost::system::errc::resource_unavailable_try_again) {
                        while (bytes_transferred > 0) {
                            const std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = owner_->BufferAllocator;
                            const std::shared_ptr<IPFrame> response_packet = IPFrame::Parse(allocator, buffer_, buffer_.get(), static_cast<int>(bytes_transferred));
                            if (NULLPTR == response_packet) {
                                break;
                            }

                            const std::shared_ptr<IcmpFrame> response_frame = IcmpFrame::Parse(response_packet.get());
                            if (NULLPTR == response_frame) {
                                break;
                            }

                            std::shared_ptr<IcmpFrame> key_frame;
                            if (response_frame->Type == IcmpType::ICMP_ER) { /* ICMP_ECHOREPLY */
                                key_frame = response_frame;
                            }
                            elif(response_frame->Type == IcmpType::ICMP_TE) { /* ICMP_TIME_EXCEEDED */
                                std::shared_ptr<BufferSegment> payload = response_frame->Payload;
                                if (NULLPTR == payload) {
                                    break;
                                }

                                const std::shared_ptr<IPFrame> request_packet = IPFrame::Parse(allocator, payload->Buffer, payload->Buffer.get(), payload->Length);
                                if (NULLPTR == request_packet) {
                                    break;
                                }

                                key_frame = IcmpFrame::Parse(request_packet.get());
                            }

                            if (NULLPTR != key_frame) {
                                UInt32 request_identification = MAKE_DWORD(key_frame->Sequence, key_frame->Identification);
                                if (request_identification == this->identification_) {
                                    Replay(response_frame->Source, response_frame->Ttl, response_frame->Type);
                                    return 1;
                                }
                            }

                            break;
                        }

                        RunOnce();
                        return 0;
                    }

                    Release();
                    if (boost::asio::error::operation_aborted == ec || boost::asio::error::eof == ec) {
                        return 0;
                    }

                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                    return -1;
                }
                /** @brief Creates translated response packet and outputs to destination. */
                void                                                    Replay(UInt32 source_ip, int ttl, IcmpType icmp_type) noexcept {
                    std::shared_ptr<IPFrame> response;
                    if (icmp_type == IcmpType::ICMP_ER) {
                        const std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = owner_->BufferAllocator;
                        response = InternetControlMessageProtocol::ER(request_.packet, request_.frame, ttl, allocator);
                    }
                    elif(icmp_type == IcmpType::ICMP_TE) {
                        const std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = owner_->BufferAllocator;
                        response = InternetControlMessageProtocol::TE(request_.packet, request_.frame, source_ip, allocator);
                    }

                    if (NULLPTR != response) {
                        owner_->Output(response.get(), destinationEP_);
                    }

                    Release();
                }
                /**
                 * @brief Releases timeout, socket, timeout table entry, and identifier.
                 *
                 * This method is idempotent through moved/reset handles.
                 */
                void                                                    Release() noexcept {
                    std::shared_ptr<Timer> timeout = std::move(timeout_);
                    if (NULLPTR != timeout) {
                        timeout->Dispose();
                    }

                    Socket::Closesocket(socket_);
                    if (std::shared_ptr<InternetControlMessageProtocol> owner = owner_;  NULLPTR != owner_) {
                        std::lock_guard<std::mutex> scope(owner->timeouts_syncobj_);
                        Dictionary::TryRemove(owner->timeouts_, this);
                    }

                    InternetControlMessageProtocol_Global::GetDefault().Deallocated(this->identification_);
                }
            };

            /** @brief Marks instance disposed and removes all pending timeout callbacks. */
            void InternetControlMessageProtocol::Finalize() noexcept {
                disposed_ = true;

                /**
                 * @brief Move the table out under the lock; the handlers are invoked
                 *        lock-free because they re-enter timeouts_ via Release().
                 */
                TimeoutEventHandlerTable timeouts;
                {
                    std::lock_guard<std::mutex> scope(timeouts_syncobj_);
                    timeouts = std::move(timeouts_);
                    timeouts_.clear();
                }

                Timer::ReleaseAllTimeouts(timeouts);
            }

            /** @brief Returns a shared reference to this protocol object. */
            std::shared_ptr<InternetControlMessageProtocol> InternetControlMessageProtocol::GetReference() noexcept {
                return shared_from_this();
            }

            /** @brief Returns the IO context associated with this protocol helper. */
            std::shared_ptr<boost::asio::io_context> InternetControlMessageProtocol::GetContext() noexcept {
                return executor_;
            }

            /** @brief Posts protocol finalization onto the bound executor. */
            void InternetControlMessageProtocol::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context,
                    [self, this, context]() noexcept {
                        Finalize();
                    });
            }

            /**
             * @brief Sends an ICMP echo request and asynchronously awaits response.
             *
             * The outgoing request is NAT-tagged with a unique identifier, then a timeout
             * protected receive loop parses and correlates inbound ICMP packets.
             */
            bool InternetControlMessageProtocol::Echo(
                const std::shared_ptr<IPFrame>&         packet,
                const std::shared_ptr<IcmpFrame>&       frame,
                const IPEndPoint&                       destinationEP) noexcept {

                using EchoAsynchronousContext = InternetControlMessageProtocol_EchoAsynchronousContext;

                if (true == disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IcmpProtocolEchoDisposed);
                    return false;
                }

                if (NULLPTR == packet || NULLPTR == frame) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return false;
                }

                const std::shared_ptr<BufferSegment> messages = packet->Payload;
                if (NULLPTR == messages || NULLPTR == messages->Buffer || 1 > messages->Length) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                    return false;
                }

                const int sockfd = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
                if (sockfd == -1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketCreateFailed, false); /* ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP); */
                }
                else {
                    const int TTL = packet->Ttl;
                    if (::setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char*)&TTL, sizeof(TTL))) { // SOL_SOCKET, SO_SNDTIMEO, SO_RCVTIMEO
                        Socket::Closesocket(sockfd);
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketOptionSetFailed, false);
                    }
                }

                boost::system::error_code ec;
                const std::shared_ptr<boost::asio::ip::udp::socket> socket = make_shared_object<boost::asio::ip::udp::socket>(*executor_);
                if (!socket) {
                    Socket::Closesocket(sockfd);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketCreateFailed, false);
                }

                ppp::net::Socket::AdjustDefaultSocketOptional(sockfd, packet->AddressesFamily == AddressFamily::InterNetwork);
                ppp::net::Socket::SetTypeOfService(sockfd);
                ppp::net::Socket::SetSignalPipeline(sockfd, false);
                ppp::net::Socket::ReuseSocketAddress(sockfd, true);

                socket->assign(boost::asio::ip::udp::v4(), sockfd, ec);
                if (ec) {
                    Socket::Closesocket(sockfd);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketOpenFailed, false);
                }

                UInt32 identification_nat = 0;
                if (!InternetControlMessageProtocol_Global::GetDefault().Allocated(identification_nat)) {
                    Socket::Closesocket(socket);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ResourceExhaustedSockets, false);
                }

                const std::shared_ptr<EchoAsynchronousContext> context = make_shared_object<EchoAsynchronousContext>(identification_nat);
                if (!context) {
                    Socket::Closesocket(socket);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IcmpProtocolEchoContextAllocFailed, false);
                }
                else {
                    const std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = this->BufferAllocator;
                    const int copys[] = { frame->Identification,  frame->Sequence };
                    frame->Identification = (UInt16)(identification_nat >> 16);
                    frame->Sequence = (UInt16)(identification_nat);

                    const std::shared_ptr<IPFrame> packet_nat = frame->ToIp(allocator);
                    const std::shared_ptr<BufferSegment> messages_nat = packet_nat->Payload;
                    frame->Identification = copys[0];
                    frame->Sequence = copys[1];

                    boost::asio::ip::udp::endpoint remoteEP = IPEndPoint::WrapAddressV4<boost::asio::ip::udp>(packet->Destination, IPEndPoint::MaxPort);
                    socket->send_to(boost::asio::buffer(messages_nat->Buffer.get(), messages_nat->Length), remoteEP,
                        boost::asio::socket_base::message_end_of_record, ec);
                    if (ec) {
                        Socket::Closesocket(socket);
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketWriteFailed, false);
                    }
                }

                const std::weak_ptr<InternetControlMessageProtocol_EchoAsynchronousContext> context_weak(context);
                const std::shared_ptr<TimeoutEventHandler> timeout_cb = make_shared_object<TimeoutEventHandler>(
                    [context_weak](Timer*) noexcept {
                        const std::shared_ptr<EchoAsynchronousContext> context = context_weak.lock();
                        if (context) {
                            context->Release();
                        }
                    });
                if (!timeout_cb) {
                    Socket::Closesocket(socket);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IcmpProtocolEchoTimeoutCallbackAllocFailed, false);
                }

                context->timeout_ = Timer::Timeout(executor_, MAX_ICMP_TIMEOUT, *timeout_cb);
                context->owner_ = shared_from_this();
                context->socket_ = socket;
                context->destinationEP_ = destinationEP;
                context->request_.frame = frame;
                context->request_.packet = packet;

                bool emplaced;
                {
                    std::lock_guard<std::mutex> scope(timeouts_syncobj_);
                    emplaced = timeouts_.emplace(context.get(), timeout_cb).second;
                }

                if (!emplaced) {
                    context->Release();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IcmpProtocolEchoTimeoutEntryConflict, false);
                }

                /* Register before the first receive so a fast completion cannot outrun the insertion. */
                context->RunOnce();
                return true;
            }

            /** @brief Builds an ICMP echo-reply packet using request metadata. */
            std::shared_ptr<IPFrame> InternetControlMessageProtocol::ER(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, int ttl, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<IcmpFrame> e = make_shared_object<IcmpFrame>();
                if (NULLPTR == e) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IcmpProtocolEchoReplyFrameAllocFailed);
                    return NULLPTR;
                }

                e->AddressesFamily = frame->AddressesFamily;
                e->Destination = frame->Source;
                e->Source = frame->Destination;
                e->Payload = frame->Payload;
                e->Type = IcmpType::ICMP_ER;
                e->Code = frame->Code;
                e->Ttl = static_cast<Byte>(ttl);
                e->Sequence = frame->Sequence;
                e->Identification = frame->Identification;

                return e->ToIp(allocator);
            }

            /** @brief Builds an ICMP time-exceeded packet embedding original request data. */
            std::shared_ptr<IPFrame> InternetControlMessageProtocol::TE(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, UInt32 source, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<IcmpFrame> e = make_shared_object<IcmpFrame>();
                if (NULLPTR == e) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IcmpProtocolTimeExceededFrameAllocFailed);
                    return NULLPTR;
                }

                e->AddressesFamily = frame->AddressesFamily;
                e->Type = IcmpType::ICMP_TE;
                e->Code = 0;
                e->Ttl = UINT8_MAX;
                e->Sequence = 0;
                e->Identification = 0;
                e->Source = source;
                e->Destination = frame->Source;
                e->Payload = packet->ToArray(allocator);

                return e->ToIp(allocator);
            }
        }
    }
}
