#include "DnsUdpRelay.h"
#include "DnsRelayOperation.h"

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/dns/DnsWireValidation.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Timer.h>
#if defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

using ppp::threading::Timer;

#if defined(_ANDROID)
#include <android/log.h>

static bool AndroidDnsUdpRelayTraceEnabled() noexcept {
#ifdef NDEBUG
    return false;
#else
    return true;
#endif
}

#define ANDROID_DNS_UDP_RELAY_TRACE(...) \
    do { \
        if (AndroidDnsUdpRelayTraceEnabled()) { \
            __android_log_print(ANDROID_LOG_INFO, "openppp2", __VA_ARGS__); \
        } \
    } while (0)
#else
#define ANDROID_DNS_UDP_RELAY_TRACE(...) ((void)0)
#endif

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                namespace {

                    class RelayResources final {
                    public:
                        RelayResources(
                            DnsQueryContext query,
                            std::shared_ptr<boost::asio::ip::udp::socket> socket) noexcept
                            : query_(std::move(query)), socket_(std::move(socket)) {
                        }

                        bool Register(void* handle,
                            const std::shared_ptr<Timer::TimeoutEventHandler>& handler) noexcept {
                            std::lock_guard<std::mutex> lock(sync_);
                            if (cleaned_ || NULLPTR == handle) {
                                return false;
                            }
                            registry_handle_ = handle;
                            registered_ = query_.emplace_timeout(handle, handler);
                            return registered_;
                        }

                        void SetTimer(const std::shared_ptr<Timer>& timer) noexcept {
                            bool stop = false;
                            {
                                std::lock_guard<std::mutex> lock(sync_);
                                stop = cleaned_;
                                if (!stop) {
                                    timer_ = timer;
                                }
                            }
                            if (stop && timer) {
                                timer->Stop();
                                timer->Dispose();
                            }
                        }

                        void Cleanup() noexcept {
                            std::shared_ptr<Timer> timer;
                            bool registered;
                            void* registry_handle;
                            {
                                std::lock_guard<std::mutex> lock(sync_);
                                if (cleaned_) {
                                    return;
                                }
                                cleaned_ = true;
                                registered = registered_;
                                registered_ = false;
                                registry_handle = registry_handle_;
                                registry_handle_ = nullptr;
                                timer = timer_.lock();
                                timer_.reset();
                            }

                            if (registered) {
                                query_.delete_timeout(registry_handle);
                            }
                            ppp::net::Socket::Closesocket(socket_);
                            if (timer) {
                                timer->Stop();
                                timer->Dispose();
                            }
                        }

                    private:
                        std::mutex sync_;
                        bool registered_ = false;
                        bool cleaned_ = false;
                        void* registry_handle_ = nullptr;
                        std::weak_ptr<Timer> timer_;
                        DnsQueryContext query_;
                        std::shared_ptr<boost::asio::ip::udp::socket> socket_;
                    };

                    void ReceiveRelayResponse(
                        const DnsQueryContext& query,
                        const std::shared_ptr<DnsRelayOperation>& operation,
                        const std::shared_ptr<boost::asio::ip::udp::socket>& socket,
                        const std::shared_ptr<Byte>& buffer,
                        const std::shared_ptr<boost::asio::ip::udp::endpoint>& received_from,
                        const boost::asio::ip::udp::endpoint& server,
                        const boost::asio::ip::udp::endpoint& source,
                        const boost::asio::ip::udp::endpoint& destination,
                        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                        int handle) noexcept {

                        if (operation->GetCompletion() != DnsRelayOperation::Completion::Pending) {
                            return;
                        }

                        socket->async_receive_from(boost::asio::buffer(buffer.get(), PPP_BUFFER_SIZE), *received_from,
                            [query, operation, socket, buffer, received_from, server, source, destination,
                             messages, handle](boost::system::error_code ec, size_t size) noexcept {
                                if (ec == boost::system::errc::success && size > 0) {
                                    if (!DnsUdpRelay::ShouldAcceptRelayResponse(
                                            *received_from, server,
                                            messages->Buffer.get(), messages->Length,
                                            buffer.get(), static_cast<int>(size))) {
                                        ReceiveRelayResponse(query, operation, socket, buffer, received_from,
                                            server, source, destination, messages, handle);
                                        return;
                                    }

                                    ANDROID_DNS_UDP_RELAY_TRACE("dns_redirect recv ok fd=%d bytes=%d",
                                        handle, (int)size);
                                    operation->CompleteResponse(
                                        [query, buffer, source, destination, size]() noexcept {
                                            query.datagram_output(source, destination, buffer,
                                                buffer.get(), static_cast<int>(size), false);
                                        });
                                    return;
                                }

#if defined(_ANDROID)
                                __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect recv failed fd=%d ec=%d",
                                    handle, ec.value());
#endif
                                operation->CompleteFallback();
                            });
                    }

                }  // namespace

                bool DnsUdpRelay::RunCoroutine(
                    const DnsQueryContext& query,
                    ppp::coroutines::YieldContext& y,
                    const std::shared_ptr<boost::asio::ip::udp::socket>& socket,
                    const std::shared_ptr<Byte>& buffer,
                    const boost::asio::ip::address& serverIP,
                    const std::shared_ptr<const DnsSessionContext>& session,
                    const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                    const std::shared_ptr<boost::asio::io_context>& context,
                    const boost::asio::ip::udp::endpoint& sourceEP,
                    const boost::asio::ip::udp::endpoint& destinationEP,
                    bool use_underlying_nic) noexcept {

                    const std::weak_ptr<const DnsSessionContext> weak_session(session);
                    const auto resources = make_shared_object<RelayResources>(query, socket);
                    if (!resources) {
                        ppp::net::Socket::Closesocket(socket);
                        const auto active_session = weak_session.lock();
                        if (active_session && active_session->IsActive()) {
                            query.handle_resolver_response(
                                messages, sourceEP, destinationEP, ppp::vector<Byte>{});
                        }
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    const auto operation = make_shared_object<DnsRelayOperation>(
                        [resources]() noexcept { resources->Cleanup(); },
                        [query, messages, sourceEP, destinationEP]() noexcept {
                            query.handle_resolver_response(
                                messages, sourceEP, destinationEP, ppp::vector<Byte>{});
                        },
                        [weak_session]() noexcept {
                            const auto active_session = weak_session.lock();
                            return active_session && active_session->IsActive();
                        });
                    if (!operation) {
                        resources->Cleanup();
                        const auto active_session = weak_session.lock();
                        if (active_session && active_session->IsActive()) {
                            query.handle_resolver_response(
                                messages, sourceEP, destinationEP, ppp::vector<Byte>{});
                        }
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::udp::endpoint serverEP(serverIP, frame->Destination.Port);

                    bool opened = ppp::coroutines::asio::async_open(y, *socket, serverEP.protocol());
                    if (!opened) {
#if defined(_ANDROID)
                        __android_log_print(ANDROID_LOG_ERROR, "openppp2", "dns_redirect socket_open failed server=%s",
                            serverIP.to_string().c_str());
#endif
                        operation->CompleteFallback();
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                    }

                    int handle = socket->native_handle();
                    ANDROID_DNS_UDP_RELAY_TRACE("dns_redirect socket_open fd=%d server=%s port=%d",
                        handle,
                        serverIP.to_string().c_str(),
                        (int)frame->Destination.Port);
                    ppp::net::Socket::AdjustDefaultSocketOptional(handle, serverIP.is_v4());
                    ppp::net::Socket::SetTypeOfService(handle);
                    ppp::net::Socket::SetSignalPipeline(handle, false);
                    ppp::net::Socket::ReuseSocketAddress(handle, true);

#if defined(_ANDROID)
                    if (!serverIP.is_loopback()) {
                        auto protector_network = query.protector_network;
                        if (NULLPTR != protector_network) {
                            if (!protector_network->Protect(handle, y)) {
                                __android_log_print(ANDROID_LOG_ERROR, "openppp2", "dns_redirect protect failed fd=%d server=%s",
                                    handle,
                                    serverIP.to_string().c_str());
                                operation->CompleteFallback();
                                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed);
                            }
                            ANDROID_DNS_UDP_RELAY_TRACE("dns_redirect protect ok fd=%d server=%s",
                                handle,
                                serverIP.to_string().c_str());
                        }
                        else {
                            __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect protector missing fd=%d server=%s",
                                handle,
                                serverIP.to_string().c_str());
                        }
                    }
#elif defined(_LINUX)
                    if (!serverIP.is_loopback()) {
                        if (use_underlying_nic) {
                            auto protector_network = query.protector_network;
                            if (NULLPTR != protector_network && !protector_network->Protect(handle, y)) {
                                operation->CompleteFallback();
                                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed);
                            }
                        }
                        else {
                            socket->bind(boost::asio::ip::udp::endpoint(serverEP.protocol(), 0), ec);
                            if (ec || NULLPTR == query.udp_flow_registry) {
                                operation->CompleteFallback();
                                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                            }

                            const boost::asio::ip::udp::endpoint localEP = socket->local_endpoint(ec);
                            if (ec || !query.udp_flow_registry->Register(
                                    localEP.port(), serverEP,
                                    std::chrono::seconds(query.configuration->udp.dns.timeout + 1))) {
                                operation->CompleteFallback();
                                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                            }
                        }
                    }
#endif

                    socket->send_to(boost::asio::buffer(messages->Buffer.get(), messages->Length), serverEP,
                        boost::asio::socket_base::message_end_of_record, ec);
                    if (ec) {
#if defined(_ANDROID)
                        __android_log_print(ANDROID_LOG_ERROR, "openppp2", "dns_redirect send failed fd=%d server=%s ec=%d",
                            handle,
                            serverIP.to_string().c_str(),
                            ec.value());
#endif
                        operation->CompleteFallback();
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpSendFailed);
                    }
                    ANDROID_DNS_UDP_RELAY_TRACE("dns_redirect send ok fd=%d server=%s bytes=%d",
                        handle,
                        serverIP.to_string().c_str(),
                        NULLPTR != messages ? (int)messages->Length : -1);

                    const std::weak_ptr<DnsRelayOperation> weak_operation(operation);
                    const auto cb = make_shared_object<Timer::TimeoutEventHandler>(
                        [weak_operation, handle](Timer*) noexcept {
#if defined(_ANDROID)
                            __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect timeout fd=%d", handle);
#endif
                            const auto active_operation = weak_operation.lock();
                            if (active_operation) {
                                active_operation->CompleteFallback();
                            }
                        });
                    if (!cb) {
                        operation->CompleteFallback();
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    // The monotonically numbered operation owns a stable registration handle that
                    // remains valid until the single winner deregisters it during cleanup.
                    if (!resources->Register(operation->RegistryHandle(), cb)) {
                        operation->CompleteFallback();
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingEntryConflict);
                    }
                    if (operation->GetCompletion() != DnsRelayOperation::Completion::Pending) {
                        return true;
                    }

                    const auto timeout = Timer::Timeout(
                        context, (uint64_t)query.configuration->udp.dns.timeout * 1000, *cb);
                    if (!timeout) {
                        operation->CompleteFallback();
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                    }
                    resources->SetTimer(timeout);
                    if (operation->GetCompletion() != DnsRelayOperation::Completion::Pending) {
                        return true;
                    }

                    const auto received_from = make_shared_object<boost::asio::ip::udp::endpoint>();
                    if (!received_from) {
                        operation->CompleteFallback();
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    ReceiveRelayResponse(query, operation, socket, buffer, received_from,
                        serverEP, sourceEP, destinationEP, messages, handle);
                    return true;
                }

                bool DnsUdpRelay::Spawn(
                    const DnsQueryContext& query,
                    const std::shared_ptr<const DnsSessionContext>& session,
                    const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
                    const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                    const boost::asio::ip::address& serverIP,
                    const boost::asio::ip::address& destinationIP,
                    bool use_underlying_nic) noexcept {

                    if (!CanSpawn(query, session)) {
                        return false;
                    }

                    std::shared_ptr<boost::asio::io_context> context = query.io_context;
                    if (NULLPTR == context) {
                        return false;
                    }

                    std::shared_ptr<Byte> buffer;
                    if (query.allocator) {
                        buffer = ppp::threading::BufferswapAllocator::MakeByteArray(query.allocator, PPP_BUFFER_SIZE);
                    }
                    if (NULLPTR == buffer) {
                        buffer = std::shared_ptr<Byte>(new Byte[PPP_BUFFER_SIZE], std::default_delete<Byte[]>());
                    }

                    const std::shared_ptr<boost::asio::ip::udp::socket> socket =
                        make_shared_object<boost::asio::ip::udp::socket>(*context);
                    if (!socket) {
                        return false;
                    }

                    const boost::asio::ip::udp::endpoint sourceEP =
                        ppp::net::IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                    const boost::asio::ip::udp::endpoint destinationEP(destinationIP, frame->Destination.Port);

                    return ppp::coroutines::YieldContext::Spawn(query.allocator.get(), *context,
                        [query, socket, buffer, frame, messages, packet, context, serverIP, sourceEP, destinationEP, session, use_underlying_nic](ppp::coroutines::YieldContext& y) noexcept {
                            (void)packet;
                            return DnsUdpRelay::RunCoroutine(
                                query, y, socket, buffer, serverIP, session, frame, messages, context, sourceEP, destinationEP,
                                use_underlying_nic);
                        });
                }

            }
        }
    }
}
