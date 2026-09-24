#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/xtcp/XtcpFirstLegHooks.h>
#include <ppp/app/client/VEthernetNetworkTcpipForwarding.inl>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/routing/ProtocolSniffer.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/protocol/templates/TVEthernetTcpipConnection.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>

#include <array>
#include <vector>

#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/rinetd/RinetdConnection.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>

#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>

/**
 * @file VEthernetNetworkTcpipConnection.cpp
 * @brief Implements TCP/IP forwarding selection for virtual Ethernet sessions.
 * @license GPL-3.0
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace {
                bool XtcpMemoryBridgeEnabled() noexcept {
                    const char* env = ::getenv("OPENPPP2_XTCP_MEMORY_BRIDGE");
                    return env != nullptr && env[0] == '1' && env[1] == '\0';
                }
            }

            /** @brief Initializes session state and marks it active. */
            VEthernetNetworkTcpipConnection::VEthernetNetworkTcpipConnection(
                const std::shared_ptr<VEthernetExchanger>& exchanger,
                const std::shared_ptr<boost::asio::io_context>& context,
                const ppp::threading::Executors::StrandPtr& strand,
                routing::TcpRoutingMode routing_mode,
                const std::shared_ptr<const routing::HumanRoutingRules>& routing_rules,
                bool domain_sniff_candidate) noexcept
                : TapTcpClient(context, strand)
                , exchanger_(exchanger)
                , routing_mode_(routing_mode)
                , routing_rules_(routing_rules)
                , domain_sniff_candidate_(domain_sniff_candidate) {
                Update();
            }

            void VEthernetNetworkTcpipConnection::SetExternalFirstLeg(
                uint64_t runtime_generation,
                uint64_t flow_generation,
                const std::weak_ptr<xtcp::XtcpFirstLegHooks>& hooks) noexcept {
                external_runtime_generation_ = runtime_generation;
                external_flow_generation_ = flow_generation;
                external_first_leg_hooks_ = hooks;
            }

            /** @brief Finalizes owned forwarding channels. */
            VEthernetNetworkTcpipConnection::~VEthernetNetworkTcpipConnection() noexcept {
                if (!external_closed_signaled_.exchange(true, std::memory_order_acq_rel)) {
                    if (std::shared_ptr<xtcp::XtcpFirstLegHooks> hooks = external_first_leg_hooks_.lock()) {
                        hooks->OnFirstLegClosed(
                            external_runtime_generation_, external_flow_generation_);
                    }
                }
                Finalize();
            }

            /** @brief Disposes any active VPN/rinetd/vmux connection objects. */
            void VEthernetNetworkTcpipConnection::Finalize() noexcept {
                {
                    std::lock_guard<std::mutex> lock(external_direct_sync_);
                    external_direct_connection_.reset();
                }
                std::shared_ptr<VirtualEthernetTcpipConnection> connection = std::move(connection_);
                std::shared_ptr<RinetdConnection> connection_rinetd = std::move(connection_rinetd_);
                std::shared_ptr<vmux::vmux_skt> connection_mux = std::move(connection_mux_);

#if defined(_IPHONE) || defined(IPHONE)
                ReleaseIosChildTransmissionSlot();
#endif

                if (NULLPTR != connection) {
                    connection->Dispose();
                }

                if (NULLPTR != connection_rinetd) {
                    connection_rinetd->Dispose();
                }

                if (NULLPTR != connection_mux) {
                    connection_mux->close();
                }
            }

            xtcp::XtcpDirectResult VEthernetNetworkTcpipConnection::SendToPeer(
                const std::uint8_t* data, std::uint32_t length,
                xtcp::XtcpUploadBudget::Reservation&& credit) noexcept {
                std::shared_ptr<VirtualEthernetTcpipConnection> connection;
                {
                    std::lock_guard<std::mutex> lock(external_direct_sync_);
                    connection = external_direct_connection_.lock();
                }
                if (!connection) {
                    return xtcp::XtcpDirectResult::Closed;
                }
                switch (connection->SendDirectToPeer(data, length, std::move(credit))) {
                case VirtualEthernetTcpipConnection::DirectIoResult::Accepted:
                    return xtcp::XtcpDirectResult::Accepted;
                case VirtualEthernetTcpipConnection::DirectIoResult::Backpressured:
                    return xtcp::XtcpDirectResult::Backpressured;
                default:
                    return xtcp::XtcpDirectResult::Closed;
                }
            }

            void VEthernetNetworkTcpipConnection::OnDownloadComplete(
                const xtcp::XtcpDirectReadReservation& reservation,
                xtcp::XtcpDirectCompletion completion) noexcept {
                std::shared_ptr<VirtualEthernetTcpipConnection> connection;
                {
                    std::lock_guard<std::mutex> lock(external_direct_sync_);
                    connection = external_direct_connection_.lock();
                }
                if (connection) {
                    connection->CompleteDirectDownload(reservation, completion);
                }
            }

            void VEthernetNetworkTcpipConnection::SetDirectQueueTelemetry(
                const std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry>& telemetry) noexcept {
                std::shared_ptr<VirtualEthernetTcpipConnection> connection;
                {
                    std::lock_guard<std::mutex> lock(external_direct_sync_);
                    connection = external_direct_connection_.lock();
                }
                if (connection) {
                    connection->SetDirectQueueTelemetry(telemetry);
                }
            }

            void VEthernetNetworkTcpipConnection::ClosePeerSend() noexcept {
                std::shared_ptr<VirtualEthernetTcpipConnection> connection;
                {
                    std::lock_guard<std::mutex> lock(external_direct_sync_);
                    connection = external_direct_connection_.lock();
                }
                if (connection) {
                    connection->CloseDirectSend();
                }
            }

            /**
             * @brief Schedules cleanup on the proper executor and disposes the base client.
             */
            void VEthernetNetworkTcpipConnection::Dispose() noexcept {
                if (IsDisposed()) {
                    return;
                }

                if (!external_closed_signaled_.exchange(true, std::memory_order_acq_rel)) {
                    if (std::shared_ptr<xtcp::XtcpFirstLegHooks> hooks = external_first_leg_hooks_.lock()) {
                        hooks->OnFirstLegClosed(
                            external_runtime_generation_, external_flow_generation_);
                    }
                }

                auto self = shared_from_this();
                auto socket = GetSocket();

                if (NULLPTR != socket) {
                    boost::asio::post(socket->get_executor(),
                        [self, this, socket]() noexcept {
                            Finalize();
                        });
                }
                else {
                    ppp::threading::Executors::ContextPtr context = GetContext();
                    ppp::threading::Executors::StrandPtr strand = GetStrand();

                    ppp::threading::Executors::Post(context, strand,
                        [self, this, context, strand]() noexcept {
                            Finalize();
                        });
                }

                TapTcpClient::Dispose();
            }

#if defined(_IPHONE) || defined(IPHONE)
            void VEthernetNetworkTcpipConnection::ReleaseIosChildTransmissionSlot() noexcept {
                if (!ios_child_transmission_slot_held_) {
                    return;
                }

                ios_child_transmission_slot_held_ = false;
                uint64_t slot_generation = ios_child_transmission_slot_generation_;
                ios_child_transmission_slot_generation_ = 0;
                if (std::shared_ptr<VEthernetExchanger> exchanger = exchanger_) {
                    exchanger->ReleaseIosChildTransmissionSlot(slot_generation);
                }
            }
#endif

            /**
             * @brief Runs whichever forwarding path is currently active.
             * @return true when forwarding loop runs successfully.
             */
            bool VEthernetNetworkTcpipConnection::Loopback(ppp::coroutines::YieldContext& y) noexcept {
                // If the connection is interrupted while the coroutine is working,
                // Or closed during other asynchronous processes or coroutines, do not perform meaningless processing.
                if (IsDisposed()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                // If rinetd local loopback link forwarding is not used, failure will be returned,
                // Otherwise the link to the peer will be processed successfully.
                if (std::shared_ptr<RinetdConnection> connection_rinetd = connection_rinetd_; NULLPTR != connection_rinetd) {
                    return connection_rinetd->Run();
                }

                // If the link is relayed through the VPN remote switcher, then run the VPN link relay subroutine.
                if (std::shared_ptr<VirtualEthernetTcpipConnection> connection = connection_; NULLPTR != connection) {
#if defined(_IPHONE)
                    // iOS ctcp: AckAccept() already starts StartNativeTapRelay() on the child
                    // transmission for download; upload uses native_upload_queue_. Run() would
                    // also read that transmission (EVP 3-byte header first) and race.
                    while (!IsDisposed() && connection->IsLinked()) {
                        connection->Update();
                        ppp::coroutines::asio::async_sleep(y, 100);
                    }
                    return !IsDisposed();
#else
                    bool ok = connection->Run(y);
                    IDisposable::DisposeReferences(connection);
                    return ok;
#endif
                }

                if (std::shared_ptr<vmux::vmux_skt> connection_mux = connection_mux_; NULLPTR != connection_mux) {
                    return connection_mux->run();
                }

                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                return false;
            }

            /**
             * @brief Builds forwarding to the peer using rinetd, vmux, or VPN transport.
             * @return true when one forwarding path is prepared successfully.
             */
            bool VEthernetNetworkTcpipConnection::ConnectToPeer(ppp::coroutines::YieldContext& y) noexcept {
                using VEthernetTcpipConnection = ppp::app::protocol::templates::TVEthernetTcpipConnection<TapTcpClient>;

                // Create a link and correctly establish a link between remote peers,
                // Indicating whether to use VPN link or Rinetd local loopback forwarding.
                do {
                    std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                    if (NULLPTR == exchanger) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                        return false;
                    }

                    if (IsDisposed()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return false;
                    }

                    std::shared_ptr<boost::asio::io_context> context = GetContext();
                    if (NULLPTR == context) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                        return false;
                    }

                    std::shared_ptr<AppConfiguration> configuration = exchanger->GetConfiguration();
                    if (NULLPTR == configuration) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                        return false;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = GetSocket();
                    if (NULLPTR == socket) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                        return false;
                    }

                    auto self = shared_from_this();
                    auto strand = GetStrand();
                    boost::asio::ip::tcp::endpoint remoteEP = GetRemoteEndPoint();

#if defined(_IPHONE) || defined(IPHONE)
                    if (routing_mode_ == routing::TcpRoutingMode::ForceDirect) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpConnectFailed);
                        return false;
                    }
#else
                    if (routing_mode_ != routing::TcpRoutingMode::ForceProxy) {
                        const bool force_direct =
                            routing_mode_ == routing::TcpRoutingMode::ForceDirect;
                        const int rinetd_status = Rinetd(
                            self, exchanger, context, strand, configuration, socket,
                            remoteEP, force_direct, connection_rinetd_, y);
                        if (rinetd_status == 0) {
                            break;
                        }

                        if (rinetd_status < 0) {
                            ppp::telemetry::Count("tcpip.peer_connect.fail.rinetd", 1);
                            ppp::telemetry::Log(
                                ppp::telemetry::Level::kInfo,
                                "tcpip",
                                force_direct
                                    ? "peer connect failed: stage=rinetd remote=%s:%u error=%d fallback=none"
                                    : "peer connect failed: stage=rinetd remote=%s:%u error=%d fallback=vpn",
                                remoteEP.address().to_string().c_str(),
                                remoteEP.port(),
                                (int)ppp::diagnostics::GetLastErrorCode());
                            connection_rinetd_.reset();
                        }
                        if (force_direct) {
                            if (rinetd_status > 0) {
                                ppp::diagnostics::SetLastErrorCode(
                                    ppp::diagnostics::ErrorCode::TcpConnectFailed);
                            }
                            return false;
                        }
                    }
#endif

                    int mux_status = Mux(self, exchanger, remoteEP, socket, connection_mux_, y);
                    if (mux_status < 1) {
                        if (mux_status < 0) {
                            ppp::telemetry::Count("tcpip.peer_connect.fail.mux", 1);
                            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip", "peer connect failed: stage=mux remote=%s:%u error=%d", remoteEP.address().to_string().c_str(), remoteEP.port(), (int)ppp::diagnostics::GetLastErrorCode());
                            if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                            }
                        }
                        return mux_status == 0;
                    }

#if defined(_IPHONE)
                    uint64_t ios_child_slot_generation = 0;
                    std::shared_ptr<ppp::transmissions::ITransmission> transmission =
                        exchanger->ConnectTransmission(context, strand, y, &ios_child_slot_generation);
#else
                    std::shared_ptr<ppp::transmissions::ITransmission> transmission =
                        exchanger->ConnectTransmission(context, strand, y);
#endif
                    if (NULLPTR == transmission) {
                        ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCode();
                        ppp::telemetry::Count("tcpip.peer_connect.fail.transport", 1);
                        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip", "peer connect failed: stage=transport remote=%s:%u error=%d", remoteEP.address().to_string().c_str(), remoteEP.port(), (int)code);
                        if (code == ppp::diagnostics::ErrorCode::Success) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                        }
                        return false;
                    }

                    std::shared_ptr<VEthernetTcpipConnection> connection =
                        make_shared_object<VEthernetTcpipConnection>(self, configuration, context, strand, exchanger->GetId(), socket);
                    if (NULLPTR == connection) {
                        IDisposable::DisposeReferences(transmission);
#if defined(_IPHONE)
                        exchanger->ReleaseIosChildTransmissionSlot(ios_child_slot_generation);
#endif
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        return false;
                    }

#if defined(_LINUX)
                    auto switcher = exchanger->GetSwitcher();
                    if (NULLPTR != switcher) {
                        connection->ProtectorNetwork = switcher->GetProtectorNetwork();
                    }
#endif

                    bool ok = connection->Connect(y, transmission, ppp::net::Ipep::ToAddressString<ppp::string>(remoteEP), remoteEP.port());
                    if (!ok) {
                        ppp::telemetry::Count("tcpip.peer_connect.fail.vpn", 1);
                        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip", "peer connect failed: stage=vpn remote=%s:%u error=%d", remoteEP.address().to_string().c_str(), remoteEP.port(), (int)ppp::diagnostics::GetLastErrorCode());
                        IDisposable::DisposeReferences(connection, transmission);
#if defined(_IPHONE)
                        exchanger->ReleaseIosChildTransmissionSlot(ios_child_slot_generation);
#endif
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionOpenFailed);
                        return false;
                    }

                    ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "tcpip", "peer connect ok remote=%s:%u", remoteEP.address().to_string().c_str(), remoteEP.port());
#if defined(_IPHONE)
                    if (ios_child_slot_generation != 0) {
                        ios_child_transmission_slot_held_ = true;
                        ios_child_transmission_slot_generation_ = ios_child_slot_generation;
                    }
#endif
                    connection_ = std::move(connection);
                } while (false);
                return true;
            }

            /** @brief Performs bounded, non-consuming initial-payload domain inspection. */
            bool VEthernetNetworkTcpipConnection::SniffDomainRouting(
                ppp::coroutines::YieldContext& y) noexcept {
                constexpr uint64_t kSniffTimeoutMilliseconds = 250;
                constexpr uint64_t kSniffPollMilliseconds = 5;

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = GetSocket();
                std::shared_ptr<const routing::HumanRoutingRules> rules = routing_rules_;
                if (NULLPTR == socket || !socket->is_open() || NULLPTR == rules) {
                    return false;
                }

                routing::ProtocolSniffer sniffer;
                routing::ProtocolSnifferResult result;
                std::array<unsigned char, routing::ProtocolSniffer::MaxInputSize> peek_buffer{};
                std::size_t fed_size = 0;
                const uint64_t started_at = ppp::threading::Executors::GetTickCount();
                const bool was_non_blocking = socket->non_blocking();
                boost::system::error_code ec;
                socket->non_blocking(true, ec);

                const char* outcome = "timeout";
                if (ec) {
                    outcome = "io_error";
                }
                else {
                    while (result.status == routing::ProtocolSnifferStatus::NeedMore) {
                        if (IsDisposed() || !socket->is_open()) {
                            outcome = "disposed";
                            break;
                        }
                        if (ppp::threading::Executors::GetTickCount() - started_at >=
                            kSniffTimeoutMilliseconds) {
                            outcome = "timeout";
                            break;
                        }

                        ec.clear();
                        const std::size_t peeked = socket->receive(
                            boost::asio::buffer(peek_buffer),
                            boost::asio::socket_base::message_peek, ec);
                        if (!ec) {
                            if (peeked > fed_size) {
                                result = sniffer.Feed(
                                    peek_buffer.data() + fed_size, peeked - fed_size);
                                fed_size = peeked;
                            }
                            if (peeked == peek_buffer.size() &&
                                result.status == routing::ProtocolSnifferStatus::NeedMore) {
                                result.status = routing::ProtocolSnifferStatus::LimitExceeded;
                            }
                        }
                        else if (ec != boost::asio::error::would_block &&
                            ec != boost::asio::error::try_again) {
                            outcome = ec == boost::asio::error::eof ? "eof" : "io_error";
                            break;
                        }

                        if (result.status == routing::ProtocolSnifferStatus::NeedMore) {
                            ppp::coroutines::asio::async_sleep(y, kSniffPollMilliseconds);
                        }
                    }

                    switch (result.status) {
                    case routing::ProtocolSnifferStatus::Complete:
                        outcome = "complete";
                        break;
                    case routing::ProtocolSnifferStatus::Unsupported:
                        outcome = "unsupported";
                        break;
                    case routing::ProtocolSnifferStatus::Malformed:
                        outcome = "malformed";
                        break;
                    case routing::ProtocolSnifferStatus::LimitExceeded:
                        outcome = "limit_exceeded";
                        break;
                    default:
                        break;
                    }
                }

                boost::system::error_code restore_ec;
                if (socket->is_open()) {
                    socket->non_blocking(was_non_blocking, restore_ec);
                }

                const char* source = "ip_fallback";
                const char* action = "ip_fallback";
                if (restore_ec) {
                    outcome = "restore_error";
                }
                else if (result.status == routing::ProtocolSnifferStatus::Complete) {
                    source = result.source == routing::ProtocolSnifferSource::TlsSni
                        ? "tls_sni" : "http_host";
                    const routing::RoutingMatch match = rules->MatchDomainRule(result.domain);
                    if (match.matched) {
                        routing::TcpRoutingSelectorInput selector_input;
                        selector_input.action = match.action;
                        const routing::TcpRoutingMode selected_mode =
                            routing::TcpRoutingSelector::Select(selector_input);
                        if (selected_mode == routing::TcpRoutingMode::ForceDirect ||
                            selected_mode == routing::TcpRoutingMode::ForceProxy) {
                            routing_mode_ = selected_mode;
                            action = selected_mode == routing::TcpRoutingMode::ForceDirect
                                ? "direct" : "proxy";
                        }
                    }
                    else {
                        outcome = "no_match";
                    }
                }

                ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "tcpip_sniff",
                    "source=%s outcome=%s action=%s", source, outcome, action);
                return !restore_ec && !IsDisposed();
            }

#if defined(_WIN32)
#pragma optimize("", off)
#pragma optimize("gsyb2", on) /* /O1 = /Og /Os /Oy /Ob2 /GF /Gy */
#else
/**
 * @brief Applies conservative compiler optimization for coroutine-sensitive code paths.
 *
 * For older GCC versions (<= 7.5.x), O1 is used to avoid known optimizer-induced
 * crashes in this section. For newer versions, optimization is disabled here to
 * keep runtime behavior stable across toolchains.
 */
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
            /** @brief Starts established-stage forwarding coroutine execution. */
            bool VEthernetNetworkTcpipConnection::Establish() noexcept {
                if (!domain_sniff_candidate_) {
                    return Spawn(
                        [this](ppp::coroutines::YieldContext& y) noexcept {
                            return Loopback(y);
                        });
                }

                return Spawn(
                    [this](ppp::coroutines::YieldContext& y) noexcept {
                        if (!SniffDomainRouting(y) || !ConnectToPeer(y)) {
                            return false;
                        }
                        return Loopback(y);
                    });
            }

            /** @brief Starts peer setup coroutine before accept acknowledgement. */
            bool VEthernetNetworkTcpipConnection::BeginAccept() noexcept {
                if (domain_sniff_candidate_) {
                    return AckAccept();
                }

                ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "tcpip", "begin accept coroutine post remote=%s:%u", GetRemoteEndPoint().address().to_string().c_str(), GetRemoteEndPoint().port());
                // mux=0: let ConnectTransmission queue for an iOS child slot instead of
                // rejecting SYN here (speed tests open 16+ parallel flows to CDN edges).
                return Spawn(
                    [this](ppp::coroutines::YieldContext& y) noexcept {
                        bool connected = ConnectToPeer(y);
                        ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCode();
                        ppp::telemetry::Log(connected ? ppp::telemetry::Level::kDebug : ppp::telemetry::Level::kInfo, "tcpip", "connect peer result=%d remote=%s:%u error=%d", connected ? 1 : 0, GetRemoteEndPoint().address().to_string().c_str(), GetRemoteEndPoint().port(), connected ? 0 : (int)code);
                        if (!connected) {
                            return false;
                        }
                        bool acked = AckAccept();
                        ppp::telemetry::Log(acked ? ppp::telemetry::Level::kDebug : ppp::telemetry::Level::kInfo, "tcpip", "ack accept result=%d remote=%s:%u", acked ? 1 : 0, GetRemoteEndPoint().address().to_string().c_str(), GetRemoteEndPoint().port());
                        return acked;
                    });
            }

            bool VEthernetNetworkTcpipConnection::AckAccept() noexcept {
                if (!IsExternal()) {
                    return TapTcpClient::AckAccept();
                }
                if (external_ready_signaled_.exchange(true, std::memory_order_acq_rel)) {
                    return true;
                }
                std::shared_ptr<xtcp::XtcpFirstLegHooks> hooks = external_first_leg_hooks_.lock();
                if (NULLPTR == hooks) {
                    return false;
                }
                const bool direct_requested = XtcpMemoryBridgeEnabled();
                const std::shared_ptr<VirtualEthernetTcpipConnection> direct_connection = connection_;
                if (direct_requested && !domain_sniff_candidate_ && direct_connection &&
                    direct_connection->IsLinked()) {
                    const std::weak_ptr<xtcp::XtcpFirstLegHooks> weak_hooks = external_first_leg_hooks_;
                    const std::uint64_t runtime_generation = external_runtime_generation_;
                    const std::uint64_t flow_generation = external_flow_generation_;
                    if (direct_connection->StartDirectBridge(
                            [weak_hooks, runtime_generation, flow_generation](
                                xtcp::XtcpDirectReadReservation& reservation,
                                const std::shared_ptr<Byte>& payload) noexcept {
                                if (!payload || reservation.length == 0) {
                                    return VirtualEthernetTcpipConnection::DirectIoResult::Closed;
                                }
                                if (reservation.runtime_generation == 0) {
                                    reservation.runtime_generation = runtime_generation;
                                }
                                else if (reservation.runtime_generation != runtime_generation) {
                                    return VirtualEthernetTcpipConnection::DirectIoResult::Closed;
                                }
                                if (reservation.flow_generation == 0) {
                                    reservation.flow_generation = flow_generation;
                                }
                                else if (reservation.flow_generation != flow_generation) {
                                    return VirtualEthernetTcpipConnection::DirectIoResult::Closed;
                                }
                                const std::shared_ptr<xtcp::XtcpFirstLegHooks> active = weak_hooks.lock();
                                if (!active) {
                                    return VirtualEthernetTcpipConnection::DirectIoResult::Closed;
                                }
                                switch (active->OnSecondLegPayload(reservation, payload)) {
                                case xtcp::XtcpDirectResult::Accepted:
                                    return VirtualEthernetTcpipConnection::DirectIoResult::Accepted;
                                case xtcp::XtcpDirectResult::Backpressured:
                                    return VirtualEthernetTcpipConnection::DirectIoResult::Backpressured;
                                default:
                                    return VirtualEthernetTcpipConnection::DirectIoResult::Closed;
                                }
                            },
                            [weak_hooks, runtime_generation, flow_generation](
                                xtcp::XtcpDirectCloseReason reason) noexcept {
                                if (const std::shared_ptr<xtcp::XtcpFirstLegHooks> active = weak_hooks.lock()) {
                                    if (reason == xtcp::XtcpDirectCloseReason::PeerEof) {
                                        active->OnSecondLegClosed(runtime_generation, flow_generation);
                                    }
                                    else {
                                        active->OnFirstLegClosed(runtime_generation, flow_generation);
                                    }
                                }
                            },
                            [weak_hooks, runtime_generation, flow_generation]() noexcept {
                                if (const std::shared_ptr<xtcp::XtcpFirstLegHooks> active = weak_hooks.lock()) {
                                    active->OnSecondLegWritable(runtime_generation, flow_generation);
                                }
                            })) {
                        {
                            std::lock_guard<std::mutex> lock(external_direct_sync_);
                            external_direct_connection_ = direct_connection;
                        }
                        const std::shared_ptr<VEthernetNetworkTcpipConnection> self =
                            std::static_pointer_cast<VEthernetNetworkTcpipConnection>(shared_from_this());
                        hooks->OnFirstLegDirectReady(
                            runtime_generation, flow_generation, self);
                        return true;
                    }
                }
                if (direct_requested) {
                    hooks->OnDirectBridgeFallback(
                        external_runtime_generation_, external_flow_generation_);
                }
                hooks->OnFirstLegReady(
                    external_runtime_generation_, external_flow_generation_);
                return Establish();
            }

            /**
             * @brief Posts a coroutine launcher to the session strand.
             * @return true when posting succeeds.
             */
            bool VEthernetNetworkTcpipConnection::Spawn(const ppp::function<bool(ppp::coroutines::YieldContext&)>& coroutine) noexcept {
                if (IsDisposed()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (NULLPTR == coroutine) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VEthernetNetworkTcpipConnectionSpawnNullCoroutine);
                    return false;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = exchanger->GetConfiguration();
                if (NULLPTR == configuration) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                    return false;
                }

                ppp::threading::Executors::ContextPtr context = GetContext();
                if (NULLPTR == context) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                    return false;
                }

                auto self = shared_from_this();
                ppp::threading::Executors::StrandPtr strand = GetStrand();

                auto post_work =
                    [self, this, context, strand, coroutine, configuration]() noexcept {
                        auto spawn_work =
                            [self, this, context, strand, coroutine](ppp::coroutines::YieldContext& y) noexcept {
                               bool ok = coroutine(y);
                               if (!ok) {
                                   Dispose();
                               }
                           };

                        auto allocator = configuration->GetBufferAllocator();
                        bool spawned = ppp::coroutines::YieldContext::Spawn(allocator.get(), *context, strand.get(), spawn_work);
                        if (!spawned) {
                            IDisposable::Dispose(this);
                        }
                    };

                bool posted = ppp::threading::Executors::Post(context, strand, post_work);
                if (!posted) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
                    return false;
                }

                return true;
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

            /**
             * @brief Tunes accepted socket options and delegates to base accept end.
             */
            bool VEthernetNetworkTcpipConnection::EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept {
                if (NULLPTR == socket) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                    return false;
                }

                if (!socket->is_open()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketNotOpen);
                    return false;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = exchanger->GetConfiguration();
                if (NULLPTR == configuration) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                    return false;
                }

                ppp::net::Socket::AdjustDefaultSocketOptional(*socket, configuration->tcp.turbo);
                ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);

                return TapTcpClient::EndAccept(socket, natEP);
            }

#if defined(_IPHONE) || defined(IPHONE)
            bool VEthernetNetworkTcpipConnection::StartNativeRelay() noexcept {
                std::weak_ptr<ppp::ethernet::VNetstack::TapTcpClient> weak_self = shared_from_this();
                auto relay_callback =
                    [weak_self](const void* data, size_t len) noexcept {
                        std::shared_ptr<ppp::ethernet::VNetstack::TapTcpClient> self = weak_self.lock();
                        if (NULLPTR != self && len > 0) {
                            self->EmitNativeToClient(data, (int)len);
                        }
                    };

                std::shared_ptr<RinetdConnection> rinetd = connection_rinetd_;
                if (NULLPTR != rinetd) {
                    std::shared_ptr<boost::asio::ip::tcp::socket> remote = rinetd->GetRemoteSocket();
                    if (NULLPTR != remote && remote->is_open() && NULLPTR != owner_.lock()) {
                        rinetd->StartRemoteToTapRelay(relay_callback);
                        ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "tcpip", "native inject ready mode=rinetd remote=%s:%u",
                            GetRemoteEndPoint().address().to_string().c_str(), GetRemoteEndPoint().port());
                        return true;
                    }
                }

                std::shared_ptr<VirtualEthernetTcpipConnection> vpn = connection_;
                if (NULLPTR != vpn && vpn->IsLinked() && NULLPTR != owner_.lock()) {
                    std::shared_ptr<VEthernetNetworkTcpipConnection> self =
                        std::static_pointer_cast<VEthernetNetworkTcpipConnection>(shared_from_this());
                    std::weak_ptr<VEthernetNetworkTcpipConnection> weak_self = self;
                    auto shutdown_callback =
                        [weak_self]() noexcept {
                            std::shared_ptr<VEthernetNetworkTcpipConnection> self = weak_self.lock();
                            if (NULLPTR != self) {
                                bool fin_ok = self->EmitNativeToClient(NULLPTR, 0,
                                    ppp::ethernet::VNetstack::tcp_hdr::TCP_FIN |
                                    ppp::ethernet::VNetstack::tcp_hdr::TCP_ACK);
                                ppp::telemetry::Log(fin_ok ? ppp::telemetry::Level::kDebug : ppp::telemetry::Level::kInfo,
                                    "tcpip",
                                    "native inject remote fin emitted ok=%d remote=%s:%u",
                                    fin_ok ? 1 : 0,
                                    self->GetRemoteEndPoint().address().to_string().c_str(),
                                    self->GetRemoteEndPoint().port());

                                self->ReleaseIosChildTransmissionSlot();
                                std::shared_ptr<VirtualEthernetTcpipConnection> vpn = self->connection_;
                                if (NULLPTR != vpn) {
                                    vpn->DisposeNativeTransportOnly();
                                }
                            }
                        };

                    if (vpn->StartNativeTapRelay(relay_callback, shutdown_callback)) {
                        ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "tcpip", "native inject ready mode=vpn remote=%s:%u",
                            GetRemoteEndPoint().address().to_string().c_str(), GetRemoteEndPoint().port());
                        return true;
                    }
                }

                return false;
            }

            bool VEthernetNetworkTcpipConnection::DeliverNativePayload(ppp::ethernet::VNetstack::tcp_hdr* tcp, int tcp_len) noexcept {
                if (NULLPTR == tcp || tcp_len < 1) {
                    return false;
                }

                const uint32_t hdrlen_bytes = ppp::ethernet::VNetstack::tcp_hdr::TCPH_HDRLEN_BYTES(tcp);
                if (tcp_len < (int)hdrlen_bytes) {
                    return false;
                }

                const int payload_len = tcp_len - (int)hdrlen_bytes;
                const uint8_t* payload = (const uint8_t*)tcp + hdrlen_bytes;
                const uint8_t tcp_flags = ppp::ethernet::VNetstack::tcp_hdr::TCPH_FLAGS(tcp);

                if (payload_len < 1) {
                    if (!UpdateNativeClientAck(tcp, tcp_len)) {
                        return false;
                    }

                    if (tcp_flags & ppp::ethernet::VNetstack::tcp_hdr::TCP_RST) {
                        std::shared_ptr<VirtualEthernetTcpipConnection> vpn = connection_;
                        if (NULLPTR != vpn) {
                            vpn->DisposeNativeTransportOnly();
                        }
                        ReleaseIosChildTransmissionSlot();
                        Dispose();
                        return true;
                    }

                    if (tcp_flags & ppp::ethernet::VNetstack::tcp_hdr::TCP_FIN) {
                        EmitNativeToClient(NULLPTR, 0);
                        std::shared_ptr<VirtualEthernetTcpipConnection> vpn = connection_;
                        if (NULLPTR != vpn) {
                            vpn->DisposeNativeTransportOnly();
                        }
                        ReleaseIosChildTransmissionSlot();
                        Dispose();
                        return true;
                    }
                    return true;
                }

                std::shared_ptr<std::vector<Byte>> payload_copy = std::make_shared<std::vector<Byte>>((size_t)payload_len);
                if (NULLPTR == payload_copy) {
                    return false;
                }
                memcpy(payload_copy->data(), payload, (size_t)payload_len);

                if (std::shared_ptr<RinetdConnection> rinetd = connection_rinetd_; NULLPTR != rinetd) {
                    ppp::threading::Executors::ContextPtr context = GetContext();
                    ppp::threading::Executors::StrandPtr strand = GetStrand();
                    if (NULLPTR == context) {
                        return false;
                    }

                    std::shared_ptr<RinetdConnection> relay = rinetd;
                    auto post_work =
                        [relay, payload_copy]() noexcept {
                            relay->WriteRemote(payload_copy->data(), payload_copy->size());
                        };

                    if (NULLPTR != strand) {
                        bool posted = ppp::threading::Executors::Post(context, strand, post_work);
                        if (posted) {
                            if (!UpdateNativeClientAck(tcp, tcp_len)) {
                                return false;
                            }
                            EmitNativeToClient(nullptr, 0);
                        }
                        return posted;
                    }

                    boost::asio::post(*context, post_work);
                    if (!UpdateNativeClientAck(tcp, tcp_len)) {
                        return false;
                    }
                    EmitNativeToClient(nullptr, 0);
                    return true;
                }

                std::shared_ptr<VirtualEthernetTcpipConnection> vpn = connection_;
                if (NULLPTR == vpn) {
                    return false;
                }

                if (!vpn->IsLinked()) {
                    if (!UpdateNativeClientAck(tcp, tcp_len)) {
                        return false;
                    }

                    EmitNativeToClient(nullptr, 0);
                    ppp::telemetry::Count("tcpip.native_payload.after_remote_fin", 1);
                    return true;
                }

                bool queued = vpn->SendBufferToPeerAsync(payload_copy);
                if (queued) {
                    if (!UpdateNativeClientAck(tcp, tcp_len)) {
                        return false;
                    }
                    // ACK upload segments only after enqueue succeeds; otherwise iOS will
                    // retransmit and naturally slow down instead of us silently dropping data.
                    EmitNativeToClient(nullptr, 0);
                }
                return queued;
            }
#endif
        }
    }
}
