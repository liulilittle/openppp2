#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/runtime/RuntimeXtcpStats.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/protocol/templates/TVEthernetTcpipConnection.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/DatapathPerfJson.h>
#include <ppp/diagnostics/TelemetryFwd.h>

#include <cstdlib>
#include <deque>
#include <vector>

#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

/**
 * @file VirtualEthernetTcpipConnection.cpp
 * @brief Implements TCP/IP connection handshake and bidirectional forwarding.
 * @author ("OPENPPP2 Team")
 * @license ("GPL-3.0")
 */

namespace ppp {
    namespace app {
        namespace protocol {
            namespace {
                void AddDirectUploadQueueTelemetry(
                    const std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry>& telemetry,
                    std::size_t bytes) noexcept {
                    if (telemetry) {
                        telemetry->Add(bytes);
                    }
                }

                void RemoveDirectUploadQueueTelemetry(
                    const std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry>& telemetry,
                    std::size_t bytes, std::size_t items) noexcept {
                    if (telemetry) {
                        telemetry->Remove(bytes, items);
                    }
                }
            }

            static constexpr int kTransmissionBinaryHeaderSize = 3;
            static constexpr int kPlaintextBase94MaxTcpReadSize = (PPP_BUFFER_SIZE / 2) - kTransmissionBinaryHeaderSize;
            static constexpr std::size_t kDirectUploadGatherDefaultBytes = 32 * 1024;
            static constexpr std::size_t kDirectUploadGatherCarrierMaxBytes = PPP_BUFFER_SIZE;

            static std::size_t GetDirectUploadGatherBytes(bool plaintext) noexcept {
                static const std::size_t requested = []() noexcept {
                    const char* value = std::getenv("OPENPPP2_XTCP_DIRECT_UPLOAD_GATHER_BYTES");
                    if (!value || !*value || *value == '-') {
                        return kDirectUploadGatherDefaultBytes;
                    }
                    char* end = nullptr;
                    const unsigned long long parsed = std::strtoull(value, &end, 10);
                    return end && *end == '\0'
                        ? static_cast<std::size_t>(std::min<unsigned long long>(
                            parsed, kDirectUploadGatherCarrierMaxBytes))
                        : kDirectUploadGatherDefaultBytes;
                }();
                return std::min(requested, plaintext
                    ? static_cast<std::size_t>(kPlaintextBase94MaxTcpReadSize)
                    : kDirectUploadGatherCarrierMaxBytes);
            }

            /**
             * @brief Temporary linklayer helper used during connect/accept handshake.
             */
            class STATIC_VIRTUAL_ETHERNET_TCPIP_CONNECTOR_NEST final : public VirtualEthernetLinklayer {
                friend class VirtualEthernetTcpipConnection;

            public:
                /**
                 * @brief Constructs handshake helper instance.
                 * @param connection Parent TCP/IP connection bridge.
                 * @param configuration Runtime configuration.
                 * @param context IO context.
                 * @param id Logical connection id.
                 * @return N/A.
                 * @note This object captures handshake packets and exposes decoded fields.
                 */
                STATIC_VIRTUAL_ETHERNET_TCPIP_CONNECTOR_NEST(
                    VirtualEthernetTcpipConnection*                         connection,
                    const AppConfigurationPtr&                              configuration,
                    const ContextPtr&                                       context,
                    const Int128&                                           id) noexcept
                    : VirtualEthernetLinklayer(configuration, context, id)
                    , ConnectId(0)
                    , ConnectOK(false)
                    , ErrorCode(0)
                    , Connect(false)
                    , Sequence(0)
                    , Acknowledge(0)
                    , Vlan(0)
                    , MuxON(false)
                    , connection_(connection) {

                }

            public:
                // PROTOCOL: PREPARED_CONNECT  CONNECT  CONNECT_OK
                int                                                         ConnectId;

                // PROTOCOL: PREPARED_CONNECT
                ppp::string                                                 Host;

                // PROTOCOL: CONNECT
                bool                                                        Connect;
                boost::asio::ip::tcp::endpoint                              Destination;

                // PROTOCOL: CONNECT_OK
                bool                                                        ConnectOK;
                Byte                                                        ErrorCode;

                // PROTOCOL: MUXON
                uint32_t                                                    Sequence;
                uint32_t                                                    Acknowledge;
                uint16_t                                                    Vlan;
                bool                                                        MuxON;

            public:
                /**
                 * @brief Returns firewall object from parent bridge.
                 * @return Firewall object or null.
                 * @note Used by linklayer pipeline for access checks.
                 */
                virtual std::shared_ptr<ppp::net::Firewall>                 GetFirewall() noexcept {
                    return connection_->GetFirewall();
                }
                /**
                 * @brief Handles PREPARED_CONNECT control message.
                 * @param transmission Active transmission channel.
                 * @param connection_id Connection identifier.
                 * @param destinationHost Destination host string.
                 * @param destinationEP Destination endpoint.
                 * @param y Coroutine yield context.
                 * @return Always true.
                 * @note Stores host for later logging.
                 */
                virtual bool                                                OnPreparedConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& destinationHost, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept override {
                    Host = destinationHost;
                    return true;
                }
                /**
                 * @brief Handles CONNECT control message.
                 * @param transmission Active transmission channel.
                 * @param connection_id Connection identifier.
                 * @param destinationEP Destination endpoint.
                 * @param y Coroutine yield context.
                 * @return Always true.
                 * @note Marks connect request as received and caches endpoint data.
                 */
                virtual bool                                                OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept override {
                    Connect = true;
                    ConnectId = connection_id;
                    Destination = destinationEP;
                    return true;
                }
                /**
                 * @brief Handles CONNECT_OK control message.
                 * @param transmission Active transmission channel.
                 * @param connection_id Connection identifier.
                 * @param error_code Handshake result code.
                 * @param y Coroutine yield context.
                 * @return Always true.
                 * @note Stores status for caller-side validation.
                 */
                virtual bool                                                OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept override {
                    ConnectOK = true;
                    ErrorCode = error_code;
                    ConnectId = connection_id;
                    return true;
                }
                /**
                 * @brief Handles MUXON control message.
                 * @param transmission Active transmission channel.
                 * @param vlan VLAN value.
                 * @param seq Sequence value.
                 * @param ack Acknowledge value.
                 * @param y Coroutine yield context.
                 * @return Always true.
                 * @note Stores mux tuple for strict handshake matching.
                 */
                virtual bool                                                OnMuxON(const ITransmissionPtr& transmission, uint16_t vlan, uint32_t seq, uint32_t ack, YieldContext& y) noexcept override {
                    MuxON = true;
                    Vlan = vlan;
                    Sequence = seq;
                    Acknowledge = ack;
                    return true;
                }

            private:
                VirtualEthernetTcpipConnection* const                       connection_;
            };

            /**
             * @brief Constructs TCP/IP bridge object.
             * @param configuration Runtime configuration.
             * @param context IO context.
             * @param strand Serialized executor.
             * @param id Logical connection id.
             * @param socket TCP socket object.
             * @return N/A.
             * @note Applies socket window/QoS hints when socket is available.
             */
            VirtualEthernetTcpipConnection::VirtualEthernetTcpipConnection(
                const AppConfigurationPtr&                              configuration,
                const ContextPtr&                                       context,
                const StrandPtr&                                        strand,
                const Int128&                                           id,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket) noexcept
                : disposed_(false)
                , connected_(false)
                , configuration_(configuration)
                , context_(context)
                , strand_(strand)
                , id_(id)
                , socket_(socket) {

                if (NULLPTR != socket) {
#if defined(_WIN32)
                    if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                        if (socket->is_open()) {
                            qoss_ = ppp::net::QoSS::New(socket->native_handle());
                        }
                    }
#endif
                    ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);
                }
            }

            /**
             * @brief Performs active connect handshake.
             * @param y Coroutine yield context.
             * @param transmission Transmission channel.
             * @param host Destination host.
             * @param port Destination port.
             * @return True on successful handshake.
             * @note Delegates to common `MuxOrConnect` path with connect mode.
             */
            bool VirtualEthernetTcpipConnection::Connect(
                YieldContext&       y,
                ITransmissionPtr&   transmission,
                const ppp::string&  host,
                int                 port) noexcept {

                return MuxOrConnect(y, transmission, host, port, 0, 0, 0, false);
            }

            /**
             * @brief Performs active mux handshake.
             * @param y Coroutine yield context.
             * @param transmission Transmission channel.
             * @param vlan VLAN value.
             * @param seq Sequence value.
             * @param ack Acknowledge value.
             * @return True on successful mux negotiation.
             * @note Delegates to common `MuxOrConnect` path with mux mode.
             */
            bool VirtualEthernetTcpipConnection::ConnectMux(
                YieldContext&       y,
                ITransmissionPtr&   transmission,
                uint32_t            vlan,
                uint32_t            seq,
                uint32_t            ack) noexcept {

                ppp::string default_host;
                int default_port = ppp::net::IPEndPoint::MinPort;

                return MuxOrConnect(y, transmission, default_host, default_port, vlan, seq, ack, true);
            }

            /**
             * @brief Shared implementation for connect/mux active negotiation.
             * @param y Coroutine yield context.
             * @param transmission Transmission channel.
             * @param host Destination host for connect mode.
             * @param port Destination port for connect mode.
             * @param vlan VLAN value for mux mode.
             * @param seq Sequence value for mux mode.
             * @param ack Acknowledge value for mux mode.
             * @param mux_or_connect True for mux handshake, false for connect handshake.
             * @return True when negotiation succeeds.
             * @note This routine sends one request and validates one peer response packet.
             */
            bool VirtualEthernetTcpipConnection::MuxOrConnect(
                YieldContext&       y,
                ITransmissionPtr&   transmission,
                const ppp::string&  host,
                int                 port,
                uint32_t            vlan,
                uint32_t            seq,
                uint32_t            ack,
                bool                mux_or_connect) noexcept {

                typedef VirtualEthernetLinklayer::ERROR_CODES ERROR_CODES;

                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionConnectAlreadyConnected);
                    return false;
                }

                if (!mux_or_connect) {
                    if (!socket_) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                        return false;
                    }
                }

                Update();

                auto connector = make_shared_object<STATIC_VIRTUAL_ETHERNET_TCPIP_CONNECTOR_NEST>(this, configuration_, context_, id_);
                if (NULLPTR == connector) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionConnectorAllocFailed);
                    return false;
                }
                else {
                    // Dispatch exactly one control packet according to selected negotiation mode.
                    bool connector_dook = false;
                    if (mux_or_connect) {
                        connector_dook = connector->DoMuxON(transmission, vlan, seq, ack, y);
                    }
                    else {
                        connector_dook = connector->DoConnect(transmission, RandomNext(1, INT_MAX), host, port, y);
                    }

                    if (!connector_dook) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                        return false;
                    }
                }

                int packet_size = 0;
                std::shared_ptr<Byte> packet = transmission->Read(y, packet_size);
                if (NULLPTR == packet || packet_size < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return false;
                }

                if (!connector->PacketInput(transmission, packet, packet.get(), packet_size, y)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                    return false;
                }

                if (mux_or_connect) {
                    // For mux mode, reply must be a MUXON echo with exact tuple match.
                    if (!connector->MuxON) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                        return false;
                    }

                    if (connector->Vlan != vlan || connector->Sequence != seq || connector->Acknowledge != ack) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                        return false;
                    }
                }
                else {
                    // For connect mode, reply must be CONNECT_OK with success code.
                    if (!connector->ConnectOK) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                        return false;
                    }

                    ERROR_CODES err = (ERROR_CODES)connector->ErrorCode;
                    if (err != ERROR_CODES::ERRORS_SUCCESS) {
                        ppp::telemetry::Count("tcpip.peer_connect.reject.protocol", 1);
                        ppp::telemetry::Log(ppp::telemetry::Level::kInfo,
                            "tcpip",
                            "peer connect rejected: host=%s port=%d protocol_error=%u",
                            host.c_str(),
                            port,
                            static_cast<unsigned int>(connector->ErrorCode));
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketConnectFailed);
                        return false;
                    }
                }

                connected_ = true;
                transmission_ = transmission;

                Update();
                return true;
            }

            /**
             * @brief Performs passive connect acceptance.
             * @param y Coroutine yield context.
             * @param transmission Transmission channel.
             * @param logger Optional logger.
             * @param mux Optional mux callback.
             * @return True on successful acceptance.
             * @note Delegates to common `MuxOrAccept` path with connect mode.
             */
            bool VirtualEthernetTcpipConnection::Accept(
                YieldContext&                                           y,
                ITransmissionPtr&                                       transmission,
                const VirtualEthernetLoggerPtr&                         logger,
                const AcceptMuxAsynchronousCallback&                    mux) noexcept {

                return MuxOrAccept(y, transmission, logger, mux, false);
            }

            /**
             * @brief Performs passive mux acceptance.
             * @param y Coroutine yield context.
             * @param transmission Transmission channel.
             * @param ac Mux callback.
             * @return True on successful mux acceptance.
             * @note Delegates to common `MuxOrAccept` path with mux mode.
             */
            bool VirtualEthernetTcpipConnection::AcceptMux(
                YieldContext&                           y,
                ITransmissionPtr&                       transmission,
                const AcceptMuxAsynchronousCallback&    ac) noexcept {

                if (NULLPTR == ac) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionAcceptMuxNullCallback);
                    return false;
                }

                return MuxOrAccept(y, transmission, NULLPTR, ac, true);
            }

            /**
             * @brief Shared implementation for connect/mux passive acceptance.
             * @param y Coroutine yield context.
             * @param transmission Transmission channel.
             * @param logger Optional logger for connect events.
             * @param accept_mux_ac Optional mux callback.
             * @param mux_or_connect True for mux-only accept path.
             * @return True when acceptance succeeds.
             * @note In connect mode this function opens/connects the local socket and returns CONNECT_OK.
             */
            bool VirtualEthernetTcpipConnection::MuxOrAccept(
                YieldContext&                                           y,
                ITransmissionPtr&                                       transmission,
                const VirtualEthernetLoggerPtr&                         logger,
                const AcceptMuxAsynchronousCallback&                    accept_mux_ac,
                bool                                                    mux_or_connect) noexcept {

                typedef VirtualEthernetLinklayer::ERROR_CODES ERROR_CODES;

                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionAcceptAlreadyConnected);
                    return false;
                }

                if (!socket_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                Update();

                int packet_size = -1;
                std::shared_ptr<Byte> packet = transmission->Read(y, packet_size);
                if (NULLPTR == packet || packet_size < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return false;
                }

                auto connector = make_shared_object<STATIC_VIRTUAL_ETHERNET_TCPIP_CONNECTOR_NEST>(this, configuration_, context_, id_);
                if (NULLPTR == connector) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionAcceptConnectorAllocFailed);
                    return false;
                }

                if (!connector->PacketInput(transmission, packet, packet.get(), packet_size, y)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                    return false;
                }

                if (mux_or_connect) {
                LABEL_MUXON:
                    // Mux mode: mark linked state and hand negotiated tuple to callback.
                    if (!connector->MuxON) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                        return false;
                    }

                    connected_ = true;
                    transmission_ = transmission;
                    Update();

                    bool ok = accept_mux_ac(connector->Vlan, connector->Sequence, connector->Acknowledge);
                    if (!ok) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                        return false;
                    }
                }
                else {
                    boost::asio::ip::tcp::endpoint& destinationEP = connector->Destination;
                    if (!connector->Connect) {
                        // If first packet is not CONNECT and mux callback exists, allow mux fallback.
                        if (NULLPTR != accept_mux_ac) {
                            goto LABEL_MUXON;
                        }

                        return false;
                    }

                    boost::system::error_code ec;
                    socket_->open(destinationEP.protocol(), ec);
                    if (ec) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                        return false;
                    }

                    boost::asio::ip::address destinationIP = destinationEP.address();
#if defined(_WIN32)
                    if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                        int destinationPort = destinationEP.port();
                        qoss_ = ppp::net::QoSS::New(socket_->native_handle(), destinationIP, destinationPort);
                    }
#elif defined(_LINUX)
                    // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter.
                    // IPV6 does not need to be linked, because VPN is IPV4,
                    // And IPV6 does not affect the physical layer network communication of the VPN.
                    if (!destinationIP.is_loopback()) {
                        auto protector_network = ProtectorNetwork;
                        if (NULLPTR != protector_network) {
                            if (!protector_network->Protect(socket_->native_handle(), y)) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed);
                                return false;
                            }
                        }
                    }
#endif

                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                    ppp::net::Socket::SetWindowSizeIfNotZero(socket_->native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);
                    ppp::net::Socket::AdjustSocketOptional(*socket_, destinationIP.is_v4(), configuration->tcp.fast_open, configuration->tcp.turbo);

                    // Connect to requested destination and send CONNECT_OK with precise status code.
                    bool ok = ppp::coroutines::asio::async_connect(*socket_, destinationEP, y);
                    if (NULLPTR != logger) {
                        logger->Connect(GetId(), transmission, socket_->local_endpoint(ec), destinationEP, connector->Host);
                    }

                    if (disposed_) {
                        connector->DoConnectOK(transmission, connector->ConnectId, ERROR_CODES::ERRORS_CONNECT_CANCEL, y);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return false;
                    }

                    if (ok) {
                        ok = connector->DoConnectOK(transmission, connector->ConnectId, ERROR_CODES::ERRORS_SUCCESS, y);
                        if (!ok) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                            return false;
                        }
                    }
                    else {
                        connector->DoConnectOK(transmission, connector->ConnectId, ERROR_CODES::ERRORS_CONNECT_TO_DESTINATION, y);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketConnectFailed);
                        return false;
                    }

                    connected_ = true;
                    transmission_ = transmission;
                    Update();
                }

                return true;
            }

            /**
             * @brief Finalizes bridge resources immediately.
             * @return void.
             * @note Closes transmission and socket; resets connected/disposed flags.
             */
            void VirtualEthernetTcpipConnection::Finalize() noexcept {
                if (disposed_.exchange(true)) {   // Publish disposal first; cleanup runs only once.
                    return;
                }

                connected_ = false;

                // Cancel in-flight I/O before closing, so read/write completions running on the
                // socket executor observe the disposed state and stop the forwarding chain.
                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                if (NULLPTR != socket) {
                    boost::system::error_code ec;
                    socket->cancel(ec);
                }

                ITransmissionPtr transmission = std::move(transmission_);
                if (NULLPTR != transmission) {
                    transmission->Dispose();
                }

                std::size_t abandoned_direct_bytes = 0;
                std::size_t abandoned_direct_items = 0;
                YieldContext* download_waiter = nullptr;
                DirectCloseHandler close_handler;
                std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry> telemetry;
                {
                    std::lock_guard<std::mutex> lock(direct_sync_);
                    abandoned_direct_bytes = direct_upload_bytes_;
                    abandoned_direct_items = direct_upload_packets_;
                    telemetry = std::move(direct_queue_telemetry_);
                    direct_bridge_started_ = false;
                    direct_upload_writer_started_ = false;
                    direct_send_close_state_ = DirectSendCloseState::Disposed;
                    if (direct_upload_backpressured_) {
                        direct_upload_backpressured_ = false;
                        if (telemetry) {
                            telemetry->SetBackpressured(false);
                        }
                    }
                    direct_upload_queue_.clear();
                    direct_upload_bytes_ = 0;
                    direct_upload_packets_ = 0;
                    direct_read_handler_ = nullptr;
                    close_handler = std::move(direct_close_handler_);
                    direct_writable_handler_ = nullptr;
                    download_waiter = direct_download_waiter_.Invalidate();
                }
                if (close_handler) {
                    close_handler(client::xtcp::XtcpDirectCloseReason::Terminal);
                }
                if (download_waiter) {
                    download_waiter->R();
                }
                if (abandoned_direct_bytes != 0 || abandoned_direct_items != 0) {
                    RemoveDirectUploadQueueTelemetry(
                        telemetry, abandoned_direct_bytes, abandoned_direct_items);
                }

#if defined(_WIN32)
                qoss_.reset();
#endif

#if defined(_IPHONE) || defined(IPHONE)
                native_tap_relay_started_.store(false, std::memory_order_release);
                {
                    std::lock_guard<std::mutex> lock(native_upload_mutex_);
                    native_upload_queue_.clear();
                    native_upload_queued_bytes_ = 0;
                    native_upload_writer_started_ = false;
                }
#endif

                ppp::net::Socket::Closesocket(socket_);
            }

            /**
             * @brief Clears handles without posting async finalization.
             * @return void.
             * @note Intended for lightweight reset scenarios.
             */
            void VirtualEthernetTcpipConnection::Clear() noexcept {
                connected_ = false;

#if defined(_WIN32)
                qoss_.reset();
#endif

                socket_.reset();
                transmission_.reset();
            }

            /**
             * @brief Destroys bridge object.
             * @return N/A.
             * @note Destructor calls `Finalize()` directly.
             */
            VirtualEthernetTcpipConnection::~VirtualEthernetTcpipConnection() noexcept {
                Finalize();
            }

            /**
             * @brief Posts asynchronous finalization to context/strand.
             * @return void.
             * @note Ensures cleanup order is consistent with other strand-bound operations.
             */
            void VirtualEthernetTcpipConnection::Dispose() noexcept {
                auto self = shared_from_this();
                ppp::threading::Executors::ContextPtr context = context_;
                ppp::threading::Executors::StrandPtr strand = strand_;

                ppp::threading::Executors::Post(context, strand,
                    [self, this, context, strand]() noexcept {
                        Finalize();
                    });
            }

            /**
             * @brief Starts the bidirectional forwarding session.
             * @param y Coroutine yield context.
             * @return True when forward loop yields at least one packet.
             * @note Starts socket-read side first, then enters transmission-read loop.
             */
            bool VirtualEthernetTcpipConnection::Run(YieldContext& y) noexcept {
                if (!ReceiveTransmissionToSocket()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
                    return false;
                }

                Update();
                return ForwardTransmissionToSocket(y);
            }

            /**
             * @brief Writes data to remote peer through transmission.
             * @param y Coroutine yield context.
             * @param packet Payload pointer.
             * @param packet_length Payload length.
             * @return True on successful write.
             * @note Requires connected and non-disposed state.
             */
            bool VirtualEthernetTcpipConnection::SendBufferToPeer(YieldContext& y, const void* packet, int packet_length) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionSendPeerInvalidPayload);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (!connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionSendPeerNotConnected);
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                if (configuration_->key.plaintext && packet_length > kPlaintextBase94MaxTcpReadSize) {
                    const Byte* p = static_cast<const Byte*>(packet);
                    int remaining = packet_length;
                    while (remaining > 0) {
                        int chunk = std::min<int>(remaining, kPlaintextBase94MaxTcpReadSize);
                        if (!transmission->Write(y, p, chunk)) {
                            return false;
                        }

                        p += chunk;
                        remaining -= chunk;
                    }

                    return true;
                }

                return transmission->Write(y, packet, packet_length);
            }

            /**
             * @brief Forwards one socket-read chunk into transmission.
             * @param buffer Shared receive buffer.
             * @param buffer_size Buffer capacity.
             * @param bytes_transferred Number of valid bytes.
             * @param transmission_write_accepted_scope Read-to-write-completion timer.
             * @return True when async transmission write is accepted.
             * @note Completion callback decides whether to continue receive loop.
             */
            bool VirtualEthernetTcpipConnection::ForwardSocketToTransmission(const std::shared_ptr<Byte>& buffer, int buffer_size, int bytes_transferred, ppp::diagnostics::datapath_perf::Scope transmission_write_accepted_scope) noexcept {
                if (NULLPTR == buffer || buffer_size < 1 || bytes_transferred < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionForwardSocketInvalidArguments);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (!connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionForwardSocketNotConnected);
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                auto self = shared_from_this();
                return transmission->Write(buffer.get(), bytes_transferred,
                    [self, this, buffer, buffer_size, bytes_transferred, transmission_write_accepted_scope](bool ok) noexcept {
                        if (!ok) {
                            ppp::telemetry::Log(ppp::telemetry::Level::kInfo,
                                "tcpip",
                                "socket->transmission write callback failed bytes=%d error=%d disposed=%s connected=%s",
                                bytes_transferred,
                                (int)ppp::diagnostics::GetLastErrorCode(),
                                disposed_ ? "yes" : "no",
                                connected_ ? "yes" : "no");
                        }
                        else {
                            ppp::diagnostics::datapath_perf::RecordTcpipBridgeTransmissionWriteAccepted(
                                bytes_transferred, transmission_write_accepted_scope.Elapsed());
                        }
                        ForwardSocketToTransmissionOK(ok, buffer, buffer_size);
                    });
            }

            /**
             * @brief Arms asynchronous socket receive and forwards received data.
             * @param buffer Shared receive buffer.
             * @param buffer_size Buffer capacity.
             * @return True when async receive is scheduled.
             * @note Receive length is randomized by skateboarding strategy to diversify chunk sizes.
             */
            bool VirtualEthernetTcpipConnection::ReceiveSocketToTransmission(const std::shared_ptr<Byte>& buffer, int buffer_size) noexcept {
                if (NULLPTR == buffer || buffer_size < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionReceiveSocketInvalidBuffer);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (!connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionReceiveSocketNotConnected);
                    return false;
                }

                auto self = shared_from_this();
                boost::asio::post(socket_->get_executor(),
                    [self, this, buffer, buffer_size]() noexcept {
                        if (disposed_) {                // Never arm new reads after finalization.
                            return;
                        }

                        // Plaintext transport still wraps binary frames in base94; cap the raw
                        // TCP chunk so the encoded frame cannot exceed PPP_BUFFER_SIZE.
                        int read_size = buffer_size;
                        if (configuration_->key.plaintext) {
                            read_size = std::min<int>(read_size, kPlaintextBase94MaxTcpReadSize);
                        }

                        // Pick a dynamic read size, then chain read -> write -> next read.
                        int bytes_transferred = BufferSkateboarding(configuration_->key.sb, read_size, PPP_BUFFER_SIZE);
                        socket_->async_read_some(boost::asio::buffer(buffer.get(), bytes_transferred),
                            [self, this, buffer, buffer_size](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                int bytes_transferred = std::max<int>(ec ? -1 : static_cast<int>(sz), -1);
                                if (bytes_transferred < 1) {
                                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo,
                                        "tcpip",
                                        "socket->transmission read closed ec=%d msg=%s size=%zu disposed=%s connected=%s",
                                        ec.value(),
                                        ec.message().c_str(),
                                        sz,
                                        disposed_ ? "yes" : "no",
                                        connected_ ? "yes" : "no");
                                    Dispose();
                                }
                                else {
                                    ppp::diagnostics::datapath_perf::RecordTcpipBridgeSocketRead(bytes_transferred);
                                    ppp::diagnostics::datapath_perf::Scope transmission_write_accepted_scope;
                                    if (ForwardSocketToTransmission(buffer, buffer_size, bytes_transferred, transmission_write_accepted_scope)) {
                                        Update();
                                    }
                                    else {
                                        ppp::telemetry::Log(ppp::telemetry::Level::kInfo,
                                            "tcpip",
                                            "socket->transmission forward failed bytes=%d error=%d disposed=%s connected=%s",
                                            bytes_transferred,
                                            (int)ppp::diagnostics::GetLastErrorCode(),
                                            disposed_ ? "yes" : "no",
                                            connected_ ? "yes" : "no");
                                        Dispose();
                                    }
                                }
                            });
                    });
                return true;
            }

            /**
             * @brief Initializes first socket receive cycle.
             * @return True when initial receive scheduling succeeds.
             * @note Allocates a single reusable read buffer.
             */
            bool VirtualEthernetTcpipConnection::ReceiveTransmissionToSocket() noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (!connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionReceiveStartNotConnected);
                    return false;
                }

                auto allocator = configuration_->GetBufferAllocator();
                auto buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, PPP_BUFFER_SIZE);
                if (NULLPTR == buffer) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionReceiveStartBufferAllocFailed);
                    return false;
                }

                return ReceiveSocketToTransmission(buffer, PPP_BUFFER_SIZE);
            }

            /**
             * @brief Reads from transmission and writes to local socket until termination.
             * @param y Coroutine yield context.
             * @return True if at least one packet is forwarded.
             * @note Loop exits on read/write failure or disposal, then schedules cleanup.
             */
            bool VirtualEthernetTcpipConnection::ForwardTransmissionToSocket(YieldContext& y) noexcept {
                if (!connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionForwardTransmissionNotConnected);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                bool any = false;
                bool stop_logged = false;
                int packets_to_socket = 0;
                long long bytes_to_socket = 0;
                while (!disposed_) {
                    // Pull framed payload from transmission, then push to TCP socket.
                    ITransmissionPtr transmission = transmission_;
                    if (NULLPTR == transmission) {
                        stop_logged = true;
                        ppp::telemetry::Log(ppp::telemetry::Level::kInfo,
                            "tcpip",
                            "transmission->socket stopped: transmission missing packets=%d bytes=%lld",
                            packets_to_socket,
                            bytes_to_socket);
                        break;
                    }

                    int packet_length = 0;
                    std::shared_ptr<Byte> packet = transmission->Read(y, packet_length);
                    if (NULLPTR == packet || packet_length < 1) {
                        stop_logged = true;
                        ppp::telemetry::Log(ppp::telemetry::Level::kInfo,
                            "tcpip",
                            "transmission->socket read failed packet_length=%d packets=%d bytes=%lld error=%d disposed=%s connected=%s",
                            packet_length,
                            packets_to_socket,
                            bytes_to_socket,
                            (int)ppp::diagnostics::GetLastErrorCode(),
                            disposed_ ? "yes" : "no",
                            connected_ ? "yes" : "no");
                        break;
                    }

                    ppp::diagnostics::datapath_perf::RecordTcpipBridgeTransmissionRead(packet_length);
                    any = true;
                    Update();

                    bool ok = false;
                    boost::asio::post(socket_->get_executor(),
                        [this, &y, &ok, packet, packet_length]() noexcept {
                            ppp::diagnostics::datapath_perf::Scope socket_write_scope;
                            boost::asio::async_write(*socket_, boost::asio::buffer(packet.get(), packet_length),
                                [&y, &ok, packet_length, socket_write_scope](const boost::system::error_code& ec, std::size_t bytes_transferred) noexcept {
                                    if (!ec && bytes_transferred == static_cast<std::size_t>(packet_length)) {
                                        ppp::diagnostics::datapath_perf::RecordTcpipBridgeSocketWriteCompleted(packet_length, socket_write_scope.Elapsed());
                                    }
                                    ok = ec == boost::system::errc::success;
                                    y.R();
                                });
                        });
                    y.Suspend();
                    if (ok) {
                        packets_to_socket++;
                        bytes_to_socket += packet_length;
                        Update();
                    }
                    else {
                        stop_logged = true;
                        ppp::telemetry::Log(ppp::telemetry::Level::kInfo,
                            "tcpip",
                            "transmission->socket write failed packet_length=%d packets=%d bytes=%lld error=%d disposed=%s connected=%s",
                            packet_length,
                            packets_to_socket,
                            bytes_to_socket,
                            (int)ppp::diagnostics::GetLastErrorCode(),
                            disposed_ ? "yes" : "no",
                            connected_ ? "yes" : "no");
                        break;
                    }
                }

                if (!stop_logged && disposed_) {
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo,
                        "tcpip",
                        "transmission->socket stopped: disposed externally packets=%d bytes=%lld connected=%s",
                        packets_to_socket,
                        bytes_to_socket,
                        connected_ ? "yes" : "no");
                }

                Dispose();
                return any;
            }

            bool VirtualEthernetTcpipConnection::StartDirectBridge(
                const DirectReadHandler& on_data,
                const DirectCloseHandler& on_close,
                const DirectWritableHandler& on_writable) noexcept {
                if (!on_data || disposed_ || !connected_ || !transmission_ ||
                    !transmission_->SupportsSendHalfClose()) {
                    return false;
                }
                {
                    std::lock_guard<std::mutex> lock(direct_sync_);
                    if (disposed_ || !connected_ || !transmission_ || direct_bridge_started_) {
                        return false;
                    }
                    direct_bridge_started_ = true;
                    direct_send_close_state_ = DirectSendCloseState::Open;
                    direct_upload_backpressured_ = false;
                    direct_download_waiter_.Reset();
                    direct_read_handler_ = on_data;
                    direct_close_handler_ = on_close;
                    direct_writable_handler_ = on_writable;
                }
                const std::shared_ptr<VirtualEthernetTcpipConnection> self = shared_from_this();
                auto allocator = configuration_->GetBufferAllocator();
                if (!YieldContext::Spawn(allocator.get(), *context_, strand_.get(),
                        [self, this](YieldContext& y) noexcept {
                            return RunDirectDownload(y);
                        })) {
                    YieldContext* download_waiter = nullptr;
                    {
                        std::lock_guard<std::mutex> lock(direct_sync_);
                        direct_bridge_started_ = false;
                        direct_read_handler_ = nullptr;
                        direct_close_handler_ = nullptr;
                        direct_writable_handler_ = nullptr;
                        download_waiter = direct_download_waiter_.Invalidate();
                    }
                    if (download_waiter) {
                        download_waiter->R();
                    }
                    return false;
                }
                return true;
            }

            VirtualEthernetTcpipConnection::DirectIoResult
            VirtualEthernetTcpipConnection::SendDirectToPeer(
                const Byte* data, std::uint32_t length,
                client::xtcp::XtcpUploadBudget::Reservation&& credit) noexcept {
                if (!data || length == 0 || !credit || credit.Bytes() != length ||
                    credit.Items() != 1 || disposed_ || !connected_) {
                    return DirectIoResult::Closed;
                }
                bool start_writer = false;
                std::shared_ptr<client::xtcp::XtcpUploadChunk> payload;
                {
                    std::lock_guard<std::mutex> lock(direct_sync_);
                    if (disposed_ || !connected_ || !transmission_ ||
                        !direct_bridge_started_ ||
                        direct_send_close_state_ != DirectSendCloseState::Open) {
                        return DirectIoResult::Closed;
                    }
                    if (direct_upload_packets_ >= kDirectQueueMaxPackets ||
                        length > kDirectQueueMaxBytes - direct_upload_bytes_) {
                        if (!direct_upload_backpressured_) {
                            direct_upload_backpressured_ = true;
                            if (direct_queue_telemetry_) {
                                direct_queue_telemetry_->SetBackpressured(true);
                            }
                        }
                        return DirectIoResult::Backpressured;
                    }
                    try {
                        // Both global credit and the per-flow queue cap are
                        // secured before copying borrowed receive bytes.
                        payload = std::make_shared<client::xtcp::XtcpUploadChunk>(data, length, std::move(credit));
                        direct_upload_queue_.emplace_back(payload);
                    }
                    catch (...) {
                        return DirectIoResult::Closed;
                    }
                    direct_upload_bytes_ += length;
                    ++direct_upload_packets_;
                    AddDirectUploadQueueTelemetry(direct_queue_telemetry_, length);
                    if (!direct_upload_writer_started_) {
                        direct_upload_writer_started_ = true;
                        start_writer = true;
                    }
                }
                if (!start_writer || StartDirectUploadWriter()) {
                    return DirectIoResult::Accepted;
                }
                std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry> telemetry;
                {
                    std::lock_guard<std::mutex> lock(direct_sync_);
                    direct_upload_writer_started_ = false;
                    if (!direct_upload_queue_.empty() && direct_upload_queue_.back() == payload) {
                        direct_upload_bytes_ -= length;
                        --direct_upload_packets_;
                        direct_upload_queue_.pop_back();
                        telemetry = direct_queue_telemetry_;
                    }
                }
                if (telemetry) {
                    RemoveDirectUploadQueueTelemetry(telemetry, length, 1);
                }
                return DirectIoResult::Closed;
            }

            void VirtualEthernetTcpipConnection::CompleteDirectDownload(
                const client::xtcp::XtcpDirectReadReservation& reservation,
                client::xtcp::XtcpDirectCompletion completion) noexcept {
                YieldContext* waiter = nullptr;
                {
                    std::lock_guard<std::mutex> lock(direct_sync_);
                    waiter = direct_download_waiter_.Complete(reservation, completion);
                }
                if (waiter) {
                    waiter->R();
                }
            }

            void VirtualEthernetTcpipConnection::SetDirectQueueTelemetry(
                const std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry>& telemetry) noexcept {
                std::lock_guard<std::mutex> lock(direct_sync_);
                if (direct_bridge_started_) {
                    direct_queue_telemetry_ = telemetry;
                }
            }

            bool VirtualEthernetTcpipConnection::StartDirectUploadWriter() noexcept {
                const std::shared_ptr<VirtualEthernetTcpipConnection> self = shared_from_this();
                return ppp::threading::Executors::Post(context_, strand_, [self, this]() noexcept {
                    auto allocator = configuration_->GetBufferAllocator();
                    if (!YieldContext::Spawn(allocator.get(), *context_, strand_.get(),
                            [self, this](YieldContext& y) noexcept {
                                ppp::telemetry::Count("xtcp.direct.upload_writer_starts", 1);
                                return RunDirectUpload(y);
                            })) {
                        Dispose();
                    }
                });
            }

            bool VirtualEthernetTcpipConnection::RunDirectUpload(YieldContext& y) noexcept {
                std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry> telemetry;
                {
                    std::lock_guard<std::mutex> lock(direct_sync_);
                    telemetry = direct_queue_telemetry_;
                }
                struct WriterTelemetryScope final {
                    explicit WriterTelemetryScope(
                        const std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry>& value) noexcept
                        : telemetry(value) {
                        if (telemetry) {
                            telemetry->WriterStarted();
                        }
                    }
                    ~WriterTelemetryScope() noexcept {
                        if (telemetry) {
                            telemetry->WriterStopped();
                        }
                    }
                    std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry> telemetry;
                } writer_telemetry_scope(telemetry);
                const std::size_t gather_limit = GetDirectUploadGatherBytes(configuration_->key.plaintext);
                for (;;) {
                    std::shared_ptr<client::xtcp::XtcpUploadChunk> payload;
                    std::size_t payload_items = 0;
                    bool shutdown_send = false;
                    {
                        std::lock_guard<std::mutex> lock(direct_sync_);
                        if (direct_upload_queue_.empty()) {
                            if (direct_send_close_state_ == DirectSendCloseState::Draining) {
                                direct_send_close_state_ = DirectSendCloseState::SendShutdown;
                                shutdown_send = true;
                            }
                            else {
                                direct_upload_writer_started_ = false;
                            }
                        }
                        else {
                            payload = direct_upload_queue_.front();
                            payload_items = 1;
                            if (gather_limit > 1 && payload->bytes.size() < gather_limit &&
                                direct_upload_queue_.size() > 1) {
                                std::size_t gathered_bytes = payload->bytes.size();
                                std::size_t gathered_items = 1;
                                for (; gathered_items < direct_upload_queue_.size(); ++gathered_items) {
                                    const std::shared_ptr<client::xtcp::XtcpUploadChunk>& candidate =
                                        direct_upload_queue_[gathered_items];
                                    if (!candidate || candidate->bytes.empty() ||
                                        !payload->credit.SameBudget(candidate->credit) ||
                                        candidate->bytes.size() > gather_limit - gathered_bytes) {
                                        break;
                                    }
                                    gathered_bytes += candidate->bytes.size();
                                }
                                if (gathered_items > 1) {
                                    try {
                                        auto combined = std::make_shared<client::xtcp::XtcpUploadChunk>();
                                        combined->bytes.reserve(gathered_bytes);
                                        for (std::size_t i = 0; i < gathered_items; ++i) {
                                            const std::vector<Byte>& item =
                                                direct_upload_queue_[i]->bytes;
                                            combined->bytes.insert(combined->bytes.end(), item.begin(), item.end());
                                        }
                                        // All allocations/copies succeeded. Transfer the
                                        // admitted credit before removing original chunks;
                                        // keep it through Write(y), including on close.
                                        for (std::size_t i = 0; i < gathered_items; ++i) {
                                            const bool merged = combined->credit.Merge(
                                                std::move(direct_upload_queue_[i]->credit));
                                            assert(merged); // SameBudget was checked above under this lock.
                                            (void)merged;
                                        }
                                        payload = std::move(combined);
                                        payload_items = gathered_items;
                                        for (std::size_t i = 0; i < gathered_items; ++i) {
                                            direct_upload_queue_.pop_front();
                                        }
                                    }
                                    catch (...) {
                                        direct_upload_queue_.pop_front();
                                    }
                                }
                                else {
                                    direct_upload_queue_.pop_front();
                                }
                            }
                            else {
                                direct_upload_queue_.pop_front();
                            }
                        }
                    }
                    if (!payload) {
                        if (!shutdown_send) {
                            ppp::telemetry::Count("xtcp.direct.upload_writer_exits", 1);
                            return true;
                        }

                        ITransmissionPtr transmission = transmission_;
                        if (!transmission || disposed_ || !connected_) {
                            ppp::telemetry::Count("xtcp.direct.close_shutdown_cancelled", 1);
                            ppp::telemetry::Count("xtcp.direct.upload_writer_exits", 1);
                            return false;
                        }

                        // Write(y) resumes after carrier write completion, so this is
                        // normally already empty. Keep the explicit barrier for carriers
                        // whose completion callback and coroutine resume are scheduled
                        // separately.
                        while (transmission->GetPendingItems() != 0 ||
                               transmission->GetPendingBytes() != 0) {
                            ppp::coroutines::asio::async_sleep(
                                y, kDirectCloseDrainPollMilliseconds);
                            bool cancelled = disposed_ || !connected_;
                            {
                                std::lock_guard<std::mutex> lock(direct_sync_);
                                cancelled = cancelled || !direct_bridge_started_ ||
                                    direct_send_close_state_ != DirectSendCloseState::SendShutdown;
                            }
                            if (cancelled) {
                                ppp::telemetry::Count("xtcp.direct.close_shutdown_cancelled", 1);
                                ppp::telemetry::Count("xtcp.direct.upload_writer_exits", 1);
                                if (!disposed_) {
                                    Dispose();
                                }
                                return false;
                            }
                        }

                        if (!transmission->ShutdownSend()) {
                            ppp::telemetry::Count("xtcp.direct.close_shutdown_failures", 1);
                            ppp::telemetry::Count("xtcp.direct.upload_writer_exits", 1);
                            Dispose();
                            return false;
                        }
                        ppp::telemetry::Count("xtcp.direct.close_shutdown_completions", 1);
                        ppp::telemetry::Count("xtcp.direct.upload_writer_exits", 1);
                        return true;
                    }
                    const bool sent = SendBufferToPeer(
                        y, payload->bytes.data(), static_cast<int>(payload->bytes.size()));
                    DirectWritableHandler writable;
                    std::size_t completed_bytes = 0;
                    std::size_t completed_items = 0;
                    {
                        std::lock_guard<std::mutex> lock(direct_sync_);
                        completed_bytes = std::min(payload->bytes.size(), direct_upload_bytes_);
                        direct_upload_bytes_ -= completed_bytes;
                        completed_items = std::min(payload_items, direct_upload_packets_);
                        direct_upload_packets_ -= completed_items;
                        if (sent && direct_upload_backpressured_ &&
                            direct_upload_bytes_ <= kDirectQueueLowBytes &&
                            direct_upload_packets_ <= kDirectQueueLowPackets) {
                            direct_upload_backpressured_ = false;
                            if (telemetry) {
                                telemetry->SetBackpressured(false);
                            }
                            writable = direct_writable_handler_;
                        }
                    }
                    if (completed_bytes != 0 || completed_items != 0) {
                        RemoveDirectUploadQueueTelemetry(telemetry, completed_bytes, completed_items);
                    }
                    // Write(y) completed. Free the payload/credit before
                    // advertising local capacity to a resumed receiver.
                    payload.reset();
                    if (!sent) {
                        ppp::telemetry::Count("xtcp.direct.upload_writer_exits", 1);
                        Dispose();
                        return false;
                    }
                    if (completed_items > 1) {
                        ppp::telemetry::Count("xtcp.direct.upload_gathered_writes", 1);
                        ppp::telemetry::Count("xtcp.direct.upload_gathered_items", completed_items);
                        ppp::telemetry::Count("xtcp.direct.upload_gathered_bytes", completed_bytes);
                    }
                    ppp::telemetry::Count("xtcp.direct.upload_writes", 1);
                    if (telemetry) {
                        telemetry->WriterProgress();
                    }
                    if (writable) {
                        writable();
                    }
                    Update();
                }
            }

            bool VirtualEthernetTcpipConnection::RunDirectDownload(YieldContext& y) noexcept {
                std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry> telemetry;
                {
                    std::lock_guard<std::mutex> lock(direct_sync_);
                    telemetry = direct_queue_telemetry_;
                }
                bool terminal = false;
                for (;;) {
                    ITransmissionPtr transmission = transmission_;
                    if (!transmission || disposed_ || !connected_) {
                        terminal = true;
                        break;
                    }
                    int packet_length = 0;
                    const std::shared_ptr<Byte> packet = transmission->Read(y, packet_length);
                    if (!packet || packet_length < 1) {
                        if (transmission->IsReceiveClosed()) {
                            DirectCloseHandler close_handler;
                            {
                                std::lock_guard<std::mutex> lock(direct_sync_);
                                close_handler = direct_close_handler_;
                            }
                            if (close_handler) {
                                close_handler(client::xtcp::XtcpDirectCloseReason::PeerEof);
                            }
                            return true;
                        }
                        terminal = true;
                        break;
                    }
                    for (int offset = 0; offset < packet_length;) {
                        const int chunk_length = std::min<int>(
                            static_cast<int>(kDirectDownloadChunkBytes), packet_length - offset);
                        const std::shared_ptr<Byte> chunk(packet, packet.get() + offset);
                        client::xtcp::XtcpDirectReadReservation reservation;
                        reservation.length = static_cast<std::uint32_t>(chunk_length);
                        for (;;) {
                            DirectReadHandler handler;
                            bool active = false;
                            {
                                std::lock_guard<std::mutex> lock(direct_sync_);
                                active = !disposed_ && connected_ && direct_bridge_started_;
                                handler = direct_read_handler_;
                            }
                            if (!active || !handler) {
                                terminal = true;
                                break;
                            }
                            const bool timing = telemetry && telemetry->TimingEnabled();
                            const std::uint64_t handler_started_us = timing
                                ? telemetry->Now() : 0;
                            const DirectIoResult result = handler(reservation, chunk);
                            if (timing) {
                                const std::uint64_t now = telemetry->Now();
                                telemetry->RecordSecondLegHandler(
                                    now > handler_started_us ? now - handler_started_us : 0);
                            }
                            if (result == DirectIoResult::Backpressured) {
                                ppp::coroutines::asio::async_sleep(y, 1);
                                {
                                    std::lock_guard<std::mutex> lock(direct_sync_);
                                    active = !disposed_ && connected_ && direct_bridge_started_;
                                }
                                if (!active) {
                                    terminal = true;
                                    break;
                                }
                                continue;
                            }
                            if (result == DirectIoResult::Closed) {
                                terminal = true;
                                break;
                            }

                            DirectReadWaiterState::Outcome registered =
                                DirectReadWaiterState::Outcome::Terminal;
                            {
                                std::lock_guard<std::mutex> lock(direct_sync_);
                                if (!disposed_ && connected_ && direct_bridge_started_) {
                                    registered = direct_download_waiter_.Register(reservation, &y);
                                }
                            }
                            DirectReadWaiterState::Outcome completed =
                                DirectReadWaiterState::Outcome::Terminal;
                            if (registered == DirectReadWaiterState::Outcome::Pending) {
                                const std::uint64_t suspend_started_us = timing
                                    ? telemetry->Now() : 0;
                                y.Suspend();
                                if (timing) {
                                    const std::uint64_t now = telemetry->Now();
                                    telemetry->RecordSecondLegAcceptedWaitToResume(
                                        now > suspend_started_us ? now - suspend_started_us : 0);
                                }
                                std::lock_guard<std::mutex> lock(direct_sync_);
                                completed = direct_download_waiter_.Consume(reservation);
                            }
                            else if (registered == DirectReadWaiterState::Outcome::Accepted) {
                                std::lock_guard<std::mutex> lock(direct_sync_);
                                completed = direct_download_waiter_.Consume(reservation);
                            }
                            if (completed != DirectReadWaiterState::Outcome::Accepted) {
                                terminal = true;
                                break;
                            }
                            offset += chunk_length;
                            break;
                        }
                        if (terminal) {
                            break;
                        }
                    }
                    if (terminal) {
                        break;
                    }
                    Update();
                }
                DirectCloseHandler close_handler;
                YieldContext* download_waiter = nullptr;
                {
                    std::lock_guard<std::mutex> lock(direct_sync_);
                    close_handler = std::move(direct_close_handler_);
                    direct_bridge_started_ = false;
                    direct_read_handler_ = nullptr;
                    direct_writable_handler_ = nullptr;
                    download_waiter = direct_download_waiter_.Invalidate();
                }
                if (close_handler) {
                    close_handler(client::xtcp::XtcpDirectCloseReason::Terminal);
                }
                if (download_waiter) {
                    download_waiter->R();
                }
                Dispose();
                return true;
            }

            void VirtualEthernetTcpipConnection::CloseDirectSend() noexcept {
                bool start_writer = false;
                {
                    std::lock_guard<std::mutex> lock(direct_sync_);
                    if (!direct_bridge_started_ ||
                        direct_send_close_state_ != DirectSendCloseState::Open) {
                        return;
                    }
                    direct_send_close_state_ = DirectSendCloseState::Draining;
                    if (!direct_upload_writer_started_) {
                        direct_upload_writer_started_ = true;
                        start_writer = true;
                    }
                }
                if (start_writer && !StartDirectUploadWriter()) {
                    Dispose();
                }
            }

#if defined(_IPHONE) || defined(IPHONE)
            namespace {
                bool IsNativeUploadWriteTerminal(ppp::diagnostics::ErrorCode error) noexcept {
                    using ppp::diagnostics::ErrorCode;
                    switch (error) {
                    case ErrorCode::SessionDisposed:
                    case ErrorCode::SocketReadFailed:
                    case ErrorCode::SessionTransportMissing:
                    case ErrorCode::TunnelWriteFailed:
                    case ErrorCode::TcpipConnectionSendPeerNotConnected:
                        return true;
                    default:
                        return false;
                    }
                }
            }

            void VirtualEthernetTcpipConnection::DisposeNativeTransportOnly() noexcept {
                ITransmissionPtr transmission = std::move(transmission_);
                if (NULLPTR != transmission) {
                    transmission->Dispose();
                }

                connected_ = false;
                native_tap_relay_started_.store(false, std::memory_order_release);
                {
                    std::lock_guard<std::mutex> lock(native_upload_mutex_);
                    native_upload_queue_.clear();
                    native_upload_queued_bytes_ = 0;
                    native_upload_writer_started_ = false;
                }
            }

            bool VirtualEthernetTcpipConnection::EnsureNativeUploadWriter() noexcept {
                if (disposed_ || !connected_) {
                    return false;
                }

                std::unique_lock<std::mutex> lock(native_upload_mutex_);
                if (native_upload_writer_started_ || native_upload_queue_.empty()) {
                    return native_upload_writer_started_;
                }

                native_upload_writer_started_ = true;
                auto self = shared_from_this();
                auto allocator = configuration_->GetBufferAllocator();
                auto spawn_work =
                    [self, this](YieldContext& y) noexcept {
                        return RunNativeUploadWriter(y);
                    };

                lock.unlock();
                if (!YieldContext::Spawn(allocator.get(), *context_, strand_.get(), spawn_work)) {
                    std::lock_guard<std::mutex> reset_lock(native_upload_mutex_);
                    native_upload_writer_started_ = false;
                    return false;
                }

                return true;
            }

            bool VirtualEthernetTcpipConnection::RunNativeUploadWriter(YieldContext& y) noexcept {
                while (!disposed_ && connected_) {
                    std::shared_ptr<std::vector<Byte>> payload;
                    {
                        std::lock_guard<std::mutex> lock(native_upload_mutex_);
                        if (native_upload_queue_.empty()) {
                            native_upload_writer_started_ = false;
                            return true;
                        }

                        payload = native_upload_queue_.front();
                        native_upload_queue_.pop_front();
                        size_t payload_size = NULLPTR != payload ? payload->size() : 0;
                        native_upload_queued_bytes_ = payload_size >= native_upload_queued_bytes_
                            ? 0
                            : native_upload_queued_bytes_ - payload_size;
                    }

                    if (NULLPTR == payload || payload->empty()) {
                        continue;
                    }

                    if (!SendBufferToPeer(y, payload->data(), (int)payload->size())) {
                        const auto error = ppp::diagnostics::GetLastErrorCode();
                        size_t queue_depth = 0;
                        bool terminal = IsNativeUploadWriteTerminal(error);
                        {
                            std::lock_guard<std::mutex> lock(native_upload_mutex_);
                            queue_depth = native_upload_queue_.size();
                            if (terminal) {
                                native_upload_queue_.clear();
                                native_upload_queued_bytes_ = 0;
                                native_upload_writer_started_ = false;
                            }
                        }
                        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip",
                            "native upload write failed len=%d error=%d queue=%zu disposed=%s connected=%s terminal=%s",
                            (int)payload->size(),
                            (int)error,
                            queue_depth,
                            disposed_ ? "yes" : "no",
                            connected_ ? "yes" : "no",
                            terminal ? "yes" : "no");
                        if (terminal) {
                            Dispose();
                            return true;
                        }
                        continue;
                    }

                    Update();
                }

                bool restart_writer = false;
                {
                    std::lock_guard<std::mutex> lock(native_upload_mutex_);
                    native_upload_writer_started_ = false;
                    restart_writer = !native_upload_queue_.empty() && !disposed_ && connected_;
                }

                if (restart_writer) {
                    EnsureNativeUploadWriter();
                }

                return true;
            }

            bool VirtualEthernetTcpipConnection::SendBufferToPeerAsync(const std::shared_ptr<std::vector<Byte>>& payload) noexcept {
                if (NULLPTR == payload || payload->empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionSendPeerInvalidPayload);
                    return false;
                }

                if (disposed_ || !connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionSendPeerNotConnected);
                    return false;
                }

                if (NULLPTR == transmission_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                const size_t payload_size = payload->size();
                {
                    std::lock_guard<std::mutex> lock(native_upload_mutex_);
                    if (native_upload_queued_bytes_ + payload_size > kNativeUploadQueueMaxBytes ||
                        native_upload_queue_.size() >= kNativeUploadQueueMaxPackets) {
                        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip",
                            "native upload queue full drop len=%zu depth=%zu bytes=%zu max_bytes=%zu",
                            payload_size,
                            native_upload_queue_.size(),
                            native_upload_queued_bytes_,
                            kNativeUploadQueueMaxBytes);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueBackpressure);
                        return false;
                    }

                    std::shared_ptr<std::vector<Byte>> tail =
                        native_upload_queue_.empty() ? std::shared_ptr<std::vector<Byte>>() : native_upload_queue_.back();
                    if (NULLPTR != tail && tail->size() + payload_size <= kNativeUploadCoalesceMaxBytes) {
                        tail->insert(tail->end(), payload->begin(), payload->end());
                    }
                    else {
                        native_upload_queue_.push_back(payload);
                    }
                    native_upload_queued_bytes_ += payload_size;
                }

                return EnsureNativeUploadWriter();
            }

            bool VirtualEthernetTcpipConnection::SendBufferToPeerAsync(const void* packet, int packet_length) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionSendPeerInvalidPayload);
                    return false;
                }

                std::shared_ptr<std::vector<Byte>> payload =
                    std::make_shared<std::vector<Byte>>((const Byte*)packet, (const Byte*)packet + packet_length);
                if (NULLPTR == payload) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                return SendBufferToPeerAsync(payload);
            }

            bool VirtualEthernetTcpipConnection::StartNativeTapRelay(const ppp::function<void(const void*, size_t)>& on_data, const ppp::function<void()>& on_shutdown) noexcept {
                if (disposed_ || !connected_ || !on_data) {
                    return false;
                }

                bool relay_started = false;
                if (!native_tap_relay_started_.compare_exchange_strong(relay_started, true, std::memory_order_acq_rel)) {
                    ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "tcpip", "vpn native inject relay already started");
                    return true;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    native_tap_relay_started_.store(false, std::memory_order_release);
                    return false;
                }

                auto self = shared_from_this();
                ppp::function<void(const void*, size_t)> relay = on_data;
                auto allocator = configuration_->GetBufferAllocator();
                auto spawn_work =
                    [self, this, relay, on_shutdown](YieldContext& y) noexcept {
                        while (!disposed_ && connected_) {
                            ITransmissionPtr active = transmission_;
                            if (NULLPTR == active) {
                                break;
                            }

                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);

                            int packet_length = 0;
                            std::shared_ptr<Byte> packet = active->Read(y, packet_length);
                            if (NULLPTR == packet || packet_length < 1) {
                                const auto error = ppp::diagnostics::GetLastErrorCode();
                                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip",
                                    "vpn native inject read end packet_length=%d error=%d disposed=%s connected=%s",
                                    packet_length,
                                    (int)error,
                                    disposed_ ? "yes" : "no",
                                    connected_ ? "yes" : "no");
                                break;
                            }

                            relay(packet.get(), (size_t)packet_length);
                            Update();
                        }

                        native_tap_relay_started_.store(false, std::memory_order_release);
                        connected_ = false;
                        if (on_shutdown) {
                            on_shutdown();
                        }
                        else {
                            Dispose();
                        }

                        return true;
                    };

                if (!YieldContext::Spawn(allocator.get(), *context_, strand_.get(), spawn_work)) {
                    native_tap_relay_started_.store(false, std::memory_order_release);
                    return false;
                }

                return true;
            }
#endif
        }
    }
}
