#pragma once

/**
 * @file VirtualEthernetTcpipConnection.h
 * @brief Declares TCP/IP bridge connection between socket and transmission.
 * @author ("OPENPPP2 Team")
 * @license ("GPL-3.0")
 */

#include <ppp/coroutines/YieldContext.h>

namespace ppp::configurations { class AppConfiguration; }
namespace ppp::diagnostics::datapath_perf { class Scope; }
#include <ppp/net/Firewall.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/app/runtime/XtcpFirstLegHooks.h>
#include <ppp/app/protocol/DirectReadWaiterState.h>
#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>

#include <atomic>
#include <deque>

#if defined(_WIN32)
#include <windows/ppp/net/QoSS.h>
#elif defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace ppp {
    namespace app {
        namespace protocol {
            /**
             * @brief Bridges a local TCP socket and a virtual Ethernet transmission channel.
             */
            class VirtualEthernetTcpipConnection : public std::enable_shared_from_this<VirtualEthernetTcpipConnection> {
            public:
                typedef ppp::configurations::AppConfiguration                   AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                       AppConfigurationPtr;
                typedef ppp::net::Firewall                                      Firewall;
                typedef std::shared_ptr<ppp::net::Firewall>                     FirewallPtr;
                typedef ppp::threading::Executors::StrandPtr                    StrandPtr;
                typedef std::shared_ptr<boost::asio::io_context>                ContextPtr;
                typedef ppp::coroutines::YieldContext                           YieldContext;
                typedef ppp::transmissions::ITransmission                       ITransmission;
                typedef std::shared_ptr<ITransmission>                          ITransmissionPtr;
                typedef ppp::app::protocol::VirtualEthernetLogger               VirtualEthernetLogger;
                typedef std::shared_ptr<VirtualEthernetLogger>                  VirtualEthernetLoggerPtr;
                typedef ppp::function<bool(uint32_t, uint32_t, uint32_t)>       AcceptMuxAsynchronousCallback;
                enum class DirectIoResult : uint8_t {
                    Accepted,
                    Backpressured,
                    Closed,
                };
                typedef ppp::function<DirectIoResult(
                    client::xtcp::XtcpDirectReadReservation&,
                    const std::shared_ptr<Byte>&)>                              DirectReadHandler;
                typedef ppp::function<void(client::xtcp::XtcpDirectCloseReason)> DirectCloseHandler;
                typedef ppp::function<void()>                                  DirectWritableHandler;

#if defined(_LINUX)
            public:
                /**
                 * @brief Shared pointer type for Linux socket protection helper.
                 */
                typedef std::shared_ptr<ppp::net::ProtectorNetwork>             ProtectorNetworkPtr;

            public:
                ProtectorNetworkPtr                                             ProtectorNetwork;
#endif

            public:
                /**
                 * @brief Initializes a TCP/IP connection bridge object.
                 * @param configuration Runtime application configuration.
                 * @param context Asio IO context.
                 * @param strand Serialized executor for callbacks.
                 * @param id Logical connection identifier.
                 * @param socket Existing TCP socket instance.
                 * @return N/A.
                 * @note The socket can be null for mux-only handshake flows.
                 */
                VirtualEthernetTcpipConnection(
                    const AppConfigurationPtr&                                  configuration,
                    const ContextPtr&                                           context,
                    const StrandPtr&                                            strand,
                    const Int128&                                               id,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&        socket) noexcept;
                /**
                 * @brief Releases connection resources.
                 * @return N/A.
                 * @note Destructor finalizes transmission and socket state.
                 */
                virtual ~VirtualEthernetTcpipConnection() noexcept;

            public:
                /** @brief Checks whether the bridge is currently linked. @return True when not disposed and connected. @note Lightweight state check. */
                bool                                                            IsLinked()          noexcept { return !disposed_ && connected_; }
                /** @brief Gets a shared self-reference. @return Shared pointer to current object. @note Requires object ownership by `shared_ptr`. */
                std::shared_ptr<VirtualEthernetTcpipConnection>                 GetReference()      noexcept { return shared_from_this(); }
                /** @brief Gets IO context. @return Context shared pointer. @note No ownership transfer. */
                ContextPtr                                                      GetContext()        noexcept { return context_; }
                /** @brief Gets strand executor. @return Strand shared pointer. @note Used to serialize internal operations. */
                StrandPtr                                                       GetStrand()         noexcept { return strand_; }
                /** @brief Gets runtime configuration. @return Configuration shared pointer. @note Read-only access pattern by convention. */
                AppConfigurationPtr                                             GetConfiguration()  noexcept { return configuration_; }
                /** @brief Gets logical connection id. @return Connection id value. @note Value is assigned during construction. */
                Int128                                                          GetId()             noexcept { return id_; }
                /** @brief Gets underlying TCP socket. @return Socket shared pointer. @note May be null after `Clear()`. */
                std::shared_ptr<boost::asio::ip::tcp::socket>                   GetSocket()         noexcept { return socket_; }
                /** @brief Gets active transmission. @return Reference to transmission shared pointer. @note Can be null before handshake completes. */
                const ITransmissionPtr&                                         GetTransmission()   noexcept { return transmission_; }

            public:
                /**
                 * @brief Clears connection references without fully disposing object.
                 * @return void.
                 * @note Primarily resets socket/transmission handles.
                 */
                void                                                            Clear() noexcept;
                /**
                 * @brief Initiates active connect handshake over transmission.
                 * @param y Coroutine yield context.
                 * @param transmission Transmission channel to use.
                 * @param host Destination host string.
                 * @param port Destination port.
                 * @return True when connect handshake succeeds.
                 * @note This path expects a normal connect-not-mux flow.
                 */
                virtual bool                                                    Connect(YieldContext& y, ITransmissionPtr& transmission, const ppp::string& host, int port) noexcept;
                /**
                 * @brief Accepts peer connect handshake and opens destination socket.
                 * @param y Coroutine yield context.
                 * @param transmission Transmission channel to use.
                 * @param logger Optional logger for connect events.
                 * @param mux Optional mux accept callback.
                 * @return True when handshake and setup succeed.
                 * @note When `mux` is provided, non-connect packets may be treated as mux handshakes.
                 */
                virtual bool                                                    Accept(YieldContext& y, ITransmissionPtr& transmission, const VirtualEthernetLoggerPtr& logger, const AcceptMuxAsynchronousCallback& mux) noexcept;

                /**
                 * @brief Initiates mux-on handshake.
                 * @param y Coroutine yield context.
                 * @param transmission Transmission channel to use.
                 * @param vlan Mux VLAN identifier.
                 * @param seq Sequence value.
                 * @param ack Acknowledge value.
                 * @return True on successful mux negotiation.
                 * @note Uses control-plane handshake without destination host/port.
                 */
                virtual bool                                                    ConnectMux(YieldContext& y, ITransmissionPtr& transmission, uint32_t vlan, uint32_t seq, uint32_t ack) noexcept;
                /**
                 * @brief Accepts mux-on handshake.
                 * @param y Coroutine yield context.
                 * @param transmission Transmission channel to use.
                 * @param ac Callback invoked with negotiated mux fields.
                 * @return True on successful mux negotiation.
                 * @note Callback must be valid and return true to complete acceptance.
                 */
                virtual bool                                                    AcceptMux(YieldContext& y, ITransmissionPtr& transmission, const AcceptMuxAsynchronousCallback& ac) noexcept;

            public:
                /**
                 * @brief Starts bidirectional forwarding loop.
                 * @param y Coroutine yield context.
                 * @return True if at least one direction starts successfully.
                 * @note Returns after forwarding loop exits and disposal is scheduled.
                 */
                virtual bool                                                    Run(YieldContext& y) noexcept;
                /**
                 * @brief Updates activity state.
                 * @return void.
                 * @note Default implementation is empty and can be overridden.
                 */
                virtual void                                                    Update() noexcept {};
                /**
                 * @brief Schedules asynchronous disposal of this connection.
                 * @return void.
                 * @note Actual cleanup runs on configured context/strand.
                 */
                virtual void                                                    Dispose() noexcept;
                /**
                 * @brief Gets firewall policy object.
                 * @return Firewall instance or null.
                 * @note Base implementation returns null.
                 */
                virtual std::shared_ptr<ppp::net::Firewall>                     GetFirewall() noexcept { return NULLPTR; }
                /**
                 * @brief Sends a raw buffer to peer through transmission.
                 * @param y Coroutine yield context.
                 * @param packet Buffer pointer.
                 * @param packet_length Buffer size.
                 * @return True on successful write.
                 * @note Requires connected and non-disposed state.
                 */
                virtual bool                                                    SendBufferToPeer(YieldContext& y, const void* packet, int packet_length) noexcept;
                bool                                                            StartDirectBridge(const DirectReadHandler& on_data, const DirectCloseHandler& on_close, const DirectWritableHandler& on_writable) noexcept;
                DirectIoResult                                                  SendDirectToPeer(const Byte* data, std::uint32_t length,
                    client::xtcp::XtcpUploadBudget::Reservation&& credit) noexcept;
                void                                                            CompleteDirectDownload(
                    const client::xtcp::XtcpDirectReadReservation& reservation,
                    client::xtcp::XtcpDirectCompletion completion) noexcept;
                void                                                            SetDirectQueueTelemetry(
                    const std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry>& telemetry) noexcept;
                void                                                            CloseDirectSend() noexcept;

#if defined(_IPHONE) || defined(IPHONE)
                /**
                 * @brief Queues native TUN upload payload for a single writer coroutine.
                 */
                bool                                                            SendBufferToPeerAsync(const void* packet, int packet_length) noexcept;
                bool                                                            SendBufferToPeerAsync(const std::shared_ptr<std::vector<Byte>>& payload) noexcept;
                /**
                 * @brief Disposes only this child transport without cascading into the owning TapTcpClient.
                 */
                void                                                            DisposeNativeTransportOnly() noexcept;
                /**
                 * @brief Reads VPN responses and forwards them through the supplied callback.
                 */
                bool                                                            StartNativeTapRelay(const ppp::function<void(const void*, size_t)>& on_data, const ppp::function<void()>& on_shutdown = ppp::function<void()>()) noexcept;
#endif

            private:
                /**
                 * @brief Finalizes connection synchronously.
                 * @return void.
                 * @note Called by destructor and posted dispose path.
                 */
                void                                                            Finalize() noexcept;
                /**
                 * @brief Starts socket-read to transmission forwarding side.
                 * @return True when initial receive is armed.
                 * @note Allocates and schedules asynchronous socket reads.
                 */
                bool                                                            ReceiveTransmissionToSocket() noexcept;
                /**
                 * @brief Runs transmission-read to socket-write forwarding loop.
                 * @param y Coroutine yield context.
                 * @return True if at least one packet is forwarded.
                 * @note Loop ends on read/write failure or disposal.
                 */
                bool                                                            ForwardTransmissionToSocket(YieldContext& y) noexcept;
                bool                                                            RunDirectUpload(YieldContext& y) noexcept;
                bool                                                            RunDirectDownload(YieldContext& y) noexcept;
                bool                                                            StartDirectUploadWriter() noexcept;
                /**
                 * @brief Arms asynchronous read from socket.
                 * @param buffer Receive buffer.
                 * @param buffer_size Receive buffer capacity.
                 * @return True when async read scheduling succeeds.
                 * @note Read completion forwards data to transmission.
                 */
                bool                                                            ReceiveSocketToTransmission(const std::shared_ptr<Byte>& buffer, int buffer_size) noexcept;
                /**
                 * @brief Forwards one socket chunk to transmission.
                 * @param buffer Receive buffer.
                 * @param buffer_size Buffer capacity.
                 * @param bytes_transferred Number of bytes to forward.
                 * @param transmission_write_accepted_scope Read-to-write-completion timer.
                 * @return True when asynchronous write is accepted.
                 * @note Completion callback decides continuation/disposal.
                 */
                bool                                                            ForwardSocketToTransmission(const std::shared_ptr<Byte>& buffer, int buffer_size, int bytes_transferred, ppp::diagnostics::datapath_perf::Scope transmission_write_accepted_scope) noexcept;
                /**
                 * @brief Handles completion of socket-to-transmission forward.
                 * @param ok True when write completed successfully.
                 * @param buffer Receive buffer.
                 * @param buffer_size Buffer capacity.
                 * @return void.
                 * @note Continues receive loop on success; otherwise disposes connection.
                 */
                void                                                            ForwardSocketToTransmissionOK(bool ok, const std::shared_ptr<Byte>& buffer, int buffer_size) noexcept {
                    if (ok) {
                        ok = ReceiveSocketToTransmission(buffer, buffer_size);
                    }

                    if (ok) {
                        Update();
                    }
                    else {
                        Dispose();
                    }
                }

            private:
                /**
                 * @brief Shared accept-side negotiation helper.
                 * @param y Coroutine yield context.
                 * @param transmission Transmission channel.
                 * @param logger Optional logger.
                 * @param accept_mux_ac Optional mux callback.
                 * @param mux_or_connect True for mux mode; false for connect mode.
                 * @return True when negotiation succeeds.
                 * @note Handles both connect and mux acceptance entry points.
                 */
                bool                                                            MuxOrAccept(
                    YieldContext&                                               y,
                    ITransmissionPtr&                                           transmission,
                    const VirtualEthernetLoggerPtr&                             logger,
                    const AcceptMuxAsynchronousCallback&                        accept_mux_ac,
                    bool                                                        mux_or_connect) noexcept;
                /**
                 * @brief Shared connect-side negotiation helper.
                 * @param y Coroutine yield context.
                 * @param transmission Transmission channel.
                 * @param host Destination host for connect mode.
                 * @param port Destination port for connect mode.
                 * @param vlan VLAN value for mux mode.
                 * @param seq Sequence value for mux mode.
                 * @param ack Acknowledge value for mux mode.
                 * @param mux_or_connect True for mux mode; false for connect mode.
                 * @return True when negotiation succeeds.
                 * @note Handles both connect and mux active entry points.
                 */
                bool                                                            MuxOrConnect(
                    YieldContext&                                               y,
                    ITransmissionPtr&                                           transmission,
                    const ppp::string&                                          host,
                    int                                                         port,
                    uint32_t                                                    vlan,
                    uint32_t                                                    seq,
                    uint32_t                                                    ack,
                    bool                                                        mux_or_connect) noexcept;

            private:
#if defined(_WIN32)
                std::shared_ptr<ppp::net::QoSS>                                 qoss_;          ///< Windows QoS socket handle for traffic prioritization.
#endif
                // Cross-executor lifecycle state: written by Finalize() on the lifecycle strand,
                // read by read/write completions running on the socket executor.
                std::atomic<bool>                                               disposed_ = { false }; ///< True after `Finalize()` has been invoked; guards idempotent cleanup.
                std::atomic<bool>                                               connected_ = { false }; ///< True once a successful handshake has been completed.
                AppConfigurationPtr                                             configuration_; ///< Runtime configuration shared with the owning context.
                ContextPtr                                                      context_;       ///< Asio IO context driving async operations for this connection.
                StrandPtr                                                       strand_;        ///< Serialized executor guaranteeing single-threaded callback ordering.
                Int128                                                          id_        = 0; ///< Logical connection identifier assigned at construction time.
                std::shared_ptr<boost::asio::ip::tcp::socket>                   socket_;        ///< Local TCP socket bridged to the virtual Ethernet transmission.
                ITransmissionPtr                                                transmission_; ///< Virtual Ethernet transmission channel used for protocol framing.
                static constexpr size_t                                         kDirectQueueMaxPackets = 4096;
                static constexpr size_t                                         kDirectQueueLowPackets = kDirectQueueMaxPackets / 2;
                static constexpr size_t                                         kDirectQueueMaxBytes = 32 * 1024 * 1024;
                static constexpr size_t                                         kDirectQueueLowBytes = kDirectQueueMaxBytes / 2;
                static constexpr size_t                                         kDirectDownloadChunkBytes = 16 * 1024;
                static constexpr int                                            kDirectCloseDrainPollMilliseconds = 5;
                enum class DirectSendCloseState : uint8_t {
                    Open,
                    Draining,
                    SendShutdown,
                    Disposed,
                };
                std::mutex                                                      direct_sync_;
                std::deque<std::shared_ptr<client::xtcp::XtcpUploadChunk>>        direct_upload_queue_;
                size_t                                                          direct_upload_bytes_ = 0;
                size_t                                                          direct_upload_packets_ = 0;
                bool                                                            direct_bridge_started_ = false;
                bool                                                            direct_upload_writer_started_ = false;
                DirectSendCloseState                                            direct_send_close_state_ = DirectSendCloseState::Open;
                bool                                                            direct_upload_backpressured_ = false;
                DirectReadHandler                                               direct_read_handler_;
                DirectCloseHandler                                              direct_close_handler_;
                DirectWritableHandler                                           direct_writable_handler_;
                DirectReadWaiterState                                           direct_download_waiter_;
                std::shared_ptr<ppp::app::runtime::XtcpDirectQueueTelemetry>    direct_queue_telemetry_;
#if defined(_IPHONE) || defined(IPHONE)
                bool                                                            EnsureNativeUploadWriter() noexcept;
                bool                                                            RunNativeUploadWriter(YieldContext& y) noexcept;

                static constexpr size_t                                         kNativeUploadQueueMaxPackets = 1024;
                static constexpr size_t                                         kNativeUploadQueueMaxBytes = 1024 * 1024;
                static constexpr size_t                                         kNativeUploadCoalesceMaxBytes = 16 * 1024;
                std::mutex                                                      native_upload_mutex_;
                std::deque<std::shared_ptr<std::vector<Byte>>>                  native_upload_queue_;
                size_t                                                          native_upload_queued_bytes_ = 0;
                bool                                                            native_upload_writer_started_ = false;
                std::atomic_bool                                                native_tap_relay_started_ = { false };
#endif
            };
        }
    }
}
