/**
 * @file ITransmission.h
 * @brief Declares the base encrypted transmission abstraction.
 */
#pragma once

/** @brief Project precompiled header and core dependencies. */
#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>

namespace ppp::configurations { class AppConfiguration; }
#include <ppp/transmissions/IAuthenticatedCarrierBinding.h>
#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/transmissions/ITransmissionStatistics.h>

namespace ppp::cryptography::noise { class NoisePskHandshakeResult; }

namespace ppp {
    namespace transmissions {

        class NoisePskAuthenticatedCarrierBinding;

        enum class AuthenticatedCarrierKind : std::uint8_t {
            None,
            Tcp,
            WebSocket,
            TlsWebSocket,
        };

        enum class AuthenticatedCarrierMethod : std::uint8_t {
            None,
            NoisePskV1,
            TlsExporterV1,
        };

        /** Encodes transport-auth-v1 capability without adding a handshake frame. */
        class TransportAuthHandshakeCapabilityCodec final {
        public:
            static Int128 EncodeClientNmux(Int128 value, bool mux, bool policy_enabled) noexcept {
                const std::uint64_t high = static_cast<std::uint64_t>(value >> 64);
                const std::uint64_t low = EncodeWord(static_cast<std::uint64_t>(value),
                    ClientNmuxMagic, mux, policy_enabled);
                return MAKE_OWORD(low, high);
            }

            static bool DecodeClientNmux(Int128 value, bool& supports_v1,
                bool& policy_enabled) noexcept {
                return DecodeWord(static_cast<std::uint64_t>(value), ClientNmuxMagic,
                    supports_v1, policy_enabled);
            }

            static Int128 EncodeServerIvv(Int128 value, bool policy_enabled) noexcept {
                const std::uint64_t high = static_cast<std::uint64_t>(value >> 64);
                const std::uint64_t low = EncodeWord(static_cast<std::uint64_t>(value),
                    ServerIvvMagic, (static_cast<std::uint64_t>(value) & 1ULL) != 0,
                    policy_enabled);
                return MAKE_OWORD(low, high);
            }

            static bool DecodeServerIvv(Int128 value, bool& supports_v1,
                bool& policy_enabled) noexcept {
                return DecodeWord(static_cast<std::uint64_t>(value), ServerIvvMagic,
                    supports_v1, policy_enabled);
            }

        private:
            static constexpr std::uint64_t ClientNmuxMagic = 0x5452414E5331ULL;
            static constexpr std::uint64_t ServerIvvMagic = 0x5452414E5332ULL;

            static std::uint64_t EncodeWord(std::uint64_t entropy,
                std::uint64_t magic, bool bit0, bool policy_enabled) noexcept {
                constexpr std::uint64_t payload_mask = 0x000000000000FFF8ULL;
                return (magic << 16) | (entropy & payload_mask) |
                    (policy_enabled ? 1ULL << 2 : 0ULL) | (1ULL << 1) |
                    (bit0 ? 1ULL : 0ULL);
            }

            static bool DecodeWord(std::uint64_t value, std::uint64_t magic,
                bool& supports_v1, bool& policy_enabled) noexcept {
                supports_v1 = false;
                policy_enabled = false;
                if ((value >> 16) != magic) {
                    return false;
                }
                supports_v1 = (value & (1ULL << 1)) != 0;
                policy_enabled = (value & (1ULL << 2)) != 0;
                return true;
            }
        };

        /**
         * @brief Base class for encrypted, handshaked, coroutine-aware transport I/O.
         */
        class ITransmission : public ppp::net::asio::IAsynchronousWriteIoQueue,
            public IAuthenticatedCarrierBinding {
            /** @brief Bridge helper that implements internal static read/write logic. */
            friend class ITransmissionBridge;
            /** @brief QoS helper requires direct access to transmission internals. */
            friend class ITransmissionQoS;

            /** @brief Deadline timer type used for handshake timeout control (monotonic, immune to wall-clock jumps). */
            typedef boost::asio::steady_timer                                                       DeadlineTimer;
            /** @brief Shared deadline timer pointer. */
            typedef std::shared_ptr<DeadlineTimer>                                                  DeadlineTimerPtr;

        public:
            /** @brief Application configuration type. */
            typedef ppp::configurations::AppConfiguration                                           AppConfiguration;
            /** @brief Shared application configuration pointer. */
            typedef std::shared_ptr<AppConfiguration>                                               AppConfigurationPtr;
            /** @brief Symmetric cipher wrapper type. */
            typedef ppp::cryptography::Ciphertext                                                   Ciphertext;
            /** @brief Shared cipher pointer. */
            typedef std::shared_ptr<Ciphertext>                                                     CiphertextPtr;
            /** @brief Coroutine yield context type. */
            typedef ppp::coroutines::YieldContext                                                   YieldContext;
            /** @brief Shared io_context pointer type. */
            typedef std::shared_ptr<boost::asio::io_context>                                        ContextPtr;
            /** @brief Shared strand pointer for serialized callback execution. */
            typedef std::shared_ptr<boost::asio::strand<boost::asio::io_context::executor_type>>    StrandPtr;
            /** @brief Asynchronous write completion callback type. */
            typedef ppp::function<void(bool)>                                                       AsynchronousWriteBytesCallback, AsynchronousWriteCallback;

        public:
            /**
             * @brief Initializes transmission context, strand, and cipher configuration.
             * @param context Shared io_context used by async operations.
             * @param strand Shared strand used for serialized state access.
             * @param configuration Application-level transmission configuration.
             */
            ITransmission(const ContextPtr& context, const StrandPtr& strand,
                const AppConfigurationPtr& configuration) noexcept;
            /** @brief Virtual destructor for polymorphic cleanup. */
            virtual ~ITransmission() noexcept;

        public:
            /** @brief Optional traffic statistics sink. */
            std::shared_ptr<ITransmissionStatistics> Statistics;
            /** @brief Optional QoS coordinator used by derived transports. */
            std::shared_ptr<ITransmissionQoS> QoS;

        public:
            /** @brief Gets current transmission configuration. */
            AppConfigurationPtr                                                                     GetConfiguration() noexcept { return configuration_; }
            /** @brief Gets mutable shared io_context reference. */
            ContextPtr&                                                                             GetContext() noexcept { return context_; }
            /** @brief Gets immutable shared io_context reference. */
            const ContextPtr&                                                                       GetContext() const noexcept { return context_; }
            /** @brief Gets mutable shared strand reference. */
            StrandPtr&                                                                              GetStrand() noexcept { return strand_; }
            /** @brief Gets immutable shared strand reference. */
            const StrandPtr&                                                                        GetStrand() const noexcept { return strand_; }
            /** @brief Reports whether the authenticated OpenPPP2 handshake completed. */
            virtual bool                                                                            IsHandshakeComplete() const noexcept { return handshaked_.load(std::memory_order_acquire); }
            /** @brief Reports whether the peer advertised transport-auth-v1 support. */
            bool                                                                                    PeerSupportsTransportAuthV1() const noexcept { return peer_supports_transport_auth_v1_.load(std::memory_order_acquire); }
            /** @brief Reports whether the peer also enabled its transport-auth-v1 policy. */
            bool                                                                                    PeerEnablesTransportAuthV1() const noexcept { return peer_enables_transport_auth_v1_.load(std::memory_order_acquire); }
            /** @brief Marks accepted server ingress whose peer endpoint is loopback. */
            void                                                                                    MarkServerLoopbackIngress() noexcept { server_loopback_ingress_.store(true, std::memory_order_release); }
            /** @brief Reports conservative server-side loopback ingress provenance. */
            bool                                                                                    IsServerLoopbackIngress() const noexcept { return server_loopback_ingress_.load(std::memory_order_acquire); }

        public:
            /** @brief Disposes transmission resources asynchronously. */
            virtual void                                                                            Dispose() noexcept override;
            /** @brief Moves transport execution to its scheduler if required. */
            virtual bool                                                                            ShiftToScheduler() noexcept = 0;
            /** @brief Returns remote TCP endpoint information. */
            virtual boost::asio::ip::tcp::endpoint                                                  GetRemoteEndPoint() noexcept = 0;
            /** @brief Identifies the carrier represented by this transmission. */
            virtual AuthenticatedCarrierKind                                                        GetAuthenticatedCarrierKind() const noexcept { return AuthenticatedCarrierKind::None; }
            /** @brief Reports whether this carrier can safely half-close its send direction. */
            virtual bool                                                                            SupportsSendHalfClose() const noexcept { return false; }
            /** @brief Half-closes the carrier send direction without closing receive. */
            virtual bool                                                                            ShutdownSend() noexcept { return false; }
            /** @brief Reports a clean peer close of the carrier receive direction. */
            virtual bool                                                                            IsReceiveClosed() const noexcept { return false; }
            /** @brief Identifies the installed authenticated carrier mechanism. */
            virtual AuthenticatedCarrierMethod                                                      GetAuthenticatedCarrierMethod() const noexcept;
            /** @brief Reports current lifecycle-valid authenticated carrier availability. */
            virtual bool                                                                            IsAuthenticatedCarrierBindingActive() const noexcept;
            /** @brief Reports whether this transport exposes an authenticated session exporter. */
            bool                                                                                    HasAuthenticatedSessionExporter() const noexcept override;
            /** @brief Exports authenticated session-bound key material. */
            bool                                                                                    ExportAuthenticatedSessionKey(
                const char* label,
                const std::uint8_t* context,
                std::size_t context_length,
                std::uint8_t* output,
                std::size_t output_length) noexcept override;
            /** @brief Installs the one-shot Noise carrier binding after application handshake. */
            bool                                                                                    InstallNoiseAuthenticatedCarrierBinding(
                ppp::cryptography::noise::NoisePskHandshakeResult&& result) noexcept;
            /** @brief Synchronously invalidates and clears installed Noise carrier material. */
            void                                                                                    InvalidateAuthenticatedCarrierBinding() noexcept;

        public:
            /**
             * @brief Runs the client-side handshake sequence.
             * @param y Coroutine yield context.
             * @param mux Output flag indicating negotiated multiplexing capability.
             * @return Negotiated session identifier, or zero on failure.
             */
            virtual Int128                                                                          HandshakeClient(YieldContext& y, bool& mux) noexcept;
            /**
             * @brief Runs the server-side handshake sequence.
             * @param y Coroutine yield context.
             * @param session_id Session identifier provided by upper layer.
             * @param mux Requested multiplexing behavior.
             * @return true if handshake succeeds; otherwise false.
             */
            virtual bool                                                                            HandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept;

        public:
            /**
             * @brief Encrypts plaintext payload into transmission packet bytes.
             * @param data Input payload pointer.
             * @param datalen Input payload length.
             * @param outlen Output encrypted length.
             * @return Encrypted packet buffer, or null on failure.
             */
            std::shared_ptr<Byte>                                                                   Encrypt(Byte* data, int datalen, int& outlen) noexcept;
            /**
             * @brief Decrypts packet bytes into plaintext payload.
             * @param data Input packet pointer.
             * @param datalen Input packet length.
             * @param outlen Output plaintext length.
             * @return Decrypted payload buffer, or null on failure.
             */
            std::shared_ptr<Byte>                                                                   Decrypt(Byte* data, int datalen, int& outlen) noexcept;
            /**
             * @brief Reads and decrypts one payload from the underlying transport.
             * @param y Coroutine yield context.
             * @param outlen Output payload length.
             * @return Decrypted payload buffer, or null on failure.
             */
            virtual std::shared_ptr<Byte>                                                           Read(YieldContext& y, int& outlen) noexcept;
            /**
             * @brief Encrypts and writes payload bytes using coroutine flow.
             * @param y Coroutine yield context.
             * @param packet Payload pointer.
             * @param packet_length Payload length.
             * @return true if write succeeds; otherwise false.
             */
            virtual bool                                                                            Write(YieldContext& y, const void* packet, int packet_length) noexcept;
            /**
             * @brief Encrypts and writes payload bytes using callback flow.
             * @param packet Payload pointer.
             * @param packet_length Payload length.
             * @param cb Completion callback.
             * @return true if write is scheduled; otherwise false.
             */
            virtual bool                                                                            Write(const void* packet, int packet_length, const AsynchronousWriteCallback& cb) noexcept;

        protected:
            /**
             * @brief Reads raw bytes from derived transport implementation.
             * @param y Coroutine yield context.
             * @param length Number of bytes to read.
             * @return Raw byte buffer, or null on failure.
             */
            virtual std::shared_ptr<Byte>                                                           DoReadBytes(YieldContext& y, int length) noexcept = 0;

        private:
            /** @brief Performs internal resource cleanup. */
            void                                                                                    Finalize() noexcept;
            /** @brief Cancels and releases the handshake timeout timer. */
            void                                                                                    InternalHandshakeTimeoutClear() noexcept;
            /** @brief Arms handshake timeout with randomized jitter. */
            bool                                                                                    InternalHandshakeTimeoutSet() noexcept;
            /** @brief Executes core client handshake steps. */
            Int128                                                                                  InternalHandshakeClient(YieldContext& y, bool& mux) noexcept;
            /** @brief Executes core server handshake steps. */
            bool                                                                                    InternalHandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept;

        private:
            /**
             * @brief Thread-safe transmission lifecycle and framing state.
             *
             * These flags are touched by the read coroutine, callback-based writes,
             * keepalive/update tasks, handshake timeout handlers, and disposal paths. They must
             * not share a packed bitfield storage unit: Android can run those handlers on
             * different executor threads, and a packed read/write races at the byte containing all
             * flags. Independent atomics keep the state publication well-defined.
             */
            std::atomic_bool                                                                        disposed_{false};
            /** @brief Set after receive path switches to simple header mode. */
            std::atomic_bool                                                                        frame_rn_{false};
            /** @brief Set after transmit path switches to simple header mode. */
            std::atomic_bool                                                                        frame_tn_{false};
            /** @brief Handshake completion state flag storage. */
            std::atomic_bool                                                                        handshaked_{false};
            /** @brief Validated peer transport-auth-v1 capability state. */
            std::atomic_bool                                                                        peer_supports_transport_auth_v1_{false};
            /** @brief Validated peer transport-auth-v1 policy state. */
            std::atomic_bool                                                                        peer_enables_transport_auth_v1_{false};
            /** @brief Server-side accepted peer was loopback or could not be classified. */
            std::atomic_bool                                                                        server_loopback_ingress_{false};

            /**
             * @brief One-shot guard ensuring Finalize() executes at most once.
             *
             * The first caller that flips it from false to true proceeds with teardown; all
             * subsequent callers return early.
             */
            std::atomic<bool>                                                                       finalized_{false};

            /** @brief Backing io_context for async operation dispatch. */
            ContextPtr                                                                              context_;           // Asio io_context (never null after construction).
            /** @brief Strand for serialized asynchronous state transitions. */
            StrandPtr                                                                               strand_;            // Strand for thread‑safe state access.
            /** @brief Serializes install/invalidate publication of Noise carrier state. */
            mutable std::mutex                                                                      authenticated_carrier_mutex_;
            /** @brief Carrier-local Noise authenticated exporter, when installed. */
            std::shared_ptr<NoisePskAuthenticatedCarrierBinding>                                    noise_authenticated_carrier_binding_;
            /** @brief Active handshake timeout timer, if armed. */
            DeadlineTimerPtr                                                                        timeout_;           // Handshake timeout timer (reset after success).
            /** @brief Optional protocol-layer cipher instance. */
            CiphertextPtr                                                                           protocol_;          // Protocol‑layer cipher (optional).
            /** @brief Optional transport-layer cipher instance. */
            CiphertextPtr                                                                           transport_;         // Transport‑layer cipher (optional).
            /** @brief Shared immutable transmission configuration. */
            AppConfigurationPtr                                                                     configuration_;     // Configuration (never null after construction).
        };

    } /** namespace transmissions */
} /** namespace ppp */
