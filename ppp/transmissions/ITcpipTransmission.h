#pragma once

/**
 * @file ITcpipTransmission.h
 * @brief Declares the TCP/IP-based transmission implementation.
 */

#include <ppp/transmissions/ITransmission.h>
#include <atomic>

#if defined(_WIN32)
#include <windows/ppp/net/QoSS.h>
#endif

namespace ppp {
    namespace transmissions {
        /** @brief Distinguishes the VPN main session TCP from per-flow ctcp child TCPs. */
        enum class TcpTransmissionRole {
            Main,
            Child,
            Server,
        };

        /**
         * @brief Implements transmission I/O over a Boost.Asio TCP socket.
         */
        class ITcpipTransmission : public ITransmission {
            /** @brief Grants QoS helper direct access to transport internals. */
            friend class                                                                        ITransmissionQoS;

        public:
            /**
             * @brief Initializes a TCP/IP transmission instance.
             * @param context Shared io_context for async operations.
             * @param strand Shared strand for serialized callbacks.
             * @param socket Connected TCP socket.
             * @param configuration Application transmission configuration.
             */
            ITcpipTransmission(
                const ContextPtr&                                                               context,
                const StrandPtr&                                                                strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&                            socket,
                const AppConfigurationPtr&                                                      configuration,
                TcpTransmissionRole                                                             role = TcpTransmissionRole::Child) noexcept;
            /** @brief Releases transmission resources. */
            virtual ~ITcpipTransmission()                                                                      noexcept;

        public:
            /** @brief Disposes socket state and base transmission resources. */
            virtual void                                                                        Dispose() noexcept override;
            /** @brief Returns the cached remote TCP endpoint. */
            virtual boost::asio::ip::tcp::endpoint                                              GetRemoteEndPoint() noexcept override;
            /** @brief Main/server sockets are authenticated TCP carriers; child flows are not. */
            AuthenticatedCarrierKind                                                            GetAuthenticatedCarrierKind() const noexcept override {
                return role_ == TcpTransmissionRole::Child
                    ? AuthenticatedCarrierKind::None
                    : AuthenticatedCarrierKind::Tcp;
            }
            /** @brief Only raw per-flow TCP carriers can preserve receive after send shutdown. */
            bool                                                                                SupportsSendHalfClose() const noexcept override;
            /** @brief Sends TCP FIN after pending writes have drained on this transmission's strand. */
            bool                                                                                ShutdownSend() noexcept override;
            /** @brief Reports a clean TCP peer FIN observed by ReadBytes. */
            bool                                                                                IsReceiveClosed() const noexcept override;
            /**
             * @brief Reads an exact number of bytes from the socket.
             * @param y Coroutine yield context.
             * @param length Requested number of bytes.
             * @return Byte buffer on success; null on failure.
             */
            virtual std::shared_ptr<Byte>                                                       ReadBytes(YieldContext& y, int length) noexcept;

        protected:
            /**
             * @brief Reads bytes through the QoS-aware read path.
             * @param y Coroutine yield context.
             * @param length Requested number of bytes.
             * @return Byte buffer on success; null on failure.
             */
            virtual std::shared_ptr<Byte>                                                       DoReadBytes(YieldContext& y, int length) noexcept;
            /**
             * @brief Asynchronously writes a byte range to the socket.
             * @param packet Buffer that owns payload memory.
             * @param offset Start offset in @p packet.
             * @param packet_length Number of bytes to write.
             * @param cb Completion callback receiving success state.
             * @return true if write is scheduled; otherwise false.
             */
            virtual bool                                                                        DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;

        private:
            /** @brief Performs one-time cleanup of socket-related resources. */
            void                                                                                Finalize() noexcept;
            /** @brief Migrates the socket to the scheduler selected by Executors. */
            virtual bool                                                                        ShiftToScheduler() noexcept override;

        private:
#if defined(_WIN32)
            /** @brief Optional Windows QoS wrapper for socket traffic classification. */
            std::shared_ptr<ppp::net::QoSS>                                                     qoss_;
#endif
            /** @brief Atomic disposed flag to prevent data races per C++17. Uses exchange pattern for thread-safe state transitions. */
            std::atomic<int>                                                                    disposed_ = FALSE;
            /** @brief Send direction is permanently closed after a successful TCP FIN. */
            std::atomic<bool>                                                                   send_shutdown_ = { false };
            /** @brief Receive direction saw a clean peer FIN rather than a transport failure. */
            std::atomic<bool>                                                                   receive_closed_ = { false };
            /** @brief Owned connected TCP socket. */
            std::shared_ptr<boost::asio::ip::tcp::socket>                                       socket_;
            /** @brief Cached peer endpoint captured at construction. */
            boost::asio::ip::tcp::endpoint                                                      remoteEP_;
            /** @brief Main VPN session vs mux=0 per-flow child transmission. */
            TcpTransmissionRole                                                                 role_ = TcpTransmissionRole::Child;
        };
    }
}
