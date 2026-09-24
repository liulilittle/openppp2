#pragma once

#include <ppp/transmissions/templates/WebSocket.h>

/**
 * @file IWebsocketTransmission.h
 * @brief Declares plaintext and TLS websocket transmission adapters.
 */

namespace ppp {
    namespace transmissions {
        /**
         * @brief WebSocket transport wrapper for non-TLS connections.
         */
        class IWebsocketTransmission : public ppp::transmissions::templates::WebSocket<ppp::net::asio::websocket> {
        public:
            /**
             * @brief Constructs a websocket transmission instance.
             * @param context Shared io_context owner.
             * @param strand Serialized execution strand.
             * @param socket Accepted or connected TCP socket.
             * @param configuration Application/network configuration.
             */
            IWebsocketTransmission(
                const ContextPtr&                                       context,
                const StrandPtr&                                        strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                const AppConfigurationPtr&                              configuration) noexcept;
            virtual ~IWebsocketTransmission()                                          noexcept;

        public:
            AuthenticatedCarrierKind GetAuthenticatedCarrierKind() const noexcept override {
                return AuthenticatedCarrierKind::WebSocket;
            }

        public:
            /** @brief Optional host override for websocket handshake. */
            ppp::string                                                 Host;
            /** @brief Optional path override for websocket handshake. */
            ppp::string                                                 Path;

        protected:
            bool ShiftToScheduler() noexcept override;
            /**
             * @brief Performs websocket client/server handshake.
             * @param configuration Runtime websocket configuration.
             * @param socket Websocket transport socket.
             * @param handshake_type Handshake role/type.
             * @param y Coroutine yield context.
             * @return true if handshake succeeds.
             */
            virtual bool                                                HandshakeWebsocket(
                const AppConfigurationPtr&                              configuration,
                const std::shared_ptr<ppp::net::asio::websocket>&       socket,
                HandshakeType                                           handshake_type,
                YieldContext&                                           y) noexcept;
            /**
             * @brief Decorates outgoing websocket HTTP request headers.
             * @param req Handshake request object.
             * @return true if decoration is applied.
             */
            virtual bool                                                Decorator(boost::beast::websocket::request_type& req) noexcept override;
            /**
             * @brief Decorates websocket HTTP response sent to the peer.
             * @param res Handshake response object.
             * @return true if decoration is applied.
             */
            virtual bool                                                Decorator(boost::beast::websocket::response_type& res) noexcept override;
        };

        /**
         * @brief WebSocket transport wrapper for TLS-enabled connections.
         */
        class ISslWebsocketTransmission : public ppp::transmissions::templates::WebSocket<ppp::net::asio::sslwebsocket> {
        public:
            /**
             * @brief Constructs a TLS websocket transmission instance.
             * @param context Shared io_context owner.
             * @param strand Serialized execution strand.
             * @param socket Accepted or connected TCP socket.
             * @param configuration Application/network configuration.
             */
            ISslWebsocketTransmission(
                const ContextPtr&                                       context,
                const StrandPtr&                                        strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                const AppConfigurationPtr&                              configuration) noexcept;
            virtual ~ISslWebsocketTransmission()                                       noexcept;

        public:
            /** @brief Optional host override for websocket handshake. */
            ppp::string                                                 Host;
            /** @brief Optional path override for websocket handshake. */
            ppp::string                                                 Path;

        public:
            AuthenticatedCarrierKind GetAuthenticatedCarrierKind() const noexcept override {
                return AuthenticatedCarrierKind::TlsWebSocket;
            }
            AuthenticatedCarrierMethod GetAuthenticatedCarrierMethod() const noexcept override {
                return AuthenticatedCarrierMethod::TlsExporterV1;
            }
            bool IsAuthenticatedCarrierBindingActive() const noexcept override {
                return HasAuthenticatedSessionExporter();
            }
            void Dispose() noexcept override;
            bool HasAuthenticatedSessionExporter() const noexcept override;
            bool ExportAuthenticatedSessionKey(
                const char* label,
                const std::uint8_t* context,
                std::size_t context_length,
                std::uint8_t* output,
                std::size_t output_length) noexcept override;

        private:
            std::atomic_bool exporter_disabled_{false};

        protected:
            bool ShiftToScheduler() noexcept override;
            /**
             * @brief Performs TLS websocket client/server handshake.
             * @param configuration Runtime websocket configuration.
             * @param socket TLS websocket transport socket.
             * @param handshake_type Handshake role/type.
             * @param y Coroutine yield context.
             * @return true if handshake succeeds.
             */
            virtual bool                                                HandshakeWebsocket(
                const AppConfigurationPtr&                              configuration,
                const std::shared_ptr<ppp::net::asio::sslwebsocket>&    socket,
                HandshakeType                                           handshake_type,
                YieldContext&                                           y) noexcept;
            /**
             * @brief Decorates outgoing websocket HTTP request headers.
             * @param req Handshake request object.
             * @return true if decoration is applied.
             */
            virtual bool                                                Decorator(boost::beast::websocket::request_type& req) noexcept override;
            /**
             * @brief Decorates websocket HTTP response sent to the peer.
             * @param res Handshake response object.
             * @return true if decoration is applied.
             */
            virtual bool                                                Decorator(boost::beast::websocket::response_type& res) noexcept override;
        };
    }
}
