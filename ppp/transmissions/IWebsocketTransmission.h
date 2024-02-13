#pragma once

#include <ppp/transmissions/templates/WebSocket.h>

namespace ppp {
    namespace transmissions {
        class IWebsocketTransmission : public ppp::transmissions::templates::WebSocket<ppp::net::asio::websocket> {
        public:
            IWebsocketTransmission(
                const ContextPtr&                                       context,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                const AppConfigurationPtr&                              configuration) noexcept;

        public:
            ppp::string                                                 Host;
            ppp::string                                                 Path;

        protected:
            virtual bool                                                HandshakeWebsocket(
                const AppConfigurationPtr&                              configuration,
                const std::shared_ptr<ppp::net::asio::websocket>&       socket,
                HandshakeType                                           handshake_type,
                YieldContext&                                           y) noexcept;
            virtual bool                                                Decorator(boost::beast::websocket::request_type& req) noexcept override;
            virtual bool                                                Decorator(boost::beast::websocket::response_type& res) noexcept override;
        };

        class ISslWebsocketTransmission : public ppp::transmissions::templates::WebSocket<ppp::net::asio::sslwebsocket> {
        public:
            ISslWebsocketTransmission(
                const ContextPtr&                                       context,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                const AppConfigurationPtr&                              configuration) noexcept;

        public:
            ppp::string                                                 Host;
            ppp::string                                                 Path;

        protected:
            virtual bool                                                HandshakeWebsocket(
                const AppConfigurationPtr&                              configuration,
                const std::shared_ptr<ppp::net::asio::sslwebsocket>&    socket,
                HandshakeType                                           handshake_type,
                YieldContext&                                           y) noexcept;
            virtual bool                                                Decorator(boost::beast::websocket::request_type& req) noexcept override;
            virtual bool                                                Decorator(boost::beast::websocket::response_type& res) noexcept override;
        };
    }
}