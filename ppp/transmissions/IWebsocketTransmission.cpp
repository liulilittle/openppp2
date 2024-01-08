#include <ppp/transmissions/IWebsocketTransmission.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace transmissions {
        IWebsocketTransmission::IWebsocketTransmission(
            const ContextPtr&                                       context,
            const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
            const AppConfigurationPtr&                              configuration) noexcept
            : WebSocket(context, socket, configuration) {

        }

        bool IWebsocketTransmission::HandshakeWebsocket(
            const AppConfigurationPtr&                              configuration,
            const std::shared_ptr<ppp::net::asio::websocket>&       socket,
            HandshakeType                                           handshake_type,
            YieldContext&                                           y) noexcept {

            ppp::string host = std::move(this->Host);
            ppp::string path = std::move(this->Path);

            if (host.size() > 0 && path.size() > 0) {
                return socket->Run(handshake_type, host, path, y);
            }
            else {
                auto& cfg = configuration->websocket;
                return socket->Run(handshake_type, cfg.host, cfg.path, y);
            }
        }

        ISslWebsocketTransmission::ISslWebsocketTransmission(
            const ContextPtr&                                       context,
            const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
            const AppConfigurationPtr&                              configuration) noexcept
            : WebSocket(context, socket, configuration) {

        }

        bool ISslWebsocketTransmission::HandshakeWebsocket(
            const AppConfigurationPtr&                              configuration,
            const std::shared_ptr<ppp::net::asio::sslwebsocket>&    socket,
            HandshakeType                                           handshake_type,
            YieldContext&                                           y) noexcept {

            ppp::string host = std::move(this->Host);
            ppp::string path = std::move(this->Path);

            if (host.size() > 0 && path.size() > 0) {
                auto& cfg = configuration->websocket;
                return socket->Run(handshake_type,
                    host,
                    path,
                    cfg.ssl.verify_peer,
                    cfg.ssl.certificate_file,
                    cfg.ssl.certificate_key_file,
                    cfg.ssl.certificate_chain_file,
                    cfg.ssl.certificate_key_password,
                    cfg.ssl.ciphersuites,
                    y);
            }
            else {
                auto& cfg = configuration->websocket;
                return socket->Run(handshake_type,
                    cfg.host,
                    cfg.path,
                    cfg.ssl.verify_peer,
                    cfg.ssl.certificate_file,
                    cfg.ssl.certificate_key_file,
                    cfg.ssl.certificate_chain_file,
                    cfg.ssl.certificate_key_password,
                    cfg.ssl.ciphersuites,
                    y);
            }
        }
    }
}