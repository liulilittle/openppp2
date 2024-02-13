#include <ppp/transmissions/IWebsocketTransmission.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace transmissions {
        template <typename R>
        static inline bool DecoratorWebsocketAllHeaders(ppp::map<ppp::string, ppp::string>& headers, R& r) noexcept {
            if (headers.empty()) {
                return false;
            }

            for (auto&& [k, v] : headers) {
                boost::beast::string_view vsv(v.data(), v.size());
                boost::beast::string_view ksv(k.data(), k.size());
                r.set(ksv, vsv);
            }

            return true;
        }

        static inline bool DecoratorWebsocketResponseToWebclient(const ITransmission::AppConfigurationPtr& configuration, boost::beast::websocket::response_type& res) noexcept {
            if (NULL == configuration) {
                return false;
            }

            int status_code = res.result_int();
            bool ok = DecoratorWebsocketAllHeaders(configuration->websocket.http.request, res);
            if (status_code == 404) {
                std::string& response_body = res.body();
                response_body = configuration->websocket.http.error;
            }

            return ok;
        }

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

        bool IWebsocketTransmission::Decorator(boost::beast::websocket::request_type& req) noexcept {
            auto configuration = GetConfiguration();
            if (NULL == configuration) {
                return false;
            }

            return DecoratorWebsocketAllHeaders(configuration->websocket.http.request, req);
        }
        
        bool IWebsocketTransmission::Decorator(boost::beast::websocket::response_type& res) noexcept {
            return DecoratorWebsocketResponseToWebclient(GetConfiguration(), res);
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

        bool ISslWebsocketTransmission::Decorator(boost::beast::websocket::request_type& req) noexcept {
            auto configuration = GetConfiguration();
            if (NULL == configuration) {
                return false;
            }

            return DecoratorWebsocketAllHeaders(configuration->websocket.http.request, req);
        }

        bool ISslWebsocketTransmission::Decorator(boost::beast::websocket::response_type& res) noexcept {
            return DecoratorWebsocketResponseToWebclient(GetConfiguration(), res);
        }
    }
}