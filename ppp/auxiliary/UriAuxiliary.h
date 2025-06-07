#pragma once

#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace auxiliary {
        class UriAuxiliary final {
        public:
            typedef ppp::coroutines::YieldContext       YieldContext;

        public:
            static ppp::string                          Encode(const ppp::string& input) noexcept;
            static ppp::string                          Decode(const ppp::string& input) noexcept;

        public:
            typedef enum {
                ProtocolType_Socks                      = -1,
                ProtocolType_PPP                        = 0,
                ProtocolType_Http,
                ProtocolType_HttpSSL,
                ProtocolType_WebSocket,
                ProtocolType_WebSocketSSL,
            }                                           ProtocolType;
            static ppp::string                          Parse(
                const ppp::string&                      url,
                ppp::string&                            hostname,
                ppp::string&                            address,
                ppp::string&                            path,
                int&                                    port,
                ProtocolType&                           protocol,
                YieldContext&                           y) noexcept;
            static ppp::string                          Parse(
                const ppp::string&                      url,
                ppp::string&                            hostname,
                ppp::string&                            address,
                ppp::string&                            path,
                int&                                    port,
                ProtocolType&                           protocol,
                ppp::string*                            abs,
                YieldContext&                           y) noexcept;
            static ppp::string                          Parse(
                const ppp::string&                      url,
                ppp::string&                            hostname,
                ppp::string&                            address,
                ppp::string&                            path,
                int&                                    port,
                ProtocolType&                           protocol,
                ppp::string*                            abs,
                YieldContext&                           y,
                bool                                    resolver) noexcept;
        };
    }
}