#include <ppp/net/asio/websocket.h>
#include <ppp/net/asio/templates/SslSocket.h>
#include <ppp/net/asio/templates/WebSocket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/net/asio/websocket/websocket_accept_websocket.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file websocket.cpp
 * @brief Websocket utility implementations, including request path and forwarded-IP parsing.
 */

//0                   1                   2                   3
//0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//+-+-+-+-+-------+-+-------------+-------------------------------+
//|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//|N|V|V|V|       |S|             |   (if payload len==126/127)   |
//| |1|2|3|       |K|             |                               |
//+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//|     Extended payload length continued, if payload len == 127  |
//+ - - - - - - - - - - - - - - - +-------------------------------+
//|                               |Masking-key, if MASK set to 1  |
//+-------------------------------+-------------------------------+
//| Masking-key (continued)       |          Payload Data         |
//+-------------------------------- - - - - - - - - - - - - - - - +
//:                     Payload Data continued ...                :
//+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//|                     Payload Data continued ...                |
//+---------------------------------------------------------------+

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Checks whether the plain websocket session is no longer usable.
             * @return True when disposed flag is set or underlying sockets are closed.
             */
            bool websocket::IsDisposed() noexcept {
                if (disposed_) {
                    return true;
                }

                if (!websocket_.is_open()) {
                    return true;
                }

                auto& next_layer = websocket_.next_layer();
                if (!next_layer.is_open()) {
                    return true;
                }

                return false;
            }

            /** @brief Returns cached local endpoint for the websocket session. */
            websocket::IPEndPoint websocket::GetLocalEndPoint() noexcept {
                return localEP_;
            }

            /** @brief Returns cached remote endpoint for the websocket session. */
            websocket::IPEndPoint websocket::GetRemoteEndPoint() noexcept {
                return remoteEP_;
            }

            /** @brief Updates cached local endpoint for the websocket session. */
            void websocket::SetLocalEndPoint(const IPEndPoint& value) noexcept {
                localEP_ = value;
            }

            /** @brief Updates cached remote endpoint for the websocket session. */
            void websocket::SetRemoteEndPoint(const IPEndPoint& value) noexcept {
                remoteEP_ = value;
            }

            /**
             * @brief Performs websocket handshake through the generic accept/connect adapter.
             * @param type Client or server handshake mode.
             * @param host Host used by websocket handshake.
             * @param path Target websocket path.
             * @param y Coroutine yield context.
             * @return True when handshake completes successfully.
             */
            bool websocket::Run(HandshakeType type, const ppp::string& host, const ppp::string& path, YieldContext& y) noexcept {
                if (host.empty() || path.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketHandshakeFailed);
                    return false;
                }

                auto self = shared_from_this();
                bool binary = binary_;

                std::shared_ptr<AcceptWebSocket> accept = make_shared_object<AcceptWebSocket>(self, websocket_, binary, host, path);
                if (NULLPTR == accept) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
                    return false;
                }

                if (!accept->Run(type == HandshakeType::HandshakeType_Client, y)) {
                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketHandshakeFailed);
                    }
                    return false;
                }

                return true;
            }

            namespace templates {
                namespace websocket {
                    /**
                     * @brief Validates request path against configured websocket root path.
                     * @param root Configured root path.
                     * @param sw HTTP request target.
                     * @return True when request target should be accepted.
                     */
                    bool                                                CheckRequestPath(ppp::string& root, const boost::beast::string_view& sw) noexcept {
                        if (root.size() <= 1) {
                            return true;
                        }

                        ppp::string path_ = "/";
                        if (sw.size()) {
                            path_ = ToLower(LTrim(RTrim(ppp::string(sw.data(), sw.size()))));
                            if (path_.empty()) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpRequestFailed);
                                return false;
                            }
                        }

                        std::size_t sz_ = path_.find_first_of('?');
                        if (sz_ == ppp::string::npos) {
                            sz_ = path_.find_first_of('#');
                        }

                        if (sz_ != ppp::string::npos) {
                            path_ = path_.substr(0, sz_);
                        }

                        if (path_.size() < root.size()) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpRequestFailed);
                            return false;
                        }

                        ppp::string lroot_ = ToLower(root);
                        if (path_ == lroot_) {
                            return true;
                        }

                        if (path_.size() == lroot_.size()) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpRequestFailed);
                            return false;
                        }

                        int ch = path_[lroot_.size()];
                        if (ch != '/') {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpRequestFailed);
                            return false;
                        }

                        return true;
                    }

                    /**
                     * @brief Extracts an untrusted claimed client address for diagnostic logging only.
                     * @param req HTTP upgrade request message.
                     * @return Canonical IP address string when found; otherwise empty string.
                     */
                    ppp::string                                         GetAddressString(http_request& req) noexcept {
                        static constexpr int _RealIpHeadersSize = 5;
                        static const char* _RealIpHeaders[_RealIpHeadersSize] = {
                            "CF-Connecting-IP",
                            "True-Client-IP",
                            "X-Real-IP",
                            "REMOTE-HOST",
                            "X-Forwarded-For",
                        };
                        /**
                         * @brief Header probe sequence; none of these claims authenticates the client.
                         *
                         * Common Nginx equivalents:
                         * - Host
                         * - X-Real-IP
                         * - REMOTE-HOST
                         * - X-Forwarded-For
                         */
                        for (int i = 0; i < _RealIpHeadersSize; i++) {
                            http_request::iterator tail = req.find(_RealIpHeaders[i]);
                            http_request::iterator endl = req.end();
                            if (tail == endl) {
                                continue;
                            }

                            const boost::beast::string_view& sw = tail->value();
                            if (sw.empty()) {
                                continue;
                            }

                            const ppp::string address = ppp::string(sw.data(), sw.size());
                            IPEndPoint localEP(address.c_str(), IPEndPoint::MinPort);
                            if (IPEndPoint::IsInvalid(localEP)) {
                                continue;
                            }

                            return localEP.ToAddressString();
                        }
                        return ppp::string();
                    }
                }
            }
        }
    }
}
