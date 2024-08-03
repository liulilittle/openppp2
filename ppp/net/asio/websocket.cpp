#include <ppp/net/asio/websocket.h>
#include <ppp/net/asio/templates/SslSocket.h>
#include <ppp/net/asio/templates/WebSocket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/net/asio/websocket/websocket_accept_websocket.h>

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

            websocket::IPEndPoint websocket::GetLocalEndPoint() noexcept {
                return localEP_;
            }

            websocket::IPEndPoint websocket::GetRemoteEndPoint() noexcept {
                return remoteEP_;
            }

            void websocket::SetLocalEndPoint(const IPEndPoint& value) noexcept {
                localEP_ = value;
            }

            void websocket::SetRemoteEndPoint(const IPEndPoint& value) noexcept {
                remoteEP_ = value;
            }

            bool websocket::Run(HandshakeType type, const ppp::string& host, const ppp::string& path, YieldContext& y) noexcept {
                if (host.empty() || path.empty()) {
                    return false;
                }

                auto self = shared_from_this();
                std::shared_ptr<AcceptWebSocket> accept = make_shared_object<AcceptWebSocket>(self, websocket_, binary_, host, path);
                if (NULL == accept) {
                    return false;
                }

                return accept->Run(type == HandshakeType::HandshakeType_Client, y);
            }

            namespace templates {
                namespace websocket {
                    bool                                                CheckRequestPath(ppp::string& root, const boost::beast::string_view& sw) noexcept {
                        if (root.size() <= 1) {
                            return true;
                        }

                        ppp::string path_ = "/";
                        if (sw.size()) {
                            path_ = ToLower(LTrim(RTrim(ppp::string(sw.data(), sw.size()))));
                            if (path_.empty()) {
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
                            return false;
                        }

                        ppp::string lroot_ = ToLower(root);
                        if (path_ == lroot_) {
                            return true;
                        }

                        if (path_.size() == lroot_.size()) {
                            return false;
                        }

                        int ch = path_[lroot_.size()];
                        return ch == '/';
                    }

                    ppp::string                                         GetAddressString(http_request& req) noexcept {
                        static constexpr int _RealIpHeadersSize = 5;
                        static const char* _RealIpHeaders[_RealIpHeadersSize] = {
                            "CF-Connecting-IP",
                            "True-Client-IP",
                            "X-Real-IP",
                            "REMOTE-HOST",
                            "X-Forwarded-For",
                        };
                        // proxy_set_header Host $host;
                        // proxy_set_header X-Real-IP $remote_addr;
                        // proxy_set_header REMOTE-HOST $remote_addr;
                        // proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
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