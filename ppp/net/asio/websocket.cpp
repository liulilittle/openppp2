#include <ppp/net/asio/websocket.h>
#include <ppp/net/asio/templates/SslSocket.h>
#include <ppp/net/asio/templates/WebSocket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/coroutines/asio/asio.h>

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
            websocket::websocket(const std::shared_ptr<boost::asio::io_context> context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, bool binary) noexcept
                : disposed_(false)
                , binary_(binary)
                , context_(context)
                , websocket_(std::move(*socket)) {

            }

            std::shared_ptr<websocket> websocket::GetReference() noexcept {
                return shared_from_this();
            }

            void websocket::Dispose() noexcept {
                auto self = shared_from_this();
                context_->post(
                    [self, this]() noexcept {
                        exchangeof(disposed_, true); {
                            const std::shared_ptr<websocket> reference = GetReference();
                            websocket_.async_close(boost::beast::websocket::close_code::normal,
                                [reference, this](const boost::system::error_code& ec_) noexcept {
                                    Socket::Closesocket(websocket_.next_layer());
                                });
                        }
                    });
            }

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

            bool websocket::Read(const void* buffer, int offset, int length, YieldContext& y) noexcept {
                if (NULL == buffer || offset < 0 || length < 1) {
                    return false;
                }

                if (IsDisposed()) {
                    return false;
                }

                return ppp::coroutines::asio::async_read_post(websocket_, boost::asio::buffer((char*)buffer + offset, length), y);
            }

            bool websocket::Write(const void* buffer, int offset, int length, const std::shared_ptr<AsynchronousWriteCallback>& cb) noexcept {
                if (NULL == buffer || offset < 0 || length < 1) {
                    return false;
                }

                if (IsDisposed()) {
                    return false;
                }

                const std::shared_ptr<AsynchronousWriteCallback> fcb = cb;
                if (NULL == fcb) {
                    return false;
                }

                const std::shared_ptr<websocket> self = shared_from_this();
                auto complete_do_write_async_callback = [self, this, fcb, buffer, offset, length]() noexcept {
                    websocket_.async_write(boost::asio::buffer(((Byte*)buffer) + (offset), length),
                        [self, this, fcb](const boost::system::error_code& ec, size_t sz) noexcept {
                            bool ok = ec == boost::system::errc::success;
                            if (fcb) {
                                (*fcb)(ok); /* b is boost::system::errc::success. */
                            }
                        });
                };

                boost::asio::dispatch(websocket_.get_executor(), complete_do_write_async_callback);
                return true;
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

                class AcceptWebSocket final : public ppp::net::asio::templates::WebSocket<AsioWebSocket> {
                public:
                    AcceptWebSocket(const std::shared_ptr<websocket>& reference, AsioWebSocket& websocket, bool binary, const ppp::string& host, const ppp::string& path) noexcept
                        : WebSocket(websocket, binary, host, path)
                        , reference_(reference) {

                    }

                public:
                    virtual void                                        Dispose() noexcept override {
                        std::shared_ptr<websocket> reference = std::move(reference_);
                        if (reference) {
                            reference_.reset();
                            reference->Dispose();
                        }
                    }
                    virtual void                                        SetAddressString(const ppp::string& address) noexcept override {
                        if (address.size() > 0) {
                            std::shared_ptr<websocket> reference = reference_;
                            if (reference) {
                                IPEndPoint remoteEP = reference->GetRemoteEndPoint();
                                reference->SetRemoteEndPoint(IPEndPoint(address.data(), remoteEP.Port));
                            }
                        }
                    }

                private:
                    std::shared_ptr<websocket>                          reference_;
                };

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
                        static const int _RealIpHeadersSize = 5;
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

            sslwebsocket::sslwebsocket(const std::shared_ptr<boost::asio::io_context>& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, bool binary) noexcept
                : disposed_(false)
                , binary_(binary)
                , context_(context)
                , socket_native_(socket) {

            }

            bool sslwebsocket::IsDisposed() noexcept {
                if (disposed_) {
                    return true;
                }

                const std::shared_ptr<SslvWebSocket> ssl_websocket = ssl_websocket_;
                if (NULL == ssl_websocket) {
                    return true;
                }

                if (!ssl_websocket->is_open()) {
                    return true;
                }

                auto& ssl_socket = ssl_websocket->next_layer().next_layer();
                if (!ssl_socket.is_open()) {
                    return true;
                }

                return false;
            }

            void sslwebsocket::Dispose() noexcept {
                auto self = shared_from_this();
                context_->post(
                    [self, this]() noexcept {
                        exchangeof(disposed_, true); {
                            const std::shared_ptr<SslvWebSocket> websocket = ssl_websocket_;
                            if (NULL != websocket) {
                                const std::shared_ptr<sslwebsocket> reference = shared_from_this();
                                websocket->async_close(boost::beast::websocket::close_code::normal,
                                    [reference, this, websocket](const boost::system::error_code& ec_) noexcept {
                                        SslvTcpSocket* ssl_socket = addressof(websocket->next_layer());
                                        ssl_socket->async_shutdown(
                                            [reference, this, ssl_socket](const boost::system::error_code& ec_) noexcept {
                                                Socket::Closesocket(ssl_socket->next_layer());
                                            });
                                    });
                            }
                        }
                    });
            }

            sslwebsocket::IPEndPoint sslwebsocket::GetLocalEndPoint() noexcept {
                return localEP_;
            }

            sslwebsocket::IPEndPoint sslwebsocket::GetRemoteEndPoint() noexcept {
                return remoteEP_;
            }

            void sslwebsocket::SetLocalEndPoint(const IPEndPoint& value) noexcept {
                localEP_ = value;
            }

            void sslwebsocket::SetRemoteEndPoint(const IPEndPoint& value) noexcept {
                remoteEP_ = value;
            }

            std::shared_ptr<sslwebsocket> sslwebsocket::GetReference() noexcept {
                return shared_from_this();
            }

            bool sslwebsocket::Read(const void* buffer, int offset, int length, YieldContext& y) noexcept {
                if (NULL == buffer || offset < 0 || length < 1) {
                    return false;
                }

                if (IsDisposed()) {
                    return false;
                }

                const std::shared_ptr<SslvWebSocket> ssl_websocket = ssl_websocket_;
                if (NULL == ssl_websocket) {
                    return false;
                }

                return ppp::coroutines::asio::async_read_post(*ssl_websocket, boost::asio::buffer((char*)buffer + offset, length), y);
            }

            bool sslwebsocket::Write(const void* buffer, int offset, int length, const std::shared_ptr<AsynchronousWriteCallback>& cb) noexcept {
                if (NULL == buffer || offset < 0 || length < 1) {
                    return false;
                }

                if (IsDisposed()) {
                    return false;
                }

                const std::shared_ptr<SslvWebSocket> ssl_websocket = ssl_websocket_;
                if (NULL == ssl_websocket) {
                    return false;
                }

                const std::shared_ptr<AsynchronousWriteCallback> fcb = cb;
                if (NULL == fcb) {
                    return false;
                }

                const std::shared_ptr<sslwebsocket> self = shared_from_this();
                auto complete_do_async_write_callback = [self, this, fcb, buffer, offset, length, ssl_websocket]() noexcept {
                    ssl_websocket->async_write(boost::asio::buffer((char*)buffer + offset, length),
                        [self, this, fcb](const boost::system::error_code& ec, size_t sz) noexcept {
                            bool ok = ec == boost::system::errc::success;
                            if (fcb) {
                                (*fcb)(ok); /* b is boost::system::errc::success. */
                            }
                        });
                };

                boost::asio::dispatch(ssl_websocket->get_executor(), complete_do_async_write_callback);
                return true;
            }

            bool sslwebsocket::Run(
                HandshakeType                                                       type,
                const ppp::string&                                                  host,
                const ppp::string&                                                  path,
                bool                                                                verify_peer,
                std::string                                                         certificate_file,
                std::string                                                         certificate_key_file,
                std::string                                                         certificate_chain_file,
                std::string                                                         certificate_key_password,
                std::string                                                         ciphersuites,
                YieldContext&                                                       y) noexcept {
                typedef std::shared_ptr<SslvWebSocket> SslvWebSocketPtr;

                if (host.empty() || path.empty() || certificate_file.empty() || certificate_key_file.empty() || certificate_chain_file.empty()) {
                    return false;
                }

                class AcceptSslvWebSocket final : public ppp::net::asio::templates::WebSocket<SslvWebSocket> {
                public:
                    AcceptSslvWebSocket(const std::shared_ptr<sslwebsocket>& reference, SslvWebSocket& websocket, bool binary, ppp::string& host, ppp::string& path) noexcept
                        : WebSocket(websocket, binary, host, path)
                        , reference_(reference) {

                    }

                public:
                    virtual void                                                    Dispose() noexcept override {
                        std::shared_ptr<sslwebsocket> reference = std::move(reference_);
                        if (reference) {
                            reference_.reset();
                            reference->Dispose();
                        }
                    }
                    virtual void                                                    SetAddressString(const ppp::string& address) noexcept override {
                        if (address.size() > 0) {
                            std::shared_ptr<sslwebsocket> reference = reference_;
                            if (reference) {
                                IPEndPoint remoteEP = reference->GetRemoteEndPoint();
                                reference->SetRemoteEndPoint(IPEndPoint(address.data(), remoteEP.Port));
                            }
                        }
                    }

                private:
                    std::shared_ptr<sslwebsocket>                                   reference_;
                };

                class AsyncSslvWebSocket final : public ppp::net::asio::templates::SslSocket<SslvWebSocketPtr> {
                public:
                    AsyncSslvWebSocket(const std::shared_ptr<sslwebsocket>&  reference,
                        std::shared_ptr<boost::asio::ip::tcp::socket>&              tcp_socket,
                        std::shared_ptr<boost::asio::ssl::context>&                 ssl_context,
                        SslvWebSocketPtr&                                           ssl_websocket,
                        bool                                                        verify_peer,
                        bool                                                        binary,
                        const ppp::string&                                          host,
                        const ppp::string&                                          path,
                        const std::string&                                          certificate_file,
                        const std::string&                                          certificate_key_file,
                        const std::string&                                          certificate_chain_file,
                        const std::string&                                          certificate_key_password,
                        const std::string&                                          ciphersuites) noexcept
                        : SslSocket(tcp_socket, ssl_context, ssl_websocket, verify_peer, host, certificate_file, certificate_key_file, certificate_chain_file, certificate_key_password, ciphersuites)
                        , path_(path)
                        , reference_(reference)
                        , binary_(binary) {

                    }

                public:
                    bool                                                            PerformWebSocketHandshake(bool handshaked_client, YieldContext& y) noexcept {
                        SslvWebSocketPtr& ssl_websocket = GetSslSocket();
                        if (NULL == ssl_websocket) {
                            return false;
                        }

                        std::shared_ptr<AcceptSslvWebSocket> accept = make_shared_object<AcceptSslvWebSocket>(reference_, *ssl_websocket, binary_, host_, path_);
                        if (NULL == accept) {
                            return false;
                        }

                        return accept->Run(handshaked_client, y);
                    }
                    virtual void                                                    Dispose() noexcept override {
                        std::shared_ptr<sslwebsocket> reference = std::move(reference_);
                        if (reference) {
                            reference_.reset();
                            reference->Dispose();
                        }
                    }
                    virtual SSL*                                                    GetSslHandle() noexcept override {
                        SslvWebSocketPtr& ssl_websocket = GetSslSocket();
                        if (NULL == ssl_websocket) {
                            return NULL;
                        }

                        SslvTcpSocket& ssl_socket = ssl_websocket->next_layer();
                        return ssl_socket.native_handle();
                    }
                    virtual bool                                                    PerformSslHandshake(bool handshaked_client, YieldContext& y) noexcept override {
                        // Perform the SSL handshake.
                        const std::shared_ptr<Reference> reference = GetReference();
                        const SslvWebSocketPtr& ssl_websocket = GetSslSocket();
                        if (NULL == ssl_websocket) {
                            return false;
                        }

                        bool ok = false;
                        ssl_websocket->next_layer().async_handshake(handshaked_client ? boost::asio::ssl::stream_base::client : boost::asio::ssl::stream_base::server,
                            [reference, this, handshaked_client, &ok, &y](const boost::system::error_code& ec) noexcept {
                                auto& context = y.GetContext();
                                ok = ec == boost::system::errc::success;
                                context.dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, y.GetPtr()));
                            });

                        y.Suspend();
                        if (!ok) {
                            return false;
                        }

                        return PerformWebSocketHandshake(handshaked_client, y);
                    }

                private:
                    ppp::string                                                     path_;
                    std::shared_ptr<sslwebsocket>                                   reference_;
                    bool                                                            binary_;
                };

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_native_;
                if (NULL == socket) {
                    return false;
                }

                if (ciphersuites.empty()) {
                    ciphersuites = GetDefaultCipherSuites();
                }

                std::shared_ptr<AsyncSslvWebSocket> accept = make_shared_object<AsyncSslvWebSocket>(
                    shared_from_this(),
                    socket,
                    ssl_context_,
                    ssl_websocket_,
                    verify_peer,
                    binary_,
                    host,
                    path,
                    certificate_file,
                    certificate_key_file,
                    certificate_chain_file,
                    certificate_key_password,
                    ciphersuites);
                if (NULL == accept) {
                    return false;
                }
                
                return accept->Run(type == HandshakeType::HandshakeType_Client, y);
            }
        }
    }
}