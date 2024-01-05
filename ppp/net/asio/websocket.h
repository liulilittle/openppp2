#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace net {
        namespace asio {
            class websocket : public std::enable_shared_from_this<websocket> {
            private:
                friend class                                                    AcceptWebSocket;

            private:
                typedef boost::asio::ip::tcp::socket                            AsioTcpSocket;
                typedef boost::beast::websocket::stream<AsioTcpSocket>          AsioWebSocket;

            public:
                typedef enum {
                    HandshakeType_Server,
                    HandshakeType_Client,
                }                                                               HandshakeType;
                typedef ppp::coroutines::YieldContext                           YieldContext;
                typedef ppp::net::IPEndPoint                                    IPEndPoint;
                typedef ppp::function<void(bool)>                               AsynchronousWriteCallback;

            public:
                websocket(const std::shared_ptr<boost::asio::io_context> context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, bool binary) noexcept;
                virtual ~websocket() noexcept = default;

            public:
                std::shared_ptr<websocket>                                      GetReference() noexcept;
                virtual void                                                    Dispose() noexcept;
                virtual bool                                                    IsDisposed() noexcept;

            public:
                virtual IPEndPoint                                              GetLocalEndPoint() noexcept;
                virtual IPEndPoint                                              GetRemoteEndPoint() noexcept;

            protected:
                void                                                            SetLocalEndPoint(const IPEndPoint& value) noexcept;
                void                                                            SetRemoteEndPoint(const IPEndPoint& value) noexcept;

            public:
                virtual bool                                                    Run(HandshakeType type, const ppp::string& host, const ppp::string& path, YieldContext& y) noexcept;
                virtual bool                                                    Write(const void* buffer, int offset, int length, const std::shared_ptr<AsynchronousWriteCallback>& cb) noexcept;
                virtual bool                                                    Read(const void* buffer, int offset, int length, YieldContext& y) noexcept;
                virtual bool                                                    ReadSome(const void* buffer, int offset, int length, YieldContext& y) noexcept;

            private:
                bool                                                            disposed_;
                bool                                                            binary_;
                AsioWebSocket                                                   websocket_;
                IPEndPoint                                                      localEP_;
                IPEndPoint                                                      remoteEP_;
                std::shared_ptr<boost::asio::io_context>                        context_;
            };

            class sslwebsocket : public std::enable_shared_from_this<sslwebsocket> {
            private:
                friend class                                                    AcceptWebSocket;

            private:
                typedef boost::asio::ip::tcp::socket                            AsioTcpSocket;
                typedef boost::asio::ssl::stream<AsioTcpSocket>                 SslvTcpSocket;
                typedef boost::beast::websocket::stream<SslvTcpSocket>          SslvWebSocket;

            public:
                typedef websocket::HandshakeType                                HandshakeType;
                typedef websocket::YieldContext                                 YieldContext;
                typedef websocket::IPEndPoint                                   IPEndPoint;
                typedef ppp::function<void(bool)>                               AsynchronousWriteCallback;

            public:
                sslwebsocket(
                    const std::shared_ptr<boost::asio::io_context>&             context,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&        socket,
                    bool                                                        binary) noexcept;
                virtual ~sslwebsocket() noexcept = default;

            public:
                std::shared_ptr<sslwebsocket>                                   GetReference() noexcept;
                virtual void                                                    Dispose() noexcept;
                virtual bool                                                    IsDisposed() noexcept;

            public:
                virtual IPEndPoint                                              GetLocalEndPoint() noexcept;
                virtual IPEndPoint                                              GetRemoteEndPoint() noexcept;

            protected:
                void                                                            SetLocalEndPoint(const IPEndPoint& value) noexcept;
                void                                                            SetRemoteEndPoint(const IPEndPoint& value) noexcept;

            public:
                virtual bool                                                    Run(
                    HandshakeType                                               type,
                    const ppp::string&                                          host,
                    const ppp::string&                                          path,
                    bool                                                        verify_peer,
                    std::string                                                 certificate_file,
                    std::string                                                 certificate_key_file,
                    std::string                                                 certificate_chain_file,
                    std::string                                                 certificate_key_password,
                    std::string                                                 ciphersuites,
                    YieldContext&                                               y) noexcept;
                virtual bool                                                    Write(const void* buffer, int offset, int length, const std::shared_ptr<AsynchronousWriteCallback>& cb) noexcept;
                virtual bool                                                    Read(const void* buffer, int offset, int length, YieldContext& y) noexcept;

            private:
                bool                                                            disposed_;
                bool                                                            binary_;
                std::shared_ptr<boost::asio::ssl::context>                      ssl_context_;
                std::shared_ptr<SslvWebSocket>                                  ssl_websocket_;
                IPEndPoint                                                      localEP_;
                IPEndPoint                                                      remoteEP_;
                std::shared_ptr<boost::asio::io_context>                        context_;
                std::shared_ptr<boost::asio::ip::tcp::socket>                   socket_native_;
            };
        }
    }
}