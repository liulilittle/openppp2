#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace net {
        namespace asio {
            class websocket : public std::enable_shared_from_this<websocket> {
                friend class                                                    AcceptWebSocket;

            public:
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
                ppp::string                                                     XForwardedFor;

            public:
                websocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, bool binary) noexcept;
                virtual ~websocket() noexcept = default;

            public:
                std::shared_ptr<websocket>                                      GetReference() noexcept { return shared_from_this(); }
                ppp::threading::Executors::ContextPtr                           GetContext()   noexcept { return context_; }
                ppp::threading::Executors::StrandPtr                            GetStrand()    noexcept { return strand_; }
                virtual void                                                    Dispose()      noexcept;
                virtual bool                                                    IsDisposed()   noexcept;

            public:
                virtual IPEndPoint                                              GetLocalEndPoint() noexcept;
                virtual IPEndPoint                                              GetRemoteEndPoint() noexcept;
                virtual bool                                                    ShiftToScheduler() noexcept;

            protected:
                virtual bool                                                    Decorator(boost::beast::websocket::request_type& req) noexcept { return false; }
                virtual bool                                                    Decorator(boost::beast::websocket::response_type& res) noexcept { return false; }
                void                                                            SetLocalEndPoint(const IPEndPoint& value) noexcept;
                void                                                            SetRemoteEndPoint(const IPEndPoint& value) noexcept;

            public:
                virtual bool                                                    Run(
                    HandshakeType                                               type, 
                    const ppp::string&                                          host, 
                    const ppp::string&                                          path, 
                    YieldContext&                                               y) noexcept;
                virtual bool                                                    Write(const void* buffer, int offset, int length, const AsynchronousWriteCallback& cb) noexcept;
                virtual bool                                                    Read(const void* buffer, int offset, int length, YieldContext& y) noexcept;

            private:
                struct {
                    bool                                                        disposed_ : 1;
                    bool                                                        binary_   : 7;
                };
                ppp::threading::Executors::ContextPtr                           context_;
                ppp::threading::Executors::StrandPtr                            strand_;
                AsioWebSocket                                                   websocket_;
                IPEndPoint                                                      localEP_;
                IPEndPoint                                                      remoteEP_;
            };

            class sslwebsocket : public std::enable_shared_from_this<sslwebsocket> {
                friend class                                                    AcceptWebSocket;
                friend class                                                    AcceptSslvWebSocket;
                
            public:
                typedef boost::asio::ip::tcp::socket                            AsioTcpSocket;
                typedef boost::asio::ssl::stream<AsioTcpSocket>                 SslvTcpSocket;
                typedef boost::beast::websocket::stream<SslvTcpSocket>          SslvWebSocket;

            public:
                typedef websocket::HandshakeType                                HandshakeType;
                typedef websocket::YieldContext                                 YieldContext;
                typedef websocket::IPEndPoint                                   IPEndPoint;
                typedef ppp::function<void(bool)>                               AsynchronousWriteCallback;

            public:
                ppp::string                                                     XForwardedFor;

            public:
                sslwebsocket(
                    const std::shared_ptr<boost::asio::io_context>&             context,
                    const ppp::threading::Executors::StrandPtr&                 strand,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&        socket,
                    bool                                                        binary) noexcept;
                virtual ~sslwebsocket() noexcept = default;

            public:
                std::shared_ptr<sslwebsocket>                                   GetReference() noexcept { return shared_from_this(); }
                ppp::threading::Executors::ContextPtr                           GetContext() noexcept { return context_; }
                ppp::threading::Executors::StrandPtr                            GetStrand() noexcept { return strand_; }
                virtual void                                                    Dispose() noexcept;
                virtual bool                                                    IsDisposed() noexcept;

            public:
                virtual IPEndPoint                                              GetLocalEndPoint() noexcept;
                virtual IPEndPoint                                              GetRemoteEndPoint() noexcept;
                virtual bool                                                    ShiftToScheduler() noexcept;

            public:
                void                                                            SetLocalEndPoint(const IPEndPoint& value) noexcept;
                void                                                            SetRemoteEndPoint(const IPEndPoint& value) noexcept;

            protected:
                virtual bool                                                    Decorator(boost::beast::websocket::request_type& req) noexcept { return false; }
                virtual bool                                                    Decorator(boost::beast::websocket::response_type& res) noexcept { return false; }

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
                virtual bool                                                    Write(const void* buffer, int offset, int length, const AsynchronousWriteCallback& cb) noexcept;
                virtual bool                                                    Read(const void* buffer, int offset, int length, YieldContext& y) noexcept;

            private:
                struct {
                    bool                                                        disposed_ : 1;
                    bool                                                        binary_   : 7;
                };
                ppp::threading::Executors::ContextPtr                           context_;
                ppp::threading::Executors::StrandPtr                            strand_;
                std::shared_ptr<boost::asio::ssl::context>                      ssl_context_;
                std::shared_ptr<SslvWebSocket>                                  ssl_websocket_;
                IPEndPoint                                                      localEP_;
                IPEndPoint                                                      remoteEP_;
                std::shared_ptr<boost::asio::ip::tcp::socket>                   socket_native_;
            };
        }
    }
}