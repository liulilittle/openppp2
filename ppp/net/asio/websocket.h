#pragma once

#include <deque>
#include <mutex>

/**
 * @file websocket.h
 * @brief Plain and TLS websocket session wrappers built on Boost.Beast.
 */

#include <ppp/stdafx.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Websocket session wrapper over a plain TCP socket.
             *
             * Provides coroutine-friendly handshake, read/write, endpoint tracking,
             * and lifecycle helpers for higher-level protocol handlers.
             */
            class websocket : public std::enable_shared_from_this<websocket> {
                friend class                                                    AcceptWebSocket;

            public:
                /** @brief Underlying TCP socket type. */
                typedef boost::asio::ip::tcp::socket                            AsioTcpSocket;
                /** @brief Beast websocket stream over plain TCP. */
                typedef boost::beast::websocket::stream<AsioTcpSocket>          AsioWebSocket;

            public:
                typedef enum {
                    /** @brief Perform server-side websocket accept flow. */
                    HandshakeType_Server,
                    /** @brief Perform client-side websocket connect flow. */
                    HandshakeType_Client,
                }                                                               HandshakeType;
                typedef ppp::coroutines::YieldContext                           YieldContext;
                typedef ppp::net::IPEndPoint                                    IPEndPoint;
                typedef ppp::function<void(bool)>                               AsynchronousWriteCallback;

            public:
                /** @brief Optional proxied client IP text from forwarding headers. */
                ppp::string                                                     XForwardedFor;

            public:
                /**
                 * @brief Constructs a plain websocket session from an accepted or connected socket.
                 * @param context Owning IO context.
                 * @param strand Execution strand for serialized callbacks.
                 * @param socket Connected TCP socket.
                 * @param binary True to send/receive binary websocket frames.
                 */
                websocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, bool binary) noexcept;
                virtual ~websocket() noexcept = default;

            public:
                std::shared_ptr<websocket>                                      GetReference() noexcept { return shared_from_this(); }
                ppp::threading::Executors::ContextPtr                           GetContext()   noexcept { return context_; }
                ppp::threading::Executors::StrandPtr                            GetStrand()    noexcept { return strand_; }
                /** @brief Releases transport resources and marks session disposed. */
                virtual void                                                    Dispose()      noexcept;
                /** @brief Checks whether websocket session is already closed/disposed. */
                virtual bool                                                    IsDisposed()   noexcept;

            public:
                /** @brief Returns cached local endpoint. */
                virtual IPEndPoint                                              GetLocalEndPoint() noexcept;
                /** @brief Returns cached remote endpoint. */
                virtual IPEndPoint                                              GetRemoteEndPoint() noexcept;
                /** @brief Switches execution to scheduler/strand thread when required. */
                virtual bool                                                    ShiftToScheduler() noexcept;

            protected:
                /** @brief Allows derived class to customize client handshake request. */
                virtual bool                                                    Decorator(boost::beast::websocket::request_type& req) noexcept { return false; }
                /** @brief Allows derived class to customize server handshake response. */
                virtual bool                                                    Decorator(boost::beast::websocket::response_type& res) noexcept { return false; }
                /** @brief Updates cached local endpoint value. */
                void                                                            SetLocalEndPoint(const IPEndPoint& value) noexcept;
                /** @brief Updates cached remote endpoint value. */
                void                                                            SetRemoteEndPoint(const IPEndPoint& value) noexcept;

            public:
                /**
                 * @brief Performs websocket handshake as server or client.
                 * @param type Handshake direction.
                 * @param host Host header / SNI host.
                 * @param path Target websocket path.
                 * @param y Coroutine yield context.
                 * @return True when handshake succeeds.
                 */
                virtual bool                                                    Run(
                    HandshakeType                                               type, 
                    const ppp::string&                                          host, 
                    const ppp::string&                                          path, 
                    YieldContext&                                               y) noexcept;
                /**
                 * @brief Writes websocket payload asynchronously.
                 * @param buffer Source buffer.
                 * @param offset Start offset in source buffer.
                 * @param length Number of bytes to write.
                 * @param cb Completion callback.
                 * @return True when write task is queued.
                 */
                virtual bool                                                    Write(const void* buffer, int offset, int length, const AsynchronousWriteCallback& cb) noexcept;
                /**
                 * @brief Reads websocket payload into caller buffer.
                 * @param buffer Destination buffer.
                 * @param offset Start offset in destination buffer.
                 * @param length Number of bytes expected.
                 * @param y Coroutine yield context.
                 * @return True when read succeeds.
                 */
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

                /**
                 * @brief One queued asynchronous write; the payload is owned by the queue
                 *        until its completion fires.
                 */
                struct AsynchronousWriteContext {
                    std::shared_ptr<Byte>                                       buffer;
                    int                                                         length = 0;
                    AsynchronousWriteCallback                                   cb;
                };
                /** @brief Serializes write queue state across IO worker threads. */
                std::mutex                                                      write_mutex_;
                /** @brief True while a Beast async_write is outstanding (at most one at a time). */
                bool                                                            write_in_progress_ = false;
                /** @brief FIFO of pending writes drained one-by-one after each completion. */
                std::deque<AsynchronousWriteContext>                            write_queue_;
                /** @brief Starts the next queued write; never overlaps a write already in flight. */
                void                                                            DoWriteAsync() noexcept;
            };

            /**
             * @brief Websocket session wrapper over TLS stream.
             *
             * Extends plain websocket behavior with TLS context and certificate
             * configuration before websocket handshake.
             */
            class sslwebsocket : public std::enable_shared_from_this<sslwebsocket> {
                friend class                                                    AcceptWebSocket;
                friend class                                                    AcceptSslvWebSocket;
                
            public:
                /** @brief Underlying TCP socket type. */
                typedef boost::asio::ip::tcp::socket                            AsioTcpSocket;
                /** @brief TLS stream over TCP socket. */
                typedef boost::asio::ssl::stream<AsioTcpSocket>                 SslvTcpSocket;
                /** @brief Beast websocket stream over TLS transport. */
                typedef boost::beast::websocket::stream<SslvTcpSocket>          SslvWebSocket;

            public:
                typedef websocket::HandshakeType                                HandshakeType;
                typedef websocket::YieldContext                                 YieldContext;
                typedef websocket::IPEndPoint                                   IPEndPoint;
                typedef ppp::function<void(bool)>                               AsynchronousWriteCallback;

            public:
                /** @brief Optional proxied client IP text from forwarding headers. */
                ppp::string                                                     XForwardedFor;

            public:
                /**
                 * @brief Constructs a TLS websocket session wrapper.
                 * @param context Owning IO context.
                 * @param strand Execution strand for serialized callbacks.
                 * @param socket Connected TCP socket.
                 * @param binary True to send/receive binary websocket frames.
                 */
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
                /** @brief Releases TLS and websocket resources and marks disposed. */
                virtual void                                                    Dispose() noexcept;
                /** @brief Checks whether TLS websocket session is closed/disposed. */
                virtual bool                                                    IsDisposed() noexcept;
                /** @brief Reports whether the completed TLS session can export key material. */
                bool                                                            HasSessionExporter() noexcept;
                /** @brief Exports key material bound to the completed TLS session. */
                bool                                                            ExportSessionKey(
                    const char* label,
                    const std::uint8_t* context,
                    std::size_t context_length,
                    std::uint8_t* output,
                    std::size_t output_length) noexcept;

            public:
                /** @brief Returns cached local endpoint. */
                virtual IPEndPoint                                              GetLocalEndPoint() noexcept;
                /** @brief Returns cached remote endpoint. */
                virtual IPEndPoint                                              GetRemoteEndPoint() noexcept;
                /** @brief Switches execution to scheduler/strand thread when required. */
                virtual bool                                                    ShiftToScheduler() noexcept;

            public:
                /** @brief Updates cached local endpoint value. */
                void                                                            SetLocalEndPoint(const IPEndPoint& value) noexcept;
                /** @brief Updates cached remote endpoint value. */
                void                                                            SetRemoteEndPoint(const IPEndPoint& value) noexcept;

            protected:
                /** @brief Allows derived class to customize client handshake request. */
                virtual bool                                                    Decorator(boost::beast::websocket::request_type& req) noexcept { return false; }
                /** @brief Allows derived class to customize server handshake response. */
                virtual bool                                                    Decorator(boost::beast::websocket::response_type& res) noexcept { return false; }

            public:
                /**
                 * @brief Performs TLS setup and websocket handshake as server or client.
                 * @param type Handshake direction.
                 * @param host Host header / SNI host.
                 * @param path Target websocket path.
                 * @param verify_peer Enables certificate verification when true.
                 * @param certificate_file Leaf certificate file path.
                 * @param certificate_key_file Private key file path.
                 * @param certificate_chain_file Certificate chain file path.
                 * @param certificate_key_password Password for private key.
                 * @param ciphersuites TLS cipher suite policy string.
                 * @param y Coroutine yield context.
                 * @return True when handshake succeeds.
                 */
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
                /**
                 * @brief Writes websocket payload asynchronously.
                 * @param buffer Source buffer.
                 * @param offset Start offset in source buffer.
                 * @param length Number of bytes to write.
                 * @param cb Completion callback.
                 * @return True when write task is queued.
                 */
                virtual bool                                                    Write(const void* buffer, int offset, int length, const AsynchronousWriteCallback& cb) noexcept;
                /**
                 * @brief Reads websocket payload into caller buffer.
                 * @param buffer Destination buffer.
                 * @param offset Start offset in destination buffer.
                 * @param length Number of bytes expected.
                 * @param y Coroutine yield context.
                 * @return True when read succeeds.
                 */
                virtual bool                                                    Read(const void* buffer, int offset, int length, YieldContext& y) noexcept;

            private:
                struct {
                    bool                                                        disposed_ : 1;
                    bool                                                        binary_   : 7;
                };
                ppp::threading::Executors::ContextPtr                           context_;
                ppp::threading::Executors::StrandPtr                            strand_;
                std::shared_ptr<boost::asio::ssl::context>                      ssl_context_;
                std::mutex                                                      exporter_mutex_;
                std::atomic_bool                                                tls_handshake_complete_{false};
                std::shared_ptr<SslvWebSocket>                                  ssl_websocket_;

                /**
                 * @brief One queued asynchronous write; the payload is owned by the queue
                 *        until its completion fires.
                 */
                struct AsynchronousWriteContext {
                    std::shared_ptr<Byte>                                       buffer;
                    int                                                         length = 0;
                    AsynchronousWriteCallback                                   cb;
                };
                /** @brief Serializes write queue state across IO worker threads. */
                std::mutex                                                      write_mutex_;
                /** @brief True while a Beast async_write is outstanding (at most one at a time). */
                bool                                                            write_in_progress_ = false;
                /** @brief FIFO of pending writes drained one-by-one after each completion. */
                std::deque<AsynchronousWriteContext>                            write_queue_;
                /** @brief Starts the next queued write; never overlaps a write already in flight. */
                void                                                            DoWriteAsync() noexcept;
                IPEndPoint                                                      localEP_;
                IPEndPoint                                                      remoteEP_;
                std::shared_ptr<boost::asio::ip::tcp::socket>                   socket_native_;
            };
        }
    }
}
