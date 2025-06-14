#pragma once

#include <ppp/net/asio/websocket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>

#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITransmission.h>

#if defined(_WIN32)
#include <windows/ppp/net/QoSS.h>
#endif

namespace ppp {
    namespace transmissions {
        namespace templates {
            template <typename IWebsocket>
            class WebSocket : public ITransmission { /* Generic */
                friend class                                                ITransmissionQoS;

            public:
                typedef typename IWebsocket::HandshakeType                  HandshakeType;

            public:
                WebSocket(
                    const ContextPtr&                                       context,
                    const StrandPtr&                                        strand,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    const AppConfigurationPtr&                              configuration) noexcept
                    : ITransmission(context, strand, configuration)
                    , disposed_(false) {

                    boost::system::error_code ec;
                    remoteEP_ = ppp::net::Ipep::V6ToV4(socket->remote_endpoint(ec));

#if defined(_WIN32)
                    if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                        qoss_ = ppp::net::QoSS::New(socket->native_handle());
                    }
#endif

                    bool binary = true;
                    if (configuration->key.plaintext) {
                        binary = false;
                    }

                    class IWebsocketObject final : public IWebsocket {
                    public:
                        IWebsocketObject(WebSocket& owner, const ContextPtr& context, const StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, bool binary) noexcept
                            : IWebsocket(context, strand, socket, binary)
                            , owner_(owner) {

                        }

                    protected:
                        virtual bool                                        Decorator(boost::beast::websocket::request_type& req) noexcept override { return owner_.Decorator(req); }
                        virtual bool                                        Decorator(boost::beast::websocket::response_type& res) noexcept override { return owner_.Decorator(res); }

                    private:
                        WebSocket&                                          owner_;
                    };
                    socket_ = make_shared_object<IWebsocketObject>(*this, context, strand, socket, binary);
                }
                virtual ~WebSocket()                                                       noexcept { Finalize(); }

            public:
                std::shared_ptr<IWebsocket>                                 GetSocket() noexcept { return socket_; }
                virtual void                                                Dispose() noexcept override {
                    auto self = shared_from_this();
                    ppp::threading::Executors::ContextPtr context = GetContext();
                    ppp::threading::Executors::StrandPtr strand = GetStrand();

                    ppp::threading::Executors::Post(context, strand,
                        [self, this, context, strand]() noexcept {
                            Finalize();
                        });
                    ITransmission::Dispose();
                }
                virtual Int128                                              HandshakeClient(YieldContext& y, bool& mux) noexcept {
                    if (!HandshakeWebsocket(false, y)) {
                        return 0;
                    }
                    
                    return ITransmission::HandshakeClient(y, mux);
                }
                virtual bool                                                HandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept {
                    if (!HandshakeWebsocket(true, y)) {
                        return false;
                    }

                    return ITransmission::HandshakeServer(y, session_id, mux);
                }
                virtual boost::asio::ip::tcp::endpoint                      GetRemoteEndPoint() noexcept override {
                    return remoteEP_;
                }

            protected:
                virtual std::shared_ptr<Byte>                               DoReadBytes(YieldContext& y, int length) noexcept {
                    if (disposed_) {
                        return NULL;
                    }

                    auto self = shared_from_this();
                    return ITransmissionQoS::DoReadBytes(y, length, self, *this, this->QoS);
                }
                virtual bool                                                DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                    using AsynchronousWriteCallback = typename IWebsocket::AsynchronousWriteCallback;

                    if (disposed_) {
                        return false;
                    }

                    std::shared_ptr<IWebsocket> socket = socket_;
                    if (socket) {
                        auto self = shared_from_this();
                        auto complete_do_write_async_callback = 
                            [self, this, cb, socket, packet, packet_length](bool ok) noexcept {
                                if (ok) {
                                    std::shared_ptr<ITransmissionStatistics> statistics = this->Statistics;
                                    if (statistics) {
                                        statistics->AddOutgoingTraffic(packet_length);
                                    }
                                }
                                else {
                                    Dispose();
                                }

                                if (cb) {
                                    cb(ok);
                                }
                            };

                        bool ok = socket->Write(packet.get(), offset, packet_length, complete_do_write_async_callback);
                        if (!ok) {
                            Dispose();
                        }

                        return ok;
                    }
                    else {
                        return false;
                    }
                }
                virtual bool                                                HandshakeWebsocket(
                    const AppConfigurationPtr&                              configuration,
                    const std::shared_ptr<IWebsocket>&                      socket,
                    HandshakeType                                           handshake_type,
                    YieldContext&                                           y) noexcept = 0;

            protected:
                virtual bool                                                Decorator(boost::beast::websocket::request_type& req) noexcept { return false; }
                virtual bool                                                Decorator(boost::beast::websocket::response_type& res) noexcept { return false; }

            private:
                bool                                                        HandshakeWebsocket(bool client_or_server, YieldContext& y) noexcept {
                    if (disposed_) {
                        return false;
                    }

                    std::shared_ptr<IWebsocket> socket = socket_;
                    if (!socket) {
                        return false;
                    }

                    AppConfigurationPtr configuration = GetConfiguration();
                    HandshakeType handshake_type = HandshakeType::HandshakeType_Server;
                    if (client_or_server) {
                        handshake_type = HandshakeType::HandshakeType_Client;
                    }

                    return HandshakeWebsocket(configuration, socket, handshake_type, y);
                }
                void                                                        Finalize() noexcept {
                    std::shared_ptr<IWebsocket> socket = std::move(socket_); 
                    if (socket) {
                        socket->Dispose();
                    }

#if defined(_WIN32)
                    qoss_.reset();
#endif

                    socket_.reset();
                    disposed_ = true;
                }
                virtual bool                                                ShiftToScheduler() noexcept override {
                    std::shared_ptr<IWebsocket> socket = socket_;
                    if (socket) {
                        return socket->ShiftToScheduler();
                    }
                    else {
                        return false;
                    }
                }

            public:
                std::shared_ptr<Byte>                                       ReadBytes(YieldContext& y, int length) noexcept {
                    if (length < 1) {
                        return NULL;
                    }

                    if (disposed_) {
                        return NULL;
                    }

                    std::shared_ptr<IWebsocket> socket = socket_;
                    if (!socket) {
                        return NULL;
                    }

                    std::shared_ptr<BufferswapAllocator> allocator = this->BufferAllocator;
                    std::shared_ptr<Byte> packet = BufferswapAllocator::MakeByteArray(allocator, length);
                    if (NULL == packet) {
                        return NULL;
                    }

                    bool ok = socket->Read(packet.get(), 0, length, y);
                    if (!ok) {
                        return NULL;
                    }

                    std::shared_ptr<ITransmissionStatistics> statistics = this->Statistics;
                    if (statistics) {
                        statistics->AddIncomingTraffic(length);
                    }

                    return packet;
                }

            private:
#if defined(_WIN32)
                std::shared_ptr<ppp::net::QoSS>                             qoss_;
#endif
                bool                                                        disposed_ = false;
                std::shared_ptr<IWebsocket>                                 socket_;
                boost::asio::ip::tcp::endpoint                              remoteEP_;
            };
        }
    }
}