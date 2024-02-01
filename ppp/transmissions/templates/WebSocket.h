#pragma once

#include <ppp/net/asio/websocket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/transmissions/ITransmission.h>

namespace ppp {
    namespace transmissions {
        namespace templates {
            template <typename IWebsocket>
            class WebSocket : public ITransmission { /* Generic */
                friend class ITransmissionQoS;

            public:
                typedef typename IWebsocket::HandshakeType                  HandshakeType;

            public:
                WebSocket(
                    const ContextPtr&                                       context,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    const AppConfigurationPtr&                              configuration) noexcept
                    : ITransmission(context, configuration)
                    , disposed_(false) {

                    boost::system::error_code ec;
                    remoteEP_ = ppp::net::Ipep::V6ToV4(socket->remote_endpoint(ec));

                    bool binary = true;
                    if (configuration->key.plaintext) {
                        binary = false;
                    }

                    socket_ = make_shared_object<IWebsocket>(context, socket, binary);
                }
                virtual ~WebSocket() noexcept                               { Finalize(); }

            public:
                virtual void                                                Dispose() noexcept override {
                    auto self = shared_from_this();
                    std::shared_ptr<boost::asio::io_context> context = GetContext();
                    context->post(
                        [self, this]() noexcept {
                            Finalize();
                        });
                    ITransmission::Dispose();
                }
                virtual Int128                                              HandshakeClient(YieldContext& y, bool& mux) noexcept {
                    return HandshakeWebsocket(false, y) && ITransmission::HandshakeClient(y, mux);
                }
                virtual bool                                                HandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept {
                    return HandshakeWebsocket(true, y) && ITransmission::HandshakeServer(y, session_id, mux);
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
                virtual bool                                                DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const std::shared_ptr<AsynchronousWriteBytesCallback>& cb) noexcept {
                    using AsynchronousWriteCallback = typename IWebsocket::AsynchronousWriteCallback;

                    if (disposed_) {
                        return false;
                    }

                    std::shared_ptr<IWebsocket> socket = socket_;
                    std::shared_ptr<AsynchronousWriteBytesCallback> fcb = cb;

                    if (socket) {
                        auto self = shared_from_this();
                        auto fx = make_shared_object<AsynchronousWriteCallback>(
                            [self, this, fcb, socket, packet, packet_length](bool ok) noexcept {
                                if (ok) {
                                    std::shared_ptr<ITransmissionStatistics> statistics = this->Statistics;
                                    if (statistics) {
                                        statistics->AddOutgoingTraffic(packet_length);
                                    }
                                }

                                if (fcb) {
                                    (*fcb)(ok);
                                }
                            });
                        if (!fx) {
                            return false;
                        }

                        return socket->Write(packet.get(), offset, packet_length, fx);
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
                    exchangeof(disposed_, true); {
                        std::shared_ptr<IWebsocket> socket = std::move(socket_);
                        if (socket) {
                            socket_.reset();
                            socket->Dispose();
                        }
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
                bool                                                        disposed_;
                std::shared_ptr<IWebsocket>                                 socket_;
                boost::asio::ip::tcp::endpoint                              remoteEP_;
            };
        }
    }
}