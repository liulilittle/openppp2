#pragma once

/**
 * @file WebSocket.h
 * @brief Declares a generic websocket-based transmission wrapper integrated with ITransmission QoS/statistics flows.
 */

#include <ppp/net/asio/websocket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>

#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITransmission.h>
#include <atomic>

#if defined(_WIN32)
#include <windows/ppp/net/QoSS.h>
#endif

namespace ppp {
    namespace transmissions {
        namespace templates {
            template <typename IWebsocket>
            /**
             * @brief Adapts an IWebsocket implementation to the ITransmission abstraction.
             * @tparam IWebsocket Concrete websocket transport type.
             */
            class WebSocket : public ITransmission { /* Generic */
                friend class                                                ITransmissionQoS;

            public:
                /** @brief Websocket handshake mode enum exposed by IWebsocket. */
                typedef typename IWebsocket::HandshakeType                  HandshakeType;

            public:
                /**
                 * @brief Constructs a websocket transmission wrapper.
                 * @param context Shared asynchronous I/O context.
                 * @param strand Serialized execution strand.
                 * @param socket Connected TCP socket used by websocket transport.
                 * @param configuration Runtime application configuration.
                 */
                WebSocket(
                    const ContextPtr&                                       context,
                    const StrandPtr&                                        strand,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    const AppConfigurationPtr&                              configuration) noexcept
                    : ITransmission(context, strand, configuration) {

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

                    /** @brief Internal websocket proxy that forwards decorator hooks to owner. */
                    class IWebsocketObject final : public IWebsocket {
                    public:
                        /** @brief Builds an IWebsocket instance bound to owner callbacks. */
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
                    std::shared_ptr<IWebsocket> websocket = make_shared_object<IWebsocketObject>(*this, context, strand, socket, binary);
                    std::atomic_store(&socket_, websocket);
                }
                /** @brief Disposes websocket resources. */
                virtual ~WebSocket()                                        noexcept { Finalize(); }

            public:
                /** @brief Gets the underlying websocket object (atomic load). */
                std::shared_ptr<IWebsocket>                                 GetSocket() noexcept { return std::atomic_load(&socket_); }
                /** @brief Gets the underlying websocket object without mutating the wrapper. */
                std::shared_ptr<IWebsocket>                                 GetSocket() const noexcept { return std::atomic_load(&socket_); }
                /** @brief Schedules asynchronous disposal and forwards to base transmission cleanup. */
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
                /** @brief Performs websocket client handshake then transmission-level handshake. */
                virtual Int128                                              HandshakeClient(YieldContext& y, bool& mux) noexcept {
                    if (!HandshakeWebsocket(false, y)) {
                        return 0;
                    }
                    
                    return ITransmission::HandshakeClient(y, mux);
                }
                /** @brief Performs websocket server handshake then transmission-level handshake. */
                virtual bool                                                HandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept {
                    if (!HandshakeWebsocket(true, y)) {
                        return false;
                    }

                    return ITransmission::HandshakeServer(y, session_id, mux);
                }
                /** @brief Gets cached remote endpoint of the underlying TCP socket. */
                virtual boost::asio::ip::tcp::endpoint                      GetRemoteEndPoint() noexcept override {
                    return remoteEP_;
                }

            protected:
                /** @brief Reads bytes via QoS pipeline using this transmission implementation. */
                virtual std::shared_ptr<Byte>                               DoReadBytes(YieldContext& y, int length) noexcept {
                    if (disposed_.load(std::memory_order_acquire)) {
                        return NULLPTR;
                    }

                    auto self = shared_from_this();
                    return ITransmissionQoS::DoReadBytes(y, length, self, *this, this->QoS);
                }
                /** @brief Writes bytes asynchronously through websocket and updates statistics on success. */
                virtual bool                                                DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                    using AsynchronousWriteCallback = typename IWebsocket::AsynchronousWriteCallback;

                    if (disposed_.load(std::memory_order_acquire)) {
                        return false;
                    }

                    std::shared_ptr<IWebsocket> socket = std::atomic_load(&socket_);
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
                /**
                 * @brief Performs websocket transport handshake for the selected direction.
                 * @param configuration Runtime configuration.
                 * @param socket Underlying websocket object.
                 * @param handshake_type Handshake role/type requested by caller.
                 * @param y Coroutine yield context.
                 * @return true if handshake succeeds; otherwise false.
                 */
                virtual bool                                                HandshakeWebsocket(
                    const AppConfigurationPtr&                              configuration,
                    const std::shared_ptr<IWebsocket>&                      socket,
                    HandshakeType                                           handshake_type,
                    YieldContext&                                           y) noexcept = 0;

            protected:
                /** @brief Optional request decorator hook for derived classes. */
                virtual bool                                                Decorator(boost::beast::websocket::request_type& req) noexcept { return false; }
                /** @brief Optional response decorator hook for derived classes. */
                virtual bool                                                Decorator(boost::beast::websocket::response_type& res) noexcept { return false; }

            private:
                /** @brief Resolves handshake role and dispatches to virtual websocket handshake implementation. */
                bool                                                        HandshakeWebsocket(bool client_or_server, YieldContext& y) noexcept {
                    if (disposed_.load(std::memory_order_acquire)) {
                        return false;
                    }

                    std::shared_ptr<IWebsocket> socket = std::atomic_load(&socket_);
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
                /** @brief Finalizes websocket resources and platform QoS objects. */
                void                                                        Finalize() noexcept {
                    if (disposed_.exchange(true, std::memory_order_acq_rel)) {
                        return;
                    }

                    std::shared_ptr<IWebsocket> socket = std::atomic_load(&socket_);
                    std::atomic_store(&socket_, std::shared_ptr<IWebsocket>());

                    if (socket) {
                        socket->Dispose();
                    }

#if defined(_WIN32)
                    qoss_.reset();
#endif
                }
                /** @brief Moves websocket I/O execution to scheduler when supported by transport. */
                virtual bool                                                ShiftToScheduler() noexcept override {
                    std::shared_ptr<IWebsocket> socket = std::atomic_load(&socket_);
                    if (socket) {
                        return socket->ShiftToScheduler();
                    }
                    else {
                        return false;
                    }
                }

            public:
                /** @brief Reads exact byte count from websocket and updates incoming statistics. */
                std::shared_ptr<Byte>                                       ReadBytes(YieldContext& y, int length) noexcept {
                    if (length < 1) {
                        return NULLPTR;
                    }

                    if (disposed_.load(std::memory_order_acquire)) {
                        return NULLPTR;
                    }

                    std::shared_ptr<IWebsocket> socket = std::atomic_load(&socket_);
                    if (!socket) {
                        return NULLPTR;
                    }

                    std::shared_ptr<BufferswapAllocator> allocator = this->BufferAllocator;
                    std::shared_ptr<Byte> packet = BufferswapAllocator::MakeByteArray(allocator, length);
                    if (NULLPTR == packet) {
                        return NULLPTR;
                    }

                    bool ok = socket->Read(packet.get(), 0, length, y);
                    if (!ok) {
                        return NULLPTR;
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
                std::atomic_bool                                                    disposed_{false};
                std::shared_ptr<IWebsocket>                                 socket_;
                boost::asio::ip::tcp::endpoint                              remoteEP_;
            };
        }
    }
}
