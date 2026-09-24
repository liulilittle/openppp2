/**
 * @file RinetdConnection.h
 * @brief Defines a bidirectional TCP relay connection used by rinetd.
 */

#pragma once

#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>

#if defined(_WIN32)
#include <windows/ppp/net/QoSS.h>
#elif defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace ppp {
    namespace configurations {
        class AppConfiguration;
    }
    namespace net {
        namespace rinetd {
            /**
             * @brief Represents one proxied TCP session in the rinetd module.
             *
             * The instance owns one accepted local socket and one outbound remote socket,
             * and relays data in both directions until either side closes or timeout occurs.
             */
            class RinetdConnection : public std::enable_shared_from_this<RinetdConnection> {
            public:
                typedef boost::asio::ip::tcp::socket::native_handle_type                RemoteSocketHandle;
                typedef ppp::function<bool(RemoteSocketHandle, ppp::coroutines::YieldContext&)>
                                                                                        RemoteSocketProtector;

#if defined(_LINUX)
                /** @brief Shared pointer type for Linux network protection helper. */
                typedef std::shared_ptr<ppp::net::ProtectorNetwork>                     ProtectorNetworkPtr;
#endif

            public:
                /** @brief Optional per-socket callback run after open and before connect. */
                RemoteSocketProtector                                                   ProtectRemoteSocket;
                /** @brief Fails Open when the per-socket callback is missing or fails. */
                bool                                                                    RemoteSocketProtectorRequired = false;
#if defined(_LINUX)
                ProtectorNetworkPtr                                                     ProtectorNetwork;
#endif

            public:
                /**
                 * @brief Constructs a relay connection object.
                 * @param configuration Application runtime configuration.
                 * @param context I/O context used for async operations.
                 * @param strand Optional strand used to serialize callbacks.
                 * @param local_socket Accepted inbound socket.
                 */
                RinetdConnection(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& local_socket) noexcept;

                /** @brief Destroys the relay and releases native resources. */
                virtual ~RinetdConnection() noexcept;

            public:
                /**
                 * @brief Opens and connects the outbound remote socket.
                 * @param remoteEP Target remote endpoint.
                 * @param y Coroutine yield context.
                 * @return true if connection is established; otherwise false.
                 */
                virtual bool                                                            Open(const boost::asio::ip::tcp::endpoint& remoteEP, ppp::coroutines::YieldContext& y) noexcept;

                /**
                 * @brief Starts bidirectional forwarding between local and remote sockets.
                 * @return true if both forwarding loops were started successfully.
                 */
                virtual bool                                                            Run() noexcept;

#if defined(_IPHONE) || defined(IPHONE)
                /**
                 * @brief Writes client payload directly to the connected remote socket.
                 * @note Used by iOS ctcp when TUN loopback to the local listener is unavailable.
                 */
                bool                                                                    WriteRemote(const void* data, size_t len) noexcept;

                /**
                 * @brief Reads remote responses and forwards them to the supplied callback.
                 */
                void                                                                    StartRemoteToTapRelay(const ppp::function<void(const void*, size_t)>& on_data) noexcept;
#endif

            public:
                /** @brief Returns a shared reference to this object. */
                std::shared_ptr<RinetdConnection>                                       GetReference()     noexcept { return shared_from_this(); }

                /** @brief Returns whether sockets are connected and not disposed. */
                bool                                                                    IsLinked()         noexcept { return !disposed_ && connected_; }

                /** @brief Returns the owning I/O context. */
                std::shared_ptr<boost::asio::io_context>                                GetContext()       noexcept { return context_; }

                /** @brief Returns the inbound/local socket. */
                std::shared_ptr<boost::asio::ip::tcp::socket>                           GetLocalSocket()   noexcept { return local_socket_; }

                /** @brief Returns the outbound/remote socket. */
                std::shared_ptr<boost::asio::ip::tcp::socket>                           GetRemoteSocket()  noexcept { return remote_socket_; }

                /** @brief Returns the active application configuration. */
                std::shared_ptr<ppp::configurations::AppConfiguration>                  GetConfiguration() noexcept { return configuration_; }

                /** @brief Returns local-to-remote forwarding buffer. */
                std::shared_ptr<Byte>                                                   GetLocalBuffer()   noexcept { return local_buffer_; }

                /** @brief Returns remote-to-local forwarding buffer. */
                std::shared_ptr<Byte>                                                   GetRemoteBuffer()  noexcept { return remote_buffer_; }

            public:
                /**
                 * @brief Returns whether the connection has exceeded its timeout threshold.
                 * @param now Current monotonic tick count in milliseconds.
                 * @return true when disposed or timed out.
                 */
                bool                                                                    IsPortAging(uint64_t now) noexcept { return disposed_ || now >= timeout_; }

                /** @brief Asynchronously disposes sockets and internal state. */
                virtual void                                                            Dispose() noexcept;

            protected:
                /** @brief Refreshes timeout deadline according to current connection phase. */
                virtual void                                                            Update() noexcept;

            private:
                /** @brief Performs final cleanup and closes sockets immediately. */
                void                                                                    Finalize() noexcept;

                /**
                 * @brief Starts one forwarding direction for this relay.
                 * @param socket Source socket.
                 * @param to Destination socket.
                 * @param buffer Temporary buffer used for transfer.
                 * @return true if async receive loop was started.
                 */
                bool                                                                    ForwardXToY(boost::asio::ip::tcp::socket* socket, boost::asio::ip::tcp::socket* to, Byte* buffer) noexcept;

            private:
#if defined(_WIN32)
                std::shared_ptr<ppp::net::QoSS>                                         qoss_[2];
#endif
                /** @brief Compact connection lifecycle flags. */
                struct {
                    bool                                                                disposed_  : 1;
                    bool                                                                connected_ : 7;
                };
                UInt64                                                                  timeout_   = 0; 
                std::shared_ptr<boost::asio::io_context>                                context_;
                ppp::threading::Executors::StrandPtr                                    strand_;
                std::shared_ptr<boost::asio::ip::tcp::socket>                           local_socket_;
                std::shared_ptr<boost::asio::ip::tcp::socket>                           remote_socket_;
                std::shared_ptr<Byte>                                                   local_buffer_;
                std::shared_ptr<Byte>                                                   remote_buffer_;
                std::shared_ptr<ppp::configurations::AppConfiguration>                  configuration_;
            };
        }
    }
}
