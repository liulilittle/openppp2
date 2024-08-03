#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>

#if defined(_WIN32)
#include <windows/ppp/net/QoSS.h>
#elif defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace ppp {
    namespace net {
        namespace rinetd {
            class RinetdConnection : public std::enable_shared_from_this<RinetdConnection> {
            public:
#if defined(_LINUX)
                typedef std::shared_ptr<ppp::net::ProtectorNetwork>                     ProtectorNetworkPtr;

            public:
                ProtectorNetworkPtr                                                     ProtectorNetwork;
#endif

            public:
                RinetdConnection(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& local_socket) noexcept;
                virtual ~RinetdConnection() noexcept;

            public:
                virtual bool                                                            Open(const boost::asio::ip::tcp::endpoint& remoteEP, ppp::coroutines::YieldContext& y) noexcept;
                virtual bool                                                            Run() noexcept;

            public:
                std::shared_ptr<RinetdConnection>                                       GetReference()     noexcept { return shared_from_this(); }
                bool                                                                    IsLinked()         noexcept { return !disposed_ && connected_; }
                std::shared_ptr<boost::asio::io_context>                                GetContext()       noexcept { return context_; }
                std::shared_ptr<boost::asio::ip::tcp::socket>                           GetLocalSocket()   noexcept { return local_socket_; }
                std::shared_ptr<boost::asio::ip::tcp::socket>                           GetRemoteSocket()  noexcept { return remote_socket_; }
                std::shared_ptr<ppp::configurations::AppConfiguration>                  GetConfiguration() noexcept { return configuration_; }
                std::shared_ptr<Byte>                                                   GetLocalBuffer()   noexcept { return local_buffer_; }
                std::shared_ptr<Byte>                                                   GetRemoteBuffer()  noexcept { return remote_buffer_; }

            public:
                bool                                                                    IsPortAging(uint64_t now) noexcept { return disposed_ || now >= timeout_; }
                virtual void                                                            Dispose() noexcept;

            protected:
                virtual void                                                            Update() noexcept;

            private:
                void                                                                    Finalize() noexcept;
                bool                                                                    ForwardXToY(boost::asio::ip::tcp::socket* socket, boost::asio::ip::tcp::socket* to, Byte* buffer) noexcept;

            private:
#if defined(_WIN32)
                std::shared_ptr<ppp::net::QoSS>                                         qoss_[2];
#endif
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