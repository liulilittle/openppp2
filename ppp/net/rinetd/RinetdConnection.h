#pragma once

#include <ppp/configurations/AppConfiguration.h>

#ifdef _LINUX
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace ppp {
    namespace net {
        namespace rinetd {
            class RinetdConnection : public std::enable_shared_from_this<RinetdConnection> {
            public:
#ifdef _LINUX
                typedef std::shared_ptr<ppp::net::ProtectorNetwork>                     ProtectorNetworkPtr;

                ProtectorNetworkPtr                                                     ProtectorNetwork;
#endif

            public:
                RinetdConnection(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const std::shared_ptr<boost::asio::io_context>& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& local_socket) noexcept;
                virtual ~RinetdConnection() noexcept;

            public:
                virtual bool                                                            Run(const boost::asio::ip::tcp::endpoint& remoteEP) noexcept;
                std::shared_ptr<boost::asio::io_context>                                GetContext() noexcept;
                std::shared_ptr<boost::asio::ip::tcp::socket>                           GetLocalSocket() noexcept;
                std::shared_ptr<boost::asio::ip::tcp::socket>                           GetRemoteSocket() noexcept;
                std::shared_ptr<ppp::configurations::AppConfiguration>                  GetConfiguration() noexcept;
                std::shared_ptr<Byte>                                                   GetLocalBuffer() noexcept;
                std::shared_ptr<Byte>                                                   GetRemoteBuffer() noexcept;

            public:
                bool                                                                    IsPortAging(uint64_t now) noexcept { return disposed_ || now >= timeout_; }
                virtual void                                                            Dispose() noexcept;

            protected:
                virtual void                                                            Update() noexcept;

            private:
                void                                                                    Finalize() noexcept;
                bool                                                                    ForwardXToY(boost::asio::ip::tcp::socket* socket, boost::asio::ip::tcp::socket* to, Byte* buffer) noexcept;

            private:
                bool                                                                    disposed_;
                UInt64                                                                  timeout_; 
                std::shared_ptr<boost::asio::io_context>                                context_;
                std::shared_ptr<boost::asio::ip::tcp::socket>                           local_socket_;
                std::shared_ptr<boost::asio::ip::tcp::socket>                           remote_socket_;
                std::shared_ptr<Byte>                                                   local_buffer_;
                std::shared_ptr<Byte>                                                   remote_buffer_;
                std::shared_ptr<ppp::configurations::AppConfiguration>                  configuration_;
            };
        }
    }
}