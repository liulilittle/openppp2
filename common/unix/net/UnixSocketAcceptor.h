#pragma once

#include <ppp/net/SocketAcceptor.h>

namespace ppp
{
    namespace net
    {
        class UnixSocketAcceptor final : public ppp::net::SocketAcceptor
        {
        public:
            UnixSocketAcceptor() noexcept;
            virtual ~UnixSocketAcceptor() noexcept;

        public:
            virtual bool                                                            IsOpen() noexcept;
            virtual bool                                                            Open(const char* localIP, int localPort, int backlog) noexcept;
            virtual void                                                            Dispose() noexcept;
            virtual int                                                             GetHandle() noexcept;

        private:
            bool                                                                    Next() noexcept;
            void                                                                    Finalize() noexcept;

        private:
            std::shared_ptr<boost::asio::ip::tcp::acceptor>                         server_;
            boost::asio::io_context*                                                context_ = NULL;
            bool                                                                    in_      = false;
        };
    }
}