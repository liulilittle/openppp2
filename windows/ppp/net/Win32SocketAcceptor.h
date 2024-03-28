#pragma once

#include <ppp/net/SocketAcceptor.h>

namespace ppp
{
    namespace net
    {
        class Win32SocketAcceptor final : public ppp::net::SocketAcceptor
        {
        public:
            Win32SocketAcceptor() noexcept;
            Win32SocketAcceptor(const std::shared_ptr<boost::asio::io_context>& context) noexcept;
            virtual ~Win32SocketAcceptor() noexcept;

        public:
            virtual bool                                                            IsOpen() noexcept;
            virtual bool                                                            Open(const char* localIP, int localPort, int backlog) noexcept;
            virtual void                                                            Dispose() noexcept;
            virtual int                                                             GetHandle() noexcept;

        private:
            bool                                                                    Next() noexcept;
            void                                                                    Finalize() noexcept;

        private:
            int                                                                     listenfd_ = -1;
            void*                                                                   hEvent_   = NULL;
            bool                                                                    in_       = false;
            std::shared_ptr<void*>                                                  afo_      = NULL;
            std::shared_ptr<boost::asio::io_context>                                context_;
        };
    }
}