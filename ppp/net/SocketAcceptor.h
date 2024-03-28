#pragma once

#include <ppp/stdafx.h>

namespace ppp 
{
    namespace net 
    {
        class SocketAcceptor : public std::enable_shared_from_this<SocketAcceptor>
        {
        public:
            typedef struct
            {
                int                                                                 Socket;
            }                                                                       AcceptSocketEventArgs;
            typedef ppp::function<void(SocketAcceptor*, AcceptSocketEventArgs&)>    AcceptSocketEventHandler;

        public:
            AcceptSocketEventHandler                                                AcceptSocket;

        public:
            virtual ~SocketAcceptor() noexcept = default;

        public:
            virtual int                                                             GetHandle() noexcept = 0;
            virtual bool                                                            IsOpen() noexcept = 0;
            virtual bool                                                            Open(const char* localIP, int localPort, int backlog) noexcept = 0;
            virtual void                                                            Dispose() noexcept = 0;
            virtual void                                                            OnAcceptSocket(AcceptSocketEventArgs& e) noexcept;

        public:
            static std::shared_ptr<SocketAcceptor>                                  New() noexcept;
        };
    }
}