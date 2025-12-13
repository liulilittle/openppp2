#include <ppp/net/SocketAcceptor.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Socket.h>

#if defined(_WIN32)
#include <windows/ppp/net/Win32SocketAcceptor.h>
#else
#include <common/unix/net/UnixSocketAcceptor.h>
#endif

namespace ppp
{
    namespace net
    {
        void SocketAcceptor::OnAcceptSocket(AcceptSocketEventArgs& e) noexcept
        {
            AcceptSocketEventHandler eh = AcceptSocket;
            if (eh)
            {
                eh(this, e);
            }
            else
            {
                Socket::Closesocket(e.Socket);
            }
        }

        std::shared_ptr<SocketAcceptor> SocketAcceptor::New() noexcept
        {
#if defined(_WIN32)
            return make_shared_object<ppp::net::Win32SocketAcceptor>();
#else
            return make_shared_object<ppp::net::UnixSocketAcceptor>();
#endif
        }
    }
}