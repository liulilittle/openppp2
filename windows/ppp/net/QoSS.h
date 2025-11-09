#pragma once

#include <ppp/stdafx.h>

namespace ppp
{
    namespace net
    {
        class QoSS final
        {
        public:
            QoSS(int fd) noexcept;
            ~QoSS() noexcept;

        public:
            static std::shared_ptr<QoSS>            New(int fd, const boost::asio::ip::address& host, int port) noexcept { return New(fd, host, port, false); }
            static std::shared_ptr<QoSS>            New(int fd) noexcept { return New(fd, boost::asio::ip::address_v4::any(), 0, true); }

        private:
            static std::shared_ptr<QoSS>            New(int fd, const boost::asio::ip::address& host, int port, bool noaddress) noexcept;

        private:
            int                                     fd_ = -1;
            void*                                   h_  = NULL;
            DWORD                                   f_  = 0;
        };
    }
}