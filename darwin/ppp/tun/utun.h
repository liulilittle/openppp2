#pragma once

#include <ppp/stdafx.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/native/rib.h>

namespace ppp 
{
    namespace darwin 
    {
        namespace tun 
        {
            void                                                utun_close(int fd) noexcept;
            bool                                                utun_set_mac(int tun, const ppp::string& mac) noexcept;
            int                                                 utun_utunnum(const ppp::string& dev) noexcept;
            bool                                                utun_set_cloexec(int fd) noexcept;
            int                                                 utun_open(int utunnum) noexcept;
            int                                                 utun_open(int utunnum, uint32_t ip, uint32_t gw, uint32_t mask) noexcept;
            bool                                                utun_set_mtu(int tun, int mtu) noexcept;
            bool                                                utun_get_if_name(int tun, ppp::string& ifrName) noexcept;
            bool                                                utun_set_if_ip_gw_and_mask(int tun, const ppp::string& ip, const ppp::string& gw, const ppp::string& mask) noexcept;
            bool                                                utun_add_route(UInt32 address, UInt32 gw) noexcept;
            bool                                                utun_del_route(UInt32 address, UInt32 gw) noexcept;
            bool                                                utun_add_route(UInt32 address, int prefix, UInt32 gw) noexcept;
            bool                                                utun_del_route(UInt32 address, int prefix, UInt32 gw) noexcept;
            bool                                                utun_add_route2(UInt32 address, UInt32 mask, UInt32 gw) noexcept;
            bool                                                utun_del_route2(UInt32 address, UInt32 mask, UInt32 gw) noexcept;
        }
    }
}