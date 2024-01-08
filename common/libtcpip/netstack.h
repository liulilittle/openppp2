#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/Executors.h>

namespace lwip {
    typedef ppp::function<bool(void* packet, int size)>     LIBTCPIP_IPV4_OUTPUT;
    typedef ppp::function<void(void)>                       LIBTCPIP_CLOSE_EVENT;

    class netstack {
    public:
        static bool                                         open() noexcept;
        static void                                         close() noexcept;

    public:
        static LIBTCPIP_IPV4_OUTPUT                         output;
        static LIBTCPIP_CLOSE_EVENT                         close_event;
        static uint32_t                                     IP;
        static uint32_t                                     GW;
        static uint32_t                                     MASK;
        static int                                          Localhost;

    public:
        static bool                                         input(const void* packet, int size) noexcept;
        static bool                                         link(int nat, uint32_t& srcAddr, int& srcPort, uint32_t& dstAddr, int& dstPort) noexcept;
    };
}