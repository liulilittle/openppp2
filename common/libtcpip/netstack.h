#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/Executors.h>

struct pbuf;

namespace lwip {
    typedef ppp::function<bool(void* packet, int size)>     LIBTCPIP_IPV4_OUTPUT;
    typedef ppp::function<void(void)>                       LIBTCPIP_CLOSE_EVENT;

    class netstack final {
    public:
        static bool                                         open() noexcept;
        static void                                         close() noexcept;

    public:
        static LIBTCPIP_IPV4_OUTPUT                         output;
        static LIBTCPIP_CLOSE_EVENT                         close_event;

    public:
        static uint32_t                                     IP;
        static uint32_t                                     GW;
        static uint32_t                                     MASK;
        static int                                          Localhost;

    public:
        static std::shared_ptr<boost::asio::io_context>     Executor;

    public:
        static bool                                         input(const void* packet, int size) noexcept;
        static bool                                         input(struct pbuf* buf) noexcept;
        static void                                         close(int nat) noexcept;
        static bool                                         link(int nat, uint32_t& srcAddr, int& srcPort, uint32_t& dstAddr, int& dstPort) noexcept;
    };

    struct pbuf*                                            netstack_pbuf_copy(const void* packet, int size) noexcept;
    struct pbuf*                                            netstack_pbuf_alloc(uint16_t len) noexcept;
    void                                                    netstack_pbuf_free(struct pbuf* buf) noexcept;
}