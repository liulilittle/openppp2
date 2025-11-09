#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/Executors.h>

struct pbuf;

namespace lwip {
    typedef ppp::function<bool(void* packet, int size)>     LIBTCPIP_IPV4_OUTPUT;
    typedef ppp::function<void(void)>                       LIBTCPIP_CLOSED_EVENT;
    typedef ppp::function<int(
        boost::asio::ip::tcp::endpoint& dest, 
        boost::asio::ip::tcp::endpoint& src,
        uint32_t                        seq,
        uint32_t                        ack,    
        uint16_t                        wnd)>               LIBTCPIP_ACCEPT_EVENT;

    class netstack final {
    public:
        static bool                                         open() noexcept;
        static void                                         close() noexcept;
        static void                                         close(const LIBTCPIP_CLOSED_EVENT& event) noexcept;

    public:
        static LIBTCPIP_IPV4_OUTPUT                         output;
        static LIBTCPIP_CLOSED_EVENT                        closed;
        static LIBTCPIP_ACCEPT_EVENT                        accept;

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
    std::shared_ptr<ppp::Byte>                              netstack_wrap_ipv4_tcp_syn_packet(
        boost::asio::ip::tcp::endpoint&                     dest, 
        boost::asio::ip::tcp::endpoint&                     src, 
        uint16_t                                            wnd, 
        uint32_t                                            ack, 
        uint32_t                                            seq,
        int&                                                outlen) noexcept;
}