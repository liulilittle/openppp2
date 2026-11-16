#pragma once

#include <ppp/stdafx.h>

struct tcp_pcb;
struct pbuf;

namespace lwip {
    /**
     * @brief TCP connection opened by the in-process stack toward a virtual-subnet peer.
     *
     * The netif address (netstack::IP) is the source. Every lwIP call runs on
     * netstack::Executor, and every handler is invoked there; consumers copy what they
     * need and hop to their own context. Received data is acknowledged to lwIP only
     * through ack(), so the peer's window follows the consumer's write progress.
     */
    class netstack_outbound final : public std::enable_shared_from_this<netstack_outbound> {
    public:
        typedef ppp::function<void(bool established)>             ConnectedHandler;
        typedef ppp::function<void(const void* data, int size)>   DataHandler;
        typedef ppp::function<void()>                             ClosedHandler;
        typedef ppp::function<void()>                             WrittenHandler;

    public:
        netstack_outbound() noexcept;
        ~netstack_outbound() noexcept;

    public:
        /** @brief Starts connecting to an IPv4 address in network byte order. */
        bool                                                      connect(uint32_t address, int port,
            const ConnectedHandler& connected, const DataHandler& data, const ClosedHandler& closed) noexcept;
        /** @brief Queues bytes; written runs once all of them are inside lwIP's send buffer. */
        bool                                                      send(const std::shared_ptr<ppp::Byte>& data, int size,
            const WrittenHandler& written) noexcept;
        /** @brief Reopens the receive window by size bytes the consumer has delivered. */
        void                                                      ack(int size) noexcept;
        /** @brief Graceful close; falls back to abort when lwIP cannot queue the FIN. */
        void                                                      close() noexcept;

    private:
        struct pending_send {
            std::shared_ptr<ppp::Byte>                            data;
            int                                                   size   = 0;
            int                                                   offset = 0;
            WrittenHandler                                        written;
        };

        bool                                                      post(const ppp::function<void()>& work) noexcept;
        /** @return true when the pcb had to be aborted (callbacks must then return ERR_ABRT). */
        bool                                                      flush() noexcept;
        void                                                      finish() noexcept;
        /** @return true when the pcb had to be aborted rather than closed. */
        bool                                                      release_pcb() noexcept;

        static signed char                                        on_connected(void* arg, struct tcp_pcb* pcb, signed char err) noexcept;
        static signed char                                        on_recv(void* arg, struct tcp_pcb* pcb, struct pbuf* p, signed char err) noexcept;
        static signed char                                        on_sent(void* arg, struct tcp_pcb* pcb, uint16_t len) noexcept;
        static void                                               on_error(void* arg, signed char err) noexcept;

    private:
        struct tcp_pcb*                                           pcb_       = NULLPTR;
        bool                                                      finished_  = false;
        std::shared_ptr<netstack_outbound>                        self_;
        ConnectedHandler                                          connected_;
        DataHandler                                               data_;
        ClosedHandler                                             closed_;
        ppp::list<pending_send>                                   sends_;
    };
}
