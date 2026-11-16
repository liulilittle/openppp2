#include "netstack_outbound.h"

#include <lwip/tcp.h>
#include <lwip/ip_addr.h>

#include "netstack.h"

#include <algorithm>

namespace lwip {
    netstack_outbound::netstack_outbound() noexcept {
    }

    netstack_outbound::~netstack_outbound() noexcept {
    }

    bool netstack_outbound::post(const ppp::function<void()>& work) noexcept {
        std::shared_ptr<boost::asio::io_context> executor = netstack::Executor;
        if (NULLPTR == executor) {
            return false;
        }

        std::shared_ptr<netstack_outbound> self = shared_from_this();
        boost::asio::post(*executor,
            [self, work]() noexcept {
                work();
            });
        return true;
    }

    bool netstack_outbound::connect(uint32_t address, int port,
        const ConnectedHandler& connected, const DataHandler& data, const ClosedHandler& closed) noexcept {
        if (port <= 0 || port > UINT16_MAX || NULLPTR == connected || NULLPTR == data || NULLPTR == closed) {
            return false;
        }

        return post(
            [this, address, port, connected, data, closed]() noexcept {
                if (NULLPTR != pcb_ || finished_) {
                    connected(false);
                    return;
                }

                struct tcp_pcb* pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
                if (NULLPTR == pcb) {
                    finished_ = true;
                    connected(false);
                    return;
                }

                connected_ = connected;
                data_ = data;
                closed_ = closed;
                pcb_ = pcb;
                // lwIP owns the pcb until close or error; the self reference keeps this
                // object alive for its callbacks until then.
                self_ = shared_from_this();

                ip_addr_t destination;
                ip_addr_set_ip4_u32(&destination, address);
                tcp_arg(pcb, this);
                tcp_recv(pcb, &netstack_outbound::on_recv);
                tcp_sent(pcb, &netstack_outbound::on_sent);
                tcp_err(pcb, &netstack_outbound::on_error);

                const err_t err = tcp_connect(pcb, &destination, static_cast<u16_t>(port), &netstack_outbound::on_connected);
                if (err != ERR_OK) {
                    release_pcb();
                    finish();
                }
            });
    }

    bool netstack_outbound::send(const std::shared_ptr<ppp::Byte>& data, int size, const WrittenHandler& written) noexcept {
        if (NULLPTR == data || size < 1) {
            return false;
        }

        return post(
            [this, data, size, written]() noexcept {
                if (NULLPTR == pcb_ || finished_) {
                    return;
                }

                pending_send item;
                item.data = data;
                item.size = size;
                item.written = written;
                sends_.emplace_back(std::move(item));
                flush();
            });
    }

    void netstack_outbound::ack(int size) noexcept {
        if (size < 1) {
            return;
        }

        post(
            [this, size]() noexcept {
                if (NULLPTR == pcb_) {
                    return;
                }

                // tcp_recved takes a u16_t, so large acknowledgements are split.
                int remaining = size;
                while (remaining > 0) {
                    const int chunk = std::min(remaining, static_cast<int>(UINT16_MAX));
                    tcp_recved(pcb_, static_cast<u16_t>(chunk));
                    remaining -= chunk;
                }
            });
    }

    void netstack_outbound::close() noexcept {
        post(
            [this]() noexcept {
                release_pcb();
                finish();
            });
    }

    /** @brief Moves queued bytes into lwIP while its send buffer has room. */
    bool netstack_outbound::flush() noexcept {
        struct tcp_pcb* pcb = pcb_;
        if (NULLPTR == pcb) {
            return false;
        }

        bool queued = false;
        while (!sends_.empty()) {
            pending_send& item = sends_.front();
            const int room = static_cast<int>(tcp_sndbuf(pcb));
            if (room < 1) {
                break;
            }

            const int chunk = std::min({ item.size - item.offset, room, static_cast<int>(UINT16_MAX) });
            const err_t err = tcp_write(pcb, item.data.get() + item.offset, static_cast<u16_t>(chunk), TCP_WRITE_FLAG_COPY);
            if (err == ERR_MEM) {
                break;
            }
            elif(err != ERR_OK) {
                const bool aborted = release_pcb();
                finish();
                return aborted;
            }

            queued = true;
            item.offset += chunk;
            if (item.offset >= item.size) {
                WrittenHandler written = std::move(item.written);
                sends_.pop_front();
                if (NULLPTR != written) {
                    written();
                }

                if (NULLPTR == pcb_) {
                    return false;
                }
            }
        }

        if (queued) {
            tcp_output(pcb);
        }
        return false;
    }

    /** @brief Reports the end of the connection once and drops the self reference. */
    void netstack_outbound::finish() noexcept {
        if (finished_) {
            return;
        }

        finished_ = true;
        sends_.clear();

        ConnectedHandler connected = std::move(connected_);
        ClosedHandler closed = std::move(closed_);
        data_ = NULLPTR;
        if (NULLPTR != connected) {
            connected(false);
        }
        elif(NULLPTR != closed) {
            closed();
        }

        std::shared_ptr<netstack_outbound> self = std::move(self_);
    }

    /** @brief Detaches callbacks and closes the pcb; abort when the FIN cannot be queued. */
    bool netstack_outbound::release_pcb() noexcept {
        struct tcp_pcb* pcb = pcb_;
        if (NULLPTR == pcb) {
            return false;
        }

        pcb_ = NULLPTR;
        tcp_arg(pcb, NULLPTR);
        tcp_recv(pcb, NULLPTR);
        tcp_sent(pcb, NULLPTR);
        tcp_err(pcb, NULLPTR);
        if (tcp_close(pcb) != ERR_OK) {
            tcp_abort(pcb);
            return true;
        }
        return false;
    }

    err_t netstack_outbound::on_connected(void* arg, struct tcp_pcb* pcb, err_t err) noexcept {
        netstack_outbound* self = static_cast<netstack_outbound*>(arg);
        if (NULLPTR == self || self->pcb_ != pcb) {
            tcp_abort(pcb);
            return ERR_ABRT;
        }

        if (err != ERR_OK) {
            const bool aborted = self->release_pcb();
            self->finish();
            return aborted ? ERR_ABRT : ERR_OK;
        }

        ConnectedHandler connected = std::move(self->connected_);
        if (NULLPTR != connected) {
            connected(true);
        }

        return self->flush() ? ERR_ABRT : ERR_OK;
    }

    err_t netstack_outbound::on_recv(void* arg, struct tcp_pcb* pcb, struct pbuf* p, err_t err) noexcept {
        netstack_outbound* self = static_cast<netstack_outbound*>(arg);
        if (NULLPTR == self || self->pcb_ != pcb) {
            if (NULLPTR != p) {
                pbuf_free(p);
            }
            return ERR_OK;
        }

        // A null pbuf is the peer's FIN; a proxied flow ends with it.
        if (NULLPTR == p || err != ERR_OK) {
            if (NULLPTR != p) {
                pbuf_free(p);
            }

            const bool aborted = self->release_pcb();
            self->finish();
            return aborted ? ERR_ABRT : ERR_OK;
        }

        DataHandler data = self->data_;
        for (struct pbuf* q = p; NULLPTR != q; q = q->next) {
            if (q->len > 0 && NULLPTR != data) {
                data(q->payload, q->len);
            }
        }

        pbuf_free(p);
        return ERR_OK;
    }

    err_t netstack_outbound::on_sent(void* arg, struct tcp_pcb* pcb, u16_t len) noexcept {
        LWIP_UNUSED_ARG(len);

        netstack_outbound* self = static_cast<netstack_outbound*>(arg);
        if (NULLPTR == self || self->pcb_ != pcb) {
            return ERR_OK;
        }

        return self->flush() ? ERR_ABRT : ERR_OK;
    }

    void netstack_outbound::on_error(void* arg, err_t err) noexcept {
        LWIP_UNUSED_ARG(err);

        // lwIP has already freed the pcb; only the bookkeeping remains.
        netstack_outbound* self = static_cast<netstack_outbound*>(arg);
        if (NULLPTR == self) {
            return;
        }

        self->pcb_ = NULLPTR;
        self->finish();
    }
}
