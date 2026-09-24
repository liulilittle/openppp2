#pragma once

#include <cstdint>

namespace ppp::app::client {

enum class ClientKeepAliveAction {
    None,
    SendEcho,
    CloseTransport,
    DeferForChildLinks,
};

class ClientKeepAlivePolicy final {
public:
    void OnConnected(
        std::uint64_t now,
        std::uint64_t next_interval) noexcept {
        active_ = true;
        last_packet_at_ = now;
        next_echo_at_ = now + next_interval;
    }

    void OnPacket(std::uint64_t now) noexcept {
        if (active_) {
            last_packet_at_ = now;
        }
    }

    void OnEchoSent(
        std::uint64_t now,
        std::uint64_t next_interval) noexcept {
        if (active_) {
            next_echo_at_ = now + next_interval;
        }
    }

    void Reset() noexcept {
        active_ = false;
        last_packet_at_ = 0;
        next_echo_at_ = 0;
    }

    ClientKeepAliveAction Evaluate(
        std::uint64_t now,
        bool immediately,
        bool has_transport,
        bool defer_for_child_links,
        std::uint64_t stale_timeout) noexcept {
        if (!active_ || !has_transport) {
            return ClientKeepAliveAction::None;
        }
        if (now >= last_packet_at_ + stale_timeout) {
            if (defer_for_child_links) {
                last_packet_at_ = now;
                return ClientKeepAliveAction::DeferForChildLinks;
            }
            return ClientKeepAliveAction::CloseTransport;
        }
        if (!immediately && now < next_echo_at_) {
            return ClientKeepAliveAction::None;
        }
        return ClientKeepAliveAction::SendEcho;
    }

    std::uint64_t LastPacketAt() const noexcept {
        return last_packet_at_;
    }

private:
    std::uint64_t last_packet_at_ = 0;
    std::uint64_t next_echo_at_ = 0;
    bool active_ = false;
};

} // namespace ppp::app::client
