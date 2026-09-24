#pragma once

/**
 * @file DnsUdpFlowRegistry.h
 * @brief Tracks resolver-owned UDP DNS requests that must bypass interception once.
 */

#include <ppp/stdafx.h>

#include <chrono>
#include <mutex>

namespace ppp {
    namespace dns {

        class DnsUdpFlowRegistry final {
        public:
            bool Register(
                uint16_t local_port,
                const boost::asio::ip::udp::endpoint& remote,
                std::chrono::milliseconds lifetime) noexcept;

            bool Consume(
                uint16_t local_port,
                const boost::asio::ip::udp::endpoint& remote) noexcept;

        private:
            struct Entry final {
                uint16_t local_port = 0;
                boost::asio::ip::udp::endpoint remote;
                std::chrono::steady_clock::time_point expires_at;
            };

            void PurgeExpired(std::chrono::steady_clock::time_point now) noexcept;

        private:
            std::mutex mutex_;
            ppp::vector<Entry> entries_;
        };

    }
}
