#pragma once

/**
 * @file DnsResponseHandler.h
 * @brief Injects resolver responses into TUN or falls back to tunnel forwarding.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace configurations {
        class AppConfiguration;
    }
    namespace net {
        namespace packet {
            class BufferSegment;
        }
    }
    namespace app {
        namespace client {
            namespace dns {

                /** @brief Injectable sinks used by HandleResolverResponse (and unit tests). */
                struct DnsResponseHandlerPorts final {
                    bool enable_dns_cache = false;
                    ppp::function<void(const Byte* packet, int packet_size)> write_cache;
                    ppp::function<bool(
                        const boost::asio::ip::udp::endpoint& sourceEP,
                        const boost::asio::ip::udp::endpoint& destinationEP,
                        const std::shared_ptr<Byte>& owner,
                        void* packet,
                        int packet_size,
                        bool caching)> datagram_output;
                    ppp::function<bool(
                        const boost::asio::ip::udp::endpoint& sourceEP,
                        const boost::asio::ip::udp::endpoint& destinationEP,
                        const void* packet,
                        int packet_size)> tunnel_send;
                };

                class DnsResponseHandler final {
                public:
                    static void HandleWithPorts(
                        const DnsResponseHandlerPorts& ports,
                        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                        const boost::asio::ip::udp::endpoint& sourceEP,
                        const boost::asio::ip::udp::endpoint& destEP,
                        ppp::vector<Byte> response) noexcept;
                };

            }
        }
    }
}
