#pragma once

/**
 * @file DnsUdpRelay.h
 * @brief Legacy UDP DNS relay (socket protect + async receive).
 */

#include <ppp/app/client/dns/DnsQueryContext.h>
#include <ppp/app/client/dns/DnsSessionContext.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/dns/DnsWireValidation.h>
#include <ppp/stdafx.h>

namespace ppp {
    namespace coroutines {
        class YieldContext;
    }
}

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                class DnsUdpRelay final {
                public:
                    static bool ShouldAcceptRelayResponse(
                        const boost::asio::ip::udp::endpoint& received_from,
                        const boost::asio::ip::udp::endpoint& expected_server,
                        const Byte* query,
                        int query_length,
                        const Byte* response,
                        int response_length) noexcept {

                        return received_from.address() == expected_server.address() &&
                            received_from.port() == expected_server.port() &&
                            ppp::dns::detail::IsDnsResponseForQuery(
                                query, static_cast<size_t>(query_length),
                                response, static_cast<size_t>(response_length));
                    }

                    static bool CanSpawn(
                        const DnsQueryContext& context,
                        const std::shared_ptr<const DnsSessionContext>& session) noexcept {
                        return context.IsValid() && NULLPTR != session && session->IsActive();
                    }

                    static bool Spawn(
                        const DnsQueryContext& context,
                        const std::shared_ptr<const DnsSessionContext>& session,
                        const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
                        const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                        const boost::asio::ip::address& serverIP,
                        const boost::asio::ip::address& destinationIP,
                        bool use_underlying_nic) noexcept;

                    static bool RunCoroutine(
                        const DnsQueryContext& context,
                        ppp::coroutines::YieldContext& y,
                        const std::shared_ptr<boost::asio::ip::udp::socket>& socket,
                        const std::shared_ptr<Byte>& buffer,
                        const boost::asio::ip::address& serverIP,
                        const std::shared_ptr<const DnsSessionContext>& session,
                        const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                        const std::shared_ptr<boost::asio::io_context>& io_context,
                        const boost::asio::ip::udp::endpoint& sourceEP,
                        const boost::asio::ip::udp::endpoint& destinationEP,
                        bool use_underlying_nic) noexcept;
                };

            }
        }
    }
}
