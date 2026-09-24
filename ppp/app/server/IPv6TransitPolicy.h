#pragma once

#include <algorithm>
#include <boost/asio/ip/address.hpp>
#include <ppp/ipv6/IPv6Packet.h>

namespace ppp {
    namespace app {
        namespace server {
            namespace ipv6_transit_policy {
                inline bool IsPacketAllowed(
                    const boost::asio::ip::address_v6& source,
                    const boost::asio::ip::address_v6& destination,
                    const boost::asio::ip::address_v6& prefix,
                    int prefix_length,
                    const boost::asio::ip::address* gateway,
                    bool destination_owned) noexcept {
                    if (!destination_owned ||
                        source.is_unspecified() || source.is_multicast() ||
                        source.is_loopback() || source.is_link_local()) {
                        return false;
                    }

                    prefix_length = std::max<int>(
                        ppp::ipv6::IPv6_MIN_PREFIX_LENGTH,
                        std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));
                    if (!ppp::ipv6::PrefixMatch(destination, prefix, prefix_length)) {
                        return false;
                    }

                    if (nullptr != gateway && gateway->is_v6() && source == gateway->to_v6()) {
                        return true;
                    }

                    const boost::asio::ip::address_v6::bytes_type source_bytes = source.to_bytes();
                    bool source_is_global_unicast = (source_bytes[0] & 0xe0) == 0x20;
                    return source_is_global_unicast &&
                        !ppp::ipv6::PrefixMatch(source, prefix, prefix_length);
                }
            }
        }
    }
}
