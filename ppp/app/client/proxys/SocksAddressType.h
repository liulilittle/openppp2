#pragma once

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                namespace detail {
                    static inline bool TryParseSocksAddressType(int wire_address_type,
                        ppp::app::protocol::AddressType& address_type,
                        int& address_length) noexcept {
                        switch (wire_address_type) {
                        case 1:
                            address_type = ppp::app::protocol::AddressType::IPv4;
                            address_length = 4;
                            return true;
                        case 3:
                            address_type = ppp::app::protocol::AddressType::Domain;
                            address_length = 0;
                            return true;
                        case 4:
                            address_type = ppp::app::protocol::AddressType::IPv6;
                            address_length = 16;
                            return true;
                        default:
                            return false;
                        }
                    }
                }
            }
        }
    }
}
