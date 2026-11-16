#pragma once

/**
 * @file ClientNetworkInterface.h
 * @brief Lightweight snapshot of a host network interface for VPN route/DNS operations.
 */

#include <ppp/net/IPEndPoint.h>

namespace ppp {
    namespace app {
        namespace client {

            /**
             * @brief Cached host NIC metadata populated during VEthernetNetworkSwitcher::Open().
             */
            class ClientNetworkInterface {
            public:
                ppp::string                                                     Name;
#if !defined(_MACOS)
                ppp::string                                                     Id;
#endif
                int                                                             Index = -1;
                ppp::vector<boost::asio::ip::address>                           DnsAddresses;

                boost::asio::ip::address                                        IPAddress;
                // Global IPv6 addresses on the same physical interface. This
                // is a snapshot used only for P2P transport candidates.
                ppp::vector<boost::asio::ip::address>                           IPv6Addresses;
                boost::asio::ip::address                                        GatewayServer;
                boost::asio::ip::address                                        SubmaskAddress;

#if defined(_WIN32)
                ppp::string                                                     Description;
#elif defined(_MACOS)
                ppp::unordered_map<uint32_t, uint32_t>                          DefaultRoutes;
#endif

                ClientNetworkInterface() noexcept : Index(-1) {}
                virtual ~ClientNetworkInterface() noexcept = default;
            };

        }
    }
}
