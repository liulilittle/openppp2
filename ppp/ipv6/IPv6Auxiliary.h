#pragma once

/**
 * @file IPv6Auxiliary.h
 * @brief Declares cross-platform helpers for applying and restoring IPv6 client/server networking state.
 */

#include <ppp/stdafx.h>
#include <ppp/tap/ITap.h>
#include <ppp/ipv6/IPv6ClientPolicy.h>

namespace ppp {
    namespace configurations {
        class AppConfiguration;
    }
    namespace ipv6 {
        namespace auxiliary {
            /**
             * @brief Carries runtime context required to configure a client-side interface.
             */
            struct ClientContext {
                ppp::tap::ITap*                                               Tap = NULLPTR;
                int                                                           InterfaceIndex = -1;
                ppp::string                                                   InterfaceName;
            };

            /**
             * @brief Stores applied IPv6 changes and captured original client settings for rollback.
             */
            struct ClientState {
                bool                                                          AddressApplied = false;
                bool                                                          AddressOwned = false;
                bool                                                          DefaultRouteApplied = false;
                bool                                                          GatewayNeighborOwned = false;
                bool                                                          SubnetRouteApplied = false;
                bool                                                          DnsApplied = false;
                bool                                                          DefaultRouteWasPresent = false;
                ppp::ipv6::client_policy::UnicastAddressIdentity              OwnedAddress;
                std::uint64_t                                                 GatewayNeighborInterfaceLuid = 0;
                int                                                           GatewayNeighborInterfaceIndex = -1;
                int                                                           OriginalDefaultRouteInterfaceIndex = -1;
                int                                                           OriginalDefaultRouteMetric = -1;
                ppp::string                                                   Address;
                ppp::string                                                   DefaultRouteGateway;
                ppp::string                                                   SubnetRoutePrefix;
                int                                                           SubnetRoutePrefixLength = 0;
                ppp::string                                                   SubnetRouteGateway;
                ppp::string                                                   OriginalDefaultRouteInterface;
                ppp::vector<ppp::string>                                      DnsServers;
                ppp::vector<ppp::string>                                      OriginalDnsServers;
                ppp::vector<ppp::string>                                      OriginalDefaultRoutes;
                ppp::string                                                   OriginalDnsConfiguration;
                ppp::string                                                   OriginalDefaultRoute;

                /**
                 * @brief Resets all recorded flags and cached configuration snapshots.
                 */
                inline void                                                   Clear() noexcept {
                    AddressApplied = false;
                    AddressOwned = false;
                    DefaultRouteApplied = false;
                    GatewayNeighborOwned = false;
                    SubnetRouteApplied = false;
                    DnsApplied = false;
                    DefaultRouteWasPresent = false;
                    OwnedAddress = {};
                    GatewayNeighborInterfaceLuid = 0;
                    GatewayNeighborInterfaceIndex = -1;
                    OriginalDefaultRouteInterfaceIndex = -1;
                    OriginalDefaultRouteMetric = -1;
                    Address.clear();
                    DefaultRouteGateway.clear();
                    SubnetRoutePrefix.clear();
                    SubnetRoutePrefixLength = 0;
                    SubnetRouteGateway.clear();
                    OriginalDefaultRouteInterface.clear();
                    DnsServers.clear();
                    OriginalDnsServers.clear();
                    OriginalDefaultRoutes.clear();
                    OriginalDnsConfiguration.clear();
                    OriginalDefaultRoute.clear();
                }

                /** @brief Returns whether exact-owned Windows mutations still require cleanup. */
                inline bool                                                   HasPendingOwnedMutations() const noexcept {
                    return AddressOwned || GatewayNeighborOwned;
                }
            };

            /**
             * @brief Prepares host-wide server-side IPv6 prerequisites before accepting clients.
             * @param configuration Application configuration used by platform-specific setup.
             * @param preferred_nic Preferred egress NIC name.
             * @param transit_ifname Transit interface name used for forwarding.
             * @return true if setup succeeded or is not required on this platform.
             */
            bool                                                              PrepareServerEnvironment(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const ppp::string& preferred_nic, const ppp::string& transit_ifname) noexcept;
            /**
             * @brief Restores server-side IPv6 environment changes made during preparation.
             * @param configuration Application configuration used by platform-specific cleanup.
             * @param preferred_nic Preferred egress NIC name.
             * @param transit_ifname Transit interface name used for forwarding.
             */
            void                                                              FinalizeServerEnvironment(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const ppp::string& preferred_nic, const ppp::string& transit_ifname) noexcept;
            /**
             * @brief Indicates whether managed IPv6 client configuration is supported.
             * @return true if current platform supports managed mode.
             */
            bool                                                              ClientSupportsManaged() noexcept;
            /**
             * @brief Captures client network state before applying managed IPv6 settings.
             * @param context Client interface runtime context.
             * @param nat_mode Whether NAT-style behavior is enabled.
             * @param state Output state snapshot.
             */
            void                                                              CaptureClientOriginalState(const ClientContext& context, bool nat_mode, ClientState& state) noexcept;
            /**
             * @brief Applies a managed IPv6 address to the client interface.
             * @param context Client interface runtime context.
             * @param address IPv6 address to assign.
             * @param prefix_length Prefix length for the assigned address.
             * @param gua_mode Whether the address is treated as globally routable.
             * @param state Mutable apply/rollback state.
             * @return true if the address configuration succeeded.
             */
            bool                                                              ApplyClientAddress(const ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool gua_mode, ClientState& state) noexcept;
            /**
             * @brief Applies or updates the default IPv6 route on the client.
             * @param context Client interface runtime context.
             * @param gateway Gateway used for default route.
             * @param nat_mode Whether NAT-style behavior is enabled.
             * @param state Mutable apply/rollback state.
             * @return true if the default route was configured successfully.
             */
            bool                                                              ApplyClientDefaultRoute(const ClientContext& context, const boost::asio::ip::address& gateway, bool nat_mode, ClientState& state) noexcept;
            /**
             * @brief Applies a subnet-specific route on the client.
             * @param context Client interface runtime context.
             * @param prefix Routed prefix.
             * @param prefix_length Routed prefix length.
             * @param gateway Gateway used for the subnet route.
             * @param nat_mode Whether NAT-style behavior is enabled.
             * @param state Mutable apply/rollback state.
             * @return true if the subnet route was configured successfully.
             */
            bool                                                              ApplyClientSubnetRoute(const ClientContext& context, const boost::asio::ip::address& prefix, int prefix_length, const boost::asio::ip::address& gateway, bool nat_mode, ClientState& state) noexcept;
            /**
             * @brief Applies DNS server configuration to the client.
             * @param context Client interface runtime context.
             * @param dns_servers DNS server list to apply.
             * @param state Mutable apply/rollback state.
             * @return true if DNS configuration succeeded.
             */
            bool                                                              ApplyClientDns(const ClientContext& context, const ppp::vector<ppp::string>& dns_servers, ClientState& state) noexcept;
            /**
             * @brief Restores original client IPv6 settings captured before managed mode.
             * @param context Client interface runtime context.
             * @param address Managed IPv6 address previously applied.
             * @param prefix_length Prefix length used for managed address.
             * @param nat_mode Whether NAT-style behavior is enabled.
             * @param state Mutable apply/rollback state.
             */
            void                                                              RestoreClientConfiguration(const ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool nat_mode, ClientState& state) noexcept;
        }
    }
}
