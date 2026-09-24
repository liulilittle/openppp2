#pragma once

/**
 * @file AssignedAddressManager.h
 * @brief Server-assigned IPv4/IPv6 apply and restore for the VPN client.
 */

#include <ppp/ipv6/IPv6Auxiliary.h>
#include <ppp/net/IPEndPoint.h>

namespace ppp { namespace app { namespace protocol { struct VirtualEthernetInformationExtensions; } } }

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;

            /**
             * @brief Applies and restores server-assigned IPv4/IPv6 addresses on the local NIC.
             *
             * @details Extracted from VEthernetNetworkSwitcher (PR2a-2). Bind() must be called once
             *          from the owning switcher constructor before any apply/restore operation.
             */
            class AssignedAddressManager {
            public:
                using IPv6AppliedState = ppp::ipv6::auxiliary::ClientState;

                AssignedAddressManager() noexcept = default;

                /** @brief Attaches the manager to its owning switcher (non-owning). */
                void Bind(VEthernetNetworkSwitcher* owner) noexcept;

#if !defined(_ANDROID) && !defined(_IPHONE)
                /** @brief Applies managed IPv6 address, route, and DNS configuration. */
                bool ApplyAssignedIPv6(const protocol::VirtualEthernetInformationExtensions& extensions) noexcept;

                /** @brief Restores previous IPv6 configuration captured before apply. */
                void RestoreAssignedIPv6() noexcept;

                /** @brief Applies the server-assigned IPv4 address to the TAP interface. */
                bool ApplyAssignedIPv4(const protocol::VirtualEthernetInformationExtensions& extensions) noexcept;

                /** @brief Restores the original IPv4 configuration on the TAP interface. */
                void RestoreAssignedIPv4() noexcept;

                /** @brief Returns whether managed IPv6 is currently applied. */
                bool Ipv6Applied() const noexcept { return ipv6_applied_; }

                /** @brief Returns whether exact-owned IPv6 mutations still require cleanup. */
                bool HasPendingIPv6Cleanup() const noexcept { return ipv6_state_.HasPendingOwnedMutations(); }

                /** @brief Returns whether server-assigned IPv4 is currently applied. */
                bool Ipv4Applied() const noexcept { return ipv4_applied_; }

                /** @brief Returns the last IPv6 address successfully applied to the local NIC. */
                boost::asio::ip::address LastAssignedIPv6() const noexcept { return last_assigned_ipv6_; }
#endif

            private:
                VEthernetNetworkSwitcher* owner_ = nullptr;

#if !defined(_ANDROID) && !defined(_IPHONE)
                bool                                                                ipv6_applied_ = false;
                IPv6AppliedState                                                    ipv6_state_;
                boost::asio::ip::address                                            last_assigned_ipv6_;

                bool                                                                ipv4_applied_ = false;
                boost::asio::ip::address                                            assigned_ipv4_address_;
                boost::asio::ip::address                                            assigned_ipv4_gateway_;
                boost::asio::ip::address                                            assigned_ipv4_mask_;

                bool                                                                static_ipv4_captured_ = false;
                boost::asio::ip::address                                            static_ipv4_address_;
                boost::asio::ip::address                                            static_ipv4_gateway_;
                boost::asio::ip::address                                            static_ipv4_mask_;
#endif
            };
        }
    }
}
