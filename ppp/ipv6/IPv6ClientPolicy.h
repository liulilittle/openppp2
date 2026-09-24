#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ppp {
    namespace ipv6 {
        namespace client_policy {
            enum class OwnershipMutation {
                Changed,
                Unchanged,
                Failed,
            };

            struct GatewayNeighborIdentity {
                std::array<std::uint8_t, 16> Address{};
                std::uint32_t ScopeId = 0;
                std::uint64_t InterfaceLuid = 0;
                std::uint32_t InterfaceIndex = 0;
                std::array<std::uint8_t, 32> PhysicalAddress{};
                std::size_t PhysicalAddressLength = 0;
                bool IsRouter = false;
                bool IsPermanent = false;
            };

            struct UnicastAddressIdentity {
                std::array<std::uint8_t, 16> Address{};
                std::uint32_t ScopeId = 0;
                std::uint64_t InterfaceLuid = 0;
                std::uint32_t InterfaceIndex = 0;
                std::uint8_t PrefixLength = 0;
                std::uint32_t PrefixOrigin = 0;
                std::uint32_t SuffixOrigin = 0;
                bool SkipAsSource = false;
            };

            inline OwnershipMutation ClassifyCreateResult(
                unsigned long status,
                unsigned long success_status,
                unsigned long already_exists_status,
                bool existing_query_succeeded,
                bool existing_equivalent) noexcept {
                if (status == success_status) {
                    return OwnershipMutation::Changed;
                }
                if (status == already_exists_status && existing_query_succeeded && existing_equivalent) {
                    return OwnershipMutation::Unchanged;
                }
                return OwnershipMutation::Failed;
            }

            inline bool IsExactGatewayNeighborMatch(
                const GatewayNeighborIdentity& existing,
                const GatewayNeighborIdentity& expected) noexcept {
                if (existing.Address != expected.Address ||
                    existing.ScopeId != expected.ScopeId ||
                    existing.InterfaceLuid != expected.InterfaceLuid ||
                    existing.InterfaceIndex != expected.InterfaceIndex ||
                    existing.PhysicalAddressLength != expected.PhysicalAddressLength ||
                    existing.IsRouter != expected.IsRouter ||
                    existing.IsPermanent != expected.IsPermanent ||
                    existing.PhysicalAddressLength > existing.PhysicalAddress.size()) {
                    return false;
                }

                for (std::size_t i = 0; i < existing.PhysicalAddressLength; ++i) {
                    if (existing.PhysicalAddress[i] != expected.PhysicalAddress[i]) {
                        return false;
                    }
                }
                return true;
            }

            inline bool IsExactUnicastAddressMatch(
                const UnicastAddressIdentity& existing,
                const UnicastAddressIdentity& expected) noexcept {
                return existing.Address == expected.Address &&
                    existing.ScopeId == expected.ScopeId &&
                    existing.InterfaceLuid == expected.InterfaceLuid &&
                    existing.InterfaceIndex == expected.InterfaceIndex &&
                    existing.PrefixLength == expected.PrefixLength &&
                    existing.PrefixOrigin == expected.PrefixOrigin &&
                    existing.SuffixOrigin == expected.SuffixOrigin &&
                    existing.SkipAsSource == expected.SkipAsSource;
            }
        }
    }
}
