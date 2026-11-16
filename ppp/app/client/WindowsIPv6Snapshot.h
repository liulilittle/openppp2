#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ppp::app::client {

// Stable, platform-independent representation of the IPv6 mutations made on
// one adapter.  InterfaceIndex is only a lookup hint; GUID and LUID are the
// compare-and-restore identity and must both be present for replay.
struct WindowsIPv6Snapshot final {
    std::uint32_t interface_index = 0;
    std::string interface_luid;
    std::string interface_guid;
    std::string address;
    std::uint8_t address_prefix_length = 0;
    std::string gateway;
    std::string subnet_prefix;
    std::uint8_t subnet_prefix_length = 0;
    std::string subnet_gateway;
    std::uint8_t mode = 0;
    std::uint64_t neighbor_interface_luid = 0;
    std::uint32_t neighbor_interface_index = 0;
    bool address_owned = false;
    bool neighbor_owned = false;
    bool subnet_owned = false;
    bool dns_applied = false;
    bool original_dns_automatic = false;
    std::vector<std::string> dns_servers;
    std::vector<std::string> original_dns_servers;
};

// OP6S v1 is length-delimited and endian-independent.  It is intentionally
// separate from OS structs so journal data remains readable after SDK changes.
bool SerializeWindowsIPv6Snapshot(
    const WindowsIPv6Snapshot& snapshot, std::string& serialized) noexcept;
bool DeserializeWindowsIPv6Snapshot(
    std::string_view serialized, WindowsIPv6Snapshot& snapshot) noexcept;

// A replay identity is valid only when both stable adapter identities match.
bool VerifyWindowsIPv6Identity(
    const WindowsIPv6Snapshot& expected,
    std::uint32_t interface_index,
    std::string_view interface_luid,
    std::string_view interface_guid) noexcept;

} // namespace ppp::app::client
