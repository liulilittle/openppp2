#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace ppp::app::client::udp {
    struct UdpRelayIdentity final {
        static constexpr std::uint32_t Prefix = 0xc6130000u;
        static bool IsIdentity(std::uint32_t address) noexcept { return (address & 0xffff0000u) == Prefix; }
        static bool Next(std::uint64_t& sequence, std::uint32_t& address, std::uint16_t& port) noexcept {
            if (sequence >= 0xffffffffu) return false;
            ++sequence;
            if ((sequence & 0xffffu) == 0) {
                if (sequence >= 0xffffffffu) return false;
                ++sequence;
            }
            address = Prefix | static_cast<std::uint32_t>(sequence >> 16);
            port = static_cast<std::uint16_t>(sequence);
            return true;
        }
    };
    struct UdpFlowQueueLimit final {
        static constexpr std::size_t MaxPackets = 32;
        static constexpr std::size_t MaxBytes = 64 * 1024;
        static bool Allows(std::size_t packets, std::size_t bytes, std::size_t incoming) noexcept {
            return incoming > 0 && incoming <= 65507 && packets < MaxPackets &&
                bytes <= MaxBytes && incoming <= MaxBytes - bytes;
        }
    };
    inline std::string NormalizeUdpFlowDomain(std::string domain) {
        for (char& c : domain) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        if (!domain.empty() && domain.back() == '.') domain.pop_back();
        return domain;
    }
}
