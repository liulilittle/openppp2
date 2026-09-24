#pragma once

#include <cstdint>

namespace ppp::tap {

struct TapRuntimeStats final {
    bool vnet_header = false;
    bool gso_merge_active = false;
    bool tx_gso_supported = false;
    std::uint64_t direct_gso_packets = 0;
    std::uint64_t direct_gso_bytes = 0;
    std::uint64_t direct_gso_rejected = 0;
};

} // namespace ppp::tap
