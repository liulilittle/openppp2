#pragma once

#include <cstdint>
#include <array>

namespace ppp::tap {

struct TapRuntimeStats final {
    std::uint64_t writev_calls = 0, writev_bytes = 0, writev_segments = 0;
    std::uint64_t writev_max_bytes = 0, writev_max_segments = 0;
    std::array<std::uint64_t, 9> gso_flushes{};
    bool vnet_header = false;
    bool gso_merge_active = false;
    bool tx_gso_supported = false;
    std::uint64_t direct_gso_packets = 0;
    std::uint64_t direct_gso_bytes = 0;
    std::uint64_t direct_gso_rejected = 0;
    std::uint64_t bound_output_lanes = 0;       // GSO lanes running on XTCP shard executors (queue mode)
    std::uint64_t lane_envelope_accepted = 0;   // read envelopes staged to the vnet executor
    std::uint64_t lane_envelope_full_drops = 0; // envelopes dropped at the 1024/8 MiB staging bound
};

} // namespace ppp::tap
