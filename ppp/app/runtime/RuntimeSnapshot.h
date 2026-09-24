#pragma once

#include <ppp/app/runtime/RuntimeError.h>
#include <ppp/app/runtime/RuntimePhase.h>
#include <ppp/app/runtime/RuntimeTraffic.h>
#include <ppp/p2p/P2PState.h>

#include <cstdint>
#include <string>
#include <vector>

namespace ppp {
    namespace app {
        namespace runtime {

            struct RuntimeSnapshot final {
                static constexpr std::uint32_t SchemaVersion = 1;

                std::uint32_t schema_version = SchemaVersion;
                std::uint64_t generation = 0;
                std::uint64_t monotonic_ms = 0;
                RuntimePhase phase = RuntimePhase::Idle;
                std::string role;
                std::string server;
                std::string transport;
                std::vector<std::string> capabilities;
                std::string requested_mux_mode;
                std::string effective_mux_mode;
                std::string mux_receiver_ordering;
                std::string mux_scheduler;       ///< competition|round_robin
                std::string mux_pool_policy;     ///< fixed|adaptive
                bool mux_turbo = false;
                std::uint16_t mux_active_links = 0;
                std::string mux_fallback_reason;
                ppp::p2p::P2PState p2p_state = ppp::p2p::P2PState::Disabled;
                RuntimeTraffic traffic;
                std::uint64_t connected_monotonic_ms = 0;
                RuntimeError last_error;
            };

        }
    }
}
