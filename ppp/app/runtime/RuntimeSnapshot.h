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

            struct RuntimePeerSnapshot final {
                std::string peer_uuid;
                std::string p2p_priority = "ipv6-first";
                std::uint32_t virtual_ip = 0;
                ppp::p2p::P2PState state = ppp::p2p::P2PState::Relay;
                std::string effective_path = "relay";
                bool has_current = false;
                bool has_pending = false;
                bool has_previous = false;
                bool pending_ready = false;
                bool migration_pending = false;
                std::uint64_t generation = 0;
                std::uint64_t key_generation = 0;
                std::uint64_t key_deadline_ms = 0;
                std::uint64_t last_receive_ms = 0;
                std::string local_candidate;
                std::string peer_candidate;

                bool operator==(const RuntimePeerSnapshot& other) const noexcept {
                    return peer_uuid == other.peer_uuid && p2p_priority == other.p2p_priority &&
                        virtual_ip == other.virtual_ip && state == other.state &&
                        effective_path == other.effective_path &&
                        has_current == other.has_current && has_pending == other.has_pending &&
                        has_previous == other.has_previous && pending_ready == other.pending_ready &&
                        migration_pending == other.migration_pending && generation == other.generation &&
                        key_generation == other.key_generation && key_deadline_ms == other.key_deadline_ms &&
                        last_receive_ms == other.last_receive_ms &&
                        local_candidate == other.local_candidate && peer_candidate == other.peer_candidate;
                }
            };

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
                std::string p2p_gate_reason;
                std::vector<RuntimePeerSnapshot> peers;
                std::string p2p_priority = "ipv6-first";
                RuntimeTraffic traffic;
                std::uint64_t connected_monotonic_ms = 0;
                RuntimeError last_error;
            };

        }
    }
}
