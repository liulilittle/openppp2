#pragma once

#include <ppp/p2p/P2PState.h>

#include <cstring>

namespace ppp::p2p {

inline constexpr bool ProductionAuthenticatedControlV1Ready = false;

struct P2PCapabilityDecision {
    bool allowed = false;
    P2PState state = P2PState::Unavailable;
    const char* reason = "unavailable";
};

class P2PCapabilityGate final {
public:
    static P2PCapabilityDecision Evaluate(bool experimental_enabled,
                                          const char* requested_mode,
                                          bool authenticated_exporter_available,
                                          bool socket_protection_ready,
                                          bool authenticated_control_v1_ready) noexcept {
        if (!experimental_enabled) {
            return {false, P2PState::Disabled, "p2p-disabled"};
        }
        if (!requested_mode || std::strcmp(requested_mode, "direct-preferred") != 0) {
            return {false, P2PState::Relay, "relay-only"};
        }
        if (!authenticated_exporter_available) {
            return {false, P2PState::Unavailable, "authenticated-exporter-unavailable"};
        }
        if (!socket_protection_ready) {
            return {false, P2PState::Unavailable, "socket-protection-unavailable"};
        }
        if (!authenticated_control_v1_ready) {
            return {false, P2PState::Unavailable, "authenticated-control-v1-unavailable"};
        }
        return {true, P2PState::Eligible, "eligible"};
    }
};

} // namespace ppp::p2p
