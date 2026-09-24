#pragma once

#include <ppp/app/runtime/RuntimePhase.h>

namespace ppp::app::runtime {

struct RuntimeReadiness final {
    bool session = false;
    bool adapter = false;
    bool route = false;
    bool dns = false;
    bool policy = false;

    bool IsFullyReady() const noexcept {
        return session && adapter && route && dns && policy;
    }
};

struct ClientRuntimeReadinessFacts final {
    bool session_established = false;
    bool adapter_open = false;
    bool route_required = true;
    bool route_applied = false;
    bool dns_required = true;
    bool dns_configured = false;
    bool dns_session_active = false;
    bool policy_negotiated = false;
};

inline RuntimeReadiness BuildClientRuntimeReadiness(
    const ClientRuntimeReadinessFacts& facts) noexcept {
    RuntimeReadiness readiness;
    readiness.session = facts.session_established;
    readiness.adapter = facts.adapter_open;
    readiness.route = !facts.route_required || facts.route_applied;
    readiness.dns = !facts.dns_required ||
        (facts.dns_configured && facts.dns_session_active);
    readiness.policy = facts.policy_negotiated;
    return readiness;
}

inline RuntimeReadiness BuildServerRuntimeReadiness(bool active) noexcept {
    return RuntimeReadiness{active, active, active, active, active};
}

inline RuntimePhase GateConnectedPhase(
    RuntimePhase requested,
    const RuntimeReadiness& readiness) noexcept {
    if (requested == RuntimePhase::Connected && !readiness.IsFullyReady()) {
        return RuntimePhase::ApplyingPolicy;
    }
    return requested;
}

}
