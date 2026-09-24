#pragma once

#include <cstdint>
#include <string>

namespace ppp::p2p {

enum class P2PState : std::uint8_t {
    Disabled,
    Unavailable,
    Relay,
    Eligible,
    Probing,
    Direct,
    Suspect,
    FallingBack,
    Failed,
};

enum class P2PFallbackReason : std::uint8_t {
    None,
    Timeout,
    AuthenticationFailure,
    SocketError,
    MigrationFailure,
};

inline const char* ToString(P2PFallbackReason reason) noexcept {
    switch (reason) {
    case P2PFallbackReason::None: return "none";
    case P2PFallbackReason::Timeout: return "timeout";
    case P2PFallbackReason::AuthenticationFailure: return "authentication_failure";
    case P2PFallbackReason::SocketError: return "socket_error";
    case P2PFallbackReason::MigrationFailure: return "migration_failure";
    }
    return "none";
}

inline const char* ToString(P2PState state) noexcept {
    switch (state) {
    case P2PState::Disabled: return "disabled";
    case P2PState::Unavailable: return "unavailable";
    case P2PState::Relay: return "relay";
    case P2PState::Eligible: return "eligible";
    case P2PState::Probing: return "probing";
    case P2PState::Direct: return "direct";
    case P2PState::Suspect: return "suspect";
    case P2PState::FallingBack: return "falling_back";
    case P2PState::Failed: return "failed";
    }
    return "unavailable";
}

inline P2PState ParseP2PState(const std::string& value) noexcept {
    if (value == "disabled") return P2PState::Disabled;
    if (value == "relay") return P2PState::Relay;
    if (value == "eligible") return P2PState::Eligible;
    if (value == "probing") return P2PState::Probing;
    if (value == "direct") return P2PState::Direct;
    if (value == "suspect") return P2PState::Suspect;
    if (value == "falling_back") return P2PState::FallingBack;
    if (value == "failed") return P2PState::Failed;
    return P2PState::Unavailable;
}

inline const char* EffectivePath(P2PState state) noexcept {
    return state == P2PState::Direct ? "direct" : "relay";
}

}
