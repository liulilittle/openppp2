#pragma once

#include <ppp/app/runtime/RuntimeSnapshot.h>

#include <string>
#include <vector>
#include <algorithm>

namespace ppp::app::tui {

inline const char* PhaseDisplayName(runtime::RuntimePhase phase) noexcept {
    switch (phase) {
    case runtime::RuntimePhase::Idle: return "Idle";
    case runtime::RuntimePhase::Starting: return "Starting";
    case runtime::RuntimePhase::PreparingHost: return "Preparing host";
    case runtime::RuntimePhase::Connecting: return "Connecting";
    case runtime::RuntimePhase::Handshaking: return "Handshaking";
    case runtime::RuntimePhase::ApplyingPolicy: return "Applying policy";
    case runtime::RuntimePhase::Connected: return "Connected";
    case runtime::RuntimePhase::Reconnecting: return "Reconnecting";
    case runtime::RuntimePhase::Stopping: return "Stopping";
    case runtime::RuntimePhase::Failed: return "Failed";
    default: return "Unknown";
    }
}

inline const char* P2PDisplayName(ppp::p2p::P2PState state) noexcept {
    switch (state) {
    case ppp::p2p::P2PState::Disabled: return "Disabled";
    case ppp::p2p::P2PState::Unavailable: return "Unavailable";
    case ppp::p2p::P2PState::Relay: return "Relay";
    case ppp::p2p::P2PState::Eligible: return "Eligible";
    case ppp::p2p::P2PState::Probing: return "Probing";
    case ppp::p2p::P2PState::Direct: return "Direct";
    case ppp::p2p::P2PState::Suspect: return "Suspect";
    case ppp::p2p::P2PState::FallingBack: return "Falling back";
    case ppp::p2p::P2PState::Failed: return "Failed";
    }
    return "Unavailable";
}

inline std::vector<std::string> BuildStatusLines(
    const runtime::RuntimeSnapshot& snapshot) {
    std::vector<std::string> lines;
    lines.emplace_back(std::string("Phase: ") + PhaseDisplayName(snapshot.phase));
    if (!snapshot.role.empty() || !snapshot.server.empty()) {
        std::string session = "Session:";
        if (!snapshot.role.empty()) session += " role=" + snapshot.role;
        lines.emplace_back(std::move(session));
    }
    if (!snapshot.server.empty()) {
        lines.emplace_back("Server: " + snapshot.server);
    }
    if (!snapshot.transport.empty()) {
        lines.emplace_back("Transport: " + snapshot.transport);
    }

    lines.emplace_back(std::string("Path: ") +
        (ppp::p2p::EffectivePath(snapshot.p2p_state) == std::string("direct")
            ? "Direct"
            : "Relay"));
    lines.emplace_back(std::string("P2P: ") + P2PDisplayName(snapshot.p2p_state));
    lines.emplace_back("Priority: " + (snapshot.p2p_priority.empty() ? std::string("ipv6-first") : snapshot.p2p_priority));

    auto format_ipv4 = [](std::uint32_t value) {
        return std::to_string(value & 0xffu) + "." +
            std::to_string((value >> 8) & 0xffu) + "." +
            std::to_string((value >> 16) & 0xffu) + "." +
            std::to_string((value >> 24) & 0xffu);
    };
    lines.emplace_back("Peers: " + std::to_string(snapshot.peers.size()) + "/16");
    for (std::size_t index = 0; index < snapshot.peers.size(); ++index) {
        lines.emplace_back("Peer " + std::to_string(index + 1) +
            ": " + format_ipv4(snapshot.peers[index].virtual_ip));
    }

    lines.emplace_back("Traffic: rx=" + std::to_string(snapshot.traffic.rx_bytes) +
        "B tx=" + std::to_string(snapshot.traffic.tx_bytes) + "B");

    if (!snapshot.effective_mux_mode.empty()) {
        lines.emplace_back(snapshot.effective_mux_mode == "compat"
            ? "VMUX: Compatibility mode"
            : "VMUX: " + snapshot.effective_mux_mode);
    }
    if (!snapshot.requested_mux_mode.empty() &&
        snapshot.requested_mux_mode != snapshot.effective_mux_mode) {
        lines.emplace_back("requested VMUX: " + snapshot.requested_mux_mode);
    }
    if (!snapshot.mux_fallback_reason.empty()) {
        lines.emplace_back("fallback reason: " + snapshot.mux_fallback_reason);
    }
    if (!snapshot.mux_receiver_ordering.empty()) {
        lines.emplace_back("receiver ordering=" + snapshot.mux_receiver_ordering);
    }
    if (!snapshot.mux_scheduler.empty()) {
        lines.emplace_back("scheduler=" + snapshot.mux_scheduler);
    }
    if (!snapshot.mux_pool_policy.empty()) {
        lines.emplace_back("pool=" + snapshot.mux_pool_policy);
    }
    if (snapshot.mux_turbo) {
        lines.emplace_back("turbo=on");
    }
    if (snapshot.mux_active_links > 0) {
        lines.emplace_back("active mux links=" + std::to_string(snapshot.mux_active_links));
    }

    if (snapshot.last_error.HasError()) {
        lines.emplace_back("code: " + std::to_string(snapshot.last_error.code));
        lines.emplace_back("severity: " + (snapshot.last_error.severity.empty()
            ? std::string("-") : snapshot.last_error.severity));
        lines.emplace_back("key: " + (snapshot.last_error.user_message_key.empty()
            ? std::string("-") : snapshot.last_error.user_message_key));
        if (!snapshot.last_error.diagnostic_detail.empty()) {
            lines.emplace_back(snapshot.last_error.diagnostic_detail);
        }
    }
    for (auto& line : lines) {
        const auto separator = line.find_first_of(":=");
        if (separator == std::string::npos) continue;
        auto label = line.substr(0, separator);
        const auto first = label.find_first_not_of(' ');
        if (first != std::string::npos) label.erase(0, first);
        const auto last = label.find_last_not_of(' ');
        if (last != std::string::npos) label.erase(last + 1);
        auto value = line.substr(separator + 1);
        const auto start = value.find_first_not_of(' ');
        if (start != std::string::npos) value.erase(0, start);
        label.resize(std::max<std::size_t>(22, label.size()), ' ');
        line = label + ": " + value;
    }
    return lines;
}

inline std::vector<std::string> BuildPeerStatusLines(
    const runtime::RuntimeSnapshot& snapshot) {
    std::vector<std::string> lines;
    lines.emplace_back(std::string("P2P: ") + P2PDisplayName(snapshot.p2p_state));
    lines.emplace_back("Priority: " + (snapshot.p2p_priority.empty() ? std::string("ipv6-first") : snapshot.p2p_priority));
    lines.emplace_back(std::string("Path: ") +
        (ppp::p2p::EffectivePath(snapshot.p2p_state) == std::string("direct") ? "Direct" : "Relay"));
    lines.emplace_back("Peers: " + std::to_string(snapshot.peers.size()) + "/16");
    if (snapshot.peers.empty()) {
        lines.emplace_back("No peer snapshot available");
        return lines;
    }
    for (std::size_t index = 0; index < snapshot.peers.size(); ++index) {
        const auto& peer = snapshot.peers[index];
        const auto format_ipv4 = [](std::uint32_t value) {
            return std::to_string(value & 0xffu) + "." +
                std::to_string((value >> 8) & 0xffu) + "." +
                std::to_string((value >> 16) & 0xffu) + "." +
                std::to_string((value >> 24) & 0xffu);
        };
        lines.emplace_back("Peer " + std::to_string(index + 1));
        lines.emplace_back(std::string(96, '-'));
        lines.emplace_back("UUID:       " + (peer.peer_uuid.empty() ? "-" : peer.peer_uuid));
        lines.emplace_back("Priority:   " + (peer.p2p_priority.empty() ? "ipv6-first" : peer.p2p_priority));
        lines.emplace_back("Virtual IP: " + format_ipv4(peer.virtual_ip));
        lines.emplace_back(std::string("State:      ") + P2PDisplayName(peer.state));
        lines.emplace_back("Path:       " + (peer.effective_path.empty() ? "-" : peer.effective_path));
        lines.emplace_back("Generation: " + std::to_string(peer.generation));
        lines.emplace_back("Key:        " + std::to_string(peer.key_generation));
        lines.emplace_back(std::string("Pending:    ") + (peer.has_pending ? "yes" : "no"));
        lines.emplace_back(std::string("Previous:   ") + (peer.has_previous ? "yes" : "no"));
        lines.emplace_back(std::string("Migration:  ") + (peer.migration_pending ? "pending" : "idle"));
        lines.emplace_back("Local:      " + (peer.local_candidate.empty() ? "-" : peer.local_candidate));
        lines.emplace_back("Remote:     " + (peer.peer_candidate.empty() ? "-" : peer.peer_candidate));
    }
    for (auto& line : lines) {
        const auto separator = line.find_first_of(":=");
        if (separator == std::string::npos) continue;
        auto label = line.substr(0, separator);
        const auto last = label.find_last_not_of(' ');
        if (last != std::string::npos) label.erase(last + 1);
        auto value = line.substr(separator + 1);
        const auto start = value.find_first_not_of(' ');
        if (start != std::string::npos) value.erase(0, start);
        label.resize(std::max<std::size_t>(22, label.size()), ' ');
        line = label + ": " + value;
    }
    return lines;
}

inline bool ContainsLine(
    const std::vector<std::string>& lines,
    const char* needle) noexcept {
    if (needle == nullptr) {
        return false;
    }
    for (const std::string& line : lines) {
        if (line.find(needle) != std::string::npos) {
            return true;
        }
    }
    return false;
}

}
