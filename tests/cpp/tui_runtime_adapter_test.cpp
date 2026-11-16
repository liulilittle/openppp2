#define BOOST_TEST_MODULE tui_runtime_adapter_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/tui/TuiRuntimeAdapter.h>

using ppp::app::runtime::RuntimePhase;
using ppp::app::runtime::RuntimeSnapshot;
using ppp::app::tui::BuildStatusLines;
using ppp::app::tui::BuildPeerStatusLines;
static bool ContainsLine(const std::vector<std::string>& lines, const char* needle) {
    std::string expected = needle;
    const auto separator = expected.find_first_of(":=");
    if (separator != std::string::npos) {
        auto label = expected.substr(0, separator);
        label.erase(label.find_last_not_of(' ') + 1);
        auto value = expected.substr(separator + 1);
        const auto start = value.find_first_not_of(' ');
        if (start != std::string::npos) value.erase(0, start);
        label.resize(std::max<std::size_t>(22, label.size()), ' ');
        expected = label + ": " + value;
    }
    return ppp::app::tui::ContainsLine(lines, expected.c_str());
}

BOOST_AUTO_TEST_CASE(connected_snapshot_renders_effective_mux_state) {
    RuntimeSnapshot snapshot;
    snapshot.phase = RuntimePhase::Connected;
    snapshot.requested_mux_mode = "balance";
    snapshot.effective_mux_mode = "compat";
    snapshot.mux_fallback_reason = "peer_missing_flow_v2";
    snapshot.mux_receiver_ordering = "compat";
    snapshot.mux_scheduler = "competition";
    snapshot.mux_pool_policy = "fixed";
    snapshot.mux_turbo = false;
    snapshot.mux_active_links = 2;

    const auto lines = BuildStatusLines(snapshot);
    BOOST_TEST(ContainsLine(lines, "Connected"));
    BOOST_TEST(!ContainsLine(lines, "== Connection"));
    BOOST_TEST(ContainsLine(lines, "VMUX: Compatibility mode"));
    BOOST_TEST(ContainsLine(lines, "requested VMUX: balance"));
    BOOST_TEST(ContainsLine(lines, "fallback reason: peer_missing_flow_v2"));
    BOOST_TEST(ContainsLine(lines, "receiver ordering=compat"));
    BOOST_TEST(ContainsLine(lines, "scheduler=competition"));
    BOOST_TEST(ContainsLine(lines, "pool=fixed"));
    BOOST_TEST(ContainsLine(lines, "active mux links=2"));
}

BOOST_AUTO_TEST_CASE(p2p_renderer_covers_every_typed_state_without_inference) {
    using ppp::p2p::P2PState;
    const struct {
        P2PState state;
        const char* state_text;
        const char* path_text;
    } cases[] = {
        {P2PState::Disabled, "P2P: Disabled", "Path: Relay"},
        {P2PState::Unavailable, "P2P: Unavailable", "Path: Relay"},
        {P2PState::Relay, "P2P: Relay", "Path: Relay"},
        {P2PState::Eligible, "P2P: Eligible", "Path: Relay"},
        {P2PState::Probing, "P2P: Probing", "Path: Relay"},
        {P2PState::Direct, "P2P: Direct", "Path: Direct"},
        {P2PState::Suspect, "P2P: Suspect", "Path: Relay"},
        {P2PState::FallingBack, "P2P: Falling back", "Path: Relay"},
        {P2PState::Failed, "P2P: Failed", "Path: Relay"},
    };

    for (const auto& item : cases) {
        RuntimeSnapshot snapshot;
        snapshot.phase = RuntimePhase::Connected;
        snapshot.p2p_state = item.state;
        const auto lines = BuildStatusLines(snapshot);
        BOOST_TEST_CONTEXT(ppp::p2p::ToString(item.state)) {
            BOOST_TEST(ContainsLine(lines, item.state_text));
            BOOST_TEST(ContainsLine(lines, item.path_text));
        }
    }
}

BOOST_AUTO_TEST_CASE(stopping_is_not_rendered_as_idle) {
    RuntimeSnapshot snapshot;
    snapshot.phase = RuntimePhase::Stopping;
    const auto lines = BuildStatusLines(snapshot);

    BOOST_TEST(ContainsLine(lines, "Stopping"));
    BOOST_TEST(!ContainsLine(lines, "Idle"));
    BOOST_TEST(!ContainsLine(lines, "Disconnected"));
}

BOOST_AUTO_TEST_CASE(failed_snapshot_renders_error_triplet) {
    RuntimeSnapshot snapshot;
    snapshot.phase = RuntimePhase::Failed;
    snapshot.last_error.code = 42;
    snapshot.last_error.severity = "error";
    snapshot.last_error.user_message_key = "LinkFailed";
    snapshot.last_error.diagnostic_detail = "handshake timeout";

    const auto lines = BuildStatusLines(snapshot);
    BOOST_TEST(ContainsLine(lines, "Failed"));
    BOOST_TEST(ContainsLine(lines, "code=42"));
    BOOST_TEST(ContainsLine(lines, "severity=error"));
    BOOST_TEST(ContainsLine(lines, "key=LinkFailed"));
    BOOST_TEST(ContainsLine(lines, "handshake timeout"));
}

BOOST_AUTO_TEST_CASE(peer_snapshot_renders_identity_path_and_key_state) {
    RuntimeSnapshot snapshot;
    snapshot.phase = RuntimePhase::Connected;
    snapshot.p2p_state = ppp::p2p::P2PState::Probing;
    ppp::app::runtime::RuntimePeerSnapshot peer;
    peer.virtual_ip = 0x0300490a; // 10.73.0.3
    peer.peer_uuid = "00112233445566778899aabbccddeeff";
    peer.p2p_priority = "ipv4-first";
    peer.state = ppp::p2p::P2PState::Direct;
    peer.effective_path = "direct";
    peer.key_generation = 4;
    peer.has_previous = true;
    peer.local_candidate = "10.0.0.2:4000";
    peer.peer_candidate = "203.0.113.3:5000";
    peer.generation = 3;
    snapshot.peers.push_back(peer);
    snapshot.p2p_priority = "ipv4-first";

    const auto lines = BuildPeerStatusLines(snapshot);
    BOOST_TEST(ContainsLine(lines, "Priority: ipv4-first"));
    BOOST_TEST(ContainsLine(lines, "Peers: 1/16"));
    BOOST_TEST(ContainsLine(lines, "Peer 1"));
    BOOST_TEST(ContainsLine(lines, "UUID: 00112233445566778899aabbccddeeff"));
    BOOST_TEST(ContainsLine(lines, "Priority: ipv4-first"));
    BOOST_TEST(ContainsLine(lines, "Virtual IP: 10.73.0.3"));
    BOOST_TEST(ContainsLine(lines, "State: Direct"));
    BOOST_TEST(ContainsLine(lines, "Path: direct"));
    BOOST_TEST(ContainsLine(lines, "Generation: 3"));
    BOOST_TEST(ContainsLine(lines, "Key: 4"));
    BOOST_TEST(ContainsLine(lines, "Previous: yes"));
    BOOST_TEST(ContainsLine(lines, "Local: 10.0.0.2:4000"));
    BOOST_TEST(ContainsLine(lines, "Remote: 203.0.113.3:5000"));
}

BOOST_AUTO_TEST_CASE(status_renders_session_transport_traffic_and_nonfatal_error) {
    RuntimeSnapshot snapshot;
    snapshot.phase = RuntimePhase::Connected;
    snapshot.role = "client";
    snapshot.server = "vpn.example";
    snapshot.transport = "tcp";
    snapshot.traffic.rx_bytes = 1200;
    snapshot.traffic.tx_bytes = 3400;
    snapshot.last_error.code = 107;
    snapshot.last_error.severity = "warning";
    snapshot.last_error.user_message_key = "SocketTimeout";

    const auto lines = BuildStatusLines(snapshot);
    BOOST_TEST(ContainsLine(lines, "Session: role=client"));
    BOOST_TEST(ContainsLine(lines, "Server: vpn.example"));
    BOOST_TEST(ContainsLine(lines, "Transport: tcp"));
    BOOST_TEST(ContainsLine(lines, "Traffic: rx=1200B tx=3400B"));
    BOOST_TEST(ContainsLine(lines, "code=107"));
    BOOST_TEST(ContainsLine(lines, "key=SocketTimeout"));
}

BOOST_AUTO_TEST_CASE(peer_blocks_keep_fields_separate_and_aligned) {
    RuntimeSnapshot snapshot;
    snapshot.phase = RuntimePhase::Connected;
    ppp::app::runtime::RuntimePeerSnapshot first;
    first.virtual_ip = 0x0300490a;
    first.state = ppp::p2p::P2PState::Relay;
    ppp::app::runtime::RuntimePeerSnapshot second;
    second.virtual_ip = 0x0400490a;
    second.state = ppp::p2p::P2PState::Direct;
    snapshot.peers = {first, second};

    const auto lines = BuildPeerStatusLines(snapshot);
    BOOST_TEST(ContainsLine(lines, "Peer 1"));
    BOOST_TEST(ContainsLine(lines, "Peer 2"));
    BOOST_TEST(ContainsLine(lines, "Virtual IP: 10.73.0.3"));
    BOOST_TEST(ContainsLine(lines, "Virtual IP: 10.73.0.4"));
    BOOST_TEST(ContainsLine(lines, "State: Relay"));
    BOOST_TEST(!ContainsLine(lines, "10.73.0.3 Relay path="));
    BOOST_TEST(lines.front() == "P2P                   : Disabled");
    BOOST_TEST(ContainsLine(lines, "Virtual IP: 10.73.0.3"));
}
