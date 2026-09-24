#define BOOST_TEST_MODULE tui_runtime_adapter_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/tui/TuiRuntimeAdapter.h>

using ppp::app::runtime::RuntimePhase;
using ppp::app::runtime::RuntimeSnapshot;
using ppp::app::tui::BuildStatusLines;
using ppp::app::tui::ContainsLine;

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
