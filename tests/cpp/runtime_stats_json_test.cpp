#define BOOST_TEST_MODULE runtime_stats_json_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/runtime/RuntimeStatsJson.h>

#include <json/json.h>

namespace runtime = ppp::app::runtime;

BOOST_AUTO_TEST_CASE(stats_json_preserves_v1_contract) {
    runtime::RuntimeStatsSample sample;
    sample.monotonic_ms = 8080123;
    sample.rx_bytes = 1932734464;
    sample.tx_bytes = 224690176;
    sample.link.quality_percent = 99.2;
    sample.link.grade = "Good";
    sample.link.error_count = 12;
    sample.link.success_count = 14803;
    sample.runtime.generation = 7;
    sample.runtime.phase = runtime::RuntimePhase::Connected;
    sample.runtime.role = "client";
    sample.runtime.mux_active_links = 4;
    sample.runtime.p2p_state = ppp::p2p::P2PState::Direct;

    Json::Value root;
    Json::Reader reader;
    const std::string encoded = runtime::SerializeRuntimeStats(sample);
    BOOST_REQUIRE(reader.parse(encoded.data(), encoded.data() + encoded.size(), root));
    BOOST_TEST(root["type"].asString() == "ppp-stats");
    BOOST_TEST(root["version"].asUInt() == 1u);
    BOOST_TEST(root["monotonic_ms"].asUInt64() == 8080123u);
    BOOST_TEST(root["rx_bytes"].asUInt64() == 1932734464u);
    BOOST_TEST(root["tx_bytes"].asUInt64() == 224690176u);
    BOOST_TEST(root["link"]["quality_percent"].asDouble() == 99.2);
    BOOST_TEST(root["link"]["grade"].asString() == "Good");
    BOOST_TEST(root["link"]["error_count"].asUInt64() == 12u);
    BOOST_TEST(root["link"]["success_count"].asUInt64() == 14803u);
    BOOST_TEST(root["runtime"]["phase"].asString() == "connected");
    BOOST_TEST(root["runtime"]["role"].asString() == "client");
    BOOST_TEST(root["runtime"]["mux_active_links"].asUInt() == 4u);
    BOOST_TEST(root["runtime"]["effective_path"].asString() == "direct");
}

BOOST_AUTO_TEST_CASE(stats_json_is_a_single_ndjson_record_without_newline) {
    const std::string json = runtime::SerializeRuntimeStats(runtime::RuntimeStatsSample());
    BOOST_TEST(!json.empty());
    BOOST_TEST(json.find('\n') == std::string::npos);
    BOOST_TEST(json.find('\r') == std::string::npos);
}

BOOST_AUTO_TEST_CASE(stats_json_omits_optional_runtime_blocks_by_default) {
    const std::string encoded = runtime::SerializeRuntimeStats(runtime::RuntimeStatsSample());
    Json::Value root;
    Json::Reader reader;
    BOOST_REQUIRE(reader.parse(encoded.data(), encoded.data() + encoded.size(), root));
    BOOST_TEST(!root.isMember("tcp_stack"));
    BOOST_TEST(!root.isMember("tap_linux"));
    BOOST_TEST(!root.isMember("xtcp"));
    BOOST_TEST(!root.isMember("acceptance_boundary"));
}

BOOST_AUTO_TEST_CASE(stats_json_emits_xtcp_block_when_present) {
    runtime::RuntimeStatsSample sample;
    sample.has_xtcp = true;
    sample.xtcp.runtime_generation = 101;
    sample.xtcp.runtime_instance_id = 1001;
    sample.xtcp.direct_bridge_starts = 102;
    sample.xtcp.direct_bridge_active = 103;
    sample.xtcp.direct_bridge_fallbacks = 104;
    sample.xtcp.direct_upload_accepted_chunks = 105;
    sample.xtcp.direct_upload_accepted_bytes = 106;
    sample.xtcp.direct_download_accepted_bytes = 107;
    sample.xtcp.direct_upload_writable_callbacks = 108;
    sample.xtcp.direct_download_writable_callbacks = 109;
    sample.xtcp.upload_budget_bytes = 4096;
    sample.xtcp.upload_budget_items = 3;
    sample.xtcp.upload_budget_max_bytes = 32 * 1024 * 1024;
    sample.xtcp.upload_budget_max_items = 65536;
    sample.xtcp.upload_budget_rejected = 7;
    sample.xtcp.ingress_submitted = 4096;
    sample.xtcp.ingress_dropped = 7;
    sample.xtcp.ingress_injected = 4089;
    sample.xtcp.flows_opened = 33;
    sample.xtcp.flows_closed = 30;
    sample.xtcp.flows_active = 3;
    sample.xtcp.timer_polls = 981;
    sample.xtcp.timer_events = 210;
    sample.xtcp.output_packets = 5100;
    sample.xtcp.output_bytes = 7340032;
    sample.xtcp.ndi_gso_enabled = true;
    sample.xtcp.ndi_gso_packets = 19;
    sample.xtcp.ndi_gso_bytes = 524288;
    sample.xtcp.ndi_gso_rejected = 2;
    sample.xtcp.connector_read_bytes = 1048576;
    sample.xtcp.connector_written_bytes = 6291456;
    sample.xtcp.resume_requested = 9;
    sample.xtcp.resume_effective = 8;
    sample.xtcp.resume_result_not_blocked = 2;
    sample.xtcp.resume_result_window_full = 1;
    sample.xtcp.resume_result_connection_missing = 3;
    sample.xtcp.resume_pending = 4;
    sample.xtcp.resume_coalesced = 5;
    sample.xtcp.resume_terminal = 6;
    sample.xtcp.resume_retry = 7;
    sample.xtcp.direct_download_chunks = 700;
    sample.xtcp.direct_download_rejected = 2;
    sample.xtcp.direct_upload_rejected = 3;
    sample.xtcp.direct_upload_queue_bytes = 32768;
    sample.xtcp.direct_upload_queue_items = 11;
    sample.xtcp.direct_upload_backpressured = 1;
    sample.xtcp.direct_upload_writer_active = 2;
    sample.xtcp.direct_upload_writer_progress_age_ms = 13;
    sample.xtcp.second_leg_close_requested = 5;
    sample.xtcp.second_leg_close_duplicate_suppressed = 4;
    sample.xtcp.degraded_half_close = 5;
    sample.xtcp.direct_download_queue_bytes = 16384;
    sample.xtcp.direct_download_queue_bytes_highwater = 1048576;

    const std::string encoded = runtime::SerializeRuntimeStats(sample);
    Json::Value root;
    Json::Reader reader;
    BOOST_REQUIRE(reader.parse(encoded.data(), encoded.data() + encoded.size(), root));
    BOOST_REQUIRE(root.isMember("xtcp"));
    const Json::Value& xtcp = root["xtcp"];
    BOOST_TEST(xtcp["runtime_generation"].asUInt64() == 101u);
    BOOST_TEST(xtcp["runtime_instance_id"].asUInt64() == 1001u);
    BOOST_TEST(xtcp["direct_bridge_starts"].asUInt64() == 102u);
    BOOST_TEST(xtcp["direct_bridge_active"].asUInt64() == 103u);
    BOOST_TEST(xtcp["direct_bridge_fallbacks"].asUInt64() == 104u);
    BOOST_TEST(xtcp["direct_upload_accepted_chunks"].asUInt64() == 105u);
    BOOST_TEST(xtcp["direct_upload_accepted_bytes"].asUInt64() == 106u);
    BOOST_TEST(xtcp["direct_download_accepted_bytes"].asUInt64() == 107u);
    BOOST_TEST(xtcp["direct_upload_writable_callbacks"].asUInt64() == 108u);
    BOOST_TEST(xtcp["direct_download_writable_callbacks"].asUInt64() == 109u);
    BOOST_TEST(xtcp["ingress_submitted"].asUInt64() == 4096u);
    BOOST_TEST(xtcp["ingress_dropped"].asUInt64() == 7u);
    BOOST_TEST(xtcp["ingress_injected"].asUInt64() == 4089u);
    BOOST_TEST(xtcp["flows_opened"].asUInt64() == 33u);
    BOOST_TEST(xtcp["flows_closed"].asUInt64() == 30u);
    BOOST_TEST(xtcp["flows_active"].asUInt64() == 3u);
    BOOST_TEST(xtcp["timer_polls"].asUInt64() == 981u);
    BOOST_TEST(xtcp["timer_events"].asUInt64() == 210u);
    BOOST_TEST(xtcp["output_packets"].asUInt64() == 5100u);
    BOOST_TEST(xtcp["output_bytes"].asUInt64() == 7340032u);
    BOOST_TEST(xtcp["ndi_gso_enabled"].asBool());
    BOOST_TEST(xtcp["ndi_gso_packets"].asUInt64() == 19u);
    BOOST_TEST(xtcp["ndi_gso_bytes"].asUInt64() == 524288u);
    BOOST_TEST(xtcp["ndi_gso_rejected"].asUInt64() == 2u);
    BOOST_TEST(xtcp["connector_read_bytes"].asUInt64() == 1048576u);
    BOOST_TEST(xtcp["connector_written_bytes"].asUInt64() == 6291456u);
    BOOST_TEST(xtcp["resume_requested"].asUInt64() == 9u);
    BOOST_TEST(xtcp["resume_effective"].asUInt64() == 8u);
    BOOST_TEST(xtcp["resume_result_not_blocked"].asUInt64() == 2u);
    BOOST_TEST(xtcp["resume_result_window_full"].asUInt64() == 1u);
    BOOST_TEST(xtcp["resume_result_connection_missing"].asUInt64() == 3u);
    BOOST_TEST(xtcp["resume_pending"].asUInt64() == 4u);
    BOOST_TEST(xtcp["resume_coalesced"].asUInt64() == 5u);
    BOOST_TEST(xtcp["resume_terminal"].asUInt64() == 6u);
    BOOST_TEST(xtcp["resume_retry"].asUInt64() == 7u);
    BOOST_TEST(xtcp["direct_download_chunks"].asUInt64() == 700u);
    BOOST_TEST(xtcp["direct_download_rejected"].asUInt64() == 2u);
    BOOST_TEST(xtcp["direct_upload_rejected"].asUInt64() == 3u);
    BOOST_TEST(xtcp["direct_upload_queue_bytes"].asUInt64() == 32768u);
    BOOST_TEST(xtcp["upload_budget_bytes"].asUInt64() == 4096u);
    BOOST_TEST(xtcp["upload_budget_items"].asUInt64() == 3u);
    BOOST_TEST(xtcp["upload_budget_max_bytes"].asUInt64() == 32u * 1024u * 1024u);
    BOOST_TEST(xtcp["upload_budget_max_items"].asUInt64() == 65536u);
    BOOST_TEST(xtcp["upload_budget_rejected"].asUInt64() == 7u);
    BOOST_TEST(xtcp["direct_upload_queue_items"].asUInt64() == 11u);
    BOOST_TEST(xtcp["direct_upload_backpressured"].asUInt64() == 1u);
    BOOST_TEST(xtcp["direct_upload_writer_active"].asUInt64() == 2u);
    BOOST_TEST(xtcp["direct_upload_writer_progress_age_ms"].asUInt64() == 13u);
    BOOST_TEST(xtcp["second_leg_close_requested"].asUInt64() == 5u);
    BOOST_TEST(xtcp["second_leg_close_duplicate_suppressed"].asUInt64() == 4u);
    BOOST_TEST(xtcp["degraded_half_close"].asUInt64() == 5u);
    BOOST_TEST(xtcp["direct_download_queue_bytes"].asUInt64() == 16384u);
    BOOST_TEST(xtcp["direct_download_queue_bytes_highwater"].asUInt64() == 1048576u);
}

BOOST_AUTO_TEST_CASE(stats_json_emits_acceptance_boundary_without_changing_root_schema) {
    runtime::RuntimeStatsSample sample;
    sample.has_acceptance_boundary = true;
    sample.acceptance_boundary.run_uuid = "run-uuid";
    sample.acceptance_boundary.cell_id = "cell-id";
    sample.acceptance_boundary.sequence = 91;
    sample.acceptance_boundary.phase = "measurement_start";
    sample.acceptance_boundary.monotonic_ms = 123456;
    sample.acceptance_boundary.process_pid = 4242;
    sample.acceptance_boundary.process_start_ticks = 987654321;
    sample.acceptance_boundary.xtcp_runtime_instance_id = 1001;

    const std::string encoded = runtime::SerializeRuntimeStats(sample);
    Json::Value root;
    Json::Reader reader;
    BOOST_REQUIRE(reader.parse(encoded.data(), encoded.data() + encoded.size(), root));
    BOOST_TEST(root["version"].asUInt() == 1u);
    BOOST_REQUIRE(root.isMember("acceptance_boundary"));
    const Json::Value& boundary = root["acceptance_boundary"];
    BOOST_REQUIRE_EQUAL(boundary.size(), 9u);
    BOOST_TEST(boundary["schema"].asUInt() == 1u);
    BOOST_TEST(boundary["run_uuid"].asString() == "run-uuid");
    BOOST_TEST(boundary["cell_id"].asString() == "cell-id");
    BOOST_TEST(boundary["sequence"].asUInt64() == 91u);
    BOOST_TEST(boundary["phase"].asString() == "measurement_start");
    BOOST_TEST(boundary["monotonic_ms"].asUInt64() == 123456u);
    BOOST_TEST(boundary["process_pid"].asUInt64() == 4242u);
    BOOST_TEST(boundary["process_start_ticks"].asUInt64() == 987654321u);
    BOOST_TEST(boundary["xtcp_runtime_instance_id"].asUInt64() == 1001u);
}

BOOST_AUTO_TEST_CASE(stats_json_emits_tcp_stack_and_active_linux_tap_blocks) {
    runtime::RuntimeStatsSample sample;
    sample.requested_tcp_stack = "xtcp";
    sample.active_tcp_stack = "xtcp";
    sample.has_tap_linux = true;
    sample.tap_linux.vnet_header = true;
    sample.tap_linux.gso_merge_active = true;
    sample.tap_linux.tx_gso_supported = true;
    sample.tap_linux.direct_gso_packets = 17;
    sample.tap_linux.direct_gso_bytes = 262144;
    sample.tap_linux.direct_gso_rejected = 1;

    const std::string encoded = runtime::SerializeRuntimeStats(sample);
    Json::Value root;
    Json::Reader reader;
    BOOST_REQUIRE(reader.parse(encoded.data(), encoded.data() + encoded.size(), root));
    BOOST_REQUIRE(root.isMember("tcp_stack"));
    BOOST_TEST(root["tcp_stack"]["requested"].asString() == "xtcp");
    BOOST_TEST(root["tcp_stack"]["active"].asString() == "xtcp");
    BOOST_REQUIRE(root.isMember("tap_linux"));
    BOOST_TEST(root["tap_linux"]["vnet_header"].asBool());
    BOOST_TEST(root["tap_linux"]["gso_merge_active"].asBool());
    BOOST_TEST(root["tap_linux"]["tx_gso_supported"].asBool());
    BOOST_TEST(root["tap_linux"]["direct_gso_packets"].asUInt64() == 17u);
    BOOST_TEST(root["tap_linux"]["direct_gso_bytes"].asUInt64() == 262144u);
    BOOST_TEST(root["tap_linux"]["direct_gso_rejected"].asUInt64() == 1u);
}
