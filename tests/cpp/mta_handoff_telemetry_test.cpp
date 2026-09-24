#define BOOST_TEST_MODULE mta_handoff_telemetry_test
#include <boost/test/included/unit_test.hpp>

#include <array>
#include <cstdint>
#include <sstream>
#include <string>

#include <ppp/diagnostics/DatapathPerfJson.h>

namespace datapath_perf = ppp::diagnostics::datapath_perf;

namespace {

datapath_perf::MtaHandoffObservation MakeObservation(uint64_t producer_thread_id, int bytes) {
    datapath_perf::MtaHandoffObservation observation;
    observation.enabled = true;
    observation.producer_thread_id = producer_thread_id;
    observation.producer_context_token = 1;
    observation.target_context_token = 2;
    observation.bytes = bytes;
    return observation;
}

void Record(uint64_t producer_thread_id, int bytes,
    const std::array<uint64_t, datapath_perf::kMtaHandoffSegmentCount>& elapsed_us) {
    datapath_perf::RecordVnetMtaHandoffCompleted(
        MakeObservation(producer_thread_id, bytes), producer_thread_id + 100, elapsed_us);
}

} // namespace

BOOST_AUTO_TEST_CASE(producer_slot_is_stable_for_repeated_producer) {
    datapath_perf::ResetMtaHandoffTelemetryForTesting();

    Record(101, 120, {1, 2, 3, 4});
    Record(101, 240, {5, 6, 7, 8});

    datapath_perf::MtaHandoffProducerSlots& slots = datapath_perf::GetMtaHandoffProducerSlots();
    std::lock_guard<std::mutex> lock(slots.mutex);
    BOOST_TEST(slots.slots[0].producer_thread_id == 101u);
    BOOST_TEST(slots.slots[0].packets == 2u);
    BOOST_TEST(slots.slots[0].bytes == 360u);
    BOOST_TEST(slots.slots[0].us_sum[0] == 6u);
    BOOST_TEST(slots.slots[0].us_sum[3] == 12u);
    BOOST_TEST(slots.slots[0].us_max[0] == 5u);
    BOOST_TEST(slots.slots[0].us_max[3] == 8u);
    BOOST_TEST(slots.slots[1].producer_thread_id == 0u);
}

BOOST_AUTO_TEST_CASE(producer_slot_json_exports_stable_producer_tid) {
    datapath_perf::ResetMtaHandoffTelemetryForTesting();

    Record(4242, 120, {1, 2, 3, 4});
    Record(4242, 240, {5, 6, 7, 8});

    std::ostringstream output;
    datapath_perf::WriteMtaHandoffProducerSlots(output);
    const std::string json = output.str();
    BOOST_TEST(json.find("\"slot\":0,\"producer_tid\":4242") != std::string::npos);
    BOOST_TEST(json.find("\"producer_tid\":0") == std::string::npos);

    datapath_perf::MtaHandoffProducerSlots& slots = datapath_perf::GetMtaHandoffProducerSlots();
    std::lock_guard<std::mutex> lock(slots.mutex);
    BOOST_TEST(slots.slots[0].producer_thread_id == 4242u);
}

BOOST_AUTO_TEST_CASE(distinct_producers_receive_discovery_order_slots) {
    datapath_perf::ResetMtaHandoffTelemetryForTesting();

    Record(300, 100, {1, 1, 1, 1});
    Record(200, 200, {2, 2, 2, 2});
    Record(300, 300, {3, 3, 3, 3});

    datapath_perf::MtaHandoffProducerSlots& slots = datapath_perf::GetMtaHandoffProducerSlots();
    std::lock_guard<std::mutex> lock(slots.mutex);
    BOOST_TEST(slots.slots[0].producer_thread_id == 300u);
    BOOST_TEST(slots.slots[0].packets == 2u);
    BOOST_TEST(slots.slots[1].producer_thread_id == 200u);
    BOOST_TEST(slots.slots[1].packets == 1u);
}

BOOST_AUTO_TEST_CASE(producer_slot_overflow_is_attributed_to_other) {
    datapath_perf::ResetMtaHandoffTelemetryForTesting();

    for (uint64_t producer = 1; producer <= datapath_perf::kMtaHandoffProducerSlotCount + 2; ++producer) {
        Record(producer, 10, {1, 2, 3, 4});
    }

    datapath_perf::MtaHandoffProducerSlots& slots = datapath_perf::GetMtaHandoffProducerSlots();
    std::lock_guard<std::mutex> lock(slots.mutex);
    for (size_t i = 0; i < datapath_perf::kMtaHandoffProducerSlotCount; ++i) {
        BOOST_TEST(slots.slots[i].producer_thread_id == i + 1);
        BOOST_TEST(slots.slots[i].packets == 1u);
    }
    BOOST_TEST(slots.other.packets == 2u);
    BOOST_TEST(slots.other.bytes == 20u);
    BOOST_TEST(slots.other.us_sum[2] == 6u);
    BOOST_TEST(slots.other.us_max[2] == 3u);
}

BOOST_AUTO_TEST_CASE(segment_duration_sums_and_maxima_are_recorded) {
    datapath_perf::ResetMtaHandoffTelemetryForTesting();

    Record(10, 64, {2, 4, 6, 8});
    Record(20, 128, {10, 12, 14, 16});

    datapath_perf::Counters& counters = datapath_perf::GetCounters();
    const std::array<uint64_t, datapath_perf::kMtaHandoffSegmentCount> expected_sums{12, 16, 20, 24};
    const std::array<uint64_t, datapath_perf::kMtaHandoffSegmentCount> expected_maxima{10, 12, 14, 16};
    for (size_t i = 0; i < datapath_perf::kMtaHandoffSegmentCount; ++i) {
        BOOST_TEST(counters.vnet_mta_handoff_segments[i].calls.load(std::memory_order_relaxed) == 2u);
        BOOST_TEST(counters.vnet_mta_handoff_segments[i].us_sum.load(std::memory_order_relaxed) == expected_sums[i]);
        BOOST_TEST(counters.vnet_mta_handoff_segments[i].us_max.load(std::memory_order_relaxed) == expected_maxima[i]);
    }
    BOOST_TEST(counters.vnet_mta_packet_queue_us_sum.load(std::memory_order_relaxed) == 20u);
    BOOST_TEST(counters.vnet_mta_packet_queue_us_max.load(std::memory_order_relaxed) == 14u);
}

BOOST_AUTO_TEST_CASE(measurement_boundary_signal_progresses_from_start_to_end) {
    BOOST_TEST(std::string(datapath_perf::MeasurementBoundaryName(1)) == "measurement_start");
    BOOST_TEST(std::string(datapath_perf::MeasurementBoundaryName(2)) == "measurement_end");
    BOOST_TEST(datapath_perf::MeasurementBoundaryName(0) == nullptr);

    datapath_perf::measurement_boundary_requests = 0;
    datapath_perf::MeasurementBoundarySignalHandler(0);
    BOOST_TEST(datapath_perf::measurement_boundary_requests == 1);
    datapath_perf::MeasurementBoundarySignalHandler(0);
    BOOST_TEST(datapath_perf::measurement_boundary_requests == 2);
    datapath_perf::MeasurementBoundarySignalHandler(0);
    BOOST_TEST(datapath_perf::measurement_boundary_requests == 2);
    datapath_perf::measurement_boundary_requests = 0;
}
