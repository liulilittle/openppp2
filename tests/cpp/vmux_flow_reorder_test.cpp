#define BOOST_TEST_MODULE vmux_flow_reorder_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/mux/MuxFlowReorderBuffer.h>

#include <string>

namespace mux = ppp::app::mux;

BOOST_AUTO_TEST_CASE(reordered_frames_remain_isolated_by_flow) {
    mux::MuxFlowReorderBuffer<std::string> flow_one;
    mux::MuxFlowReorderBuffer<std::string> flow_two;

    BOOST_REQUIRE(flow_one.TryInsert(2, 1, "flow-one-2", 10, 64, 4));
    BOOST_REQUIRE(flow_two.TryInsert(2, 1, "flow-two-2", 10, 64, 4));

    std::string delivered;
    BOOST_REQUIRE(flow_two.Take(2, delivered));
    BOOST_TEST(delivered == "flow-two-2");
    BOOST_TEST(flow_two.empty());
    BOOST_TEST(flow_one.buffered_bytes() == 10u);

    BOOST_REQUIRE(flow_one.Take(2, delivered));
    BOOST_TEST(delivered == "flow-one-2");
}

BOOST_AUTO_TEST_CASE(reorder_memory_is_strictly_bounded) {
    mux::MuxFlowReorderBuffer<int> flow;

    BOOST_REQUIRE(flow.TryInsert(2, 1, 20, 6, 8, 4));
    BOOST_TEST(!flow.TryInsert(3, 1, 30, 3, 8, 4));
    BOOST_TEST(flow.buffered_bytes() == 6u);
    BOOST_TEST(flow.size() == 1u);

    int delivered = 0;
    BOOST_REQUIRE(flow.Take(2, delivered));
    BOOST_TEST(delivered == 20);
    BOOST_TEST(flow.buffered_bytes() == 0u);
}

BOOST_AUTO_TEST_CASE(reorder_node_count_is_strictly_bounded) {
    mux::MuxFlowReorderBuffer<int> flow;

    BOOST_REQUIRE(flow.TryInsert(1, 0, 1, 1, 1024, 3));
    BOOST_REQUIRE(flow.TryInsert(2, 0, 2, 1, 1024, 3));
    BOOST_REQUIRE(flow.TryInsert(3, 0, 3, 1, 1024, 3));
    BOOST_TEST(!flow.TryInsert(4, 0, 4, 1, 1024, 3));
    BOOST_TEST(flow.size() == 3u);
}

BOOST_AUTO_TEST_CASE(first_future_sequence_handles_wrap_with_standard_map_order) {
    mux::MuxFlowReorderBuffer<int> flow;
    BOOST_REQUIRE(flow.TryInsert(0xffffffffu, 0xfffffffeu, 1, 1, 64, 8));
    BOOST_REQUIRE(flow.TryInsert(0u, 0xfffffffeu, 2, 1, 64, 8));
    BOOST_REQUIRE(flow.TryInsert(1u, 0xfffffffeu, 3, 1, 64, 8));

    std::uint32_t selected = 0;
    BOOST_REQUIRE(flow.FirstSequence(0xfffffffeu, selected));
    BOOST_TEST(selected == 0xffffffffu);

    int value = 0;
    BOOST_REQUIRE(flow.Take(selected, value));
    BOOST_REQUIRE(flow.FirstSequence(0xffffffffu, selected));
    BOOST_TEST(selected == 0u);
}

BOOST_AUTO_TEST_CASE(first_future_sequence_uses_ordered_lookup_after_reference_moves) {
    mux::MuxFlowReorderBuffer<int> flow;
    BOOST_REQUIRE(flow.TryInsert(20u, 10u, 20, 1, 64, 8));
    BOOST_REQUIRE(flow.TryInsert(30u, 10u, 30, 1, 64, 8));
    BOOST_REQUIRE(flow.TryInsert(40u, 10u, 40, 1, 64, 8));

    std::uint32_t selected = 0;
    BOOST_REQUIRE(flow.FirstSequence(25u, selected));
    BOOST_TEST(selected == 30u);
}

BOOST_AUTO_TEST_CASE(first_future_sequence_rejects_ambiguous_ordered_candidate) {
    mux::MuxFlowReorderBuffer<int> flow;
    BOOST_REQUIRE(flow.TryInsert(0xffffffffu, 0xfffffffeu, 1, 1, 64, 8));

    std::uint32_t selected = 0;
    BOOST_TEST(!flow.FirstSequence(0x7fffffffu, selected));
}

BOOST_AUTO_TEST_CASE(half_circle_is_ambiguous_and_not_selected) {
    mux::MuxFlowReorderBuffer<int> ambiguous_only;
    BOOST_TEST(!ambiguous_only.TryInsert(0x80000000u, 0u, 1, 1, 64, 8));

    std::uint32_t selected = 0;
    BOOST_TEST(!ambiguous_only.FirstSequence(0u, selected));

    mux::MuxFlowReorderBuffer<int> with_valid_future;
    BOOST_TEST(!with_valid_future.TryInsert(0x80000000u, 0u, 1, 1, 64, 8));
    BOOST_REQUIRE(with_valid_future.TryInsert(5u, 0u, 2, 1, 64, 8));
    BOOST_REQUIRE(with_valid_future.FirstSequence(0u, selected));
    BOOST_TEST(selected == 5u);
}
