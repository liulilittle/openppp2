#define BOOST_TEST_MODULE runtime_stop_pipeline_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/runtime/RuntimeStopPipeline.h>
#include <ppp/app/runtime/RuntimeLifecycle.h>

#include <string>
#include <vector>

using ppp::app::runtime::RuntimeStopPipeline;
using ppp::app::runtime::RuntimeStopStep;

BOOST_AUTO_TEST_CASE(teardown_runs_in_contract_order) {
    std::vector<std::string> calls;
    const auto result = RuntimeStopPipeline::Execute({
        [&]() { calls.emplace_back("input"); return true; },
        [&]() { calls.emplace_back("dns"); return true; },
        [&]() { calls.emplace_back("exchanger"); return true; },
        [&]() { calls.emplace_back("route"); return true; },
    });

    const std::vector<std::string> expected = {
        "input", "dns", "exchanger", "route"
    };
    BOOST_TEST(result.success);
    BOOST_TEST(calls == expected, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(failure_is_reported_but_later_cleanup_still_runs) {
    std::vector<std::string> calls;
    const auto result = RuntimeStopPipeline::Execute({
        [&]() { calls.emplace_back("input"); return true; },
        [&]() { calls.emplace_back("dns"); return false; },
        [&]() { calls.emplace_back("exchanger"); return true; },
        [&]() { calls.emplace_back("route"); return false; },
    });

    BOOST_TEST(!result.success);
    BOOST_TEST(static_cast<int>(result.first_failed_step) ==
               static_cast<int>(RuntimeStopStep::Dns));
    BOOST_TEST(calls.size() == 4u);
}

BOOST_AUTO_TEST_CASE(one_hundred_generations_have_one_owner_and_finish_cleanup) {
    ppp::app::runtime::RuntimeLifecycle lifecycle;
    std::uint64_t now = 1;
    for (std::uint64_t cycle = 1; cycle <= 100; ++cycle) {
        const auto generation = lifecycle.Begin({}, now++);
        BOOST_REQUIRE(lifecycle.TryBeginStop(generation, now++));
        BOOST_TEST(!lifecycle.TryBeginStop(generation, now++));

        std::size_t calls = 0;
        const bool route_success = cycle % 10 != 0;
        const auto result = RuntimeStopPipeline::Execute({
            [&]() { ++calls; return true; },
            [&]() { ++calls; return true; },
            [&]() { ++calls; return true; },
            [&]() { ++calls; return route_success; },
        });
        BOOST_TEST(calls == 4u);

        ppp::app::runtime::RuntimeError error;
        error.code = result.success ? 0 : 1;
        BOOST_REQUIRE(lifecycle.CompleteStop(
            generation, result.success, std::move(error), now++));
        BOOST_TEST(!lifecycle.CompleteStop(generation, true, {}, now++));
    }
}
