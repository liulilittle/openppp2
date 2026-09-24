#define BOOST_TEST_MODULE client_lifecycle_stress_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/runtime/RuntimeLifecycle.h>
#include <ppp/app/runtime/RuntimeStopPipeline.h>

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

using ppp::app::runtime::RuntimeError;
using ppp::app::runtime::RuntimeLifecycle;
using ppp::app::runtime::RuntimePhase;
using ppp::app::runtime::RuntimeStopPipeline;

BOOST_AUTO_TEST_CASE(one_hundred_cycles_release_resources_with_one_stop_owner) {
    const RuntimePhase phases[] = {
        RuntimePhase::Starting,
        RuntimePhase::PreparingHost,
        RuntimePhase::Connecting,
        RuntimePhase::Handshaking,
        RuntimePhase::ApplyingPolicy,
        RuntimePhase::Connected,
        RuntimePhase::Reconnecting,
    };

    RuntimeLifecycle lifecycle;
    std::uint64_t now = 1;
    std::uint64_t previous_generation = 0;
    for (std::uint64_t cycle = 1; cycle <= 100; ++cycle) {
        const std::uint64_t generation = lifecycle.Begin({}, now++);
        if (previous_generation != 0) {
            BOOST_TEST(!lifecycle.CompleteStop(
                previous_generation, true, {}, now++));
        }
        previous_generation = generation;

        const RuntimePhase phase = phases[
            (cycle - 1) % (sizeof(phases) / sizeof(phases[0]))];
        BOOST_REQUIRE(lifecycle.Transition(generation, phase, now++));

        std::atomic<int> owners{0};
        const std::uint64_t stop_now = now++;
        auto claim = [&]() {
            if (lifecycle.TryBeginStop(generation, stop_now)) {
                owners.fetch_add(1, std::memory_order_relaxed);
            }
        };
        std::thread first(claim);
        std::thread duplicate(claim);
        first.join();
        duplicate.join();
        BOOST_REQUIRE_EQUAL(owners.load(std::memory_order_relaxed), 1);

        auto input = std::make_shared<int>(1);
        auto dns = std::make_shared<int>(2);
        auto exchanger = std::make_shared<int>(3);
        auto route = std::make_shared<int>(4);
        const std::weak_ptr<int> input_weak = input;
        const std::weak_ptr<int> dns_weak = dns;
        const std::weak_ptr<int> exchanger_weak = exchanger;
        const std::weak_ptr<int> route_weak = route;
        std::vector<int> order;
        const bool route_success = cycle % 10 != 0;
        const auto result = RuntimeStopPipeline::Execute({
            [&]() { order.push_back(1); input.reset(); return true; },
            [&]() { order.push_back(2); dns.reset(); return true; },
            [&]() { order.push_back(3); exchanger.reset(); return true; },
            [&]() { order.push_back(4); route.reset(); return route_success; },
        });

        const std::vector<int> expected{1, 2, 3, 4};
        BOOST_TEST(order == expected, boost::test_tools::per_element());
        BOOST_TEST(input_weak.expired());
        BOOST_TEST(dns_weak.expired());
        BOOST_TEST(exchanger_weak.expired());
        BOOST_TEST(route_weak.expired());

        RuntimeError error;
        error.code = result.success ? 0 : 1;
        BOOST_REQUIRE(lifecycle.CompleteStop(
            generation, result.success, std::move(error), now++));
        BOOST_TEST(!lifecycle.CompleteStop(generation, true, {}, now++));
        BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
            static_cast<int>(route_success ? RuntimePhase::Idle : RuntimePhase::Failed));
    }
}
