#define BOOST_TEST_MODULE network_ownership_test

#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/route/NetworkOwnership.h>
#include <atomic>
#include <thread>
#include <vector>

namespace route = ppp::app::client::route;

BOOST_AUTO_TEST_CASE(lease_is_exclusive_and_releases_on_scope_exit) {
    auto first = route::NetworkOwnershipLease::Acquire("test-first");
    BOOST_REQUIRE(first.has_value());
    BOOST_TEST(first->IsHeld());
    BOOST_TEST(!first->Token().empty());
    BOOST_TEST(first->OwnerId() == "test-first");

    auto conflict = route::NetworkOwnershipLease::Acquire("test-second");
    BOOST_TEST(!conflict.has_value());

    first.reset();
    auto second = route::NetworkOwnershipLease::Acquire("test-second");
    BOOST_REQUIRE(second.has_value());
    BOOST_TEST(second->IsHeld());
}

BOOST_AUTO_TEST_CASE(empty_owner_id_is_rejected) {
    BOOST_TEST(!route::NetworkOwnershipLease::Acquire("").has_value());
}

BOOST_AUTO_TEST_CASE(concurrent_acquisition_has_exactly_one_holder) {
    constexpr int contenders = 24;
    std::atomic_int ready{0}, attempted{0}, acquired{0};
    std::atomic_bool start{false};
    std::vector<std::thread> threads;
    for (int i = 0; i < contenders; ++i) {
        threads.emplace_back([&] {
            ++ready;
            while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
            auto lease = route::NetworkOwnershipLease::Acquire("concurrent-owner");
            if (lease) ++acquired;
            ++attempted;
            // The winner must keep ownership until every contender tried.
            while (attempted.load() != contenders) std::this_thread::yield();
        });
    }
    while (ready.load() != contenders) std::this_thread::yield();
    start.store(true, std::memory_order_release);
    for (auto& thread : threads) thread.join();
    BOOST_TEST(acquired.load() == 1);
    BOOST_TEST(route::NetworkOwnershipLease::Acquire("after-contention").has_value());
}

BOOST_AUTO_TEST_CASE(ownership_can_be_released_on_a_different_thread) {
    auto lease = route::NetworkOwnershipLease::Acquire("move-owner");
    BOOST_REQUIRE(lease.has_value());
    std::thread releaser([held = std::move(lease)]() mutable { held.reset(); });
    releaser.join();
    BOOST_TEST(route::NetworkOwnershipLease::Acquire("after-move").has_value());
}
