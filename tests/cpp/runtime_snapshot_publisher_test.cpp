#define BOOST_TEST_MODULE runtime_snapshot_publisher_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/runtime/RuntimeSnapshotPublisher.h>

namespace {

using ppp::app::runtime::RuntimePhase;
using ppp::app::runtime::RuntimeSnapshot;
using ppp::app::runtime::RuntimeSnapshotPublisher;

RuntimeSnapshot MakeSnapshot(
    std::uint64_t generation,
    std::uint64_t monotonic_ms,
    RuntimePhase phase) {
    RuntimeSnapshot snapshot;
    snapshot.generation = generation;
    snapshot.monotonic_ms = monotonic_ms;
    snapshot.phase = phase;
    return snapshot;
}

}

BOOST_AUTO_TEST_CASE(publisher_rejects_stale_or_duplicate_snapshots) {
    RuntimeSnapshotPublisher publisher;

    BOOST_TEST(publisher.Publish(MakeSnapshot(2, 10, RuntimePhase::Starting)));
    BOOST_TEST(!publisher.Publish(MakeSnapshot(1, 20, RuntimePhase::Connected)));
    BOOST_TEST(!publisher.Publish(MakeSnapshot(2, 10, RuntimePhase::Connected)));
    BOOST_TEST(!publisher.Publish(MakeSnapshot(2, 9, RuntimePhase::Connected)));
    BOOST_TEST(publisher.Publish(MakeSnapshot(2, 11, RuntimePhase::Connected)));

    const RuntimeSnapshot latest = publisher.GetLatest();
    BOOST_TEST(latest.generation == 2u);
    BOOST_TEST(latest.monotonic_ms == 11u);
    BOOST_TEST(static_cast<int>(latest.phase) == static_cast<int>(RuntimePhase::Connected));
}

BOOST_AUTO_TEST_CASE(callbacks_run_outside_lock_and_exceptions_are_isolated) {
    RuntimeSnapshotPublisher publisher;
    int healthy_calls = 0;
    std::uint64_t reentrant_token = 0;

    publisher.Subscribe([](const RuntimeSnapshot&) { throw 42; });
    publisher.Subscribe([&](const RuntimeSnapshot&) noexcept { ++healthy_calls; });
    reentrant_token = publisher.Subscribe([&](const RuntimeSnapshot& snapshot) noexcept {
        publisher.Unsubscribe(reentrant_token);
        if (snapshot.phase == RuntimePhase::Starting) {
            publisher.Publish(MakeSnapshot(1, 2, RuntimePhase::Connecting));
        }
    });

    BOOST_TEST(publisher.Publish(MakeSnapshot(1, 1, RuntimePhase::Starting)));
    BOOST_TEST(healthy_calls == 2);
    BOOST_TEST(static_cast<int>(publisher.GetLatest().phase) ==
               static_cast<int>(RuntimePhase::Connecting));
}

BOOST_AUTO_TEST_CASE(unsubscribe_prevents_future_notifications) {
    RuntimeSnapshotPublisher publisher;
    int calls = 0;
    const std::uint64_t token = publisher.Subscribe(
        [&](const RuntimeSnapshot&) noexcept { ++calls; });

    BOOST_TEST(token != 0u);
    BOOST_TEST(publisher.Publish(MakeSnapshot(1, 1, RuntimePhase::Starting)));
    publisher.Unsubscribe(token);
    BOOST_TEST(publisher.Publish(MakeSnapshot(1, 2, RuntimePhase::Connecting)));
    BOOST_TEST(calls == 1);
}
