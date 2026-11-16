#define BOOST_TEST_MODULE yield_context_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/coroutines/YieldContext.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;
using Anchor = ppp::coroutines::YieldContext::Anchor;

/**
 * @brief Runs an io_context on N worker threads with a work guard, mirroring the
 *        production multi-runner configuration that exposed the lost-wakeup defect.
 */
struct Runner {
    boost::asio::io_context context;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> guard;
    std::vector<std::thread> threads;

    Runner() : guard(boost::asio::make_work_guard(context)) {}
    ~Runner() { Stop(); }

    void Start(int count) {
        for (int i = 0; i < count; ++i) {
            threads.emplace_back([this]() noexcept { context.run(); });
        }
    }

    void Stop() noexcept {
        guard.reset();
        context.stop();
        for (std::thread& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }
        threads.clear();
    }
};

/** @brief Thread-safe slot for handing an armed anchor from the coroutine to the test thread. */
struct AnchorSlot {
    std::mutex mutex;
    Anchor anchor;

    void Set(const Anchor& value) {
        std::lock_guard<std::mutex> lock(mutex);
        anchor = value;
    }

    Anchor Get() {
        std::lock_guard<std::mutex> lock(mutex);
        return anchor;
    }
};

bool WaitFor(const std::function<bool()>& pred, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(1ms);
    }
    return pred();
}

}  // namespace

/**
 * A wakeup posted right before Suspend() must never be lost: with several run()
 * threads the posted wakeup routinely executes while the coroutine is still
 * running (STATUS_RESUMED) or is in the middle of the suspend handoff
 * (STATUS_SUSPENDING).  It must be latched for its anchor and consumed by the
 * matching Suspend().
 *
 * Every iteration arms one anchor, posts exactly one wakeup and suspends exactly
 * once, so the coroutine can only finish all iterations if no wakeup was dropped.
 * A dropped wakeup therefore shows up as a timeout, not a spurious pass.
 */
BOOST_AUTO_TEST_CASE(completion_before_suspend_multi_runner) {
    Runner runner;
    runner.Start(4);

    constexpr int kCoroutines = 8;
    constexpr int kIterations = 300;
    std::atomic<int> done{0};
    std::atomic<int> failures{0};

    for (int i = 0; i < kCoroutines; ++i) {
        const bool spawned = ppp::coroutines::YieldContext::Spawn(runner.context,
            [&done, &failures, kIterations](ppp::coroutines::YieldContext& y) noexcept {
                boost::asio::io_context& ctx = y.GetContext();
                for (int k = 0; k < kIterations; ++k) {
                    const Anchor anchor = y.Arm();
                    boost::asio::post(ctx, [anchor]() noexcept { anchor.R(); });
                    if (!y.Suspend(anchor)) {
                        failures.fetch_add(1);
                        return;
                    }
                }
                done.fetch_add(1);
            });
        BOOST_REQUIRE(spawned);
    }

    BOOST_REQUIRE_MESSAGE(
        WaitFor([&] { return done.load() == kCoroutines; }, 60s),
        "coroutines hung: done=" << done.load() << "/" << kCoroutines
                                 << " failures=" << failures.load());
    BOOST_TEST(failures.load() == 0);
}

/**
 * Deterministic variant: the wakeup is delivered while the coroutine is still
 * running (before Suspend() is reached).  It must be latched for the armed anchor
 * and the subsequent Suspend() must return immediately without parking; a dropped
 * wakeup would park the coroutine forever and time out.
 */
BOOST_AUTO_TEST_CASE(early_wakeup_is_latched_not_dropped) {
    Runner runner;
    runner.Start(2);

    std::atomic<int> result{0};

    const bool spawned = ppp::coroutines::YieldContext::Spawn(runner.context,
        [&](ppp::coroutines::YieldContext& y) noexcept {
            const Anchor anchor = y.Arm();
            const bool won = anchor.R();
            // The resume runs on the second worker while this coroutine still
            // occupies the first, so it is latched rather than delivered.
            std::this_thread::sleep_for(200ms);
            const bool ok = won && y.Suspend(anchor);
            result.store(ok ? 1 : -1);
        });
    BOOST_REQUIRE(spawned);

    BOOST_REQUIRE_MESSAGE(
        WaitFor([&] { return result.load() != 0; }, 30s),
        "coroutine hung: early wakeup was dropped instead of latched");
    BOOST_TEST(result.load() == 1);
}

/**
 * Basic sanity: a parked coroutine is resumed through Anchor::R(), which may be
 * invoked from a thread that does not run the io_context.
 */
BOOST_AUTO_TEST_CASE(suspend_then_resume_via_R) {
    Runner runner;
    runner.Start(1);

    AnchorSlot slot;
    std::atomic<int> phase{0};

    const bool spawned = ppp::coroutines::YieldContext::Spawn(runner.context,
        [&](ppp::coroutines::YieldContext& y) noexcept {
            const Anchor anchor = y.Arm();
            slot.Set(anchor);
            phase.store(1);
            const bool ok = y.Suspend(anchor);
            phase.store(ok ? 2 : -1);
        });
    BOOST_REQUIRE(spawned);

    BOOST_REQUIRE(WaitFor([&] { return phase.load() == 1; }, 5s));
    BOOST_TEST(slot.Get().R());
    BOOST_REQUIRE_MESSAGE(WaitFor([&] { return phase.load() == 2; }, 5s),
        "coroutine did not resume after R()");
}

/**
 * Two wakeup sources for one suspension (I/O completion racing a timeout): only
 * the first may resume.  The loser must not leak into the NEXT suspension - the
 * latent defect of the unanchored latch, which let a stale wakeup end an
 * unrelated wait while that wait's operation still referenced the stack.
 */
BOOST_AUTO_TEST_CASE(duplicate_wakeup_cannot_leak_into_next_suspend) {
    Runner runner;
    runner.Start(2);

    AnchorSlot first;
    AnchorSlot second;
    std::atomic<int> phase{0};

    const bool spawned = ppp::coroutines::YieldContext::Spawn(runner.context,
        [&](ppp::coroutines::YieldContext& y) noexcept {
            const Anchor a1 = y.Arm();
            first.Set(a1);
            phase.store(1);
            if (!y.Suspend(a1)) {
                phase.store(-1);
                return;
            }

            const Anchor a2 = y.Arm();
            second.Set(a2);
            phase.store(2);
            phase.store(y.Suspend(a2) ? 3 : -2);
        });
    BOOST_REQUIRE(spawned);

    BOOST_REQUIRE(WaitFor([&] { return phase.load() == 1; }, 5s));
    const Anchor a1 = first.Get();
    BOOST_TEST(a1.R());                  // wins
    BOOST_REQUIRE(WaitFor([&] { return phase.load() == 2; }, 5s));
    BOOST_TEST(!a1.R());                 // late duplicate: CAS fails, dropped

    // The coroutine must still be parked on a2; nothing may have woken it.
    std::this_thread::sleep_for(100ms);
    BOOST_TEST(phase.load() == 2);

    BOOST_TEST(second.Get().R());
    BOOST_REQUIRE(WaitFor([&] { return phase.load() == 3; }, 5s));
}

/**
 * An anchor abandoned without suspending (its operation failed to start) is
 * superseded by the next Arm(); it can neither park the coroutine nor resume the
 * new wait.
 */
BOOST_AUTO_TEST_CASE(rearm_invalidates_abandoned_anchor) {
    Runner runner;
    runner.Start(1);

    AnchorSlot stale;
    AnchorSlot current;
    std::atomic<int> phase{0};
    std::atomic<bool> stale_suspend_rejected{false};

    const bool spawned = ppp::coroutines::YieldContext::Spawn(runner.context,
        [&](ppp::coroutines::YieldContext& y) noexcept {
            const Anchor abandoned = y.Arm();
            stale.Set(abandoned);
            const Anchor anchor = y.Arm();
            current.Set(anchor);
            stale_suspend_rejected.store(!y.Suspend(abandoned));
            phase.store(1);
            phase.store(y.Suspend(anchor) ? 2 : -1);
        });
    BOOST_REQUIRE(spawned);

    BOOST_REQUIRE(WaitFor([&] { return phase.load() == 1; }, 5s));
    BOOST_TEST(stale_suspend_rejected.load());
    BOOST_TEST(!stale.Get().R());
    std::this_thread::sleep_for(100ms);
    BOOST_TEST(phase.load() == 1);

    BOOST_TEST(current.Get().R());
    BOOST_REQUIRE(WaitFor([&] { return phase.load() == 2; }, 5s));
}

/**
 * Anchors are strictly increasing per coroutine, and copies of one anchor share
 * a single credential: exactly one of them can wake the coroutine.
 */
BOOST_AUTO_TEST_CASE(anchors_are_monotonic_and_single_use) {
    Runner runner;
    runner.Start(1);

    std::atomic<int> phase{0};
    std::atomic<uint64_t> v1{0};
    std::atomic<uint64_t> v2{0};
    AnchorSlot slot;

    const bool spawned = ppp::coroutines::YieldContext::Spawn(runner.context,
        [&](ppp::coroutines::YieldContext& y) noexcept {
            const Anchor a1 = y.Arm();
            const Anchor a2 = y.Arm();
            v1.store(a1.Value());
            v2.store(a2.Value());
            slot.Set(a2);
            phase.store(1);
            phase.store(y.Suspend(a2) ? 2 : -1);
        });
    BOOST_REQUIRE(spawned);

    BOOST_REQUIRE(WaitFor([&] { return phase.load() == 1; }, 5s));
    BOOST_TEST(v1.load() > 0u);
    BOOST_TEST(v2.load() > v1.load());

    const Anchor a = slot.Get();
    const Anchor b = a;
    BOOST_TEST(b.R());
    BOOST_TEST(!a.R());
    BOOST_REQUIRE(WaitFor([&] { return phase.load() == 2; }, 5s));
}

/**
 * A wakeup arriving after the coroutine finished (e.g. a timer outliving the
 * operation it guarded) must be a harmless no-op: the CAS runs on the shared
 * anchor cell, never on the reclaimed coroutine.  Run under ASan/TSan to catch
 * any use-after-free.
 */
BOOST_AUTO_TEST_CASE(wakeup_after_completion_is_harmless) {
    Runner runner;
    runner.Start(1);

    AnchorSlot leftover;
    std::atomic<bool> finished{false};

    const bool spawned = ppp::coroutines::YieldContext::Spawn(runner.context,
        [&](ppp::coroutines::YieldContext& y) noexcept {
            leftover.Set(y.Arm());               // armed, then abandoned by returning
            finished.store(true);
        });
    BOOST_REQUIRE(spawned);

    BOOST_REQUIRE(WaitFor([&] { return finished.load(); }, 5s));
    std::this_thread::sleep_for(50ms);           // let the context be reclaimed
    BOOST_TEST(!leftover.Get().R());
}

/**
 * Many coroutines with two racing wakeup sources per suspension on several
 * runners: every suspension is resumed exactly once and every coroutine finishes.
 */
BOOST_AUTO_TEST_CASE(racing_wakeup_sources_multi_runner) {
    Runner runner;
    runner.Start(4);

    constexpr int kCoroutines = 8;
    constexpr int kIterations = 300;
    std::atomic<int> done{0};
    std::atomic<int> failures{0};
    std::atomic<int> winners{0};

    for (int i = 0; i < kCoroutines; ++i) {
        const bool spawned = ppp::coroutines::YieldContext::Spawn(runner.context,
            [&](ppp::coroutines::YieldContext& y) noexcept {
                boost::asio::io_context& ctx = y.GetContext();
                for (int k = 0; k < kIterations; ++k) {
                    const Anchor anchor = y.Arm();
                    auto wake = [anchor, &winners]() noexcept {
                        if (anchor.R()) {
                            winners.fetch_add(1);
                        }
                    };
                    boost::asio::post(ctx, wake);
                    boost::asio::post(ctx, wake);
                    if (!y.Suspend(anchor)) {
                        failures.fetch_add(1);
                        return;
                    }
                }
                done.fetch_add(1);
            });
        BOOST_REQUIRE(spawned);
    }

    BOOST_REQUIRE_MESSAGE(
        WaitFor([&] { return done.load() == kCoroutines; }, 60s),
        "coroutines hung: done=" << done.load() << "/" << kCoroutines);
    BOOST_TEST(failures.load() == 0);
    std::this_thread::sleep_for(100ms);          // let straggling losers run
    BOOST_TEST(winners.load() == kCoroutines * kIterations);
}

BOOST_AUTO_TEST_CASE(randomized_anchor_resume_four_workers) {
    Runner runner;
    std::atomic<int> done{0}, failures{0};
    runner.Start(4);
    for (unsigned seed = 1; seed <= 8; ++seed) {
        BOOST_REQUIRE(ppp::coroutines::YieldContext::Spawn(runner.context,
            [&, seed](ppp::coroutines::YieldContext& y) {
                std::minstd_rand random(seed);
                Anchor previous;
                for (int k = 0; k < 500; ++k) {
                    auto anchor = y.Arm();
                    const unsigned delay = random() % 5;
                    boost::asio::post(y.GetContext(), [anchor, delay] {
                        for (unsigned n = 0; n < delay; ++n) std::this_thread::yield();
                        anchor.R();
                        anchor.R();
                    });
                    if (previous.R()) ++failures;
                    if ((random() & 1) != 0) std::this_thread::yield();
                    if (!y.Suspend(anchor)) { ++failures; return; }
                    previous = anchor;
                }
                ++done;
            }));
    }
    BOOST_REQUIRE(WaitFor([&] { return done.load() == 8; }, 60s));
    BOOST_TEST(failures.load() == 0);
    runner.Stop();
}
