#define BOOST_TEST_MODULE yield_context_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/coroutines/YieldContext.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;

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
 * threads the posted Resume() routinely executes while the coroutine is still
 * running (STATUS_RESUMED) or is in the middle of the suspend handoff
 * (STATUS_SUSPENDING).  The old CAS protocol dropped such wakeups and the
 * coroutine parked forever; the latch protocol must consume them instead.
 *
 * Every iteration posts exactly one Resume() and suspends exactly once, so the
 * coroutine can only finish all iterations if no wakeup was dropped.  A dropped
 * wakeup therefore shows up as a timeout, not a spurious pass.
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
            [&done, &failures](ppp::coroutines::YieldContext& y) noexcept {
                ppp::coroutines::YieldContext* py = &y;
                boost::asio::io_context& ctx = y.GetContext();
                for (int k = 0; k < kIterations; ++k) {
                    boost::asio::post(ctx, [py]() noexcept { py->Resume(); });
                    if (!y.Suspend()) {
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
 * Deterministic variant: the Resume() is guaranteed to execute while the
 * coroutine is still running (before Suspend() is reached).  The wakeup must be
 * latched and the subsequent Suspend() must return immediately without parking.
 */
BOOST_AUTO_TEST_CASE(early_wakeup_is_latched_not_dropped) {
    Runner runner;
    runner.Start(2);

    std::atomic<ppp::coroutines::YieldContext*> py{nullptr};
    std::atomic<bool> resume_executed{false};
    std::atomic<int> result{0};

    const bool spawned = ppp::coroutines::YieldContext::Spawn(runner.context,
        [&](ppp::coroutines::YieldContext& y) noexcept {
            py.store(&y);
            boost::asio::post(y.GetContext(), [&]() noexcept {
                // Runs on the second worker while this coroutine occupies the first.
                py.load()->Resume();
                resume_executed.store(true);
            });
            // Guarantee the Resume() lands before Suspend() is reached.
            while (!resume_executed.load()) {
                std::this_thread::yield();
            }
            // The latched wakeup must make this suspend return without parking.
            const bool ok = y.Suspend();
            result.store(ok ? 1 : -1);
        });
    BOOST_REQUIRE(spawned);

    BOOST_REQUIRE_MESSAGE(
        WaitFor([&] { return result.load() != 0; }, 30s),
        "coroutine hung: early wakeup was dropped instead of latched");
    BOOST_TEST(result.load() == 1);
}

/**
 * Basic sanity: a parked coroutine is resumed through the public R() path, which
 * may be invoked from a thread that does not run the io_context.
 */
BOOST_AUTO_TEST_CASE(suspend_then_resume_via_R) {
    Runner runner;
    runner.Start(1);

    std::atomic<ppp::coroutines::YieldContext*> py{nullptr};
    std::atomic<int> phase{0};

    const bool spawned = ppp::coroutines::YieldContext::Spawn(runner.context,
        [&](ppp::coroutines::YieldContext& y) noexcept {
            py.store(&y);
            phase.store(1);
            const bool ok = y.Suspend();
            phase.store(ok ? 2 : -1);
        });
    BOOST_REQUIRE(spawned);

    BOOST_REQUIRE(WaitFor([&] { return phase.load() == 1; }, 5s));
    BOOST_TEST(py.load()->R());
    BOOST_REQUIRE_MESSAGE(WaitFor([&] { return phase.load() == 2; }, 5s),
        "coroutine did not resume after R()");
}
