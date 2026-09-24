#define BOOST_TEST_MODULE spinlock_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/threading/SpinLock.h>

#include <atomic>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {

using ppp::threading::RecursiveSpinLock;
using ppp::threading::SpinLock;

}  // namespace

BOOST_AUTO_TEST_CASE(recursive_enter_leave_single_thread) {
    RecursiveSpinLock lock;
    BOOST_TEST(!lock.IsLockTaken());

    lock.Enter();
    lock.Enter();
    lock.Enter();
    BOOST_TEST(lock.IsLockTaken());

    // Recursive TryEnter from the owning thread must succeed.
    BOOST_TEST(lock.TryEnter());

    lock.Leave();
    lock.Leave();
    BOOST_TEST(lock.IsLockTaken());
    lock.Leave();
    lock.Leave();
    BOOST_TEST(!lock.IsLockTaken());
}

BOOST_AUTO_TEST_CASE(tryenter_fails_while_other_thread_owns) {
    RecursiveSpinLock lock;
    lock.Enter();

    std::atomic<int> probe{0};
    std::thread worker([&]() noexcept {
        // Non-recursive TryEnter must fail while the main thread owns the lock.
        if (!lock.TryEnter()) {
            probe.store(1);
        }
    });
    worker.join();
    BOOST_TEST(probe.load() == 1);

    lock.Leave();

    std::atomic<int> acquired{0};
    std::thread worker2([&]() noexcept {
        if (lock.TryEnter()) {
            acquired.store(1);
            lock.Leave();
        }
    });
    worker2.join();
    BOOST_TEST(acquired.load() == 1);
    BOOST_TEST(!lock.IsLockTaken());
}

BOOST_AUTO_TEST_CASE(unmatched_leave_throws) {
    RecursiveSpinLock lock;
    // Leave() by a thread that does not own the lock is a contract violation
    // and must fail loudly instead of corrupting the recursion counter.
    BOOST_CHECK_THROW(lock.Leave(), std::runtime_error);

    lock.Enter();
    std::atomic<bool> threw{false};
    std::thread worker([&]() noexcept {
        try {
            lock.Leave();
        } catch (const std::runtime_error&) {
            threw.store(true);
        }
    });
    worker.join();
    BOOST_TEST(threw.load());
    BOOST_TEST(lock.IsLockTaken());
    lock.Leave();
}

/**
 * Regression for the lost-underlying-lock interleaving: the old implementation
 * let a non-owner thread bump the recursion counter before the ownership check,
 * which made the owner skip releasing the underlying SpinLock — every later
 * Enter() spun forever.  The rewrite keeps owner check and counter update in
 * one critical section; this stress test must neither hang (ctest TIMEOUT is
 * the watchdog) nor lose mutual exclusion (final count must be exact).
 */
BOOST_AUTO_TEST_CASE(contention_stress_no_lost_lock_no_race) {
    RecursiveSpinLock lock;
    constexpr int kThreads = 8;
    constexpr int kIterations = 20000;

    int64_t counter = 0;
    std::atomic<int> ready{0};
    std::atomic<bool> go{false};

    std::vector<std::thread> threads;
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&]() noexcept {
            ready.fetch_add(1);
            while (!go.load()) {
                std::this_thread::yield();
            }
            for (int k = 0; k < kIterations; ++k) {
                lock.Enter();
                ++counter;
                lock.Enter();  // recursive re-entry inside the critical section
                ++counter;
                lock.Leave();
                lock.Leave();
            }
        });
    }

    while (ready.load() != kThreads) {
        std::this_thread::yield();
    }
    go.store(true);
    for (std::thread& t : threads) {
        t.join();
    }

    BOOST_TEST(counter == 2LL * kThreads * kIterations);
    BOOST_TEST(!lock.IsLockTaken());
}

BOOST_AUTO_TEST_CASE(plain_spinlock_mutual_exclusion) {
    SpinLock lock;
    constexpr int kThreads = 8;
    constexpr int kIterations = 20000;

    int64_t counter = 0;
    std::vector<std::thread> threads;
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&]() noexcept {
            for (int k = 0; k < kIterations; ++k) {
                lock.Enter();
                ++counter;
                lock.Leave();
            }
        });
    }
    for (std::thread& t : threads) {
        t.join();
    }

    BOOST_TEST(counter == static_cast<int64_t>(kThreads) * kIterations);
}
