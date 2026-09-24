#include "ppp/app/client/xtcp/XtcpUploadBudget.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace {
thread_local bool fail_next_allocation = false;
}

void* operator new(std::size_t bytes) {
    if (fail_next_allocation) {
        fail_next_allocation = false;
        throw std::bad_alloc();
    }
    if (void* result = std::malloc(bytes ? bytes : 1)) return result;
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value, std::size_t) noexcept { std::free(value); }

namespace {

std::atomic<int> g_checks{0};

void CheckImpl(bool condition, int line) {
    ++g_checks;
    if (!condition) {
        std::fprintf(stderr, "XtcpUploadBudget test failed at line %d\n", line);
        std::abort();
    }
}

#define Check(condition) CheckImpl((condition), __LINE__)

struct WakeCount {
    std::size_t count = 0;

    void operator()() {
        ++count;
    }
};

void TestBasicLimits() {
    auto budget = std::make_shared<ppp::app::client::xtcp::XtcpUploadBudget>(10, 1);

    auto oversized = budget->TryReserve(11);
    Check(!oversized);
    Check(budget->Snapshot().bytes == 0);
    Check(budget->Snapshot().items == 0);

    auto zero = budget->TryReserve(0);
    Check(!zero);

    auto first = budget->TryReserve(10);
    Check(static_cast<bool>(first));
    Check(first.Bytes() == 10);
    Check(first.Items() == 1);
    Check(budget->Snapshot().bytes == 10);
    Check(budget->Snapshot().items == 1);

    auto no_item_capacity = budget->TryReserve(1);
    Check(!no_item_capacity);
    Check(budget->Snapshot().bytes == 10);

    first.Reset();
    Check(!first);
    Check(budget->Snapshot().bytes == 0);
    Check(budget->Snapshot().items == 0);

    first = budget->TryReserve(1);
    Check(static_cast<bool>(first));
    Check(!budget->TryReserve(1)); // item limit binds despite free bytes
    first.Reset();
    Check(!first);
}

void TestHugeRequests() {
    constexpr std::uint64_t max_u64 = std::numeric_limits<std::uint64_t>::max();
    auto budget = std::make_shared<ppp::app::client::xtcp::XtcpUploadBudget>(max_u64 - 1, 10);
    Check(!budget->TryReserve(0));
    Check(!budget->TryReserve(max_u64));
    Check(!budget->AwaitCapacity(0));
    Check(!budget->AwaitCapacity(max_u64));
    Check(budget->Snapshot().bytes == 0);
    Check(budget->Snapshot().items == 0);

    auto empty_budget = std::make_shared<ppp::app::client::xtcp::XtcpUploadBudget>(0, 0);
    Check(!empty_budget->TryReserve(1));
    Check(!empty_budget->AwaitCapacity(0));
    Check(!empty_budget->AwaitCapacity(1));
}

void TestMoveAndReset() {
    auto budget = std::make_shared<ppp::app::client::xtcp::XtcpUploadBudget>(4, 1);
    auto source = budget->TryReserve(4);
    Check(static_cast<bool>(source));

    auto destination = std::move(source);
    Check(!source);
    Check(static_cast<bool>(destination));
    Check(destination.Bytes() == 4);
    Check(budget->Snapshot().bytes == 4);

    source = std::move(destination);
    Check(!destination);
    Check(static_cast<bool>(source));
    Check(source.Bytes() == 4);
    Check(budget->Snapshot().bytes == 4);

    source.Reset();
    source.Reset();
    Check(!source);
    Check(budget->Snapshot().bytes == 0);
    Check(budget->Snapshot().items == 0);
}

void TestMerge() {
    auto budget = std::make_shared<ppp::app::client::xtcp::XtcpUploadBudget>(10, 4);
    auto target = budget->TryReserve(3);
    auto source = budget->TryReserve(2);
    Check(static_cast<bool>(target) && static_cast<bool>(source));

    Check(!target.Merge(std::move(target)));
    Check(target.Bytes() == 3);

    Check(target.Merge(std::move(source)));
    Check(!source);
    Check(target.Bytes() == 5);
    Check(target.Items() == 2);
    Check(budget->Snapshot().bytes == 5);
    Check(budget->Snapshot().items == 2);

    auto other_budget = std::make_shared<ppp::app::client::xtcp::XtcpUploadBudget>(10, 4);
    auto foreign = other_budget->TryReserve(1);
    Check(static_cast<bool>(foreign));
    Check(!target.Merge(std::move(foreign)));
    Check(static_cast<bool>(foreign));
    Check(foreign.Bytes() == 1);
    Check(target.Bytes() == 5);
    Check(budget->Snapshot().bytes == 5);
    Check(other_budget->Snapshot().bytes == 1);

    auto empty_target = budget->TryReserve(4);
    Check(static_cast<bool>(empty_target));
    empty_target.Reset();
    Check(!empty_target);
    auto transfer_source = budget->TryReserve(1);
    Check(static_cast<bool>(transfer_source));
    Check(empty_target.Merge(std::move(transfer_source)));
    Check(static_cast<bool>(empty_target));
    Check(!transfer_source);
    Check(empty_target.Bytes() == 1);
    Check(budget->Snapshot().bytes == 6);
    Check(budget->Snapshot().items == 3);

    target.Reset();
    empty_target.Reset();
    foreign.Reset();
    Check(budget->Snapshot().bytes == 0);
    Check(budget->Snapshot().items == 0);
    Check(other_budget->Snapshot().bytes == 0);
}

class BlockingWake {
public:
    void operator()() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            notified_ = true;
        }
        condition_.notify_all();
    }

    void Wait() {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this] { return notified_; });
        notified_ = false;
    }

private:
    std::mutex mutex_;
    std::condition_variable condition_;
    bool notified_ = false;
};

void TestAwaitAndWakeup() {
    auto budget = std::make_shared<ppp::app::client::xtcp::XtcpUploadBudget>(4, 1);
    auto reservation = budget->TryReserve(4);
    Check(static_cast<bool>(reservation));
    Check(!budget->AwaitCapacity(1));
    Check(!budget->AwaitCapacity(5));

    reservation.Reset();
    Check(budget->Snapshot().bytes == 0);
    Check(budget->Snapshot().items == 0);

    reservation = budget->TryReserve(4);
    Check(static_cast<bool>(reservation));
    auto wake = std::make_shared<BlockingWake>();
    budget->SetWakeHandler([wake] { (*wake)(); });
    Check(!budget->AwaitCapacity(1));
    reservation.Reset();
    wake->Wait();

    auto replacement = budget->TryReserve(4);
    Check(static_cast<bool>(replacement));
    Check(!budget->AwaitCapacity(1));
    replacement.Reset();
    wake->Wait();
    Check(budget->Snapshot().bytes == 0);
}

void TestWakeCallbackCanUseBudget() {
    auto budget = std::make_shared<ppp::app::client::xtcp::XtcpUploadBudget>(4, 2);
    auto reservation = budget->TryReserve(4);
    Check(static_cast<bool>(reservation));

    bool called = false;
    budget->SetWakeHandler([&budget, &called] {
        called = true;
        const auto state = budget->Snapshot();
        Check(state.bytes == 0 && state.items == 0);
        auto callback_reservation = budget->TryReserve(1);
        Check(static_cast<bool>(callback_reservation));
        Check(budget->Snapshot().bytes == 1);
    });

    Check(!budget->AwaitCapacity(1));
    reservation.Reset();
    Check(called);
    Check(budget->Snapshot().bytes == 0);
    Check(budget->Snapshot().items == 0);
}

void TestHandlerReplacement() {
    auto budget = std::make_shared<ppp::app::client::xtcp::XtcpUploadBudget>(4, 1);
    auto reservation = budget->TryReserve(4);
    Check(static_cast<bool>(reservation));

    auto first_count = std::make_shared<std::size_t>(0);
    auto second_count = std::make_shared<std::size_t>(0);
    budget->SetWakeHandler([first_count] { ++*first_count; });
    Check(!budget->AwaitCapacity(1));
    budget->SetWakeHandler([second_count] { ++*second_count; });

    reservation.Reset();
    Check(*first_count == 0);
    Check(*second_count == 1);
    Check(budget->Snapshot().bytes == 0);
}

void TestTokenWaiterSkipsHeadThatDoesNotFit() {
    using ppp::app::client::xtcp::XtcpUploadBudget;

    auto budget = std::make_shared<XtcpUploadBudget>(10, 4);
    auto large_in_flight = budget->TryReserve(9);
    auto small_in_flight = budget->TryReserve(1);
    Check(static_cast<bool>(large_in_flight));
    Check(static_cast<bool>(small_in_flight));

    Check(!budget->TryReserveFor(1, 2));
    Check(!budget->AwaitCapacity(1, 2));
    Check(!budget->TryReserveFor(2, 1));
    Check(!budget->AwaitCapacity(2, 1));
    Check(budget->WaiterTokens() == (std::vector<XtcpUploadBudget::WaitToken>{1, 2}));

    // One byte is released. The oldest two-byte request still cannot fit,
    // but the next one-byte waiter can consume the partial credit.
    small_in_flight.Reset();
    auto wake_order = budget->WaiterTokens();
    XtcpUploadBudget::WaitToken selected = 0;
    for (const auto token : wake_order) {
        const std::uint64_t needed = token == 1 ? 2 : 1;
        if (budget->AwaitCapacity(token, needed)) {
            selected = token;
            break;
        }
    }
    Check(selected == 2);
    auto small_grant = budget->TryReserveFor(2, 1);
    Check(static_cast<bool>(small_grant));
    Check(small_grant.Bytes() == 1);

    large_in_flight.Reset();
    small_grant.Reset();
    Check(budget->AwaitCapacity(1, 2));
    auto large_grant = budget->TryReserveFor(1, 2);
    Check(static_cast<bool>(large_grant));
    Check(large_grant.Bytes() == 2);
    large_grant.Reset();
    Check(budget->Snapshot().bytes == 0);
    Check(budget->Snapshot().items == 0);
    Check(budget->WaiterTokens().empty());
}

void TestChunkLifetime() {
    using ppp::app::client::xtcp::XtcpUploadChunk;

    auto budget = std::make_shared<ppp::app::client::xtcp::XtcpUploadBudget>(8, 2);
    const std::uint8_t payload[] = {1, 2, 3};
    {
        XtcpUploadChunk chunk(payload, sizeof(payload), budget->TryReserve(sizeof(payload)));
        Check(chunk.bytes == (std::vector<std::uint8_t>{1, 2, 3}));
        Check(budget->Snapshot().bytes == 3);
        Check(budget->Snapshot().items == 1);
        XtcpUploadChunk moved_chunk(std::move(chunk));
        Check(moved_chunk.credit.Bytes() == 3);
        Check(moved_chunk.bytes.size() == 3);
        Check(budget->Snapshot().bytes == 3);
    }
    Check(budget->Snapshot().bytes == 0);
    Check(budget->Snapshot().items == 0);
}

void TestConcurrentReservation() {
    constexpr std::size_t thread_count = 8;
    constexpr std::size_t operations_per_thread = 250;
    auto budget = std::make_shared<ppp::app::client::xtcp::XtcpUploadBudget>(16, 4);

    std::atomic<std::size_t> wake_count{0};
    budget->SetWakeHandler([&wake_count] { ++wake_count; });
    auto full = budget->TryReserve(16);
    Check(static_cast<bool>(full));
    std::mutex start_mutex;
    std::condition_variable start_condition;
    std::size_t ready = 0;
    bool go = false;
    std::atomic<std::size_t> accepted{0};

    std::vector<std::thread> threads;
    threads.reserve(thread_count);
    for (std::size_t index = 0; index < thread_count; ++index) {
        threads.emplace_back([&, index] {
            Check(!budget->TryReserve(1)); // deterministically register waiters
            {
                std::unique_lock<std::mutex> lock(start_mutex);
                ++ready;
                start_condition.notify_all();
                start_condition.wait(lock, [&] { return go; });
            }
            for (std::size_t operation = 0; operation < operations_per_thread; ++operation) {
                auto reservation = budget->TryReserve(index + 1);
                if (reservation) ++accepted;
                const auto observed = budget->Snapshot();
                Check(observed.bytes <= 16);
                Check(observed.items <= 4);
                if (reservation) Check(observed.bytes >= reservation.Bytes());
                std::this_thread::yield();
            }
        });
    }

    {
        std::unique_lock<std::mutex> lock(start_mutex);
        start_condition.wait(lock, [&] { return ready == thread_count; });
    }
    full.Reset();
    {
        std::lock_guard<std::mutex> lock(start_mutex);
        go = true;
    }
    start_condition.notify_all();

    for (auto& thread : threads) {
        thread.join();
    }

    const auto state = budget->Snapshot();
    Check(state.bytes == 0);
    Check(state.items == 0);
    Check(wake_count.load() > 0);
    Check(accepted.load() > 0);
}

void TestChunkConstructorException() {
    using ppp::app::client::xtcp::XtcpUploadChunk;

    auto budget = std::make_shared<ppp::app::client::xtcp::XtcpUploadBudget>(32, 2);
    const std::uint8_t data[32] = {};
    auto reservation = budget->TryReserve(sizeof(data));
    Check(static_cast<bool>(reservation));
    bool threw = false;
    fail_next_allocation = true;
    try {
        XtcpUploadChunk chunk(data, sizeof(data), std::move(reservation));
    } catch (const std::bad_alloc&) {
        threw = true;
        Check(!reservation);
    }
    fail_next_allocation = false;
    Check(threw);
    Check(budget->Snapshot().bytes == 0);
    Check(budget->Snapshot().items == 0);
}

void TestSharedFlowQueues() {
    using ppp::app::client::xtcp::XtcpUploadChunk;

    auto budget = std::make_shared<ppp::app::client::xtcp::XtcpUploadBudget>(16, 2);
    const std::uint8_t payload[8] = {};

    std::vector<XtcpUploadChunk> waiting_flow;
    waiting_flow.emplace_back(payload, sizeof(payload), budget->TryReserve(sizeof(payload)));
    auto in_flight = std::make_unique<XtcpUploadChunk>(
        payload, sizeof(payload), budget->TryReserve(sizeof(payload)));
    Check(budget->Snapshot().bytes == 16);
    Check(budget->Snapshot().items == 2);

    waiting_flow.clear();
    Check(budget->Snapshot().bytes == 8);
    Check(budget->Snapshot().items == 1);

    in_flight.reset();
    Check(budget->Snapshot().bytes == 0);
    Check(budget->Snapshot().items == 0);
}

void TestGatherKeepsOriginalCredit() {
    using namespace ppp::app::client::xtcp;
    auto budget = std::make_shared<XtcpUploadBudget>(4, 2);
    const std::uint8_t a[] = {1, 2}, b[] = {3, 4};
    auto first = std::make_shared<XtcpUploadChunk>(a, 2, budget->TryReserve(2));
    auto second = std::make_shared<XtcpUploadChunk>(b, 2, budget->TryReserve(2));
    auto combined = std::make_shared<XtcpUploadChunk>();
    combined->bytes.insert(combined->bytes.end(), first->bytes.begin(), first->bytes.end());
    combined->bytes.insert(combined->bytes.end(), second->bytes.begin(), second->bytes.end());
    Check(combined->credit.Merge(std::move(first->credit)));
    Check(combined->credit.Merge(std::move(second->credit)));
    first.reset();
    second.reset();
    Check(budget->Snapshot().bytes == 4 && budget->Snapshot().items == 2);
    Check(!budget->TryReserve(1));
    Check(combined->bytes == (std::vector<std::uint8_t>{1, 2, 3, 4}));
    combined.reset();
    Check(budget->Snapshot().bytes == 0 && budget->Snapshot().items == 0);
}

} // namespace

int main() {
    TestBasicLimits();
    TestHugeRequests();
    TestMoveAndReset();
    TestMerge();
    TestAwaitAndWakeup();
    TestWakeCallbackCanUseBudget();
    TestHandlerReplacement();
    TestTokenWaiterSkipsHeadThatDoesNotFit();
    TestChunkLifetime();
    TestChunkConstructorException();
    TestSharedFlowQueues();
    TestGatherKeepsOriginalCredit();
    TestConcurrentReservation();

    std::printf("XtcpUploadBudget: %d checks passed\n", g_checks.load());
    return 0;
}
