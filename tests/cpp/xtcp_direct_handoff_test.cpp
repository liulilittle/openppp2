// Focused tests for the production direct-upload queue
// (ppp/app/protocol/XtcpDirectUploadQueue.h) in both deque (default) and
// opt-in SPSC modes, using the real XtcpUploadBudget.

#include <ppp/app/protocol/XtcpDirectUploadQueue.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

namespace {

using ppp::app::protocol::XtcpDirectResult;
using ppp::app::protocol::XtcpDirectUploadQueue;
using ppp::app::protocol::XtcpUploadBudget;
using Mode = XtcpDirectUploadQueue::Mode;

int failures = 0;

#define CHECK(condition)                                                          \
    do {                                                                          \
        if (!(condition)) {                                                       \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            ++failures;                                                           \
        }                                                                         \
    } while (0)

const char* Name(Mode mode) noexcept { return mode == Mode::Spsc ? "spsc" : "deque"; }

std::shared_ptr<XtcpUploadBudget> MakeBudget() {
    return std::make_shared<XtcpUploadBudget>(std::uint64_t{1} << 40, std::size_t{1} << 24);
}

bool BudgetIdle(const std::shared_ptr<XtcpUploadBudget>& budget) noexcept {
    const XtcpUploadBudget::State state = budget->Snapshot();
    return state.bytes == 0 && state.items == 0;
}

XtcpDirectResult PushBytes(XtcpDirectUploadQueue& queue, const std::shared_ptr<XtcpUploadBudget>& budget,
    const std::vector<std::uint8_t>& bytes, bool* raised = nullptr) {
    auto credit = budget->TryReserve(bytes.size());
    const auto outcome = queue.Push(bytes.data(), bytes.size(), std::move(credit));
    if (raised) *raised = outcome.backpressure_raised;
    return outcome.result;
}

// Drains one write unit and releases it like RunDirectUpload does.
bool DrainOne(XtcpDirectUploadQueue& queue, std::size_t gather_limit, std::vector<std::uint8_t>& sink,
    bool* resumed = nullptr) {
    XtcpDirectUploadQueue::ChunkPtr payload;
    std::size_t items = 0;
    if (!queue.DrainGather(gather_limit, payload, items)) return false;
    sink.insert(sink.end(), payload->bytes.begin(), payload->bytes.end());
    std::size_t completed_bytes = 0, completed_items = 0;
    const bool resume = queue.Release(payload->bytes.size(), items, true, completed_bytes, completed_items);
    if (resumed) *resumed = resume;
    payload.reset();
    return true;
}

void FifoAndByteIntegrity(Mode mode) {
    auto budget = MakeBudget();
    {
        XtcpDirectUploadQueue queue(mode);
        CHECK(queue.Open());
        std::mt19937 rng(1234);
        std::uniform_int_distribution<int> len(1, 3000);
        std::vector<std::uint8_t> expected, actual;
        std::uint8_t next = 0;
        for (int i = 0; i < 10000; ++i) {
            std::vector<std::uint8_t> chunk(static_cast<std::size_t>(len(rng)));
            for (auto& b : chunk) b = next++;
            expected.insert(expected.end(), chunk.begin(), chunk.end());
            CHECK(PushBytes(queue, budget, chunk) == XtcpDirectResult::Accepted);
            if (i % 7 == 6) {
                while (DrainOne(queue, (i % 2) ? 1 : 65536, actual)) {}
            }
        }
        while (DrainOne(queue, 65536, actual)) {}
        CHECK(actual == expected);
        CHECK(queue.Bytes() == 0 && queue.Items() == 0);
        CHECK(queue.Empty());
    }
    CHECK(BudgetIdle(budget));
}

void ItemAndByteCapBackpressure(Mode mode) {
    auto budget = MakeBudget();
    {
        XtcpDirectUploadQueue queue(mode);
        CHECK(queue.Open());
        const std::vector<std::uint8_t> one(1, 7);
        for (std::size_t i = 0; i < XtcpDirectUploadQueue::kMaxItems; ++i) {
            CHECK(PushBytes(queue, budget, one) == XtcpDirectResult::Accepted);
        }
        auto credit = budget->TryReserve(1);
        auto outcome = queue.Push(one.data(), 1, std::move(credit));
        CHECK(outcome.result == XtcpDirectResult::Backpressured);
        CHECK(outcome.backpressure_raised);
        CHECK(static_cast<bool>(credit)); // rejected before the credit was consumed
        outcome = queue.Push(one.data(), 1, std::move(credit));
        CHECK(outcome.result == XtcpDirectResult::Backpressured);
        CHECK(!outcome.backpressure_raised); // raised only once per episode
        credit.Reset();
        int resumes = 0;
        std::vector<std::uint8_t> sink;
        bool resumed = false;
        while (DrainOne(queue, 1, sink, &resumed)) resumes += resumed ? 1 : 0;
        CHECK(resumes == 1);
        CHECK(!queue.Backpressured());
    }
    CHECK(BudgetIdle(budget));
    {
        XtcpDirectUploadQueue queue(mode);
        CHECK(queue.Open());
        const std::vector<std::uint8_t> mib(1024 * 1024, 3);
        for (int i = 0; i < 32; ++i) CHECK(PushBytes(queue, budget, mib) == XtcpDirectResult::Accepted);
        bool raised = false;
        CHECK(PushBytes(queue, budget, mib, &raised) == XtcpDirectResult::Backpressured);
        CHECK(raised);
        std::vector<std::uint8_t> sink;
        int resumes = 0;
        bool resumed = false;
        while (DrainOne(queue, 1, sink, &resumed)) resumes += resumed ? 1 : 0;
        CHECK(resumes == 1);
        CHECK(sink.size() == 32u * mib.size());
    }
    CHECK(BudgetIdle(budget));
}

void CreditReleaseOrdering(Mode mode) {
    for (int order = 0; order < 2; ++order) {
        auto budget = MakeBudget();
        XtcpDirectUploadQueue queue(mode);
        CHECK(queue.Open());
        const std::vector<std::uint8_t> bytes(100, 1);
        CHECK(PushBytes(queue, budget, bytes) == XtcpDirectResult::Accepted);
        XtcpDirectUploadQueue::ChunkPtr payload;
        std::size_t items = 0;
        CHECK(queue.DrainGather(1, payload, items));
        std::size_t cb = 0, ci = 0;
        if (order == 0) {
            payload.reset();                // credit returned before accounting
            CHECK(BudgetIdle(budget));
            (void)queue.Release(100, items, true, cb, ci);
        }
        else {
            (void)queue.Release(100, items, true, cb, ci);
            CHECK(!BudgetIdle(budget));     // credit held until the write unit drops
            payload.reset();
        }
        CHECK(cb == 100 && ci == 1);
        CHECK(BudgetIdle(budget));
        CHECK(queue.Bytes() == 0 && queue.Items() == 0);
    }
}

void CloseWithFullRing(Mode mode) {
    auto budget = MakeBudget();
    {
        XtcpDirectUploadQueue queue(mode);
        CHECK(queue.Open());
        const std::vector<std::uint8_t> one(10, 9);
        for (std::size_t i = 0; i < XtcpDirectUploadQueue::kMaxItems; ++i) {
            CHECK(PushBytes(queue, budget, one) == XtcpDirectResult::Accepted);
        }
        queue.RequestClose();
        if (mode == Mode::Spsc) {
            CHECK(PushBytes(queue, budget, one) == XtcpDirectResult::Closed);
        }
        std::vector<std::uint8_t> sink;
        for (int i = 0; i < 10; ++i) CHECK(DrainOne(queue, 1, sink)); // close keeps queued data
        queue.Abort();
        if (mode == Mode::Spsc) {
            CHECK(PushBytes(queue, budget, one) == XtcpDirectResult::Closed);
            CHECK(!queue.Open()); // a closed ring is never reopened
        }
        std::size_t ab = 0, ai = 0;
        (void)queue.Clear(ab, ai);
        CHECK(ai == XtcpDirectUploadQueue::kMaxItems - 10);
        CHECK(queue.Bytes() == 0 && queue.Items() == 0);
    }
    CHECK(BudgetIdle(budget));
}

void StaleEpochAfterRestart(Mode mode) {
    auto budget = MakeBudget();
    auto old_queue = std::make_unique<XtcpDirectUploadQueue>(mode);
    CHECK(old_queue->Open());
    const std::vector<std::uint8_t> bytes(64, 5);
    for (int i = 0; i < 8; ++i) CHECK(PushBytes(*old_queue, budget, bytes) == XtcpDirectResult::Accepted);
    old_queue->Abort();
    XtcpDirectUploadQueue fresh(mode);
    CHECK(fresh.Open());
    CHECK(PushBytes(fresh, budget, bytes) == XtcpDirectResult::Accepted);
    old_queue.reset(); // stale chunks die after the new bridge started
    CHECK(fresh.Bytes() == 64 && fresh.Items() == 1);
    const auto state = budget->Snapshot();
    CHECK(state.bytes == 64 && state.items == 1);
    std::vector<std::uint8_t> sink;
    CHECK(DrainOne(fresh, 1, sink));
    CHECK(BudgetIdle(budget));
}

void AllocationFailureFallsBack() {
    auto& counters = XtcpDirectUploadQueue::Global();
    const auto before = counters.alloc_fallback.load();
    counters.fail_next_open.store(true);
    XtcpDirectUploadQueue queue(Mode::Spsc);
    CHECK(!queue.Open());
    CHECK(counters.alloc_fallback.load() == before + 1);
    auto budget = MakeBudget();
    const std::vector<std::uint8_t> bytes(8, 1);
    CHECK(PushBytes(queue, budget, bytes) == XtcpDirectResult::Closed);
    CHECK(BudgetIdle(budget));
    XtcpDirectUploadQueue deque(Mode::Deque);
    counters.fail_next_open.store(true);
    CHECK(deque.Open()); // deque mode never allocates a ring
    counters.fail_next_open.store(false);
}

// Models VirtualEthernetTcpipConnection: producer pushes (lock-free in SPSC
// mode) and starts the writer once per batch under the control lock; the
// writer drains under that lock and parks when empty. Asserts every byte is
// consumed in order, at most one writer exists, and no lost wake-up occurs.
void TwoThreadStress(Mode mode, std::size_t total) {
    auto budget = MakeBudget();
    XtcpDirectUploadQueue queue(mode);
    CHECK(queue.Open());
    std::mutex control;
    std::condition_variable cv;
    bool writer_started = false;
    int writer_owners = 0;
    bool duplicate_writer = false;
    std::size_t wakes = 0;
    std::size_t consumed = 0;
    std::uint32_t expected_next = 0;
    bool order_ok = true;
    std::atomic<bool> done{false};

    std::thread writer([&]() {
        std::unique_lock<std::mutex> lock(control);
        while (!done.load() || writer_started) {
            cv.wait_for(lock, std::chrono::milliseconds(50), [&] { return writer_started || done.load(); });
            if (!writer_started) continue;
            if (++writer_owners > 1) duplicate_writer = true;
            for (;;) {
                if (queue.Empty()) {
                    writer_started = false; // park; producer restarts on next batch
                    break;
                }
                XtcpDirectUploadQueue::ChunkPtr payload;
                std::size_t items = 0;
                (void)queue.DrainGather(4096, payload, items);
                for (std::size_t off = 0; off + 4 <= payload->bytes.size(); off += 4) {
                    std::uint32_t value = 0;
                    for (int b = 0; b < 4; ++b) value |= std::uint32_t(payload->bytes[off + b]) << (8 * b);
                    if (value != expected_next++) order_ok = false;
                }
                std::size_t cb = 0, ci = 0;
                (void)queue.Release(payload->bytes.size(), items, true, cb, ci);
                consumed += ci;
                payload.reset();
                lock.unlock();
                lock.lock();
            }
            --writer_owners;
        }
    });

    std::uint32_t value = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
    std::size_t pushed = 0;
    std::size_t batches = 0;
    while (pushed < total && std::chrono::steady_clock::now() < deadline) {
        std::size_t batch = 0;
        for (; batch < 32 && pushed < total; ++batch) {
            std::uint8_t bytes[4];
            for (int b = 0; b < 4; ++b) bytes[b] = static_cast<std::uint8_t>(value >> (8 * b));
            auto credit = budget->TryReserve(4);
            XtcpDirectResult result;
            if (mode == Mode::Deque) {
                std::lock_guard<std::mutex> lock(control);
                result = queue.Push(bytes, 4, std::move(credit)).result;
            }
            else {
                result = queue.Push(bytes, 4, std::move(credit)).result;
            }
            if (result != XtcpDirectResult::Accepted) break; // backpressured: flush and retry
            ++value;
            ++pushed;
        }
        ++batches;
        std::lock_guard<std::mutex> lock(control); // FlushDirectPeerSend
        if (queue.HasPending() && !writer_started) {
            writer_started = true;
            ++wakes;
            cv.notify_one();
        }
    }
    done.store(true);
    {
        std::lock_guard<std::mutex> lock(control);
        if (queue.HasPending() && !writer_started) {
            writer_started = true;
            cv.notify_one();
        }
    }
    writer.join();
    CHECK(pushed == total);
    CHECK(consumed == total);
    CHECK(order_ok);
    CHECK(!duplicate_writer);
    CHECK(wakes <= batches); // at most one writer start per batch
    CHECK(queue.Bytes() == 0 && queue.Items() == 0);
    CHECK(BudgetIdle(budget));
}

} // namespace

int main(int argc, char** argv) {
    const std::size_t stress = argc > 1 ? static_cast<std::size_t>(std::strtoull(argv[1], nullptr, 10)) : 1000000;
    for (Mode mode : {Mode::Deque, Mode::Spsc}) {
        const int before = failures;
        FifoAndByteIntegrity(mode);
        ItemAndByteCapBackpressure(mode);
        CreditReleaseOrdering(mode);
        CloseWithFullRing(mode);
        StaleEpochAfterRestart(mode);
        TwoThreadStress(mode, stress);
        std::printf("mode %s: %s\n", Name(mode), failures == before ? "ok" : "FAILED");
    }
    AllocationFailureFallsBack();
    if (failures != 0) {
        std::fprintf(stderr, "xtcp_direct_handoff_test: %d failure(s)\n", failures);
        return 1;
    }
    std::puts("xtcp_direct_handoff_test: passed");
    return 0;
}
