#include <ppp/threading/SpscHandoff.h>

#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <functional>
#include <thread>
#include <vector>
#include <chrono>
#include <algorithm>
#include <array>

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "line %d: %s\n", __LINE__, #x); std::abort(); } } while (0)
using namespace ppp::threading;

struct Item {
    static std::atomic<int> live;
    std::unique_ptr<unsigned> value;
    Item() noexcept { ++live; }
    explicit Item(unsigned n) : value(new unsigned(n)) { ++live; }
    Item(Item&& other) noexcept : value(std::move(other.value)) { ++live; }
    Item& operator=(Item&& other) noexcept { value = std::move(other.value); return *this; }
    ~Item() noexcept { --live; }
};
std::atomic<int> Item::live{0};
using Queue = SpscHandoff<Item>;

void Storage() {
    for (std::size_t capacity : {1u, 2u, 3u, 7u}) {
        // Cross actual unsigned wrap, including non-power-of-two logical caps.
        Queue q(capacity, 9, UINT64_MAX - 3);
        Item output;
        for (unsigned round = 0; round < 50; ++round) {
            std::vector<Item> batch;
            for (unsigned i = 0; i < capacity; ++i) batch.emplace_back(round * 100 + i);
            CHECK(q.TryPushBatch(batch.data(), capacity) == HandoffPush::Accepted);
            Item rejected(999);
            CHECK(q.TryPush(std::move(rejected)) == HandoffPush::Full);
            CHECK(*rejected.value == 999);
            for (unsigned i = 0; i < capacity; ++i) {
                CHECK(q.TryPop(output) == HandoffDrain::Item);
                CHECK(*output.value == round * 100 + i);
            }
            CHECK(q.TryPop(output) == HandoffDrain::Empty);
        }
        std::vector<Item> too_many;
        for (unsigned i = 0; i <= capacity; ++i) too_many.emplace_back(i);
        CHECK(q.TryPushBatch(too_many.data(), too_many.size()) == HandoffPush::Full);
        CHECK(q.Empty());
        for (auto& item : too_many) CHECK(item.value);
    }
}

void WakeInterleavings() {
    unsigned modeled = 0;
    std::array<int, 4> steps{{0, 1, 2, 3}}; // publish, commit, arm, recheck
    do {
        const auto position = [&](int step) { return std::find(steps.begin(), steps.end(), step); };
        if (position(0) > position(1) || position(2) > position(3)) continue;
        ++modeled;
        Queue q(1, 71);
        CHECK(q.CommitWake() && q.Claim(71));
        Item item(71), output;
        for (int step : steps) {
            if (step == 0) CHECK(q.TryPush(std::move(item)) == HandoffPush::Accepted);
            if (step == 1) (void)q.CommitWake();
            if (step == 2) CHECK(q.ArmWait());
            if (step == 3) (void)q.RecheckAfterArm();
        }
        if (q.GetState() == Queue::State::Scheduled) CHECK(q.Claim(71));
        CHECK(q.GetState() == Queue::State::Running);
        CHECK(q.TryPop(output) == HandoffDrain::Item && *output.value == 71);
    } while (std::next_permutation(steps.begin(), steps.end()));
    CHECK(modeled == 6);
    // Publish/commit on every boundary of arm/recheck; no future traffic needed.
    for (int boundary = 0; boundary < 4; ++boundary) {
        Queue q(2, 10);
        CHECK(q.CommitWake());
        CHECK(!q.Claim(9));
        CHECK(q.Claim(10));
        CHECK(!q.Claim(10));
        Item input(42), output;
        if (boundary == 0) {
            CHECK(q.TryPush(std::move(input)) == HandoffPush::Accepted);
            CHECK(!q.CommitWake()); // mandatory Running -> Running RMW
        }
        CHECK(q.ArmWait());
        if (boundary == 1) {
            CHECK(q.TryPush(std::move(input)) == HandoffPush::Accepted);
            // Publication without commit: consumer reclaims Running first.
        }
        if (boundary == 2) {
            CHECK(q.TryPush(std::move(input)) == HandoffPush::Accepted);
            CHECK(q.CommitWake());
        }
        const bool yield = q.RecheckAfterArm();
        if (boundary == 3) {
            CHECK(yield);
            CHECK(q.TryPush(std::move(input)) == HandoffPush::Accepted);
            CHECK(q.CommitWake());
        }
        if (boundary >= 2) { CHECK(yield); CHECK(q.Claim(10)); }
        else CHECK(!yield);
        if (boundary == 1) CHECK(!q.CommitWake());
        CHECK(q.TryPop(output) == HandoffDrain::Item);
        CHECK(*output.value == 42);
        CHECK(q.ArmWaitAndRecheck());
    }
    Queue busy(2, 1);
    Item a(1), b(2), out;
    CHECK(busy.TryPush(std::move(a)) == HandoffPush::Accepted);
    CHECK(busy.CommitWake());
    CHECK(busy.TryPush(std::move(b)) == HandoffPush::Accepted);
    CHECK(!busy.CommitWake()); // already Scheduled
    CHECK(busy.Claim(1));
    CHECK(busy.TryPop(out) == HandoffDrain::Item);
    // Running stays responsible while an asynchronous write or gather is pending.
    Item c(3);
    CHECK(busy.TryPush(std::move(c)) == HandoffPush::Accepted);
    CHECK(!busy.CommitWake());
    CHECK(busy.TryPop(out) == HandoffDrain::Item && *out.value == 2);
    CHECK(busy.TryPop(out) == HandoffDrain::Item && *out.value == 3);
    CHECK(busy.ArmWaitAndRecheck());
}

void CloseAndFailure() {
    for (bool full : {false, true}) {
        Queue q(1, 1);
        Item input(7), output;
        if (full) CHECK(q.TryPush(std::move(input)) == HandoffPush::Accepted);
        CHECK(q.RequestClose()); // control cannot be blocked by full data slots
        CHECK(q.Claim(1));
        Item rejected(8);
        CHECK(q.TryPush(std::move(rejected)) == HandoffPush::Closed && rejected.value);
        if (full) CHECK(q.TryPop(output) == HandoffDrain::Item && *output.value == 7);
        CHECK(q.TryPop(output) == HandoffDrain::Closed);
        q.Abort();
        CHECK(q.ArmWaitAndRecheck());
    }
    for (bool throws : {false, true}) {
        SerializedSpscHandoff<Item> endpoint(2, 17);
        Item batch[] = {Item(1), Item(2)};
        CHECK(endpoint.PushBatch(batch, 2, [&](std::uint64_t) -> bool {
            if (throws) throw 1;
            return false;
        }) == HandoffPush::Closed);
        CHECK(!batch[0].value && !batch[1].value);
        CHECK(!endpoint.Consumer().Claim(17));
        // Only the quiescent owner reclaims the failed post's slots.
        Item out;
        CHECK(endpoint.Consumer().TryPop(out) == HandoffDrain::Item);
        CHECK(endpoint.Consumer().TryPop(out) == HandoffDrain::Item);
        CHECK(endpoint.Consumer().TryPop(out) == HandoffDrain::Closed);
    }
    {
        auto endpoint = std::make_shared<SerializedSpscHandoff<Item>>(1, 19);
        std::function<void()> pending;
        Item item(19);
        CHECK(endpoint->PushBatch(&item, 1, [&](std::uint64_t epoch) {
            pending = [endpoint, epoch] { CHECK(!endpoint->Consumer().Claim(epoch)); };
            // Force the control transition while the post is still in progress.
            endpoint->Consumer().Abort();
            return true;
        }) == HandoffPush::Accepted);
        endpoint.reset();
        pending();
        pending = {}; // retained queued storage reclaimed only at quiescence
    }
    auto old = std::make_shared<SerializedSpscHandoff<Item>>(1, 20);
    Item item(3);
    std::function<void()> callback;
    CHECK(old->PushBatch(&item, 1, [&](std::uint64_t epoch) {
        callback = [old, epoch] { CHECK(!old->Consumer().Claim(epoch)); };
        return true;
    }) == HandoffPush::Accepted);
    old->Abort();
    old.reset();
    Queue restarted(1, 21);
    CHECK(!restarted.Claim(20));
    std::thread migrated([&] { callback(); });
    migrated.join();
    callback = {};
}

void SerializedProducers() {
    SerializedSpscHandoff<Item> endpoint(3, 31);
    std::mutex sync;
    std::condition_variable changed;
    unsigned turn = 0;
    std::atomic<unsigned> posts{0};
    auto post = [&](std::uint64_t) { ++posts; return true; };
    // Alternate a two-packet GRO batch and an ordinary packet (same logical flow).
    auto producer = [&](unsigned identity) {
        for (unsigned round = 0; round < 100; ++round) {
            std::unique_lock<std::mutex> lock(sync);
            CHECK(changed.wait_for(lock, std::chrono::seconds(10), [&] { return turn == round * 3 + identity; }));
            lock.unlock();
            const unsigned base = round * 3 + (identity == 0 ? 0 : 2);
            Item items[] = {Item(base), Item(base + 1)};
            CHECK(endpoint.PushBatch(items, identity == 0 ? 2 : 1, post) == HandoffPush::Accepted);
            lock.lock(); ++turn; lock.unlock(); changed.notify_all();
        }
    };
    std::thread first([&] { producer(0); });
    std::thread second([&] { producer(1); });
    for (unsigned round = 0; round < 100; ++round) {
        std::unique_lock<std::mutex> lock(sync);
        CHECK(changed.wait_for(lock, std::chrono::seconds(10), [&] { return turn == round * 3 + 2; }));
        lock.unlock();
        CHECK(endpoint.Consumer().Claim(31));
        Item output;
        for (unsigned expected : {round * 3, round * 3 + 1, round * 3 + 2}) {
            CHECK(endpoint.Consumer().TryPop(output) == HandoffDrain::Item);
            CHECK(*output.value == expected);
        }
        CHECK(endpoint.Consumer().ArmWaitAndRecheck());
        lock.lock(); ++turn; lock.unlock(); changed.notify_all();
    }
    first.join(); second.join();
    CHECK(posts == 100);
}

void ConcurrentAndFairness() {
    SerializedSpscHandoff<Item> endpoint(7, 41);
    std::atomic<bool> scheduled{false};
    std::atomic<unsigned> consumed{0};
    auto post = [&](std::uint64_t) { CHECK(!scheduled.exchange(true)); return true; };
    std::thread producer([&] {
        for (unsigned i = 0; i < 10000; ++i) {
            Item item(i);
            while (endpoint.PushBatch(&item, 1, post) == HandoffPush::Full) std::this_thread::yield();
        }
    });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (consumed != 10000) {
        CHECK(std::chrono::steady_clock::now() < deadline);
        if (!scheduled.exchange(false)) { std::this_thread::yield(); continue; }
        CHECK(endpoint.Consumer().Claim(41));
        for (;;) {
            Item out;
            unsigned quantum = 0;
            while (quantum < 3 && endpoint.Consumer().TryPop(out) == HandoffDrain::Item) {
                CHECK(*out.value == consumed++); ++quantum;
            }
            if (!endpoint.Consumer().Empty()) {
                CHECK(endpoint.Consumer().ScheduleContinuation());
                CHECK(endpoint.PostOrAbort(post));
                break;
            }
            if (endpoint.Consumer().ArmWaitAndRecheck()) break;
        }
    }
    producer.join();
    // Deterministic dispatcher: timer/other flow runs before the continuation,
    // even while the producer replenishes the queue each dispatch.
    Queue q(2, 50);
    Item item(1), out;
    CHECK(q.TryPush(std::move(item)) == HandoffPush::Accepted && q.CommitWake());
    std::deque<std::function<void()>> tasks;
    unsigned other = 0, timers = 0, drains = 0;
    std::function<void()> drain = [&] {
        CHECK(q.Claim(50)); ++drains;
        CHECK(q.TryPop(out) == HandoffDrain::Item);
        Item next(drains);
        CHECK(q.TryPush(std::move(next)) == HandoffPush::Accepted);
        CHECK(!q.CommitWake());
        CHECK(q.ScheduleContinuation());
        tasks.push_back(drain);
    };
    tasks.push_back(drain); tasks.push_back([&] { ++other; }); tasks.push_back([&] { ++timers; });
    for (unsigned i = 0; i < 3; ++i) { auto task = tasks.front(); tasks.pop_front(); task(); }
    CHECK(drains == 1 && other == 1 && timers == 1);
    q.Abort();
}

void RacingProducers() {
    SerializedSpscHandoff<Item> endpoint(7, 81);
    std::atomic<bool> scheduled{false};
    auto post = [&](std::uint64_t) { CHECK(!scheduled.exchange(true)); return true; };
    auto produce = [&](unsigned id) {
        for (unsigned i = 0; i < 2000; ++i) {
            // Mixed atomic GRO pairs and ordinary items, with no turn-taking
            // lock outside the real serialized-producer adapter.
            const unsigned count = i % 2 ? 1 : 2;
            Item batch[] = {Item(id * 100000 + i * 2), Item(id * 100000 + i * 2 + 1)};
            while (endpoint.PushBatch(batch, count, post) == HandoffPush::Full) std::this_thread::yield();
        }
    };
    std::thread first([&] { produce(0); }), second([&] { produce(1); });
    unsigned seen[2] = {}, next[2] = {};
    unsigned total = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (total < 6000) {
        CHECK(std::chrono::steady_clock::now() < deadline);
        if (!scheduled.exchange(false)) { std::this_thread::yield(); continue; }
        CHECK(endpoint.Consumer().Claim(81));
        for (;;) {
            Item output;
            while (endpoint.Consumer().TryPop(output) == HandoffDrain::Item) {
                const unsigned id = *output.value / 100000;
                CHECK(id < 2);
                const unsigned value = *output.value % 100000;
                CHECK(value == next[id]);
                ++seen[id]; ++total;
                const unsigned group = value / 2;
                next[id] = value % 2 == 0 && group % 2 == 0 ? value + 1 : (group + 1) * 2;
            }
            if (endpoint.Consumer().ArmWaitAndRecheck()) break;
        }
    }
    first.join(); second.join();
    CHECK(seen[0] == 3000 && seen[1] == 3000);
}

void AbortIsIdempotentAndObservable() {
    const int baseline = Item::live.load();
    {
        Queue endpoint(2, 91);
        {
            Item queued(7);
            CHECK(endpoint.TryPush(std::move(queued)) == HandoffPush::Accepted);
        }
        // The accepted item stays owned by the queue across Abort.
        CHECK(Item::live == baseline + 1);
        endpoint.Abort();
        endpoint.Abort();
        CHECK(endpoint.GetState() == Queue::State::Closed);
        CHECK(endpoint.Closing());
        Item rejected(9);
        CHECK(endpoint.TryPush(std::move(rejected)) == HandoffPush::Closed);
        CHECK(rejected.value && *rejected.value == 9);
        CHECK(!endpoint.Claim(91));
        CHECK(!endpoint.ArmWait());
        CHECK(!endpoint.CommitWake());
        CHECK(Item::live == baseline + 2);
    }
    // The quiescent owner's destructor reclaims the item Abort left queued.
    CHECK(Item::live == baseline);
}

int main() {
    Storage(); WakeInterleavings(); CloseAndFailure(); SerializedProducers(); ConcurrentAndFairness(); RacingProducers(); AbortIsIdempotentAndObservable();
    CHECK(Item::live == 0);
    std::puts("spsc_handoff_test: 7 groups passed");
}
