#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>

#include <condition_variable>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TestQueue final : public ppp::net::asio::IAsynchronousWriteIoQueue {
public:
    enum class StartMode {
        Async,
        SyncSuccess,
        SyncThenFail,
        Fail,
        BlockingFail,
    };

    explicit TestQueue(std::vector<StartMode> modes = {}) noexcept
        : IAsynchronousWriteIoQueue(NULLPTR)
        , modes_(std::move(modes)) {
    }

    bool Send(int length, const AsynchronousWriteBytesCallback& callback) {
        auto packet = ppp::make_shared_alloc<ppp::Byte>(length);
        return WriteBytes(packet, length, callback);
    }

    void Complete(std::size_t index, bool ok) {
        AsynchronousWriteBytesCallback callback;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            callback = completions_.at(index);
        }
        callback(ok);
    }

    // Stored completions capture the queue (shared_from_this) like a real
    // transport handler; drop them at test end to break the cycle.
    void ReleaseCompletions() {
        std::lock_guard<std::mutex> lock(mutex_);
        completions_.clear();
    }

    std::vector<int> Starts() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return starts_;
    }

    void WaitUntilBlockingStart() {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this]() noexcept { return blocking_started_; });
    }

    void ReleaseBlockingStart() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            release_blocking_ = true;
        }
        condition_.notify_all();
    }

protected:
    bool DoWriteBytes(
        std::shared_ptr<ppp::Byte>,
        int,
        int packet_length,
        const AsynchronousWriteBytesCallback& callback) noexcept override {
        StartMode mode = StartMode::Async;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            starts_.push_back(packet_length);
            if (next_mode_ < modes_.size()) {
                mode = modes_[next_mode_++];
            }
            if (mode == StartMode::Async) {
                completions_.push_back(callback);
                return true;
            }
        }

        if (mode == StartMode::SyncSuccess) {
            callback(true);
            return true;
        }
        if (mode == StartMode::SyncThenFail) {
            callback(true);
            return false;
        }
        if (mode == StartMode::BlockingFail) {
            std::unique_lock<std::mutex> lock(mutex_);
            blocking_started_ = true;
            condition_.notify_all();
            condition_.wait(lock, [this]() noexcept { return release_blocking_; });
        }
        return false;
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::vector<StartMode> modes_;
    std::size_t next_mode_ = 0;
    std::vector<int> starts_;
    std::vector<AsynchronousWriteBytesCallback> completions_;
    bool blocking_started_ = false;
    bool release_blocking_ = false;
};

void TestFinalizeClaimsInflightAndQueued() {
    auto queue = std::make_shared<TestQueue>();
    std::vector<bool> results;
    Require(queue->Send(10, [&](bool ok) { results.push_back(ok); }), "first accepted");
    Require(queue->Send(20, [&](bool ok) { results.push_back(ok); }), "second queued");
    Require(queue->GetPendingItems() == 2, "two pending items");
    Require(queue->GetPendingBytes() == 30, "thirty pending bytes");

    queue->Dispose();
    Require(results == std::vector<bool>({false, false}), "Finalize fails in-flight and queued");
    Require(queue->GetPendingItems() == 0, "Finalize clears item accounting");
    Require(queue->GetPendingBytes() == 0, "Finalize clears byte accounting");

    queue->Complete(0, true);
    queue->Complete(0, false);
    Require(results.size() == 2, "late and repeated completions are ignored");
    Require(queue->GetPendingItems() == 0 && queue->GetPendingBytes() == 0,
        "late completion cannot underflow accounting");
    queue->ReleaseCompletions();
}

void TestSynchronousCompletion() {
    auto queue = std::make_shared<TestQueue>(std::vector<TestQueue::StartMode>{
        TestQueue::StartMode::SyncSuccess,
        TestQueue::StartMode::SyncThenFail,
    });
    int callbacks = 0;
    Require(queue->Send(3, [&](bool ok) { Require(ok, "sync success callback"); ++callbacks; }),
        "sync success accepted");
    Require(queue->Send(4, [&](bool ok) { Require(ok, "sync false-return callback"); ++callbacks; }),
        "completion wins over false start result");
    Require(callbacks == 2, "sync callbacks exactly once");
    Require(queue->GetPendingItems() == 0 && queue->GetPendingBytes() == 0,
        "sync completion accounting drained");
}

void TestFirstStartFailureContinuesQueuedWork() {
    auto queue = std::make_shared<TestQueue>(std::vector<TestQueue::StartMode>{
        TestQueue::StartMode::BlockingFail,
        TestQueue::StartMode::Async,
    });
    int first_callbacks = 0;
    int second_callbacks = 0;
    bool first_result = true;
    std::thread starter([&]() {
        first_result = queue->Send(5, [&](bool) { ++first_callbacks; });
    });

    queue->WaitUntilBlockingStart();
    Require(queue->Send(7, [&](bool ok) { Require(ok, "queued completion succeeds"); ++second_callbacks; }),
        "work queues behind blocking first start");
    queue->ReleaseBlockingStart();
    starter.join();

    Require(!first_result, "first start failure returns false");
    Require(first_callbacks == 0, "first start failure does not callback");
    Require(queue->Starts() == std::vector<int>({5, 7}), "queued work starts after first failure");
    queue->Complete(0, true);
    Require(second_callbacks == 1, "queued work completes");
    Require(queue->GetPendingItems() == 0 && queue->GetPendingBytes() == 0,
        "first failure and queued completion account once");
    queue->ReleaseCompletions();
}

void TestQueuedStartFailureDisposesRemainder() {
    auto queue = std::make_shared<TestQueue>(std::vector<TestQueue::StartMode>{
        TestQueue::StartMode::Async,
        TestQueue::StartMode::Fail,
    });
    std::vector<int> callbacks;
    Require(queue->Send(1, [&](bool ok) { callbacks.push_back(ok ? 1 : -1); }), "first accepted");
    Require(queue->Send(2, [&](bool ok) { callbacks.push_back(ok ? 2 : -2); }), "second queued");
    Require(queue->Send(3, [&](bool ok) { callbacks.push_back(ok ? 3 : -3); }), "third queued");

    queue->Complete(0, true);
    Require(callbacks == std::vector<int>({1, -2, -3}),
        "queued start failure callbacks false then disposes remainder");
    Require(queue->GetPendingItems() == 0 && queue->GetPendingBytes() == 0,
        "queued failure disposal clears accounting");
    queue->ReleaseCompletions();
}

void TestQueuedStartFailureClosesAdmissionBeforeCallback() {
    auto queue = std::make_shared<TestQueue>(std::vector<TestQueue::StartMode>{
        TestQueue::StartMode::Async,
        TestQueue::StartMode::Fail,
    });
    bool reentry_result = true;
    std::vector<int> callbacks;
    Require(queue->Send(1, [&](bool ok) { callbacks.push_back(ok ? 1 : -1); }), "first accepted");
    Require(queue->Send(2, [&](bool ok) {
        callbacks.push_back(ok ? 2 : -2);
        reentry_result = queue->Send(4, [&](bool) { callbacks.push_back(4); });
    }), "second queued");
    Require(queue->Send(3, [&](bool ok) { callbacks.push_back(ok ? 3 : -3); }), "third queued");

    queue->Complete(0, true);
    Require(!reentry_result, "queued start failure closes admission before callback");
    Require(callbacks == std::vector<int>({1, -2, -3}), "failure callback cannot bypass older queued work");
    Require(queue->Starts() == std::vector<int>({1, 2}), "reentrant write never starts");
    queue->ReleaseCompletions();
}

void TestAsynchronousFailureDisposesQueue() {
    auto queue = std::make_shared<TestQueue>();
    std::vector<int> callbacks;
    Require(queue->Send(1, [&](bool ok) { callbacks.push_back(ok ? 1 : -1); }), "first accepted");
    Require(queue->Send(2, [&](bool ok) { callbacks.push_back(ok ? 2 : -2); }), "second queued");

    queue->Complete(0, false);
    Require(callbacks == std::vector<int>({-1, -2}), "physical failure terminates current and waiting writes");
    Require(queue->Starts() == std::vector<int>({1}), "physical failure does not start next write");
    Require(!queue->Send(3, [&](bool) { callbacks.push_back(3); }), "physical failure closes admission");
    Require(queue->GetPendingItems() == 0 && queue->GetPendingBytes() == 0,
        "physical failure clears accounting");
    queue->ReleaseCompletions();
}

void TestCallbackReentryPreservesQueueOrder() {
    auto queue = std::make_shared<TestQueue>();
    std::vector<int> callbacks;
    Require(queue->Send(1, [&](bool ok) {
        Require(ok, "first completion");
        callbacks.push_back(1);
        Require(queue->Send(3, [&](bool nested_ok) {
            Require(nested_ok, "reentrant completion");
            callbacks.push_back(3);
        }), "reentrant send accepted");
    }), "first accepted");
    Require(queue->Send(2, [&](bool ok) {
        Require(ok, "second completion");
        callbacks.push_back(2);
    }), "second queued");

    queue->Complete(0, true);
    Require(queue->Starts() == std::vector<int>({1, 2}), "pre-existing queued item starts before reentrant item");
    queue->Complete(1, true);
    Require(queue->Starts() == std::vector<int>({1, 2, 3}), "reentrant item starts third");
    queue->Complete(2, true);
    Require(callbacks == std::vector<int>({1, 2, 3}), "callbacks preserve FIFO order");
    queue->ReleaseCompletions();
}

void TestConcurrentDispose() {
    auto queue = std::make_shared<TestQueue>();
    std::atomic<int> callbacks{0};
    for (int i = 0; i < 32; ++i) {
        Require(queue->Send(1, [&](bool ok) {
            Require(!ok, "Dispose callback is false");
            callbacks.fetch_add(1, std::memory_order_relaxed);
        }), "concurrent Dispose fixture enqueue");
    }

    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([queue]() { queue->Dispose(); });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
    Require(callbacks.load(std::memory_order_relaxed) == 32, "concurrent Dispose claims each callback once");
    queue->Complete(0, true);
    Require(callbacks.load(std::memory_order_relaxed) == 32, "late completion after concurrent Dispose ignored");
    queue->ReleaseCompletions();
}

void TestBackpressure() {
    auto queue = std::make_shared<TestQueue>();
    queue->SetMaxPendingItems(2);
    queue->SetMaxPendingBytes(5);
    int callbacks = 0;
    Require(queue->Send(3, [&](bool) { ++callbacks; }), "first under byte limit");
    Require(queue->Send(2, [&](bool) { ++callbacks; }), "second exactly reaches limits");
    Require(!queue->Send(1, [&](bool) { ++callbacks; }), "item and byte backpressure reject");
    Require(queue->GetPendingItems() == 2 && queue->GetPendingBytes() == 5,
        "rejection does not reserve accounting");
    Require(callbacks == 0, "backpressure rejection does not callback");
    queue->Dispose();
    Require(callbacks == 2, "accepted requests still finalize");
    queue->ReleaseCompletions();
}

// Byte-stream style queue that accepts gathered writes and records each start.
class GatherQueue final : public ppp::net::asio::IAsynchronousWriteIoQueue {
public:
    GatherQueue() noexcept
        : IAsynchronousWriteIoQueue(NULLPTR) {
    }

    bool Send(int length, const AsynchronousWriteBytesCallback& callback) {
        auto packet = ppp::make_shared_alloc<ppp::Byte>(length);
        return WriteBytes(packet, length, callback);
    }

    void Complete(std::size_t index, bool ok) {
        AsynchronousWriteBytesCallback callback = completions_.at(index);
        callback(ok);
    }

    void ReleaseCompletions() {
        completions_.clear();
    }

    // Each start records the lengths it wrote; a single write has one entry.
    std::vector<std::vector<int>> starts;
    bool fail_gather = false;

protected:
    bool CanGatherWrites() noexcept override { return true; }

    bool DoWriteBytes(std::shared_ptr<ppp::Byte>, int, int packet_length,
        const AsynchronousWriteBytesCallback& callback) noexcept override {
        starts.push_back({ packet_length });
        completions_.push_back(callback);
        return true;
    }

    bool DoWriteBytesGather(const WriteSegments& segments,
        const AsynchronousWriteBytesCallback& callback) noexcept override {
        std::vector<int> lengths;
        for (const WriteSegment& segment : segments) {
            Require(segment.first != nullptr, "gathered segment lost its buffer");
            lengths.push_back(segment.second);
        }
        starts.push_back(lengths);
        if (fail_gather) {
            return false;
        }
        completions_.push_back(callback);
        return true;
    }

private:
    std::vector<AsynchronousWriteBytesCallback> completions_;
};

void TestGatherMergesBacklogInOrder() {
    auto queue = std::make_shared<GatherQueue>();
    std::vector<int> completed;
    for (int length : { 10, 20, 30, 40 }) {
        Require(queue->Send(length, [&completed, length](bool ok) {
            Require(ok, "gathered write reported failure");
            completed.push_back(length);
        }), "send accepted");
    }

    // The first packet starts alone; the three that queued behind it form one batch.
    Require(queue->starts == std::vector<std::vector<int>>({ { 10 } }), "first write starts alone");
    Require(queue->GetPendingItems() == 4 && queue->GetPendingBytes() == 100, "initial accounting");

    queue->Complete(0, true);
    Require(queue->starts.size() == 2 && queue->starts[1] == std::vector<int>({ 20, 30, 40 }),
        "backlog merged into one gathered write");
    Require(queue->GetPendingItems() == 1 && queue->GetPendingBytes() == 90, "batch counts as one item");

    queue->Complete(1, true);
    Require(completed == std::vector<int>({ 10, 20, 30, 40 }), "callbacks complete in FIFO order");
    Require(queue->GetPendingItems() == 0 && queue->GetPendingBytes() == 0, "accounting drained");
    queue->ReleaseCompletions();
}

void TestGatherFailureFailsEveryMergedPacket() {
    auto queue = std::make_shared<GatherQueue>();
    std::vector<bool> results;
    for (int length : { 5, 6, 7 }) {
        Require(queue->Send(length, [&results](bool ok) { results.push_back(ok); }), "send accepted");
    }

    queue->fail_gather = true;
    queue->Complete(0, true);
    Require(results == std::vector<bool>({ true, false, false }), "failed batch fails each merged packet once");
    Require(queue->GetPendingItems() == 0 && queue->GetPendingBytes() == 0, "failed batch clears accounting");
    queue->ReleaseCompletions();
}

void TestDisposeFailsInflightBatch() {
    auto queue = std::make_shared<GatherQueue>();
    std::vector<bool> results;
    for (int length : { 1, 2, 3, 4 }) {
        Require(queue->Send(length, [&results](bool ok) { results.push_back(ok); }), "send accepted");
    }

    queue->Complete(0, true);
    queue->Dispose();
    Require(results == std::vector<bool>({ true, false, false, false }), "dispose fails each packet in the batch once");
    queue->Complete(1, true);
    Require(results.size() == 4, "late batch completion is ignored");
    queue->ReleaseCompletions();
}

} // namespace

int main() {
    try {
        TestFinalizeClaimsInflightAndQueued();
        TestSynchronousCompletion();
        TestFirstStartFailureContinuesQueuedWork();
        TestQueuedStartFailureDisposesRemainder();
        TestQueuedStartFailureClosesAdmissionBeforeCallback();
        TestAsynchronousFailureDisposesQueue();
        TestCallbackReentryPreservesQueueOrder();
        TestConcurrentDispose();
        TestBackpressure();
        TestGatherMergesBacklogInOrder();
        TestGatherFailureFailsEveryMergedPacket();
        TestDisposeFailsInflightBatch();
        std::cout << "asynchronous_write_io_queue_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "asynchronous_write_io_queue_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
