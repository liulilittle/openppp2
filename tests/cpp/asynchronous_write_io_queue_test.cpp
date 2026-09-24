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
        std::cout << "asynchronous_write_io_queue_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "asynchronous_write_io_queue_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
