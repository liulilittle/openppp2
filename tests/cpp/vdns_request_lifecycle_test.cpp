#include <ppp/net/asio/VdnsRequestCompletion.h>

#include <atomic>
#include <cassert>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

using ppp::net::asio::vdns::VdnsRequestCompletion;

namespace {

class StartGate final {
public:
    explicit StartGate(int participants) noexcept
        : participants_(participants) {
    }

    void ArriveAndWait() {
        std::unique_lock<std::mutex> lock(mutex_);
        ++arrived_;
        condition_.notify_all();
        condition_.wait(lock, [this]() noexcept { return released_; });
    }

    void ReleaseWhenReady() {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this]() noexcept { return arrived_ == participants_; });
        released_ = true;
        condition_.notify_all();
    }

private:
    const int participants_;
    int arrived_ = 0;
    bool released_ = false;
    std::mutex mutex_;
    std::condition_variable condition_;
};

class RequestHarness final {
public:
    using State = VdnsRequestCompletion::State;

    bool Finish() noexcept {
        return Complete(State::Finished, true);
    }

    bool Timeout() noexcept {
        return Complete(State::TimedOut, true);
    }

    bool Cancel() noexcept {
        return Complete(State::Cancelled, false);
    }

    void LateMergeHandler() noexcept {
        if (completion_.IsPending()) {
            Finish();
        }
    }

    void LateTimerHandler() noexcept {
        if (completion_.IsPending()) {
            Timeout();
        }
    }

    State StateValue() const noexcept {
        return completion_.GetState();
    }

    int CallbackCount() const noexcept {
        return callbacks_.load(std::memory_order_relaxed);
    }

    int CleanupCount() const noexcept {
        return cleanups_.load(std::memory_order_relaxed);
    }

private:
    bool Complete(State state, bool invoke_callback) noexcept {
        return completion_.TryComplete(state, [this, invoke_callback]() noexcept {
            if (invoke_callback) {
                callbacks_.fetch_add(1, std::memory_order_relaxed);
            }
            cleanups_.fetch_add(1, std::memory_order_relaxed);
        });
    }

    VdnsRequestCompletion completion_;
    std::atomic_int callbacks_{0};
    std::atomic_int cleanups_{0};
};

void TestFinishAndTimeoutWinners() {
    RequestHarness finished;
    assert(finished.Finish());
    assert(finished.StateValue() == VdnsRequestCompletion::State::Finished);
    assert(finished.CallbackCount() == 1);
    assert(finished.CleanupCount() == 1);
    finished.LateMergeHandler();
    finished.LateTimerHandler();
    assert(finished.CallbackCount() == 1);
    assert(finished.CleanupCount() == 1);

    RequestHarness timed_out;
    assert(timed_out.Timeout());
    assert(timed_out.StateValue() == VdnsRequestCompletion::State::TimedOut);
    assert(timed_out.CallbackCount() == 1);
    assert(timed_out.CleanupCount() == 1);
    timed_out.LateMergeHandler();
    timed_out.LateTimerHandler();
    assert(timed_out.CallbackCount() == 1);
    assert(timed_out.CleanupCount() == 1);
}

void TestCancelSuppressesCallback() {
    RequestHarness request;
    assert(request.Cancel());
    assert(request.StateValue() == VdnsRequestCompletion::State::Cancelled);
    request.LateMergeHandler();
    request.LateTimerHandler();
    assert(request.CallbackCount() == 0);
    assert(request.CleanupCount() == 1);
}

void TestFinishTimeoutCancelRace() {
    auto request = std::make_shared<RequestHarness>();
    StartGate gate(5);
    std::vector<std::thread> contenders;
    contenders.emplace_back([&]() { gate.ArriveAndWait(); request->Finish(); });
    contenders.emplace_back([&]() { gate.ArriveAndWait(); request->Timeout(); });
    contenders.emplace_back([&]() { gate.ArriveAndWait(); request->Cancel(); });
    contenders.emplace_back([&]() { gate.ArriveAndWait(); request->LateMergeHandler(); });
    contenders.emplace_back([&]() { gate.ArriveAndWait(); request->LateTimerHandler(); });

    gate.ReleaseWhenReady();
    for (auto& contender : contenders) {
        contender.join();
    }

    const auto state = request->StateValue();
    assert(state != VdnsRequestCompletion::State::Pending);
    assert(request->CleanupCount() == 1);
    assert(request->CallbackCount() <= 1);
    if (state == VdnsRequestCompletion::State::Cancelled) {
        assert(request->CallbackCount() == 0);
    }
    else {
        assert(request->CallbackCount() == 1);
    }
}

void TestWeakHandlersDoNotRetainRequest() {
    std::weak_ptr<RequestHarness> weak_request;
    std::vector<std::function<void()>> retained_handlers;
    {
        auto request = std::make_shared<RequestHarness>();
        weak_request = request;
        retained_handlers.emplace_back([weak_request]() noexcept {
            if (auto request = weak_request.lock(); request && request->StateValue() == VdnsRequestCompletion::State::Pending) {
                request->LateMergeHandler();
            }
        });
        retained_handlers.emplace_back([weak_request]() noexcept {
            if (auto request = weak_request.lock(); request && request->StateValue() == VdnsRequestCompletion::State::Pending) {
                request->LateTimerHandler();
            }
        });
        assert(request->Cancel());
    }

    assert(weak_request.expired());
    for (auto& handler : retained_handlers) {
        handler();
    }
    assert(weak_request.expired());
}

}  // namespace

int main() {
    TestFinishAndTimeoutWinners();
    TestCancelSuppressesCallback();
    TestFinishTimeoutCancelRace();
    TestWeakHandlersDoNotRetainRequest();
    return 0;
}
