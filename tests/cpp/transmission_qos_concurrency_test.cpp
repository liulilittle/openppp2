#define BOOST_TEST_MODULE transmission_qos_concurrency_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/transmissions/ITransmissionQoS.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace {

using QoS = ppp::transmissions::ITransmissionQoS;

class StartBarrier final {
public:
    explicit StartBarrier(int participants) noexcept
        : participants_(participants) {
    }

    void ArriveAndWait() noexcept {
        std::unique_lock<std::mutex> lock(mutex_);
        ++arrived_;
        condition_.notify_all();
        condition_.wait(lock, [this]() noexcept { return released_; });
    }

    void WaitUntilAllArrive() noexcept {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this]() noexcept { return arrived_ == participants_; });
    }

    void Release() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
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

bool WaitUntilDisposed(const std::shared_ptr<QoS>& qos) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline) {
        if (!qos->EndRead(1)) {
            return true;
        }
        std::this_thread::yield();
    }
    return false;
}

class AdmissionControlledQoS final : public QoS {
public:
    AdmissionControlledQoS(
        const std::shared_ptr<boost::asio::io_context>& context,
        ppp::Int64 bandwidth) noexcept
        : QoS(context, bandwidth) {
    }

    void WaitForAdmission() {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this]() noexcept { return admitted_; });
    }

    void ReleaseAwait() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        release_ = true;
        condition_.notify_all();
    }

protected:
    bool AwaitRead(YieldContext& y, const ReadWaiterPtr& waiter) noexcept override {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            admitted_ = true;
            condition_.notify_all();
            condition_.wait(lock, [this]() noexcept { return release_; });
        }
        return QoS::AwaitRead(y, waiter);
    }

private:
    std::mutex mutex_;
    std::condition_variable condition_;
    bool admitted_ = false;
    bool release_ = false;
};

class CompletionMarker final {
public:
    void Signal() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        signaled_ = true;
        condition_.notify_all();
    }

    void Wait() {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this]() noexcept { return signaled_; });
    }

private:
    std::mutex mutex_;
    std::condition_variable condition_;
    bool signaled_ = false;
};

}  // namespace

BOOST_AUTO_TEST_CASE(queued_callback_is_exactly_once_when_update_races_finalize) {
    auto context = std::make_shared<boost::asio::io_context>();
    auto qos = std::make_shared<QoS>(context, 1);
    BOOST_REQUIRE(qos->EndRead(128));

    std::atomic_int callback_count{0};
    std::mutex callback_mutex;
    std::condition_variable callback_condition;
    bool callback_entered = false;
    bool release_callback = false;

    BOOST_REQUIRE(qos->BeginRead([&]() noexcept {
        callback_count.fetch_add(1, std::memory_order_relaxed);
        std::unique_lock<std::mutex> lock(callback_mutex);
        callback_entered = true;
        callback_condition.notify_all();
        callback_condition.wait(lock, [&]() noexcept { return release_callback; });
    }));

    qos->Update(1000);
    qos->Dispose();

    StartBarrier start(2);
    std::thread first([&]() {
        start.ArriveAndWait();
        context->run();
    });
    std::thread second([&]() {
        start.ArriveAndWait();
        context->run();
    });
    start.WaitUntilAllArrive();
    start.Release();

    {
        std::unique_lock<std::mutex> lock(callback_mutex);
        BOOST_REQUIRE(callback_condition.wait_for(
            lock, std::chrono::seconds(2), [&]() noexcept { return callback_entered; }));
    }
    const bool disposed_while_callback_blocked = WaitUntilDisposed(qos);
    {
        std::lock_guard<std::mutex> lock(callback_mutex);
        release_callback = true;
        callback_condition.notify_all();
    }

    first.join();
    second.join();

    BOOST_TEST(disposed_while_callback_blocked);
    BOOST_TEST(callback_count.load(std::memory_order_relaxed) == 1);
}

BOOST_AUTO_TEST_CASE(finalize_drains_queue_and_disposed_instance_rejects_reads) {
    auto context = std::make_shared<boost::asio::io_context>();
    auto qos = std::make_shared<QoS>(context, 1);
    BOOST_REQUIRE(qos->EndRead(128));

    int callback_count = 0;
    BOOST_REQUIRE(qos->BeginRead([&callback_count]() noexcept { ++callback_count; }));

    qos->Dispose();
    context->run();

    BOOST_TEST(callback_count == 1);
    BOOST_TEST(!qos->BeginRead([]() noexcept {}));
    BOOST_TEST(!qos->EndRead(1));
}

BOOST_AUTO_TEST_CASE(update_completion_before_suspend_is_consumed_once) {
    auto context = std::make_shared<boost::asio::io_context>();
    auto qos = std::make_shared<AdmissionControlledQoS>(context, 1);
    BOOST_REQUIRE(qos->EndRead(128));

    std::atomic_int callback_count{0};
    std::atomic_bool read_completed{false};
    BOOST_REQUIRE(QoS::YieldContext::Spawn(*context, [qos, &callback_count, &read_completed](auto& y) noexcept {
        auto packet = qos->ReadBytes(y, 1, [&callback_count](auto&, int*) noexcept {
            callback_count.fetch_add(1, std::memory_order_relaxed);
            return std::shared_ptr<ppp::Byte>(new ppp::Byte[1], std::default_delete<ppp::Byte[]>());
        });
        read_completed.store(nullptr != packet, std::memory_order_release);
    }));

    std::thread admitted_worker([&]() { context->run(); });
    qos->WaitForAdmission();

    CompletionMarker marker;
    qos->Update(1000);
    boost::asio::post(*context, [&marker]() noexcept { marker.Signal(); });
    std::thread completion_worker([&]() { context->run(); });
    marker.Wait();
    qos->ReleaseAwait();

    admitted_worker.join();
    completion_worker.join();
    BOOST_TEST(read_completed.load(std::memory_order_acquire));
    BOOST_TEST(callback_count.load(std::memory_order_relaxed) == 1);
}

BOOST_AUTO_TEST_CASE(finalize_completion_before_suspend_rejects_callback) {
    auto context = std::make_shared<boost::asio::io_context>();
    auto qos = std::make_shared<AdmissionControlledQoS>(context, 1);
    BOOST_REQUIRE(qos->EndRead(128));

    std::atomic_int callback_count{0};
    std::atomic_bool read_completed{false};
    BOOST_REQUIRE(QoS::YieldContext::Spawn(*context, [qos, &callback_count, &read_completed](auto& y) noexcept {
        auto packet = qos->ReadBytes(y, 1, [&callback_count](auto&, int*) noexcept {
            callback_count.fetch_add(1, std::memory_order_relaxed);
            return std::shared_ptr<ppp::Byte>(new ppp::Byte[1], std::default_delete<ppp::Byte[]>());
        });
        read_completed.store(nullptr != packet, std::memory_order_release);
    }));

    std::thread admitted_worker([&]() { context->run(); });
    qos->WaitForAdmission();

    CompletionMarker marker;
    qos->Dispose();
    boost::asio::post(*context, [&marker]() noexcept { marker.Signal(); });
    std::thread completion_worker([&]() { context->run(); });
    marker.Wait();
    qos->ReleaseAwait();

    admitted_worker.join();
    completion_worker.join();
    BOOST_TEST(!read_completed.load(std::memory_order_acquire));
    BOOST_TEST(callback_count.load(std::memory_order_relaxed) == 0);
    BOOST_TEST(!qos->BeginRead([]() noexcept {}));
}
