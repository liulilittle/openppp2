#include <linux/ppp/net/ProtectorNetworkRequest.h>

#include <atomic>
#include <cassert>
#include <future>
#include <memory>
#include <thread>
#include <vector>

using ppp::net::ProtectorNetworkRequest;
using ppp::net::ProtectorNetworkRequestSession;

namespace
{
    typedef ProtectorNetworkRequest::State RequestState;

    void TestCompletionBeforeSuspend()
    {
        ProtectorNetworkRequestSession session(1);
        std::atomic<int> wakes{0};
        auto request = session.Create([&]() noexcept { ++wakes; });

        assert(request->GetState() == RequestState::Pending);
        assert(session.Begin(request));
        assert(request->GetState() == RequestState::Running);
        assert(request->Complete(true));
        assert(session.Finish(request));

        assert(request->GetState() == RequestState::Completed);
        assert(request->Result());
        assert(wakes.load() == 1);
        assert(!request->Complete(false));
        assert(!request->Cancel());
        assert(wakes.load() == 1);
    }

    void TestDetachBeforeCallback()
    {
        ProtectorNetworkRequestSession session(2);
        std::atomic<int> wakes{0};
        auto request = session.Create([&]() noexcept { ++wakes; });

        session.Deactivate();

        assert(request->GetState() == RequestState::Cancelled);
        assert(!request->Result());
        assert(!session.Begin(request));
        assert(!request->Complete(true));
        assert(wakes.load() == 1);
    }

    void TestCallbackDetachRace()
    {
        ProtectorNetworkRequestSession session(3);
        std::atomic<int> wakes{0};
        auto request = session.Create([&]() noexcept { ++wakes; });
        std::promise<void> callback_admitted;
        std::future<void> admitted = callback_admitted.get_future();
        std::promise<void> detach_calling;
        std::future<void> detaching = detach_calling.get_future();
        std::promise<void> allow_completion;
        std::shared_future<void> completion_gate = allow_completion.get_future().share();
        std::atomic<bool> detached{false};

        std::thread callback([&]() noexcept {
            assert(session.Begin(request));
            callback_admitted.set_value();
            completion_gate.wait();
            assert(request->Complete(true));
            assert(session.Finish(request));
        });
        std::thread detach([&]() noexcept {
            admitted.wait();
            detach_calling.set_value();
            session.Deactivate();
            detached.store(true);
        });

        admitted.wait();
        detaching.wait();
        assert(session.RunningCount() == 1);
        assert(request->GetState() == RequestState::Running);
        assert(!detached.load());
        allow_completion.set_value();
        callback.join();
        detach.join();

        assert(detached.load());
        assert(request->GetState() == RequestState::Completed);
        assert(request->Result());
        assert(wakes.load() == 1);
    }

    void TestOldGenerationIsolation()
    {
        ProtectorNetworkRequestSession old_session(1001);
        ProtectorNetworkRequestSession new_session(1002);
        std::atomic<int> old_wakes{0};
        std::atomic<int> new_wakes{0};
        auto old_request = old_session.Create([&]() noexcept { ++old_wakes; });
        auto new_request = new_session.Create([&]() noexcept { ++new_wakes; });

        old_session.Deactivate();
        assert(!new_session.Begin(old_request));
        assert(new_session.Begin(new_request));
        assert(new_request->Complete(true));
        assert(new_session.Finish(new_request));

        assert(old_request->Generation() != new_request->Generation());
        assert(old_request->GetState() == RequestState::Cancelled);
        assert(new_request->GetState() == RequestState::Completed);
        assert(!old_request->Result());
        assert(new_request->Result());
        assert(old_wakes.load() == 1);
        assert(new_wakes.load() == 1);
    }

    void TestPendingCancellationWakesOnce()
    {
        ProtectorNetworkRequestSession session(2001);
        std::atomic<int> wakes{0};
        std::vector<std::shared_ptr<ProtectorNetworkRequest>> requests;
        for (int i = 0; i < 64; ++i)
        {
            requests.emplace_back(session.Create([&]() noexcept { ++wakes; }));
        }
        assert(session.PendingCount() == requests.size());

        assert(session.Cancel(requests.front()));
        assert(session.PendingCount() + 1 == requests.size());
        session.Deactivate();

        assert(session.PendingCount() == 0);
        assert(session.RunningCount() == 0);
        assert(wakes.load() == static_cast<int>(requests.size()));
        for (const auto& request : requests)
        {
            assert(request->GetState() == RequestState::Cancelled);
            assert(!request->Result());
            assert(!request->Cancel());
        }
        assert(wakes.load() == static_cast<int>(requests.size()));
    }

    void TestRequestAndSessionReleased()
    {
        std::weak_ptr<ProtectorNetworkRequestSession> weak_session;
        std::weak_ptr<ProtectorNetworkRequest> weak_request;
        std::packaged_task<void()> retained_handler;
        {
            auto session = std::make_shared<ProtectorNetworkRequestSession>(4001);
            auto request = session->Create([]() noexcept {});
            weak_session = session;
            weak_request = request;
            retained_handler = std::packaged_task<void()>(
                [weak_session, weak_request]() noexcept {
                    assert(weak_session.expired());
                    assert(weak_request.expired());
                });

            session->Deactivate();
            request.reset();
            session.reset();
        }

        // A handler retained forever by a stopped executor owns only weak tokens.
        assert(weak_session.expired());
        assert(weak_request.expired());
        retained_handler();
    }
}

int main()
{
    TestCompletionBeforeSuspend();
    TestDetachBeforeCallback();
    TestCallbackDetachRace();
    TestOldGenerationIsolation();
    TestPendingCancellationWakesOnce();
    TestRequestAndSessionReleased();
    return 0;
}
