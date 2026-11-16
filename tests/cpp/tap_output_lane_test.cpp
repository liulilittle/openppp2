#include <ppp/tap/TapOutputLanePolicy.h>

#include <climits>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "line %d: %s\n", __LINE__, #x); std::abort(); } } while (0)

using namespace ppp::tap;

void DefaultSlotIsShared() {
    CHECK(SelectTapOutputLane(-1, true) == -1);
}

void ScopeNestsAndRestores() {
    CHECK(TapOutputLaneSlot() == -1);
    {
        TapOutputLaneScope outer(3);
        CHECK(TapOutputLaneSlot() == 3);
        {
            TapOutputLaneScope inner(5);
            CHECK(TapOutputLaneSlot() == 5);
        }
        CHECK(TapOutputLaneSlot() == 3);
    }
    CHECK(TapOutputLaneSlot() == -1);
}

void ThreadLocalIsolation() {
    std::mutex mutex;
    std::condition_variable changed;
    unsigned ready = 0;
    std::thread first([&] {
        TapOutputLaneScope scope(1);
        std::unique_lock<std::mutex> lock(mutex);
        if (++ready == 2) changed.notify_all();
        changed.wait(lock, [&] { return ready == 2; });
        CHECK(TapOutputLaneSlot() == 1);
    });
    std::thread second([&] {
        TapOutputLaneScope scope(2);
        std::unique_lock<std::mutex> lock(mutex);
        if (++ready == 2) changed.notify_all();
        changed.wait(lock, [&] { return ready == 2; });
        CHECK(TapOutputLaneSlot() == 2);
    });
    first.join(); second.join();
}

void OutOfRangeFallsBack() {
    CHECK(SelectTapOutputLane(-5, true) == -1);
    CHECK(SelectTapOutputLane(16, true) == -1);
    CHECK(SelectTapOutputLane(INT_MAX, true) == -1);
    CHECK(SelectTapOutputLane(0, true) == 0);
    CHECK(SelectTapOutputLane(15, true) == 15);
}

void DisabledLanesFallBack() {
    CHECK(SelectTapOutputLane(3, false) == -1);
}

int main() {
    DefaultSlotIsShared(); ScopeNestsAndRestores(); ThreadLocalIsolation(); OutOfRangeFallsBack(); DisabledLanesFallBack();
    std::puts("tap_output_lane_test: 5 groups passed");
}
