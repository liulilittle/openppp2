#include <ppp/coroutines/ContextBackend.h>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#if defined(_MSC_VER) && defined(_M_X64)
#include <windows.h>
#include <intrin.h>
#endif

namespace b = ppp::coroutines::backend;
static void check(bool ok) { if (!ok) std::abort(); }
#if defined(_MSC_VER) && defined(_M_X64)
static void check_native_stack() {
    char local;
    const auto address = reinterpret_cast<std::uintptr_t>(&local);
    check(address < __readgsqword(0x08) && address >= __readgsqword(0x10));
    // Exercise native SEH while executing on the alternate stack.
    int handled = 0;
    __try { RaiseException(0xE0000001, 0, 0, nullptr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { handled = 1; }
    check(handled == 1);
}
#else
static void check_native_stack() {}
#endif
struct Fiber {
    std::unique_ptr<char[]> stack{new char[128 * 1024]};
    b::Context context;
    explicit Fiber(void (*entry)(b::Transfer))
        : context(b::Make(stack.get() + 128 * 1024, 128 * 1024, entry)) { check(context != nullptr); }
    ~Fiber() {
#if defined(PPP_COROUTINE_BACKEND_COROCC)
        b::Destroy(context);
#endif
    }
};
struct State { int count = 0; int token = 42; };
static void ping(b::Transfer t) {
    auto& state = *static_cast<State*>(t.data);
    for (int i = 0; i < 500000; ++i) {
        if (i == 0) check_native_stack();
        check(t.fctx != nullptr && t.data == &state && state.token == 42);
        ++state.count;
        t = b::Jump(t.fctx, &state.token);
    }
    b::Finish(t.fctx, nullptr);
    std::abort();
}
static void child(b::Transfer t) {
    auto caller = t.fctx;
    check(*static_cast<int*>(t.data) == 42);
    t = b::Jump(caller, t.data);
    check(t.fctx != nullptr && *static_cast<int*>(t.data) == 43);
    b::Finish(t.fctx, nullptr);
    std::abort();
}
static void parent(b::Transfer t) {
    auto caller = t.fctx;
    int token = 42;
    {
        Fiber nested(child);
        auto r = b::Jump(nested.context, &token);
        check(r.data == &token);
        token = 43;
        r = b::Jump(r.fctx, &token);
        check(r.data == nullptr);
    }
    b::Finish(caller, nullptr);
    std::abort();
}
static void migrating(b::Transfer t) {
    for (int i = 0; i < 100; ++i) {
        check(t.fctx && t.data);
        ++*static_cast<int*>(t.data);
        t = b::Jump(t.fctx, t.data);
    }
    b::Finish(t.fctx, nullptr);
    std::abort();
}
struct Relay {
    b::Context root{};
    b::Context first{};
    b::Context second{};
    int phase = 0;
};
static void relay_second(b::Transfer t) {
    auto& relay = *static_cast<Relay*>(t.data);
    relay.first = t.fctx;
    check(relay.phase == 1);
    relay.phase = 2;
    t = b::Jump(relay.root, &relay);
    check(relay.phase == 3 && t.data == &relay);
    relay.phase = 4;
    t = b::Jump(relay.first, &relay);
    check(relay.phase == 5 && t.data == &relay);
    b::Finish(t.fctx, nullptr);
    std::abort();
}
static void relay_first(b::Transfer t) {
    auto& relay = *static_cast<Relay*>(t.data);
    relay.root = t.fctx;
    relay.phase = 1;
    t = b::Jump(relay.second, &relay);
    // The root resumed second, which resumed us. This return must identify
    // second, not the root that originally entered this coroutine.
    check(relay.phase == 4 && t.data == &relay);
    relay.second = t.fctx;
    relay.phase = 5;
    check(b::Jump(relay.second, &relay).data == nullptr);
    b::Finish(relay.root, nullptr);
    std::abort();
}
int main() {
#if defined(_MSC_VER) && defined(_M_X64)
    const std::array<unsigned __int64, 3> tib_before{
        __readgsqword(0x08), __readgsqword(0x10), __readgsqword(0x1478)};
#endif
    {
        State state;
        Fiber fiber(ping);
        auto context = fiber.context;
        const auto begin = std::chrono::steady_clock::now();
        for (int i = 0; i < 500000; ++i) {
            auto r = b::Jump(context, &state);
            check(r.data == &state.token && state.count == i + 1);
            context = r.fctx;
        }
        check(b::Jump(context, &state).data == nullptr);
        std::cout << "1000000 switches: "
            << std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - begin).count() / 1000000
            << " ns/switch\n";
    }
    { Fiber fiber(parent); check(b::Jump(fiber.context, nullptr).data == nullptr); }
    {
        Relay relay;
        Fiber first(relay_first), second(relay_second);
        relay.second = second.context;
        auto r = b::Jump(first.context, &relay);
        check(relay.phase == 2 && r.data == &relay);
        relay.phase = 3;
        check(b::Jump(r.fctx, &relay).data == nullptr);
        check(relay.phase == 5);
    }
    {
        Fiber fiber(migrating);
        auto context = fiber.context;
        int count = 0;
        // join provides the handoff happens-before; every resume uses a fresh
        // thread root, catching retained caller/TLS identity from earlier jumps.
        for (int i = 0; i <= 100; ++i) {
            b::Transfer r{};
            std::thread worker([&] { r = b::Jump(context, &count); });
            worker.join();
            check(count == (i < 100 ? i + 1 : 100));
            check((r.data == nullptr) == (i == 100));
            context = r.fctx;
        }
    }
    {
        Fiber fiber(migrating);
        auto context = fiber.context;
        int count = 0, turn = 0;
        bool done = false;
        std::mutex mutex;
        std::condition_variable ready;
        std::array<std::thread, 4> workers;
        for (int id = 0; id < 4; ++id) {
            workers[id] = std::thread([&, id] {
                for (;;) {
                    std::unique_lock<std::mutex> lock(mutex);
                    ready.wait(lock, [&] { return done || turn % 4 == id; });
                    if (done) return;
                    auto target = context;
                    lock.unlock();
                    auto r = b::Jump(target, &count);
                    lock.lock();
                    check(count == (turn < 100 ? turn + 1 : 100));
                    check((r.data == nullptr) == (turn == 100));
                    context = r.fctx;
                    done = ++turn == 101;
                    ready.notify_all();
                }
            });
        }
        for (auto& worker : workers) worker.join();
        check(count == 100 && turn == 101);
        std::cout << "four live workers: 101 handoffs passed\n";
    }
    std::cout << "roundtrip, nested, relay, migration, completion: passed\n";
#if defined(_MSC_VER) && defined(_M_X64)
    check(tib_before[0] == __readgsqword(0x08));
    check(tib_before[1] == __readgsqword(0x10));
    check(tib_before[2] == __readgsqword(0x1478));
#endif
}
