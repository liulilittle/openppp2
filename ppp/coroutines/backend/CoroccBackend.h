#pragma once

#include <corocc/coro_ctx.h>
#include <atomic>
#include <cstdlib>
#include <new>
#include <memory>
#if defined(PPP_COROUTINES_ASAN_ENABLED)
#include <sanitizer/common_interface_defs.h>
#endif

namespace ppp { namespace coroutines { namespace backend {
struct ContextRecord;
using Context = ContextRecord*;
inline constexpr const char* Name = "corocc";
struct Transfer { Context fctx; void* data; };

// One stable record per stack. The thread's root record is borrowed, never
// destroyed through coro_ctx_destroy (its TSan fiber belongs to the thread).
struct ContextRecord {
    coro_ctx native{};
    coro_stack stack{};
    Transfer incoming{};
    void (*entry)(Transfer) = nullptr;
#if defined(PPP_COROUTINES_ASAN_ENABLED)
    void* asan_fake = nullptr;
#endif
};

#if defined(_MSC_VER)
__declspec(noinline)
#else
__attribute__((noinline))
#endif
inline Context& Current() noexcept {
    // Keep TLS address calculation inside this call: a suspended stack can
    // resume on another OS thread. The fence prevents a pure/const accessor.
    std::atomic_signal_fence(std::memory_order_seq_cst);
    static thread_local ContextRecord root;
    static thread_local Context current = &root;
    return current;
}

inline void Arrive(Context self) noexcept {
#if defined(PPP_COROUTINES_ASAN_ENABLED)
    const void* bottom = nullptr;
    std::size_t size = 0;
    __sanitizer_finish_switch_fiber(self->asan_fake, &bottom, &size);
    // Discover the actual root thread stack on first entry. Its record is
    // different after migration; every transfer publishes the current source.
    auto source = self->incoming.fctx;
    source->stack.lo = const_cast<void*>(bottom);
    source->stack.usable = size;
    source->native.stack = &source->stack;
#else
    (void)self;
#endif
}

inline void Enter(void* state) noexcept {
    auto self = static_cast<Context>(state);
    Current() = self;
    Arrive(self);
    self->entry(self->incoming);
    // YieldContext always hands off explicitly, including completion. Returning
    // here would bypass the adapter's transfer protocol.
    std::abort();
}

inline Context Make(void* top, std::size_t size, void (*entry)(Transfer)) noexcept {
    auto self = new (std::nothrow) ContextRecord;
    if (!self) return nullptr;
    // L0 consumes a borrowed range; ownership remains with BufferswapAllocator.
    // coro_stack's range fields are the pinned L0 ABI (no borrowed-range API).
    self->stack.lo = static_cast<char*>(top) - size;
    self->stack.usable = size;
    self->entry = entry;
    if (coro_ctx_init(&self->native, &self->stack, Enter, self)) {
        delete self;
        return nullptr;
    }
    return self;
}

inline Transfer Switch(Context target, void* data, bool terminating) noexcept {
    Context self = Current();
    target->incoming = {self, data};
    Current() = target;
#if defined(PPP_COROUTINES_ASAN_ENABLED)
    __sanitizer_start_switch_fiber(terminating ? nullptr : &self->asan_fake,
        target->stack.lo, target->stack.usable);
#else
    (void)terminating;
#endif
    coro_ctx_swap(&self->native, &target->native);
    // Do not restore a TLS reference saved before swap: it may be from a
    // different worker. incoming is written by the actual new resumer.
    Current() = self;
    Arrive(self);
    return self->incoming;
}

inline Transfer Jump(Context target, void* data) noexcept { return Switch(target, data, false); }
inline Transfer Finish(Context target, void* data) noexcept { return Switch(target, data, true); }

inline void Destroy(Context self) noexcept {
    if (!self) return;
    coro_ctx_destroy(&self->native);
    delete self;
}

#if defined(PPP_COROCC_GUARD_STACK)
inline std::shared_ptr<unsigned char> AllocateStack(int size) noexcept {
    coro_stack stack{};
    if (coro_stack_alloc(&stack, static_cast<std::size_t>(size))) return {};
    try {
        // shared_ptr invokes the deleter itself if its control allocation fails.
        return {static_cast<unsigned char*>(stack.lo), [stack](unsigned char*) mutable {
            coro_stack_free(&stack);
        }};
    } catch (...) {
        return {};
    }
}
#endif
}}}
