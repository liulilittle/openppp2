#pragma once

/**
 * @file YieldContext.h
 * @brief Declares the stackful coroutine yield/resume context used throughout the PPP
 *        event-driven state machine (EDSM) infrastructure.
 *
 * @details
 * ## Design Overview
 *
 * `YieldContext` is a manually-managed, stackful coroutine context that integrates with
 * Boost.Asio's `io_context` execution model without relying on `boost::asio::spawn` or
 * `boost::coroutines2`.  Instead it owns a raw `boost::context::fcontext_t` stack and
 * performs symmetric context switches via `boost::context::detail::jump_fcontext`.
 *
 * ### Lifecycle
 * ```
 * io_context thread                coroutine stack
 *      |                                 |
 *      |-- YieldContext::Spawn() ------->|  (allocates stack, posts first Resume)
 *      |                                 |
 *      |<-- asio::post fires Resume() ---|
 *      |       jump_fcontext  ---------->|  SpawnHander(yield) runs
 *      |                                 |
 *      |           [async I/O needed]    |
 *      |<----------- Suspend() ----------|  jump back to caller
 *      |                                 |
 *      |    [I/O completion callback]    |
 *      |---------- R() / Resume() ------>|  jump back to coroutine
 *      |                                 |
 *      |           [handler returns]     |
 *      |<----------- ~YieldContext() ----|  stack freed
 * ```
 *
 * ### `nullof<YieldContext>()` — Synchronous vs Asynchronous Mode
 *
 * Many functions in this project accept a `YieldContext&` parameter.  The parameter
 * is tested against `nullof<YieldContext>()` at the call site:
 *
 * ```cpp
 * // Inside an async helper:
 * if (&y == nullof<YieldContext>()) {
 *     // Caller does NOT have a coroutine context — block the calling thread
 *     // using a std::condition_variable or similar synchronisation primitive.
 * } else {
 *     // Caller IS running inside a coroutine — suspend via y.Suspend(),
 *     // post a wakeup, and resume transparently.
 * }
 * ```
 *
 * `nullof<YieldContext>()` returns a pointer whose address is a sentinel value
 * (typically the address of a static null object).  Passing this sentinel instead of
 * a real `YieldContext&` signals "synchronous / thread-blocking mode".  This is **not**
 * undefined behaviour — the framework explicitly defines and relies on this convention.
 * **Do not remove or modify this pattern.**
 *
 * @note  `YieldContext` is non-copyable and non-movable.  Instances are created
 *        exclusively through the `Spawn` family of static factory methods and destroyed
 *        automatically when the coroutine handler returns.
 * @note  All `Spawn` overloads are thread-safe with respect to the target `io_context`.
 * @note  `Resume()` and `Suspend()` may only be called from threads that own the
 *        associated `io_context` run-loop — calling from an unrelated thread causes
 *        undefined behaviour.
 */

#include <ppp/stdafx.h>
#include <boost/coroutine/detail/coroutine_context.hpp>
#include <boost/context/detail/fcontext.hpp>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp
{
    namespace coroutines
    {
        /**
         * @brief Stackful coroutine context integrated with Boost.Asio execution.
         *
         * @details
         * Each `YieldContext` instance encapsulates a dedicated stack allocation and a
         * pair of `fcontext_t` handles (`callee_` / `caller_`) that represent the
         * bidirectional jump targets between the coroutine body and the Asio event loop.
         *
         * The state flag `s_` is guarded by `syncobj_` and serialises concurrent
         * `Resume()` / `Suspend()` calls.  A wakeup (`Resume()` / `R()`) that arrives
         * while the coroutine is still running, or while it is in the middle of its
         * suspend handoff, is latched into `wakeup_pending_` instead of being dropped;
         * the next `Suspend()` consumes the latch and returns without blocking.  This
         * makes the completion-before-suspend interleaving impossible to lose when the
         * owning `io_context` is executed by more than one `run()` thread.  The mutex
         * is never held across a `jump_fcontext` call.
         *
         * @warning Never construct directly — use the `Spawn` static factory methods.
         */
        class YieldContext final
        {
        public:
            /**
             * @brief Coroutine entry handler signature.
             * @details The handler receives a reference to the owning `YieldContext`.
             *          It may call `y.Suspend()` / `y.R()` to yield control back to the
             *          Asio event loop and be resumed later.  When the handler returns the
             *          coroutine terminates and the `YieldContext` is automatically destroyed.
             */
            typedef ppp::function<void(YieldContext&)>                          SpawnHander;

        public:
            /**
             * @brief Attempts to resume a suspended coroutine context.
             * @return true  when the context switch succeeded and the coroutine ran until
             *               its next `Suspend()` call or completion.
             * @return false when the coroutine is already running, has completed, or the
             *               internal state machine transition was rejected.
             * @note  Must be called from the thread that runs the associated `io_context`.
             */
            bool                                                                Resume() noexcept;

            /**
             * @brief Suspends the currently executing coroutine and returns control to the caller.
             * @return true  when the suspend-and-switch succeeded.
             * @return false when called outside of a valid coroutine context or when the
             *               state transition is inconsistent.
             * @note  Must only be invoked from within the `SpawnHander` body.
             */
            bool                                                                Suspend() noexcept;

            /**
             * @brief Returns a raw pointer to this instance.
             * @return Non-null pointer to the current `YieldContext`.
             * @note  Useful when the caller needs to store or compare the address.
             */
            YieldContext*                                                       GetPtr() const noexcept        { return constantof(this);}

            /**
             * @brief Returns a reference to the bound Asio I/O context.
             * @return Reference to the `io_context` supplied at construction.
             */
            boost::asio::io_context&                                            GetContext() const noexcept    { return context_; }

            /**
             * @brief Returns the optional strand bound at construction time.
             * @return Pointer to the strand, or `NULLPTR` when none was provided.
             * @note  When non-null, `Resume()` posts through this strand to guarantee
             *        serialised handler execution.
             */
            boost::asio::strand<boost::asio::io_context::executor_type>*        GetStrand() const noexcept     { return strand_; }

        public:
            /**
             * @brief Returns whether the internal state flag `s_` is non-zero.
             * @return true when the coroutine is in an active/suspended state.
             */
            bool                                                                S() noexcept { return s_.load() != 0; }

            /**
             * @brief Convenience alias for `Suspend()`.
             * @return Result of `Suspend()`.
             */
            bool                                                                Y() noexcept { return Suspend(); }

            /**
             * @brief Posts a `Resume()` call back to the bound executor asynchronously.
             * @return true when the post was submitted successfully.
             * @note  This is the preferred wakeup path from async completion callbacks
             *        because it re-enters the coroutine on the correct execution context.
             */
            bool                                                                R() noexcept;

        public:
            /**
             * @brief Implicit boolean conversion — always true for a non-null `this`.
             * @return true unconditionally (the instance exists).
             * @note  Callers can write `if (yield)` to test whether a real context was
             *        passed vs. the `nullof<YieldContext>()` sentinel.
             */
            operator                                                            bool() const noexcept          { return NULLPTR != GetPtr(); }

            /**
             * @brief Implicit conversion to raw pointer.
             * @return Same value as `GetPtr()`.
             */
            operator                                                            YieldContext*() const noexcept { return GetPtr();         }

        public:
            /**
             * @brief Spawns a coroutine on `context` using the default stack size.
             * @param context Asio I/O context that will own the coroutine's execution.
             * @param spawn   Coroutine entry handler; called with a valid `YieldContext&`.
             * @return true when the coroutine was successfully scheduled.
             */
            static bool                                                         Spawn(boost::asio::io_context& context, SpawnHander&& spawn) noexcept
            {
                return YieldContext::Spawn(context, std::move(spawn), PPP_COROUTINE_STACK_SIZE);
            }

            /**
             * @brief Spawns a coroutine on `context` with an explicit stack size.
             * @param context    Asio I/O context that will own the coroutine's execution.
             * @param spawn      Coroutine entry handler.
             * @param stack_size Stack size in bytes for the new coroutine.
             * @return true when the coroutine was successfully scheduled.
             */
            static bool                                                         Spawn(boost::asio::io_context& context, SpawnHander&& spawn, int stack_size) noexcept
            {
                ppp::threading::BufferswapAllocator* allocator = NULLPTR;
                return YieldContext::Spawn(allocator, context, std::move(spawn), stack_size);
            }

            /**
             * @brief Spawns a coroutine with an optional custom memory allocator and default stack.
             * @param allocator  Custom allocator for the `YieldContext` object itself; may be null.
             * @param context    Asio I/O context that will own the coroutine's execution.
             * @param spawn      Coroutine entry handler.
             * @return true when the coroutine was successfully scheduled.
             */
            static bool                                                         Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, SpawnHander&& spawn) noexcept
            {
                return YieldContext::Spawn(allocator, context, std::move(spawn), PPP_COROUTINE_STACK_SIZE);
            }

            /**
             * @brief Spawns a coroutine with a custom allocator and explicit stack size.
             * @param allocator  Custom allocator for the `YieldContext` object itself; may be null.
             * @param context    Asio I/O context that will own the coroutine's execution.
             * @param spawn      Coroutine entry handler.
             * @param stack_size Stack size in bytes for the new coroutine.
             * @return true when the coroutine was successfully scheduled.
             */
            static bool                                                         Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, SpawnHander&& spawn, int stack_size) noexcept
            {
                boost::asio::strand<boost::asio::io_context::executor_type>* strand = NULLPTR;
                return YieldContext::Spawn(allocator, context, strand, std::move(spawn), PPP_COROUTINE_STACK_SIZE);
            }

            /**
             * @brief Spawns a coroutine bound to an optional strand, using default stack size.
             * @param allocator Custom allocator for the `YieldContext` object itself; may be null.
             * @param context   Asio I/O context that will own the coroutine's execution.
             * @param strand    Optional strand; when non-null, all resume posts go through it.
             * @param spawn     Coroutine entry handler.
             * @return true when the coroutine was successfully scheduled.
             */
            static bool                                                         Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn)
            {
                return YieldContext::Spawn(allocator, context, strand, std::move(spawn), PPP_COROUTINE_STACK_SIZE);
            }

            /**
             * @brief Primary `Spawn` overload with full control over all parameters.
             * @param allocator  Custom allocator for the `YieldContext` object itself;
             *                   null selects default heap allocation via `Malloc`.
             * @param context    Asio I/O context that will schedule the coroutine.
             * @param strand     Optional strand for serialised resume dispatch; may be null.
             * @param spawn      Coroutine entry handler; ownership is transferred.
             * @param stack_size Stack size in bytes; values below a platform minimum are
             *                   clamped automatically.
             * @return true when the `YieldContext` was allocated, the stack was allocated,
             *         and the first resume was posted to `context` successfully.
             * @return false on allocation failure or invalid parameters.
             * @note  The `YieldContext` object's lifetime is managed internally; it is
             *        destroyed automatically when `spawn` returns.
             */
            static bool                                                         Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn, int stack_size) noexcept;

        private:
            /**
             * @brief Allocates the coroutine stack and performs the initial context switch.
             * @note  Called once from within the Asio thread after the first `Resume()` fires.
             */
            void                                                                Invoke() noexcept;

            /** @brief Coroutine entry-point trampoline; must be noexcept (cannot throw across fcontext). */
            static void                                                         Handle(boost::context::detail::transfer_t t) noexcept;

            /**
             * @brief Publishes the fully-suspended state after the coroutine jumped out.
             * @return true  when the coroutine was parked (`STATUS_SUSPEND`); the caller
             *               must return to the event loop.
             * @return false when a latched wakeup was consumed instead; the caller must
             *               immediately re-enter the coroutine (the suspend must not block).
             * @note  Must be called without holding `syncobj_`; the lock is taken internally.
             */
            bool                                                                Switch() noexcept;

            /**
             * @brief Stores the inbound transfer and completes the switch step.
             * @details When the coroutine completed (`t.data` is null) the context is
             *          marked `STATUS_COMPLETED` and released.  Otherwise the coroutine
             *          park point is stored and `Switch()` publishes the suspended state;
             *          while a latched wakeup remains outstanding the coroutine is
             *          re-entered immediately until it parks with no wakeup pending.
             * @param t Transfer structure from `jump_fcontext`.
             * @param y Pointer to the owning `YieldContext`; used to update `caller_`.
             * @return true on success.
             */
            static bool                                                         Switch(const boost::context::detail::transfer_t& t, YieldContext* y) noexcept;

        private:
            template <typename T, typename... A>
            /**
             * @brief Allocates and constructs an object via an optional custom allocator.
             * @tparam T  Type to construct.
             * @tparam A  Constructor argument pack.
             * @param allocator Custom allocator; null selects `Malloc`.
             * @param args      Forwarded constructor arguments.
             * @return Pointer to the newly constructed object, or `NULLPTR` on failure.
             * @note  Memory is zero-initialized before placement-new to satisfy
             *        `-Wdynamic-class-memaccess` requirements.
             */
            static T*                                                           New(ppp::threading::BufferswapAllocator* allocator, A&&... args) noexcept
            {
                if (NULLPTR == allocator)
                {
                    void* memory = Malloc(sizeof(T));
                    if (NULLPTR == memory)
                    {
                        return NULLPTR;
                    }

                    memset(memory, 0, sizeof(T)); /* -Wdynamic-class-memaccess */
                    return new (memory) T(allocator, std::forward<A&&>(args)...);
                }
                else
                {
                    void* memory = allocator->Alloc(sizeof(T));
                    if (NULLPTR == memory)
                    {
                        allocator = NULLPTR;
                        return New<T>(allocator, std::forward<A&&>(args)...);
                    }

                    memset(memory, 0, sizeof(T)); /* -Wdynamic-class-memaccess */
                    return new (memory) T(allocator, std::forward<A&&>(args)...);
                }
            }

            template <typename T>
            /**
             * @brief Destroys and frees an object created by `New`.
             * @tparam T Object type; destructor is called explicitly before deallocation.
             * @param p  Pointer to the object; no-op when null.
             * @return true when the object was destroyed; false when `p` is null.
             */
            static bool                                                         Release(T* p) noexcept
            {
                if (NULLPTR == p)
                {
                    return false;
                }

                ppp::threading::BufferswapAllocator* const allocator = p->allocator_;
                p->~T();

                if (NULLPTR == allocator)
                {
                    Mfree(p);
                }
                else
                {
                    allocator->Free(p);
                }

                return true;
            }

            /**
             * @brief Performs a safe `jump_fcontext` when the target context handle is valid.
             * @param context Destination fcontext handle.
             * @param state   User data pointer passed through the jump.
             * @return The transfer structure returned by `jump_fcontext`.
             */
            static boost::context::detail::transfer_t                           Jump(boost::context::detail::fcontext_t context, void* state) noexcept;

        private:
            /** @brief Default construction is deleted — use `Spawn` factory methods. */
            YieldContext() = delete;
            /** @brief Move construction is deleted — context handles are not relocatable. */
            YieldContext(YieldContext&&) = delete;
            /** @brief Copy construction is deleted — each coroutine owns unique stack storage. */
            YieldContext(const YieldContext&) = delete;

            /**
             * @brief Internal constructor invoked only by `Spawn`.
             * @param allocator  Allocator used to create this object; stored for `Release`.
             * @param context    Asio I/O context bound for the lifetime of this coroutine.
             * @param strand     Optional strand for serialised resume dispatch.
             * @param spawn      Coroutine entry handler; ownership transferred.
             * @param stack_size Requested stack size in bytes.
             */
            YieldContext(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn, int stack_size) noexcept;

            /**
             * @brief Destroys the coroutine context and releases the stack allocation.
             * @note  Destructor is private; `Release<YieldContext>` is the intended
             *        deallocation path — do not call `delete` directly.
             */
            ~YieldContext() noexcept;

        private:
            /** @brief Coroutine state flag (`STATUS_*`); written under `syncobj_`, read lock-free by `S()`. */
            std::atomic<int>                                                    s_          = 0;
            /** @brief Guards `s_` / `wakeup_pending_` transitions; never held across `jump_fcontext`. */
            std::mutex                                                          syncobj_;
            /** @brief Latched wakeup consumed by the next `Suspend()` (completion-before-suspend). */
            bool                                                                wakeup_pending_ = false;
            /** @brief Stored callee (coroutine) context handle; updated on each switch. */
            std::atomic<boost::context::detail::fcontext_t>                     callee_     = NULLPTR;
            /** @brief Stored caller (event loop) context handle; updated on each switch. */
            std::atomic<boost::context::detail::fcontext_t>                     caller_     = NULLPTR;
            /** @brief User-provided coroutine entry function. */
            SpawnHander                                                         h_;
            /** @brief Associated Asio I/O context; lifetime must exceed this object. */
            boost::asio::io_context&                                            context_;
            /** @brief Optional strand for serialised callback dispatch; may be null. */
            boost::asio::strand<boost::asio::io_context::executor_type>*        strand_;
            /** @brief Allocated coroutine stack size in bytes. */
            int                                                                 stack_size_ = 0;
            /** @brief Backing storage for the coroutine stack; freed on destruction. */
            std::shared_ptr<Byte>                                               stack_;
            /** @brief Allocator used to allocate this object; null means heap via `Malloc`. */
            ppp::threading::BufferswapAllocator*                                allocator_  = NULLPTR;
#if defined(PPP_COROUTINES_TSAN_ENABLED)
            /** @brief ThreadSanitizer identity for the coroutine stack. */
            void*                                                               sanitizer_fiber_ = NULLPTR;
            /** @brief ThreadSanitizer identity of the Asio runner currently calling in. */
            void*                                                               sanitizer_caller_fiber_ = NULLPTR;
#endif
        };
    }
}
