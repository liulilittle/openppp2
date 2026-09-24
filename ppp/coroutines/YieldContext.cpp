#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>
#if defined(PPP_COROUTINES_TSAN_ENABLED)
#include <sanitizer/tsan_interface.h>
#endif

namespace ppp
{
    namespace coroutines
    {
        /**
         * @file YieldContext.cpp
         * @brief Implements stackful coroutine state transitions and scheduling glue.
         */

        /** @brief State: coroutine is currently resumed/running. */
        static constexpr int STATUS_RESUMED    = 0;
        /** @brief State: coroutine is entering suspend transition. */
        static constexpr int STATUS_SUSPENDING = 1;
        /** @brief State: coroutine is fully suspended and resumable. */
        static constexpr int STATUS_SUSPEND    = 2;
        /** @brief State: coroutine is entering resume transition. */
        static constexpr int STATUS_RESUMING   = -1;
        /** @brief State: coroutine handler returned; the context is being reclaimed. */
        static constexpr int STATUS_COMPLETED  = 3;

        /**
         * @brief Constructs a coroutine context and allocates stack memory.
         */
        YieldContext::YieldContext(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn, int stack_size) noexcept
            : s_(0)
            , callee_(NULLPTR)
            , caller_(NULLPTR)
            , h_(std::move(spawn))
            , context_(context)
            , strand_(strand)
            , stack_size_(stack_size)
            , allocator_(allocator)
        {
            std::shared_ptr<ppp::threading::BufferswapAllocator> heap;
            if (allocator) 
            {
                heap = allocator->shared_from_this();
            }

            stack_ = ppp::threading::BufferswapAllocator::MakeByteArray(heap, stack_size);
#if defined(PPP_COROUTINES_TSAN_ENABLED)
            sanitizer_fiber_ = __tsan_create_fiber(0);
#endif
        }

        /** @brief Releases references and owned state fields. */
        YieldContext::~YieldContext() noexcept
        {
            YieldContext* y = this;
#if defined(PPP_COROUTINES_TSAN_ENABLED)
            if (y->sanitizer_fiber_)
            {
                __tsan_destroy_fiber(y->sanitizer_fiber_);
                y->sanitizer_fiber_ = NULLPTR;
            }
            y->sanitizer_caller_fiber_ = NULLPTR;
#endif
            y->h_          = NULLPTR;
            y->stack_      = NULLPTR;
            y->stack_size_ = 0;
            y->strand_     = NULLPTR;
            y->allocator_  = NULLPTR;
        }

        /** @brief Suspends execution and switches back to caller context. */
        bool YieldContext::Suspend() noexcept
        {
            YieldContext* y = this;
            {
                std::lock_guard<std::mutex> scope(y->syncobj_);
                if (y->wakeup_pending_)
                {
                    /**
                     * @brief A completion was latched before this suspend could park
                     *        (completion-before-suspend); consume it without blocking.
                     */
                    y->wakeup_pending_ = false;
                    return true;
                }

                if (y->s_.load() != STATUS_RESUMED)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                    return false;
                }

                y->s_.store(STATUS_SUSPENDING);
            }

            /** @brief The mutex is released before jumping; never hold it across fcontext switches. */
#if defined(PPP_COROUTINES_TSAN_ENABLED)
            __tsan_switch_to_fiber(y->sanitizer_caller_fiber_, 0);
#endif
            y->caller_.exchange(
                boost::context::detail::jump_fcontext(
                    y->caller_.exchange(NULLPTR), y).fctx);

            {
                /** @brief The resumer published STATUS_RESUMING before jumping back in. */
                std::lock_guard<std::mutex> scope(y->syncobj_);
                y->s_.store(STATUS_RESUMED);
            }

            return true;
        }

        /** @brief Resumes execution from suspended coroutine context. */
        bool YieldContext::Resume() noexcept
        {
            YieldContext* y = this;
            {
                std::lock_guard<std::mutex> scope(y->syncobj_);
                int status = y->s_.load();
                if (status == STATUS_SUSPEND)
                {
                    y->s_.store(STATUS_RESUMING);
                }
                else if (status == STATUS_RESUMED || status == STATUS_SUSPENDING)
                {
                    /**
                     * @brief The coroutine has not published its park point yet (it is
                     *        still running, or is in the middle of the suspend handoff).
                     *        Latch the wakeup so the pending Suspend() consumes it;
                     *        dropping it here permanently hangs the coroutine when the
                     *        io_context is driven by more than one run() thread.
                     */
                    y->wakeup_pending_ = true;
                    return true;
                }
                else
                {
                    /** @brief STATUS_RESUMING (duplicate wakeup) or STATUS_COMPLETED. */
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                    return false;
                }
            }

#if defined(PPP_COROUTINES_TSAN_ENABLED)
            y->sanitizer_caller_fiber_ = __tsan_get_current_fiber();
            __tsan_switch_to_fiber(y->sanitizer_fiber_, 0);
#endif
            return Switch(
                boost::context::detail::jump_fcontext(
                    y->callee_.exchange(NULLPTR), y), y);
        }

        /**
         * @brief Creates coroutine fcontext and performs initial handoff.
         */
        void YieldContext::Invoke() noexcept
        {
            YieldContext* y = this;
            Byte* stack = stack_.get(); 

            if (stack)
            {
                boost::context::detail::fcontext_t callee =
                    boost::context::detail::make_fcontext(stack + stack_size_, stack_size_, &YieldContext::Handle);
#if defined(PPP_COROUTINES_TSAN_ENABLED)
                y->sanitizer_caller_fiber_ = __tsan_get_current_fiber();
                __tsan_switch_to_fiber(y->sanitizer_fiber_, 0);
#endif
                Switch(boost::context::detail::jump_fcontext(callee, y), y);
            }
            else
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                YieldContext::Release(y);
            }
        }

        /** @brief Performs guarded fcontext jump only when target is valid. */
        boost::context::detail::transfer_t YieldContext::Jump(boost::context::detail::fcontext_t context, void* state) noexcept
        {
            if (context) 
            {
                return boost::context::detail::jump_fcontext(context, state);
            }

            return boost::context::detail::transfer_t{ NULLPTR, NULLPTR };
        }

        /**
         * @brief Publishes the suspended state, or consumes a wakeup that raced the
         *        suspend handoff and requests immediate re-entry.
         */
        bool YieldContext::Switch() noexcept
        {
            YieldContext* y = this;
            std::lock_guard<std::mutex> scope(y->syncobj_);

            if (y->s_.load() != STATUS_SUSPENDING)
            {
                /** @brief Defensive: the suspend handoff is single-threaded, so this is unreachable. */
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                return true;
            }

            if (y->wakeup_pending_)
            {
                /**
                 * @brief A wakeup raced the suspend handoff; consume it and tell the
                 *        caller to re-enter the coroutine immediately so the suspend
                 *        never blocks.
                 */
                y->wakeup_pending_ = false;
                y->s_.store(STATUS_RESUMING);
                return false;
            }

            y->s_.store(STATUS_SUSPEND);
            return true;
        }

        /**
         * @brief Stores transfer context and finishes one switch cycle.
         */
        bool YieldContext::Switch(const boost::context::detail::transfer_t& t, YieldContext* y) noexcept
        {
            if (!t.data)
            {
                /** @brief Coroutine handler returned; mark completed and reclaim. */
                {
                    std::lock_guard<std::mutex> scope(y->syncobj_);
                    y->s_.store(STATUS_COMPLETED);
                }

                YieldContext::Release(y);
                return true;
            }

            y->callee_.exchange(t.fctx);
            while (!y->Switch())
            {
                /**
                 * @brief A wakeup was latched while the coroutine was parking; re-enter
                 *        it immediately so the suspend is never allowed to block.
                 */
#if defined(PPP_COROUTINES_TSAN_ENABLED)
                y->sanitizer_caller_fiber_ = __tsan_get_current_fiber();
                __tsan_switch_to_fiber(y->sanitizer_fiber_, 0);
#endif
                boost::context::detail::transfer_t r =
                    boost::context::detail::jump_fcontext(
                        y->callee_.exchange(NULLPTR), y);

                if (!r.data)
                {
                    {
                        std::lock_guard<std::mutex> scope(y->syncobj_);
                        y->s_.store(STATUS_COMPLETED);
                    }

                    YieldContext::Release(y);
                    return true;
                }

                y->callee_.exchange(r.fctx);
            }

            return true;
        }

        /**
         * @brief Coroutine trampoline that executes the user handler and performs final
         *        context handoff back to the caller.
         *
         * @param t  Transfer descriptor injected by jump_fcontext; t.data points to the
         *           owning YieldContext instance.
         *
         * @note  This function MUST be declared noexcept.  It is registered as the entry
         *        point for a Boost.Context fcontext stack via make_fcontext().  Any C++
         *        exception that propagates out of an fcontext trampoline crosses stack
         *        frames that were not constructed with exception support, producing
         *        undefined behaviour (typically silent memory corruption or a crash at
         *        the next unwind table lookup).
         *
         *        The error condition previously guarded by a throw — a non-null callee_
         *        after the final Jump() — indicates that a completed coroutine was
         *        accidentally resumed.  This is a caller-side programming error.  At
         *        this level we cannot throw, so we clear the stale callee_ reference
         *        and release the context to prevent a second invalid jump and a memory
         *        leak.
         */
        void YieldContext::Handle(boost::context::detail::transfer_t t) noexcept
        {
            YieldContext* y = (YieldContext*)t.data;
            if (y)
            {
                SpawnHander h = std::move(y->h_);
                y->h_ = NULLPTR;
                y->caller_.exchange(t.fctx);

                if (h)
                {
                    try
                {
                    h(*y);
                    }
                    catch (const std::exception&)
                    {
                        /* An exception escaping the handler would cross the fcontext
                         * boundary below (undefined behaviour per Boost.Context). Catch
                         * every exception here and convert it into an error code so the
                         * coroutine terminates gracefully instead of crashing. */
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineHandlerException);
                    }
                    catch (...)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineHandlerException);
                    }

                    h = NULLPTR;
                }

#if defined(PPP_COROUTINES_TSAN_ENABLED)
                __tsan_switch_to_fiber(y->sanitizer_caller_fiber_, 0);
#endif
                Jump(y->caller_.exchange(NULLPTR), NULLPTR);

                // If execution reaches here the coroutine was resumed after completion.
                // This is a programming error (caller-side bug) that we cannot repair.
                // Clear the stale callee reference to prevent a second invalid jump,
                // then release the context so its memory is reclaimed.
                // We must NOT throw: propagating an exception across an fcontext
                // boundary is undefined behaviour per Boost.Context documentation.
                y->callee_.exchange(NULLPTR);
                YieldContext::Release(y);
            }
        }
 
        /**
         * @brief Allocates and schedules a new coroutine on context or strand.
         */
        bool YieldContext::Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn, int stack_size) noexcept
        {
            if (!spawn)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::YieldContextSpawnNullHandler);
                return false;
            }

            stack_size = std::max<int>(stack_size, PPP_MEMORY_ALIGNMENT_SIZE);
#if defined(PPP_COROUTINES_TSAN_ENABLED)
            /** @brief TSan instrumentation needs substantially more stack than production code. */
            stack_size = std::max<int>(stack_size, 1 << 20);
#endif

            /**
             * @brief Instantiates context object before posting execution.
             *
             * Execution runs immediately when posting from the owner thread;
             * otherwise it is queued and driven by the context event loop.
             */
            YieldContext* y = New<YieldContext>(allocator, context, strand, std::move(spawn), stack_size);
            if (!y)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineSpawnFailed);
                return false;
            }

            /** @brief Posted callable that starts coroutine invocation. */
            auto invoked =
                [y]() noexcept -> void
                {
                    y->Invoke();
                };

            if (strand)
            {
                boost::asio::post(*strand, invoked);
            }
            else
            {
                boost::asio::post(context, invoked);
            }

            return true;
        }

        /**
         * @brief Posts a resume request to the strand or context.
         * @note Resume() latches the wakeup when the coroutine has not finished parking
         *       yet, so a completion racing Suspend() is consumed by that Suspend()
         *       instead of being dropped.  Resume() only fails on a duplicate wakeup
         *       (STATUS_RESUMING) or after the coroutine has completed.
         */
        bool YieldContext::R() noexcept
        {
            YieldContext* y = this;
            auto invoked =
                [y]() noexcept -> void
                {
                    bool resumed = y->Resume();
                    if (!resumed)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                    }
                };

            boost::asio::io_context* context = &y->context_;
            bool ok = ppp::threading::Executors::Post(context, y->strand_, invoked);
            if (!ok)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
            }

            return ok;
        }
    }
}
