#include <ppp/stdafx.h>
#include <ppp/threading/Thread.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file Thread.cpp
 * @brief Implements managed thread lifecycle and TLS helpers.
 */

namespace ppp
{
    namespace threading
    {
        typedef std::mutex                          SynchronizedObject;
        typedef std::lock_guard<SynchronizedObject> SynchronizedObjectScope;
        typedef std::shared_ptr<Thread>             ThreadPtr;
        typedef ppp::unordered_map<int, ThreadPtr>  ThreadTable;

        /**
         * @brief Shared runtime table used to map OS thread ids to `Thread` instances.
         */
        struct ThreadInternal final
        {
            ThreadTable                             Threads;
            SynchronizedObject                      Lock;
        };

        static std::shared_ptr<ThreadInternal>      Internal;

        /**
         * @brief Initializes static runtime state for thread bookkeeping.
         */
        void Thread_cctor() noexcept 
        {
            Internal = ppp::make_shared_object<ThreadInternal>();
        }

        /**
         * @brief Constructs an idle thread wrapper.
         */
        Thread::Thread() noexcept
            : Id(0)
            , State(ThreadState::Stopped)
            , Priority(ThreadPriority::Normal)
        {

        }

        /**
         * @brief Constructs an idle thread wrapper with start callback.
         */
        Thread::Thread(const ThreadStart& start) noexcept
            : Thread()
        {
            _start = start;
        }

        /**
         * @brief Detaches the underlying thread during destruction.
         */
        Thread::~Thread() noexcept
        {
            Detach();
        }

        /**
         * @brief Detaches the underlying thread when possible.
         * @note  Serialized against `Join()` through `_lifecycle`; a concurrent
         *        `join()`/`detach()` on the same `std::thread` object is undefined
         *        behaviour. When a join is in progress this call is a no-op.
         */
        bool Thread::Detach() noexcept
        {
            SynchronizedObjectScope scope(_lifecycle);
            auto& t = _thread;
            if (_joining || !t.joinable())
            {
                return false;
            }

            try 
            {
                t.detach();
                return true;
            }
            catch (const std::exception&)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeThreadDetachFailed);
                return false;
            }
        }

        /**
         * @brief Gets the instance mutex used for state synchronization.
         */
        Thread::SynchronizedObject& Thread::GetSynchronizedObject() noexcept
        {
            return _syncobj;
        }

        /**
         * @brief Looks up the managed wrapper for the currently executing thread.
         */
        std::shared_ptr<Thread> Thread::GetCurrentThread() noexcept
        {
            SynchronizedObjectScope scope(Internal->Lock);
            auto tail = Internal->Threads.find(GetCurrentThreadId());
            auto endl = Internal->Threads.end();
            return tail != endl ? tail->second : NULLPTR;
        }

        /**
         * @brief Returns processor count from platform utility.
         */
        int Thread::GetProcessorCount() noexcept
        {
            return ppp::GetProcesserCount();
        }

        /**
         * @brief Joins the underlying thread when joinable.
         * @note  The blocking `join()` runs without holding `_lifecycle`: the worker
         *        thread's own `Detach()` needs that mutex to finish, so holding it
         *        across the join would deadlock. `_joining` is set under the lock to
         *        make `Detach()` back off, keeping `join()`/`detach()` serialized.
         */
        bool Thread::Join() noexcept
        {
            {
                SynchronizedObjectScope scope(_lifecycle);
                if (!_thread.joinable())
                {
                    return false;
                }

                _joining = true;
            }

            bool ok = false;
            try
            {
                _thread.join();
                ok = true;
            }
            catch (const std::exception&)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeThreadJoinFailed);
            }

            {
                SynchronizedObjectScope scope(_lifecycle);
                _joining = false;
            }

            return ok;
        }

        /**
         * @brief Starts the configured callback on a new std::thread.
         */
        bool Thread::Start() noexcept
        {
            ThreadStart start;
            {
                SynchronizedObjectScope scope(_lifecycle);
                if (_started || State != ThreadState::Stopped || Id != 0)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeThreadAlreadyStarted);
                    return false;
                }

                start = std::move(_start);
                _start = NULLPTR;

                if (NULLPTR == start)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeThreadEntryMissing);
                    return false;
                }

                /* One-shot wrapper: reject any further Start() from here on,
                 * even when std::thread construction below ends up throwing. */
                _started = true;
            }

            auto self = shared_from_this();
            /**
             * @brief Worker entry routine updating registration and lifecycle state.
             */
            auto thread_start = [this, self, start]() noexcept
                {
                    constantof(Id) = GetCurrentThreadId();
                    if (Priority != ThreadPriority::Normal)
                    {
                        SetThreadPriorityToMaxLevel();
                    }

                    constantof(State) = ThreadState::Running;
                    {
                        SynchronizedObjectScope scope(Internal->Lock);
                        Internal->Threads[Id] = self;
                    }

                    SetThreadName("fork");
                    start(this);

                    /* The thread handle is reclaimed by an external Join()
                     * or by ~Thread() -> Detach(); the worker must not detach
                     * itself here, otherwise a Join() holding `_lifecycle`
                     * while waiting for this worker would deadlock against
                     * this trailing Detach() locking the same mutex. */
                    constantof(State) = ThreadState::Stopped;
                    {
                        SynchronizedObjectScope scope(Internal->Lock);
                        auto tail = Internal->Threads.find(Id);
                        auto endl = Internal->Threads.end();
                        if (tail != endl)
                        {
                            Internal->Threads.erase(tail);
                        }
                    }
                };

            try {
                SynchronizedObjectScope scope(_lifecycle);
                _thread = std::thread(thread_start);
            }
            catch (const std::bad_alloc&)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return false;
            }
            catch (const std::exception&)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeThreadStartFailed);
                return false;
            }

            return true;
        }

        /**
         * @brief Reads a thread-local data slot.
         */
        void* Thread::GetData(int index) noexcept
        {
            SynchronizedObjectScope scope(_syncobj);
            auto tail = _tls.find(index);
            auto endl = _tls.end();
            if (tail == endl)
            {
                return NULLPTR;
            }
            else
            {
                return tail->second;
            }
        }

        /**
         * @brief Writes or removes a thread-local data slot.
         */
        void* Thread::SetData(int index, const void* value) noexcept
        {
            SynchronizedObjectScope scope(_syncobj);
            if (NULLPTR == value)
            {
                auto tail = _tls.find(index);
                auto endl = _tls.end();
                if (tail == endl)
                {
                    return NULLPTR;
                }

                void* result = tail->second;
                _tls.erase(tail);
                return result;
            }
            else
            {
                void*& storage = _tls[index];
                void* result = storage;
                storage = (void*)value;
                return result;
            }
        }

        /**
         * @brief Stores startup priority preference for this thread wrapper.
         */
        void Thread::SetPriority(ThreadPriority priority) noexcept
        {
            constantof(Priority) = priority;
        }
    }
}
