#include <ppp/threading/SpinLock.h>
#include <ppp/threading/Thread.h>

namespace ppp
{
    namespace threading
    {
        template <class LockObject>
        static constexpr bool Lock_TryEnter(
            LockObject&                                             lock,
            int                                                     loop,
            int                                                     timeout) noexcept
        {
            auto tryEnter = [&lock, timeout](uint64_t last) noexcept -> int
            {
                bool lockTaken = lock.TryEnter();
                if (lockTaken)
                {
                    return 1;
                }

                if (timeout < 0)
                {
                    return 0;
                }

                uint64_t now = GetTickCount();
                return static_cast<int64_t>(now - last) < timeout ? 0 : -1;
            };

            uint64_t last = GetTickCount();
            if (loop > -1)
            {
                for (int i = 0; i < loop; i++)
                {
                    int status = tryEnter(last);
                    if (status != 0)
                    {
                        return status > 0;
                    }
                }

                return false;
            }
            
            for (;;)
            {
                int status = tryEnter(last);
                if (status != 0)
                {
                    return status > 0;
                }
            }
        }

        template <class LockObject, class LockInternalObject, typename... TryEnterArguments>
        static constexpr bool RecursiveLock_TryEnter(LockObject&    lock, 
            LockInternalObject&                                     lock_internal, 
            volatile int64_t*                                       tid,
            std::atomic<int>&                                       reentries, 
            TryEnterArguments&&...                                  arguments)
        {
            int n = ++reentries;
            assert(n > 0);

            int64_t current_tid = GetCurrentThreadId(); /* std::hash<std::thread::id>{}(std::this_thread::get_id()); */
            if (n == 1)
            {
                bool lockTaken = lock_internal.TryEnter(std::forward<TryEnterArguments>(arguments)...);
                if (!lockTaken)
                {
                    reentries--;
                    return false;
                }

                Thread::MemoryBarrier();
                *tid = current_tid;
                Thread::MemoryBarrier();
            }
            else
            {
                Thread::MemoryBarrier();
                int lockTaken_tid = *tid;
                Thread::MemoryBarrier();

                if (lockTaken_tid != current_tid)
                {
                    lock.Leave();
                    return false;
                }
            }

            return true;
        }

        SpinLock::SpinLock() noexcept
            : _(false)
        {

        }

        SpinLock::~SpinLock() noexcept(false)
        {
            bool lockTaken = IsLockTaken();
            if (lockTaken)
            {
                throw std::runtime_error("fail to release the atomic lock.");
            }
        }

        bool SpinLock::TryEnter(int loop, int timeout) noexcept
        {
            return Lock_TryEnter(*this, loop, timeout);
        }

        bool SpinLock::TryEnter() noexcept
        {
            int expected = FALSE;
            return _.compare_exchange_strong(expected, TRUE, std::memory_order_acquire);
        }

        void SpinLock::Leave()
        {
            int expected = TRUE;
            bool ok = _.compare_exchange_strong(expected, FALSE, std::memory_order_release);
            if (!ok)
            {
                throw std::runtime_error("failed to acquire the atomic lock.");
            }
        }

        RecursiveSpinLock::RecursiveSpinLock() noexcept
            : lockobj_()
            , tid_(0)
            , reentries_(0)
        {

        }

        bool RecursiveSpinLock::TryEnter() noexcept
        {
            return RecursiveLock_TryEnter(*this, lockobj_, &tid_, reentries_);
        }

        bool RecursiveSpinLock::TryEnter(int loop, int timeout) noexcept
        {
            return RecursiveLock_TryEnter(*this, lockobj_, &tid_, reentries_, loop, timeout);
        }

        void RecursiveSpinLock::Leave() 
        {
            int n = --reentries_;
            assert(n >= 0);

            if (n == 0)
            {
                lockobj_.Leave();
            }
        }
    }
}