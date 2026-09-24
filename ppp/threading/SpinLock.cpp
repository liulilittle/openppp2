#include <ppp/threading/SpinLock.h>
#include <ppp/threading/Thread.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file SpinLock.cpp
 * @brief Implements spin lock and recursive spin lock behavior.
 */

namespace ppp
{
    namespace threading
    {
        /**
         * @brief Shared try-enter loop helper for lock-like objects.
         * @tparam LockObject Lock type exposing `TryEnter()`.
         * @param lock Lock instance to acquire.
         * @param loop Maximum retry attempts; negative means infinite retries.
         * @param timeout Timeout in milliseconds; negative means no timeout.
         * @return true if acquired; otherwise false.
         */
        template <class LockObject>
        static constexpr bool Lock_TryEnter(
            LockObject&                                             lock,
            int                                                     loop,
            int                                                     timeout) noexcept
        {
            /**
             * @brief Attempts one acquisition pass and evaluates timeout state.
             */
            auto tryEnter = 
                [&lock, timeout](uint64_t last) noexcept -> int
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

        /**
         * @brief Constructs an unlocked spin lock.
         */
        SpinLock::SpinLock() noexcept
            : _(false)
        {

        }

        /**
         * @brief Ensures the lock is not held at destruction time.
         * @throws std::runtime_error Thrown when the lock is still held.
         */
        SpinLock::~SpinLock() noexcept(false)
        {
            bool lockTaken = IsLockTaken();
            if (lockTaken)
            {
                throw std::runtime_error("Failed to release the atomic lock.");
            }
        }

        /**
         * @brief Attempts to acquire with loop and timeout controls.
         */
        bool SpinLock::TryEnter(int loop, int timeout) noexcept
        {
            bool lockTaken = Lock_TryEnter(*this, loop, timeout);
            if (!lockTaken)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ThreadSyncConditionWaitFailed);
            }

            return lockTaken;
        }

        /**
         * @brief Attempts a single atomic acquisition.
         */
        bool SpinLock::TryEnter() noexcept 
        {
            int expected = FALSE;
            return _.compare_exchange_strong(expected, TRUE);
        }

        /**
         * @brief Releases the atomic lock state.
         * @throws std::runtime_error Thrown when lock ownership state is invalid.
         */
        void SpinLock::Leave()
        {
            int expected = TRUE;
            bool ok = _.compare_exchange_strong(expected, FALSE);
            if (!ok)
            {
                throw std::runtime_error("Failed to acquire the atomic lock.");
            }
        }

        /**
         * @brief Constructs an unlocked recursive spin lock.
         */
        RecursiveSpinLock::RecursiveSpinLock() noexcept
            : lockobj_()
            , tid_(0)
            , reentries_(0)
        {

        }

        /**
         * @brief Verifies the recursive lock is fully released before destruction.
         * @throws std::runtime_error Thrown when the recursive lock is still held.
         */
        RecursiveSpinLock::~RecursiveSpinLock() noexcept(false)
        {
            lockobj_.Enter();
            bool lockTaken = reentries_ != 0;
            lockobj_.Leave();
            if (lockTaken)
            {
                throw std::runtime_error("Failed to release the recursive lock.");
            }
        }

        /**
         * @brief Attempts to acquire recursively once.
         */
        bool RecursiveSpinLock::TryEnter() noexcept
        {
            if (!lockobj_.TryEnter())
            {
                return false;
            }

            int64_t current_tid = GetCurrentThreadId();
            bool lockTaken = false;
            if (reentries_ == 0)
            {
                tid_ = current_tid;
                reentries_ = 1;
                lockTaken = true;
            }
            else if (tid_ == current_tid)
            {
                ++reentries_;
                lockTaken = true;
            }

            lockobj_.Leave();
            return lockTaken;
        }

        /**
         * @brief Attempts recursive acquisition with loop and timeout controls.
         */
        bool RecursiveSpinLock::TryEnter(int loop, int timeout) noexcept
        {
            bool lockTaken = Lock_TryEnter(*this, loop, timeout);
            if (!lockTaken)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ThreadSyncConditionWaitFailed);
            }

            return lockTaken;
        }

        /**
         * @brief Releases one recursion level and unlocks on final release.
         */
        void RecursiveSpinLock::Leave()
        {
            lockobj_.Enter();
            int64_t current_tid = GetCurrentThreadId();
            if (reentries_ == 0 || tid_ != current_tid)
            {
                lockobj_.Leave();
                throw std::runtime_error("Failed to release a recursive lock from a non-owner thread.");
            }

            --reentries_;
            if (reentries_ == 0)
            {
                tid_ = 0;
            }
            lockobj_.Leave();
        }

        /**
         * @brief Returns a state-gate-protected logical held snapshot.
         */
        bool RecursiveSpinLock::IsLockTaken() noexcept
        {
            lockobj_.Enter();
            bool lockTaken = reentries_ != 0;
            lockobj_.Leave();
            return lockTaken;
        }
    }
}
