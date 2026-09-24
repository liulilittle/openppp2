#pragma once

#include <atomic>

/**
 * @file SpinLock.h
 * @brief Declares lightweight spin-based lock primitives.
 */

namespace ppp
{
    namespace threading
    {
        /**
         * @brief Non-recursive spin lock built on an atomic flag.
         */
        class SpinLock final
        {
        public:
            /**
             * @brief Constructs an unlocked spin lock.
             */
            explicit SpinLock() noexcept;
            SpinLock(const SpinLock&) = delete;
            SpinLock(SpinLock&&) = delete;
            /**
             * @brief Verifies the lock is released before destruction.
             */
            ~SpinLock() noexcept(false);

        public:
            SpinLock&                   operator=(const SpinLock&) = delete;

        public:
            /**
             * @brief Attempts to acquire the lock once.
             * @return true if the lock is acquired; otherwise false.
             */
            bool                        TryEnter() noexcept;
            /**
             * @brief Attempts to acquire the lock with optional spin and timeout limits.
             * @param loop Maximum retry attempts; negative means infinite retries.
             * @param timeout Timeout in milliseconds; negative means no timeout.
             * @return true if the lock is acquired; otherwise false.
             */
            bool                        TryEnter(int loop, int timeout) noexcept;
            /**
             * @brief Acquires the lock, spinning until successful.
             */
            void                        Enter() noexcept { TryEnter(-1, -1); }
            /**
             * @brief Releases the lock.
             */
            void                        Leave();
            /**
             * @brief Checks whether the lock is currently held.
             * @return true when held, otherwise false.
             */
            bool                        IsLockTaken() noexcept { return _.load(); }

        public:
            /** @brief STL Lockable interface: acquires the lock (spins until success). */
            void                        lock() noexcept { Enter(); }
            /** @brief STL Lockable interface: releases the lock. */
            void                        unlock() noexcept { Leave(); }

        private:
            /** @brief Underlying atomic flag; 0 = unlocked, 1 = locked. */
            std::atomic<int>            _ = 0;
        };

        /**
         * @brief Recursive spin lock that tracks owner thread and reentry count.
         */
        class RecursiveSpinLock final
        {
        public:
            /**
             * @brief Constructs an unlocked recursive spin lock.
             */
            explicit RecursiveSpinLock() noexcept;
            RecursiveSpinLock(const RecursiveSpinLock&) = delete;
            RecursiveSpinLock(RecursiveSpinLock&&) = delete;
            /**
             * @brief Verifies the recursive lock is fully released before destruction.
             */
            ~RecursiveSpinLock() noexcept(false);

        public:
            RecursiveSpinLock&          operator=(const RecursiveSpinLock&) = delete;

        public:
            /**
             * @brief Attempts to acquire the recursive lock once.
             * @return true if acquired or re-entered by owner; otherwise false.
             */
            bool                        TryEnter() noexcept;
            /**
             * @brief Attempts to acquire with optional spin and timeout limits.
             * @param loop Maximum retry attempts; negative means infinite retries.
             * @param timeout Timeout in milliseconds; negative means no timeout.
             * @return true if acquired or re-entered by owner; otherwise false.
             */
            bool                        TryEnter(int loop, int timeout) noexcept;
            /**
             * @brief Acquires the recursive lock, spinning until successful.
             */
            void                        Enter() noexcept { TryEnter(-1, -1); }
            /**
             * @brief Releases one recursion level and unlocks at zero depth.
             */
            void                        Leave();
            /**
             * @brief Checks whether the recursive lock is logically held.
             * @return true when held, otherwise false.
             */
            bool                        IsLockTaken() noexcept;

        public:
            /** @brief STL Lockable interface: acquires the recursive lock. */
            void                        lock() noexcept { Enter(); }
            /** @brief STL Lockable interface: releases one recursion level. */
            void                        unlock() noexcept { Leave(); }

        private:
            /** @brief Serializes all owner and recursion-depth updates. */
            SpinLock                    lockobj_;
            /** @brief Thread ID of the current lock owner; 0 when unowned. */
            int64_t                     tid_       = 0;
            /** @brief Current recursion depth for the owning thread. */
            int                         reentries_ = 0;
        };
    }
}
