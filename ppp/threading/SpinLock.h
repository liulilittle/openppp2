#pragma once

#include <atomic>

namespace ppp
{
    namespace threading
    {
        class SpinLock final
        {
        public:
            explicit SpinLock() noexcept;
            SpinLock(const SpinLock&) = delete;
            SpinLock(SpinLock&&) = delete;
            ~SpinLock() noexcept(false);

        public:
            SpinLock&                   operator=(const SpinLock&) = delete;

        public:
            bool                        TryEnter() noexcept;
            bool                        TryEnter(int loop, int timeout) noexcept;
            void                        Enter() noexcept { TryEnter(-1, -1); }
            void                        Leave();
            bool                        IsLockTaken() noexcept { return _.load(); }

        public:
            void                        lock() noexcept { Enter(); }
            void                        unlock() noexcept { Leave(); }

        public:
            std::atomic<int>            _ = 0;
        };

        class RecursiveSpinLock final
        {
        public:
            explicit RecursiveSpinLock() noexcept;
            RecursiveSpinLock(const RecursiveSpinLock&) = delete;
            RecursiveSpinLock(RecursiveSpinLock&&) = delete;
            ~RecursiveSpinLock() = default;

        public:
            RecursiveSpinLock&          operator=(const RecursiveSpinLock&) = delete;

        public:
            bool                        TryEnter() noexcept;
            bool                        TryEnter(int loop, int timeout) noexcept;
            void                        Enter() noexcept { TryEnter(-1, -1); }
            void                        Leave();
            bool                        IsLockTaken() noexcept { return lockobj_.IsLockTaken(); }

        public:
            void                        lock() noexcept { Enter(); }
            void                        unlock() noexcept { Leave(); }

        public:
            SpinLock                    lockobj_;
            volatile int64_t            tid_       = 0;
            std::atomic<int>            reentries_ = 0;
        };
    }
}