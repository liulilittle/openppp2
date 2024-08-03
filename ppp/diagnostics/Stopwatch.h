#pragma once

#include <ppp/stdafx.h>
#include <ppp/DateTime.h>

namespace ppp 
{
    namespace diagnostics 
    {
        // Provides a set of methods and properties that you can use to accurately measure elapsed time.
        class Stopwatch 
        {
            using clock_timepoint                   = std::chrono::high_resolution_clock::time_point;
            using SynchronizeObject                 = std::mutex;
            using SynchronizeObjectScope            = std::lock_guard<SynchronizeObject>;

        public:
            void                                    Start() noexcept;
            void                                    StartNew() noexcept { Restart(); }
            void                                    Stop() noexcept;
            void                                    Reset() noexcept;
            void                                    Restart() noexcept;
            bool                                    IsRunning() noexcept;

        public:
            int64_t                                 ElapsedMilliseconds() noexcept;
            int64_t                                 ElapsedTicks() noexcept;
            DateTime                                Elapsed() noexcept;

        private:
            SynchronizeObject                       syncobj_;
            clock_timepoint                         start_;
            clock_timepoint                         stop_;
        };
    }
}