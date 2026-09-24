#pragma once

/**
 * @file Timer.h
 * @brief Provides an asynchronous timer abstraction based on Boost.Asio.
 */

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/coroutines/YieldContext.h>

#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

namespace ppp {
    namespace threading {
        /**
         * @brief Schedules periodic tick callbacks and one-shot timeout callbacks.
         */
        class Timer final : public std::enable_shared_from_this<Timer> {
        public:
            /**
             * @brief Event arguments for timer tick notifications.
             */
            struct TickEventArgs {
            public:
                /** @brief Initializes an empty tick event argument. */
                TickEventArgs() noexcept;
                /**
                 * @brief Initializes tick event arguments with elapsed time.
                 * @param elapsedMilliseconds Elapsed milliseconds since previous tick.
                 */
                TickEventArgs(UInt64 elapsedMilliseconds) noexcept;

            public:
                /** @brief Elapsed milliseconds since the previous tick. */
                const UInt64                                                            ElapsedMilliseconds = 0;
            };
            /** @brief Tick callback signature. */
            typedef ppp::function<void(Timer* sender, TickEventArgs& e)>                  TickEventHandler;
            /** @brief One-shot timeout callback signature. */
            typedef ppp::function<void(Timer*)>                                         TimeoutEventHandler;
            /** @brief Shared timeout callback type. */
            typedef std::shared_ptr<TimeoutEventHandler>                                  TimeoutEventHandlerPtr;
            /** @brief Timeout callback table keyed by user token pointer. */
            typedef ppp::unordered_map<void*, TimeoutEventHandlerPtr>                     TimeoutEventHandlerTable;
            /** @brief Supported interval units for timer duration creation. */
            enum DurationType {
                kHours,                                                                 ///< Duration expressed in hours.
                kMinutes,                                                               ///< Duration expressed in minutes.
                kSeconds,                                                               ///< Duration expressed in seconds.
                kMilliseconds,                                                        ///< Duration expressed in milliseconds.
            };
            /** @brief Default duration unit used by DurationTime overloads. */
            static constexpr DurationType                                               kDefaultDurationType = static_cast<DurationType>(3);
            /** @brief Minimum valid interval in milliseconds. */
            static constexpr int                                                   kMinimumInterval = 1;
            /**
             * @brief Converts an interval and unit into a Boost deadline duration.
             * @param interval Duration value.
             * @param durationType Unit of @p interval.
             * @return Boost.Asio deadline timer duration.
             */
            static boost::asio::steady_timer::duration                                 DurationTime(long long int interval, DurationType durationType = kDefaultDurationType) noexcept;

        public:
            /** @brief Creates a timer without binding an external io_context. */
            Timer();
            /**
             * @brief Creates a timer bound to the specified io_context.
             * @param context Shared io_context used for scheduling timer callbacks.
             */
            Timer(const std::shared_ptr<boost::asio::io_context>& context);
            /** @brief Releases timer resources. */
            ~Timer() noexcept;

        public:
            /** @brief Tick event handler invoked when the timer interval elapses. */
            TickEventHandler                                                          TickEvent;

        protected:
            /**
             * @brief Raises the tick event callback.
             * @param e Tick event arguments.
             */
            void                                                                    OnTick(TickEventArgs& e) noexcept;

        public:
            /** @brief Disposes and stops the timer. */
            void                                                                    Dispose() noexcept;
            /**
             * @brief Sets the timer interval in milliseconds.
             * @param milliseconds Interval value.
             * @return true if interval is accepted; otherwise false.
             */
            bool                                                                    SetInterval(int milliseconds) noexcept;

        public:
            /** @brief Starts timer scheduling. */
            bool                                                                    Start() noexcept;
            /** @brief Stops timer scheduling. */
            bool                                                                    Stop() noexcept;

        public:
            /** @brief Gets a shared reference to this timer instance. */
            std::shared_ptr<Timer>                                                  GetReference() noexcept;
            /** @brief Checks whether timer scheduling is active. */
            bool                                                                    IsEnabled() noexcept;
            /**
             * @brief Enables or disables timer scheduling.
             * @param value true to enable; false to stop.
             * @return true if state changed successfully.
             */
            bool                                                                    SetEnabled(bool value) noexcept;
            /** @brief Gets the configured interval in milliseconds. */
            int                                                                     GetInterval() noexcept;

        public:
            /**
             * @brief Releases and clears all timeout handlers in a table.
             * @param timeouts Timeout table to clear.
             */
            static void                                                             ReleaseAllTimeouts(TimeoutEventHandlerTable& timeouts) noexcept;
            /**
             * @brief Coroutine-friendly sleep helper.
             * @param milliseconds Timeout value.
             * @param y Yield context used to suspend/resume.
             * @return true if wait completes successfully.
             */
            static bool                                                             Timeout(int milliseconds, ppp::coroutines::YieldContext& y) noexcept;
            /**
             * @brief Creates a one-shot timer and invokes a callback on expiration.
             * @param milliseconds Timeout value.
             * @param handler Callback to invoke on expiration.
             * @return Created timer instance, or null on failure.
             */
            static std::shared_ptr<Timer>                                           Timeout(int milliseconds, const TimeoutEventHandler& handler) noexcept;
            /**
             * @brief Creates a one-shot timer on the specified context.
             * @param context Shared io_context used for scheduling.
             * @param milliseconds Timeout value.
             * @param handler Callback to invoke on expiration.
             * @return Created timer instance, or null on failure.
             */
            static std::shared_ptr<Timer>                                           Timeout(const std::shared_ptr<boost::asio::io_context>& context, int milliseconds, const TimeoutEventHandler& handler) noexcept;

        private:
            /** @brief Schedules the next interval tick. */
            bool                                                                    Next() noexcept;
            /** @brief Finalizes timer internals and releases resources. */
            void                                                                    Finalize() noexcept;
            /** @brief Stops the active timer; caller must hold `_syncobj`. */
            bool                                                                    StopLocked() noexcept;

        private:
            /** @brief Guards `_disposed_`, `_last`, `_interval`, and `_deadline_timer` against cross-thread access. */
            std::mutex                                                              _syncobj;
            /** @brief Indicates whether Dispose/Finalize has been called. */
            bool                                                                    _disposed_ = false;
            /** @brief Synchronization flag for TickEvent access (false when Finalize in progress). */
            std::atomic<bool>                                                       tick_event_guard_ = { true };
            /** @brief Stores the previous tick timestamp in milliseconds. */
            UInt64                                                                  _last      = 0;
            /** @brief Timer interval in milliseconds. */
            int                                                                     _interval  = 0;
            /** @brief Execution context used by the timer. */
            std::shared_ptr<boost::asio::io_context>                                  _context;
            /** @brief Underlying Boost.Asio steady (monotonic) timer instance. */
            std::shared_ptr<boost::asio::steady_timer>                                _deadline_timer;
        };
    }
}