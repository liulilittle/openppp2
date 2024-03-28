#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/coroutines/YieldContext.h>
#include <boost/asio.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

namespace ppp {
    namespace threading {
        class Timer final : public std::enable_shared_from_this<Timer> {
        public:
            struct TickEventArgs {
            public:
                TickEventArgs() noexcept;
                TickEventArgs(UInt64 elapsedMilliseconds) noexcept;

            public:
                const UInt64                                                                                ElapsedMilliseconds;
            };
            typedef ppp::function<void(Timer* sender, TickEventArgs& e)>                                    TickEventHandler;
            typedef ppp::function<void()>                                                                   TimeoutEventHandler;
            enum DurationType {
                kHours,                                                                                     // 时
                kMinutes,                                                                                   // 分
                kSeconds,                                                                                   // 秒
                kMilliseconds,                                                                              // 毫秒
            };
            static boost::asio::deadline_timer::duration_type                                               DurationTime(long long int interval, DurationType durationType = kMilliseconds) noexcept;

        public:
            Timer();
            Timer(const std::shared_ptr<boost::asio::io_context>& context);
            virtual ~Timer() noexcept;

        public:
            TickEventHandler                                                                                TickEvent;

        protected:
            void                                                                                            OnTick(TickEventArgs& e) noexcept;

        public:
            void                                                                                            Dispose() noexcept;
            bool                                                                                            SetInterval(int milliseconds) noexcept;
        
        public:     
            bool                                                                                            Start() noexcept;
            bool                                                                                            Stop() noexcept;

        public:
            std::shared_ptr<Timer>                                                                          GetReference() noexcept;
            bool                                                                                            IsEnabled() noexcept;
            bool                                                                                            SetEnabled(bool value) noexcept;
            int                                                                                             GetInterval() noexcept;
            
        public:
            static bool                                                                                     Timeout(
                const std::shared_ptr<boost::asio::io_context>&                                             context, 
                int                                                                                         milliseconds, 
                ppp::coroutines::YieldContext&                                                              y) noexcept;
            static std::shared_ptr<Timer>                                                                   Timeout(int milliseconds, const TimeoutEventHandler& handler) noexcept;
            static std::shared_ptr<Timer>                                                                   Timeout(const std::shared_ptr<boost::asio::io_context>& context, int milliseconds, const TimeoutEventHandler& handler) noexcept;

        private:
            bool                                                                                            Next() noexcept;
            void                                                                                            Finalize() noexcept;

        private:
            bool                                                                                            _disposed_ = false;
            UInt64                                                                                          _last      = 0;
            int                                                                                             _interval  = 0;
            std::shared_ptr<boost::asio::io_context>                                                        _context;
            std::shared_ptr<boost::asio::deadline_timer>                                                    _deadline_timer;                                                                 
        };
    }
}