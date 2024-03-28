#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/net/Socket.h>

namespace ppp {
    namespace threading {
        Timer::Timer()
            : Timer(Executors::GetDefault()) {

        }

        Timer::Timer(const std::shared_ptr<boost::asio::io_context>& context)
            : _disposed_(false)
            , _last(0)
            , _interval(0)
            , _context(context) {

            if (NULL == context) {
                throw std::runtime_error("An NullReferences form of the context is not allowed");
            }
        }

        Timer::~Timer() noexcept {
            Finalize();
        }

        void Timer::Finalize() noexcept {
            _disposed_ = true;
            Stop();
            TickEvent.reset();
        }

        void Timer::OnTick(TickEventArgs& e) noexcept {
            TickEventHandler eh = TickEvent;
            if (eh) {
                eh(this, e);
            }
        }

        bool Timer::Start() noexcept {
            if (_disposed_) {
                return false;
            }

            if (_interval < 1) {
                return false;
            }
            else {
                Stop();
            }

            _last = 0;
            _deadline_timer = make_shared_object<boost::asio::deadline_timer>(*_context);
            return Next();
        }

        bool Timer::Next() noexcept {
            if (_disposed_) {
                return false;
            }

            std::shared_ptr<boost::asio::deadline_timer> t = _deadline_timer;
            if (NULL == t) {
                return false;
            }
            else {
                _last = Executors::GetTickCount();
            }

            std::shared_ptr<Timer> self = GetReference();
            boost::asio::deadline_timer::duration_type durationTime = Timer::DurationTime(_interval);
            t->expires_from_now(durationTime);
            t->async_wait(
                [self, this, t](const boost::system::error_code& ec) noexcept {
                    if (ec) {
                        _last = 0;
                    }
                    else {
                        TickEventArgs e(Executors::GetTickCount() - _last);
                        OnTick(e);
                        Next();
                    }
                });
            return true;
        }

        bool Timer::Stop() noexcept {
            std::shared_ptr<boost::asio::deadline_timer> t = std::move(_deadline_timer);
            if (t) {
                ppp::net::Socket::Cancel(*t);
            }

            _last = 0;
            _deadline_timer = NULL;
            return NULL != t;
        }

        void Timer::Dispose() noexcept {
            auto self = shared_from_this();
            _context->post(
                [self, this]()noexcept {
                    Finalize();
                });
        }

        bool Timer::SetInterval(int milliseconds) noexcept {
            if (milliseconds < 1) {
                milliseconds = 0;
            }

            if (milliseconds < 1) {
                Stop();
            }

            _interval = milliseconds;
            return milliseconds;
        }

        std::shared_ptr<Timer> Timer::GetReference() noexcept {
            return shared_from_this();
        }

        bool Timer::IsEnabled() noexcept {
            return NULL != _deadline_timer;
        }

        bool Timer::SetEnabled(bool value) noexcept {
            return value ? this->Start() : this->Stop();
        }

        int Timer::GetInterval() noexcept {
            return _interval;
        }

        Timer::TickEventArgs::TickEventArgs(UInt64 elapsedMilliseconds) noexcept
            : ElapsedMilliseconds(elapsedMilliseconds) {

        }

        Timer::TickEventArgs::TickEventArgs() noexcept
            : ElapsedMilliseconds(0) {

        }

        boost::asio::deadline_timer::duration_type Timer::DurationTime(long long int interval, DurationType durationType) noexcept {
            switch (durationType)
            {
            case DurationType::kHours:
                return boost::posix_time::hours(interval);
            case DurationType::kMinutes:
                return boost::posix_time::minutes(interval);
            case DurationType::kSeconds:
                return boost::posix_time::seconds(interval);
            case DurationType::kMilliseconds:
                return boost::posix_time::milliseconds(interval);
            default:
                return boost::posix_time::milliseconds(interval);
            };
        }

        std::shared_ptr<Timer> Timer::Timeout(int milliseconds, const TimeoutEventHandler& handler) noexcept {
            std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
            return Timeout(context, milliseconds, handler);
        }

        std::shared_ptr<Timer> Timer::Timeout(const std::shared_ptr<boost::asio::io_context>& context, int milliseconds, const TimeoutEventHandler& handler) noexcept {
            if (NULL == handler) {
                return NULL;
            }

            if (NULL == context) {
                return NULL;
            }

            if (milliseconds < 1) {
                milliseconds = 1;
            }

            std::shared_ptr<Timer> t = make_shared_object<Timer>(context);
            if (NULL == t) {
                return NULL;
            }

            t->TickEvent = 
                [handler](Timer* sender, Timer::TickEventArgs& e) noexcept {
                    sender->Stop();
                    sender->Dispose();
                    handler();
                };

            bool ok = t->SetInterval(milliseconds) && t->Start();
            if (ok) {
                return t;
            }
            else {
                t->Dispose();
                return NULL;
            }
        }

        bool Timer::Timeout(const std::shared_ptr<boost::asio::io_context>& context, int milliseconds, ppp::coroutines::YieldContext& y) noexcept {
            if (NULL == context) {
                return false;
            }

            if (!y) {
                return false;
            }

            std::shared_ptr<boost::asio::deadline_timer> deadlineTimer = make_shared_object<boost::asio::deadline_timer>(*context);
            if (NULL == deadlineTimer) {
                return false;
            }
            
            if (milliseconds < 0) {
                milliseconds = 0;
            }

            bool ok = false;
            boost::asio::deadline_timer::duration_type durationTime = Timer::DurationTime(milliseconds);
            deadlineTimer->expires_from_now(durationTime);
            deadlineTimer->async_wait(
                [&y, &ok](const boost::system::error_code& ec) noexcept {
                    if (ec == boost::system::errc::success) {
                        ok = true;
                    }

                    auto& context = y.GetContext();
                    context.dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, y.GetPtr()));
                });

            y.Suspend();
            return ok;
        }
    }
}