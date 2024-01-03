#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>

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
            exchangeof(_disposed_, true); {
                Stop();
                TickEvent = NULL;
            }
        }

        void Timer::OnTick(TickEventArgs& e) noexcept {
            std::shared_ptr<TickEventHandler> eh = TickEvent;
            if (eh) {
                (*eh)(this, e);
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
                boost::system::error_code ec;
                try {
                    t->cancel(ec);
                }
                catch (const std::exception&) {}
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

        std::shared_ptr<Timer> Timer::Timeout(int milliseconds, const std::shared_ptr<TimeoutEventHandler>& handler) noexcept {
            std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
            return Timeout(context, milliseconds, handler);
        }

        std::shared_ptr<Timer> Timer::Timeout(const std::shared_ptr<boost::asio::io_context>& context, int milliseconds, const std::shared_ptr<TimeoutEventHandler>& handler) noexcept {
            if (NULL == handler) {
                return NULL;
            }

            if (NULL == context) {
                return NULL;
            }

            if (milliseconds < 0) {
                milliseconds = 0;
            }

            std::shared_ptr<TimeoutEventHandler> f = handler;
            std::shared_ptr<Timer> t = make_shared_object<Timer>(context);
            t->TickEvent = make_shared_object<TickEventHandler>(
                [f](Timer* sender, Timer::TickEventArgs& e) noexcept {
                    sender->Stop();
                    sender->Dispose();
                    (*f)();
                });

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
            TimeoutAopHandler aop = NULL;
            return Timer::Timeout(context, milliseconds, y, aop);
        }

        bool Timer::Timeout(const std::shared_ptr<boost::asio::io_context>& context, int milliseconds, ppp::coroutines::YieldContext& y, const TimeoutAopHandler& aop) noexcept {
            if (!context) {
                return false;
            }

            if (!y) {
                return false;
            }

            auto* p = y.GetPtr();
            auto initiate = make_shared_object<Int128>(false);
            auto timeout_cb = make_shared_object<Timer::TimeoutEventHandler>(
                [p, initiate]() noexcept {
                    if (*initiate) {
                        p->GetContext().dispatch(std::bind(&ppp::coroutines::YieldContext::Resume, p));
                    }
                });

            auto timeout = Timer::Timeout(context, milliseconds, timeout_cb);
            if (!timeout) {
                return false;
            }
            elif(!aop || aop(timeout.get(), true)) {
                *initiate = true;
                y.Suspend();
            }
            else {
                timeout->Dispose();
                return false;
            }

            bool ok = true;
            if (aop) {
                ok = aop(timeout.get(), false);
            }

            timeout->Dispose();
            return ok;
        }
    }
}