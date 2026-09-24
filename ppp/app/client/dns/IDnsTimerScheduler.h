#pragma once

#include <cstdint>
#include <functional>

namespace ppp::app::client::dns {

class IDnsTimerScheduler {
public:
    virtual ~IDnsTimerScheduler() noexcept = default;
    virtual uint64_t Schedule(int64_t timeout_ms, std::function<void()> callback) noexcept = 0;
    virtual bool Cancel(uint64_t timer_id) noexcept = 0;
    virtual void CancelAll() noexcept = 0;
};

}
