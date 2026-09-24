#include <ppp/app/client/SwitcherTimeoutRegistry.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/threading/Timer.h>

using ppp::collections::Dictionary;
using ppp::ethernet::VEthernet;
using ppp::threading::Timer;

namespace ppp::app::client {

void SwitcherTimeoutRegistry::Bind(VEthernet::SynchronizedObject* sync) noexcept {
    sync_ = sync;
}

bool SwitcherTimeoutRegistry::Emplace(
    RegistrationHandle handle,
    const std::shared_ptr<ppp::function<void(ppp::threading::Timer*)>>& handler) noexcept {
    if (NULLPTR == sync_ || NULLPTR == handle || NULLPTR == handler) {
        return false;
    }
    VEthernet::SynchronizedObjectScope scope(*sync_);
    if (released_) {
        return false;
    }
    return timeouts_.emplace(handle, handler).second;
}

bool SwitcherTimeoutRegistry::Delete(RegistrationHandle handle) noexcept {
    if (NULLPTR == sync_ || NULLPTR == handle) {
        return false;
    }
    VEthernet::SynchronizedObjectScope scope(*sync_);
    return Dictionary::RemoveValueByKey(timeouts_, handle);
}

void SwitcherTimeoutRegistry::ReleaseAll() noexcept {
    if (NULLPTR == sync_) {
        return;
    }
    Timer::TimeoutEventHandlerTable timeouts;
    {
        VEthernet::SynchronizedObjectScope scope(*sync_);
        released_ = true;
        timeouts = std::move(timeouts_);
        timeouts_.clear();
    }
    for (auto&& kv : timeouts) {
        const std::shared_ptr<Timer::TimeoutEventHandler>& handler = kv.second;
        if (handler) {
            (*handler)(nullptr);
        }
    }
}

}  // namespace ppp::app::client
