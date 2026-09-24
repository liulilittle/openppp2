#pragma once

#include <ppp/app/mux/MuxRuntimeState.h>
#include <ppp/app/mux/vmux_net.h>

#include <memory>
#include <mutex>

namespace ppp::app::mux {

class MuxCoordinator final {
public:
    using SessionPtr = std::shared_ptr<vmux::vmux_net>;

    ~MuxCoordinator() noexcept;

    SessionPtr Session() const noexcept;
    bool IsCurrent(const SessionPtr& session) const noexcept;
    void Replace(SessionPtr session) noexcept;
    SessionPtr Take() noexcept;
    void ResetIfCurrent(const SessionPtr& session) noexcept;
    MuxRuntimeState RuntimeState() const noexcept;
    void Stop() noexcept;

private:
    mutable std::mutex mutex_;
    std::shared_ptr<vmux::vmux_net> session_;
};

} // namespace ppp::app::mux
