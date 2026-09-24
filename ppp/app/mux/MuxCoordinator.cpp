#include <ppp/stdafx.h>
#include <ppp/app/mux/MuxCoordinator.h>

namespace ppp::app::mux {

MuxCoordinator::~MuxCoordinator() noexcept {
    Stop();
}

MuxCoordinator::SessionPtr MuxCoordinator::Session() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return session_;
}

bool MuxCoordinator::IsCurrent(const SessionPtr& session) const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return session_ == session;
}

void MuxCoordinator::Replace(SessionPtr session) noexcept {
    SessionPtr previous;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        previous = std::exchange(session_, std::move(session));
    }
    if (previous) {
        previous->close_exec();
    }
}

MuxCoordinator::SessionPtr MuxCoordinator::Take() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::move(session_);
}

void MuxCoordinator::ResetIfCurrent(const SessionPtr& session) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ == session) {
        session_.reset();
    }
}

MuxRuntimeState MuxCoordinator::RuntimeState() const noexcept {
    const SessionPtr session = Session();
    return session ? session->get_runtime_state() : MuxRuntimeState{};
}

void MuxCoordinator::Stop() noexcept {
    const SessionPtr session = Take();
    if (session) {
        session->close_exec();
    }
}

} // namespace ppp::app::mux
