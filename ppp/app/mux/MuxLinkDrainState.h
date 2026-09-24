#pragma once

#include <atomic>
#include <cstddef>
#include <memory>
#include <mutex>

namespace ppp::app::mux {

/** Thread-safe write accounting shared by VMUX completion fallback and retirement. */
class MuxLinkDrainState final {
public:
    class WriteTicket final {
    public:
        WriteTicket() noexcept = default;
        explicit operator bool() const noexcept { return consumed_ != nullptr; }

    private:
        friend class MuxLinkDrainState;
        WriteTicket(const MuxLinkDrainState* owner, std::shared_ptr<std::atomic<bool>> consumed) noexcept
            : owner_(owner), consumed_(std::move(consumed)) {}

        const MuxLinkDrainState* owner_ = nullptr;
        std::shared_ptr<std::atomic<bool>> consumed_;
    };

    WriteTicket BeginWrite() noexcept {
        std::lock_guard<std::mutex> scope(mutex_);
        if (retiring_) {
            return {};
        }
        try {
            auto consumed = std::make_shared<std::atomic<bool>>(false);
            ++inflight_;
            return WriteTicket(this, std::move(consumed));
        }
        catch (...) {
            return {};
        }
    }

    bool CompleteWrite(const WriteTicket& ticket) noexcept {
        return Consume(ticket);
    }

    bool AbortWrite(const WriteTicket& ticket) noexcept {
        return Consume(ticket);
    }

    void BeginRetire() noexcept {
        std::lock_guard<std::mutex> scope(mutex_);
        retiring_ = true;
    }

    bool accepting_writes() const noexcept { return !retiring(); }
    bool retiring() const noexcept {
        std::lock_guard<std::mutex> scope(mutex_);
        return retiring_;
    }
    bool reapable() const noexcept {
        std::lock_guard<std::mutex> scope(mutex_);
        return retiring_ && inflight_ == 0;
    }
    std::size_t inflight() const noexcept {
        std::lock_guard<std::mutex> scope(mutex_);
        return inflight_;
    }

private:
    bool Consume(const WriteTicket& ticket) noexcept {
        if (ticket.owner_ != this || ticket.consumed_ == nullptr) {
            return false;
        }
        bool expected = false;
        if (!ticket.consumed_->compare_exchange_strong(
                expected, true, std::memory_order_acq_rel, std::memory_order_acquire)) {
            return false;
        }
        std::lock_guard<std::mutex> scope(mutex_);
        if (inflight_ == 0) {
            return false;
        }
        --inflight_;
        return true;
    }

    mutable std::mutex mutex_;
    std::size_t inflight_ = 0;
    bool retiring_ = false;
};

} // namespace ppp::app::mux
