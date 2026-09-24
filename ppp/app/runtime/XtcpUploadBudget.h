#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace ppp::app::client::xtcp {

// Runtime-wide logical upload payload budget, including asynchronous writes.
// Encoding/gather scratch space and transport/socket buffers are separate.
class XtcpUploadBudget final : public std::enable_shared_from_this<XtcpUploadBudget> {
public:
    using WakeHandler = std::function<void()>;
    using WaitToken = std::uint64_t;

    struct State final {
        std::uint64_t bytes = 0;
        std::size_t items = 0;
        std::uint64_t max_bytes = 0;
        std::size_t max_items = 0;
        std::size_t waiters = 0;
        std::uint64_t wake_events = 0;
        std::uint64_t fairness_switches = 0;
    };

    class Reservation final {
    public:
        Reservation() noexcept : bytes_(0), items_(0) {}
        Reservation(const Reservation&) = delete;
        Reservation& operator=(const Reservation&) = delete;
        Reservation(Reservation&& other) noexcept : bytes_(0), items_(0) { Swap(other); }
        Reservation& operator=(Reservation&& other) noexcept {
            if (this != &other) { Reset(); Swap(other); }
            return *this;
        }
        ~Reservation() noexcept { Reset(); }

        explicit operator bool() const noexcept { return owner_ != nullptr; }
        std::uint64_t Bytes() const noexcept { return bytes_; }
        std::size_t Items() const noexcept { return items_; }
        bool SameBudget(const Reservation& other) const noexcept {
            return owner_ == other.owner_;
        }
        // Used only after the gather has copied successfully. No new credit
        // is acquired and the source becomes empty, so rollback stays exact.
        bool Merge(Reservation&& other) noexcept {
            if (this == &other) return false;
            if (!other) return true;
            if (!*this) { Swap(other); return true; }
            if (!SameBudget(other)) return false;
            bytes_ += std::exchange(other.bytes_, 0);
            items_ += std::exchange(other.items_, 0);
            other.owner_.reset();
            return true;
        }
        void Reset() noexcept {
            auto owner = std::move(owner_);
            const auto bytes = std::exchange(bytes_, 0);
            const auto items = std::exchange(items_, 0);
            if (owner) owner->Release(bytes, items);
        }

    private:
        friend class XtcpUploadBudget;
        Reservation(std::shared_ptr<XtcpUploadBudget> owner, std::uint64_t bytes) noexcept
            : owner_(std::move(owner)), bytes_(bytes), items_(1) {}
        void Swap(Reservation& other) noexcept {
            owner_.swap(other.owner_);
            std::swap(bytes_, other.bytes_);
            std::swap(items_, other.items_);
        }
        std::shared_ptr<XtcpUploadBudget> owner_;
        std::uint64_t bytes_;
        std::size_t items_;
    };

    XtcpUploadBudget(std::uint64_t bytes, std::size_t items) noexcept
        : max_bytes_(bytes), max_items_(items) {}

    Reservation TryReserve(std::uint64_t bytes) noexcept {
        auto owner = weak_from_this().lock();
        if (!owner || bytes == 0 || bytes > max_bytes_) return {};
        std::lock_guard<std::mutex> lock(sync_);
        if (!Fits(bytes)) { waiting_ = true; return {}; }
        bytes_ += bytes;
        ++items_;
        return Reservation(std::move(owner), bytes);
    }

    // Token-aware admission used by the runtime. Only the current queue head
    // may take credit; a blocked head is explicitly rotated to the tail by the
    // runtime, so one hot flow cannot monopolize every release and a blocked
    // flow cannot deadlock the queue.
    Reservation TryReserveFor(WaitToken token, std::uint64_t bytes) noexcept {
        auto owner = weak_from_this().lock();
        if (!owner || token == 0 || bytes == 0 || bytes > max_bytes_) return {};
        std::lock_guard<std::mutex> lock(sync_);
        if (!Fits(bytes)) {
            waiting_ = true;
            return {};
        }
        if (!waiters_.empty() && waiters_.front() != token) {
            waiting_ = true;
            return {};
        }
        if (!waiters_.empty()) {
            waiters_.erase(waiters_.begin());
        }
        if (last_granted_ != 0 && last_granted_ != token) {
            ++fairness_switches_;
        }
        last_granted_ = token;
        bytes_ += bytes;
        ++items_;
        waiting_ = !waiters_.empty();
        return Reservation(std::move(owner), bytes);
    }

    // Re-arm notifications when another shard consumed the released credit
    // before a wake handler ran. Check and waiter registration share the lock.
    bool AwaitCapacity(std::uint64_t bytes) noexcept {
        std::lock_guard<std::mutex> lock(sync_);
        if (bytes == 0 || bytes > max_bytes_) return false;
        if (Fits(bytes)) return true;
        waiting_ = true;
        return false;
    }

    // Register or re-check a fair waiter. Only the queue head can observe
    // capacity as available. If the head's request cannot fit in the currently
    // free bytes, rotate it once so a smaller waiter can use that capacity.
    // This avoids head-of-line blocking when in-flight reservations release
    // bytes in chunks smaller than the oldest request.
    bool AwaitCapacity(WaitToken token, std::uint64_t bytes) noexcept {
        std::lock_guard<std::mutex> lock(sync_);
        if (token == 0 || bytes == 0 || bytes > max_bytes_) return false;
        auto found = std::find(waiters_.begin(), waiters_.end(), token);
        if (Fits(bytes)) {
            if (waiters_.empty() && found == waiters_.end()) {
                if (last_granted_ != 0 && last_granted_ != token) {
                    ++fairness_switches_;
                }
                last_granted_ = token;
                return true;
            }
            if (found != waiters_.end() && found == waiters_.begin()) {
                if (last_granted_ != 0 && last_granted_ != token) {
                    ++fairness_switches_;
                }
                last_granted_ = token;
                return true;
            }
        }
        if (found == waiters_.end()) {
            waiters_.push_back(token);
        }
        else if (found == waiters_.begin() && waiters_.size() > 1) {
            std::rotate(waiters_.begin(), waiters_.begin() + 1, waiters_.end());
        }
        waiting_ = true;
        return false;
    }

    void CancelWait(WaitToken token) noexcept {
        if (token == 0) return;
        std::lock_guard<std::mutex> lock(sync_);
        const auto found = std::find(waiters_.begin(), waiters_.end(), token);
        if (found != waiters_.end()) {
            waiters_.erase(found);
        }
        waiting_ = !waiters_.empty();
    }

    void RotateWait(WaitToken token) noexcept {
        if (token == 0) return;
        std::lock_guard<std::mutex> lock(sync_);
        const auto found = std::find(waiters_.begin(), waiters_.end(), token);
        if (found != waiters_.end()) {
            const WaitToken moved = *found;
            waiters_.erase(found);
            waiters_.push_back(moved);
        }
        waiting_ = !waiters_.empty();
    }

    std::vector<WaitToken> WaiterTokens() const {
        std::lock_guard<std::mutex> lock(sync_);
        return waiters_;
    }

    State Snapshot() const noexcept {
        std::lock_guard<std::mutex> lock(sync_);
        return {bytes_, items_, max_bytes_, max_items_, waiters_.size(),
            wake_events_, fairness_switches_};
    }

    // Cold-path binding can change on runtime restart. Reservations from the
    // previous generation still count until their actual owners release them.
    void SetWakeHandler(WakeHandler handler) {
        auto wake = std::make_shared<WakeHandler>(std::move(handler));
        std::lock_guard<std::mutex> lock(sync_);
        wake_ = std::move(wake);
    }

private:
    bool Fits(std::uint64_t bytes) const noexcept {
        return items_ < max_items_ && bytes <= max_bytes_ - bytes_;
    }
    void Release(std::uint64_t bytes, std::size_t items) noexcept {
        std::shared_ptr<WakeHandler> wake;
        {
            std::lock_guard<std::mutex> lock(sync_);
            bytes_ -= bytes;
            items_ -= items;
            if (waiting_ && wake_) {
                waiting_ = false;
                ++wake_events_;
                wake = wake_;
            }
        }
        // Never run callbacks under the budget lock. The runtime callback
        // only posts work: releases can occur under a connection's queue lock.
        if (wake && *wake) {
            try { (*wake)(); }
            catch (...) {
                std::lock_guard<std::mutex> lock(sync_);
                waiting_ = true;
            }
        }
    }

    const std::uint64_t max_bytes_;
    const std::size_t max_items_;
    mutable std::mutex sync_;
    std::uint64_t bytes_ = 0;
    std::size_t items_ = 0;
    bool waiting_ = false;
    std::vector<WaitToken> waiters_;
    std::uint64_t last_granted_ = 0;
    std::uint64_t wake_events_ = 0;
    std::uint64_t fairness_switches_ = 0;
    std::shared_ptr<WakeHandler> wake_;
};

struct XtcpUploadChunk final {
    // Declaration order releases bytes before returning their credit.
    XtcpUploadBudget::Reservation credit;
    std::vector<std::uint8_t> bytes;

    XtcpUploadChunk() = default;
    XtcpUploadChunk(const std::uint8_t* data, std::size_t length,
        XtcpUploadBudget::Reservation&& reservation)
        : credit(std::move(reservation)), bytes(data, data + length) {}
};

} // namespace ppp::app::client::xtcp
