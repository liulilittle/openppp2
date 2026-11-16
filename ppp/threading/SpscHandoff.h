#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace ppp::threading {

enum class HandoffPush { Accepted, Full, Closed };
enum class HandoffDrain { Item, Empty, Closed };

// One serialized producer and one serialized consumer, which may migrate threads.
// The owner must quiesce both sides and all callbacks before destruction. Abort
// never destroys live slots; the consumer or the quiescent owner reclaims them.
template<class T> class SpscHandoff final {
    static_assert(std::is_nothrow_move_constructible<T>::value, "nothrow move required");
    static_assert(std::is_nothrow_move_assignable<T>::value, "nothrow assignment required");
    static_assert(std::is_nothrow_destructible<T>::value, "nothrow destruction required");
    using Slot = typename std::aligned_storage<sizeof(T), alignof(T)>::type;
public:
    enum class State { Running, Waiting, Scheduled, Closed };
    explicit SpscHandoff(std::size_t capacity, std::uint64_t epoch, std::uint64_t initial_index = 0)
        : capacity_(capacity), epoch_(epoch), backing_(Backing(capacity)), slots_(new Slot[backing_]),
          head_(initial_index), tail_(initial_index) {}
    ~SpscHandoff() noexcept {
        const auto end = tail_.load(std::memory_order_relaxed);
        for (auto i = head_.load(std::memory_order_relaxed); i != end; ++i)
            At(i)->~T();
    }
    SpscHandoff(const SpscHandoff&) = delete;
    SpscHandoff& operator=(const SpscHandoff&) = delete;

    HandoffPush TryPush(T&& item) noexcept { return TryPushBatch(&item, 1); }
    HandoffPush TryPushBatch(T* items, std::size_t count) noexcept {
        if (closing_.load(std::memory_order_acquire) || GetState() == State::Closed)
            return HandoffPush::Closed;
        const auto tail = tail_.load(std::memory_order_relaxed);
        const auto head = head_.load(std::memory_order_acquire);
        if (count > capacity_ - static_cast<std::size_t>(tail - head))
            return HandoffPush::Full;
        for (std::size_t i = 0; i < count; ++i)
            ::new (Storage(tail + i)) T(std::move(items[i]));
        // The entire batch becomes visible in one publication.
        tail_.store(tail + count, std::memory_order_release);
        return HandoffPush::Accepted;
    }
    HandoffDrain TryPop(T& item) noexcept {
        const auto head = head_.load(std::memory_order_relaxed);
        if (head == tail_.load(std::memory_order_acquire))
            return closing_.load(std::memory_order_acquire) || GetState() == State::Closed
                ? HandoffDrain::Closed : HandoffDrain::Empty;
        T* slot = At(head);
        item = std::move(*slot);
        slot->~T();
        head_.store(head + 1, std::memory_order_release);
        return HandoffDrain::Item;
    }
    bool Empty() const noexcept {
        return head_.load(std::memory_order_relaxed) == tail_.load(std::memory_order_acquire);
    }
    // Even a busy producer performs an acq_rel same-state RMW. The consumer's
    // arm RMW acquires that publication through the gate's RMW chain.
    bool CommitWake() noexcept {
        State state = gate_.load(std::memory_order_acquire);
        for (;;) {
            if (state == State::Closed) return false;
            const State next = state == State::Waiting ? State::Scheduled : state;
            if (gate_.compare_exchange_weak(state, next, std::memory_order_acq_rel,
                    std::memory_order_acquire)) return state == State::Waiting;
        }
    }
    bool Claim(std::uint64_t epoch) noexcept {
        if (epoch != epoch_) return false;
        State expected = State::Scheduled;
        return gate_.compare_exchange_strong(expected, State::Running, std::memory_order_acq_rel);
    }
    // Split only to permit deterministic tests at the arm/recheck boundary.
    bool ArmWait() noexcept {
        State expected = State::Running;
        return gate_.compare_exchange_strong(expected, State::Waiting, std::memory_order_acq_rel);
    }
    bool RecheckAfterArm() noexcept {
        if (GetState() == State::Closed) return true;
        if (!Empty() || closing_.load(std::memory_order_acquire)) {
            State expected = State::Waiting;
            if (gate_.compare_exchange_strong(expected, State::Running, std::memory_order_acq_rel))
                return false;
        }
        return true;
    }
    bool ArmWaitAndRecheck() noexcept { return !ArmWait() || RecheckAfterArm(); }
    bool ScheduleContinuation() noexcept {
        State expected = State::Running;
        return gate_.compare_exchange_strong(expected, State::Scheduled, std::memory_order_acq_rel);
    }
    bool RequestClose() noexcept {
        closing_.store(true, std::memory_order_release);
        return CommitWake();
    }
    void Abort() noexcept {
        // Abort is terminal and idempotent. closing_ is published before the
        // Closed gate, so any thread observing Closed also observes closing_;
        // a producer that only observes closing_ can no longer schedule work
        // and can only fail CommitWake or observe Closed, without losing
        // already-accepted items or duplicating scheduling.
        closing_.store(true, std::memory_order_release);
        gate_.exchange(State::Closed, std::memory_order_acq_rel);
    }
    bool Closing() const noexcept { return closing_.load(std::memory_order_acquire); }
    State GetState() const noexcept { return gate_.load(std::memory_order_acquire); }
    std::uint64_t Epoch() const noexcept { return epoch_; }
    std::size_t Capacity() const noexcept { return capacity_; }
    bool CanPush(std::size_t count) const noexcept {
        const auto tail = tail_.load(std::memory_order_relaxed);
        return count <= capacity_ - static_cast<std::size_t>(tail - head_.load(std::memory_order_acquire));
    }
private:
    static std::size_t Backing(std::size_t capacity) {
        // Unsigned monotonic distance is unambiguous below half the index range.
        if (!capacity || capacity > std::numeric_limits<std::size_t>::max() / 4)
            throw std::invalid_argument("SPSC capacity");
        std::size_t backing = 1;
        while (backing < capacity) backing *= 2;
        return backing;
    }
    void* Storage(std::uint64_t index) noexcept {
        // Power-of-two backing preserves slot order even across uint64 wrap;
        // admission still enforces the exact (possibly non-power-of-two) limit.
        return &slots_[static_cast<std::size_t>(index & (backing_ - 1))];
    }
    T* At(std::uint64_t index) noexcept {
        return std::launder(reinterpret_cast<T*>(Storage(index)));
    }
    const std::size_t capacity_;
    const std::uint64_t epoch_;
    const std::size_t backing_;
    std::unique_ptr<Slot[]> slots_;
    alignas(64) std::atomic<std::uint64_t> head_{0};
    alignas(64) std::atomic<std::uint64_t> tail_{0};
    alignas(64) std::atomic<State> gate_{State::Waiting};
    std::atomic<bool> closing_{false};
};

// Post must return bool (or throw). A failed post makes the endpoint terminal;
// storage stays owned until consumer/owner quiescence. It never pops on failure.
template<class T> class SerializedSpscHandoff final {
public:
    SerializedSpscHandoff(std::size_t capacity, std::uint64_t epoch) : queue_(capacity, epoch) {}
    template<class Post> HandoffPush PushBatch(T* items, std::size_t count, Post&& post) noexcept {
        return PushBatchWithAdmission(items, count, []() noexcept { return true; }, std::forward<Post>(post));
    }
    template<class Admit, class Post>
    HandoffPush PushBatchWithAdmission(T* items, std::size_t count, Admit&& admit, Post&& post) noexcept {
        std::lock_guard<std::mutex> lock(producer_);
        if (queue_.Closing() || queue_.GetState() == SpscHandoff<T>::State::Closed)
            return HandoffPush::Closed;
        if (!queue_.CanPush(count)) return HandoffPush::Full;
        if (!admit()) return HandoffPush::Full;
        const auto result = queue_.TryPushBatch(items, count);
        if (result != HandoffPush::Accepted) return result;
        // Commit is inseparable from publication, including every error exit.
        if (queue_.CommitWake() && !PostOrAbort(post)) return HandoffPush::Closed;
        return result;
    }
    template<class Post> bool PostOrAbort(Post&& post) noexcept {
        try { if (post(queue_.Epoch())) return true; } catch (...) {}
        queue_.Abort();
        return false;
    }
    template<class Post> void Close(Post&& post) noexcept {
        std::lock_guard<std::mutex> lock(producer_);
        if (queue_.RequestClose()) PostOrAbort(post);
    }
    void Abort() noexcept {
        // Serializing the adapter preserves the same closing-before-Closed
        // ordering; repeated aborts converge to the terminal Closed state.
        std::lock_guard<std::mutex> lock(producer_);
        queue_.Abort();
    }
    SpscHandoff<T>& Consumer() noexcept { return queue_; }
private:
    std::mutex producer_;
    SpscHandoff<T> queue_;
};

} // namespace ppp::threading
