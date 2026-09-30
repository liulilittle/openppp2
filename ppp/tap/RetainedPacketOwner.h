#pragma once

#include <cstddef>
#include <new>
#include <type_traits>
#include <utility>

namespace ppp::tap {

// Small type-erased move-only owner for packet buffers retained by a
// synchronous output boundary. The inline storage keeps packet retention off
// the heap; owners must be nothrow movable and fit in the fixed slot.
class RetainedPacketOwner final {
public:
    RetainedPacketOwner() noexcept = default;
    RetainedPacketOwner(const RetainedPacketOwner&) = delete;
    RetainedPacketOwner& operator=(const RetainedPacketOwner&) = delete;

    template <class Owner>
    explicit RetainedPacketOwner(Owner&& owner, bool checksum_partial = false) noexcept
        : checksum_partial_(checksum_partial) {
        using Stored = std::decay_t<Owner>;
        static_assert(sizeof(Stored) <= kStorageBytes, "retained owner exceeds inline storage");
        static_assert(alignof(Stored) <= alignof(std::max_align_t), "retained owner alignment is unsupported");
        static_assert(std::is_nothrow_move_constructible_v<Stored>, "retained owner must move without throwing");
        new (storage_) Stored(std::forward<Owner>(owner));
        destroy_ = [](void* value) noexcept { static_cast<Stored*>(value)->~Stored(); };
        move_ = [](void* from, void* to) noexcept {
            auto* source = static_cast<Stored*>(from);
            new (to) Stored(std::move(*source));
            source->~Stored();
        };
    }

    RetainedPacketOwner(RetainedPacketOwner&& other) noexcept { MoveFrom(other); }
    RetainedPacketOwner& operator=(RetainedPacketOwner&& other) noexcept {
        if (this != &other) {
            Reset();
            MoveFrom(other);
        }
        return *this;
    }
    ~RetainedPacketOwner() noexcept { Reset(); }

    bool HasValue() const noexcept { return destroy_ != nullptr; }
    bool ChecksumPartial() const noexcept { return checksum_partial_; }
    void Reset() noexcept {
        if (destroy_ != nullptr) destroy_(storage_);
        destroy_ = nullptr;
        move_ = nullptr;
        checksum_partial_ = false;
    }

private:
    static constexpr std::size_t kStorageBytes = 64;
    void MoveFrom(RetainedPacketOwner& other) noexcept {
        if (other.move_ == nullptr) return;
        other.move_(other.storage_, storage_);
        destroy_ = other.destroy_;
        move_ = other.move_;
        checksum_partial_ = other.checksum_partial_;
        other.checksum_partial_ = false;
        other.destroy_ = nullptr;
        other.move_ = nullptr;
    }

    alignas(std::max_align_t) unsigned char storage_[kStorageBytes]{};
    void (*destroy_)(void*) noexcept = nullptr;
    void (*move_)(void*, void*) noexcept = nullptr;
    bool checksum_partial_ = false;
};

} // namespace ppp::tap
