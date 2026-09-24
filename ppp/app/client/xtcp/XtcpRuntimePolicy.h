#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace ppp::app::client::xtcp {

// Ingress admission budget (XTCP-STRAND-DISPATCH-001 lock-free rework).
// Hot paths (TryAdmit/Release) run on the packet-ingress and strand threads
// per packet: they are lock-free CAS on a single state word so the two
// threads never contend on a mutex. State word layout: high 32 bits = items,
// low 32 bits = bytes (max_items <= UINT32_MAX, max_bytes <= UINT32_MAX).
// Start/MarkReady/Stop are cold, single-shot transitions on separate
// flag/generation words.
class XtcpIngressBudget final {
public:
    static constexpr std::uint64_t kItemsShift = 32;

    XtcpIngressBudget(std::size_t max_items, std::size_t max_bytes) noexcept
        : max_items_(static_cast<std::uint32_t>(max_items)),
          max_bytes_(static_cast<std::uint32_t>(max_bytes)) {}

    bool TryAdmit(std::uint64_t generation, std::size_t bytes) noexcept {
        if (!running_.load(std::memory_order_acquire) ||
            !ready_.load(std::memory_order_acquire) || bytes == 0 ||
            generation == 0 || generation != generation_.load(std::memory_order_acquire) ||
            bytes > static_cast<std::uint64_t>(max_bytes_)) {
            return false;
        }
        const std::uint32_t byte_delta = static_cast<std::uint32_t>(bytes);
        std::uint64_t current = state_.load(std::memory_order_relaxed);
        for (;;) {
            const std::uint32_t items =
                static_cast<std::uint32_t>(current >> kItemsShift);
            const std::uint32_t used_bytes =
                static_cast<std::uint32_t>(current & UINT32_C(0xFFFFFFFF));
            if (items >= max_items_ || byte_delta > max_bytes_ - used_bytes) {
                return false;
            }
            const std::uint64_t updated =
                (static_cast<std::uint64_t>(items + 1) << kItemsShift) |
                static_cast<std::uint64_t>(used_bytes + byte_delta);
            if (state_.compare_exchange_weak(current, updated,
                    std::memory_order_relaxed, std::memory_order_relaxed)) {
                return true;
            }
        }
    }

    bool TryReserve(std::size_t bytes) noexcept {
        return TryAdmit(generation_.load(std::memory_order_acquire), bytes);
    }

    void Release(std::size_t bytes) noexcept {
        if (bytes > static_cast<std::size_t>(max_bytes_)) {
            return;
        }
        const std::uint32_t byte_delta = static_cast<std::uint32_t>(bytes);
        std::uint64_t current = state_.load(std::memory_order_relaxed);
        for (;;) {
            std::uint32_t items =
                static_cast<std::uint32_t>(current >> kItemsShift);
            std::uint32_t used_bytes =
                static_cast<std::uint32_t>(current & UINT32_C(0xFFFFFFFF));
            if (items > 0) {
                --items;
            }
            used_bytes = byte_delta <= used_bytes ? used_bytes - byte_delta : 0;
            const std::uint64_t updated =
                (static_cast<std::uint64_t>(items) << kItemsShift) |
                static_cast<std::uint64_t>(used_bytes);
            if (state_.compare_exchange_weak(current, updated,
                    std::memory_order_relaxed, std::memory_order_relaxed)) {
                return;
            }
        }
    }

    std::uint64_t Start() noexcept {
        std::uint64_t generation = generation_.load(std::memory_order_relaxed) + 1;
        if (generation == 0) {
            ++generation;
        }
        generation_.store(generation, std::memory_order_relaxed);
        state_.store(0, std::memory_order_relaxed);
        ready_.store(false, std::memory_order_release);
        running_.store(true, std::memory_order_release);
        return generation;
    }

    void MarkReady(std::uint64_t generation) noexcept {
        if (generation != 0 && generation == generation_.load(std::memory_order_acquire) &&
            running_.load(std::memory_order_acquire)) {
            ready_.store(true, std::memory_order_release);
        }
    }

    void Stop() noexcept {
        running_.store(false, std::memory_order_release);
        ready_.store(false, std::memory_order_relaxed);
        state_.store(0, std::memory_order_relaxed);
    }

    bool Accepts(std::uint64_t generation) const noexcept {
        return running_.load(std::memory_order_acquire) && generation != 0 &&
            generation == generation_.load(std::memory_order_acquire);
    }

    bool IsReady() const noexcept { return running_.load(std::memory_order_acquire) && ready_.load(std::memory_order_acquire); }
    bool IsRunning() const noexcept { return running_.load(std::memory_order_acquire); }
    std::uint64_t Generation() const noexcept { return generation_.load(std::memory_order_acquire); }
    std::size_t Items() const noexcept { return static_cast<std::size_t>(state_.load(std::memory_order_relaxed) >> kItemsShift); }
    std::size_t Bytes() const noexcept { return static_cast<std::size_t>(state_.load(std::memory_order_relaxed) & UINT32_C(0xFFFFFFFF)); }

private:
    const std::uint32_t max_items_;
    const std::uint32_t max_bytes_;
    std::atomic<std::uint64_t> state_{0};
    std::atomic<std::uint64_t> generation_{0};
    std::atomic<bool> running_{false};
    std::atomic<bool> ready_{false};
};

inline bool ShouldConsumeXtcpPacket(
    bool dispatch_consumed,
    bool xtcp_mode,
    bool ipv4_tcp) noexcept {
    return dispatch_consumed || (xtcp_mode && ipv4_tcp);
}

inline bool IsRegisteredExternalLoopback(
    bool is_loopback,
    std::uint16_t source_port,
    std::uint16_t registered_port,
    std::uint64_t generation,
    std::uint64_t registered_generation) noexcept {
    return is_loopback && source_port != 0 &&
        source_port == registered_port && generation != 0 &&
        generation == registered_generation;
}

constexpr std::array<unsigned char, 4> IPv4AddressBytes(
    std::uint32_t network_address) noexcept {
    return {{
        static_cast<unsigned char>(network_address >> 24),
        static_cast<unsigned char>(network_address >> 16),
        static_cast<unsigned char>(network_address >> 8),
        static_cast<unsigned char>(network_address),
    }};
}

constexpr bool IsFragmentedIPv4(
    std::uint16_t fragment_offset,
    std::uint8_t flags) noexcept {
    constexpr std::uint8_t kMoreFragments = 0x01;
    return fragment_offset != 0 || (flags & kMoreFragments) != 0;
}

} // namespace ppp::app::client::xtcp
