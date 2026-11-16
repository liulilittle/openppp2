#pragma once
#include <array>
#include <atomic>
#include <cstdint>

namespace ppp::tap {
// Process-lifetime totals across Linux TUN instances and lanes; approximate snapshots.
struct TunWriteDiagnostics final {
    std::atomic<uint64_t> calls{0}, bytes{0}, segments{0}, max_bytes{0}, max_segments{0};
    std::array<std::atomic<uint64_t>, 9> flushes{};
    static TunWriteDiagnostics& Instance() noexcept {
        static TunWriteDiagnostics value;
        return value;
    }
    static void Max(std::atomic<uint64_t>& target, uint64_t value) noexcept {
        auto old = target.load(std::memory_order_relaxed);
        while (old < value && !target.compare_exchange_weak(old, value,
            std::memory_order_relaxed, std::memory_order_relaxed)) {}
    }
    void Write(uint64_t size, uint64_t count) noexcept {
        calls.fetch_add(1, std::memory_order_relaxed);
        bytes.fetch_add(size, std::memory_order_relaxed);
        segments.fetch_add(count, std::memory_order_relaxed);
        Max(max_bytes, size);
        Max(max_segments, count);
    }
};
}
