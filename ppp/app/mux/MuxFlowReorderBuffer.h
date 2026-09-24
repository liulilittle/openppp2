#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <utility>

namespace ppp::app::mux {

/** Per-flow storage bounded by payload bytes and map-node count. */
template <typename T>
class MuxFlowReorderBuffer final {
public:
    bool TryInsert(
        std::uint32_t sequence,
        std::uint32_t reference,
        T value,
        std::size_t bytes,
        std::size_t byte_cap,
        std::size_t entry_cap) {
        const std::uint32_t distance = sequence - reference;
        if (distance == 0 || distance >= 0x80000000u ||
            packets_.find(sequence) != packets_.end() || packets_.size() >= entry_cap ||
            bytes > byte_cap || buffered_bytes_ > byte_cap - bytes) {
            return false;
        }

        auto inserted = packets_.emplace(sequence, Entry{std::move(value), bytes});
        if (!inserted.second) {
            return false;
        }

        buffered_bytes_ += bytes;
        return true;
    }

    bool Take(std::uint32_t sequence, T& value) {
        auto packet = packets_.find(sequence);
        if (packet == packets_.end()) {
            return false;
        }

        value = std::move(packet->second.value);
        buffered_bytes_ -= packet->second.bytes;
        packets_.erase(packet);
        return true;
    }

    bool FirstSequence(std::uint32_t reference, std::uint32_t& sequence) const noexcept {
        if (packets_.empty()) {
            return false;
        }

        auto packet = packets_.lower_bound(reference + 1);
        if (packet == packets_.end()) {
            packet = packets_.begin();
        }

        const std::uint32_t distance = packet->first - reference;
        // Zero is not future; exactly half the sequence space is ambiguous.
        if (distance == 0 || distance >= 0x80000000u) {
            return false;
        }

        sequence = packet->first;
        return true;
    }

    bool empty() const noexcept { return packets_.empty(); }
    std::size_t size() const noexcept { return packets_.size(); }
    std::size_t buffered_bytes() const noexcept { return buffered_bytes_; }

private:
    struct Entry final {
        T value;
        std::size_t bytes;
    };

    std::map<std::uint32_t, Entry> packets_;
    std::size_t buffered_bytes_ = 0;
};

} // namespace ppp::app::mux
