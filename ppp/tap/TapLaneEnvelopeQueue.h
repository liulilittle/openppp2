#pragma once

// Bounded staging for TUN read envelopes in the opt-in XTCP queue mode.
//
// GSO output-lane readers (one per lane, each on its shard worker) copy every
// read into an envelope and push it here before re-arming their descriptor.
// A single consumer on the original vnet executor drains the lanes in
// round-robin order and runs the unchanged OnInput/policy path.
//
// Invariants:
//  - per-lane FIFO; round-robin across lanes on the consumer side;
//  - a global bound of kMaxItems envelopes / kMaxBytes payload bytes counts
//    queued plus in-flight envelopes (credit is held until Complete());
//  - a full queue drops the new envelope and counts it, never blocks a reader;
//  - at most one consumer drain is scheduled at a time (Push reports the
//    one push that must post it; EndDrain re-checks under the same lock);
//  - Close() drops queued envelopes, rejects later pushes, and the counters
//    return to zero once in-flight envelopes complete.
//
// Producers are serialized by an internal mutex (multi-reader safe); this is
// the "serialized producer" variant of the section 3 handoff component.

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <utility>

namespace ppp {
    namespace tap {
        class TapLaneEnvelopeQueue final {
        public:
            static constexpr std::size_t kMaxLanes = 16;
            static constexpr std::size_t kMaxItems = 1024;
            static constexpr std::size_t kMaxBytes = 8 * 1024 * 1024;

            struct Envelope final {
                std::shared_ptr<std::uint8_t> data;
                std::size_t length = 0;
                int lane = -1;
            };

            enum class PushResult { Accepted, AcceptedPostDrain, Full, Closed };

            struct Snapshot final {
                std::size_t items = 0;
                std::size_t bytes = 0;
                std::uint64_t accepted = 0;
                std::uint64_t full_drops = 0;
                std::uint64_t closed_drops = 0;
            };

            PushResult Push(int lane, std::shared_ptr<std::uint8_t> data, std::size_t length) noexcept {
                if (lane < 0 || static_cast<std::size_t>(lane) >= kMaxLanes || !data || length == 0) {
                    return PushResult::Full;
                }
                std::lock_guard<std::mutex> lock(sync_);
                if (closed_) {
                    ++closed_drops_;
                    return PushResult::Closed;
                }
                if (items_ >= kMaxItems || length > kMaxBytes - bytes_) {
                    ++full_drops_;
                    return PushResult::Full;
                }
                try {
                    lanes_[static_cast<std::size_t>(lane)].push_back(Envelope{std::move(data), length, lane});
                }
                catch (...) {
                    ++full_drops_;
                    return PushResult::Full;
                }
                ++items_;
                bytes_ += length;
                ++queued_;
                ++accepted_;
                if (drain_scheduled_) {
                    return PushResult::Accepted;
                }
                drain_scheduled_ = true;
                return PushResult::AcceptedPostDrain;
            }

            // Consumer: next envelope in round-robin lane order.
            bool Pop(Envelope& out) noexcept {
                std::lock_guard<std::mutex> lock(sync_);
                if (queued_ == 0) {
                    return false;
                }
                for (std::size_t i = 0; i < kMaxLanes; ++i) {
                    std::deque<Envelope>& q = lanes_[(next_lane_ + i) % kMaxLanes];
                    if (!q.empty()) {
                        out = std::move(q.front());
                        q.pop_front();
                        --queued_;
                        next_lane_ = (static_cast<std::size_t>(out.lane) + 1) % kMaxLanes;
                        return true;
                    }
                }
                return false;
            }

            // Consumer: releases the envelope's credit after OnInput returned.
            void Complete(Envelope& envelope) noexcept {
                if (!envelope.data) {
                    return;
                }
                envelope.data.reset();
                std::lock_guard<std::mutex> lock(sync_);
                --items_;
                bytes_ -= envelope.length;
            }

            // Consumer: ends a drain batch. Returns true when more envelopes
            // are queued and the consumer must keep draining (re-post).
            bool EndDrain() noexcept {
                std::lock_guard<std::mutex> lock(sync_);
                if (queued_ != 0 && !closed_) {
                    return true;
                }
                drain_scheduled_ = false;
                return false;
            }

            void Close() noexcept {
                std::array<std::deque<Envelope>, kMaxLanes> dropped;
                {
                    std::lock_guard<std::mutex> lock(sync_);
                    closed_ = true;
                    for (std::size_t i = 0; i < kMaxLanes; ++i) {
                        for (const Envelope& envelope : lanes_[i]) {
                            --items_;
                            bytes_ -= envelope.length;
                        }
                        dropped[i].swap(lanes_[i]);
                    }
                    queued_ = 0;
                }
                // Envelope payloads are released outside the lock.
            }

            bool Closed() const noexcept {
                std::lock_guard<std::mutex> lock(sync_);
                return closed_;
            }

            Snapshot GetSnapshot() const noexcept {
                std::lock_guard<std::mutex> lock(sync_);
                Snapshot snapshot;
                snapshot.items = items_;
                snapshot.bytes = bytes_;
                snapshot.accepted = accepted_;
                snapshot.full_drops = full_drops_;
                snapshot.closed_drops = closed_drops_;
                return snapshot;
            }

        private:
            mutable std::mutex sync_;
            std::array<std::deque<Envelope>, kMaxLanes> lanes_;
            std::size_t next_lane_ = 0;
            std::size_t queued_ = 0;   // envelopes waiting in lanes_
            std::size_t items_ = 0;    // queued + in flight (credit)
            std::size_t bytes_ = 0;
            std::uint64_t accepted_ = 0;
            std::uint64_t full_drops_ = 0;
            std::uint64_t closed_drops_ = 0;
            bool drain_scheduled_ = false;
            bool closed_ = false;
        };
    }
}
