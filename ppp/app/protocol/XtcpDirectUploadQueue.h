#pragma once

// Direct-upload data queue shared by VirtualEthernetTcpipConnection and its
// focused tests (production and tests use this exact class).
//
// Invariants (both modes):
//  - one serialized producer (the XTCP shard strand calling Push) and one
//    serialized consumer (the direct upload writer, plus the disposing owner);
//  - the chunk owns its upload credit until the gather write completes or the
//    chunk is dropped, so credit is released exactly once;
//  - byte/item counters cover queued plus in-flight chunks and reach zero once
//    every admitted chunk has been released or cleared;
//  - the backpressure flag is raised at most once per episode and the
//    low-watermark resume is reported exactly once per raise;
//  - after RequestClose()/Abort() no further chunk is published.
//
// Deque mode (default): every call is made under the owner's control lock.
//
// Spsc mode (opt-in, OPENPPP2_XTCP_DIRECT_SPSC=1): Push() does not need the
// owner's lock. Admission, counters, the backpressure raise and the publish
// happen inside the SerializedSpscHandoff producer section, so Abort() fences
// every producer. Consumer calls (Empty, ShouldWaitForGather, DrainGather,
// Release, Clear) stay under the owner's control lock, which also keeps the
// "at most one gather writer" ownership flag; HasPending() is the
// producer-side check used to start that writer once per ingress batch.

#include <ppp/app/protocol/XtcpDirectIo.h>
#include <ppp/threading/SpscHandoff.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <new>
#include <utility>
#include <vector>

namespace ppp::app::protocol {

class XtcpDirectUploadQueue final {
public:
    using ChunkPtr = std::shared_ptr<XtcpUploadChunk>;
    using Handoff = ppp::threading::SerializedSpscHandoff<ChunkPtr>;

    enum class Mode : std::uint8_t { Deque, Spsc };

    static constexpr std::size_t kMaxItems = 4096;
    static constexpr std::size_t kLowItems = kMaxItems / 2;
    static constexpr std::size_t kMaxBytes = 32 * 1024 * 1024;
    static constexpr std::size_t kLowBytes = kMaxBytes / 2;
    static constexpr std::size_t kGatherWaitMaxItems = 16;

    struct PushOutcome final {
        XtcpDirectResult result = XtcpDirectResult::Closed;
        bool backpressure_raised = false; // false -> true transition happened
    };

    struct Counters final {
        std::atomic<std::uint64_t> handoff_full{0};
        std::atomic<std::uint64_t> handoff_wakes{0};
        std::atomic<std::uint64_t> alloc_fallback{0};
        std::atomic<bool> fail_next_open{false}; // test hook
    };

    explicit XtcpDirectUploadQueue(Mode mode = Mode::Deque) noexcept : mode_(mode) {}
    XtcpDirectUploadQueue(const XtcpDirectUploadQueue&) = delete;
    XtcpDirectUploadQueue& operator=(const XtcpDirectUploadQueue&) = delete;

    // Process-wide counters (cumulative since process start).
    static Counters& Global() noexcept {
        static Counters counters;
        return counters;
    }
    static bool SpscEnabledFromEnvironment() noexcept {
        static const bool enabled = []() noexcept {
            const char* value = std::getenv("OPENPPP2_XTCP_DIRECT_SPSC");
            return value != nullptr && std::strcmp(value, "1") == 0;
        }();
        return enabled;
    }
    static Mode DefaultMode() noexcept {
        return SpscEnabledFromEnvironment() ? Mode::Spsc : Mode::Deque;
    }

    Mode GetMode() const noexcept { return mode_; }

    // Spsc: allocates the fixed 4096-slot ring once (owner lock held, before
    // the bridge is published). Returns false on allocation failure or when
    // the ring was already closed; the caller falls back to the relay path.
    bool Open() noexcept {
        if (mode_ != Mode::Spsc) return true;
        Handoff* ring = ring_.load(std::memory_order_acquire);
        if (ring) return !ring->Consumer().Closing();
        try {
            if (Global().fail_next_open.exchange(false)) throw std::bad_alloc();
            ring_storage_ = std::make_unique<Handoff>(kMaxItems, 1);
        }
        catch (...) {
            Global().alloc_fallback.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        ring_.store(ring_storage_.get(), std::memory_order_release);
        return true;
    }

    // Copies the borrowed bytes only after the per-flow caps admitted them
    // (Spsc re-checks inside the producer section). on_accepted runs once the
    // chunk is counted and before it becomes visible to the consumer.
    // on_raised runs (inside the same section) when this push raised the
    // backpressure flag.
    template<class OnAccepted, class OnRaised>
    PushOutcome Push(const std::uint8_t* data, std::size_t length,
        XtcpUploadBudget::Reservation&& credit, OnAccepted&& on_accepted,
        OnRaised&& on_raised) noexcept {
        PushOutcome outcome;
        if (mode_ == Mode::Deque) {
            if (!Admit(length, outcome)) {
                if (outcome.backpressure_raised) on_raised();
                return outcome;
            }
            try {
                queue_.emplace_back(std::make_shared<XtcpUploadChunk>(data, length, std::move(credit)));
            }
            catch (...) {
                return outcome;
            }
            Count(length);
            on_accepted();
            outcome.result = XtcpDirectResult::Accepted;
            return outcome;
        }
        Handoff* ring = ring_.load(std::memory_order_acquire);
        if (!ring || ring->Consumer().Closing()) return outcome;
        if (OverCap(length) && !AdmitSpscRejected(*ring, length, outcome, on_raised)) {
            return outcome; // raised (or closed) inside the producer section
        }
        outcome = PushOutcome{};
        ChunkPtr chunk;
        try {
            chunk = std::make_shared<XtcpUploadChunk>(data, length, std::move(credit));
        }
        catch (...) {
            return outcome;
        }
        bool admitted = false;
        const ppp::threading::HandoffPush pushed = ring->PushBatchWithAdmission(&chunk, 1,
            [&]() noexcept {
                if (!Admit(length, outcome)) {
                    if (outcome.backpressure_raised) on_raised();
                    return false;
                }
                Count(length);
                on_accepted();
                admitted = true;
                return true;
            },
            [](std::uint64_t) noexcept { return true; });
        if (pushed == ppp::threading::HandoffPush::Accepted) {
            outcome.result = XtcpDirectResult::Accepted;
            return outcome;
        }
        if (pushed == ppp::threading::HandoffPush::Full && !admitted &&
            outcome.result == XtcpDirectResult::Backpressured) {
            return outcome;
        }
        if (pushed == ppp::threading::HandoffPush::Full) {
            // The ring capacity equals the item cap, so this is defensive.
            Global().handoff_full.fetch_add(1, std::memory_order_relaxed);
            outcome.result = XtcpDirectResult::Backpressured;
            return outcome;
        }
        outcome.result = XtcpDirectResult::Closed;
        return outcome;
    }
    PushOutcome Push(const std::uint8_t* data, std::size_t length,
        XtcpUploadBudget::Reservation&& credit) noexcept {
        return Push(data, length, std::move(credit), []() noexcept {}, []() noexcept {});
    }

    // Producer-side: anything admitted and not yet released.
    bool HasPending() const noexcept {
        return mode_ == Mode::Deque ? !queue_.empty() : Items() != 0;
    }

    // Consumer-side views (owner lock held).
    bool Empty() noexcept { Pull(); return queue_.empty(); }
    std::size_t Bytes() const noexcept { return bytes_.load(); }
    std::size_t Items() const noexcept { return items_.load(); }
    bool Backpressured() const noexcept { return backpressured_.load(); }
    void ResetBackpressure() noexcept { backpressured_.store(false); }

    // True when a short bounded wait may let adjacent segments join the write.
    bool ShouldWaitForGather(std::size_t gather_limit) noexcept {
        Pull();
        return Bytes() < gather_limit && queue_.size() > 1 &&
            queue_.size() < kGatherWaitMaxItems;
    }

    // Pops the head chunk, merging following same-budget chunks up to
    // gather_limit bytes. Credits are merged only after every copy succeeded.
    bool DrainGather(std::size_t gather_limit, ChunkPtr& payload, std::size_t& items) noexcept {
        Pull();
        if (queue_.empty()) return false;
        payload = queue_.front();
        items = 1;
        if (gather_limit > 1 && payload->bytes.size() < gather_limit && queue_.size() > 1) {
            std::size_t gathered_bytes = payload->bytes.size();
            std::size_t gathered_items = 1;
            for (; gathered_items < queue_.size(); ++gathered_items) {
                const ChunkPtr& candidate = queue_[gathered_items];
                if (!candidate || candidate->bytes.empty() ||
                    !payload->credit.SameBudget(candidate->credit) ||
                    candidate->bytes.size() > gather_limit - gathered_bytes) {
                    break;
                }
                gathered_bytes += candidate->bytes.size();
            }
            if (gathered_items > 1) {
                try {
                    auto combined = std::make_shared<XtcpUploadChunk>();
                    combined->bytes.reserve(gathered_bytes);
                    for (std::size_t i = 0; i < gathered_items; ++i) {
                        const std::vector<std::uint8_t>& item = queue_[i]->bytes;
                        combined->bytes.insert(combined->bytes.end(), item.begin(), item.end());
                    }
                    for (std::size_t i = 0; i < gathered_items; ++i) {
                        const bool merged = combined->credit.Merge(std::move(queue_[i]->credit));
                        assert(merged); // SameBudget was checked above.
                        (void)merged;
                    }
                    payload = std::move(combined);
                    items = gathered_items;
                    for (std::size_t i = 0; i < gathered_items; ++i) {
                        queue_.pop_front();
                    }
                    return true;
                }
                catch (...) {
                }
            }
        }
        queue_.pop_front();
        return true;
    }

    // Accounts a finished write. Returns true exactly once when a successful
    // write drops a backpressured queue to the low watermark.
    bool Release(std::size_t bytes, std::size_t items, bool sent,
        std::size_t& completed_bytes, std::size_t& completed_items) noexcept {
        completed_bytes = SubSaturating(bytes_, bytes);
        completed_items = SubSaturating(items_, items);
        if (sent && BelowLow() && backpressured_.load()) {
            return backpressured_.exchange(false);
        }
        return false;
    }

    // Spsc: stops further publication; queued chunks stay for the writer.
    void RequestClose() noexcept {
        if (Handoff* ring = ring_.load(std::memory_order_acquire)) {
            ring->Close([](std::uint64_t) noexcept { return true; });
        }
    }
    // Spsc: terminal; fences every producer section.
    void Abort() noexcept {
        if (Handoff* ring = ring_.load(std::memory_order_acquire)) {
            ring->Abort();
        }
    }

    // Drops queued chunks (releasing their credit) and zeroes the counters.
    // Call after Abort() in Spsc mode. Returns whether it was backpressured.
    bool Clear(std::size_t& abandoned_bytes, std::size_t& abandoned_items) noexcept {
        Pull();
        abandoned_bytes = bytes_.exchange(0);
        abandoned_items = items_.exchange(0);
        queue_.clear();
        return backpressured_.exchange(false);
    }

private:
    bool OverCap(std::size_t length) const noexcept {
        return Items() >= kMaxItems || length > kMaxBytes - Bytes();
    }
    bool BelowLow() const noexcept {
        return Bytes() <= kLowBytes && Items() <= kLowItems;
    }
    // Raises backpressure when over the caps. In Spsc mode the consumer may
    // release below the low watermark between the cap check and the raise;
    // re-check after raising so a resume cannot be lost.
    bool Admit(std::size_t length, PushOutcome& outcome) noexcept {
        if (!OverCap(length)) return true;
        outcome.backpressure_raised = !backpressured_.exchange(true);
        if (mode_ == Mode::Spsc && outcome.backpressure_raised && BelowLow() &&
            backpressured_.exchange(false)) {
            outcome.backpressure_raised = false;
            if (!OverCap(length)) return true;
        }
        outcome.result = XtcpDirectResult::Backpressured;
        return false;
    }
    // Over-cap fast path: performs the raise inside a zero-item producer
    // section so it is serialized with Abort(). Returns true when the caps
    // were freed meanwhile and the caller should continue with the push.
    template<class OnRaised>
    bool AdmitSpscRejected(Handoff& ring, std::size_t length, PushOutcome& outcome,
        OnRaised& on_raised) noexcept {
        ChunkPtr none;
        bool admitted = false;
        bool entered = false;
        (void)ring.PushBatchWithAdmission(&none, 0,
            [&]() noexcept {
                entered = true;
                admitted = Admit(length, outcome);
                if (!admitted && outcome.backpressure_raised) on_raised();
                return false;
            },
            [](std::uint64_t) noexcept { return true; });
        if (!entered) outcome.result = XtcpDirectResult::Closed;
        return admitted;
    }
    void Count(std::size_t length) noexcept {
        bytes_.fetch_add(length);
        items_.fetch_add(1);
    }
    static std::size_t SubSaturating(std::atomic<std::size_t>& value, std::size_t amount) noexcept {
        std::size_t current = value.load();
        for (;;) {
            const std::size_t taken = std::min(current, amount);
            if (value.compare_exchange_weak(current, current - taken)) return taken;
        }
    }
    void Pull() noexcept {
        Handoff* ring = ring_.load(std::memory_order_acquire);
        if (!ring) return;
        ChunkPtr chunk;
        while (ring->Consumer().TryPop(chunk) == ppp::threading::HandoffDrain::Item) {
            queue_.push_back(std::move(chunk)); // deque growth is bounded by kMaxItems
        }
    }

    const Mode mode_;
    std::deque<ChunkPtr> queue_; // Deque: the queue; Spsc: consumer staging
    std::unique_ptr<Handoff> ring_storage_;
    std::atomic<Handoff*> ring_{nullptr};
    std::atomic<std::size_t> bytes_{0};
    std::atomic<std::size_t> items_{0};
    std::atomic<bool> backpressured_{false};
};

} // namespace ppp::app::protocol
