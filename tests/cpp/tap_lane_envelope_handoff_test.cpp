// Tests for ppp/tap/TapLaneEnvelopeQueue.h: the bounded read-envelope staging
// used by the opt-in XTCP queue mode (lane readers -> vnet executor).

#include <ppp/tap/TapLaneEnvelopeQueue.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace {
using ppp::tap::TapLaneEnvelopeQueue;
using Push = TapLaneEnvelopeQueue::PushResult;

int failures = 0;
#define CHECK(condition)                                                          \
    do {                                                                          \
        if (!(condition)) {                                                       \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            ++failures;                                                           \
        }                                                                         \
    } while (0)

std::shared_ptr<std::uint8_t> Bytes(std::size_t length, std::uint32_t tag) {
    std::shared_ptr<std::uint8_t> data(new std::uint8_t[length], std::default_delete<std::uint8_t[]>());
    std::memset(data.get(), 0, length);
    std::memcpy(data.get(), &tag, std::min<std::size_t>(sizeof(tag), length));
    return data;
}

std::uint32_t Tag(const TapLaneEnvelopeQueue::Envelope& envelope) {
    std::uint32_t tag = 0;
    std::memcpy(&tag, envelope.data.get(), sizeof(tag));
    return tag;
}

void PerLaneFifoAndRoundRobin() {
    TapLaneEnvelopeQueue queue;
    CHECK(queue.Push(0, Bytes(8, 0x000), 8) == Push::AcceptedPostDrain); // first push posts the drain
    CHECK(queue.Push(0, Bytes(8, 0x001), 8) == Push::Accepted);
    CHECK(queue.Push(0, Bytes(8, 0x002), 8) == Push::Accepted);
    CHECK(queue.Push(3, Bytes(8, 0x300), 8) == Push::Accepted);
    CHECK(queue.Push(3, Bytes(8, 0x301), 8) == Push::Accepted);
    CHECK(queue.Push(7, Bytes(8, 0x700), 8) == Push::Accepted);
    const std::uint32_t expected[] = {0x000, 0x300, 0x700, 0x001, 0x301, 0x002};
    for (std::uint32_t tag : expected) {
        TapLaneEnvelopeQueue::Envelope envelope;
        CHECK(queue.Pop(envelope));
        CHECK(Tag(envelope) == tag);
        queue.Complete(envelope);
    }
    TapLaneEnvelopeQueue::Envelope none;
    CHECK(!queue.Pop(none));
    CHECK(!queue.EndDrain());                                            // parks the consumer
    CHECK(queue.Push(1, Bytes(8, 1), 8) == Push::AcceptedPostDrain);     // next push re-posts
    CHECK(queue.EndDrain());                                             // pending -> keep draining
    TapLaneEnvelopeQueue::Envelope envelope;
    CHECK(queue.Pop(envelope));
    queue.Complete(envelope);
    CHECK(!queue.EndDrain());
    const auto snapshot = queue.GetSnapshot();
    CHECK(snapshot.items == 0 && snapshot.bytes == 0 && snapshot.accepted == 7);
}

void ItemAndByteBounds() {
    TapLaneEnvelopeQueue queue;
    for (std::size_t i = 0; i < TapLaneEnvelopeQueue::kMaxItems; ++i) {
        CHECK(queue.Push(static_cast<int>(i % 4), Bytes(16, 0), 16) != Push::Full);
    }
    CHECK(queue.Push(0, Bytes(16, 0), 16) == Push::Full);
    CHECK(queue.GetSnapshot().full_drops == 1);
    // Credit is held by an in-flight envelope until Complete().
    TapLaneEnvelopeQueue::Envelope envelope;
    CHECK(queue.Pop(envelope));
    CHECK(queue.Push(0, Bytes(16, 0), 16) == Push::Full);
    queue.Complete(envelope);
    CHECK(queue.Push(0, Bytes(16, 0), 16) == Push::Accepted);
    queue.Close();

    TapLaneEnvelopeQueue bytes;
    const std::size_t chunk = 64 * 1024;
    for (std::size_t i = 0; i < TapLaneEnvelopeQueue::kMaxBytes / chunk; ++i) {
        CHECK(bytes.Push(2, Bytes(chunk, 0), chunk) != Push::Full);
    }
    CHECK(bytes.Push(2, Bytes(1, 0), 1) == Push::Full);
    CHECK(bytes.GetSnapshot().bytes == TapLaneEnvelopeQueue::kMaxBytes);
    CHECK(bytes.Push(-1, Bytes(1, 0), 1) == Push::Full);
    CHECK(bytes.Push(16, Bytes(1, 0), 1) == Push::Full);
}

void CloseReleasesAndZeroes() {
    TapLaneEnvelopeQueue queue;
    std::weak_ptr<std::uint8_t> watched;
    {
        auto data = Bytes(32, 9);
        watched = data;
        CHECK(queue.Push(5, std::move(data), 32) == Push::AcceptedPostDrain);
    }
    CHECK(queue.Push(6, Bytes(32, 10), 32) == Push::Accepted);
    TapLaneEnvelopeQueue::Envelope in_flight;
    CHECK(queue.Pop(in_flight));
    queue.Close();
    CHECK(queue.Push(5, Bytes(32, 11), 32) == Push::Closed);
    CHECK(queue.GetSnapshot().closed_drops == 1);
    CHECK(queue.GetSnapshot().items == 1);    // only the in-flight envelope
    queue.Complete(in_flight);
    CHECK(queue.GetSnapshot().items == 0 && queue.GetSnapshot().bytes == 0);
    CHECK(watched.expired());
    CHECK(!queue.EndDrain());
}

// Several lane readers (producers) and one consumer that drains in batches
// and is (re)scheduled only through AcceptedPostDrain/EndDrain.
void MultiReaderStress() {
    TapLaneEnvelopeQueue queue;
    constexpr int kReaders = 4;
    constexpr std::uint32_t kPerReader = 50000;
    std::mutex sync;
    std::condition_variable cv;
    int posts = 0;
    bool stop = false;
    std::atomic<std::uint64_t> pushed{0}, dropped{0};
    std::vector<std::uint32_t> next(kReaders, 0);
    bool order_ok = true;
    std::uint64_t consumed = 0;
    bool overlapping_drain = false;
    std::atomic<int> draining{0};

    std::thread consumer([&]() {
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(sync);
                cv.wait_for(lock, std::chrono::milliseconds(100), [&] { return posts > 0 || stop; });
                if (posts == 0 && stop) break;
                if (posts == 0) continue;
                --posts;
            }
            if (draining.fetch_add(1) != 0) overlapping_drain = true;
            for (;;) {
                for (int i = 0; i < 64; ++i) {
                    TapLaneEnvelopeQueue::Envelope envelope;
                    if (!queue.Pop(envelope)) break;
                    const std::uint32_t tag = Tag(envelope);
                    const int lane = envelope.lane;
                    // Drops are allowed, reordering is not.
                    if (lane < 0 || lane >= kReaders || tag < next[lane]) order_ok = false;
                    else next[lane] = tag + 1;
                    ++consumed;
                    queue.Complete(envelope);
                }
                if (!queue.EndDrain()) break;
            }
            draining.fetch_sub(1);
        }
    });

    std::vector<std::thread> readers;
    for (int r = 0; r < kReaders; ++r) {
        readers.emplace_back([&, r]() {
            for (std::uint32_t i = 0; i < kPerReader; ++i) {
                switch (queue.Push(r, Bytes(64, i), 64)) {
                case Push::AcceptedPostDrain: {
                    ++pushed;
                    std::lock_guard<std::mutex> lock(sync);
                    ++posts;
                    cv.notify_one();
                    break;
                }
                case Push::Accepted: ++pushed; break;
                default: ++dropped; break;
                }
            }
        });
    }
    for (auto& reader : readers) reader.join();
    {
        std::lock_guard<std::mutex> lock(sync);
        stop = true;
        cv.notify_one();
    }
    consumer.join();
    CHECK(order_ok);
    CHECK(!overlapping_drain);
    CHECK(pushed + dropped == std::uint64_t(kReaders) * kPerReader);
    CHECK(consumed == pushed.load());
    const auto snapshot = queue.GetSnapshot();
    CHECK(snapshot.items == 0 && snapshot.bytes == 0);
    CHECK(snapshot.full_drops == dropped.load());
}
} // namespace

int main() {
    PerLaneFifoAndRoundRobin();
    ItemAndByteBounds();
    CloseReleasesAndZeroes();
    MultiReaderStress();
    if (failures != 0) {
        std::fprintf(stderr, "tap_lane_envelope_handoff_test: %d failure(s)\n", failures);
        return 1;
    }
    std::puts("tap_lane_envelope_handoff_test: passed");
    return 0;
}
