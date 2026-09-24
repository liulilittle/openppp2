// VMUX-QA-001: Malicious ACK range end-to-end input path test.
//
// Validates that DecodeMuxAckFrame and MuxRetransmitBuffer::Ack are robust
// against crafted/malicious ACK payloads.  Covers:
//   - block_count / range_count overflow and zero values
//   - truncated frames at every possible boundary
//   - start > end, end > largest
//   - trailing garbage
//   - extreme wrap-around values (UINT32_MAX neighbourhood)
//   - large volume of well-formed-but-invalid ACKs (no resource growth)
//   - ACK confirming never-sent DSNs (RTX buffer integrity)
//   - response amplification check (decode output ≤ input)
//
// All tests are component-level (no network / no vmux_net).  They exercise
// the same codec and RTX buffer that vmux_net uses on the real input path.

#include <ppp/app/mux/MuxAckTracker.h>
#include <ppp/app/mux/MuxRetransmitBuffer.h>

#include <cassert>
#include <cstring>
#include <vector>
#include <cstdint>
#include <memory>
#include <string>

namespace {

using ppp::app::mux::MuxAckBlock;
using ppp::app::mux::MuxAckRange;
using ppp::app::mux::MuxAckTracker;
using ppp::app::mux::DecodeMuxAckFrame;
using ppp::app::mux::EncodeMuxAckFrame;
using ppp::app::mux::MuxAckFrameMaxSize;
using ppp::app::mux::MuxRetransmitBuffer;
using ppp::app::mux::MuxRtxEntry;

constexpr std::size_t MAX_BLOCKS = 8;
constexpr std::size_t MAX_RANGES = 24;

// ---------------------------------------------------------------------------
// Helpers to build raw ACK frames byte-by-byte.
// ---------------------------------------------------------------------------

void put_u32_be(std::vector<std::uint8_t>& buf, std::uint32_t v) {
    buf.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

// Build a valid single-block ACK frame for (cid, largest) with the given
// ranges.  No validation — caller is expected to pass sane values for the
// "valid" helper, or craft bytes manually for malicious cases.
std::vector<std::uint8_t> build_ack(
    std::uint32_t cid, std::uint32_t largest,
    const std::vector<MuxAckRange>& ranges)
{
    std::vector<std::uint8_t> buf;
    buf.push_back(static_cast<std::uint8_t>(1)); // block_count
    put_u32_be(buf, cid);
    put_u32_be(buf, largest);
    buf.push_back(static_cast<std::uint8_t>(ranges.size()));
    for (const auto& r : ranges) {
        put_u32_be(buf, r.start);
        put_u32_be(buf, r.end);
    }
    return buf;
}

std::vector<std::uint8_t> build_ack_multi(
    const std::vector<std::tuple<std::uint32_t, std::uint32_t, std::vector<MuxAckRange>>>& blocks)
{
    std::vector<std::uint8_t> buf;
    buf.push_back(static_cast<std::uint8_t>(blocks.size()));
    for (const auto& [cid, largest, ranges] : blocks) {
        put_u32_be(buf, cid);
        put_u32_be(buf, largest);
        buf.push_back(static_cast<std::uint8_t>(ranges.size()));
        for (const auto& r : ranges) {
            put_u32_be(buf, r.start);
            put_u32_be(buf, r.end);
        }
    }
    return buf;
}

// ---------------------------------------------------------------------------
// Test framework (minimal, no external deps).
// ---------------------------------------------------------------------------

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define RUN_TEST(name) \
    do { \
        ++g_tests_run; \
        name(); \
        ++g_tests_passed; \
    } while (0)

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            abort(); \
        } \
    } while (0)

// ===========================================================================
// Group 1: DecodeMuxAckFrame — structural validation
// ===========================================================================

// 1.1: null pointer
void test_null_pointer() {
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(nullptr, 10, MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// 1.2: zero-length input
void test_zero_length() {
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(reinterpret_cast<const std::uint8_t*>(""), 0, MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// 1.3: block_count == 0
void test_zero_block_count() {
    std::vector<std::uint8_t> frame = {0x00};
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// 1.4: block_count > max_blocks
void test_block_count_exceeds_max() {
    std::vector<std::uint8_t> frame = {static_cast<std::uint8_t>(MAX_BLOCKS + 1)};
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// 1.5: block_count = 255 (way over max)
void test_block_count_255() {
    std::vector<std::uint8_t> frame = {0xFF};
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// 1.6: range_count == 0 inside a block
void test_zero_range_count() {
    std::vector<std::uint8_t> buf;
    buf.push_back(1); // 1 block
    put_u32_be(buf, 0); // cid
    put_u32_be(buf, 100); // largest
    buf.push_back(0); // 0 ranges — invalid
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(buf.data(), buf.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// 1.7: range_count > max_ranges
void test_range_count_exceeds_max() {
    std::vector<std::uint8_t> buf;
    buf.push_back(1);
    put_u32_be(buf, 0);
    put_u32_be(buf, 100);
    buf.push_back(static_cast<std::uint8_t>(MAX_RANGES + 1));
    // Don't need to append range data — decoder should reject before reading.
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(buf.data(), buf.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// 1.8: range_count = 255
void test_range_count_255() {
    std::vector<std::uint8_t> buf;
    buf.push_back(1);
    put_u32_be(buf, 0);
    put_u32_be(buf, 100);
    buf.push_back(0xFF);
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(buf.data(), buf.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// ===========================================================================
// Group 2: Truncated frames
// ===========================================================================

// 2.1: truncated at block header (len < 9 after block_count)
void test_truncated_block_header() {
    // 1 block, but only 4 bytes after block_count
    std::vector<std::uint8_t> buf;
    buf.push_back(1);
    put_u32_be(buf, 0); // cid only, missing largest + range_count
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(buf.data(), buf.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// 2.2: truncated in range data
void test_truncated_range_data() {
    std::vector<std::uint8_t> buf;
    buf.push_back(1);
    put_u32_be(buf, 0);
    put_u32_be(buf, 100);
    buf.push_back(2); // 2 ranges = 16 bytes expected
    put_u32_be(buf, 90); // range[0].start
    put_u32_be(buf, 95); // range[0].end
    // Only 4 bytes of range[1] instead of 8
    put_u32_be(buf, 96);
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(buf.data(), buf.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// 2.3: truncated to exactly 1 byte (just block_count)
void test_truncated_just_block_count() {
    std::vector<std::uint8_t> buf = {0x01};
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(buf.data(), buf.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// 2.4: truncated between blocks (2 blocks declared, only 1 present)
void test_truncated_between_blocks() {
    std::vector<std::uint8_t> buf;
    buf.push_back(2); // 2 blocks
    // Block 0 (complete)
    put_u32_be(buf, 0);
    put_u32_be(buf, 100);
    buf.push_back(1);
    put_u32_be(buf, 95);
    put_u32_be(buf, 100);
    // Block 1 missing entirely
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(buf.data(), buf.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// 2.5: truncated at each byte position within a single-block frame
void test_truncated_every_byte() {
    // Build a valid frame first.
    auto valid = build_ack(42, 1000, {{900, 950}, {960, 1000}});
    // Truncate at every length from 1 to len-1.
    for (std::size_t trunc = 1; trunc < valid.size(); ++trunc) {
        std::vector<MuxAckBlock> out;
        bool ok = DecodeMuxAckFrame(valid.data(), trunc, MAX_BLOCKS, MAX_RANGES, out);
        // Every truncation must be rejected.
        CHECK(!ok);
        CHECK(out.empty());
    }
}

// ===========================================================================
// Group 3: Range validation
// ===========================================================================

// 3.1: start > end
void test_start_greater_than_end() {
    std::vector<std::uint8_t> buf;
    buf.push_back(1);
    put_u32_be(buf, 0);
    put_u32_be(buf, 100);
    buf.push_back(1);
    put_u32_be(buf, 90);  // start
    put_u32_be(buf, 80);  // end < start — invalid
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(buf.data(), buf.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// 3.2: end > largest
void test_end_greater_than_largest() {
    std::vector<std::uint8_t> buf;
    buf.push_back(1);
    put_u32_be(buf, 0);
    put_u32_be(buf, 100);
    buf.push_back(1);
    put_u32_be(buf, 90);
    put_u32_be(buf, 101); // end > largest — invalid
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(buf.data(), buf.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// 3.3: start == end == largest (boundary valid)
void test_start_end_equal_largest() {
    auto frame = build_ack(0, 100, {{100, 100}});
    std::vector<MuxAckBlock> out;
    CHECK(DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.size() == 1);
    CHECK(out[0].ranges.size() == 1);
    CHECK(out[0].ranges[0].start == 100);
    CHECK(out[0].ranges[0].end == 100);
}

// 3.4: start == 0, end == largest (full range, valid)
void test_full_range() {
    auto frame = build_ack(0, 1000, {{0, 1000}});
    std::vector<MuxAckBlock> out;
    CHECK(DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.size() == 1);
    CHECK(out[0].ranges[0].start == 0);
    CHECK(out[0].ranges[0].end == 1000);
}

// 3.5: overlapping ranges (decoder allows — it doesn't check overlap)
// Verify the decoder accepts overlaps without crash and returns them as-is.
void test_overlapping_ranges() {
    // Ranges [50,100] and [80,120] overlap. Decoder doesn't reject overlap.
    auto frame = build_ack(0, 200, {{50, 100}, {80, 120}});
    std::vector<MuxAckBlock> out;
    bool ok = DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out);
    // Decoder accepts overlapping ranges (it only checks start<=end, end<=largest).
    CHECK(ok);
    CHECK(out.size() == 1);
    CHECK(out[0].ranges.size() == 2);
}

// 3.6: out-of-order ranges (descending) — decoder allows
void test_descending_ranges() {
    // Ranges [80,100] then [50,70] — descending. Decoder doesn't enforce order.
    auto frame = build_ack(0, 200, {{80, 100}, {50, 70}});
    std::vector<MuxAckBlock> out;
    bool ok = DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out);
    CHECK(ok);
    CHECK(out[0].ranges.size() == 2);
}

// 3.7: duplicate ranges
void test_duplicate_ranges() {
    auto frame = build_ack(0, 200, {{50, 100}, {50, 100}});
    std::vector<MuxAckBlock> out;
    bool ok = DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out);
    CHECK(ok);
    CHECK(out[0].ranges.size() == 2);
}

// ===========================================================================
// Group 4: Trailing garbage
// ===========================================================================

// 4.1: extra byte after valid frame
void test_trailing_garbage_one_byte() {
    auto frame = build_ack(0, 100, {{50, 100}});
    frame.push_back(0xAA); // trailing garbage
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// 4.2: many extra bytes
void test_trailing_garbage_many() {
    auto frame = build_ack(0, 100, {{50, 100}});
    for (int i = 0; i < 100; ++i) {
        frame.push_back(static_cast<std::uint8_t>(i));
    }
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// ===========================================================================
// Group 5: Extreme wrap-around values
// ===========================================================================

// 5.1: largest = UINT32_MAX
void test_largest_uint32_max() {
    auto frame = build_ack(0, 0xFFFFFFFFu, {{0xFFFFFF00u, 0xFFFFFFFFu}});
    std::vector<MuxAckBlock> out;
    CHECK(DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out[0].largest == 0xFFFFFFFFu);
}

// 5.2: all fields at UINT32_MAX
void test_all_max() {
    auto frame = build_ack(0xFFFFFFFFu, 0xFFFFFFFFu, {{0xFFFFFFFFu, 0xFFFFFFFFu}});
    std::vector<MuxAckBlock> out;
    CHECK(DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out[0].connection_id == 0xFFFFFFFFu);
    CHECK(out[0].largest == 0xFFFFFFFFu);
    CHECK(out[0].ranges[0].start == 0xFFFFFFFFu);
    CHECK(out[0].ranges[0].end == 0xFFFFFFFFu);
}

// 5.3: start=0, end=0, largest=0 — edge case (0 is a valid sequence)
void test_all_zero() {
    auto frame = build_ack(0, 0, {{0, 0}});
    std::vector<MuxAckBlock> out;
    CHECK(DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out[0].largest == 0);
    CHECK(out[0].ranges[0].start == 0);
    CHECK(out[0].ranges[0].end == 0);
}

// 5.4: wrap-around: largest near 0, range near UINT32_MAX (invalid: end > largest)
void test_wrap_invalid() {
    // largest = 5, range [0xFFFFFFF0, 0xFFFFFFFF] — end > largest
    auto frame = build_ack(0, 5, {{0xFFFFFFF0u, 0xFFFFFFFFu}});
    std::vector<MuxAckBlock> out;
    CHECK(!DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.empty());
}

// ===========================================================================
// Group 6: Multi-block edge cases
// ===========================================================================

// 6.1: max_blocks valid
void test_max_blocks_valid() {
    std::vector<std::tuple<std::uint32_t, std::uint32_t, std::vector<MuxAckRange>>> blocks;
    for (std::size_t i = 0; i < MAX_BLOCKS; ++i) {
        blocks.push_back({static_cast<std::uint32_t>(i), 100, {{50, 100}}});
    }
    auto frame = build_ack_multi(blocks);
    std::vector<MuxAckBlock> out;
    CHECK(DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out.size() == MAX_BLOCKS);
}

// 6.2: max_ranges valid per block
void test_max_ranges_valid() {
    std::vector<MuxAckRange> ranges;
    for (std::size_t i = 0; i < MAX_RANGES; ++i) {
        ranges.push_back({static_cast<std::uint32_t>(i * 4), static_cast<std::uint32_t>(i * 4 + 3)});
    }
    auto frame = build_ack(0, MAX_RANGES * 4 - 1, ranges);
    std::vector<MuxAckBlock> out;
    CHECK(DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out));
    CHECK(out[0].ranges.size() == MAX_RANGES);
}

// 6.3: duplicate connection_id across blocks (decoder allows)
void test_duplicate_cid_blocks() {
    auto frame = build_ack_multi({
        {5, 100, {{50, 100}}},
        {5, 200, {{150, 200}}},  // same cid
    });
    std::vector<MuxAckBlock> out;
    bool ok = DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out);
    CHECK(ok);
    CHECK(out.size() == 2);
    CHECK(out[0].connection_id == 5);
    CHECK(out[1].connection_id == 5);
}

// ===========================================================================
// Group 7: Volume / DoS resistance
// ===========================================================================

// 7.1: 10000 decode calls of valid frames — no crash, no resource growth
void test_high_volume_valid() {
    for (int i = 0; i < 10000; ++i) {
        auto frame = build_ack(0, 1000, {{static_cast<std::uint32_t>(i % 1000), static_cast<std::uint32_t>((i % 1000) + 100)}});
        // Some will have end > largest — those are invalid.
        std::vector<MuxAckBlock> out;
        DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out);
        // Whether ok or not, out should be either empty or bounded.
        CHECK(out.size() <= 1);
    }
}

// 7.2: 10000 decode calls of invalid frames — no crash, no growth
void test_high_volume_invalid() {
    for (int i = 0; i < 10000; ++i) {
        std::vector<std::uint8_t> garbage;
        garbage.push_back(static_cast<std::uint8_t>(1));
        for (int j = 0; j < 20; ++j) {
            garbage.push_back(static_cast<std::uint8_t>((i * 31 + j * 7) & 0xFF));
        }
        std::vector<MuxAckBlock> out;
        DecodeMuxAckFrame(garbage.data(), garbage.size(), MAX_BLOCKS, MAX_RANGES, out);
        CHECK(out.size() <= 1);
    }
}

// 7.3: response amplification check — decoded output size ≤ input size
void test_no_response_amplification() {
    // Build a max-size valid frame.
    std::vector<MuxAckRange> ranges;
    for (std::size_t i = 0; i < MAX_RANGES; ++i) {
        ranges.push_back({static_cast<std::uint32_t>(i * 4), static_cast<std::uint32_t>(i * 4 + 3)});
    }
    std::vector<std::tuple<std::uint32_t, std::uint32_t, std::vector<MuxAckRange>>> blocks;
    for (std::size_t i = 0; i < MAX_BLOCKS; ++i) {
        blocks.push_back({static_cast<std::uint32_t>(i), 1000, ranges});
    }
    auto frame = build_ack_multi(blocks);

    std::vector<MuxAckBlock> out;
    CHECK(DecodeMuxAckFrame(frame.data(), frame.size(), MAX_BLOCKS, MAX_RANGES, out));

    // Measure decoded "output size": sum of all ranges across all blocks.
    std::size_t decoded_ranges = 0;
    for (const auto& b : out) {
        decoded_ranges += b.ranges.size();
    }
    // Each decoded range corresponds to 8 input bytes + 9 bytes block header.
    // The decoded struct is smaller than the wire representation.
    CHECK(decoded_ranges == MAX_BLOCKS * MAX_RANGES);
    CHECK(frame.size() == 1 + MAX_BLOCKS * (9 + MAX_RANGES * 8));

    // Decoded ranges count can never exceed what was in the wire format.
    CHECK(decoded_ranges * sizeof(MuxAckRange) <= frame.size());
}

// ===========================================================================
// Group 8: MuxRetransmitBuffer interaction
// ===========================================================================

// Helper: create a buffer for RTX tracking.
struct RtxBuffer {
    std::shared_ptr<std::uint8_t> data;
    int length;
};

RtxBuffer make_rtx_buffer(const std::string& payload) {
    RtxBuffer b;
    b.length = static_cast<int>(payload.size());
    b.data = std::shared_ptr<std::uint8_t>(
        new std::uint8_t[b.length],
        std::default_delete<std::uint8_t[]>());
    std::memcpy(b.data.get(), payload.data(), b.length);
    return b;
}

// 8.1: ACK confirming never-sent DSNs — RTX buffer must be unchanged
void test_ack_unsent_dsn_no_effect() {
    MuxRetransmitBuffer rtx;
    auto buf = make_rtx_buffer("hello");
    CHECK(rtx.Track(0, 10, buf.data, buf.length, 100, 1024 * 1024, 1));
    CHECK(rtx.size() == 1);

    // ACK for DSN 50-100, which was never sent.
    std::vector<MuxAckRange> ranges = {{50, 100}};
    std::vector<std::uint64_t> fast_candidates;
    rtx.Ack(0, 100, ranges, 200, 3, 0, fast_candidates);

    // RTX buffer should still have our entry.
    CHECK(rtx.size() == 1);
    CHECK(rtx.bytes() == static_cast<std::size_t>(buf.length));
}

// 8.2: ACK with valid range removes the right entry
void test_ack_removes_correct_entry() {
    MuxRetransmitBuffer rtx;
    auto buf1 = make_rtx_buffer("aaa");
    auto buf2 = make_rtx_buffer("bbb");
    auto buf3 = make_rtx_buffer("ccc");

    CHECK(rtx.Track(0, 10, buf1.data, buf1.length, 100, 1024 * 1024, 1));
    CHECK(rtx.Track(0, 20, buf2.data, buf2.length, 100, 1024 * 1024, 1));
    CHECK(rtx.Track(0, 30, buf3.data, buf3.length, 100, 1024 * 1024, 1));
    CHECK(rtx.size() == 3);

    // ACK DSN 20 only.
    std::vector<MuxAckRange> ranges = {{20, 20}};
    std::vector<std::uint64_t> fast_candidates;
    rtx.Ack(0, 30, ranges, 200, 3, 0, fast_candidates);

    CHECK(rtx.size() == 2);
    // Entries 10 and 30 should remain.
    CHECK(rtx.Find(MuxRetransmitBuffer::Key(0, 10)) != nullptr);
    CHECK(rtx.Find(MuxRetransmitBuffer::Key(0, 20)) == nullptr);
    CHECK(rtx.Find(MuxRetransmitBuffer::Key(0, 30)) != nullptr);
}

// 8.3: ACK for different connection_id doesn't affect entries
void test_ack_different_cid_no_effect() {
    MuxRetransmitBuffer rtx;
    auto buf = make_rtx_buffer("test");
    CHECK(rtx.Track(5, 10, buf.data, buf.length, 100, 1024 * 1024, 1));

    // ACK for cid 3.
    std::vector<MuxAckRange> ranges = {{10, 10}};
    std::vector<std::uint64_t> fast_candidates;
    rtx.Ack(3, 10, ranges, 200, 3, 0, fast_candidates);

    CHECK(rtx.size() == 1);
    CHECK(rtx.Find(MuxRetransmitBuffer::Key(5, 10)) != nullptr);
}

// 8.4: ACK with overlapping ranges — entries should be removed once, not double-freed
void test_ack_overlapping_ranges_no_double_free() {
    MuxRetransmitBuffer rtx;
    auto buf = make_rtx_buffer("overlap");

    CHECK(rtx.Track(0, 50, buf.data, buf.length, 100, 1024 * 1024, 1));
    CHECK(rtx.size() == 1);

    // Overlapping ranges both covering DSN 50.
    std::vector<MuxAckRange> ranges = {{40, 60}, {50, 70}};
    std::vector<std::uint64_t> fast_candidates;
    rtx.Ack(0, 100, ranges, 200, 3, 0, fast_candidates);

    // Entry should be removed exactly once.
    CHECK(rtx.size() == 0);
    CHECK(rtx.bytes() == 0);
}

// 8.5: ACK with range.end > largest (passed directly to RTX, bypassing decoder)
// RTX buffer should handle gracefully (it just checks seq in range).
void test_rtx_ack_range_exceeds_largest() {
    MuxRetransmitBuffer rtx;
    auto buf = make_rtx_buffer("test");
    CHECK(rtx.Track(0, 50, buf.data, buf.length, 100, 1024 * 1024, 1));

    // Malicious range: end > largest.  RTX.Ack doesn't validate this; it just
    // checks if seq is in [start, end].  DSN 50 is in [40, 200], so it gets
    // acked.  This is not a security issue — the entry is correctly released.
    std::vector<MuxAckRange> ranges = {{40, 200}};
    std::vector<std::uint64_t> fast_candidates;
    rtx.Ack(0, 100, ranges, 200, 3, 0, fast_candidates);

    CHECK(rtx.size() == 0);
}

// 8.6: ACK with start > end (malicious) — RTX checks seq >= start && seq <= end
// If start > end, no seq can match, so no entry is removed.  Safe.
void test_rtx_ack_start_greater_than_end() {
    MuxRetransmitBuffer rtx;
    auto buf = make_rtx_buffer("test");
    CHECK(rtx.Track(0, 50, buf.data, buf.length, 100, 1024 * 1024, 1));

    std::vector<MuxAckRange> ranges = {{100, 40}}; // start > end
    std::vector<std::uint64_t> fast_candidates;
    rtx.Ack(0, 100, ranges, 200, 3, 0, fast_candidates);

    // No entry should be removed (no seq satisfies start <= seq <= end when start > end).
    CHECK(rtx.size() == 1);
}

// 8.7: Empty ranges vector — no effect
void test_rtx_ack_empty_ranges() {
    MuxRetransmitBuffer rtx;
    auto buf = make_rtx_buffer("test");
    CHECK(rtx.Track(0, 50, buf.data, buf.length, 100, 1024 * 1024, 1));

    std::vector<MuxAckRange> ranges;
    std::vector<std::uint64_t> fast_candidates;
    rtx.Ack(0, 100, ranges, 200, 3, 0, fast_candidates);

    CHECK(rtx.size() == 1);
}

// 8.8: Large number of ranges — RTX must handle without excessive CPU
void test_rtx_ack_many_ranges() {
    MuxRetransmitBuffer rtx;
    // Track 100 entries.
    for (int i = 0; i < 100; ++i) {
        auto buf = make_rtx_buffer("x");
        CHECK(rtx.Track(0, static_cast<std::uint32_t>(i), buf.data, buf.length,
                        100, 1024 * 1024, 1));
    }
    CHECK(rtx.size() == 100);

    // ACK with 24 ranges (max), each covering 4 DSNs.
    std::vector<MuxAckRange> ranges;
    for (int i = 0; i < 24; ++i) {
        ranges.push_back({static_cast<std::uint32_t>(i * 4),
                          static_cast<std::uint32_t>(i * 4 + 3)});
    }
    std::vector<std::uint64_t> fast_candidates;
    rtx.Ack(0, 95, ranges, 200, 3, 0, fast_candidates);

    // 24 * 4 = 96 entries should be acked.
    CHECK(rtx.size() == 4);
}

// 8.9: Byte cap enforcement — Track returns false when exceeded
void test_rtx_byte_cap() {
    MuxRetransmitBuffer rtx;
    auto buf = make_rtx_buffer(std::string(100, 'x'));

    // byte_cap = 50, frame = 100 → should fail.
    CHECK(!rtx.Track(0, 1, buf.data, buf.length, 100, 50, 1));
    CHECK(rtx.size() == 0);
    CHECK(rtx.bytes() == 0);

    // byte_cap = 200 → should succeed.
    CHECK(rtx.Track(0, 1, buf.data, buf.length, 100, 200, 1));
    CHECK(rtx.size() == 1);
    CHECK(rtx.bytes() == 100);
}

// 8.10: Flow close (EraseCid) cleans up all entries for that cid
void test_erase_cid() {
    MuxRetransmitBuffer rtx;
    auto buf = make_rtx_buffer("x");
    rtx.Track(0, 10, buf.data, buf.length, 100, 1024 * 1024, 1);
    rtx.Track(0, 20, buf.data, buf.length, 100, 1024 * 1024, 1);
    rtx.Track(1, 30, buf.data, buf.length, 100, 1024 * 1024, 1);

    rtx.EraseCid(0);
    CHECK(rtx.size() == 1);
    CHECK(rtx.Find(MuxRetransmitBuffer::Key(0, 10)) == nullptr);
    CHECK(rtx.Find(MuxRetransmitBuffer::Key(0, 20)) == nullptr);
    CHECK(rtx.Find(MuxRetransmitBuffer::Key(1, 30)) != nullptr);
}

// 8.11: Re-ack of already-acked entry is safe (idempotent)
void test_reack_already_acked() {
    MuxRetransmitBuffer rtx;
    auto buf = make_rtx_buffer("test");
    CHECK(rtx.Track(0, 50, buf.data, buf.length, 100, 1024 * 1024, 1));

    std::vector<MuxAckRange> ranges = {{50, 50}};
    std::vector<std::uint64_t> fast_candidates;

    // First ack removes entry.
    rtx.Ack(0, 50, ranges, 200, 3, 0, fast_candidates);
    CHECK(rtx.size() == 0);

    // Second ack on same DSN — should be safe, no crash, no negative bytes.
    rtx.Ack(0, 50, ranges, 300, 3, 0, fast_candidates);
    CHECK(rtx.size() == 0);
    CHECK(rtx.bytes() == 0);
}

// 8.12: Fast retransmit candidate detection — spurious fast rtx should be deduped
void test_fast_rtx_dedup() {
    MuxRetransmitBuffer rtx;
    // Track entries DSN 10..15.
    for (int i = 10; i <= 15; ++i) {
        auto buf = make_rtx_buffer("x");
        CHECK(rtx.Track(0, static_cast<std::uint32_t>(i), buf.data, buf.length,
                        100, 1024 * 1024, 1));
    }

    // ACK DSN 15 (largest).  DSN 10 is 5 below largest, with threshold=3.
    // Time threshold=0 (disabled).  DSN 10 should become a fast candidate.
    std::vector<MuxAckRange> ranges = {{15, 15}};
    std::vector<std::uint64_t> fast_candidates;
    rtx.Ack(0, 15, ranges, 200, 3, 0, fast_candidates);

    // DSN 10, 11, 12 are ≥3 below largest=15.
    CHECK(fast_candidates.size() == 3);

    // Second ACK with same largest — should NOT produce duplicates.
    fast_candidates.clear();
    rtx.Ack(0, 15, ranges, 250, 3, 0, fast_candidates);
    CHECK(fast_candidates.empty()); // Deduped via fast_rtx_mark.
}

// ===========================================================================
// Group 9: Round-trip encode → decode fidelity
// ===========================================================================

// 9.1: Encode then decode produces identical blocks
void test_encode_decode_roundtrip() {
    std::vector<MuxAckBlock> blocks;
    MuxAckBlock b0;
    b0.connection_id = 42;
    b0.largest = 1000;
    b0.ranges = {{100, 200}, {300, 400}, {500, 600}};
    blocks.push_back(b0);

    MuxAckBlock b1;
    b1.connection_id = 99;
    b1.largest = 5000;
    b1.ranges = {{0, 10}, {4990, 5000}};
    blocks.push_back(b1);

    std::size_t cap = MuxAckFrameMaxSize(MAX_BLOCKS, MAX_RANGES);
    std::vector<std::uint8_t> wire(cap);
    std::size_t len = EncodeMuxAckFrame(blocks.data(), blocks.size(),
                                        wire.data(), cap, MAX_RANGES);
    CHECK(len > 0);
    wire.resize(len);

    std::vector<MuxAckBlock> decoded;
    CHECK(DecodeMuxAckFrame(wire.data(), wire.size(), MAX_BLOCKS, MAX_RANGES, decoded));
    CHECK(decoded.size() == 2);

    CHECK(decoded[0].connection_id == 42);
    CHECK(decoded[0].largest == 1000);
    CHECK(decoded[0].ranges.size() == 3);
    CHECK(decoded[0].ranges[0].start == 100);
    CHECK(decoded[0].ranges[0].end == 200);
    CHECK(decoded[0].ranges[2].start == 500);
    CHECK(decoded[0].ranges[2].end == 600);

    CHECK(decoded[1].connection_id == 99);
    CHECK(decoded[1].largest == 5000);
    CHECK(decoded[1].ranges.size() == 2);
    CHECK(decoded[1].ranges[1].start == 4990);
    CHECK(decoded[1].ranges[1].end == 5000);
}

// 9.2: Encode with insufficient cap returns 0
void test_encode_insufficient_cap() {
    MuxAckBlock block;
    block.connection_id = 0;
    block.largest = 100;
    block.ranges = {{0, 100}};

    std::vector<std::uint8_t> wire(5); // Too small.
    std::size_t len = EncodeMuxAckFrame(&block, 1, wire.data(), 5, MAX_RANGES);
    CHECK(len == 0);
}

// 9.3: Encode with block_count > 255 returns 0
void test_encode_too_many_blocks() {
    std::vector<MuxAckBlock> blocks(300);
    std::vector<std::uint8_t> wire(10000);
    CHECK(EncodeMuxAckFrame(blocks.data(), 300, wire.data(), 10000, MAX_RANGES) == 0);
}

// ===========================================================================
// Group 10: MuxAckTracker (receiver side) — wrap and bounds
// ===========================================================================

// 10.1: Tracker caps at max_ranges
void test_tracker_caps_ranges() {
    MuxAckTracker tracker;
    constexpr std::size_t MAX_R = 8;
    // Add 20 distinct, non-mergeable ranges.
    for (int i = 0; i < 20; ++i) {
        tracker.Add(static_cast<std::uint32_t>(i * 10), MAX_R);
    }
    CHECK(tracker.size() <= MAX_R);
}

// 10.2: Tracker merges adjacent ranges
void test_tracker_merges_adjacent() {
    MuxAckTracker tracker;
    tracker.Add(10, 100);
    tracker.Add(11, 100);
    tracker.Add(12, 100);
    CHECK(tracker.size() == 1);
    CHECK(tracker.largest() == 12);
    CHECK(tracker.ranges()[0].start == 10);
    CHECK(tracker.ranges()[0].end == 12);
}

// 10.3: Tracker wrap resets
void test_tracker_wrap() {
    MuxAckTracker tracker;
    tracker.Add(0xFFFFFFF0u, 100);
    CHECK(tracker.size() == 1);
    CHECK(tracker.largest() == 0xFFFFFFF0u);

    // Add a sequence that's more than half the space behind — triggers wrap.
    tracker.Add(10, 100);
    // After wrap, tracker should have reset and now only contain 10.
    CHECK(tracker.size() == 1);
    CHECK(tracker.largest() == 10);
}

// 10.4: Tracker duplicate sequence is a no-op (already in range)
void test_tracker_duplicate() {
    MuxAckTracker tracker;
    tracker.Add(50, 100);
    tracker.Add(50, 100);
    CHECK(tracker.size() == 1);
    CHECK(tracker.ranges()[0].start == 50);
    CHECK(tracker.ranges()[0].end == 50);
}

} // namespace

int main() {
    // Group 1: Structural validation
    RUN_TEST(test_null_pointer);
    RUN_TEST(test_zero_length);
    RUN_TEST(test_zero_block_count);
    RUN_TEST(test_block_count_exceeds_max);
    RUN_TEST(test_block_count_255);
    RUN_TEST(test_zero_range_count);
    RUN_TEST(test_range_count_exceeds_max);
    RUN_TEST(test_range_count_255);

    // Group 2: Truncated frames
    RUN_TEST(test_truncated_block_header);
    RUN_TEST(test_truncated_range_data);
    RUN_TEST(test_truncated_just_block_count);
    RUN_TEST(test_truncated_between_blocks);
    RUN_TEST(test_truncated_every_byte);

    // Group 3: Range validation
    RUN_TEST(test_start_greater_than_end);
    RUN_TEST(test_end_greater_than_largest);
    RUN_TEST(test_start_end_equal_largest);
    RUN_TEST(test_full_range);
    RUN_TEST(test_overlapping_ranges);
    RUN_TEST(test_descending_ranges);
    RUN_TEST(test_duplicate_ranges);

    // Group 4: Trailing garbage
    RUN_TEST(test_trailing_garbage_one_byte);
    RUN_TEST(test_trailing_garbage_many);

    // Group 5: Extreme wrap-around
    RUN_TEST(test_largest_uint32_max);
    RUN_TEST(test_all_max);
    RUN_TEST(test_all_zero);
    RUN_TEST(test_wrap_invalid);

    // Group 6: Multi-block
    RUN_TEST(test_max_blocks_valid);
    RUN_TEST(test_max_ranges_valid);
    RUN_TEST(test_duplicate_cid_blocks);

    // Group 7: Volume / DoS
    RUN_TEST(test_high_volume_valid);
    RUN_TEST(test_high_volume_invalid);
    RUN_TEST(test_no_response_amplification);

    // Group 8: RTX buffer interaction
    RUN_TEST(test_ack_unsent_dsn_no_effect);
    RUN_TEST(test_ack_removes_correct_entry);
    RUN_TEST(test_ack_different_cid_no_effect);
    RUN_TEST(test_ack_overlapping_ranges_no_double_free);
    RUN_TEST(test_rtx_ack_range_exceeds_largest);
    RUN_TEST(test_rtx_ack_start_greater_than_end);
    RUN_TEST(test_rtx_ack_empty_ranges);
    RUN_TEST(test_rtx_ack_many_ranges);
    RUN_TEST(test_rtx_byte_cap);
    RUN_TEST(test_erase_cid);
    RUN_TEST(test_reack_already_acked);
    RUN_TEST(test_fast_rtx_dedup);

    // Group 9: Round-trip
    RUN_TEST(test_encode_decode_roundtrip);
    RUN_TEST(test_encode_insufficient_cap);
    RUN_TEST(test_encode_too_many_blocks);

    // Group 10: AckTracker (receiver)
    RUN_TEST(test_tracker_caps_ranges);
    RUN_TEST(test_tracker_merges_adjacent);
    RUN_TEST(test_tracker_wrap);
    RUN_TEST(test_tracker_duplicate);

    fprintf(stderr, "vmux_qa001_ack_malicious_test: %d/%d tests passed\n",
            g_tests_passed, g_tests_run);
    return 0;
}
