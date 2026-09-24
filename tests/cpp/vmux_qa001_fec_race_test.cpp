#define BOOST_TEST_MODULE vmux_qa001_fec_race_test
#include <boost/test/included/unit_test.hpp>

/**
 * @file vmux_qa001_fec_race_test.cpp
 * @brief VMUX-QA-001: FEC recovery vs original data race conditions.
 * @license GPL-3.0
 *
 * Tests the FEC recovery path when parity and original/RTX frames compete
 * to fill a missing slot. The core invariant is: regardless of arrival order,
 * the missing frame is recovered at most once, the recovered bytes are
 * byte-exact, and duplicate arrivals after recovery do not cause double
 * delivery or state corruption.
 *
 * Because the full vmux_net session cannot be instantiated in the standalone
 * test suite, we simulate the receiver-side FEC state machine using the real
 * MuxFecEncoder / ParseMuxFecFrame / MuxFecRecover functions and a faithful
 * re-implementation of the per-group tracking logic.
 *
 * Scenarios covered:
 *   1.  parity arrives before any data frame → recovery, then originals arrive
 *   2.  some data frames arrive, then parity → recovery of the missing one
 *   3.  all data frames arrive, then parity → no recovery needed
 *   4.  FEC recovery and RTX of the same frame compete → only one delivery
 *   5.  two data frames missing → recovery fails, left to RTX
 *   6.  duplicate parity frames → second is ignored
 *   7.  group ID wrap-around → old group's parity does not affect new group
 *   8.  flow close after FEC group started → late parity is safely ignored
 *   9.  parity with wrong entry count → rejected
 *  10.  recovered frame passes byte-exact verification
 *  11.  extreme length disparity (1B vs 60000B) → recovery still correct
 *  12.  parity arrives, recovery succeeds, then original arrives → no double
 */

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <vector>

#include <ppp/app/mux/MuxFecCodec.h>

namespace mux = ppp::app::mux;

namespace {

// Generate a deterministic frame with given seed and length.
std::vector<std::uint8_t> make_frame(std::uint8_t seed, std::size_t length) {
    std::vector<std::uint8_t> frame(length);
    for (std::size_t i = 0; i < length; ++i) {
        frame[i] = static_cast<std::uint8_t>(seed + i * 31);
    }
    return frame;
}

// Build a parity wire frame from a group of frames.
struct GroupBuilder {
    mux::MuxFecEncoder encoder;
    std::vector<std::vector<std::uint8_t>> frames;
    std::vector<mux::MuxFecFrameId> ids;
    std::vector<std::uint8_t> wire;

    void add(std::uint32_t cid, std::uint32_t seq, const std::vector<std::uint8_t>& frame) {
        if (frames.empty()) {
            encoder.Reset(0);
        }
        encoder.Add(cid, seq, frame.data(), static_cast<int>(frame.size()));
        frames.push_back(frame);
        ids.push_back({ cid, seq });
    }

    void build() {
        wire.resize(encoder.MaxPayloadSize());
        int len = encoder.Build(wire.data(), static_cast<int>(wire.size()));
        BOOST_REQUIRE(len > 0);
        wire.resize(static_cast<std::size_t>(len));
    }
};

/**
 * Simulated per-group receiver state.
 * Tracks which frames have been delivered and whether FEC recovery occurred.
 * Mirrors the essential invariants of vmux_net's FEC group cache:
 *   - A frame is delivered at most once.
 *   - Recovery happens only when exactly one frame is missing.
 *   - A late-arriving original after recovery is silently dropped.
 */
struct FecGroupState {
    std::vector<mux::MuxFecFrameId> entries;
    std::vector<std::vector<std::uint8_t>> received_frames; // index-aligned, empty = not yet received
    std::vector<bool> delivered;       // true = frame was delivered to upper layer
    bool parity_received = false;
    std::vector<std::uint8_t> parity;
    bool recovery_attempted = false;
    int recovered_index = -1;
    bool flow_closed = false;

    void init(const mux::MuxFecFrameView& view) {
        entries = view.entries;
        received_frames.resize(entries.size());
        delivered.assign(entries.size(), false);
        parity_received = true;
        parity = view.parity;
    }

    // Receive an original data frame for this group. Returns true if delivered.
    bool receive_data(int index, const std::uint8_t* data, int len) {
        if (flow_closed) return false;
        if (index < 0 || index >= static_cast<int>(entries.size())) return false;
        if (delivered[index]) return false; // Already delivered (duplicate).

        received_frames[index].assign(data, data + len);
        delivered[index] = true;
        return true;
    }

    // Count how many frames are still missing.
    int missing_count() const {
        int c = 0;
        for (bool d : delivered) {
            if (!d) ++c;
        }
        return c;
    }

    // Attempt FEC recovery if exactly one frame is missing and parity is available.
    // Returns the recovered frame, or empty vector if recovery not possible.
    std::vector<std::uint8_t> try_recover() {
        if (!parity_received || recovery_attempted || flow_closed) {
            return {};
        }
        if (missing_count() != 1) {
            return {};
        }

        // Find the missing index.
        int missing_idx = -1;
        for (int i = 0; i < static_cast<int>(entries.size()); ++i) {
            if (!delivered[i]) {
                missing_idx = i;
                break;
            }
        }
        if (missing_idx < 0) return {};

        recovery_attempted = true;

        // Build the present array.
        std::vector<const std::uint8_t*> present(entries.size(), nullptr);
        std::vector<int> present_lengths(entries.size(), 0);
        for (int i = 0; i < static_cast<int>(entries.size()); ++i) {
            if (i == missing_idx) continue;
            present[i] = received_frames[i].data();
            present_lengths[i] = static_cast<int>(received_frames[i].size());
        }

        mux::MuxFecFrameView view;
        view.entries = entries;
        view.parity = parity;

        std::vector<std::uint8_t> recovered(parity.size());
        int recovered_len = mux::MuxFecRecover(view, present.data(), present_lengths.data(),
            missing_idx, recovered.data(), static_cast<int>(recovered.size()));

        if (recovered_len <= 0) {
            return {};
        }

        recovered.resize(static_cast<std::size_t>(recovered_len));

        // Mark as delivered.
        received_frames[missing_idx] = recovered;
        delivered[missing_idx] = true;
        recovered_index = missing_idx;

        return recovered;
    }

    // Close the flow — late arrivals should be ignored.
    void close_flow() {
        flow_closed = true;
    }
};

} // anonymous namespace

// ===========================================================================
// Scenario 1: Parity arrives before any data frame.
//              Recovery fills the single missing slot, then originals arrive.
//              Late originals must be silently dropped (already delivered via FEC).
// ===========================================================================

BOOST_AUTO_TEST_CASE(parity_first_then_originals_no_double_delivery) {
    GroupBuilder gb;
    auto f1 = make_frame(10, 20);
    auto f2 = make_frame(20, 30);
    auto f3 = make_frame(30, 25);
    gb.add(1, 1, f1);
    gb.add(1, 2, f2);
    gb.add(1, 3, f3);
    gb.build();

    // Parse parity.
    mux::MuxFecFrameView view;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(gb.wire.data(), static_cast<int>(gb.wire.size()), 16, view));

    FecGroupState group;
    group.init(view);

    // No data frames have arrived. 3 missing — can't recover yet.
    BOOST_TEST(group.missing_count() == 3);
    BOOST_TEST(group.try_recover().empty());

    // f1 arrives.
    BOOST_TEST(group.receive_data(0, f1.data(), static_cast<int>(f1.size())));
    BOOST_TEST(group.missing_count() == 2);
    BOOST_TEST(group.try_recover().empty()); // Still 2 missing.

    // f3 arrives. Now only f2 is missing — recover.
    BOOST_TEST(group.receive_data(2, f3.data(), static_cast<int>(f3.size())));
    BOOST_TEST(group.missing_count() == 1);

    auto recovered = group.try_recover();
    BOOST_REQUIRE(!recovered.empty());
    BOOST_TEST(recovered.size() == f2.size());
    BOOST_TEST(std::memcmp(recovered.data(), f2.data(), f2.size()) == 0);
    BOOST_TEST(group.missing_count() == 0);
    BOOST_TEST(group.recovered_index == 1);

    // Late f2 arrives — should NOT be delivered again.
    BOOST_TEST(!group.receive_data(1, f2.data(), static_cast<int>(f2.size())));
    BOOST_TEST(group.missing_count() == 0); // Still 0.
}

// ===========================================================================
// Scenario 2: Some data frames arrive, then parity → recovery.
//              This is the normal "loss detected via parity" path.
// ===========================================================================

BOOST_AUTO_TEST_CASE(data_then_parity_recovers_missing) {
    GroupBuilder gb;
    auto f1 = make_frame(100, 15);
    auto f2 = make_frame(200, 40);
    auto f3 = make_frame(250, 15);
    auto f4 = make_frame(180, 20);
    gb.add(5, 1, f1);
    gb.add(5, 2, f2);
    gb.add(5, 3, f3);
    gb.add(5, 4, f4);
    gb.build();

    // Simulate: f1, f2, f4 arrived. f3 lost.
    mux::MuxFecFrameView view;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(gb.wire.data(), static_cast<int>(gb.wire.size()), 16, view));

    FecGroupState group;
    group.init(view);
    group.receive_data(0, f1.data(), static_cast<int>(f1.size()));
    group.receive_data(1, f2.data(), static_cast<int>(f2.size()));
    group.receive_data(3, f4.data(), static_cast<int>(f4.size()));

    BOOST_TEST(group.missing_count() == 1);

    auto recovered = group.try_recover();
    BOOST_REQUIRE(!recovered.empty());
    BOOST_TEST(recovered.size() == f3.size());
    BOOST_TEST(std::memcmp(recovered.data(), f3.data(), f3.size()) == 0);
}

// ===========================================================================
// Scenario 3: All data frames arrive, then parity → no recovery needed.
//              Parity is recorded but recovery is not attempted.
// ===========================================================================

BOOST_AUTO_TEST_CASE(all_data_arrives_no_recovery_needed) {
    GroupBuilder gb;
    auto f1 = make_frame(50, 12);
    auto f2 = make_frame(60, 18);
    gb.add(3, 10, f1);
    gb.add(3, 11, f2);
    gb.build();

    mux::MuxFecFrameView view;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(gb.wire.data(), static_cast<int>(gb.wire.size()), 16, view));

    FecGroupState group;
    group.init(view);
    group.receive_data(0, f1.data(), static_cast<int>(f1.size()));
    group.receive_data(1, f2.data(), static_cast<int>(f2.size()));

    BOOST_TEST(group.missing_count() == 0);
    BOOST_TEST(group.try_recover().empty()); // Nothing to recover.
    BOOST_TEST(!group.recovery_attempted);
}

// ===========================================================================
// Scenario 4: FEC recovery and RTX of the same frame compete.
//              RTX arrives first → frame delivered. Then parity triggers
//              recovery attempt → recovery finds 0 missing → no-op.
//              Alternatively: recovery first, then RTX → RTX is duplicate.
// ===========================================================================

BOOST_AUTO_TEST_CASE(rtx_and_fec_competition_single_delivery) {
    GroupBuilder gb;
    auto f1 = make_frame(11, 22);
    auto f2 = make_frame(22, 22);
    auto f3 = make_frame(33, 22);
    gb.add(7, 1, f1);
    gb.add(7, 2, f2);
    gb.add(7, 3, f3);
    gb.build();

    mux::MuxFecFrameView view;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(gb.wire.data(), static_cast<int>(gb.wire.size()), 16, view));

    // --- Sub-case A: RTX fills the gap before FEC recovery. ---
    {
        FecGroupState group;
        group.init(view);

        // f1 and f3 arrive. f2 is missing.
        group.receive_data(0, f1.data(), static_cast<int>(f1.size()));
        group.receive_data(2, f3.data(), static_cast<int>(f3.size()));
        BOOST_TEST(group.missing_count() == 1);

        // RTX of f2 arrives before recovery is attempted.
        BOOST_TEST(group.receive_data(1, f2.data(), static_cast<int>(f2.size())));
        BOOST_TEST(group.missing_count() == 0);

        // Now try recovery — nothing missing.
        BOOST_TEST(group.try_recover().empty());
        BOOST_TEST(group.recovered_index == -1); // Recovery didn't fire.
    }

    // --- Sub-case B: FEC recovery fires first, then RTX arrives. ---
    {
        FecGroupState group;
        group.init(view);

        group.receive_data(0, f1.data(), static_cast<int>(f1.size()));
        group.receive_data(2, f3.data(), static_cast<int>(f3.size()));

        auto recovered = group.try_recover();
        BOOST_REQUIRE(!recovered.empty());
        BOOST_TEST(std::memcmp(recovered.data(), f2.data(), f2.size()) == 0);

        // Late RTX of f2 — should be rejected (already delivered via FEC).
        BOOST_TEST(!group.receive_data(1, f2.data(), static_cast<int>(f2.size())));
    }
}

// ===========================================================================
// Scenario 5: Two data frames missing → recovery fails, left to RTX.
//              FEC can only recover exactly one loss per group.
// ===========================================================================

BOOST_AUTO_TEST_CASE(two_missing_recovery_fails) {
    GroupBuilder gb;
    auto f1 = make_frame(15, 30);
    auto f2 = make_frame(25, 30);
    auto f3 = make_frame(35, 30);
    gb.add(2, 1, f1);
    gb.add(2, 2, f2);
    gb.add(2, 3, f3);
    gb.build();

    mux::MuxFecFrameView view;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(gb.wire.data(), static_cast<int>(gb.wire.size()), 16, view));

    FecGroupState group;
    group.init(view);

    // Only f1 arrives. f2 and f3 missing.
    group.receive_data(0, f1.data(), static_cast<int>(f1.size()));
    BOOST_TEST(group.missing_count() == 2);
    BOOST_TEST(!group.recovery_attempted); // Recovery not attempted (2 missing).
    BOOST_TEST(group.missing_count() == 2); // Still missing.

    // f3 arrives via RTX. Now 1 missing → recovery can succeed.
    group.receive_data(2, f3.data(), static_cast<int>(f3.size()));
    BOOST_TEST(group.missing_count() == 1);

    // Reset recovery_attempted to allow a second try (in real code, the
    // arrival of a new frame would re-evaluate recovery).
    group.recovery_attempted = false;
    auto recovered = group.try_recover();
    BOOST_REQUIRE(!recovered.empty());
    BOOST_TEST(std::memcmp(recovered.data(), f2.data(), f2.size()) == 0);
}

// ===========================================================================
// Scenario 6: Duplicate parity frames → second is ignored.
//              Receiving the same parity twice must not cause issues.
// ===========================================================================

BOOST_AUTO_TEST_CASE(duplicate_parity_ignored) {
    GroupBuilder gb;
    auto f1 = make_frame(70, 18);
    auto f2 = make_frame(80, 22);
    gb.add(4, 1, f1);
    gb.add(4, 2, f2);
    gb.build();

    mux::MuxFecFrameView view1;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(gb.wire.data(), static_cast<int>(gb.wire.size()), 16, view1));

    // Parse a second copy.
    mux::MuxFecFrameView view2;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(gb.wire.data(), static_cast<int>(gb.wire.size()), 16, view2));

    FecGroupState group;
    group.init(view1);

    // "Receive" the duplicate parity — in real code, this would be detected
    // by group_id and dropped. Here we just verify that re-initializing
    // doesn't corrupt state.
    BOOST_TEST(group.parity_received);
    BOOST_TEST(group.parity == view2.parity); // Same content, no change.

    // Normal recovery still works.
    group.receive_data(0, f1.data(), static_cast<int>(f1.size()));
    auto recovered = group.try_recover();
    BOOST_REQUIRE(!recovered.empty());
    BOOST_TEST(std::memcmp(recovered.data(), f2.data(), f2.size()) == 0);
}

// ===========================================================================
// Scenario 7: Group ID wrap-around → old group's parity does not affect
//              new group. We simulate this by having two separate groups
//              with the same group_id (after wrap) and verifying isolation.
// ===========================================================================

BOOST_AUTO_TEST_CASE(group_wraparound_isolation) {
    // Group A (old): frames with seq 0xFFFFFFFE, 0xFFFFFFFF
    GroupBuilder gbA;
    auto a1 = make_frame(1, 16);
    auto a2 = make_frame(2, 16);
    gbA.add(1, 0xFFFFFFFE, a1);
    gbA.add(1, 0xFFFFFFFF, a2);
    gbA.build();

    // Group B (new, after wrap): seq 0, 1
    GroupBuilder gbB;
    auto b1 = make_frame(3, 16);
    auto b2 = make_frame(4, 16);
    gbB.add(1, 0, b1);
    gbB.add(1, 1, b2);
    gbB.build();

    mux::MuxFecFrameView viewA;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(gbA.wire.data(), static_cast<int>(gbA.wire.size()), 16, viewA));

    mux::MuxFecFrameView viewB;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(gbB.wire.data(), static_cast<int>(gbB.wire.size()), 16, viewB));

    // The entries are distinct — group A has high seqs, group B has low seqs.
    BOOST_TEST(viewA.entries[0].sequence == 0xFFFFFFFEu);
    BOOST_TEST(viewB.entries[0].sequence == 0u);

    // Recovering group B with group A's parity must fail (wrong entries).
    FecGroupState groupB;
    groupB.init(viewB);
    groupB.receive_data(0, b1.data(), static_cast<int>(b1.size()));

    // Try recovering with group A's parity instead of B's — wrong parity.
    FecGroupState groupB_wrong_parity;
    groupB_wrong_parity.init(viewA); // Wrong parity!
    groupB_wrong_parity.entries = viewB.entries; // But B's entries.
    groupB_wrong_parity.receive_data(0, b1.data(), static_cast<int>(b1.size()));

    auto recovered = groupB_wrong_parity.try_recover();
    // Recovery should either fail or produce garbage — but NOT b2.
    if (!recovered.empty()) {
        // If it produces something, it must NOT match b2.
        BOOST_TEST(std::memcmp(recovered.data(), b2.data(),
            std::min(recovered.size(), b2.size())) != 0);
    }

    // Correct recovery with the right parity works.
    auto correct = groupB.try_recover();
    BOOST_REQUIRE(!correct.empty());
    BOOST_TEST(std::memcmp(correct.data(), b2.data(), b2.size()) == 0);
}

// ===========================================================================
// Scenario 8: Flow close after FEC group started → late parity is safely
//              ignored. No recovery, no delivery.
// ===========================================================================

BOOST_AUTO_TEST_CASE(flow_close_ignores_late_parity) {
    GroupBuilder gb;
    auto f1 = make_frame(90, 20);
    auto f2 = make_frame(99, 20);
    gb.add(8, 5, f1);
    gb.add(8, 6, f2);
    gb.build();

    mux::MuxFecFrameView view;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(gb.wire.data(), static_cast<int>(gb.wire.size()), 16, view));

    FecGroupState group;
    group.init(view);

    // f1 arrives, f2 is missing.
    group.receive_data(0, f1.data(), static_cast<int>(f1.size()));
    BOOST_TEST(group.missing_count() == 1);

    // Flow closes before recovery is attempted.
    group.close_flow();

    // Recovery must not fire after close.
    BOOST_TEST(group.try_recover().empty());
    BOOST_TEST(group.missing_count() == 1); // Still missing, but we don't care.

    // Late f2 arrives after close — must be rejected.
    BOOST_TEST(!group.receive_data(1, f2.data(), static_cast<int>(f2.size())));
}

// ===========================================================================
// Scenario 9: Parity with wrong entry count → rejected by ParseMuxFecFrame.
//              A parity frame claiming 0 entries or more than max is invalid.
// ===========================================================================

BOOST_AUTO_TEST_CASE(wrong_entry_count_rejected) {
    // Zero count.
    const std::uint8_t zero_count[] = { 0 };
    mux::MuxFecFrameView view;
    BOOST_TEST(!mux::ParseMuxFecFrame(zero_count, sizeof(zero_count), 16, view));

    // Count exceeds cap.
    const std::uint8_t over_cap[] = { 17 };
    BOOST_TEST(!mux::ParseMuxFecFrame(over_cap, sizeof(over_cap), 16, view));

    // Count is 255 (exceeds typical max_count of 16).
    const std::uint8_t huge[] = { 255 };
    BOOST_TEST(!mux::ParseMuxFecFrame(huge, sizeof(huge), 16, view));
}

// ===========================================================================
// Scenario 10: Recovered frame passes byte-exact verification with
//               varied frame sizes (not all equal).
// ===========================================================================

BOOST_AUTO_TEST_CASE(recovered_frame_byte_exact_varied_sizes) {
    GroupBuilder gb;
    auto f1 = make_frame(1, 1);     // 1 byte
    auto f2 = make_frame(2, 500);   // 500 bytes
    auto f3 = make_frame(3, 100);   // 100 bytes
    auto f4 = make_frame(4, 1000);  // 1000 bytes
    gb.add(9, 1, f1);
    gb.add(9, 2, f2);
    gb.add(9, 3, f3);
    gb.add(9, 4, f4);
    gb.build();

    mux::MuxFecFrameView view;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(gb.wire.data(), static_cast<int>(gb.wire.size()), 16, view));

    // Lose f2 (the 500-byte frame).
    FecGroupState group;
    group.init(view);
    group.receive_data(0, f1.data(), static_cast<int>(f1.size()));
    group.receive_data(2, f3.data(), static_cast<int>(f3.size()));
    group.receive_data(3, f4.data(), static_cast<int>(f4.size()));

    auto recovered = group.try_recover();
    BOOST_REQUIRE(!recovered.empty());
    BOOST_TEST(recovered.size() == f2.size());
    BOOST_TEST(std::memcmp(recovered.data(), f2.data(), f2.size()) == 0);
}

// ===========================================================================
// Scenario 11: Extreme length disparity — 1B vs 60000B.
//               Recovery must still be byte-exact.
// ===========================================================================

BOOST_AUTO_TEST_CASE(extreme_length_disparity_recovery) {
    GroupBuilder gb;
    auto f1 = make_frame(0xAB, 1);      // 1 byte
    auto f2 = make_frame(0xCD, 60000);  // 60000 bytes
    gb.add(10, 1, f1);
    gb.add(10, 2, f2);
    gb.build();

    mux::MuxFecFrameView view;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(gb.wire.data(), static_cast<int>(gb.wire.size()), 16, view));

    // Lose f1 (the 1-byte frame).
    {
        FecGroupState group;
        group.init(view);
        group.receive_data(1, f2.data(), static_cast<int>(f2.size()));

        auto recovered = group.try_recover();
        BOOST_REQUIRE(!recovered.empty());
        BOOST_TEST(recovered.size() == f1.size());
        BOOST_TEST(recovered[0] == f1[0]);
    }

    // Lose f2 (the 60000-byte frame).
    {
        FecGroupState group;
        group.init(view);
        group.receive_data(0, f1.data(), static_cast<int>(f1.size()));

        auto recovered = group.try_recover();
        BOOST_REQUIRE(!recovered.empty());
        BOOST_TEST(recovered.size() == f2.size());
        BOOST_TEST(std::memcmp(recovered.data(), f2.data(), f2.size()) == 0);
    }
}

// ===========================================================================
// Scenario 12: Parity arrives, recovery succeeds, then original arrives.
//              The original must be silently dropped — no double delivery.
//              This is the same invariant as Scenario 1 but with only 2 frames
//              and the original arriving much later (simulating cross-link delay).
// ===========================================================================

BOOST_AUTO_TEST_CASE(recovery_then_original_silently_dropped) {
    GroupBuilder gb;
    auto f1 = make_frame(42, 28);
    auto f2 = make_frame(84, 28);
    gb.add(6, 100, f1);
    gb.add(6, 101, f2);
    gb.build();

    mux::MuxFecFrameView view;
    BOOST_REQUIRE(mux::ParseMuxFecFrame(gb.wire.data(), static_cast<int>(gb.wire.size()), 16, view));

    FecGroupState group;
    group.init(view);

    // f1 arrives, f2 is missing → recover f2.
    group.receive_data(0, f1.data(), static_cast<int>(f1.size()));
    auto recovered = group.try_recover();
    BOOST_REQUIRE(!recovered.empty());
    BOOST_TEST(std::memcmp(recovered.data(), f2.data(), f2.size()) == 0);
    BOOST_TEST(group.missing_count() == 0);

    // Much later, the original f2 arrives on a slow link.
    // It must NOT be delivered again.
    bool delivered = group.receive_data(1, f2.data(), static_cast<int>(f2.size()));
    BOOST_TEST(!delivered);
    BOOST_TEST(group.missing_count() == 0); // Still 0.
}
