import XCTest
@testable import OpenPPP2Logic

@MainActor
final class RuntimeStoreTests: XCTestCase {
    func testInitialStoreExposesBundledVMUXCapabilities() {
        XCTAssertEqual(RuntimeStore().state.capabilities, RuntimeSnapshot.bundledCapabilities)
    }

    private func snapshot(
        generation: UInt64,
        monotonicMs: UInt64,
        phase: RuntimePhase
    ) -> RuntimeSnapshot {
        RuntimeSnapshot(
            generation: generation,
            monotonicMs: monotonicMs,
            phase: phase
        )
    }

    func testOlderGenerationCannotOverwriteCurrentState() {
        let store = RuntimeStore(initial: snapshot(
            generation: 8,
            monotonicMs: 100,
            phase: .connected
        ))

        XCTAssertFalse(store.apply(snapshot(
            generation: 7,
            monotonicMs: 200,
            phase: .idle
        )))
        XCTAssertEqual(store.state.generation, 8)
        XCTAssertEqual(store.state.phase, .connected)
    }

    func testOlderEventWithinGenerationIsIgnored() {
        let store = RuntimeStore(initial: snapshot(
            generation: 8,
            monotonicMs: 200,
            phase: .stopping
        ))

        XCTAssertFalse(store.apply(snapshot(
            generation: 8,
            monotonicMs: 150,
            phase: .connected
        )))
        XCTAssertEqual(store.state.phase, .stopping)
    }

    func testDuplicateTimestampWithinGenerationIsIgnored() {
        let store = RuntimeStore(initial: snapshot(
            generation: 8,
            monotonicMs: 200,
            phase: .stopping
        ))

        XCTAssertFalse(store.apply(snapshot(
            generation: 8,
            monotonicMs: 200,
            phase: .connected
        )))
        XCTAssertEqual(store.state.phase, .stopping)
    }

    func testNewGenerationReplacesPriorState() {
        let store = RuntimeStore(initial: snapshot(
            generation: 8,
            monotonicMs: 200,
            phase: .failed
        ))

        XCTAssertTrue(store.apply(snapshot(
            generation: 9,
            monotonicMs: 1,
            phase: .starting
        )))
        XCTAssertEqual(store.state.generation, 9)
        XCTAssertEqual(store.state.phase, .starting)
    }

    func testInvalidOrUnavailableSnapshotIsPresentedAsUnknown() {
        let store = RuntimeStore(initial: RuntimeSnapshot(
            generation: 8,
            monotonicMs: 200,
            phase: .connected,
            p2pState: .direct
        ))

        store.markUnknown()
        XCTAssertEqual(store.state.generation, 8)
        XCTAssertEqual(store.state.monotonicMs, 200)
        XCTAssertEqual(store.state.phase, .unknown)
        XCTAssertEqual(store.state.p2pState, .unavailable)
        XCTAssertEqual(store.state.effectivePath, "relay")
        XCTAssertTrue(store.apply(snapshot(
            generation: 8,
            monotonicMs: 201,
            phase: .reconnecting
        )))
        XCTAssertEqual(store.state.phase, .reconnecting)
    }

    func testOrderedUnknownRejectsStalePayloadAndAdvancesGenerationWatermark() {
        let store = RuntimeStore(initial: snapshot(
            generation: 8,
            monotonicMs: 200,
            phase: .connected
        ))

        XCTAssertFalse(store.applyUnknown(generation: 7, monotonicMs: 300))
        XCTAssertEqual(store.state.phase, .connected)
        XCTAssertTrue(store.applyUnknown(generation: 9, monotonicMs: 1))
        XCTAssertEqual(store.state.generation, 9)
        XCTAssertEqual(store.state.phase, .unknown)
        XCTAssertEqual(store.state.p2pState, .unavailable)
        XCTAssertEqual(store.state.effectivePath, "relay")
        XCTAssertFalse(store.apply(snapshot(
            generation: 8,
            monotonicMs: 400,
            phase: .connected
        )))
    }
}
