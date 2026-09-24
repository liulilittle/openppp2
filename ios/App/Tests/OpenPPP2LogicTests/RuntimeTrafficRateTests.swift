import XCTest
@testable import OpenPPP2Logic

final class RuntimeTrafficRateTests: XCTestCase {
    private func sample(
        generation: UInt64 = 1,
        monotonicMs: UInt64,
        rxBytes: UInt64 = 0,
        txBytes: UInt64 = 0,
        connectedMonotonicMs: UInt64 = 0,
        phase: RuntimePhase = .connected
    ) -> RuntimeSnapshot {
        RuntimeSnapshot(
            generation: generation,
            monotonicMs: monotonicMs,
            phase: phase,
            traffic: RuntimeTrafficSnapshot(rxBytes: rxBytes, txBytes: txBytes),
            connectedMonotonicMs: connectedMonotonicMs
        )
    }

    func testRateComesFromTheSnapshotClockNotTheSamplingInterval() {
        let previous = sample(monotonicMs: 1_000, rxBytes: 1_000, txBytes: 500)
        // Two seconds of snapshot time, whatever the UI poll interval was.
        let current = sample(monotonicMs: 3_000, rxBytes: 5_000, txBytes: 1_500)

        let rate = RuntimeTrafficRate.between(previous, current)
        XCTAssertEqual(rate.rxBytes, 5_000)
        XCTAssertEqual(rate.txBytes, 1_500)
        XCTAssertEqual(rate.rxBytesPerSecond, 2_000)
        XCTAssertEqual(rate.txBytesPerSecond, 500)
    }

    func testFirstSampleReportsTotalsWithNoRate() {
        let rate = RuntimeTrafficRate.between(
            nil,
            sample(monotonicMs: 1_000, rxBytes: 4_096, txBytes: 2_048)
        )
        XCTAssertEqual(rate.rxBytes, 4_096)
        XCTAssertEqual(rate.txBytes, 2_048)
        XCTAssertEqual(rate.rxBytesPerSecond, 0)
        XCTAssertEqual(rate.txBytesPerSecond, 0)
    }

    func testNewGenerationDoesNotReportASpikeAcrossSessions() {
        let previous = sample(generation: 1, monotonicMs: 9_000, rxBytes: 10_000_000)
        let current = sample(generation: 2, monotonicMs: 100, rxBytes: 512)

        let rate = RuntimeTrafficRate.between(previous, current)
        XCTAssertEqual(rate.rxBytes, 512)
        XCTAssertEqual(rate.rxBytesPerSecond, 0)
    }

    func testCountersThatMovedBackwardsReportNoRate() {
        let previous = sample(monotonicMs: 1_000, rxBytes: 8_000, txBytes: 8_000)
        let current = sample(monotonicMs: 2_000, rxBytes: 10, txBytes: 10)

        let rate = RuntimeTrafficRate.between(previous, current)
        XCTAssertEqual(rate.rxBytesPerSecond, 0)
        XCTAssertEqual(rate.txBytesPerSecond, 0)
    }

    func testClockThatDidNotAdvanceReportsNoRate() {
        let previous = sample(monotonicMs: 2_000, rxBytes: 100)
        let current = sample(monotonicMs: 2_000, rxBytes: 900)

        XCTAssertEqual(RuntimeTrafficRate.between(previous, current).rxBytesPerSecond, 0)
    }

    func testPhaseSnapshotBetweenTrafficSamplesDoesNotSpikeTheRate() {
        let trafficA = sample(monotonicMs: 1_000, rxBytes: 1_000, txBytes: 500)
        let phaseOnly = sample(
            monotonicMs: 1_001,
            rxBytes: 1_000,
            txBytes: 500,
            phase: .applyingPolicy
        )
        let trafficB = sample(monotonicMs: 3_000, rxBytes: 5_000, txBytes: 1_500)

        XCTAssertFalse(RuntimeTrafficRate.advancesTrafficBaseline(trafficA, phaseOnly))
        XCTAssertTrue(RuntimeTrafficRate.advancesTrafficBaseline(trafficA, trafficB))

        let rate = RuntimeTrafficRate.between(trafficA, trafficB)
        XCTAssertEqual(rate.rxBytesPerSecond, 2_000)
        XCTAssertEqual(rate.txBytesPerSecond, 500)

        let spiked = RuntimeTrafficRate.between(
            phaseOnly,
            sample(monotonicMs: 1_002, rxBytes: 3_000, txBytes: 500)
        )
        XCTAssertGreaterThan(spiked.rxBytesPerSecond, 100_000)
    }

    func testConnectedElapsedIsMeasuredAgainstTheSnapshotClock() {
        let snapshot = sample(monotonicMs: 42_000, connectedMonotonicMs: 30_000)
        XCTAssertEqual(connectedElapsedMs(snapshot), 12_000)
    }

    func testConnectedElapsedIsZeroWhileNotConnected() {
        XCTAssertEqual(
            connectedElapsedMs(sample(monotonicMs: 42_000, phase: .connecting)),
            0
        )
    }

    func testConnectedElapsedIsZeroWhenTheClockIsBehindTheStamp() {
        let snapshot = sample(monotonicMs: 1_000, connectedMonotonicMs: 30_000)
        XCTAssertEqual(connectedElapsedMs(snapshot), 0)
    }
}
