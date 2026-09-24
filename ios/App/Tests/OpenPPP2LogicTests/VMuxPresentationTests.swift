import XCTest
@testable import OpenPPP2Logic

final class VMuxPresentationTests: XCTestCase {
    func testSelectorUsesCapabilitiesAndHidesStripeOutsideExperimentalMode() {
        let snapshot = RuntimeSnapshot(
            generation: 1,
            monotonicMs: 1,
            phase: .connected,
            capabilities: ["mux.compat", "mux.flow", "mux.balance", "mux.stripe"]
        )

        XCTAssertEqual(snapshot.availableMuxModes(), ["compat", "flow", "balance"])
        XCTAssertEqual(snapshot.availableMuxModes(experimental: true), ["compat", "flow", "balance", "stripe"])
    }

    func testFallbackPresentationKeepsRequestedModeDiagnostic() {
        let snapshot = RuntimeSnapshot(
            generation: 1,
            monotonicMs: 1,
            phase: .connected,
            requestedMuxMode: "balance",
            effectiveMuxMode: "compat",
            muxFallbackReason: "peer_missing_flow_v2"
        )

        XCTAssertEqual(snapshot.effectiveMuxDisplayName, "Compatibility mode")
        XCTAssertTrue(snapshot.muxDiagnosticLines.contains("Requested VMUX: balance"))
        XCTAssertTrue(snapshot.muxDiagnosticLines.contains("Fallback reason: peer_missing_flow_v2"))
    }
}
