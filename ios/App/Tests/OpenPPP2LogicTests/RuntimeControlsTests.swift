import XCTest
@testable import OpenPPP2Logic

final class RuntimeControlsTests: XCTestCase {
    func testPhaseMappingIsAuthoritativeForActions() {
        XCTAssertEqual(controlsFor(.idle).action, .start)
        XCTAssertEqual(controlsFor(.connected).action, .stop)
        XCTAssertEqual(controlsFor(.reconnecting).action, .stop)
        XCTAssertEqual(controlsFor(.stopping).action, .none)
        XCTAssertEqual(controlsFor(.failed).action, .retry)
        XCTAssertEqual(controlsFor(.unknown).action, .forceStop)
    }

    func testStopTimeoutChangesPresentationWithoutEnablingAction() {
        let controls = controlsFor(.stopping, stopTakingTooLong: true)
        XCTAssertEqual(controls.action, .none)
        XCTAssertFalse(controls.buttonEnabled)
        XCTAssertEqual(controls.detailKey, "home.stopTakingTooLong")
    }
}
