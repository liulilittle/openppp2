import XCTest
@testable import OpenPPP2Logic

final class SubscriptionUrlPolicyTests: XCTestCase {
    func testAcceptsHttps() {
        XCTAssertTrue(
            SubscriptionUrlPolicy.isSecure(URL(string: "https://example.com/sub.json")!)
        )
    }

    func testRejectsRemoteHttp() {
        XCTAssertFalse(
            SubscriptionUrlPolicy.isSecure(URL(string: "http://example.com/sub.json")!)
        )
    }

    func testAcceptsLoopbackHttp() {
        XCTAssertTrue(SubscriptionUrlPolicy.isSecure(URL(string: "http://localhost:8080/s")!))
        XCTAssertTrue(SubscriptionUrlPolicy.isSecure(URL(string: "http://127.0.0.1/s")!))
        XCTAssertTrue(SubscriptionUrlPolicy.isSecure(URL(string: "http://[::1]/s")!))
    }

    func testMaxRedirectsIsFive() {
        XCTAssertEqual(SubscriptionUrlPolicy.maxRedirects, 5)
    }
}
