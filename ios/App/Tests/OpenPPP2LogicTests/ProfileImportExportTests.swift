import XCTest
@testable import OpenPPP2Logic

final class ProfileImportExportTests: XCTestCase {
    private func sampleProfile(id: String, name: String) -> ConfigProfile {
        var options = LaunchOptions()
        options.mtu = 1380
        options.allowLan = true
        return ConfigProfile(
            id: id,
            name: name,
            subtitle: "test",
            flag: "JP",
            json: "{\"client\":{\"server\":\"ppp://127.0.0.1:20000/\"}}",
            favorite: false,
            options: options,
            history: []
        )
    }

    func testRoundTripEncodeDecode() throws {
        let bundle = ProfileExportBundle(
            activeProfileId: "p1",
            profiles: [
                sampleProfile(id: "p1", name: "Primary"),
                sampleProfile(id: "p2", name: "Secondary"),
            ]
        )

        let data = try ProfileImportExportCodec.encode(bundle)
        let decoded = try ProfileImportExportCodec.decode(data)

        XCTAssertEqual(decoded, bundle)
    }

    func testRejectsUnsupportedType() {
        let json = """
        {"type":"other","version":1,"exportedAtMs":1,"profiles":[]}
        """
        let data = Data(json.utf8)
        XCTAssertThrowsError(try ProfileImportExportCodec.decode(data)) { error in
            XCTAssertEqual(error as? ProfileImportExportError, .unsupportedType("other"))
        }
    }

    func testRejectsUnsupportedVersion() {
        let json = """
        {"type":"openppp2-profile-export","version":99,"exportedAtMs":1,"profiles":[{"id":"p1","name":"A","subtitle":"","flag":"","json":"{}","favorite":false,"options":{},"history":[]}]}
        """
        let data = Data(json.utf8)
        XCTAssertThrowsError(try ProfileImportExportCodec.decode(data)) { error in
            XCTAssertEqual(error as? ProfileImportExportError, .unsupportedVersion(99))
        }
    }

    func testMergeUpdatesExistingAndAppendsNew() {
        let existing = [
            sampleProfile(id: "p1", name: "Old"),
            sampleProfile(id: "p2", name: "Keep"),
        ]
        let bundle = ProfileExportBundle(
            profiles: [
                sampleProfile(id: "p1", name: "New"),
                sampleProfile(id: "p3", name: "Added"),
            ]
        )

        let applied = ProfileImportExportLogic.applyImport(
            bundle: bundle,
            mode: .merge,
            existingProfiles: existing,
            activeProfileId: "p2"
        )

        XCTAssertEqual(applied.activeProfileId, "p2")
        XCTAssertEqual(applied.profiles.count, 3)
        XCTAssertEqual(applied.profiles.first(where: { $0.id == "p1" })?.name, "New")
        XCTAssertEqual(applied.result.updatedCount, 1)
        XCTAssertEqual(applied.result.addedCount, 1)
    }

    func testReplaceSetsActiveProfileFromBundle() {
        let existing = [sampleProfile(id: "old", name: "Old")]
        let bundle = ProfileExportBundle(
            activeProfileId: "p2",
            profiles: [
                sampleProfile(id: "p1", name: "One"),
                sampleProfile(id: "p2", name: "Two"),
            ]
        )

        let applied = ProfileImportExportLogic.applyImport(
            bundle: bundle,
            mode: .replace,
            existingProfiles: existing,
            activeProfileId: "old"
        )

        XCTAssertEqual(applied.activeProfileId, "p2")
        XCTAssertEqual(applied.profiles.map(\.id), ["p1", "p2"])
        XCTAssertEqual(applied.result.addedCount, 2)
    }

    func testFilenameHelpers() {
        XCTAssertTrue(ProfileImportExportCodec.allProfilesFilename().hasPrefix("openppp2-profiles-"))
        XCTAssertEqual(ProfileImportExportCodec.singleProfileFilename(name: "JP/Test"), "openppp2-profile-JP-Test.json")
    }
}
