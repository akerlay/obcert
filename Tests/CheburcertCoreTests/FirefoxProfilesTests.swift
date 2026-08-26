import XCTest
@testable import CheburcertCore

final class FirefoxProfilesTests: XCTestCase {
    func testParsesRelativeAndAbsoluteProfiles() throws {
        let ini = """
        [Profile0]
        Name=default
        IsRelative=1
        Path=Profiles/abc.default

        [Profile1]
        Name=dev
        IsRelative=0
        Path=/custom/place/dev-profile
        """
        let base = URL(fileURLWithPath: "/Users/x/Library/Application Support/Firefox")
        let dirs = FirefoxProfiles.parse(iniContents: ini, firefoxDir: base).map { $0.path }
        XCTAssertEqual(dirs, [
            "/Users/x/Library/Application Support/Firefox/Profiles/abc.default",
            "/custom/place/dev-profile",
        ])
    }

    func testEmptyWhenNoProfiles() {
        let base = URL(fileURLWithPath: "/tmp/none")
        XCTAssertTrue(FirefoxProfiles.parse(iniContents: "[General]\nStartWithLastProfile=1", firefoxDir: base).isEmpty)
    }
}
