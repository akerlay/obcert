import XCTest
@testable import CheburcertCore

final class SmokeTests: XCTestCase {
    func testErrorEquatable() {
        XCTAssertEqual(CheburcertError.firefoxRunning, CheburcertError.firefoxRunning)
    }
}
