import XCTest
@testable import CheburcertCore

final class PresetsTests: XCTestCase {
    func testPresetsAreNormalizedAndNonEmpty() throws {
        for preset in Presets.all {
            XCTAssertFalse(preset.domains.isEmpty, "\(preset.name) is empty")
            for d in preset.domains {
                XCTAssertEqual(try DomainList.normalize(d), d, "\(d) not normalized")
            }
        }
    }

    func testGosuslugiPresetIncludesGosuslugi() {
        let g = Presets.all.first { $0.id == "gosuslugi" }
        XCTAssertNotNil(g)
        XCTAssertTrue(g!.domains.contains("gosuslugi.ru"))
    }

    func testWholeZonePresetUsesLeadingDotForms() {
        let z = Presets.all.first { $0.id == "zones" }!
        XCTAssertEqual(Set(z.domains), [".ru", ".su", ".xn--p1ai"])
    }
}
