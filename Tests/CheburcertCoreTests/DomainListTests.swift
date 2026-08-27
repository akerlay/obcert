import XCTest
@testable import CheburcertCore

final class DomainListTests: XCTestCase {
    func testStripsSchemeWildcardWhitespaceAndLowercases() throws {
        XCTAssertEqual(try DomainList.normalize(" HTTPS://*.Sberbank.RU/ "), "sberbank.ru")
    }

    func testLeadingDotZonePreserved() throws {
        XCTAssertEqual(try DomainList.normalize(".RU"), ".ru")
    }

    func testCyrillicConvertedToPunycode() throws {
        XCTAssertEqual(try DomainList.normalize("сбербанк.рф"), "xn--80abap1arsf.xn--p1ai")
    }

    func testLeadingDotCyrillicZone() throws {
        XCTAssertEqual(try DomainList.normalize(".рф"), ".xn--p1ai")
    }

    func testRejectsEmpty() {
        XCTAssertThrowsError(try DomainList.normalize("   "))
    }

    func testRejectsBareTLDLabelWithoutDot() throws {
        // "ru" (no leading dot, single label) is ambiguous; require an explicit form.
        XCTAssertThrowsError(try DomainList.normalize("ru"))
    }

    func testDeduplicatesPreservingOrder() throws {
        let out = try DomainList.normalizedUnique(["sberbank.ru", "SBERBANK.ru", "gosuslugi.ru"])
        XCTAssertEqual(out, ["sberbank.ru", "gosuslugi.ru"])
    }
}
