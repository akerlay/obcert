import XCTest
import X509
@testable import CheburcertCore

final class CertFetcherTests: XCTestCase {
    func testParsesConcatenatedPEMBundle() throws {
        let pki = try TestPKI()
        let pem = try pki.root.serializeAsPEM().pemString + "\n"
                + (try pki.intermediate.serializeAsPEM().pemString) + "\n"
        let certs = try CertFetcher.parsePEMBundle(pem)
        XCTAssertEqual(certs.count, 2)
        XCTAssertEqual(certs[0].subject, pki.root.subject)
    }

    func testFingerprintIsStableUppercaseHexColonSeparated() throws {
        let pki = try TestPKI()
        let fp = try CertFetcher.sha256Fingerprint(pki.root)
        XCTAssertEqual(fp, fp.uppercased())
        XCTAssertEqual(fp.filter { $0 == ":" }.count, 31) // 32 bytes -> 31 separators
    }

    func testParseRejectsGarbage() {
        XCTAssertThrowsError(try CertFetcher.parsePEMBundle("not a pem"))
    }
}
