import XCTest
import X509
@testable import CheburcertCore

final class MintsifrySourceTests: XCTestCase {
    /// The pinned fingerprint must equal the library's own fingerprint of the real
    /// Минцифры root. This guards two things at once: (1) the pinned constant is correct,
    /// and (2) swift-asn1's DER round-trip is byte-identical to the original, so pinning
    /// against a re-serialized cert won't spuriously reject the genuine download.
    func testPinnedFingerprintMatchesRealRoot() throws {
        let url = try XCTUnwrap(Bundle.module.url(
            forResource: "russian_trusted_root", withExtension: "pem", subdirectory: "Fixtures"))
        let pem = try String(contentsOf: url, encoding: .utf8)
        let certs = try CertFetcher.parsePEMBundle(pem)
        let root = try XCTUnwrap(certs.first)
        let fp = try CertFetcher.sha256Fingerprint(root)
        XCTAssertEqual(fp, MintsifrySource.expectedRootFingerprint)
    }

    func testDistributionURLsAreLendingPaths() {
        XCTAssertEqual(MintsifrySource.urls.count, 3)
        for url in MintsifrySource.urls {
            XCTAssertTrue(url.path.hasPrefix("/content/lending/"), "unexpected path: \(url.path)")
        }
    }
}
