import XCTest
import X509
@testable import CheburcertCore

final class VerifierTests: XCTestCase {
    func testSelfCheckAcceptsPermittedRejectsOther() async throws {
        let pki = try TestPKI()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])
        let ok = try pki.leaf(host: "a.sberbank.ru")
        let bad = try pki.leaf(host: "a.example.com")

        let permitted = await ChainSelfCheck.validates(
            leaf: ok, intermediates: [pki.intermediate, bundle.crossCert],
            localRoot: bundle.localRoot, at: pki.notBefore.addingTimeInterval(1))
        let blocked = await ChainSelfCheck.validates(
            leaf: bad, intermediates: [pki.intermediate, bundle.crossCert],
            localRoot: bundle.localRoot, at: pki.notBefore.addingTimeInterval(1))

        XCTAssertTrue(permitted)
        XCTAssertFalse(blocked)
    }
}
