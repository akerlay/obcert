import XCTest
import X509
import SwiftASN1
@testable import CheburcertCore

final class CryptoEngineTests: XCTestCase {
    func testCrossCertPreservesRootIdentity() throws {
        let pki = try TestPKI()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"],
            mintsifryRoot: pki.root,
            mintsifryIntermediates: [pki.intermediate]
        )
        XCTAssertEqual(bundle.crossCert.publicKey, pki.root.publicKey)
        XCTAssertEqual(bundle.crossCert.subject, pki.root.subject)
        XCTAssertEqual(bundle.crossCert.serialNumber, pki.root.serialNumber)
        XCTAssertEqual(bundle.crossCert.issuer, bundle.localRoot.subject)
    }

    func testChainValidatesForPermittedDomain() async throws {
        let pki = try TestPKI()
        let leaf = try pki.leaf(host: "online.sberbank.ru")
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])

        var roots = CertificateStore()
        roots.append(bundle.localRoot)
        var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: pki.notBefore.addingTimeInterval(1)) }
        let result = await verifier.validate(
            leafCertificate: leaf,
            intermediates: CertificateStore([pki.intermediate, bundle.crossCert]))
        guard case .validCertificate = result else {
            return XCTFail("expected valid chain, got \(result)")
        }
    }

    func testChainRejectedForNonPermittedDomain() async throws {
        let pki = try TestPKI()
        let leaf = try pki.leaf(host: "evil.com")
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])

        var roots = CertificateStore()
        roots.append(bundle.localRoot)
        var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: pki.notBefore.addingTimeInterval(1)) }
        let result = await verifier.validate(
            leafCertificate: leaf,
            intermediates: CertificateStore([pki.intermediate, bundle.crossCert]))
        guard case .couldNotValidate = result else {
            return XCTFail("expected name-constraint rejection, got \(result)")
        }
    }

    func testChainRejectedForIPAddressLeaf() async throws {
        let pki = try TestPKI()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])
        let ipLeaf = try pki.leaf(ipv4: "192.0.2.10")

        let ok = await ChainSelfCheck.validates(
            leaf: ipLeaf, intermediates: [pki.intermediate, bundle.crossCert],
            localRoot: bundle.localRoot, at: pki.notBefore.addingTimeInterval(1))

        XCTAssertFalse(ok, "лист с iPAddress SAN должен отсекаться excludedIPRanges")
    }

    func testLocalRootHasCriticalNameConstraints() throws {
        let pki = try TestPKI()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])
        let nc = try XCTUnwrap(try bundle.localRoot.extensions.nameConstraints)
        XCTAssertTrue(Array(nc.permittedDNSDomains).contains(".ru"))
    }
}
