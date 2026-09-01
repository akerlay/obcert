import XCTest
import X509
import TestbedKit

final class FakeGovPKITests: XCTestCase {
    func testRootIsSelfSignedCA() throws {
        let pki = try FakeGovPKI()
        XCTAssertEqual(pki.root.issuer, pki.root.subject)
        let bc = try XCTUnwrap(try pki.root.extensions.basicConstraints)
        guard case .isCertificateAuthority = bc else {
            return XCTFail("подставной корень должен быть CA")
        }
    }

    func testSubCAIsIssuedByRoot() throws {
        let pki = try FakeGovPKI()
        XCTAssertEqual(pki.subCA.issuer, pki.root.subject)
    }

    func testDNSLeafRetainsItsPrivateKey() throws {
        let pki = try FakeGovPKI()
        let leaf = try pki.leaf(dnsName: "ok.example.test")
        XCTAssertEqual(leaf.certificate.issuer, pki.subCA.subject)
        // Без приватного ключа листа TLS-сервер стенда невозможен.
        XCTAssertEqual(leaf.privateKey.publicKey, leaf.certificate.publicKey)
    }

    func testIPLeafCarriesIPAddressSAN() throws {
        let pki = try FakeGovPKI()
        let leaf = try pki.leaf(ipv4: "192.0.2.10")
        let sans = try XCTUnwrap(try leaf.certificate.extensions.subjectAlternativeNames)
        XCTAssertTrue(sans.contains { if case .ipAddress = $0 { return true }; return false })
    }

    func testInvalidIPv4IsRejected() throws {
        let pki = try FakeGovPKI()
        XCTAssertThrowsError(try pki.leaf(ipv4: "192.168.1")) { error in
            XCTAssertEqual(error as? FakeGovPKIError, .invalidIPv4("192.168.1"))
        }
    }
}
