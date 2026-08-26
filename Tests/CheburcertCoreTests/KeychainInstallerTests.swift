import XCTest
import X509
@testable import CheburcertCore

final class KeychainInstallerTests: XCTestCase {
    func testInstallWritesTrustedRootThenAddsCrossAndIntermediates() throws {
        let pki = try TestPKI()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])
        let priv = MockPrivilegedRunner()
        let installer = KeychainInstaller(privileged: priv, workDir: FileManager.default.temporaryDirectory)
        try installer.install(bundle)

        XCTAssertEqual(priv.batches.count, 1)
        let script = priv.batches[0]
        XCTAssertTrue(script.contains("add-trusted-cert"))
        XCTAssertTrue(script.contains("-r trustRoot"))
        XCTAssertTrue(script.contains("add-certificates") || script.contains("add-trusted-cert"))
    }

    func testRemoveDeletesByCommonName() throws {
        let priv = MockPrivilegedRunner()
        let installer = KeychainInstaller(privileged: priv, workDir: FileManager.default.temporaryDirectory)
        try installer.removeAll()
        XCTAssertEqual(priv.batches.count, 1)
        XCTAssertTrue(priv.batches[0].contains("delete-certificate"))
        XCTAssertTrue(priv.batches[0].contains("Cheburcert Local Constrained Root"))
    }

    func testInstallBatchFailsFastWithSetE() throws {
        let pki = try TestPKI()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])
        let priv = MockPrivilegedRunner()
        let installer = KeychainInstaller(privileged: priv, workDir: FileManager.default.temporaryDirectory)
        try installer.install(bundle)

        let script = priv.batches[0]
        XCTAssertTrue(script.contains("set -e"))
        XCTAssertTrue(script.contains("add-trusted-cert"))
        // The add commands must NOT be suffixed with `|| true` (they must fail-fast).
        XCTAssertNil(script.range(of: "add-trusted-cert[^;]*\\|\\| true", options: .regularExpression))
        XCTAssertNil(script.range(of: "add-certificates[^;]*\\|\\| true", options: .regularExpression))
    }

    func testRemoveAllAfterInstallDeletesByHash() throws {
        let pki = try TestPKI()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let priv = MockPrivilegedRunner()
        let installer = KeychainInstaller(privileged: priv, workDir: tmp)
        try installer.install(bundle)
        try installer.removeAll()

        let removeBatch = priv.batches.last!
        XCTAssertTrue(removeBatch.contains("delete-certificate -Z"))
        XCTAssertTrue(removeBatch.contains("-c '\(KeychainInstaller.localRootCN)'"))
    }
}
