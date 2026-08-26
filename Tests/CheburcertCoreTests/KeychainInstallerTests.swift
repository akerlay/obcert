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
}
