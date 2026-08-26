import XCTest
import X509
@testable import CheburcertCore

final class ServiceTests: XCTestCase {
    func testApplyBuildsInstallsBothStoresAndPersists() async throws {
        let pki = try TestPKI()
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let priv = MockPrivilegedRunner()
        let ffRunner = MockCommandRunner()

        let service = CheburcertService(
            fetch: { FetchedCerts(root: pki.root, intermediates: [pki.intermediate],
                                  rootFingerprint: try CertFetcher.sha256Fingerprint(pki.root)) },
            keychain: KeychainInstaller(privileged: priv, workDir: tmp),
            firefox: FirefoxInstaller(certutilPath: "/opt/certutil", runner: ffRunner,
                                      profiles: { [URL(fileURLWithPath: "/p/one")] },
                                      isFirefoxRunning: { false }, workDir: tmp),
            domainStore: DomainStore(file: tmp.appendingPathComponent("d.json")),
            keyStore: KeyStore(keyFile: tmp.appendingPathComponent("k.pem"),
                               certFile: tmp.appendingPathComponent("r.crt")))

        try await service.apply(domains: ["sberbank.ru"])

        XCTAssertEqual(priv.batches.count, 1)
        XCTAssertTrue(ffRunner.calls.contains { $0.arguments.contains("-A") })
        XCTAssertEqual(try DomainStore(file: tmp.appendingPathComponent("d.json")).load(), ["sberbank.ru"])
    }
}
