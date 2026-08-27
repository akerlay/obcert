import XCTest
import X509
@testable import CheburcertCore

final class ServiceRemoveTests: XCTestCase {
    func testRemoveAllDeletesPersistedKeyAndCertButKeepsDomains() async throws {
        let pki = try TestPKI()
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let kcRunner = MockCommandRunner()
        let ffRunner = MockCommandRunner()

        let keyStore = KeyStore(keyFile: tmp.appendingPathComponent("k.pem"),
                                certFile: tmp.appendingPathComponent("r.crt"))
        let domainStore = DomainStore(file: tmp.appendingPathComponent("d.json"))

        let service = CheburcertService(
            fetch: { FetchedCerts(root: pki.root, intermediates: [pki.intermediate],
                                  rootFingerprint: try CertFetcher.sha256Fingerprint(pki.root)) },
            keychain: KeychainInstaller(runner: kcRunner, workDir: tmp),
            firefox: FirefoxInstaller(certutilPath: "/opt/certutil", runner: ffRunner,
                                      profiles: { [URL(fileURLWithPath: "/p/one")] },
                                      isFirefoxRunning: { false }, workDir: tmp),
            domainStore: domainStore,
            keyStore: keyStore)

        try await service.apply(domains: ["sberbank.ru"])
        XCTAssertTrue(FileManager.default.fileExists(atPath: keyStore.certFile.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: keyStore.keyFile.path))

        try service.removeAll()

        XCTAssertFalse(FileManager.default.fileExists(atPath: keyStore.certFile.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: keyStore.keyFile.path))
        XCTAssertEqual(try domainStore.load(), ["sberbank.ru"])
    }
}
