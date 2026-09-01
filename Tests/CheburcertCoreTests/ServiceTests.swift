import XCTest
import X509
@testable import CheburcertCore

final class ServiceTests: XCTestCase {
    func testApplyBuildsInstallsBothStoresAndPersists() async throws {
        let pki = try TestPKI()
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let kcRunner = MockCommandRunner()
        let ffRunner = MockCommandRunner()

        let service = CheburcertService(
            fetch: { FetchedCerts(root: pki.root, intermediates: [pki.intermediate],
                                  rootFingerprint: try CertFetcher.sha256Fingerprint(pki.root)) },
            keychain: KeychainInstaller(runner: kcRunner, workDir: tmp),
            firefox: FirefoxInstaller(certutilPath: "/opt/certutil", runner: ffRunner,
                                      profiles: { [URL(fileURLWithPath: "/p/one")] },
                                      isFirefoxRunning: { false }, workDir: tmp),
            domainStore: DomainStore(file: tmp.appendingPathComponent("d.json")),
            keyStore: KeyStore(keyFile: tmp.appendingPathComponent("k.pem"),
                               certFile: tmp.appendingPathComponent("r.crt")))

        try await service.apply(domains: ["sberbank.ru"])

        XCTAssertTrue(kcRunner.calls.contains { $0.arguments.first == "add-trusted-cert" })
        XCTAssertTrue(ffRunner.calls.contains { $0.arguments.contains("-A") })
        XCTAssertEqual(try DomainStore(file: tmp.appendingPathComponent("d.json")).load(), ["sberbank.ru"])
    }

    func testApplyLeavesNoPrivateKeyOnDisk() async throws {
        let pki = try TestPKI()
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let keyStore = KeyStore(keyFile: tmp.appendingPathComponent("k.pem"),
                                certFile: tmp.appendingPathComponent("r.crt"))
        // A key left over by an older version must be destroyed too, not just skipped.
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        try "stale".write(to: keyStore.keyFile, atomically: true, encoding: .utf8)

        let service = CheburcertService(
            fetch: { FetchedCerts(root: pki.root, intermediates: [pki.intermediate],
                                  rootFingerprint: try CertFetcher.sha256Fingerprint(pki.root)) },
            keychain: KeychainInstaller(runner: MockCommandRunner(), workDir: tmp),
            firefox: FirefoxInstaller(certutilPath: "/opt/certutil", runner: MockCommandRunner(),
                                      profiles: { [] }, isFirefoxRunning: { false }, workDir: tmp),
            domainStore: DomainStore(file: tmp.appendingPathComponent("d.json")),
            keyStore: keyStore)

        try await service.apply(domains: ["sberbank.ru"])

        XCTAssertFalse(FileManager.default.fileExists(atPath: keyStore.keyFile.path),
                       "приватный ключ CA не должен переживать установку")
        XCTAssertTrue(FileManager.default.fileExists(atPath: keyStore.certFile.path),
                      "сертификат корня нужен для определения статуса")
    }

    func testExportDoesNotPersistItsKeyEither() async throws {
        let pki = try TestPKI()
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let keyStore = KeyStore(keyFile: tmp.appendingPathComponent("k.pem"),
                                certFile: tmp.appendingPathComponent("r.crt"))
        let service = CheburcertService(
            fetch: { FetchedCerts(root: pki.root, intermediates: [pki.intermediate],
                                  rootFingerprint: try CertFetcher.sha256Fingerprint(pki.root)) },
            keychain: KeychainInstaller(runner: MockCommandRunner(), workDir: tmp),
            firefox: FirefoxInstaller(certutilPath: "/opt/certutil", runner: MockCommandRunner(),
                                      profiles: { [] }, isFirefoxRunning: { false }, workDir: tmp),
            domainStore: DomainStore(file: tmp.appendingPathComponent("d.json")),
            keyStore: keyStore)

        _ = try await service.buildBundleForExport(domains: ["sberbank.ru"])

        XCTAssertFalse(FileManager.default.fileExists(atPath: keyStore.keyFile.path))
    }

}
