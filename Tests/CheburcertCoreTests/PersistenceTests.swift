import XCTest
import X509
import Crypto
@testable import CheburcertCore

final class PersistenceTests: XCTestCase {
    func tempDir() -> URL {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }

    func testDomainStoreRoundTrips() throws {
        let file = tempDir().appendingPathComponent("domains.json")
        let store = DomainStore(file: file)
        try store.save(["sberbank.ru", ".ru"])
        XCTAssertEqual(try store.load(), ["sberbank.ru", ".ru"])
    }

    func testDomainStoreLoadsEmptyWhenMissing() throws {
        let store = DomainStore(file: tempDir().appendingPathComponent("nope.json"))
        XCTAssertEqual(try store.load(), [])
    }

    func testKeyStoreSavesTheCertificateAndNeverTheKey() throws {
        let dir = tempDir()
        let store = KeyStore(keyFile: dir.appendingPathComponent("k.pem"),
                             certFile: dir.appendingPathComponent("r.crt"))
        let pki = try TestPKI()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root,
            mintsifryIntermediates: [pki.intermediate])
        try store.save(localRoot: bundle.localRoot)

        XCTAssertTrue(FileManager.default.fileExists(atPath: store.certFile.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.keyFile.path),
                       "у KeyStore не должно быть пути, по которому ключ попадает на диск")
    }

    func testDestroyKeyRemovesOneLeftByAnOlderVersion() throws {
        let dir = tempDir()
        let store = KeyStore(keyFile: dir.appendingPathComponent("k.pem"),
                             certFile: dir.appendingPathComponent("r.crt"))
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try "-----BEGIN PRIVATE KEY-----".write(to: store.keyFile, atomically: true, encoding: .utf8)

        XCTAssertTrue(store.destroyKey(), "должен сообщить, что ключ был найден")
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.keyFile.path))
        XCTAssertFalse(store.destroyKey(), "повторный вызов идемпотентен")
    }
}
