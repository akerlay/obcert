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

    func testKeyStoreRoundTripsAndSetsMode0600() throws {
        let dir = tempDir()
        let store = KeyStore(keyFile: dir.appendingPathComponent("k.pem"),
                             certFile: dir.appendingPathComponent("r.crt"))
        let pki = try TestPKI()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root,
            mintsifryIntermediates: [pki.intermediate])
        try store.save(key: bundle.localRootKey, localRoot: bundle.localRoot)

        let attrs = try FileManager.default.attributesOfItem(atPath: store.keyFile.path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertNotNil(try store.loadKey())
    }
}
