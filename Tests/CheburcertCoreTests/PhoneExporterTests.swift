import XCTest
import X509
import SwiftASN1
@testable import CheburcertCore

final class PhoneExporterTests: XCTestCase {
    func makeBundle() throws -> TrustBundle {
        let pki = try TestPKI()
        return try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])
    }

    func testExportWritesMobileconfigAndPEMs() throws {
        let bundle = try makeBundle()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let result = try PhoneExporter().export(bundle, to: dir)

        XCTAssertTrue(FileManager.default.fileExists(atPath: result.mobileconfig.path))
        XCTAssertEqual(result.mobileconfig.pathExtension, "mobileconfig")
        // localRoot + cross + 1 intermediate = 3 pem files
        XCTAssertEqual(result.pemFiles.count, 3)
        for f in result.pemFiles { XCTAssertTrue(FileManager.default.fileExists(atPath: f.path)) }
    }

    func testMobileconfigIsValidPlistWithRootPayload() throws {
        let bundle = try makeBundle()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let result = try PhoneExporter().export(bundle, to: dir)

        let data = try Data(contentsOf: result.mobileconfig)
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as! [String: Any]
        XCTAssertEqual(plist["PayloadType"] as? String, "Configuration")
        let payloads = try XCTUnwrap(plist["PayloadContent"] as? [[String: Any]])
        // 1 root + 1 cross + 1 intermediate
        XCTAssertEqual(payloads.count, 3)
        let types = payloads.compactMap { $0["PayloadType"] as? String }
        XCTAssertEqual(types.filter { $0 == "com.apple.security.root" }.count, 1)
        XCTAssertEqual(types.filter { $0 == "com.apple.security.pkcs1" }.count, 2)
        // root payload carries the localRoot DER
        let rootPayload = try XCTUnwrap(payloads.first { $0["PayloadType"] as? String == "com.apple.security.root" })
        var ser = DER.Serializer(); try ser.serialize(bundle.localRoot)
        XCTAssertEqual(rootPayload["PayloadContent"] as? Data, Data(ser.serializedBytes))
    }

    func testBuildBundleForExportProducesConstrainedRoot() async throws {
        let pki = try TestPKI()
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let service = CheburcertService(
            fetch: { FetchedCerts(root: pki.root, intermediates: [pki.intermediate],
                                  rootFingerprint: try CertFetcher.sha256Fingerprint(pki.root)) },
            keychain: KeychainInstaller(runner: MockCommandRunner(), workDir: tmp),
            firefox: FirefoxInstaller(certutilPath: "/opt/certutil", runner: MockCommandRunner(),
                                      profiles: { [] }, isFirefoxRunning: { false }, workDir: tmp),
            domainStore: DomainStore(file: tmp.appendingPathComponent("d.json")),
            keyStore: KeyStore(keyFile: tmp.appendingPathComponent("k.pem"),
                               certFile: tmp.appendingPathComponent("r.crt")))
        let bundle = try await service.buildBundleForExport(domains: ["sberbank.ru"])
        XCTAssertEqual(bundle.domains, ["sberbank.ru"])
        let nc = try XCTUnwrap(try bundle.localRoot.extensions.nameConstraints)
        XCTAssertTrue(Array(nc.permittedDNSDomains).contains("sberbank.ru"))
    }
}
