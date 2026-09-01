import XCTest
import X509
@testable import CheburcertCore

final class CertFetcherTests: XCTestCase {
    func testParsesConcatenatedPEMBundle() throws {
        let pki = try TestPKI()
        let pem = try pki.root.serializeAsPEM().pemString + "\n"
                + (try pki.intermediate.serializeAsPEM().pemString) + "\n"
        let certs = try CertFetcher.parsePEMBundle(pem)
        XCTAssertEqual(certs.count, 2)
        XCTAssertEqual(certs[0].subject, pki.root.subject)
    }

    func testFingerprintIsStableUppercaseHexColonSeparated() throws {
        let pki = try TestPKI()
        let fp = try CertFetcher.sha256Fingerprint(pki.root)
        XCTAssertEqual(fp, fp.uppercased())
        XCTAssertEqual(fp.filter { $0 == ":" }.count, 31) // 32 bytes -> 31 separators
    }

    func testParseRejectsGarbage() {
        XCTAssertThrowsError(try CertFetcher.parsePEMBundle("not a pem"))
    }

    func testFetchFailsFastWhenSourceHangs() async throws {
        // Discard port: accepts the connection and never answers, so only the deadline
        // can end the wait.
        let hanging = URL(string: "https://0.0.0.0:9/never")!
        let fetcher = CertFetcher(deadline: .milliseconds(300))
        let started = Date()
        do {
            _ = try await fetcher.fetch(from: [hanging])
            XCTFail("ожидался таймаут")
        } catch let error as CheburcertError {
            guard case .network = error else { return XCTFail("ожидалась .network, получено \(error)") }
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 10,
                          "дедлайн должен обрывать ожидание, а не полагаться на URLSession")
    }
}
