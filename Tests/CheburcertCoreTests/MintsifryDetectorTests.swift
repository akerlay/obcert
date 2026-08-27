import XCTest
import X509
@testable import CheburcertCore

final class MintsifryDetectorTests: XCTestCase {
    func realRootPEM() throws -> String {
        let url = try XCTUnwrap(Bundle.module.url(
            forResource: "russian_trusted_root", withExtension: "pem", subdirectory: "Fixtures"))
        return try String(contentsOf: url, encoding: .utf8)
    }

    func testDetectsOriginalWhenPresent() throws {
        let runner = MockCommandRunner()
        let pem = try realRootPEM()
        runner.resultForCall = { _ in CommandResult(exitCode: 0, stdout: pem, stderr: "") }
        let det = MintsifryDetector(runner: runner,
            expectedFingerprint: try XCTUnwrap(MintsifrySource.expectedRootFingerprint))
        let presence = try det.detect()
        XCTAssertTrue(presence.isPresent)
        XCTAssertFalse(presence.sha1Hashes.isEmpty)
    }

    func testAbsentWhenNoMatchingCert() throws {
        // security returns a different (non-original) cert.
        let other = try TestPKI().root.serializeAsPEM().pemString
        let runner = MockCommandRunner()
        runner.resultForCall = { _ in CommandResult(exitCode: 0, stdout: other, stderr: "") }
        let det = MintsifryDetector(runner: runner,
            expectedFingerprint: try XCTUnwrap(MintsifrySource.expectedRootFingerprint))
        XCTAssertEqual(try det.detect(), .absent)
    }

    func testAbsentWhenSecurityReturnsNothing() throws {
        let runner = MockCommandRunner()
        runner.stubResult = CommandResult(exitCode: 1, stdout: "", stderr: "not found")
        let det = MintsifryDetector(runner: runner,
            expectedFingerprint: try XCTUnwrap(MintsifrySource.expectedRootFingerprint))
        XCTAssertEqual(try det.detect(), .absent)
    }

    func testRemoveComposesPrivilegedDeleteByHash() throws {
        let pem = try realRootPEM()
        let runner = MockCommandRunner()
        runner.resultForCall = { _ in CommandResult(exitCode: 0, stdout: pem, stderr: "") }
        let det = MintsifryDetector(runner: runner,
            expectedFingerprint: try XCTUnwrap(MintsifrySource.expectedRootFingerprint))
        let presence = try det.detect()
        let priv = MockPrivilegedRunner()
        try det.remove(presence, privileged: priv)
        XCTAssertEqual(priv.batches.count, 1)
        XCTAssertTrue(priv.batches[0].contains("delete-certificate -Z"))
        XCTAssertTrue(priv.batches[0].contains(presence.sha1Hashes[0]))
    }
}
