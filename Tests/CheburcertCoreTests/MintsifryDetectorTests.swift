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

    // System-keychain case: the cert still resolves after the user-context delete
    // (mock always returns it), so removal escalates to a privileged System delete.
    func testRemoveEscalatesToSystemWhenStillPresent() throws {
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
        XCTAssertTrue(priv.batches[0].contains("/Library/Keychains/System.keychain"))
        XCTAssertTrue(priv.batches[0].contains(presence.sha1Hashes[0]))
    }

    // Login-keychain case: the user-context delete removes it, so a re-detect finds it
    // gone and NO admin escalation happens.
    func testRemoveFromLoginNeedsNoAdmin() throws {
        let pem = try realRootPEM()
        let runner = MockCommandRunner()
        var deleted = false
        runner.resultForCall = { call in
            if call.arguments.first == "delete-certificate" {
                deleted = true
                return CommandResult(exitCode: 0, stdout: "", stderr: "")
            }
            // find-certificate: returns the original until a delete has happened.
            return CommandResult(exitCode: 0, stdout: deleted ? "" : pem, stderr: "")
        }
        let det = MintsifryDetector(runner: runner,
            expectedFingerprint: try XCTUnwrap(MintsifrySource.expectedRootFingerprint))
        let presence = try det.detect()
        XCTAssertTrue(presence.isPresent)
        let priv = MockPrivilegedRunner()
        try det.remove(presence, privileged: priv)
        XCTAssertTrue(priv.batches.isEmpty, "login-keychain removal must not prompt for admin")
        XCTAssertTrue(runner.calls.contains { $0.arguments.first == "delete-certificate" })
    }
}
