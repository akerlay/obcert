import XCTest
import X509
@testable import CheburcertCore

final class KeychainInstallerTests: XCTestCase {
    func tempDir() -> URL {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }

    func makeBundle() throws -> TrustBundle {
        let pki = try TestPKI()
        return try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])
    }

    func testInstallAddsBridgingCertsThenTrustsRoot() throws {
        let bundle = try makeBundle()
        let runner = MockCommandRunner()
        let installer = KeychainInstaller(runner: runner, workDir: tempDir())
        try installer.install(bundle)

        // add-certificates for cross + one intermediate (untrusted bridging certs)
        let addCerts = runner.calls.filter { $0.arguments.first == "add-certificates" }
        XCTAssertEqual(addCerts.count, 2)
        // exactly one trusted-root add, user domain (no -d), with -r trustRoot
        let trustCalls = runner.calls.filter { $0.arguments.first == "add-trusted-cert" }
        XCTAssertEqual(trustCalls.count, 1)
        XCTAssertTrue(trustCalls[0].arguments.contains("-r"))
        XCTAssertTrue(trustCalls[0].arguments.contains("trustRoot"))
        XCTAssertFalse(trustCalls[0].arguments.contains("-d"), "must NOT use admin domain")
        // trust anchor is added after the bridging certs
        let lastAdd = runner.calls.lastIndex { $0.arguments.first == "add-trusted-cert" }!
        let lastBridge = runner.calls.lastIndex { $0.arguments.first == "add-certificates" }!
        XCTAssertGreaterThan(lastAdd, lastBridge)
    }

    func testInstallDeletesFirstByHash() throws {
        let bundle = try makeBundle()
        let runner = MockCommandRunner()
        let installer = KeychainInstaller(runner: runner, workDir: tempDir())
        try installer.install(bundle)

        let deletes = runner.calls.filter {
            $0.arguments.first == "delete-certificate" && $0.arguments.contains("-Z")
        }
        // localRoot + cross + 1 intermediate = 3 idempotent delete-firsts
        XCTAssertEqual(deletes.count, 3)
    }

    func testInstallThrowsAuthorizationDeniedOnCancel() throws {
        let bundle = try makeBundle()
        let runner = MockCommandRunner()
        runner.resultForCall = { call in
            call.arguments.first == "add-trusted-cert"
                ? CommandResult(exitCode: 1, stdout: "", stderr: "User canceled.")
                : CommandResult(exitCode: 0, stdout: "", stderr: "")
        }
        let installer = KeychainInstaller(runner: runner, workDir: tempDir())
        XCTAssertThrowsError(try installer.install(bundle)) {
            XCTAssertEqual($0 as? CheburcertError, .authorizationDenied)
        }
    }

    func testRemoveDeletesByCommonName() throws {
        let runner = MockCommandRunner()
        let installer = KeychainInstaller(runner: runner, workDir: tempDir())
        try installer.removeAll()
        XCTAssertTrue(runner.calls.contains {
            $0.arguments.first == "delete-certificate"
                && $0.arguments.contains("-c")
                && $0.arguments.contains(KeychainInstaller.localRootCN)
        })
    }

    func testRemoveAllAfterInstallDeletesByHash() throws {
        let bundle = try makeBundle()
        let runner = MockCommandRunner()
        let dir = tempDir()
        let installer = KeychainInstaller(runner: runner, workDir: dir)
        try installer.install(bundle)
        try installer.removeAll()

        // removeAll should delete each manifest hash by -Z, plus the CN fallback.
        let hashDeletes = runner.calls.filter {
            $0.arguments.first == "delete-certificate" && $0.arguments.contains("-Z")
        }
        // 3 from install delete-first + 3 from removeAll manifest = at least 3 in removeAll
        XCTAssertGreaterThanOrEqual(hashDeletes.count, 6)
        XCTAssertTrue(runner.calls.contains {
            $0.arguments.contains("-c") && $0.arguments.contains(KeychainInstaller.localRootCN)
        })
    }
}
