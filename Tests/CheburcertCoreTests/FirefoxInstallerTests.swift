import XCTest
import X509
@testable import CheburcertCore

final class FirefoxInstallerTests: XCTestCase {
    func makeBundle() throws -> TrustBundle {
        let pki = try TestPKI()
        return try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])
    }

    func testInstallsLocalRootWithTrustFlagIntoEachProfile() throws {
        let bundle = try makeBundle()
        let runner = MockCommandRunner()
        let profiles = [URL(fileURLWithPath: "/p/one"), URL(fileURLWithPath: "/p/two")]
        let installer = FirefoxInstaller(
            certutilPath: "/opt/certutil", runner: runner,
            profiles: { profiles }, isFirefoxRunning: { false },
            workDir: FileManager.default.temporaryDirectory)
        try installer.install(bundle)

        let addCalls = runner.calls.filter { $0.arguments.contains("-A") }
        XCTAssertEqual(addCalls.count, 2)
        XCTAssertTrue(addCalls[0].arguments.contains("sql:/p/one"))
        XCTAssertTrue(addCalls[0].arguments.contains("C,,"))
        XCTAssertTrue(addCalls[0].arguments.contains(KeychainInstaller.localRootCN))
    }

    func testThrowsWhenFirefoxRunning() throws {
        let bundle = try makeBundle()
        let installer = FirefoxInstaller(
            certutilPath: "/opt/certutil", runner: MockCommandRunner(),
            profiles: { [URL(fileURLWithPath: "/p/one")] }, isFirefoxRunning: { true },
            workDir: FileManager.default.temporaryDirectory)
        XCTAssertThrowsError(try installer.install(bundle)) {
            XCTAssertEqual($0 as? CheburcertError, .firefoxRunning)
        }
    }

    func testNoProfilesIsNotAnErrorButInstallsNothing() throws {
        let bundle = try makeBundle()
        let runner = MockCommandRunner()
        let installer = FirefoxInstaller(
            certutilPath: "/opt/certutil", runner: runner,
            profiles: { [] }, isFirefoxRunning: { false },
            workDir: FileManager.default.temporaryDirectory)
        try installer.install(bundle)
        XCTAssertTrue(runner.calls.isEmpty)
    }
}
