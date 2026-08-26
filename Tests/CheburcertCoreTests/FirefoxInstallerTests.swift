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

        // The local root must be added once per profile with the trust anchor flag.
        let rootAddCalls = runner.calls.filter {
            $0.arguments.contains("-A") && $0.arguments.contains(KeychainInstaller.localRootCN)
        }
        XCTAssertEqual(rootAddCalls.count, 2)
        for (i, profile) in ["sql:/p/one", "sql:/p/two"].enumerated() {
            XCTAssertTrue(rootAddCalls[i].arguments.contains("C,,"))
            XCTAssertTrue(rootAddCalls[i].arguments.contains(profile))
        }
    }

    func testInstallsCrossCertAndIntermediatesIntoEachProfile() throws {
        let bundle = try makeBundle()
        let runner = MockCommandRunner()
        let installer = FirefoxInstaller(
            certutilPath: "/opt/certutil", runner: runner,
            profiles: { [URL(fileURLWithPath: "/p/one")] }, isFirefoxRunning: { false },
            workDir: FileManager.default.temporaryDirectory)
        try installer.install(bundle)

        let addCalls = runner.calls.filter { $0.arguments.contains("-A") }
        let crossAdd = addCalls.first {
            $0.arguments.contains("Cheburcert Cross")
        }
        XCTAssertNotNil(crossAdd)
        XCTAssertTrue(crossAdd?.arguments.contains(",,") ?? false)
        XCTAssertTrue(addCalls.contains { $0.arguments.contains("Cheburcert Intermediate 0") })
    }

    func testRemoveAllDeletesLocalRootCrossAndIntermediateNicknames() throws {
        let runner = MockCommandRunner()
        let installer = FirefoxInstaller(
            certutilPath: "/opt/certutil", runner: runner,
            profiles: { [URL(fileURLWithPath: "/p/one")] }, isFirefoxRunning: { false },
            workDir: FileManager.default.temporaryDirectory)
        try installer.removeAll()

        let delCalls = runner.calls.filter { $0.arguments.contains("-D") }
        XCTAssertTrue(delCalls.contains { $0.arguments.contains(KeychainInstaller.localRootCN) })
        XCTAssertTrue(delCalls.contains { $0.arguments.contains("Cheburcert Cross") })
        XCTAssertTrue(delCalls.contains { $0.arguments.contains("Cheburcert Intermediate 0") })
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
