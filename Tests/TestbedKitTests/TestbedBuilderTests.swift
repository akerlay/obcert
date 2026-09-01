import XCTest
import X509
import TestbedKit
import CheburcertCore

final class TestbedBuilderTests: XCTestCase {
    private func tempDir() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    }

    func testBuildWritesProfileCertsAndManifest() async throws {
        let dir = tempDir()
        let out = try await TestbedBuilder().build(lanIP: "192.0.2.10", port: 8443, to: dir)
        let fm = FileManager.default

        XCTAssertEqual(out.manifest.permittedHost, "ok.192-0-2-10.sslip.io")
        XCTAssertEqual(out.manifest.forbiddenHost, "bad.192-0-2-10.sslip.io")
        XCTAssertTrue(fm.fileExists(atPath: out.manifest.mobileconfig))
        XCTAssertTrue(out.manifest.mobileconfig.hasSuffix("obcert-test.mobileconfig"),
                      "тестовый профиль должен быть неотличим от продового только по имени файла")
        XCTAssertTrue(fm.fileExists(atPath: out.manifestFile.path))
        XCTAssertTrue(fm.fileExists(atPath: out.manifest.localRootPEM))
        for pem in out.manifest.storeCertPEMs { XCTAssertTrue(fm.fileExists(atPath: pem)) }

        XCTAssertEqual(out.manifest.cases.map(\.name), ["ok", "okfull", "badfull", "bad", "ip"])
        for c in out.manifest.cases {
            XCTAssertTrue(fm.fileExists(atPath: c.certificateChainPEM))
            XCTAssertTrue(fm.fileExists(atPath: c.privateKeyPEM))
        }
        XCTAssertEqual(out.manifest.cases.map(\.expectation), [.valid, .valid, .invalid, .invalid, .invalid])
    }

    func testConstraintHoldsOffline() async throws {
        let out = try await TestbedBuilder().build(lanIP: "192.0.2.10", port: 8443, to: tempDir())
        XCTAssertEqual(out.offlineVerdicts, [.valid, .valid, .invalid, .invalid, .invalid],
                       "ChainSelfCheck должен подтвердить матрицу до любых ручных прогонов")
        XCTAssertEqual(out.offlineVerdicts, out.manifest.cases.map(\.expectation))
    }

    func testManifestRoundTripsAsJSON() async throws {
        let out = try await TestbedBuilder().build(lanIP: "192.0.2.10", port: 8443, to: tempDir())
        let data = try Data(contentsOf: out.manifestFile)
        let decoded = try JSONDecoder().decode(TestbedManifest.self, from: data)
        XCTAssertEqual(decoded.permittedHost, out.manifest.permittedHost)
        XCTAssertEqual(decoded.cases.count, 5)
        XCTAssertEqual(decoded.port, 8443)
    }

    func testPrivateKeysAreNotWorldReadable() async throws {
        let out = try await TestbedBuilder().build(lanIP: "192.0.2.10", port: 8443, to: tempDir())
        for c in out.manifest.cases {
            let attrs = try FileManager.default.attributesOfItem(atPath: c.privateKeyPEM)
            XCTAssertEqual(attrs[.posixPermissions] as? Int, 0o600)
        }
    }

    func testMalformedIPIsRejected() async throws {
        do {
            _ = try await TestbedBuilder().build(lanIP: "192.168.1", port: 8443, to: tempDir())
            XCTFail("ожидалась ошибка разбора адреса")
        } catch let error as FakeGovPKIError {
            XCTAssertEqual(error, .invalidIPv4("192.168.1"))
        }
    }

    func testSelfContainedCaseShipsTheCrossCertificateInline() async throws {
        let out = try await TestbedBuilder().build(lanIP: "192.0.2.10", port: 8443, to: tempDir())
        func certCount(_ caseName: String) throws -> Int {
            let c = try XCTUnwrap(out.manifest.cases.first { $0.name == caseName })
            return try String(contentsOfFile: c.certificateChainPEM, encoding: .utf8)
                .components(separatedBy: "BEGIN CERTIFICATE").count - 1
        }
        // "ok" mirrors a real Минцифры host: leaf + sub CA, cross-certificate from the store.
        XCTAssertEqual(try certCount("ok"), 2)
        // "okfull" carries the cross-certificate itself, so path building needs no store.
        XCTAssertEqual(try certCount("okfull"), 3)
        // The forbidden twin must be self-contained too, or its rejection is unattributable.
        XCTAssertEqual(try certCount("badfull"), 3)
    }

    func testLayoutsGetSeparateIdentifiersAndAnchorVariantOmitsTheLocalRoot() async throws {
        var identifiers: Set<String> = []
        for layout in ProfileLayout.allCases {
            let out = try await TestbedBuilder().build(
                lanIP: "192.0.2.10", port: 8443, tag: "l", layout: layout, to: tempDir())
            let plist = try XCTUnwrap(try PropertyListSerialization.propertyList(
                from: Data(contentsOf: URL(fileURLWithPath: out.manifest.mobileconfig)),
                options: [], format: nil) as? [String: Any])
            identifiers.insert(try XCTUnwrap(plist["PayloadIdentifier"] as? String))

            let payloads = try XCTUnwrap(plist["PayloadContent"] as? [[String: Any]])
            let roots = payloads.filter { $0["PayloadType"] as? String == "com.apple.security.root" }
            XCTAssertEqual(roots.count, 1, "ровно один якорь в любом варианте")
            if layout == .crossAsAnchor {
                // The anchor must be the cross-certificate, and the local root must be absent
                // — otherwise the run would not test anchor-level constraint enforcement.
                XCTAssertEqual(payloads.count, 1)
            }
        }
        XCTAssertEqual(identifiers.count, ProfileLayout.allCases.count,
                       "варианты не должны вытеснять друг друга при установке")
    }

    func testTagMakesHostnamesUniquePerRun() async throws {
        let out = try await TestbedBuilder().build(
            lanIP: "192.0.2.10", port: 8443, tag: "r3", to: tempDir())
        XCTAssertEqual(out.manifest.permittedHost, "ok-r3.192-0-2-10.sslip.io")
        XCTAssertEqual(out.manifest.forbiddenHost, "bad-r3.192-0-2-10.sslip.io")
        XCTAssertEqual(out.offlineVerdicts, [.valid, .valid, .invalid, .invalid, .invalid],
                       "метка не должна ломать сами ограничения")
    }

    func testTestbedProfileCannotReplaceTheProductionOne() async throws {
        let out = try await TestbedBuilder().build(
            lanIP: "192.0.2.10", port: 8443, tag: "r4", to: tempDir())
        let plist = try XCTUnwrap(try PropertyListSerialization.propertyList(
            from: Data(contentsOf: URL(fileURLWithPath: out.manifest.mobileconfig)),
            options: [], format: nil) as? [String: Any])

        // iOS keys profiles by PayloadIdentifier: sharing one means installing the testbed
        // silently removes the user's real protection.
        let identifier = try XCTUnwrap(plist["PayloadIdentifier"] as? String)
        XCTAssertNotEqual(identifier, PhoneExporter.Identity.production.identifier)
        XCTAssertTrue(identifier.hasPrefix(TestbedBuilder.testIdentity.identifier))
        // Each layout gets its own identifier so two variants can be installed side by side
        // without one replacing the other.
        XCTAssertEqual(identifier, TestbedBuilder.testIdentity.identifier + ".pkcs1")

        // The CN is all iOS shows in Certificate Trust Settings, so it must differ too.
        XCTAssertNotEqual(TestbedBuilder.testRootCommonName(tag: nil), "obcert Local Constrained Root")
        // The generation marker must reach the CN, or a regenerated testbed is
        // indistinguishable from the previous one in the phone's trust settings.
        XCTAssertTrue(TestbedBuilder.testRootCommonName(tag: "r9").contains("r9"))
    }
}
