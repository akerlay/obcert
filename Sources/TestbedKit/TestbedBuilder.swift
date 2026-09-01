import Foundation
import X509
import SwiftASN1
import CheburcertCore

public enum CaseExpectation: String, Codable, Sendable {
    case valid
    case invalid
}

public struct TestbedCase: Codable, Sendable {
    public let name: String
    /// SNI / URL host the client must use. Empty for the bare-IP case (no SNI).
    public let serverName: String
    public let url: String
    public let expectation: CaseExpectation
    /// Whether the server sends the cross-certificate itself. A case can only be compared
    /// against a control that builds its path the same way.
    public let sendsFullChain: Bool
    public let certificateChainPEM: String
    public let privateKeyPEM: String
}

public struct TestbedManifest: Codable, Sendable {
    public let lanIP: String
    public let port: Int
    public let permittedHost: String
    public let forbiddenHost: String
    /// Trust anchor the profile installs.
    public let localRootPEM: String
    /// Certificates the profile installs WITHOUT trust. The whole question is whether the
    /// client will use them to build a path; naming them after one layout's cross-certificate
    /// stopped being honest once a plain-intermediate layout existed.
    public let storeCertPEMs: [String]
    public let mobileconfig: String
    /// CNs of the roots the profile installs, i.e. exactly the switches that must be turned
    /// on in Certificate Trust Settings. The anchor variant trusts the cross-certificate,
    /// whose CN is the stand-in Минцифры name — nobody would guess to look for that.
    public let anchorCommonNames: [String]
    public let cases: [TestbedCase]
}

public struct TestbedOutput: Sendable {
    public let manifest: TestbedManifest
    public let manifestFile: URL
    public let directory: URL
    /// Verdicts from `ChainSelfCheck`, in the same order as `manifest.cases`.
    public let offlineVerdicts: [CaseExpectation]
}

/// Builds every artifact the name-constraint testbed needs.
///
/// The point of the exercise: the real Минцифры private key is unobtainable, so the MITM a
/// constrained root is supposed to stop cannot be staged with genuine certificates. A local
/// stand-in root whose key we hold reproduces exactly that capability, and the pair
/// (permitted host, forbidden host) differs only in the name — so a difference in outcome can
/// only come from the name constraints.
/// How the cross-certificate reaches the phone's trust store.
public enum ProfileLayout: String, Sendable, CaseIterable {
    /// Production shape: the constrained local root is the anchor, the cross-certificate is
    /// installed as an ordinary certificate and must be found by the path builder.
    case pkcs1
    /// Same, but the cross-certificate is carried as PEM instead of DER.
    case pem
    /// Experiment: the cross-certificate is installed as a trust anchor and the local root
    /// is left out, so no store lookup is needed at all. Only safe if the client enforces
    /// name constraints on an anchor — RFC 5280 §6.1 makes that optional, so this layout
    /// must never ship without measuring it.
    case crossAsAnchor
}

public struct TestbedBuilder: Sendable {
    public static func testRootCommonName(tag: String?) -> String {
        "obcert TESTBED Root\(tag.map { " \($0)" } ?? "") — DELETE ME"
    }
    public static let testIdentity = PhoneExporter.Identity(
        identifier: "me.obcert.profile.testbed",
        displayName: "obcert TESTBED — удалить после проверки",
        fileName: "obcert-test.mobileconfig")

    public init() {}

    /// Experiment-only profile: trusts the cross-certificate directly and omits the local
    /// root, so the chain needs nothing from the store. Kept here rather than in
    /// PhoneExporter because it is not a shape the product may ship as-is.
    static func writeCrossAsAnchorProfile(
        bundle: TrustBundle, identity: PhoneExporter.Identity, to directory: URL
    ) throws -> URL {
        var der = DER.Serializer()
        try der.serialize(bundle.crossCert)
        let payload: [String: Any] = [
            "PayloadType": "com.apple.security.root",
            "PayloadVersion": 1,
            "PayloadContent": Data(der.serializedBytes),
            "PayloadCertificateFileName": "obcert-cross.cer",
            "PayloadDisplayName": "obcert TESTBED cross-as-anchor",
            "PayloadIdentifier": "\(identity.identifier).cross",
            "PayloadUUID": UUID().uuidString,
        ]
        let profile: [String: Any] = [
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadDisplayName": identity.displayName,
            "PayloadIdentifier": identity.identifier,
            "PayloadUUID": UUID().uuidString,
            "PayloadDescription": "TESTBED: кросс-сертификат установлен как доверенный корень.",
            "PayloadContent": [payload],
        ]
        let url = directory.appendingPathComponent(identity.fileName)
        try PropertyListSerialization
            .data(fromPropertyList: profile, format: .xml, options: 0)
            .write(to: url, options: .atomic)
        return url
    }

    /// - Parameter tag: distinguishes this run's hostnames from every previous one.
    ///   Safari remembers a certificate exception the user clicked through, and that
    ///   memory is per hostname — reusing names silently turns a later run into a replay
    ///   of the earlier decision instead of a test.
    public func build(lanIP: String, port: Int, tag: String? = nil,
                      layout: ProfileLayout = .pkcs1,
                      to directory: URL) async throws -> TestbedOutput {
        _ = try FakeGovPKI.ipv4Octets(lanIP)   // fail early on a malformed address

        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])

        // 4096-bit root mirrors the real Минцифры root, whose public key the cross-cert reuses.
        let pki = try FakeGovPKI(rootKeySize: .bits4096, label: tag)
        let base = "\(lanIP.replacingOccurrences(of: ".", with: "-")).sslip.io"
        let suffix = tag.map { "-\($0)" } ?? ""
        let permittedHost = "ok\(suffix).\(base)"
        let forbiddenHost = "bad\(suffix).\(base)"
        // Same permitted name, but the server sends the cross-certificate itself instead of
        // relying on the trust store to supply it. A real Минцифры host never does this, so
        // it is not the production scenario — it isolates one question: does the client use
        // a profile-installed intermediate for path building, or must the chain arrive whole?
        let selfContainedHost = "okfull\(suffix).\(base)"
        // Forbidden name, chain sent whole. With the anchor reachable, the only thing left
        // that can reject it is the name constraint — so this is the case that actually
        // answers whether the client enforces it. A rejection of a forbidden name whose
        // chain never reached the anchor proves nothing.
        let selfContainedForbidden = "badfull\(suffix).\(base)"

        // A distinct CN and profile identifier are not cosmetic. iOS shows only the CN in
        // Certificate Trust Settings and keys installed profiles by PayloadIdentifier, so
        // reusing the production values makes the testbed root indistinguishable from the
        // real one AND makes installing the testbed silently replace the user's actual
        // protection profile.
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [permittedHost, selfContainedHost],
            mintsifryRoot: pki.root, mintsifryIntermediates: [pki.subCA],
            localRootCommonName: Self.testRootCommonName(tag: tag))

        // PhoneExporter writes obcert-root.pem / obcert-cross.pem / obcert-intermediate-0.pem
        // plus obcert.mobileconfig; reuse those files rather than duplicating the PEM writing.
        let identity = PhoneExporter.Identity(
            identifier: "\(Self.testIdentity.identifier).\(layout.rawValue.lowercased())",
            displayName: "\(Self.testIdentity.displayName) [\(layout.rawValue)]",
            fileName: Self.testIdentity.fileName,
            crossPayload: layout == .pem ? .pem : .pkcs1)
        let exported = try PhoneExporter(identity: identity).export(bundle, to: directory)
        var testProfile = exported.mobileconfig
        if layout == .crossAsAnchor {
            testProfile = try Self.writeCrossAsAnchorProfile(
                bundle: bundle, identity: identity, to: directory)
        }

        let localRootPEM = directory.appendingPathComponent("obcert-root.pem")
        let crossPEM = directory.appendingPathComponent("obcert-cross.pem")
        let fakeSubPEM = directory.appendingPathComponent("obcert-intermediate-0.pem")

        let leaves: [(name: String, serverName: String, leaf: IssuedLeaf,
                      expect: CaseExpectation, sendCross: Bool)] = [
            ("ok", permittedHost, try pki.leaf(dnsName: permittedHost), .valid, false),
            ("okfull", selfContainedHost, try pki.leaf(dnsName: selfContainedHost), .valid, true),
            ("badfull", selfContainedForbidden,
             try pki.leaf(dnsName: selfContainedForbidden), .invalid, true),
            ("bad", forbiddenHost, try pki.leaf(dnsName: forbiddenHost), .invalid, false),
            ("ip", "", try pki.leaf(ipv4: lanIP), .invalid, false),
        ]

        var cases: [TestbedCase] = []
        var verdicts: [CaseExpectation] = []
        for entry in leaves {
            let chain = directory.appendingPathComponent("leaf-\(entry.name)-chain.pem")
            let key = directory.appendingPathComponent("leaf-\(entry.name)-key.pem")
            var chainPEM = try entry.leaf.certificate.serializeAsPEM().pemString + "\n"
                + pki.subCA.serializeAsPEM().pemString + "\n"
            if entry.sendCross {
                chainPEM += try bundle.crossCert.serializeAsPEM().pemString + "\n"
            }
            try chainPEM.write(to: chain, atomically: true, encoding: .utf8)
            try entry.leaf.privateKey.serializeAsPEM().pemString
                .write(to: key, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: key.path)

            let host = entry.serverName.isEmpty ? lanIP : entry.serverName
            cases.append(TestbedCase(
                name: entry.name, serverName: entry.serverName,
                url: "https://\(host):\(port)/", expectation: entry.expect,
                sendsFullChain: entry.sendCross,
                certificateChainPEM: chain.path, privateKeyPEM: key.path))

            let valid = await ChainSelfCheck.validates(
                leaf: entry.leaf.certificate,
                intermediates: [pki.subCA, bundle.crossCert],
                localRoot: bundle.localRoot,
                at: pki.notBefore.addingTimeInterval(1))
            verdicts.append(valid ? .valid : .invalid)
        }

        let manifest = TestbedManifest(
            lanIP: lanIP, port: port,
            permittedHost: permittedHost, forbiddenHost: forbiddenHost,
            localRootPEM: localRootPEM.path,
            storeCertPEMs: [fakeSubPEM.path, crossPEM.path],
            mobileconfig: testProfile.path,
            anchorCommonNames: layout == .crossAsAnchor
                ? [bundle.crossCert.subject.description]
                : [Self.testRootCommonName(tag: tag)],
            cases: cases)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let manifestFile = directory.appendingPathComponent("manifest.json")
        try encoder.encode(manifest).write(to: manifestFile, options: .atomic)

        return TestbedOutput(
            manifest: manifest, manifestFile: manifestFile,
            directory: directory, offlineVerdicts: verdicts)
    }
}
