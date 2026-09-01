import Foundation
import Crypto
import _CryptoExtras
import X509
import SwiftASN1
import CheburcertCore

/// A testbed with no cross-signing and no name constraints at all.
///
/// It answers one question the main testbed cannot: does the client use an ordinary
/// intermediate that only the profile supplied? The cross-certificate is an unusual object —
/// it shares its subject and Subject Key Identifier with a root that is not installed, and it
/// carries a critical `nameConstraints` extension on a CA — so "iOS ignored it" has two very
/// different readings, and only one of them is about profile-installed intermediates in
/// general.
///
/// Here the chain is boring on purpose: self-signed root, ordinary intermediate, leaf. The
/// profile installs the root as an anchor and the intermediate as a plain certificate, and
/// the server sends the leaf alone. If that validates, profile-installed intermediates work
/// and the blocker is the cross-certificate itself.
public struct PlainChainTestbed: Sendable {
    public static func rootCommonName(tag: String?) -> String {
        "obcert PLAIN Root\(tag.map { " \($0)" } ?? "") — DELETE ME"
    }

    public init() {}

    public func build(lanIP: String, port: Int, tag: String? = nil,
                      to directory: URL) async throws -> TestbedOutput {
        _ = try FakeGovPKI.ipv4Octets(lanIP)

        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])

        let now = Date()
        let caEnd = now.addingTimeInterval(10 * 365 * 24 * 3600)

        let rootKey = Certificate.PrivateKey(P384.Signing.PrivateKey())
        let rootDN = try DistinguishedName {
            CommonName(Self.rootCommonName(tag: tag))
            OrganizationName("obcert")
        }
        let rootSKI = SubjectKeyIdentifier(hash: rootKey.publicKey)
        let root = try Certificate(
            version: .v3, serialNumber: Certificate.SerialNumber(),
            publicKey: rootKey.publicKey,
            notValidBefore: now, notValidAfter: caEnd,
            issuer: rootDN, subject: rootDN,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 1))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                rootSKI
            },
            issuerPrivateKey: rootKey)

        let interKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let interDN = try DistinguishedName {
            CommonName("obcert PLAIN Intermediate\(tag.map { " \($0)" } ?? "")")
            OrganizationName("obcert")
        }
        let interPublicKey = interKey.publicKey
        let intermediate = try Certificate(
            version: .v3, serialNumber: Certificate.SerialNumber(),
            publicKey: interPublicKey,
            notValidBefore: now, notValidAfter: caEnd,
            issuer: rootDN, subject: interDN,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                SubjectKeyIdentifier(hash: interPublicKey)
                AuthorityKeyIdentifier(keyIdentifier: rootSKI.keyIdentifier)
            },
            issuerPrivateKey: rootKey)

        let base = "\(lanIP.replacingOccurrences(of: ".", with: "-")).sslip.io"
        let suffix = tag.map { "-\($0)" } ?? ""
        let storeHost = "plain\(suffix).\(base)"      // intermediate must come from the store
        let inlineHost = "plainfull\(suffix).\(base)" // intermediate sent by the server

        func leaf(_ host: String) throws -> (Certificate, Certificate.PrivateKey) {
            let key = Certificate.PrivateKey(P256.Signing.PrivateKey())
            let cert = try Certificate(
                version: .v3, serialNumber: Certificate.SerialNumber(),
                publicKey: key.publicKey,
                notValidBefore: now,
                notValidAfter: now.addingTimeInterval(FakeGovPKI.leafLifetime),
                issuer: interDN, subject: try DistinguishedName { CommonName(host) },
                signatureAlgorithm: .ecdsaWithSHA256,
                extensions: try Certificate.Extensions {
                    Critical(BasicConstraints.notCertificateAuthority)
                    KeyUsage(digitalSignature: true, keyEncipherment: true)
                    try ExtendedKeyUsage([.serverAuth])
                    SubjectAlternativeNames([.dnsName(host)])
                },
                issuerPrivateKey: interKey)
            return (cert, key)
        }

        let rootPEM = directory.appendingPathComponent("plain-root.pem")
        let interPEM = directory.appendingPathComponent("plain-intermediate.pem")
        try (root.serializeAsPEM().pemString + "\n").write(to: rootPEM, atomically: true, encoding: .utf8)
        try (intermediate.serializeAsPEM().pemString + "\n").write(to: interPEM, atomically: true, encoding: .utf8)

        var cases: [TestbedCase] = []
        var verdicts: [CaseExpectation] = []
        for (name, host, inline) in [("plain", storeHost, false), ("plainfull", inlineHost, true)] {
            let (cert, key) = try leaf(host)
            var chainPEM = try cert.serializeAsPEM().pemString + "\n"
            if inline { chainPEM += try intermediate.serializeAsPEM().pemString + "\n" }
            let chain = directory.appendingPathComponent("leaf-\(name)-chain.pem")
            let keyFile = directory.appendingPathComponent("leaf-\(name)-key.pem")
            try chainPEM.write(to: chain, atomically: true, encoding: .utf8)
            try key.serializeAsPEM().pemString.write(to: keyFile, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: keyFile.path)

            cases.append(TestbedCase(
                name: name, serverName: host, url: "https://\(host):\(port)/",
                expectation: .valid, sendsFullChain: inline,
                certificateChainPEM: chain.path, privateKeyPEM: keyFile.path))
            let ok = await ChainSelfCheck.validates(
                leaf: cert, intermediates: [intermediate], localRoot: root,
                at: now.addingTimeInterval(1))
            verdicts.append(ok ? .valid : .invalid)
        }

        let identity = PhoneExporter.Identity(
            identifier: "me.obcert.profile.testbed.plain",
            displayName: "obcert TESTBED PLAIN — удалить после проверки",
            fileName: "obcert-plain.mobileconfig")
        let profile = try Self.writeProfile(
            root: root, intermediate: intermediate, identity: identity, to: directory)

        let manifest = TestbedManifest(
            lanIP: lanIP, port: port,
            permittedHost: storeHost, forbiddenHost: inlineHost,
            localRootPEM: rootPEM.path, storeCertPEMs: [interPEM.path],
            mobileconfig: profile.path,
            anchorCommonNames: [Self.rootCommonName(tag: tag)],
            cases: cases)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let manifestFile = directory.appendingPathComponent("manifest.json")
        try encoder.encode(manifest).write(to: manifestFile, options: .atomic)

        return TestbedOutput(manifest: manifest, manifestFile: manifestFile,
                             directory: directory, offlineVerdicts: verdicts)
    }

    static func writeProfile(root: Certificate, intermediate: Certificate,
                             identity: PhoneExporter.Identity, to directory: URL) throws -> URL {
        func der(_ cert: Certificate) throws -> Data {
            var s = DER.Serializer(); try s.serialize(cert); return Data(s.serializedBytes)
        }
        func payload(_ cert: Certificate, type: String, name: String) throws -> [String: Any] {
            [
                "PayloadType": type,
                "PayloadVersion": 1,
                "PayloadContent": try der(cert),
                "PayloadCertificateFileName": "\(name).cer",
                "PayloadDisplayName": name,
                "PayloadIdentifier": "\(identity.identifier).\(name)",
                "PayloadUUID": UUID().uuidString,
            ]
        }
        let profile: [String: Any] = [
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadDisplayName": identity.displayName,
            "PayloadIdentifier": identity.identifier,
            "PayloadUUID": UUID().uuidString,
            "PayloadDescription": "TESTBED: обычный корень и промежуточный, без ограничений имён.",
            "PayloadContent": [
                try payload(root, type: "com.apple.security.root", name: "plain-root"),
                try payload(intermediate, type: "com.apple.security.pkcs1", name: "plain-intermediate"),
            ],
        ]
        let url = directory.appendingPathComponent(identity.fileName)
        try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0)
            .write(to: url, options: .atomic)
        return url
    }
}
