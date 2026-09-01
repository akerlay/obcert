import Foundation
import X509
import SwiftASN1

/// Result of a phone export: an Apple configuration profile plus Android-friendly PEM files.
public struct PhoneExportResult: Equatable, Sendable {
    public let mobileconfig: URL
    public let pemFiles: [URL]
}

/// Writes a trust bundle in phone-installable forms:
///  - an iOS/iPadOS `.mobileconfig` configuration profile (unsigned XML plist), and
///  - Android-friendly `.pem` files.
public struct PhoneExporter: Sendable {
    public init() {}

    /// Writes obcert.mobileconfig and Android .pem files into `directory` (created if needed).
    @discardableResult
    public func export(_ bundle: TrustBundle, to directory: URL) throws -> PhoneExportResult {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        // --- Configuration profile (.mobileconfig) ---
        var payloads: [[String: Any]] = []
        payloads.append(try Self.certPayload(
            bundle.localRoot, type: "com.apple.security.root",
            fileName: "obcert-root.cer", displayName: "obcert Local Constrained Root"))
        payloads.append(try Self.certPayload(
            bundle.crossCert, type: "com.apple.security.pkcs1",
            fileName: "obcert-cross.cer", displayName: "obcert Cross Certificate"))
        for (i, cert) in bundle.intermediates.enumerated() {
            payloads.append(try Self.certPayload(
                cert, type: "com.apple.security.pkcs1",
                fileName: "obcert-intermediate-\(i).cer",
                displayName: "obcert Intermediate \(i)"))
        }

        let profile: [String: Any] = [
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadDisplayName": "obcert — доверенный корень",
            "PayloadIdentifier": "me.obcert.profile",
            "PayloadUUID": UUID().uuidString,
            "PayloadDescription": "Устанавливает ограниченный (name-constrained) корневой сертификат obcert, "
                + "чтобы доверять только заданным российским доменам.",
            "PayloadContent": payloads,
        ]

        let plistData = try PropertyListSerialization.data(
            fromPropertyList: profile, format: .xml, options: 0)
        let mobileconfig = directory.appendingPathComponent("obcert.mobileconfig")
        try plistData.write(to: mobileconfig, options: .atomic)

        // --- Android-friendly PEM files ---
        var pemFiles: [URL] = []
        pemFiles.append(try Self.writePEM(bundle.localRoot, name: "obcert-root.pem", in: directory))
        pemFiles.append(try Self.writePEM(bundle.crossCert, name: "obcert-cross.pem", in: directory))
        for (i, cert) in bundle.intermediates.enumerated() {
            pemFiles.append(try Self.writePEM(cert, name: "obcert-intermediate-\(i).pem", in: directory))
        }

        return PhoneExportResult(mobileconfig: mobileconfig, pemFiles: pemFiles)
    }

    /// Build one certificate payload dict for the configuration profile.
    private static func certPayload(
        _ cert: Certificate, type: String, fileName: String, displayName: String
    ) throws -> [String: Any] {
        [
            "PayloadType": type,
            "PayloadVersion": 1,
            "PayloadContent": try der(cert),
            "PayloadCertificateFileName": fileName,
            "PayloadDisplayName": displayName,
            "PayloadIdentifier": "me.obcert.profile.\(UUID().uuidString)",
            "PayloadUUID": UUID().uuidString,
        ]
    }

    /// DER-encode a certificate.
    private static func der(_ cert: Certificate) throws -> Data {
        var serializer = DER.Serializer()
        try serializer.serialize(cert)
        return Data(serializer.serializedBytes)
    }

    @discardableResult
    private static func writePEM(_ cert: Certificate, name: String, in dir: URL) throws -> URL {
        let url = dir.appendingPathComponent(name)
        // Trailing newline matters: without it, concatenating two exported files puts
        // "-----END CERTIFICATE----------BEGIN CERTIFICATE-----" on one line and the whole
        // bundle becomes unparseable to OpenSSL and friends.
        let pem = try cert.serializeAsPEM().pemString + "\n"
        try pem.write(to: url, atomically: true, encoding: .utf8)
        return url
    }
}
