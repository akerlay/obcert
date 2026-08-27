import Foundation
import Crypto
import SwiftASN1
import X509

public struct KeychainInstaller: TrustStoreInstaller {
    public static let localRootCN = "obcert Local Constrained Root"
    let privileged: PrivilegedRunner
    let workDir: URL
    let systemKeychain = "/Library/Keychains/System.keychain"

    /// Manifest of SHA-1 hashes installed, so `removeAll` can delete by hash without a bundle.
    var manifestFile: URL { workDir.appendingPathComponent("keychain-installed.txt") }

    public init(privileged: PrivilegedRunner, workDir: URL) {
        self.privileged = privileged
        self.workDir = workDir
    }

    public func install(_ bundle: TrustBundle) throws {
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        let localRootPath = try write(bundle.localRoot, "cheburcert-localroot.crt")
        let crossPath = try write(bundle.crossCert, "cheburcert-cross.crt")
        var interPaths: [String] = []
        for (i, cert) in bundle.intermediates.enumerated() {
            interPaths.append(try write(cert, "cheburcert-inter-\(i).crt"))
        }

        // SHA-1 hashes of every cert we install; used for idempotent delete-first and the manifest.
        var hashes = [try Self.sha1Hash(bundle.localRoot), try Self.sha1Hash(bundle.crossCert)]
        hashes += try bundle.intermediates.map { try Self.sha1Hash($0) }
        try hashes.joined(separator: "\n").write(to: manifestFile, atomically: true, encoding: .utf8)

        var lines: [String] = ["set -e"]
        // Idempotent cleanup: delete anything a previous apply left, by hash and by CN.
        for h in hashes {
            lines.append("/usr/bin/security delete-certificate -Z \(h) \(systemKeychain) || true")
        }
        lines.append("/usr/bin/security delete-certificate -c '\(Self.localRootCN)' \(systemKeychain) || true")
        // Adds must fail-fast (no `|| true`).
        lines.append("/usr/bin/security add-trusted-cert -d -r trustRoot -k \(systemKeychain) '\(localRootPath)'")
        lines.append("/usr/bin/security add-certificates -k \(systemKeychain) '\(crossPath)'")
        for p in interPaths {
            lines.append("/usr/bin/security add-certificates -k \(systemKeychain) '\(p)'")
        }
        try privileged.runScript(lines.joined(separator: "; "))
    }

    public func removeAll() throws {
        var lines: [String] = ["set -e"]
        if let manifest = try? String(contentsOf: manifestFile, encoding: .utf8) {
            for h in manifest.split(whereSeparator: \.isNewline) where !h.isEmpty {
                lines.append("/usr/bin/security delete-certificate -Z \(h) \(systemKeychain) || true")
            }
        }
        // Belt-and-suspenders for the trust anchor.
        lines.append("/usr/bin/security delete-certificate -c '\(Self.localRootCN)' \(systemKeychain) || true")
        try privileged.runScript(lines.joined(separator: "; "))
    }

    /// SHA-1 over the cert's DER, as bare UPPERCASE hex (what `security -Z` expects).
    static func sha1Hash(_ cert: Certificate) throws -> String {
        var serializer = DER.Serializer()
        try serializer.serialize(cert)
        let digest = Insecure.SHA1.hash(data: Data(serializer.serializedBytes))
        return digest.map { String(format: "%02X", $0) }.joined()
    }

    private func write(_ cert: Certificate, _ name: String) throws -> String {
        let url = workDir.appendingPathComponent(name)
        let pem = try cert.serializeAsPEM().pemString
        try pem.write(to: url, atomically: true, encoding: .utf8)
        return url.path
    }
}
