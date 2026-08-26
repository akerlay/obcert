import Foundation
import X509

public struct KeychainInstaller: TrustStoreInstaller {
    public static let localRootCN = "Cheburcert Local Constrained Root"
    let privileged: PrivilegedRunner
    let workDir: URL
    let systemKeychain = "/Library/Keychains/System.keychain"

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

        var lines: [String] = []
        lines.append(removeScriptBody())
        lines.append("/usr/bin/security add-trusted-cert -d -r trustRoot -k \(systemKeychain) '\(localRootPath)'")
        lines.append("/usr/bin/security add-certificates -k \(systemKeychain) '\(crossPath)'")
        for p in interPaths {
            lines.append("/usr/bin/security add-certificates -k \(systemKeychain) '\(p)'")
        }
        try privileged.runScript(lines.joined(separator: "; "))
    }

    public func removeAll() throws {
        try privileged.runScript(removeScriptBody())
    }

    private func removeScriptBody() -> String {
        "/usr/bin/security delete-certificate -c '\(Self.localRootCN)' \(systemKeychain) || true"
    }

    private func write(_ cert: Certificate, _ name: String) throws -> String {
        let url = workDir.appendingPathComponent(name)
        let pem = try cert.serializeAsPEM().pemString
        try pem.write(to: url, atomically: true, encoding: .utf8)
        return url.path
    }
}
