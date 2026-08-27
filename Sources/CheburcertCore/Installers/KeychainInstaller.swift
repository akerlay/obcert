import Foundation
import Crypto
import SwiftASN1
import X509

/// Installs the trust bundle into the macOS keychain.
///
/// Runs `security` DIRECTLY as the user (not via `osascript … with administrator
/// privileges`). Setting a trusted root calls `SecTrustSettingsSetTrustSettings`,
/// which must be able to present its authorization dialog — impossible in the
/// detached root context an osascript-admin batch runs in (it fails with
/// "authorization denied … no user interaction was possible"). Run directly in the
/// user's GUI session, macOS shows the native trust dialog and the user approves.
///
/// The local root is trusted in the USER trust domain (login keychain); the cross-cert
/// and intermediates are added untrusted so the chain can build. User-domain trust is
/// honored by Safari and Chrome for the current user — sufficient for a single-user Mac
/// and requiring no admin password.
public struct KeychainInstaller: TrustStoreInstaller {
    public static let localRootCN = "obcert Local Constrained Root"
    let runner: CommandRunner
    let workDir: URL
    /// Keychain to target; nil = the user's default (login) keychain.
    let keychain: String?

    /// Manifest of SHA-1 hashes installed, so `removeAll` can delete by hash without a bundle.
    var manifestFile: URL { workDir.appendingPathComponent("keychain-installed.txt") }

    public init(runner: CommandRunner = ProcessCommandRunner(), workDir: URL, keychain: String? = nil) {
        self.runner = runner
        self.workDir = workDir
        self.keychain = keychain
    }

    private var keychainArgs: [String] { keychain.map { ["-k", $0] } ?? [] }

    public func install(_ bundle: TrustBundle) throws {
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        let localRootPath = try write(bundle.localRoot, "obcert-localroot.crt")
        let crossPath = try write(bundle.crossCert, "obcert-cross.crt")
        var interPaths: [String] = []
        for (i, cert) in bundle.intermediates.enumerated() {
            interPaths.append(try write(cert, "obcert-inter-\(i).crt"))
        }

        // SHA-1 hashes of every cert we install; for idempotent delete-first and the manifest.
        var hashes = [try Self.sha1Hash(bundle.localRoot), try Self.sha1Hash(bundle.crossCert)]
        hashes += try bundle.intermediates.map { try Self.sha1Hash($0) }
        try hashes.joined(separator: "\n").write(to: manifestFile, atomically: true, encoding: .utf8)

        // Idempotent cleanup: remove anything a previous apply left (ignore failures).
        // Delete every prior local root BY NAME — when the domain list changes the new
        // root has a different hash, so a hash-only delete would leave the old (stale,
        // differently-constrained) root trusted alongside the new one.
        _ = try? runner.run("/usr/bin/security", ["delete-certificate", "-c", Self.localRootCN] + keychainArgs)
        for h in hashes {
            _ = try? runner.run("/usr/bin/security", ["delete-certificate", "-Z", h] + keychainArgs)
        }

        // Add every cert to the keychain first (local root included). This is required:
        // `add-trusted-cert` on a cert that is NOT already in the keychain silently
        // no-ops instead of importing + trusting it, so the local root must be imported
        // here before it can be trusted. `add-certificates` exits non-zero when a cert is
        // already present ("already in ... keychain") — harmless, so failures are ignored.
        for path in [localRootPath, crossPath] + interPaths {
            _ = try? runner.run("/usr/bin/security", ["add-certificates"] + keychainArgs + [path])
        }
        // Trust anchor: mark the (now-imported) local root as a user-domain trusted root.
        // Presents the native macOS trust dialog; this is the one command that must succeed.
        try runOrThrow(["add-trusted-cert", "-r", "trustRoot"] + keychainArgs + [localRootPath])
    }

    public func removeAll() throws {
        if let manifest = try? String(contentsOf: manifestFile, encoding: .utf8) {
            for h in manifest.split(whereSeparator: \.isNewline) where !h.isEmpty {
                _ = try? runner.run("/usr/bin/security",
                                    ["delete-certificate", "-Z", String(h)] + keychainArgs)
            }
        }
        // Belt-and-suspenders for the trust anchor (removes cert and its user trust settings).
        _ = try? runner.run("/usr/bin/security",
                            ["delete-certificate", "-c", Self.localRootCN] + keychainArgs)
    }

    /// Run a `security` subcommand, mapping a user cancel to `.authorizationDenied`.
    private func runOrThrow(_ args: [String]) throws {
        let res = try runner.run("/usr/bin/security", args)
        guard res.exitCode != 0 else { return }
        let err = res.stderr.lowercased()
        if err.contains("-128") || err.contains("cancel") || err.contains("user canceled") {
            throw CheburcertError.authorizationDenied
        }
        throw CheburcertError.commandFailed(command: "security", exitCode: res.exitCode, stderr: res.stderr)
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
