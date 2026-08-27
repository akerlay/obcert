import Foundation
import X509

/// Whether the original, unconstrained Минцифры root is present in the trust stores.
public struct OriginalRootPresence: Equatable, Sendable {
    public var isPresent: Bool
    /// SHA-1 hashes (bare uppercase hex) of each matching original cert, for `-Z` removal.
    public var sha1Hashes: [String]
    public init(isPresent: Bool, sha1Hashes: [String]) {
        self.isPresent = isPresent
        self.sha1Hashes = sha1Hashes
    }
    public static let absent = OriginalRootPresence(isPresent: false, sha1Hashes: [])
}

/// Detects whether the ORIGINAL, unconstrained Минцифры root CA ("Russian Trusted Root CA")
/// is trusted in the macOS keychains, and can remove it.
///
/// The app installs a name-CONSTRAINED cross-signed copy of this root. That copy shares the
/// same Subject CN and public key as the original, so the two can only be told apart by
/// fingerprint. If the user ALSO trusts the original, a Минцифры leaf for any domain would
/// validate directly against it and bypass our constraint — so the app must detect and block.
public struct MintsifryDetector: Sendable {
    let runner: CommandRunner
    let expectedFingerprint: String
    /// Keychains to scan/remove from. Default: user default search list + System.
    let keychains: [String]

    public init(runner: CommandRunner = ProcessCommandRunner(),
                expectedFingerprint: String = MintsifrySource.expectedRootFingerprint ?? "",
                keychains: [String] = ["/Library/Keychains/System.keychain"]) {
        self.runner = runner
        self.expectedFingerprint = expectedFingerprint
        self.keychains = keychains
    }

    /// Scan the trust stores for a "Russian Trusted Root CA" whose SHA-256 equals the
    /// pinned original fingerprint (distinguishing it from our own cross-cert).
    public func detect() throws -> OriginalRootPresence {
        var hashes: [String] = []
        // Scan the default search list (no explicit keychain) plus each explicit keychain.
        var targets: [[String]] = [["find-certificate", "-a", "-c", "Russian Trusted Root CA", "-p"]]
        for kc in keychains {
            targets.append(["find-certificate", "-a", "-c", "Russian Trusted Root CA", "-p", kc])
        }
        for args in targets {
            let res = try? runner.run("/usr/bin/security", args)
            guard let out = res?.stdout, out.contains("BEGIN CERTIFICATE") else { continue }
            let certs = (try? CertFetcher.parsePEMBundle(out)) ?? []
            for cert in certs {
                let fp = (try? CertFetcher.sha256Fingerprint(cert)) ?? ""
                if fp == expectedFingerprint {
                    if let h = try? KeychainInstaller.sha1Hash(cert), !hashes.contains(h) {
                        hashes.append(h)
                    }
                }
            }
        }
        return OriginalRootPresence(isPresent: !hashes.isEmpty, sha1Hashes: hashes)
    }

    /// Remove the detected original root from the keychains (one admin prompt).
    public func remove(_ presence: OriginalRootPresence, privileged: PrivilegedRunner) throws {
        guard !presence.sha1Hashes.isEmpty else { return }
        var lines = ["set -e"]
        for h in presence.sha1Hashes {
            for kc in keychains {
                lines.append("/usr/bin/security delete-certificate -Z \(h) \(kc) || true")
            }
            // Also try the default search list (covers login keychain).
            lines.append("/usr/bin/security delete-certificate -Z \(h) || true")
        }
        try privileged.runScript(lines.joined(separator: "; "))
    }
}
