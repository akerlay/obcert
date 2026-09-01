import Foundation
import X509
import Crypto

/// Stores the local root's certificate — and deliberately not its private key.
///
/// The key signs the constrained root and the cross-certificate once, at build time, and is
/// never needed again: nothing after installation issues anything. Keeping it would leave a
/// CA able to mint a valid certificate for every permitted domain sitting in the user's home
/// directory, readable by any process running as that user, and swept up by backups and
/// cloud sync. For the "all of .ru" preset that is every bank in the country.
///
/// So the key is not persisted at all — no write, no window, nothing to shred. `destroyKey`
/// exists to clear keys written by earlier versions.
public struct KeyStore: Sendable {
    public let keyFile: URL
    public let certFile: URL

    public init(keyFile: URL = AppPaths.keyFile, certFile: URL = AppPaths.localRootFile) {
        self.keyFile = keyFile; self.certFile = certFile
    }

    /// Persist the root certificate. The status screen keys "installed" on this file.
    public func save(localRoot: Certificate) throws {
        try FileManager.default.createDirectory(
            at: certFile.deletingLastPathComponent(), withIntermediateDirectories: true)
        try localRoot.serializeAsPEM().pemString.write(to: certFile, atomically: true, encoding: .utf8)
    }

    /// Remove a private key left behind by an earlier version. Returns true if one was there.
    @discardableResult
    public func destroyKey() -> Bool {
        guard FileManager.default.fileExists(atPath: keyFile.path) else { return false }
        try? FileManager.default.removeItem(at: keyFile)
        return true
    }
}
