import Foundation
import X509
import Crypto

public struct KeyStore: Sendable {
    public let keyFile: URL
    public let certFile: URL
    public init(keyFile: URL = AppPaths.keyFile, certFile: URL = AppPaths.localRootFile) {
        self.keyFile = keyFile; self.certFile = certFile
    }

    public func save(key: Certificate.PrivateKey, localRoot: Certificate) throws {
        try FileManager.default.createDirectory(
            at: keyFile.deletingLastPathComponent(), withIntermediateDirectories: true)
        try key.serializeAsPEM().pemString.write(to: keyFile, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyFile.path)
        try localRoot.serializeAsPEM().pemString.write(to: certFile, atomically: true, encoding: .utf8)
    }

    public func loadKey() throws -> Certificate.PrivateKey? {
        guard let pem = try? String(contentsOf: keyFile, encoding: .utf8) else { return nil }
        return try Certificate.PrivateKey(pemEncoded: pem)
    }
}
