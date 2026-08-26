import Foundation

public protocol TrustStoreInstaller {
    /// Install the bundle; idempotent (safe to call repeatedly).
    func install(_ bundle: TrustBundle) throws
    /// Remove everything Cheburcert installed.
    func removeAll() throws
}
