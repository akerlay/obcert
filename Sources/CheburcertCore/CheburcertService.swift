import Foundation
import X509

/// Top-level orchestration the app calls. Dependencies are injected for testing.
public struct CheburcertService: Sendable {
    public typealias Fetch = @Sendable () async throws -> FetchedCerts

    let fetch: Fetch
    let keychain: TrustStoreInstaller
    let firefox: TrustStoreInstaller
    let domainStore: DomainStore
    let keyStore: KeyStore

    public init(fetch: @escaping Fetch, keychain: TrustStoreInstaller, firefox: TrustStoreInstaller,
                domainStore: DomainStore = DomainStore(), keyStore: KeyStore = KeyStore()) {
        self.fetch = fetch; self.keychain = keychain; self.firefox = firefox
        self.domainStore = domainStore; self.keyStore = keyStore
    }

    /// Normalize domains, build the bundle, install into Firefox (no prompt) then Keychain (one prompt), persist.
    public func apply(domains rawDomains: [String]) async throws {
        let domains = try DomainList.normalizedUnique(rawDomains)
        guard !domains.isEmpty else { throw CheburcertError.invalidDomain("(empty list)") }

        let fetched = try await fetch()
        // A fresh CA key every time. Reusing one bought nothing — the certificate changes
        // whenever the domain list does, so the trust dialog appears either way — and it
        // required keeping the key on disk, which is exactly what we refuse to do.
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: domains, mintsifryRoot: fetched.root,
            mintsifryIntermediates: fetched.intermediates)

        try firefox.install(bundle)   // unprivileged; may throw .firefoxRunning
        try keychain.install(bundle)  // one admin prompt

        try keyStore.save(localRoot: bundle.localRoot)
        try domainStore.save(domains)
        // The key has done its only job. Drop it here, and clear any left by older versions.
        keyStore.destroyKey()
    }

    /// Build the trust bundle for the given domains WITHOUT installing anything
    /// (used by phone export). Generates a throwaway CA key that is never persisted, so the
    /// exported profile gets its own anchor, independent of the one installed on this Mac.
    public func buildBundleForExport(domains rawDomains: [String]) async throws -> TrustBundle {
        let domains = try DomainList.normalizedUnique(rawDomains)
        guard !domains.isEmpty else { throw CheburcertError.invalidDomain("(empty list)") }
        let fetched = try await fetch()
        // The exported profile carries certificates only, so this key can be dropped the
        // moment the bundle is built — it is never written anywhere.
        return try CryptoEngine.buildTrustBundle(
            domains: domains, mintsifryRoot: fetched.root,
            mintsifryIntermediates: fetched.intermediates)
    }

    /// Remove from all stores and delete persisted key/cert so status flips to "off".
    /// Keeps the saved domain list by default.
    public func removeAll() throws {
        try? firefox.removeAll()
        try keychain.removeAll()
        // Delete persisted artifacts AppModel.refreshStatus keys "installed" on.
        // Keep the domain list — the user keeps their list.
        keyStore.destroyKey()
        try? FileManager.default.removeItem(at: keyStore.certFile)
    }

    public func savedDomains() -> [String] { (try? domainStore.load()) ?? [] }
}
