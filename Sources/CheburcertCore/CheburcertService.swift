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
        let existingKey = try? keyStore.loadKey()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: domains, mintsifryRoot: fetched.root,
            mintsifryIntermediates: fetched.intermediates,
            localKeyOverride: existingKey ?? nil)

        try firefox.install(bundle)   // unprivileged; may throw .firefoxRunning
        try keychain.install(bundle)  // one admin prompt

        try keyStore.save(key: bundle.localRootKey, localRoot: bundle.localRoot)
        try domainStore.save(domains)
    }

    /// Remove from all stores and delete persisted key/cert so status flips to "off".
    /// Keeps the saved domain list by default.
    public func removeAll() throws {
        try? firefox.removeAll()
        try keychain.removeAll()
        // Delete persisted artifacts AppModel.refreshStatus keys "installed" on.
        // Keep the domain list — the user keeps their list.
        try? FileManager.default.removeItem(at: keyStore.keyFile)
        try? FileManager.default.removeItem(at: keyStore.certFile)
    }

    public func savedDomains() -> [String] { (try? domainStore.load()) ?? [] }
}
