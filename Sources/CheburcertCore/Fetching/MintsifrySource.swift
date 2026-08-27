import Foundation

public enum MintsifrySource {
    /// Official Минцифры PEM distribution points (root + sub CAs), served under
    /// gosuslugi's `/content/lending/` path. The older `/content/Other/doc/` paths
    /// now return 404.
    public static let urls: [URL] = [
        URL(string: "https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt")!,
        URL(string: "https://gu-st.ru/content/lending/russian_trusted_sub_ca_pem.crt")!,
        URL(string: "https://gu-st.ru/content/lending/russian_trusted_sub_ca_2024_pem.crt")!,
    ]

    /// Pinned SHA-256 fingerprint (DER) of the official "Russian Trusted Root CA".
    /// The fetcher compares the downloaded root against this and refuses to proceed on
    /// mismatch, so a tampered download cannot be silently trusted. Uppercase hex,
    /// colon-separated — the same format `CertFetcher.sha256Fingerprint` produces.
    public static let expectedRootFingerprint: String? =
        "D2:6D:2D:02:31:B7:C3:9F:92:CC:73:85:12:BA:54:10:35:19:E4:40:5D:68:B5:BD:70:3E:97:88:CA:8E:CF:31"
}
