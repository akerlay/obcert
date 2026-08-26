import Foundation

public enum MintsifrySource {
    /// Official Минцифры PEM distribution points (root + sub CAs).
    public static let urls: [URL] = [
        URL(string: "https://gu-st.ru/content/Other/doc/russian_trusted_root_ca_pem.crt")!,
        URL(string: "https://gu-st.ru/content/Other/doc/russian_trusted_sub_ca_pem.crt")!,
    ]
    /// Known-good SHA-256 fingerprint of the current root, shown to the user for verification.
    /// nil means "show fetched value, no comparison".
    public static let expectedRootFingerprint: String? = nil
}
