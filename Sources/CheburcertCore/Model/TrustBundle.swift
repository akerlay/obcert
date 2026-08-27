import Foundation
import X509

/// The full set of artifacts the crypto engine produces for one domain list.
public struct TrustBundle: Sendable {
    /// Locally-generated constrained root CA (trusted anchor).
    public let localRoot: Certificate
    /// Private key of `localRoot` (needed for idempotent re-install and removal).
    public let localRootKey: Certificate.PrivateKey
    /// Минцифры root re-signed by `localRoot`, preserving its public key/subject/SKI/serial.
    public let crossCert: Certificate
    /// Минцифры intermediates, installed untrusted so chains build offline.
    public let intermediates: [Certificate]
    /// The normalized domain list baked into the name constraints.
    public let domains: [String]
}
