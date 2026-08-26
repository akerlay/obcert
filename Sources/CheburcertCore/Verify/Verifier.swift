import Foundation
import X509

/// Offline validation that a built chain honors the name constraints.
public enum ChainSelfCheck {
    public static func validates(
        leaf: Certificate, intermediates: [Certificate],
        localRoot: Certificate, at time: Date
    ) async -> Bool {
        var roots = CertificateStore(); roots.append(localRoot)
        var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: time) }
        let result = await verifier.validate(
            leafCertificate: leaf, intermediates: CertificateStore(intermediates))
        if case .validCertificate = result { return true }
        return false
    }
}
