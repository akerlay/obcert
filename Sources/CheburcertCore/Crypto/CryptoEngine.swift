import Foundation
import Crypto
import X509
import SwiftASN1

public enum CryptoEngine {
    /// Build the constrained trust bundle for a domain list.
    public static func buildTrustBundle(
        domains: [String],
        mintsifryRoot: Certificate,
        mintsifryIntermediates: [Certificate],
        validity: DateInterval = defaultValidity(),
        localKeyOverride: Certificate.PrivateKey? = nil
    ) throws -> TrustBundle {
        guard !domains.isEmpty else { throw CheburcertError.cryptoFailure("empty domain list") }

        let nameConstraints = try makeNameConstraints(domains: domains)

        // 1. Local constrained root CA (ECDSA P384).
        let localKey = localKeyOverride ?? Certificate.PrivateKey(P384.Signing.PrivateKey())
        let localDN = try DistinguishedName {
            CommonName("obcert Local Constrained Root")
            OrganizationName("obcert")
        }
        let localSKI = SubjectKeyIdentifier(hash: localKey.publicKey)
        let localRoot = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: localKey.publicKey,
            notValidBefore: validity.start, notValidAfter: validity.end,
            issuer: localDN, subject: localDN,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 5))
                Critical(KeyUsage(digitalSignature: true, keyCertSign: true, cRLSign: true))
                localSKI
                nameConstraints   // already a critical Certificate.Extension
            },
            issuerPrivateKey: localKey
        )

        // 2. Cross-signed Минцифры root: same subject/pubkey/SKI/serial, signed by localRoot.
        let rootSKI = try copiedOrComputedSKI(from: mintsifryRoot)
        let crossCert = try Certificate(
            version: .v3,
            serialNumber: mintsifryRoot.serialNumber,
            publicKey: mintsifryRoot.publicKey,
            notValidBefore: validity.start, notValidAfter: validity.end,
            issuer: localDN, subject: mintsifryRoot.subject,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 5))
                Critical(KeyUsage(digitalSignature: true, keyCertSign: true, cRLSign: true))
                SubjectKeyIdentifier(keyIdentifier: rootSKI)
                AuthorityKeyIdentifier(keyIdentifier: localSKI.keyIdentifier)
                nameConstraints   // already a critical Certificate.Extension
            },
            issuerPrivateKey: localKey
        )

        return TrustBundle(
            localRoot: localRoot, localRootKey: localKey,
            crossCert: crossCert, intermediates: mintsifryIntermediates,
            domains: domains)
    }

    static func makeNameConstraints(domains: [String]) throws -> Certificate.Extension {
        let ipv4Any = ASN1OctetString(contentBytes: ArraySlice([UInt8](repeating: 0, count: 8)))
        let ipv6Any = ASN1OctetString(contentBytes: ArraySlice([UInt8](repeating: 0, count: 32)))
        let nc = NameConstraints(
            permittedDNSDomains: domains,
            excludedIPRanges: [ipv4Any, ipv6Any])
        return try Certificate.Extension(nc, critical: true)
    }

    /// Reuse the root's own SKI bytes if it publishes one; otherwise compute the standard hash.
    static func copiedOrComputedSKI(from root: Certificate) throws -> ArraySlice<UInt8> {
        if let ext = try root.extensions.subjectKeyIdentifier {
            return ext.keyIdentifier
        }
        return SubjectKeyIdentifier(hash: root.publicKey).keyIdentifier
    }

    public static func defaultValidity() -> DateInterval {
        // Backdate the start by a day to tolerate client clock skew (standard CA
        // practice) so freshly-issued anchors validate immediately.
        let start = Date().addingTimeInterval(-24 * 3600)
        return DateInterval(start: start, end: start.addingTimeInterval(10 * 365 * 24 * 3600))
    }
}
