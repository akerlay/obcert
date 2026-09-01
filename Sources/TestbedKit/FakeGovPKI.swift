import Foundation
import Crypto
import _CryptoExtras
import X509
import SwiftASN1

/// A leaf certificate together with the private key needed to serve TLS with it.
public struct IssuedLeaf: Sendable {
    public let certificate: Certificate
    public let privateKey: Certificate.PrivateKey

    public init(certificate: Certificate, privateKey: Certificate.PrivateKey) {
        self.certificate = certificate
        self.privateKey = privateKey
    }
}

/// A stand-in for the Минцифры PKI, generated locally with keys we keep.
///
/// The real Минцифры private key is unobtainable, so a MITM against the constrained root
/// cannot be staged with genuine certificates. Holding the fake root's key instead lets us
/// issue a leaf for any name — exactly the capability the constraint is supposed to bound —
/// and observe whether each verifier honours `nameConstraints`.
///
/// The root uses RSA to mimic the real one, whose public key the cross-certificate reuses.
public struct FakeGovPKI: Sendable {
    public let rootKey: Certificate.PrivateKey
    public let root: Certificate
    public let subCAKey: Certificate.PrivateKey
    public let subCA: Certificate
    /// Validity is anchored to "now" so it overlaps `CryptoEngine`'s now-relative window;
    /// callers validate at `notBefore + 1s`, which must fall inside every window in the chain.
    public let notBefore: Date
    public let notAfter: Date

    /// - Parameter label: appended to the CA common names. The trust settings screen shows
    ///   nothing but the CN, so without a per-run marker there is no way to tell which
    ///   generation of a regenerated testbed is actually installed on the phone.
    public init(rootKeySize: _RSA.Signing.KeySize = .bits2048, label: String? = nil) throws {
        let mark = label.map { " (\($0))" } ?? ""
        let now = Date()
        notBefore = now
        notAfter = now.addingTimeInterval(10 * 365 * 24 * 3600)

        let rootRSA = try _RSA.Signing.PrivateKey(keySize: rootKeySize)
        rootKey = Certificate.PrivateKey(rootRSA)
        let rootDN = try DistinguishedName {
            CountryName("RU")
            OrganizationName("Fake Ministry of Digital Development")
            CommonName("Fake Russian Trusted Root CA" + mark)
        }
        let rootSKI = SubjectKeyIdentifier(hash: rootKey.publicKey)
        root = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: rootKey.publicKey,
            notValidBefore: notBefore, notValidAfter: notAfter,
            issuer: rootDN, subject: rootDN,
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 2))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                rootSKI
            },
            issuerPrivateKey: rootKey
        )

        let subRSA = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        subCAKey = Certificate.PrivateKey(subRSA)
        let subDN = try DistinguishedName {
            CountryName("RU")
            OrganizationName("Fake Ministry of Digital Development")
            CommonName("Fake Russian Trusted Sub CA" + mark)
        }
        // Hoist stored-property reads into locals so the result-builder closure does not
        // capture a partially-initialized `self`.
        let subPublicKey = subCAKey.publicKey
        subCA = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: subPublicKey,
            notValidBefore: notBefore, notValidAfter: notAfter,
            issuer: rootDN, subject: subDN,
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                SubjectKeyIdentifier(hash: subPublicKey)
                AuthorityKeyIdentifier(keyIdentifier: rootSKI.keyIdentifier)
            },
            issuerPrivateKey: rootKey
        )
    }

    /// Issue a leaf whose only SAN is `dnsName`.
    public func leaf(dnsName: String) throws -> IssuedLeaf {
        try issue(commonName: dnsName, sans: [.dnsName(dnsName)])
    }

    /// Issue a leaf whose only SAN is an IPv4 address, to exercise `excludedIPRanges`.
    public func leaf(ipv4: String) throws -> IssuedLeaf {
        let octets = try Self.ipv4Octets(ipv4)
        return try issue(
            commonName: ipv4,
            sans: [.ipAddress(ASN1OctetString(contentBytes: ArraySlice(octets)))])
    }

    /// Apple's trust evaluation caps TLS leaf lifetime and requires an explicit serverAuth
    /// EKU. A leaf missing either is rejected for that reason alone, which would mask the
    /// name-constraint verdict the testbed exists to measure — so leaves look like real
    /// server certificates.
    static let leafLifetime: TimeInterval = 390 * 24 * 3600

    private func issue(commonName: String, sans: [GeneralName]) throws -> IssuedLeaf {
        let leafKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let leafDN = try DistinguishedName { CommonName(commonName) }
        let cert = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: leafKey.publicKey,
            notValidBefore: notBefore,
            notValidAfter: notBefore.addingTimeInterval(Self.leafLifetime),
            issuer: subCA.subject, subject: leafDN,
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                KeyUsage(digitalSignature: true, keyEncipherment: true)
                try ExtendedKeyUsage([.serverAuth])
                SubjectAlternativeNames(sans)
            },
            issuerPrivateKey: subCAKey
        )
        return IssuedLeaf(certificate: cert, privateKey: leafKey)
    }

    static func ipv4Octets(_ text: String) throws -> [UInt8] {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { throw FakeGovPKIError.invalidIPv4(text) }
        return try parts.map {
            guard let byte = UInt8($0) else { throw FakeGovPKIError.invalidIPv4(text) }
            return byte
        }
    }
}

public enum FakeGovPKIError: Error, Equatable {
    case invalidIPv4(String)
}
