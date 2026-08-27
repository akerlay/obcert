import Foundation
import Crypto
import _CryptoExtras
import X509
import SwiftASN1
@testable import CheburcertCore

/// A fake Минцифры-style PKI generated in memory for tests.
struct TestPKI {
    let rootKey: Certificate.PrivateKey
    let root: Certificate            // self-signed "Russian Trusted Root CA" analog (RSA)
    let intermediateKey: Certificate.PrivateKey
    let intermediate: Certificate    // signed by root
    // Anchor the fake PKI's validity window to "now" so it overlaps the crypto
    // engine's default (now-based) validity for the locally-generated certs.
    // Tests validate at `notBefore + 1s`, which must fall inside every window in
    // the chain; a now-relative window guarantees that overlap.
    let notBefore = Date()
    let notAfter = Date().addingTimeInterval(10 * 365 * 24 * 3600)

    init() throws {
        // Root uses RSA to mimic the real Минцифры root (its public key gets reused by the cross-cert).
        let rootRSA = try _RSA.Signing.PrivateKey(keySize: .bits2048) // 2048 keeps tests fast
        rootKey = Certificate.PrivateKey(rootRSA)
        let rootDN = try DistinguishedName {
            CountryName("RU"); OrganizationName("Fake Ministry of Digital Development")
            CommonName("Fake Russian Trusted Root CA")
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

        let interRSA = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        intermediateKey = Certificate.PrivateKey(interRSA)
        let interDN = try DistinguishedName {
            CountryName("RU"); OrganizationName("Fake Ministry of Digital Development")
            CommonName("Fake Russian Trusted Sub CA")
        }
        // Hoist stored-property reads into locals so the result-builder closure
        // does not capture a partially-initialized `self`.
        let interPublicKey = intermediateKey.publicKey
        intermediate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: interPublicKey,
            notValidBefore: notBefore, notValidAfter: notAfter,
            issuer: rootDN, subject: interDN,
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                SubjectKeyIdentifier(hash: interPublicKey)
                AuthorityKeyIdentifier(keyIdentifier: rootSKI.keyIdentifier)
            },
            issuerPrivateKey: rootKey
        )
    }

    /// Issue a leaf certificate for `host` signed by the intermediate.
    func leaf(host: String) throws -> Certificate {
        let leafKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let leafDN = try DistinguishedName { CommonName(host) }
        return try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: leafKey.publicKey,
            notValidBefore: notBefore, notValidAfter: notAfter,
            issuer: intermediate.subject, subject: leafDN,
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                SubjectAlternativeNames([.dnsName(host)])
            },
            issuerPrivateKey: intermediateKey
        )
    }
}
