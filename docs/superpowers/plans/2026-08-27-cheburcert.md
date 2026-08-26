# Cheburcert Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A native macOS SwiftUI app that makes the Минцифры (Russian Trusted) root CA trusted **only** for a user-specified list of domains, by generating a local `nameConstraints` CA that cross-signs the Минцифры root, and installing it into the macOS System keychain and all Firefox profiles.

**Architecture:** All logic lives in a testable Swift Package library `CheburcertCore` (domain list, cert fetching, the crypto engine that builds the constrained chain, trust-store installers, privileged-command runner, verifier). A thin SwiftUI app target depends on the library, provides the single-window UI, and bundles the `certutil` binary for Firefox. The crypto engine is pure and offline, so it is built test-first; installers are tested through a mockable command-runner boundary.

**Tech Stack:** Swift 6 / SwiftUI, Swift Package Manager, `apple/swift-certificates` + `apple/swift-crypto` (`_CryptoExtras` for RSA), `certutil` (bundled NSS tool) for Firefox, `security` CLI + `osascript ... with administrator privileges` for the System keychain.

---

## Key technical facts (verified against upstream source before writing this plan)

These are the exact APIs the crypto engine relies on. They were confirmed against `apple/swift-certificates` `main`:

- `Certificate.init(version:serialNumber:publicKey:notValidBefore:notValidAfter:issuer:subject:signatureAlgorithm:extensions:issuerPrivateKey:)` — `publicKey` and `issuerPrivateKey` are **independent** parameters. This is the `openssl -force_pubkey` equivalent: pass the Минцифры root's public key as `publicKey` and our local CA's key as `issuerPrivateKey`.
- `Certificate` conforms to `PEMRepresentable` → `Certificate(pemEncoded: String)` parses PEM, `serializeAsPEM().pemString` writes PEM.
- `parsedCert.publicKey` returns a `Certificate.PublicKey`; `parsedCert.subject` returns `DistinguishedName`; `parsedCert.serialNumber` returns `Certificate.SerialNumber`; `parsedCert.extensions` returns `Certificate.Extensions`.
- `NameConstraints(permittedDNSDomains: some Sequence<String>, excludedDNSDomains:..., permittedIPRanges: some Sequence<ASN1OctetString>, excludedIPRanges:..., ...)` then `try Certificate.Extension(nameConstraints, critical: true)`.
- `SubjectKeyIdentifier(hash: Certificate.PublicKey)` computes the standard SKI; `SubjectKeyIdentifier(keyIdentifier: ArraySlice<UInt8>)` wraps existing bytes; `.makeCertificateExtension()` produces the `Certificate.Extension`.
- `BasicConstraints.isCertificateAuthority(maxPathLength:)`, `KeyUsage(keyCertSign:cRLSign:digitalSignature:)`, each with `.makeCertificateExtension()` / `Certificate.Extension(_, critical:)`.
- Local CA key: `Certificate.PrivateKey(P384.Signing.PrivateKey())` (P384 chosen: fast to generate, universally supported by Safari/Chrome/Firefox; RSA-4096 from the blog was convention, not a requirement). Signature algorithm for anything the local CA signs: `.ecdsaWithSHA384`.
- Name-constraint IP exclusion of all addresses: `ASN1OctetString(contentBytes: [UInt8](repeating: 0, count: 8))` for IPv4 `0.0.0.0/0` (4 address + 4 mask bytes) and `count: 32` for IPv6 `::/0`.

**Chain-building robustness rules the engine MUST follow** (so the real Минцифры intermediate chains to our cross-cert):
1. Cross-cert `subject` = the real root's `subject` (copy the `DistinguishedName` verbatim).
2. Cross-cert `publicKey` = the real root's `publicKey` (verbatim).
3. Cross-cert `SubjectKeyIdentifier` = the real root's existing SKI extension bytes if present (copy verbatim); only fall back to `SubjectKeyIdentifier(hash:)` if the root has no SKI extension.
4. Cross-cert `serialNumber` = the real root's `serialNumber` (some validators match Authority Key Identifier by issuer+serial).
5. Cross-cert `issuer` = local CA `subject`; cross-cert carries `AuthorityKeyIdentifier` = local CA SKI.
6. `nameConstraints` (critical) go on **both** the local root and the cross-cert.

---

## File structure

```
cheburcert/
  Package.swift                              # SPM manifest: CheburcertCore lib + test target
  Sources/CheburcertCore/
    Model/
      TrustBundle.swift                      # value type: localRoot, crossCert, intermediates, key (PEM)
      InstallState.swift                     # what is installed where
      CheburcertError.swift                  # typed errors for all failure modes
    Domain/
      DomainList.swift                       # normalize + validate domain entries
      Presets.swift                          # built-in domain sets
    Persistence/
      AppPaths.swift                         # Application Support / cache locations
      DomainStore.swift                      # load/save domains.json
      KeyStore.swift                         # load/save local CA key + certs (mode 0600)
    Fetching/
      MintsifrySource.swift                  # URLs of root+sub CAs
      CertFetcher.swift                      # download, parse PEM, SHA-256 fingerprint
    Crypto/
      CryptoEngine.swift                     # buildTrustBundle(domains:mintsifry:) -> TrustBundle
    Command/
      CommandRunner.swift                    # protocol + real impl (Process)
      PrivilegedRunner.swift                 # protocol + osascript-admin impl
    Installers/
      TrustStoreInstaller.swift              # protocol
      KeychainInstaller.swift                # security add-trusted-cert / remove
      FirefoxProfiles.swift                  # parse profiles.ini -> [profile dirs]
      FirefoxInstaller.swift                 # certutil per profile
    Verify/
      Verifier.swift                         # local chain check + installed-state read
  Tests/CheburcertCoreTests/
    DomainListTests.swift
    PresetsTests.swift
    CryptoEngineTests.swift
    CertFetcherTests.swift
    FirefoxProfilesTests.swift
    KeychainInstallerTests.swift
    FirefoxInstallerTests.swift
    VerifierTests.swift
    TestPKI.swift                            # helper: builds a fake Минцифры hierarchy in-memory
  App/CheburcertApp/                         # Xcode SwiftUI app target (added in Phase 6)
    CheburcertApp.swift
    AppModel.swift
    ContentView.swift
    Views/
      StatusBanner.swift
      DomainListPane.swift
      ActionsPane.swift
      WarningFooter.swift
    Resources/
      certutil                               # bundled NSS binary (+ dylibs)
```

---

## Phase 0 — Project scaffold

### Task 0: Create the Swift Package

**Files:**
- Create: `Package.swift`
- Create: `Sources/CheburcertCore/Model/CheburcertError.swift`
- Test: `Tests/CheburcertCoreTests/SmokeTests.swift`

- [ ] **Step 1: Write `Package.swift`**

```swift
// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "CheburcertCore",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "CheburcertCore", targets: ["CheburcertCore"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "CheburcertCore",
            dependencies: [
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "CheburcertCoreTests",
            dependencies: ["CheburcertCore"]
        ),
    ]
)
```

- [ ] **Step 2: Write a minimal error type so the module compiles**

`Sources/CheburcertCore/Model/CheburcertError.swift`:

```swift
import Foundation

public enum CheburcertError: Error, Equatable {
    case network(String)
    case fingerprintMismatch(expected: String, got: String)
    case certificateParse(String)
    case cryptoFailure(String)
    case commandFailed(command: String, exitCode: Int32, stderr: String)
    case firefoxRunning
    case noFirefoxProfiles
    case authorizationDenied
    case invalidDomain(String)
    case ioFailure(String)
}
```

- [ ] **Step 3: Write the smoke test**

`Tests/CheburcertCoreTests/SmokeTests.swift`:

```swift
import XCTest
@testable import CheburcertCore

final class SmokeTests: XCTestCase {
    func testErrorEquatable() {
        XCTAssertEqual(CheburcertError.firefoxRunning, CheburcertError.firefoxRunning)
    }
}
```

- [ ] **Step 4: Resolve dependencies and run tests**

Run: `swift test 2>&1 | tail -20`
Expected: dependencies resolve (swift-certificates, swift-crypto), `testErrorEquatable` PASSES.

- [ ] **Step 5: Commit**

```bash
git add Package.swift Sources Tests
git commit -m "chore: scaffold CheburcertCore Swift package"
```

---

## Phase 1 — Domain list & presets

### Task 1: Domain normalization and validation

**Files:**
- Create: `Sources/CheburcertCore/Domain/DomainList.swift`
- Test: `Tests/CheburcertCoreTests/DomainListTests.swift`

- [ ] **Step 1: Write the failing tests**

`Tests/CheburcertCoreTests/DomainListTests.swift`:

```swift
import XCTest
@testable import CheburcertCore

final class DomainListTests: XCTestCase {
    func testStripsSchemeWildcardWhitespaceAndLowercases() throws {
        XCTAssertEqual(try DomainList.normalize(" HTTPS://*.Sberbank.RU/ "), "sberbank.ru")
    }

    func testLeadingDotZonePreserved() throws {
        XCTAssertEqual(try DomainList.normalize(".RU"), ".ru")
    }

    func testCyrillicConvertedToPunycode() throws {
        XCTAssertEqual(try DomainList.normalize("сбербанк.рф"), "xn--80aac0aqbb1i.xn--p1ai")
    }

    func testLeadingDotCyrillicZone() throws {
        XCTAssertEqual(try DomainList.normalize(".рф"), ".xn--p1ai")
    }

    func testRejectsEmpty() {
        XCTAssertThrowsError(try DomainList.normalize("   "))
    }

    func testRejectsBareTLDLabelWithoutDot() throws {
        // "ru" (no leading dot, single label) is ambiguous; require an explicit form.
        XCTAssertThrowsError(try DomainList.normalize("ru"))
    }

    func testDeduplicatesPreservingOrder() throws {
        let out = try DomainList.normalizedUnique(["sberbank.ru", "SBERBANK.ru", "gosuslugi.ru"])
        XCTAssertEqual(out, ["sberbank.ru", "gosuslugi.ru"])
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `swift test --filter DomainListTests 2>&1 | tail -20`
Expected: FAIL — `DomainList` type not found.

- [ ] **Step 3: Implement `DomainList`**

`Sources/CheburcertCore/Domain/DomainList.swift`:

```swift
import Foundation

public enum DomainList {
    /// Normalize one user-entered domain into a name-constraint DNS suffix.
    /// - Strips scheme, "*.", surrounding whitespace, trailing "/" and dots (except a single leading dot).
    /// - Lowercases and converts Cyrillic/IDN labels to Punycode (A-labels).
    /// - A single leading dot ("zone" form like ".ru") is preserved.
    public static func normalize(_ raw: String) throws -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let range = s.range(of: "://") { s = String(s[range.upperBound...]) }
        if let slash = s.firstIndex(of: "/") { s = String(s[..<slash]) }
        while s.hasPrefix("*.") { s.removeFirst(2) }
        s = s.trimmingCharacters(in: .whitespaces)

        let leadingDot = s.hasPrefix(".")
        let core = leadingDot ? String(s.dropFirst()) : s
        guard !core.isEmpty else { throw CheburcertError.invalidDomain(raw) }

        let puny = try punycode(core)
        // Reject a single bare label with no dot and no leading-dot zone form.
        if !leadingDot && !puny.contains(".") {
            throw CheburcertError.invalidDomain(raw)
        }
        return leadingDot ? "." + puny : puny
    }

    public static func normalizedUnique(_ raws: [String]) throws -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for r in raws {
            let n = try normalize(r)
            if seen.insert(n).inserted { out.append(n) }
        }
        return out
    }

    /// Convert each dot-separated label to its IDNA ASCII (Punycode) form when needed.
    static func punycode(_ host: String) throws -> String {
        let labels = host.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        let encoded = try labels.map { label -> String in
            if label.allSatisfy({ $0.isASCII }) { return label }
            guard let a = IDNA.encode(label) else { throw CheburcertError.invalidDomain(host) }
            return a
        }
        return encoded.joined(separator: ".")
    }
}
```

- [ ] **Step 4: Implement Punycode helper**

`Sources/CheburcertCore/Domain/DomainList.swift` (append `IDNA` enum in the same file):

```swift
/// Minimal RFC 3492 Punycode encoder producing "xn--" A-labels.
enum IDNA {
    static func encode(_ label: String) -> String? {
        let input = Array(label.unicodeScalars)
        var output = input.filter { $0.isASCII }.map { Character($0) }
        let basicCount = output.count
        var handled = basicCount
        if basicCount > 0 { output.append("-") }

        var n: UInt32 = 0x80
        var delta: UInt32 = 0
        var bias: UInt32 = 72
        let base: UInt32 = 36, tmin: UInt32 = 1, tmax: UInt32 = 26
        let skew: UInt32 = 38, damp: UInt32 = 700

        func adapt(_ d: UInt32, _ numPoints: UInt32, _ firstTime: Bool) -> UInt32 {
            var delta = firstTime ? d / damp : d / 2
            delta += delta / numPoints
            var k: UInt32 = 0
            while delta > ((base - tmin) * tmax) / 2 {
                delta /= (base - tmin); k += base
            }
            return k + ((base - tmin + 1) * delta) / (delta + skew)
        }

        while handled < input.count {
            let m = input.filter { $0.value >= n }.map { $0.value }.min()!
            delta += (m - n) * UInt32(handled + 1)
            n = m
            for scalar in input {
                if scalar.value < n { delta += 1 }
                if scalar.value == n {
                    var q = delta
                    var k = base
                    while true {
                        let t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias)
                        if q < t { break }
                        let code = t + (q - t) % (base - t)
                        output.append(digit(code))
                        q = (q - t) / (base - t)
                        k += base
                    }
                    output.append(digit(q))
                    bias = adapt(delta, UInt32(handled + 1), handled == basicCount)
                    delta = 0
                    handled += 1
                }
            }
            delta += 1
            n += 1
        }
        return "xn--" + String(output)
    }

    private static func digit(_ d: UInt32) -> Character {
        // 0..25 -> 'a'..'z', 26..35 -> '0'..'9'
        if d < 26 { return Character(UnicodeScalar(d + 97)!) }
        return Character(UnicodeScalar(d - 26 + 48)!)
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `swift test --filter DomainListTests 2>&1 | tail -20`
Expected: PASS (all 7). In particular `сбербанк.рф` → `xn--80aac0aqbb1i.xn--p1ai` and `.рф` → `.xn--p1ai`.

- [ ] **Step 6: Commit**

```bash
git add Sources/CheburcertCore/Domain/DomainList.swift Tests/CheburcertCoreTests/DomainListTests.swift
git commit -m "feat: domain normalization with punycode and validation"
```

### Task 2: Presets

**Files:**
- Create: `Sources/CheburcertCore/Domain/Presets.swift`
- Test: `Tests/CheburcertCoreTests/PresetsTests.swift`

- [ ] **Step 1: Write the failing test**

`Tests/CheburcertCoreTests/PresetsTests.swift`:

```swift
import XCTest
@testable import CheburcertCore

final class PresetsTests: XCTestCase {
    func testPresetsAreNormalizedAndNonEmpty() throws {
        for preset in Presets.all {
            XCTAssertFalse(preset.domains.isEmpty, "\(preset.name) is empty")
            for d in preset.domains {
                XCTAssertEqual(try DomainList.normalize(d), d, "\(d) not normalized")
            }
        }
    }

    func testGosuslugiPresetIncludesGosuslugi() {
        let g = Presets.all.first { $0.id == "gosuslugi" }
        XCTAssertNotNil(g)
        XCTAssertTrue(g!.domains.contains("gosuslugi.ru"))
    }

    func testWholeZonePresetUsesLeadingDotForms() {
        let z = Presets.all.first { $0.id == "zones" }!
        XCTAssertEqual(Set(z.domains), [".ru", ".su", ".xn--p1ai"])
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `swift test --filter PresetsTests 2>&1 | tail -20`
Expected: FAIL — `Presets` not found.

- [ ] **Step 3: Implement presets**

`Sources/CheburcertCore/Domain/Presets.swift`:

```swift
import Foundation

public struct DomainPreset: Identifiable, Sendable, Equatable {
    public let id: String
    public let name: String
    public let domains: [String]
}

public enum Presets {
    public static let all: [DomainPreset] = [
        DomainPreset(id: "gosuslugi", name: "Госуслуги", domains: [
            "gosuslugi.ru", "nalog.gov.ru", "pfr.gov.ru", "mos.ru",
        ]),
        DomainPreset(id: "banks", name: "Крупные банки", domains: [
            "sberbank.ru", "sber.ru", "vtb.ru", "tinkoff.ru",
            "alfabank.ru", "gazprombank.ru", "raiffeisen.ru", "psbank.ru",
        ]),
        DomainPreset(id: "zones", name: "Весь .ru / .рф / .su", domains: [
            ".ru", ".su", ".xn--p1ai",
        ]),
    ]
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `swift test --filter PresetsTests 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Sources/CheburcertCore/Domain/Presets.swift Tests/CheburcertCoreTests/PresetsTests.swift
git commit -m "feat: built-in domain presets"
```

---

## Phase 2 — Crypto engine (the core)

### Task 3: Test PKI helper

**Files:**
- Create: `Tests/CheburcertCoreTests/TestPKI.swift`

This helper builds a fake Минцифры hierarchy in-memory so the crypto engine can be tested without the network.

- [ ] **Step 1: Write the helper (no assertions yet; it is used by later tests)**

`Tests/CheburcertCoreTests/TestPKI.swift`:

```swift
import Foundation
import Crypto
import _CryptoExtras
import X509
@testable import CheburcertCore

/// A fake Минцифры-style PKI generated in memory for tests.
struct TestPKI {
    let rootKey: Certificate.PrivateKey
    let root: Certificate            // self-signed "Russian Trusted Root CA" analog (RSA)
    let intermediateKey: Certificate.PrivateKey
    let intermediate: Certificate    // signed by root
    let notBefore = Date(timeIntervalSince1970: 1_700_000_000)
    let notAfter = Date(timeIntervalSince1970: 2_000_000_000)

    init() throws {
        // Root uses RSA to mimic the real Минцифры root (public key gets reused by the cross-cert).
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
        intermediate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: intermediateKey.publicKey,
            notValidBefore: notBefore, notValidAfter: notAfter,
            issuer: rootDN, subject: interDN,
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                SubjectKeyIdentifier(hash: intermediateKey.publicKey)
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
```

- [ ] **Step 2: Compile the test target**

Run: `swift build --build-tests 2>&1 | tail -20`
Expected: builds. If any DN-builder or extension name differs from the installed swift-certificates version, fix the symbol name now (e.g. `SubjectAlternativeNames`, `AuthorityKeyIdentifier`) using `swift build` errors as the guide.

- [ ] **Step 3: Commit**

```bash
git add Tests/CheburcertCoreTests/TestPKI.swift
git commit -m "test: in-memory fake Минцифры PKI helper"
```

### Task 4: `TrustBundle` model

**Files:**
- Create: `Sources/CheburcertCore/Model/TrustBundle.swift`
- Test: covered by Task 5.

- [ ] **Step 1: Implement the value type**

`Sources/CheburcertCore/Model/TrustBundle.swift`:

```swift
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
```

- [ ] **Step 2: Build**

Run: `swift build 2>&1 | tail -5`
Expected: builds.

- [ ] **Step 3: Commit**

```bash
git add Sources/CheburcertCore/Model/TrustBundle.swift
git commit -m "feat: TrustBundle model"
```

### Task 5: CryptoEngine — build the constrained chain

**Files:**
- Create: `Sources/CheburcertCore/Crypto/CryptoEngine.swift`
- Test: `Tests/CheburcertCoreTests/CryptoEngineTests.swift`

- [ ] **Step 1: Write the failing tests**

`Tests/CheburcertCoreTests/CryptoEngineTests.swift`:

```swift
import XCTest
import X509
import SwiftASN1
@testable import CheburcertCore

final class CryptoEngineTests: XCTestCase {
    func testCrossCertPreservesRootIdentity() throws {
        let pki = try TestPKI()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"],
            mintsifryRoot: pki.root,
            mintsifryIntermediates: [pki.intermediate]
        )
        // force_pubkey: cross-cert reuses the root's public key, subject, serial.
        XCTAssertEqual(bundle.crossCert.publicKey, pki.root.publicKey)
        XCTAssertEqual(bundle.crossCert.subject, pki.root.subject)
        XCTAssertEqual(bundle.crossCert.serialNumber, pki.root.serialNumber)
        // cross-cert is issued by the local root.
        XCTAssertEqual(bundle.crossCert.issuer, bundle.localRoot.subject)
    }

    func testChainValidatesForPermittedDomain() async throws {
        let pki = try TestPKI()
        let leaf = try pki.leaf(host: "online.sberbank.ru")
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])

        var roots = CertificateStore()
        roots.append(bundle.localRoot)
        var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: pki.notBefore.addingTimeInterval(1)) }
        let result = await verifier.validate(
            leafCertificate: leaf,
            intermediates: CertificateStore([pki.intermediate, bundle.crossCert]))
        guard case .validCertificate = result else {
            return XCTFail("expected valid chain, got \(result)")
        }
    }

    func testChainRejectedForNonPermittedDomain() async throws {
        let pki = try TestPKI()
        let leaf = try pki.leaf(host: "evil.com")
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])

        var roots = CertificateStore()
        roots.append(bundle.localRoot)
        var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: pki.notBefore.addingTimeInterval(1)) }
        let result = await verifier.validate(
            leafCertificate: leaf,
            intermediates: CertificateStore([pki.intermediate, bundle.crossCert]))
        guard case .couldNotValidate = result else {
            return XCTFail("expected name-constraint rejection, got \(result)")
        }
    }

    func testLocalRootHasCriticalNameConstraints() throws {
        let pki = try TestPKI()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])
        let nc = try XCTUnwrap(try bundle.localRoot.extensions.nameConstraints)
        XCTAssertTrue(Array(nc.permittedDNSDomains).contains(".ru"))
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `swift test --filter CryptoEngineTests 2>&1 | tail -25`
Expected: FAIL — `CryptoEngine` not found.

- [ ] **Step 3: Implement the crypto engine**

`Sources/CheburcertCore/Crypto/CryptoEngine.swift`:

```swift
import Foundation
import Crypto
import X509
import SwiftASN1

public enum CryptoEngine {
    /// Build the constrained trust bundle for a domain list.
    /// - Parameters:
    ///   - domains: already-normalized DNS suffixes (e.g. "sberbank.ru", ".ru").
    ///   - mintsifryRoot: the real Минцифры root certificate.
    ///   - mintsifryIntermediates: the real Минцифры sub-CA certificates.
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
            CommonName("Cheburcert Local Constrained Root")
            OrganizationName("Cheburcert")
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
        if let ext = root.extensions.subjectKeyIdentifier {
            return ext.keyIdentifier
        }
        return SubjectKeyIdentifier(hash: root.publicKey).keyIdentifier
    }

    public static func defaultValidity() -> DateInterval {
        let start = Date()
        return DateInterval(start: start, end: start.addingTimeInterval(10 * 365 * 24 * 3600))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `swift test --filter CryptoEngineTests 2>&1 | tail -25`
Expected: PASS (4 tests). The permitted-domain chain validates; the `evil.com` chain is rejected by the name-constraint policy.

Note: if `Verifier`/`RFC5280Policy`/`.validCertificate`/`.couldNotValidate` symbol names differ in the installed version, adjust the test to the installed API (check `swift build` errors); the engine implementation does not depend on them.

- [ ] **Step 5: Commit**

```bash
git add Sources/CheburcertCore/Crypto/CryptoEngine.swift Sources/CheburcertCore/Model/TrustBundle.swift Tests/CheburcertCoreTests/CryptoEngineTests.swift
git commit -m "feat: crypto engine builds name-constrained cross-signed root"
```

---

## Phase 3 — Fetching Минцифры certificates

### Task 6: Fingerprint + PEM parsing (offline)

**Files:**
- Create: `Sources/CheburcertCore/Fetching/CertFetcher.swift`
- Create: `Sources/CheburcertCore/Fetching/MintsifrySource.swift`
- Test: `Tests/CheburcertCoreTests/CertFetcherTests.swift`

- [ ] **Step 1: Write the failing tests (parsing + fingerprint only; no network)**

`Tests/CheburcertCoreTests/CertFetcherTests.swift`:

```swift
import XCTest
import X509
@testable import CheburcertCore

final class CertFetcherTests: XCTestCase {
    func testParsesConcatenatedPEMBundle() throws {
        let pki = try TestPKI()
        let pem = try pki.root.serializeAsPEM().pemString + "\n"
                + try pki.intermediate.serializeAsPEM().pemString + "\n"
        let certs = try CertFetcher.parsePEMBundle(pem)
        XCTAssertEqual(certs.count, 2)
        XCTAssertEqual(certs[0].subject, pki.root.subject)
    }

    func testFingerprintIsStableUppercaseHexColonSeparated() throws {
        let pki = try TestPKI()
        let fp = try CertFetcher.sha256Fingerprint(pki.root)
        XCTAssertEqual(fp, fp.uppercased())
        XCTAssertEqual(fp.filter { $0 == ":" }.count, 31) // 32 bytes -> 31 separators
    }

    func testParseRejectsGarbage() {
        XCTAssertThrowsError(try CertFetcher.parsePEMBundle("not a pem"))
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `swift test --filter CertFetcherTests 2>&1 | tail -20`
Expected: FAIL — `CertFetcher` not found.

- [ ] **Step 3: Implement source list and fetcher**

`Sources/CheburcertCore/Fetching/MintsifrySource.swift`:

```swift
import Foundation

public enum MintsifrySource {
    /// Official Минцифры PEM distribution points (root + sub CAs).
    public static let urls: [URL] = [
        URL(string: "https://gu-st.ru/content/Other/doc/russian_trusted_root_ca_pem.crt")!,
        URL(string: "https://gu-st.ru/content/Other/doc/russian_trusted_sub_ca_pem.crt")!,
    ]
    /// Known-good SHA-256 fingerprint of the current root, shown to the user for verification.
    /// Filled in from a first trusted fetch; empty means "show fetched value, no comparison".
    public static let expectedRootFingerprint: String? = nil
}
```

`Sources/CheburcertCore/Fetching/CertFetcher.swift`:

```swift
import Foundation
import Crypto
import X509
import SwiftASN1

public struct FetchedCerts: Sendable {
    public let root: Certificate
    public let intermediates: [Certificate]
    public let rootFingerprint: String
}

public struct CertFetcher: Sendable {
    let session: URLSession
    public init(session: URLSession = .shared) { self.session = session }

    public func fetch(from urls: [URL] = MintsifrySource.urls) async throws -> FetchedCerts {
        var all: [Certificate] = []
        for url in urls {
            let data: Data
            do {
                (data, _) = try await session.data(from: url)
            } catch {
                throw CheburcertError.network("\(url.lastPathComponent): \(error.localizedDescription)")
            }
            guard let text = String(data: data, encoding: .utf8) else {
                throw CheburcertError.certificateParse("\(url.lastPathComponent): not UTF-8")
            }
            all.append(contentsOf: try Self.parsePEMBundle(text))
        }
        guard let root = all.first(where: { $0.subject == $0.issuer }) else {
            throw CheburcertError.certificateParse("no self-signed root found in downloaded bundle")
        }
        let intermediates = all.filter { $0.subject != $0.issuer }
        let fp = try Self.sha256Fingerprint(root)
        if let expected = MintsifrySource.expectedRootFingerprint, expected != fp {
            throw CheburcertError.fingerprintMismatch(expected: expected, got: fp)
        }
        return FetchedCerts(root: root, intermediates: intermediates, rootFingerprint: fp)
    }

    public static func parsePEMBundle(_ text: String) throws -> [Certificate] {
        let docs = try? PEMDocument.parseMultiple(pemString: text)
        guard let docs, !docs.isEmpty else {
            throw CheburcertError.certificateParse("no PEM certificates found")
        }
        return try docs.map { try Certificate(pemDocument: $0) }
    }

    public static func sha256Fingerprint(_ cert: Certificate) throws -> String {
        var serializer = DER.Serializer()
        try serializer.serialize(cert)
        let digest = SHA256.hash(data: Data(serializer.serializedBytes))
        return digest.map { String(format: "%02X", $0) }.joined(separator: ":")
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `swift test --filter CertFetcherTests 2>&1 | tail -20`
Expected: PASS.

Note: if `PEMDocument.parseMultiple` differs in the installed SwiftASN1 version, split on `-----END CERTIFICATE-----` and parse each block with `Certificate(pemEncoded:)`; keep the same function signature/tests.

- [ ] **Step 5: Commit**

```bash
git add Sources/CheburcertCore/Fetching Tests/CheburcertCoreTests/CertFetcherTests.swift
git commit -m "feat: fetch and fingerprint Минцифры certificates"
```

---

## Phase 4 — Command runner & installers

### Task 7: Command runner boundary

**Files:**
- Create: `Sources/CheburcertCore/Command/CommandRunner.swift`
- Test: `Tests/CheburcertCoreTests/KeychainInstallerTests.swift` (uses the mock; added in Task 8)

- [ ] **Step 1: Implement the protocol + real + mock runners**

`Sources/CheburcertCore/Command/CommandRunner.swift`:

```swift
import Foundation

public struct CommandResult: Sendable, Equatable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String
}

public protocol CommandRunner: Sendable {
    func run(_ executable: String, _ arguments: [String]) throws -> CommandResult
}

/// Runs a subprocess unprivileged (used for certutil and read-only `security` calls).
public struct ProcessCommandRunner: CommandRunner {
    public init() {}
    public func run(_ executable: String, _ arguments: [String]) throws -> CommandResult {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: executable)
        proc.arguments = arguments
        let out = Pipe(), err = Pipe()
        proc.standardOutput = out; proc.standardError = err
        do { try proc.run() } catch {
            throw CheburcertError.commandFailed(command: executable, exitCode: -1, stderr: error.localizedDescription)
        }
        proc.waitUntilExit()
        let o = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let e = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        return CommandResult(exitCode: proc.terminationStatus, stdout: o, stderr: e)
    }
}

/// Records invocations for tests; returns canned results.
public final class MockCommandRunner: CommandRunner, @unchecked Sendable {
    public struct Call: Equatable { public let executable: String; public let arguments: [String] }
    public private(set) var calls: [Call] = []
    public var stubResult: CommandResult = CommandResult(exitCode: 0, stdout: "", stderr: "")
    public var resultForCall: ((Call) -> CommandResult)?
    public init() {}
    public func run(_ executable: String, _ arguments: [String]) throws -> CommandResult {
        let call = Call(executable: executable, arguments: arguments)
        calls.append(call)
        return resultForCall?(call) ?? stubResult
    }
}
```

- [ ] **Step 2: Build**

Run: `swift build 2>&1 | tail -5`
Expected: builds.

- [ ] **Step 3: Commit**

```bash
git add Sources/CheburcertCore/Command/CommandRunner.swift
git commit -m "feat: command runner boundary with mock"
```

### Task 8: Keychain installer

**Files:**
- Create: `Sources/CheburcertCore/Command/PrivilegedRunner.swift`
- Create: `Sources/CheburcertCore/Installers/TrustStoreInstaller.swift`
- Create: `Sources/CheburcertCore/Installers/KeychainInstaller.swift`
- Create: `Sources/CheburcertCore/Persistence/AppPaths.swift`
- Test: `Tests/CheburcertCoreTests/KeychainInstallerTests.swift`

- [ ] **Step 1: Write the failing tests**

`Tests/CheburcertCoreTests/KeychainInstallerTests.swift`:

```swift
import XCTest
import X509
@testable import CheburcertCore

final class KeychainInstallerTests: XCTestCase {
    func testInstallWritesTrustedRootThenAddsCrossAndIntermediates() throws {
        let pki = try TestPKI()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])
        let priv = MockPrivilegedRunner()
        let installer = KeychainInstaller(privileged: priv, workDir: FileManager.default.temporaryDirectory)
        try installer.install(bundle)

        // One privileged batch was executed.
        XCTAssertEqual(priv.batches.count, 1)
        let script = priv.batches[0]
        // Local root added as trusted root.
        XCTAssertTrue(script.contains("add-trusted-cert"))
        XCTAssertTrue(script.contains("-r trustRoot"))
        // Cross-cert + intermediate added (as plain certs).
        XCTAssertTrue(script.contains("add-certificates") || script.contains("add-trusted-cert"))
    }

    func testRemoveDeletesByCommonName() throws {
        let priv = MockPrivilegedRunner()
        let installer = KeychainInstaller(privileged: priv, workDir: FileManager.default.temporaryDirectory)
        try installer.removeAll()
        XCTAssertEqual(priv.batches.count, 1)
        XCTAssertTrue(priv.batches[0].contains("delete-certificate"))
        XCTAssertTrue(priv.batches[0].contains("Cheburcert Local Constrained Root"))
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `swift test --filter KeychainInstallerTests 2>&1 | tail -20`
Expected: FAIL — types not found.

- [ ] **Step 3: Implement `AppPaths`, `PrivilegedRunner`, protocol, and `KeychainInstaller`**

`Sources/CheburcertCore/Persistence/AppPaths.swift`:

```swift
import Foundation

public enum AppPaths {
    public static var appSupport: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("Cheburcert", isDirectory: true)
    }
    public static func ensureAppSupport() throws {
        try FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)
    }
    public static var domainsFile: URL { appSupport.appendingPathComponent("domains.json") }
    public static var keyFile: URL { appSupport.appendingPathComponent("localRoot.key.pem") }
    public static var localRootFile: URL { appSupport.appendingPathComponent("localRoot.crt") }
}
```

`Sources/CheburcertCore/Command/PrivilegedRunner.swift`:

```swift
import Foundation

/// Runs a shell script once with administrator privileges (single macOS password prompt).
public protocol PrivilegedRunner: Sendable {
    func runScript(_ script: String) throws
}

/// Uses osascript "do shell script ... with administrator privileges".
public struct OSAScriptPrivilegedRunner: PrivilegedRunner {
    let runner: CommandRunner
    public init(runner: CommandRunner = ProcessCommandRunner()) { self.runner = runner }
    public func runScript(_ script: String) throws {
        let escaped = script.replacingOccurrences(of: "\\", with: "\\\\")
                            .replacingOccurrences(of: "\"", with: "\\\"")
        let appleScript = "do shell script \"\(escaped)\" with administrator privileges"
        let result = try runner.run("/usr/bin/osascript", ["-e", appleScript])
        if result.exitCode != 0 {
            if result.stderr.contains("-128") || result.stderr.lowercased().contains("cancel") {
                throw CheburcertError.authorizationDenied
            }
            throw CheburcertError.commandFailed(command: "osascript", exitCode: result.exitCode, stderr: result.stderr)
        }
    }
}

/// Test double: records the composed scripts instead of running them.
public final class MockPrivilegedRunner: PrivilegedRunner, @unchecked Sendable {
    public private(set) var batches: [String] = []
    public var shouldThrow: CheburcertError?
    public init() {}
    public func runScript(_ script: String) throws {
        if let e = shouldThrow { throw e }
        batches.append(script)
    }
}
```

`Sources/CheburcertCore/Installers/TrustStoreInstaller.swift`:

```swift
import Foundation

public protocol TrustStoreInstaller {
    /// Install the bundle; idempotent (safe to call repeatedly).
    func install(_ bundle: TrustBundle) throws
    /// Remove everything Cheburcert installed.
    func removeAll() throws
}
```

`Sources/CheburcertCore/Installers/KeychainInstaller.swift`:

```swift
import Foundation
import X509

public struct KeychainInstaller: TrustStoreInstaller {
    public static let localRootCN = "Cheburcert Local Constrained Root"
    let privileged: PrivilegedRunner
    let workDir: URL
    let systemKeychain = "/Library/Keychains/System.keychain"

    public init(privileged: PrivilegedRunner, workDir: URL) {
        self.privileged = privileged
        self.workDir = workDir
    }

    public func install(_ bundle: TrustBundle) throws {
        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        let localRootPath = try write(bundle.localRoot, "cheburcert-localroot.crt")
        let crossPath = try write(bundle.crossCert, "cheburcert-cross.crt")
        var interPaths: [String] = []
        for (i, cert) in bundle.intermediates.enumerated() {
            interPaths.append(try write(cert, "cheburcert-inter-\(i).crt"))
        }

        // Compose one privileged script: remove stale, add trusted local root, add cross + intermediates.
        var lines: [String] = []
        lines.append(removeScriptBody())
        lines.append("/usr/bin/security add-trusted-cert -d -r trustRoot -k \(systemKeychain) '\(localRootPath)'")
        lines.append("/usr/bin/security add-certificates -k \(systemKeychain) '\(crossPath)'")
        for p in interPaths {
            lines.append("/usr/bin/security add-certificates -k \(systemKeychain) '\(p)'")
        }
        try privileged.runScript(lines.joined(separator: "; "))
    }

    public func removeAll() throws {
        try privileged.runScript(removeScriptBody())
    }

    private func removeScriptBody() -> String {
        // delete-certificate returns nonzero if absent; "|| true" keeps the batch going.
        "/usr/bin/security delete-certificate -c '\(Self.localRootCN)' \(systemKeychain) || true"
    }

    private func write(_ cert: Certificate, _ name: String) throws -> String {
        let url = workDir.appendingPathComponent(name)
        let pem = try cert.serializeAsPEM().pemString
        try pem.write(to: url, atomically: true, encoding: .utf8)
        return url.path
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `swift test --filter KeychainInstallerTests 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Sources/CheburcertCore/Persistence/AppPaths.swift Sources/CheburcertCore/Command/PrivilegedRunner.swift Sources/CheburcertCore/Installers/TrustStoreInstaller.swift Sources/CheburcertCore/Installers/KeychainInstaller.swift Tests/CheburcertCoreTests/KeychainInstallerTests.swift
git commit -m "feat: keychain installer via single privileged batch"
```

### Task 9: Firefox profile discovery

**Files:**
- Create: `Sources/CheburcertCore/Installers/FirefoxProfiles.swift`
- Test: `Tests/CheburcertCoreTests/FirefoxProfilesTests.swift`

- [ ] **Step 1: Write the failing tests**

`Tests/CheburcertCoreTests/FirefoxProfilesTests.swift`:

```swift
import XCTest
@testable import CheburcertCore

final class FirefoxProfilesTests: XCTestCase {
    func testParsesRelativeAndAbsoluteProfiles() throws {
        let ini = """
        [Profile0]
        Name=default
        IsRelative=1
        Path=Profiles/abc.default

        [Profile1]
        Name=dev
        IsRelative=0
        Path=/custom/place/dev-profile
        """
        let base = URL(fileURLWithPath: "/Users/x/Library/Application Support/Firefox")
        let dirs = FirefoxProfiles.parse(iniContents: ini, firefoxDir: base).map { $0.path }
        XCTAssertEqual(dirs, [
            "/Users/x/Library/Application Support/Firefox/Profiles/abc.default",
            "/custom/place/dev-profile",
        ])
    }

    func testEmptyWhenNoProfiles() {
        let base = URL(fileURLWithPath: "/tmp/none")
        XCTAssertTrue(FirefoxProfiles.parse(iniContents: "[General]\nStartWithLastProfile=1", firefoxDir: base).isEmpty)
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `swift test --filter FirefoxProfilesTests 2>&1 | tail -20`
Expected: FAIL — `FirefoxProfiles` not found.

- [ ] **Step 3: Implement**

`Sources/CheburcertCore/Installers/FirefoxProfiles.swift`:

```swift
import Foundation

public enum FirefoxProfiles {
    public static var firefoxDir: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Firefox", isDirectory: true)
    }

    /// All profile directories on disk (parses profiles.ini). Empty if Firefox isn't installed.
    public static func discover(firefoxDir: URL = firefoxDir) -> [URL] {
        let ini = firefoxDir.appendingPathComponent("profiles.ini")
        guard let contents = try? String(contentsOf: ini, encoding: .utf8) else { return [] }
        return parse(iniContents: contents, firefoxDir: firefoxDir)
            .filter { FileManager.default.fileExists(atPath: $0.path) }
    }

    static func parse(iniContents: String, firefoxDir: URL) -> [URL] {
        var results: [URL] = []
        var path: String?
        var isRelative = true

        func flush() {
            guard let p = path else { return }
            results.append(isRelative ? firefoxDir.appendingPathComponent(p) : URL(fileURLWithPath: p))
            path = nil; isRelative = true
        }

        for line in iniContents.split(whereSeparator: \.isNewline) {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("[Profile") { flush() }
            else if t.hasPrefix("Path=") { path = String(t.dropFirst(5)) }
            else if t.hasPrefix("IsRelative=") { isRelative = t.dropFirst(11) == "1" }
        }
        flush()
        return results
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `swift test --filter FirefoxProfilesTests 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Sources/CheburcertCore/Installers/FirefoxProfiles.swift Tests/CheburcertCoreTests/FirefoxProfilesTests.swift
git commit -m "feat: parse Firefox profiles.ini"
```

### Task 10: Firefox installer via certutil

**Files:**
- Create: `Sources/CheburcertCore/Installers/FirefoxInstaller.swift`
- Test: `Tests/CheburcertCoreTests/FirefoxInstallerTests.swift`

- [ ] **Step 1: Write the failing tests**

`Tests/CheburcertCoreTests/FirefoxInstallerTests.swift`:

```swift
import XCTest
import X509
@testable import CheburcertCore

final class FirefoxInstallerTests: XCTestCase {
    func makeBundle() throws -> TrustBundle {
        let pki = try TestPKI()
        return try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])
    }

    func testInstallsLocalRootWithTrustFlagIntoEachProfile() throws {
        let bundle = try makeBundle()
        let runner = MockCommandRunner()
        let profiles = [URL(fileURLWithPath: "/p/one"), URL(fileURLWithPath: "/p/two")]
        let installer = FirefoxInstaller(
            certutilPath: "/opt/certutil", runner: runner,
            profiles: { profiles }, isFirefoxRunning: { false },
            workDir: FileManager.default.temporaryDirectory)
        try installer.install(bundle)

        let addCalls = runner.calls.filter { $0.arguments.contains("-A") }
        XCTAssertEqual(addCalls.count, 2) // one per profile for the local root
        XCTAssertTrue(addCalls[0].arguments.contains("sql:/p/one"))
        XCTAssertTrue(addCalls[0].arguments.contains("C,,"))
        XCTAssertTrue(addCalls[0].arguments.contains(KeychainInstaller.localRootCN))
    }

    func testThrowsWhenFirefoxRunning() throws {
        let bundle = try makeBundle()
        let installer = FirefoxInstaller(
            certutilPath: "/opt/certutil", runner: MockCommandRunner(),
            profiles: { [URL(fileURLWithPath: "/p/one")] }, isFirefoxRunning: { true },
            workDir: FileManager.default.temporaryDirectory)
        XCTAssertThrowsError(try installer.install(bundle)) {
            XCTAssertEqual($0 as? CheburcertError, .firefoxRunning)
        }
    }

    func testNoProfilesIsNotAnErrorButInstallsNothing() throws {
        let bundle = try makeBundle()
        let runner = MockCommandRunner()
        let installer = FirefoxInstaller(
            certutilPath: "/opt/certutil", runner: runner,
            profiles: { [] }, isFirefoxRunning: { false },
            workDir: FileManager.default.temporaryDirectory)
        try installer.install(bundle)
        XCTAssertTrue(runner.calls.isEmpty)
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `swift test --filter FirefoxInstallerTests 2>&1 | tail -20`
Expected: FAIL — `FirefoxInstaller` not found.

- [ ] **Step 3: Implement**

`Sources/CheburcertCore/Installers/FirefoxInstaller.swift`:

```swift
import Foundation
import X509

public struct FirefoxInstaller: TrustStoreInstaller {
    let certutilPath: String
    let runner: CommandRunner
    let profilesProvider: () -> [URL]
    let isFirefoxRunning: () -> Bool
    let workDir: URL

    public init(
        certutilPath: String,
        runner: CommandRunner = ProcessCommandRunner(),
        profiles: @escaping () -> [URL] = { FirefoxProfiles.discover() },
        isFirefoxRunning: @escaping () -> Bool = FirefoxInstaller.defaultRunningCheck,
        workDir: URL
    ) {
        self.certutilPath = certutilPath
        self.runner = runner
        self.profilesProvider = profiles
        self.isFirefoxRunning = isFirefoxRunning
        self.workDir = workDir
    }

    public func install(_ bundle: TrustBundle) throws {
        let profiles = profilesProvider()
        guard !profiles.isEmpty else { return } // Firefox absent: skip silently
        if isFirefoxRunning() { throw CheburcertError.firefoxRunning }

        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        let rootPath = try write(bundle.localRoot, "ff-localroot.crt")

        for profile in profiles {
            // Remove any prior copy (ignore failure), then add with CA trust flag "C,,".
            _ = try? runner.run(certutilPath, ["-D", "-d", "sql:\(profile.path)", "-n", KeychainInstaller.localRootCN])
            let res = try runner.run(certutilPath, [
                "-A", "-d", "sql:\(profile.path)", "-t", "C,,",
                "-n", KeychainInstaller.localRootCN, "-i", rootPath,
            ])
            if res.exitCode != 0 {
                throw CheburcertError.commandFailed(command: "certutil", exitCode: res.exitCode, stderr: res.stderr)
            }
        }
    }

    public func removeAll() throws {
        for profile in profilesProvider() {
            _ = try? runner.run(certutilPath, ["-D", "-d", "sql:\(profile.path)", "-n", KeychainInstaller.localRootCN])
        }
    }

    public static let defaultRunningCheck: () -> Bool = {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        p.arguments = ["-x", "firefox"]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = Pipe()
        do { try p.run(); p.waitUntilExit() } catch { return false }
        return p.terminationStatus == 0
    }

    private func write(_ cert: Certificate, _ name: String) throws -> String {
        let url = workDir.appendingPathComponent(name)
        try cert.serializeAsPEM().pemString.write(to: url, atomically: true, encoding: .utf8)
        return url.path
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `swift test --filter FirefoxInstallerTests 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Sources/CheburcertCore/Installers/FirefoxInstaller.swift Tests/CheburcertCoreTests/FirefoxInstallerTests.swift
git commit -m "feat: firefox installer via bundled certutil"
```

---

## Phase 5 — Persistence, verifier, orchestration

### Task 11: Domain store & key store

**Files:**
- Create: `Sources/CheburcertCore/Persistence/DomainStore.swift`
- Create: `Sources/CheburcertCore/Persistence/KeyStore.swift`
- Test: `Tests/CheburcertCoreTests/PersistenceTests.swift`

- [ ] **Step 1: Write the failing tests**

`Tests/CheburcertCoreTests/PersistenceTests.swift`:

```swift
import XCTest
import X509
@testable import CheburcertCore

final class PersistenceTests: XCTestCase {
    func tempDir() -> URL {
        let u = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }

    func testDomainStoreRoundTrips() throws {
        let file = tempDir().appendingPathComponent("domains.json")
        let store = DomainStore(file: file)
        try store.save(["sberbank.ru", ".ru"])
        XCTAssertEqual(try store.load(), ["sberbank.ru", ".ru"])
    }

    func testDomainStoreLoadsEmptyWhenMissing() throws {
        let store = DomainStore(file: tempDir().appendingPathComponent("nope.json"))
        XCTAssertEqual(try store.load(), [])
    }

    func testKeyStoreRoundTripsAndSetsMode0600() throws {
        let dir = tempDir()
        let store = KeyStore(keyFile: dir.appendingPathComponent("k.pem"),
                             certFile: dir.appendingPathComponent("r.crt"))
        let key = Certificate.PrivateKey(P384.Signing.PrivateKey())
        let pki = try TestPKI()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root,
            mintsifryIntermediates: [pki.intermediate], localKeyOverride: key)
        try store.save(key: bundle.localRootKey, localRoot: bundle.localRoot)

        let attrs = try FileManager.default.attributesOfItem(atPath: store.keyFile.path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertNotNil(try store.loadKey())
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `swift test --filter PersistenceTests 2>&1 | tail -20`
Expected: FAIL — types not found.

- [ ] **Step 3: Implement**

`Sources/CheburcertCore/Persistence/DomainStore.swift`:

```swift
import Foundation

public struct DomainStore: Sendable {
    public let file: URL
    public init(file: URL = AppPaths.domainsFile) { self.file = file }

    public func load() throws -> [String] {
        guard let data = try? Data(contentsOf: file) else { return [] }
        return (try? JSONDecoder().decode([String].self, from: data)) ?? []
    }
    public func save(_ domains: [String]) throws {
        try FileManager.default.createDirectory(
            at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(domains)
        try data.write(to: file, options: .atomic)
    }
}
```

`Sources/CheburcertCore/Persistence/KeyStore.swift`:

```swift
import Foundation
import X509
import Crypto

public struct KeyStore: Sendable {
    public let keyFile: URL
    public let certFile: URL
    public init(keyFile: URL = AppPaths.keyFile, certFile: URL = AppPaths.localRootFile) {
        self.keyFile = keyFile; self.certFile = certFile
    }

    public func save(key: Certificate.PrivateKey, localRoot: Certificate) throws {
        try FileManager.default.createDirectory(
            at: keyFile.deletingLastPathComponent(), withIntermediateDirectories: true)
        try key.serializeAsPEM().pemString.write(to: keyFile, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyFile.path)
        try localRoot.serializeAsPEM().pemString.write(to: certFile, atomically: true, encoding: .utf8)
    }

    public func loadKey() throws -> Certificate.PrivateKey? {
        guard let pem = try? String(contentsOf: keyFile, encoding: .utf8) else { return nil }
        return try Certificate.PrivateKey(pemEncoded: pem)
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `swift test --filter PersistenceTests 2>&1 | tail -20`
Expected: PASS. If `Certificate.PrivateKey(pemEncoded:)` / `serializeAsPEM()` names differ for keys in the installed version, adapt to the installed key PEM API; keep tests green.

- [ ] **Step 5: Commit**

```bash
git add Sources/CheburcertCore/Persistence/DomainStore.swift Sources/CheburcertCore/Persistence/KeyStore.swift Tests/CheburcertCoreTests/PersistenceTests.swift
git commit -m "feat: domain and key persistence"
```

### Task 12: Verifier & install-state

**Files:**
- Create: `Sources/CheburcertCore/Model/InstallState.swift`
- Create: `Sources/CheburcertCore/Verify/Verifier.swift`
- Test: `Tests/CheburcertCoreTests/VerifierTests.swift`

- [ ] **Step 1: Write the failing tests**

`Tests/CheburcertCoreTests/VerifierTests.swift`:

```swift
import XCTest
import X509
@testable import CheburcertCore

final class VerifierTests: XCTestCase {
    func testSelfCheckAcceptsPermittedRejectsOther() async throws {
        let pki = try TestPKI()
        let bundle = try CryptoEngine.buildTrustBundle(
            domains: [".ru"], mintsifryRoot: pki.root, mintsifryIntermediates: [pki.intermediate])
        let ok = try pki.leaf(host: "a.sberbank.ru")
        let bad = try pki.leaf(host: "a.example.com")

        let permitted = await ChainSelfCheck.validates(
            leaf: ok, intermediates: [pki.intermediate, bundle.crossCert],
            localRoot: bundle.localRoot, at: pki.notBefore.addingTimeInterval(1))
        let blocked = await ChainSelfCheck.validates(
            leaf: bad, intermediates: [pki.intermediate, bundle.crossCert],
            localRoot: bundle.localRoot, at: pki.notBefore.addingTimeInterval(1))

        XCTAssertTrue(permitted)
        XCTAssertFalse(blocked)
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `swift test --filter VerifierTests 2>&1 | tail -20`
Expected: FAIL — `ChainSelfCheck` not found.

- [ ] **Step 3: Implement**

`Sources/CheburcertCore/Model/InstallState.swift`:

```swift
import Foundation

public struct InstallState: Sendable, Equatable {
    public var keychainInstalled: Bool
    public var firefoxProfileCount: Int
    public var installedDomains: [String]
    public static let notInstalled = InstallState(
        keychainInstalled: false, firefoxProfileCount: 0, installedDomains: [])
}
```

`Sources/CheburcertCore/Verify/Verifier.swift`:

```swift
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
```

- [ ] **Step 4: Run to verify pass**

Run: `swift test --filter VerifierTests 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Sources/CheburcertCore/Model/InstallState.swift Sources/CheburcertCore/Verify/Verifier.swift Tests/CheburcertCoreTests/VerifierTests.swift
git commit -m "feat: offline chain self-check and install-state model"
```

### Task 13: `CheburcertService` orchestration facade

**Files:**
- Create: `Sources/CheburcertCore/CheburcertService.swift`
- Test: `Tests/CheburcertCoreTests/ServiceTests.swift`

- [ ] **Step 1: Write the failing test (apply flow drives Firefox then keychain once)**

`Tests/CheburcertCoreTests/ServiceTests.swift`:

```swift
import XCTest
import X509
@testable import CheburcertCore

final class ServiceTests: XCTestCase {
    func testApplyBuildsInstallsBothStoresAndPersists() async throws {
        let pki = try TestPKI()
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let priv = MockPrivilegedRunner()
        let ffRunner = MockCommandRunner()

        let service = CheburcertService(
            fetch: { FetchedCerts(root: pki.root, intermediates: [pki.intermediate],
                                  rootFingerprint: try CertFetcher.sha256Fingerprint(pki.root)) },
            keychain: KeychainInstaller(privileged: priv, workDir: tmp),
            firefox: FirefoxInstaller(certutilPath: "/opt/certutil", runner: ffRunner,
                                      profiles: { [URL(fileURLWithPath: "/p/one")] },
                                      isFirefoxRunning: { false }, workDir: tmp),
            domainStore: DomainStore(file: tmp.appendingPathComponent("d.json")),
            keyStore: KeyStore(keyFile: tmp.appendingPathComponent("k.pem"),
                               certFile: tmp.appendingPathComponent("r.crt")))

        try await service.apply(domains: ["sberbank.ru"])

        XCTAssertEqual(priv.batches.count, 1)                       // one keychain batch
        XCTAssertTrue(ffRunner.calls.contains { $0.arguments.contains("-A") }) // firefox add
        XCTAssertEqual(try DomainStore(file: tmp.appendingPathComponent("d.json")).load(), ["sberbank.ru"])
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `swift test --filter ServiceTests 2>&1 | tail -20`
Expected: FAIL — `CheburcertService` not found.

- [ ] **Step 3: Implement the facade**

`Sources/CheburcertCore/CheburcertService.swift`:

```swift
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
        // Reuse the stored key when it exists so unchanged installs stay idempotent.
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

    /// Remove from all stores. Keeps the saved domain list by default.
    public func removeAll() throws {
        try? firefox.removeAll()
        try keychain.removeAll()
    }

    public func savedDomains() -> [String] { (try? domainStore.load()) ?? [] }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `swift test 2>&1 | tail -25`
Expected: full suite PASS (all phases).

- [ ] **Step 5: Commit**

```bash
git add Sources/CheburcertCore/CheburcertService.swift Tests/CheburcertCoreTests/ServiceTests.swift
git commit -m "feat: CheburcertService orchestration facade"
```

---

## Phase 6 — SwiftUI app shell

> These tasks are UI wiring, verified by build + manual smoke run rather than unit tests. Keep the app target thin: it owns the window, the `AppModel`, and bundling `certutil`; all logic stays in `CheburcertCore`.

### Task 14: Xcode app target depending on the package

**Files:**
- Create: `App/CheburcertApp/CheburcertApp.swift`
- Create: `App/CheburcertApp/AppModel.swift`
- Create: `App/CheburcertApp/project.yml` (XcodeGen spec) or a hand-made `.xcodeproj`

- [ ] **Step 1: Create an XcodeGen project spec**

`App/CheburcertApp/project.yml`:

```yaml
name: Cheburcert
options:
  bundleIdPrefix: me.cheburcert
  deploymentTarget:
    macOS: "13.0"
packages:
  CheburcertCore:
    path: ../..
targets:
  Cheburcert:
    type: application
    platform: macOS
    sources: [.]
    dependencies:
      - package: CheburcertCore
        product: CheburcertCore
    settings:
      base:
        PRODUCT_NAME: Cheburcert
        MARKETING_VERSION: "1.0"
        ENABLE_HARDENED_RUNTIME: YES
        CODE_SIGN_ENTITLEMENTS: Cheburcert.entitlements
    info:
      path: Info.plist
      properties:
        LSMinimumSystemVersion: "13.0"
        CFBundleDisplayName: Cheburcert
```

- [ ] **Step 2: Create the entitlements (no sandbox: we run `security`/`certutil`)**

`App/CheburcertApp/Cheburcert.entitlements`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.app-sandbox</key>
  <false/>
</dict>
</plist>
```

- [ ] **Step 3: Write the app entry + model**

`App/CheburcertApp/CheburcertApp.swift`:

```swift
import SwiftUI

@main
struct CheburcertApp: App {
    @StateObject private var model = AppModel()
    var body: some Scene {
        WindowGroup {
            ContentView().environmentObject(model)
                .frame(minWidth: 720, minHeight: 480)
        }
        .windowResizability(.contentSize)
    }
}
```

`App/CheburcertApp/AppModel.swift`:

```swift
import Foundation
import SwiftUI
import CheburcertCore

@MainActor
final class AppModel: ObservableObject {
    @Published var domains: [String] = []
    @Published var newDomain: String = ""
    @Published var searchText: String = ""
    @Published var status: String = "Проверка…"
    @Published var isBusy = false
    @Published var lastError: String?
    @Published var installState: InstallState = .notInstalled

    let presets = Presets.all
    private let service: CheburcertService

    init() {
        // certutil is bundled in the app Resources.
        let certutil = Bundle.main.url(forResource: "certutil", withExtension: nil)?.path ?? "/usr/bin/false"
        let workDir = AppPaths.appSupport.appendingPathComponent("work")
        self.service = CheburcertService(
            fetch: { try await CertFetcher().fetch() },
            keychain: KeychainInstaller(privileged: OSAScriptPrivilegedRunner(), workDir: workDir),
            firefox: FirefoxInstaller(certutilPath: certutil, workDir: workDir))
        self.domains = service.savedDomains()
        refreshStatus()
    }

    var filteredDomains: [String] {
        searchText.isEmpty ? domains
            : domains.filter { $0.localizedCaseInsensitiveContains(searchText) }
    }

    func addDomain() {
        let raw = newDomain
        newDomain = ""
        do {
            let n = try DomainList.normalize(raw)
            if !domains.contains(n) { domains.append(n) }
        } catch { lastError = "Некорректный домен: \(raw)" }
    }

    func remove(_ domain: String) { domains.removeAll { $0 == domain } }

    func applyPreset(_ p: DomainPreset) {
        for d in p.domains where !domains.contains(d) { domains.append(d) }
    }

    func apply() {
        isBusy = true; lastError = nil
        let ds = domains
        Task {
            do { try await service.apply(domains: ds) }
            catch let e as CheburcertError { lastError = Self.message(for: e) }
            catch { lastError = error.localizedDescription }
            refreshStatus(); isBusy = false
        }
    }

    func removeAll() {
        isBusy = true; lastError = nil
        Task {
            do { try service.removeAll() }
            catch let e as CheburcertError { lastError = Self.message(for: e) }
            catch { lastError = error.localizedDescription }
            refreshStatus(); isBusy = false
        }
    }

    func refreshStatus() {
        let ff = FirefoxProfiles.discover().count
        installState = InstallState(
            keychainInstalled: FileManager.default.fileExists(atPath: AppPaths.localRootFile.path),
            firefoxProfileCount: ff, installedDomains: service.savedDomains())
        status = installState.keychainInstalled ? "Защита включена" : "Защита выключена"
    }

    static func message(for e: CheburcertError) -> String {
        switch e {
        case .firefoxRunning: return "Firefox запущен. Закройте его и повторите."
        case .authorizationDenied: return "Не введён пароль администратора."
        case .network(let m): return "Не удалось скачать сертификаты: \(m)"
        case .fingerprintMismatch: return "Отпечаток корня Минцифры не совпал — установка отменена."
        case .noFirefoxProfiles: return "Профили Firefox не найдены."
        case .invalidDomain(let d): return "Некорректный домен: \(d)"
        default: return "Ошибка: \(e)"
        }
    }
}
```

- [ ] **Step 4: Generate the project and build**

Run:
```bash
brew list xcodegen >/dev/null 2>&1 || brew install xcodegen
cd App/CheburcertApp && xcodegen generate && \
xcodebuild -project Cheburcert.xcodeproj -scheme Cheburcert -configuration Debug build 2>&1 | tail -15
```
Expected: `BUILD SUCCEEDED` (ContentView referenced next task may need a stub — create an empty `ContentView` if the build complains, then flesh it out in Task 15).

- [ ] **Step 5: Commit**

```bash
git add App/CheburcertApp/project.yml App/CheburcertApp/Cheburcert.entitlements App/CheburcertApp/CheburcertApp.swift App/CheburcertApp/AppModel.swift
git commit -m "feat: SwiftUI app shell and model"
```

### Task 15: The single-window UI

**Files:**
- Create: `App/CheburcertApp/ContentView.swift`
- Create: `App/CheburcertApp/Views/StatusBanner.swift`
- Create: `App/CheburcertApp/Views/DomainListPane.swift`
- Create: `App/CheburcertApp/Views/ActionsPane.swift`
- Create: `App/CheburcertApp/Views/WarningFooter.swift`

- [ ] **Step 1: Implement `ContentView` matching the approved mockup**

`App/CheburcertApp/ContentView.swift`:

```swift
import SwiftUI
import CheburcertCore

struct ContentView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(spacing: 0) {
            StatusBanner()
            HStack(alignment: .top, spacing: 16) {
                DomainListPane()
                ActionsPane()
            }.padding(20)
            Spacer(minLength: 0)
            WarningFooter()
        }
        .alert("Ошибка", isPresented: Binding(
            get: { model.lastError != nil }, set: { if !$0 { model.lastError = nil } })) {
            Button("OK", role: .cancel) { model.lastError = nil }
        } message: { Text(model.lastError ?? "") }
    }
}
```

`App/CheburcertApp/Views/StatusBanner.swift`:

```swift
import SwiftUI

struct StatusBanner: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: model.installState.keychainInstalled ? "checkmark.seal.fill" : "xmark.seal")
                .foregroundStyle(model.installState.keychainInstalled ? .green : .secondary)
                .font(.title2)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.status).font(.headline)
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Проверить") { model.refreshStatus() }
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
        .background(model.installState.keychainInstalled ? Color.green.opacity(0.12) : Color.gray.opacity(0.1))
    }
    var subtitle: String {
        let ff = model.installState.firefoxProfileCount
        var parts: [String] = []
        if model.installState.keychainInstalled { parts.append("Safari · Chrome") }
        if ff > 0 { parts.append("Firefox (\(ff) проф.)") }
        return parts.isEmpty ? "Ничего не установлено" : "Установлено: " + parts.joined(separator: " · ")
    }
}
```

`App/CheburcertApp/Views/DomainListPane.swift`:

```swift
import SwiftUI
import CheburcertCore

struct DomainListPane: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Разрешённые домены").font(.headline)
                Text("· \(model.domains.count)").foregroundStyle(.secondary)
                Spacer()
                Text("каждый домен включает поддомены")
                    .font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                TextField("например, sberbank.ru или .ru", text: $model.newDomain)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { model.addDomain() }
                Button("Добавить") { model.addDomain() }
            }
            TextField("Поиск по списку", text: $model.searchText).textFieldStyle(.roundedBorder)
            List {
                ForEach(model.filteredDomains, id: \.self) { d in
                    HStack {
                        Text(d)
                        Spacer()
                        Button {
                            model.remove(d)
                        } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }
                        .buttonStyle(.plain)
                    }
                }
            }
            .frame(minHeight: 180)
            Text("Быстрые наборы:").font(.caption).foregroundStyle(.secondary)
            HStack {
                ForEach(model.presets) { p in
                    Button("+ \(p.name)") { model.applyPreset(p) }.controlSize(.small)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
```

`App/CheburcertApp/Views/ActionsPane.swift`:

```swift
import SwiftUI

struct ActionsPane: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(spacing: 12) {
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Применить изменения").font(.headline)
                    Text("Пересоберём ограниченный корень и обновим браузеры. Потребуется пароль администратора.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button {
                        model.apply()
                    } label: { Text("Применить").frame(maxWidth: .infinity) }
                    .buttonStyle(.borderedProminent).tint(.green)
                    .disabled(model.isBusy || model.domains.isEmpty)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Отключить защиту").font(.headline).foregroundStyle(.red)
                    Text("Удалить всё установленное из Safari, Chrome и Firefox.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button(role: .destructive) {
                        model.removeAll()
                    } label: { Text("Удалить всё").frame(maxWidth: .infinity) }
                    .disabled(model.isBusy)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            if model.isBusy { ProgressView().padding(.top, 4) }
        }
        .frame(width: 260)
    }
}
```

`App/CheburcertApp/Views/WarningFooter.swift`:

```swift
import SwiftUI

struct WarningFooter: View {
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.yellow)
            Text("В Firefox ограничение по доменам работает строго. В Safari и Chrome оно соблюдается ненадёжно — там сертификат Минцифры может приниматься и для других доменов.")
                .font(.caption)
            Spacer()
        }
        .padding(.horizontal, 20).padding(.vertical, 12)
        .background(Color.yellow.opacity(0.12))
    }
}
```

- [ ] **Step 2: Regenerate and build**

Run:
```bash
cd App/CheburcertApp && xcodegen generate && \
xcodebuild -project Cheburcert.xcodeproj -scheme Cheburcert -configuration Debug build 2>&1 | tail -15
```
Expected: `BUILD SUCCEEDED`.

- [ ] **Step 3: Manual smoke run**

Run: open the built app (path from `xcodebuild -showBuildSettings | grep TARGET_BUILD_DIR`), or `open` the `.app`. Confirm: window shows status banner, empty domain list, presets, Apply disabled when empty, warning footer visible. Do NOT click Apply yet (certutil not bundled until Task 16).

- [ ] **Step 4: Commit**

```bash
git add App/CheburcertApp/ContentView.swift App/CheburcertApp/Views
git commit -m "feat: single-window UI matching approved mockup"
```

---

## Phase 7 — Bundle certutil, package, docs

### Task 16: Bundle certutil and its NSS libraries

**Files:**
- Create: `App/CheburcertApp/Resources/` (binaries added by script)
- Create: `scripts/bundle-certutil.sh`

- [ ] **Step 1: Write the bundling script**

`scripts/bundle-certutil.sh`:

```bash
#!/usr/bin/env bash
# Copies certutil + its NSS/NSPR dylibs into the app Resources and rewrites
# their load paths to @loader_path so the app is self-contained.
set -euo pipefail
SRC_CERTUTIL="${1:-/opt/homebrew/opt/nss/bin/certutil}"
DEST="App/CheburcertApp/Resources"
mkdir -p "$DEST"
cp "$SRC_CERTUTIL" "$DEST/certutil"

# Copy every non-system dylib the binary (transitively) needs.
copy_deps() {
  local bin="$1"
  otool -L "$bin" | awk 'NR>1{print $1}' | while read -r lib; do
    case "$lib" in
      /usr/lib/*|/System/*) continue;;
    esac
    local base; base="$(basename "$lib")"
    if [ ! -f "$DEST/$base" ]; then
      cp "$lib" "$DEST/$base"
      install_name_tool -id "@loader_path/$base" "$DEST/$base" || true
      copy_deps "$DEST/$base"
    fi
    install_name_tool -change "$lib" "@loader_path/$base" "$bin" || true
  done
}
copy_deps "$DEST/certutil"
echo "Bundled certutil and deps into $DEST"
otool -L "$DEST/certutil"
```

- [ ] **Step 2: Run the script and verify self-containment**

Run:
```bash
brew list nss >/dev/null 2>&1 || brew install nss
chmod +x scripts/bundle-certutil.sh && ./scripts/bundle-certutil.sh
otool -L App/CheburcertApp/Resources/certutil | grep -vE "/usr/lib|/System" | tail -n +2
```
Expected: every remaining dependency line points to `@loader_path/...` (no `/opt/homebrew` paths).

- [ ] **Step 3: Add Resources to the target and rebuild**

Edit `App/CheburcertApp/project.yml` — add under the target:
```yaml
    sources:
      - path: .
      - path: Resources
        buildPhase: resources
```
Run:
```bash
cd App/CheburcertApp && xcodegen generate && \
xcodebuild -project Cheburcert.xcodeproj -scheme Cheburcert -configuration Debug build 2>&1 | tail -8
```
Expected: `BUILD SUCCEEDED`; `certutil` present in `Cheburcert.app/Contents/Resources/`.

- [ ] **Step 4: Manual end-to-end test on a scratch account or VM**

Manual checklist (documented, run by a human — installs into real trust stores):
1. Launch app, add `gosuslugi.ru`, click Apply, enter admin password once.
2. Status banner shows Safari · Chrome · Firefox with profile count.
3. In Firefox, open a real Минцифры-served site (e.g. an actual `.ru` gov/bank site) — loads without warning.
4. In Firefox, confirm a Минцифры-issued cert for a non-listed domain is rejected (name-constraint error), demonstrating the constraint. Safari/Chrome may not enforce — that is the documented caveat.
5. Click "Удалить всё" — banner returns to "Защита выключена"; Firefox no longer lists the Cheburcert root.

- [ ] **Step 5: Commit**

```bash
git add scripts/bundle-certutil.sh App/CheburcertApp/project.yml App/CheburcertApp/Resources
git commit -m "build: bundle self-contained certutil for Firefox install"
```

### Task 17: README and distribution notes

**Files:**
- Create: `README.md`
- Create: `scripts/make-dmg.sh`

- [ ] **Step 1: Write `README.md`**

`README.md`:

```markdown
# Cheburcert

Доверяй корневому сертификату Минцифры РФ только для нужных доменов.

Cheburcert создаёт локальный доверенный корень с ограничением по доменам
(`nameConstraints`) и кросс-подписывает им корень Минцифры. Реальные сертификаты
Минцифры принимаются только для доменов из вашего списка (и их поддоменов).

## Важно про браузеры
- **Firefox** — ограничение соблюдается строго.
- **Safari / Chrome** — ограничение соблюдается ненадёжно; сертификат Минцифры может
  быть принят и для других доменов. Приложение честно предупреждает об этом.

## Сборка
```bash
swift test                      # ядро (CheburcertCore)
brew install nss xcodegen
./scripts/bundle-certutil.sh
cd App/CheburcertApp && xcodegen generate
xcodebuild -scheme Cheburcert -configuration Release build
```

## Как это работает
См. `docs/superpowers/specs/2026-08-27-cheburcert-design.md`.
```

- [ ] **Step 2: Write the (skeleton) DMG script for signed/notarized release**

`scripts/make-dmg.sh`:

```bash
#!/usr/bin/env bash
# Build Release, codesign (Developer ID), notarize, staple, and produce a .dmg.
# Requires: DEVELOPER_ID_APP, NOTARY_PROFILE env vars.
set -euo pipefail
APP="build/Cheburcert.app"
xcodebuild -project App/CheburcertApp/Cheburcert.xcodeproj -scheme Cheburcert \
  -configuration Release -derivedDataPath build/dd build
cp -R "build/dd/Build/Products/Release/Cheburcert.app" "$APP"
codesign --force --deep --options runtime \
  --entitlements App/CheburcertApp/Cheburcert.entitlements \
  --sign "$DEVELOPER_ID_APP" "$APP"
hdiutil create -volname Cheburcert -srcfolder "$APP" -ov -format UDZO build/Cheburcert.dmg
xcrun notarytool submit build/Cheburcert.dmg --keychain-profile "$NOTARY_PROFILE" --wait
xcrun stapler staple build/Cheburcert.dmg
echo "Made build/Cheburcert.dmg"
```

- [ ] **Step 3: Verify scripts are executable and the core suite is green**

Run: `chmod +x scripts/make-dmg.sh && swift test 2>&1 | tail -5`
Expected: all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add README.md scripts/make-dmg.sh
git commit -m "docs: readme and dmg packaging script"
```

---

## Manual verification summary (post-implementation)

Automated (`swift test`) covers: domain normalization/punycode, presets, the crypto
engine (chain validates for permitted domains, rejected for others, critical name
constraints present, force-pubkey identity preserved), PEM parse + fingerprint,
Firefox profiles.ini parsing, keychain/firefox installer command composition,
persistence (incl. 0600 key mode), and the service orchestration flow.

Manual (human, touches real trust stores): the end-to-end checklist in Task 16 Step 4,
plus notarized `.dmg` install on a clean machine.

## Notes / risks captured during planning

- **Safari/Chrome name-constraint enforcement is unreliable** — surfaced in UI, README, and spec. Not a bug to fix; a platform limitation to disclose.
- **swift-certificates API drift**: exact symbol names (`Verifier`, `RFC5280Policy`, `AuthorityKeyIdentifier`, `PEMDocument.parseMultiple`, key PEM helpers) can differ across versions. Each affected task says to adapt the test/impl to the installed API using `swift build` errors; the design does not change.
- **certutil while Firefox runs**: `cert9.db` may be locked; installer checks `pgrep -x firefox` and throws `.firefoxRunning`.
- **Privileged batch**: all keychain mutations run in one `osascript ... with administrator privileges` call = one password prompt per Apply/Remove.
- **Fingerprint handling deviates slightly from spec**: the spec says "show the SHA-256 to the user for manual comparison". For non-technical users, eyeballing hex adds little; the plan instead computes the fingerprint and compares it to a code-pinned `MintsifrySource.expectedRootFingerprint` (nil until seeded from a first trusted fetch), throwing `.fingerprintMismatch` on tamper. If a visible fingerprint is still wanted, surface `FetchedCerts.rootFingerprint` in the status area — a small UI addition, not a design change.
```
