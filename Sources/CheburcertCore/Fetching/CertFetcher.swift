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
    /// Deadline for the WHOLE fetch, not per request. `URLSession` defaults give 60s per
    /// request and 7 days per resource; with three sequential sources that is minutes of a
    /// spinner with no way out, on a path the user reaches from two different buttons.
    let deadline: Duration

    public init(session: URLSession = .shared, deadline: Duration = .seconds(20)) {
        self.session = session
        self.deadline = deadline
    }

    public func fetch(from urls: [URL] = MintsifrySource.urls) async throws -> FetchedCerts {
        try await withThrowingTaskGroup(of: FetchedCerts?.self) { group in
            group.addTask { try await self.download(from: urls) }
            group.addTask {
                try? await Task.sleep(for: self.deadline)
                throw CheburcertError.network("превышен таймаут \(self.deadline)")
            }
            guard let first = try await group.next(), let result = first else {
                throw CheburcertError.network("загрузка прервана")
            }
            group.cancelAll()
            return result
        }
    }

    private func download(from urls: [URL]) async throws -> FetchedCerts {
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
