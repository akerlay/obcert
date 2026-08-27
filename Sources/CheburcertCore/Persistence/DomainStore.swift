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
