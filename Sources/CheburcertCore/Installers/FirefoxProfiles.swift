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
