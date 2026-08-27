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
