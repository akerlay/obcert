import Foundation
import X509

public struct FirefoxInstaller: TrustStoreInstaller {
    let certutilPath: String
    let runner: CommandRunner
    let profilesProvider: @Sendable () -> [URL]
    let isFirefoxRunning: @Sendable () -> Bool
    let workDir: URL

    public init(
        certutilPath: String,
        runner: CommandRunner = ProcessCommandRunner(),
        profiles: @escaping @Sendable () -> [URL] = { FirefoxProfiles.discover() },
        isFirefoxRunning: @escaping @Sendable () -> Bool = FirefoxInstaller.defaultRunningCheck,
        workDir: URL
    ) {
        self.certutilPath = certutilPath
        self.runner = runner
        self.profilesProvider = profiles
        self.isFirefoxRunning = isFirefoxRunning
        self.workDir = workDir
    }

    /// Cross-cert nickname used across install/removeAll.
    static let crossNickname = "Cheburcert Cross"
    /// Nickname for intermediate at index `i`.
    static func intermediateNickname(_ i: Int) -> String { "Cheburcert Intermediate \(i)" }
    /// Upper bound of intermediates removeAll clears when it has no bundle.
    static let intermediateSweepCount = 10

    public func install(_ bundle: TrustBundle) throws {
        let profiles = profilesProvider()
        guard !profiles.isEmpty else { return } // Firefox absent: skip silently
        if isFirefoxRunning() { throw CheburcertError.firefoxRunning }

        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        let rootPath = try write(bundle.localRoot, "ff-localroot.crt")
        let crossPath = try write(bundle.crossCert, "ff-cross.crt")
        var interPaths: [(nick: String, path: String)] = []
        for (i, cert) in bundle.intermediates.enumerated() {
            interPaths.append((Self.intermediateNickname(i), try write(cert, "ff-inter-\(i).crt")))
        }

        for profile in profiles {
            let dir = "sql:\(profile.path)"
            // Trust anchor: the local constrained root.
            try add(dir: dir, nick: KeychainInstaller.localRootCN, trust: "C,,", path: rootPath)
            // Bridging certs: present but not explicitly trusted.
            try add(dir: dir, nick: Self.crossNickname, trust: ",,", path: crossPath)
            for inter in interPaths {
                try add(dir: dir, nick: inter.nick, trust: ",,", path: inter.path)
            }
        }
    }

    /// Delete-first (idempotent), then add. Throws `.commandFailed` on any add failure.
    private func add(dir: String, nick: String, trust: String, path: String) throws {
        _ = try? runner.run(certutilPath, ["-D", "-d", dir, "-n", nick])
        let res = try runner.run(certutilPath, ["-A", "-d", dir, "-t", trust, "-n", nick, "-i", path])
        if res.exitCode != 0 {
            throw CheburcertError.commandFailed(command: "certutil", exitCode: res.exitCode, stderr: res.stderr)
        }
    }

    public func removeAll() throws {
        var nicks = [KeychainInstaller.localRootCN, Self.crossNickname]
        nicks += (0..<Self.intermediateSweepCount).map { Self.intermediateNickname($0) }
        for profile in profilesProvider() {
            let dir = "sql:\(profile.path)"
            for nick in nicks {
                _ = try? runner.run(certutilPath, ["-D", "-d", dir, "-n", nick])
            }
        }
    }

    public static let defaultRunningCheck: @Sendable () -> Bool = {
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
