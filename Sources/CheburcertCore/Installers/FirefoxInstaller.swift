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

    public func install(_ bundle: TrustBundle) throws {
        let profiles = profilesProvider()
        guard !profiles.isEmpty else { return } // Firefox absent: skip silently
        if isFirefoxRunning() { throw CheburcertError.firefoxRunning }

        try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        let rootPath = try write(bundle.localRoot, "ff-localroot.crt")

        for profile in profiles {
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
