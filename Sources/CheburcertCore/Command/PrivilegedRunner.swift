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
