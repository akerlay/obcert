import Foundation

public struct CommandResult: Sendable, Equatable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String
}

public protocol CommandRunner: Sendable {
    func run(_ executable: String, _ arguments: [String], workingDirectory: String?) throws -> CommandResult
}

public extension CommandRunner {
    /// Convenience for callers that don't need a working directory.
    func run(_ executable: String, _ arguments: [String]) throws -> CommandResult {
        try run(executable, arguments, workingDirectory: nil)
    }
}

/// Runs a subprocess unprivileged (used for certutil and read-only `security` calls).
public struct ProcessCommandRunner: CommandRunner {
    public init() {}
    public func run(_ executable: String, _ arguments: [String], workingDirectory: String?) throws -> CommandResult {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: executable)
        proc.arguments = arguments
        // certutil dlopen()s its NSS softoken modules by leaf name; running it with the
        // bundle dir as cwd lets dyld find them there.
        if let wd = workingDirectory { proc.currentDirectoryURL = URL(fileURLWithPath: wd) }
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
    public func run(_ executable: String, _ arguments: [String], workingDirectory: String?) throws -> CommandResult {
        let call = Call(executable: executable, arguments: arguments)
        calls.append(call)
        return resultForCall?(call) ?? stubResult
    }
}
