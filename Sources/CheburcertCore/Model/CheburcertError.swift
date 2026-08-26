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
