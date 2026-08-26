import Foundation

public struct InstallState: Sendable, Equatable {
    public var keychainInstalled: Bool
    public var firefoxProfileCount: Int
    public var installedDomains: [String]
    public init(keychainInstalled: Bool, firefoxProfileCount: Int, installedDomains: [String]) {
        self.keychainInstalled = keychainInstalled
        self.firefoxProfileCount = firefoxProfileCount
        self.installedDomains = installedDomains
    }
    public static let notInstalled = InstallState(
        keychainInstalled: false, firefoxProfileCount: 0, installedDomains: [])
}
