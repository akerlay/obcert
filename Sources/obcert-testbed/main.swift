import Foundation
import TestbedKit

/// Generates the name-constraint testbed: a stand-in Минцифры PKI whose key we hold, a
/// constrained bundle built by the production `CryptoEngine`, an iOS profile built by the
/// production `PhoneExporter`, and three leaves that differ only in the name they claim.

struct Options {
    var out: URL
    var ip: String
    var port: Int
    var tag: String?
    var layout: ProfileLayout
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("obcert-testbed: \(message)\n".utf8))
    exit(2)
}

func detectLANIP() -> String? {
    for interface in ["en0", "en1"] {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/sbin/ipconfig")
        proc.arguments = ["getifaddr", interface]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = Pipe()
        guard (try? proc.run()) != nil else { continue }
        proc.waitUntilExit()
        let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let ip = out.trimmingCharacters(in: .whitespacesAndNewlines)
        if !ip.isEmpty { return ip }
    }
    return nil
}

func parseOptions() -> Options {
    var out: String?
    var ip: String?
    var tag: String?
    var layout = ProfileLayout.pkcs1
    var port = 8443
    var args = Array(CommandLine.arguments.dropFirst())
    while let flag = args.first {
        args.removeFirst()
        switch flag {
        case "--out":
            guard let v = args.first else { fail("--out requires a directory") }
            out = v; args.removeFirst()
        case "--ip":
            guard let v = args.first else { fail("--ip requires an IPv4 address") }
            ip = v; args.removeFirst()
        case "--tag":
            guard let v = args.first, !v.isEmpty,
                  v.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" }) else {
                fail("--tag requires a short alphanumeric label")
            }
            tag = v; args.removeFirst()
        case "--layout":
            guard let v = args.first, let parsed = ProfileLayout(rawValue: v) else {
                fail("--layout must be one of: "
                     + ProfileLayout.allCases.map(\.rawValue).joined(separator: ", "))
            }
            layout = parsed; args.removeFirst()
        case "--port":
            guard let v = args.first, let p = Int(v), (1...65535).contains(p) else {
                fail("--port requires a number in 1...65535")
            }
            port = p; args.removeFirst()
        case "-h", "--help":
            print("usage: obcert-testbed --out <dir> [--ip <ipv4>] [--port <n>] [--tag <label>]")
            print("  --tag  makes this run's hostnames unique, so a certificate exception")
            print("         the user clicked through earlier cannot replay as a pass")
            exit(0)
        default:
            fail("unknown argument \(flag)")
        }
    }
    guard let out else { fail("--out <dir> is required") }
    guard let resolved = ip ?? detectLANIP() else {
        fail("could not detect a LAN address on en0/en1 — pass --ip explicitly")
    }
    return Options(out: URL(fileURLWithPath: out), ip: resolved, port: port, tag: tag, layout: layout)
}

let options = parseOptions()
let output = try await TestbedBuilder().build(
    lanIP: options.ip, port: options.port, tag: options.tag,
    layout: options.layout, to: options.out)

print("testbed: \(output.directory.path)")
print("profile: \(output.manifest.mobileconfig)")
print("manifest: \(output.manifestFile.path)")
print("")
print("case  expect   offline  url")
var mismatches: [String] = []
for (index, testCase) in output.manifest.cases.enumerated() {
    let offline = output.offlineVerdicts[index]
    let mark = offline == testCase.expectation ? "ok " : "MISMATCH"
    print("\(testCase.name.padding(toLength: 6, withPad: " ", startingAt: 0))"
        + "\(testCase.expectation.rawValue.padding(toLength: 9, withPad: " ", startingAt: 0))"
        + "\(offline.rawValue.padding(toLength: 9, withPad: " ", startingAt: 0))"
        + "\(testCase.url)   \(mark)")
    if offline != testCase.expectation {
        mismatches.append("\(testCase.name): expected \(testCase.expectation.rawValue), got \(offline.rawValue)")
    }
}
print("")
print("WARNING: \(output.directory.path) holds the stand-in CA private key, which can mint")
print("         certificates for \(output.manifest.permittedHost). Delete the directory and")
print("         remove the test profile from the phone when finished.")
print("")
print("next: python3 scripts/testbed-server.py --manifest \(output.manifestFile.path)")
print("      bash scripts/testbed-verify.sh \(output.directory.path)")

if !mismatches.isEmpty {
    FileHandle.standardError.write(Data(("offline verdicts disagree with the matrix:\n  "
        + mismatches.joined(separator: "\n  ") + "\n").utf8))
    exit(1)
}
