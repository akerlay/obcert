import Foundation
import X509
import TestbedKit

/// Adapter over `TestbedKit.FakeGovPKI` so the existing tests keep their call sites.
///
/// The generator itself lives in `TestbedKit` because the testbed executable needs the
/// leaf private keys to serve TLS; tests only need the certificates.
struct TestPKI {
    private let pki: FakeGovPKI
    let root: Certificate
    let intermediate: Certificate
    let notBefore: Date

    init() throws {
        // 2048-bit root keeps the test suite fast; the testbed uses 4096 to mimic the real one.
        pki = try FakeGovPKI(rootKeySize: .bits2048)
        root = pki.root
        intermediate = pki.subCA
        notBefore = pki.notBefore
    }

    func leaf(host: String) throws -> Certificate { try pki.leaf(dnsName: host).certificate }
    func leaf(ipv4: String) throws -> Certificate { try pki.leaf(ipv4: ipv4).certificate }
}
