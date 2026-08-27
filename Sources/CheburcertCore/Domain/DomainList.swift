import Foundation

public enum DomainList {
    /// Normalize one user-entered domain into a name-constraint DNS suffix.
    /// - Strips scheme, "*.", surrounding whitespace, trailing "/" and dots (except a single leading dot).
    /// - Lowercases and converts Cyrillic/IDN labels to Punycode (A-labels).
    /// - A single leading dot ("zone" form like ".ru") is preserved.
    public static func normalize(_ raw: String) throws -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let range = s.range(of: "://") { s = String(s[range.upperBound...]) }
        if let slash = s.firstIndex(of: "/") { s = String(s[..<slash]) }
        while s.hasPrefix("*.") { s.removeFirst(2) }
        s = s.trimmingCharacters(in: .whitespaces)

        let leadingDot = s.hasPrefix(".")
        let core = leadingDot ? String(s.dropFirst()) : s
        guard !core.isEmpty else { throw CheburcertError.invalidDomain(raw) }

        let puny = try punycode(core)
        // Reject a single bare label with no dot and no leading-dot zone form.
        if !leadingDot && !puny.contains(".") {
            throw CheburcertError.invalidDomain(raw)
        }
        return leadingDot ? "." + puny : puny
    }

    public static func normalizedUnique(_ raws: [String]) throws -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for r in raws {
            let n = try normalize(r)
            if seen.insert(n).inserted { out.append(n) }
        }
        return out
    }

    /// Convert each dot-separated label to its IDNA ASCII (Punycode) form when needed.
    static func punycode(_ host: String) throws -> String {
        let labels = host.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        let encoded = try labels.map { label -> String in
            if label.allSatisfy({ $0.isASCII }) { return label }
            guard let a = IDNA.encode(label) else { throw CheburcertError.invalidDomain(host) }
            return a
        }
        return encoded.joined(separator: ".")
    }
}

/// Minimal RFC 3492 Punycode encoder producing "xn--" A-labels.
enum IDNA {
    static func encode(_ label: String) -> String? {
        let input = Array(label.unicodeScalars)
        var output = input.filter { $0.isASCII }.map { Character($0) }
        let basicCount = output.count
        var handled = basicCount
        if basicCount > 0 { output.append("-") }

        var n: UInt32 = 0x80
        var delta: UInt32 = 0
        var bias: UInt32 = 72
        let base: UInt32 = 36, tmin: UInt32 = 1, tmax: UInt32 = 26
        let skew: UInt32 = 38, damp: UInt32 = 700

        func adapt(_ d: UInt32, _ numPoints: UInt32, _ firstTime: Bool) -> UInt32 {
            var delta = firstTime ? d / damp : d / 2
            delta += delta / numPoints
            var k: UInt32 = 0
            while delta > ((base - tmin) * tmax) / 2 {
                delta /= (base - tmin); k += base
            }
            return k + ((base - tmin + 1) * delta) / (delta + skew)
        }

        while handled < input.count {
            let m = input.filter { $0.value >= n }.map { $0.value }.min()!
            delta += (m - n) * UInt32(handled + 1)
            n = m
            for scalar in input {
                if scalar.value < n { delta += 1 }
                if scalar.value == n {
                    var q = delta
                    var k = base
                    while true {
                        let t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias)
                        if q < t { break }
                        let code = t + (q - t) % (base - t)
                        output.append(digit(code))
                        q = (q - t) / (base - t)
                        k += base
                    }
                    output.append(digit(q))
                    bias = adapt(delta, UInt32(handled + 1), handled == basicCount)
                    delta = 0
                    handled += 1
                }
            }
            delta += 1
            n += 1
        }
        return "xn--" + String(output)
    }

    private static func digit(_ d: UInt32) -> Character {
        // 0..25 -> 'a'..'z', 26..35 -> '0'..'9'
        if d < 26 { return Character(UnicodeScalar(d + 97)!) }
        return Character(UnicodeScalar(d - 26 + 48)!)
    }
}
