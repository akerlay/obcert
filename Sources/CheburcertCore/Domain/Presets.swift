import Foundation

public struct DomainPreset: Identifiable, Sendable, Equatable {
    public let id: String
    public let name: String
    public let domains: [String]
}

public enum Presets {
    public static let all: [DomainPreset] = [
        DomainPreset(id: "gosuslugi", name: "Госуслуги", domains: [
            "gosuslugi.ru", "nalog.gov.ru", "pfr.gov.ru", "mos.ru",
        ]),
        DomainPreset(id: "banks", name: "Крупные банки", domains: [
            "sberbank.ru", "sber.ru", "vtb.ru", "tinkoff.ru",
            "alfabank.ru", "gazprombank.ru", "raiffeisen.ru", "psbank.ru",
        ]),
        DomainPreset(id: "zones", name: "Весь .ru / .рф / .su", domains: [
            ".ru", ".su", ".xn--p1ai",
        ]),
    ]
}
