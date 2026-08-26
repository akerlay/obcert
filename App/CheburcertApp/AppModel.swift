import Foundation
import SwiftUI
import CheburcertCore

@MainActor
final class AppModel: ObservableObject {
    @Published var domains: [String] = []
    @Published var newDomain: String = ""
    @Published var searchText: String = ""
    @Published var status: String = "Проверка…"
    @Published var isBusy = false
    @Published var lastError: String?
    @Published var installState: InstallState = .notInstalled

    let presets = Presets.all
    private let service: CheburcertService

    init() {
        let certutil = Bundle.main.url(forResource: "certutil", withExtension: nil)?.path ?? "/usr/bin/false"
        let workDir = AppPaths.appSupport.appendingPathComponent("work")
        self.service = CheburcertService(
            fetch: { try await CertFetcher().fetch() },
            keychain: KeychainInstaller(privileged: OSAScriptPrivilegedRunner(), workDir: workDir),
            firefox: FirefoxInstaller(certutilPath: certutil, workDir: workDir))
        self.domains = service.savedDomains()
        refreshStatus()
    }

    var filteredDomains: [String] {
        searchText.isEmpty ? domains
            : domains.filter { $0.localizedCaseInsensitiveContains(searchText) }
    }

    func addDomain() {
        let raw = newDomain
        newDomain = ""
        do {
            let n = try DomainList.normalize(raw)
            if !domains.contains(n) { domains.append(n) }
        } catch { lastError = "Некорректный домен: \(raw)" }
    }

    func remove(_ domain: String) { domains.removeAll { $0 == domain } }

    func applyPreset(_ p: DomainPreset) {
        for d in p.domains where !domains.contains(d) { domains.append(d) }
    }

    func apply() {
        isBusy = true; lastError = nil
        let ds = domains
        Task {
            do { try await service.apply(domains: ds) }
            catch let e as CheburcertError { lastError = Self.message(for: e) }
            catch { lastError = error.localizedDescription }
            refreshStatus(); isBusy = false
        }
    }

    func removeAll() {
        isBusy = true; lastError = nil
        Task {
            do { try service.removeAll() }
            catch let e as CheburcertError { lastError = Self.message(for: e) }
            catch { lastError = error.localizedDescription }
            refreshStatus(); isBusy = false
        }
    }

    func refreshStatus() {
        let ff = FirefoxProfiles.discover().count
        installState = InstallState(
            keychainInstalled: FileManager.default.fileExists(atPath: AppPaths.localRootFile.path),
            firefoxProfileCount: ff, installedDomains: service.savedDomains())
        status = installState.keychainInstalled ? "Защита включена" : "Защита выключена"
    }

    static func message(for e: CheburcertError) -> String {
        switch e {
        case .firefoxRunning: return "Firefox запущен. Закройте его и повторите."
        case .authorizationDenied: return "Не введён пароль администратора."
        case .network(let m): return "Не удалось скачать сертификаты: \(m)"
        case .fingerprintMismatch: return "Отпечаток корня Минцифры не совпал — установка отменена."
        case .noFirefoxProfiles: return "Профили Firefox не найдены."
        case .invalidDomain(let d): return "Некорректный домен: \(d)"
        default: return "Ошибка: \(e)"
        }
    }
}
