import Foundation
import SwiftUI
import AppKit
import CheburcertCore

@MainActor
final class AppModel: ObservableObject {
    @Published var domains: [String] = []
    @Published var newDomain: String = ""
    @Published var searchText: String = ""
    @Published var status: String = "Проверка…"
    @Published var isBusy = false
    @Published var lastError: String?
    @Published var lastInfo: String?
    @Published var installState: InstallState = .notInstalled

    // Original-root gate
    @Published var originalRootBlocked = false
    @Published var didCheckOriginal = false
    private var originalPresence: OriginalRootPresence = .absent
    private let detector = MintsifryDetector()

    let presets = Presets.all
    private let service: CheburcertService

    init() {
        let certutil = Bundle.main.url(forResource: "certutil", withExtension: nil)?.path ?? "/usr/bin/false"
        let workDir = AppPaths.appSupport.appendingPathComponent("work")
        self.service = CheburcertService(
            fetch: { try await CertFetcher().fetch() },
            keychain: KeychainInstaller(workDir: workDir),
            firefox: FirefoxInstaller(certutilPath: certutil, workDir: workDir))
        self.domains = service.savedDomains()
        refreshStatus()
        checkOriginalRoot()
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
    func clearDomains() { domains.removeAll() }

    func applyPreset(_ p: DomainPreset) {
        for d in p.domains where !domains.contains(d) { domains.append(d) }
    }

    func apply() {
        isBusy = true; lastError = nil
        let ds = domains
        Task {
            var ok = false
            do { try await service.apply(domains: ds); ok = true }
            catch let e as CheburcertError { lastError = Self.message(for: e) }
            catch { lastError = error.localizedDescription }
            refreshStatus(); isBusy = false
            if ok {
                lastInfo = "Готово. Перезапустите браузеры (полностью закройте и откройте заново), чтобы изменения вступили в силу — Chrome и Safari перечитывают доверие к сертификатам только при запуске."
            }
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

    func exportForPhone() {
        guard !domains.isEmpty else { lastError = "Список доменов пуст."; return }
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.prompt = "Экспортировать сюда"
        panel.message = "Выберите папку для файлов сертификата"
        guard panel.runModal() == .OK, let dir = panel.url else { return }
        isBusy = true; lastError = nil
        let ds = domains
        Task {
            do {
                let bundle = try await service.buildBundleForExport(domains: ds)
                let res = try PhoneExporter().export(bundle, to: dir)
                NSWorkspace.shared.activateFileViewerSelecting([res.mobileconfig])
            } catch let e as CheburcertError { lastError = Self.message(for: e) }
            catch { lastError = error.localizedDescription }
            isBusy = false
        }
    }

    func checkOriginalRoot() {
        Task {
            let p = (try? detector.detect()) ?? .absent
            originalPresence = p
            originalRootBlocked = p.isPresent
            didCheckOriginal = true
        }
    }

    func removeOriginalRoot() {
        isBusy = true; lastError = nil
        let p = originalPresence
        Task {
            do { try detector.remove(p, privileged: OSAScriptPrivilegedRunner()) }
            catch let e as CheburcertError { lastError = Self.message(for: e) }
            catch { lastError = error.localizedDescription }
            let np = (try? detector.detect()) ?? .absent
            originalPresence = np
            originalRootBlocked = np.isPresent
            isBusy = false
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
