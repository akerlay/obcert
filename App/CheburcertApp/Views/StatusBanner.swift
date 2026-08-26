import SwiftUI

struct StatusBanner: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: model.installState.keychainInstalled ? "checkmark.seal.fill" : "xmark.seal")
                .foregroundStyle(model.installState.keychainInstalled ? .green : .secondary)
                .font(.title2)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.status).font(.headline)
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Проверить") { model.refreshStatus() }
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
        .background(model.installState.keychainInstalled ? Color.green.opacity(0.12) : Color.gray.opacity(0.1))
    }
    var subtitle: String {
        let ff = model.installState.firefoxProfileCount
        var parts: [String] = []
        if model.installState.keychainInstalled { parts.append("Safari · Chrome") }
        if ff > 0 { parts.append("Firefox (\(ff) проф.)") }
        return parts.isEmpty ? "Ничего не установлено" : "Установлено: " + parts.joined(separator: " · ")
    }
}
