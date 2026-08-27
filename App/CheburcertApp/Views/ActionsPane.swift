import SwiftUI

struct ActionsPane: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(spacing: 12) {
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Применить изменения").font(.headline)
                    Text("Пересоберём ограниченный корень и обновим браузеры. macOS попросит подтвердить доверие сертификату (пароль пользователя).")
                        .font(.caption).foregroundStyle(.secondary)
                    Button {
                        model.apply()
                    } label: { Text("Применить").frame(maxWidth: .infinity) }
                    .buttonStyle(.borderedProminent).tint(.green)
                    .disabled(model.isBusy || model.domains.isEmpty)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Для телефона").font(.headline)
                    Text("Сохранить сертификат: профиль .mobileconfig для iPhone/iPad и .pem для Android.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button {
                        model.exportForPhone()
                    } label: { Text("Экспорт для телефона…").frame(maxWidth: .infinity) }
                    .disabled(model.isBusy || model.domains.isEmpty)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Отключить защиту").font(.headline).foregroundStyle(.red)
                    Text("Удалить всё установленное из Safari, Chrome и Firefox.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button(role: .destructive) {
                        model.removeAll()
                    } label: { Text("Удалить всё").frame(maxWidth: .infinity) }
                    .disabled(model.isBusy)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            if model.isBusy { ProgressView().padding(.top, 4) }
        }
        .frame(width: 280)
    }
}
