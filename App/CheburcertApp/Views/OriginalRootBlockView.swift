import SwiftUI

struct OriginalRootBlockView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.shield.fill")
                .font(.system(size: 52)).foregroundStyle(.orange)
            Text("Обнаружен оригинальный корень Минцифры").font(.title2).bold()
            Text("Пока в системе установлен доверенным оригинальный (неограниченный) сертификат Минцифры, ограничение по доменам можно обойти — он должен быть удалён, чтобы obcert работал корректно.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
                .frame(maxWidth: 480)
            HStack(spacing: 12) {
                Button("Проверить снова") { model.checkOriginalRoot() }
                Button {
                    model.removeOriginalRoot()
                } label: { Text("Удалить оригинал Минцифры").frame(minWidth: 220) }
                .buttonStyle(.borderedProminent).tint(.red)
                .disabled(model.isBusy)
            }
            if model.isBusy { ProgressView().padding(.top, 4) }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
