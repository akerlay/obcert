import SwiftUI
import CheburcertCore

struct ContentView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(spacing: 0) {
            StatusBanner()
            HStack(alignment: .top, spacing: 16) {
                DomainListPane()
                ActionsPane()
            }.padding(20)
            Spacer(minLength: 0)
            WarningFooter()
        }
        .alert("Ошибка", isPresented: Binding(
            get: { model.lastError != nil }, set: { if !$0 { model.lastError = nil } })) {
            Button("OK", role: .cancel) { model.lastError = nil }
        } message: { Text(model.lastError ?? "") }
    }
}
