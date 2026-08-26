import SwiftUI

struct WarningFooter: View {
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.yellow)
            Text("В Firefox ограничение по доменам работает строго. В Safari и Chrome оно соблюдается ненадёжно — там сертификат Минцифры может приниматься и для других доменов.")
                .font(.caption)
            Spacer()
        }
        .padding(.horizontal, 20).padding(.vertical, 12)
        .background(Color.yellow.opacity(0.12))
    }
}
