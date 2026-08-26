import SwiftUI
import CheburcertCore

struct DomainListPane: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Разрешённые домены").font(.headline)
                Text("· \(model.domains.count)").foregroundStyle(.secondary)
                Spacer()
                Text("каждый домен включает поддомены")
                    .font(.caption).foregroundStyle(.secondary)
            }
            HStack {
                TextField("например, sberbank.ru или .ru", text: $model.newDomain)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { model.addDomain() }
                Button("Добавить") { model.addDomain() }
            }
            TextField("Поиск по списку", text: $model.searchText).textFieldStyle(.roundedBorder)
            List {
                ForEach(model.filteredDomains, id: \.self) { d in
                    HStack {
                        Text(d)
                        Spacer()
                        Button {
                            model.remove(d)
                        } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }
                        .buttonStyle(.plain)
                    }
                }
            }
            .frame(minHeight: 180)
            Text("Быстрые наборы:").font(.caption).foregroundStyle(.secondary)
            HStack {
                ForEach(model.presets) { p in
                    Button("+ \(p.name)") { model.applyPreset(p) }.controlSize(.small)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
