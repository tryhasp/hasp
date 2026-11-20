import HaspDesign
import SwiftUI

struct ProviderListView: View {
  @Bindable var model: ProviderScreenModel

  var body: some View {
    List {
      if model.rows.isEmpty {
        Text("provider.empty")
          .foregroundStyle(HaspColor.textSecondary)
          .accessibilityIdentifier("provider.empty")
      }
      ForEach(model.rows) { row in
        Button {
          Task { await model.select(row) }
        } label: {
          ProviderRowView(row: row)
        }
        .accessibilityIdentifier("provider.row.\(row.title)")
      }
    }
    .listStyle(.plain)
    .searchable(text: $model.query, prompt: Text("provider.search"))
    .task(id: model.query) { await model.reload() }
  }
}

struct ProviderRowView: View {
  let row: ProviderRow

  var body: some View {
    HStack(spacing: 12) {
      Image(systemName: symbol)
        .foregroundStyle(HaspColor.accent)
        .frame(width: 24)
        .accessibilityHidden(true)
      VStack(alignment: .leading, spacing: 2) {
        Text(verbatim: row.title)
          .foregroundStyle(HaspColor.text)
        if !row.subtitle.isEmpty {
          Text(verbatim: row.subtitle)
            .font(.footnote)
            .foregroundStyle(HaspColor.textSecondary)
        }
      }
      Spacer(minLength: 0)
    }
    .contentShape(Rectangle())
  }

  private var symbol: String {
    switch row.kind {
    case .password: "key"
    case .passkey: "person.badge.key"
    case .oneTimeCode: "number"
    case .text: "text.cursor"
    }
  }
}
