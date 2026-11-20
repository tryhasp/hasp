import HaspDesign
import HaspKit
import SwiftUI

struct ItemListView: View {
  @Bindable var library: LibraryModel
  @FocusState.Binding var listFocused: Bool

  var body: some View {
    VStack(spacing: 0) {
      header
      if library.visibleItems.isEmpty {
        EmptyListView(isSearching: !library.searchText.isEmpty)
      } else {
        List(library.visibleItems, selection: $library.selectedKey) { item in
          ItemRowView(
            item: item,
            selected: item.key == library.selectedKey,
            sharedVault: library.sharedName(for: item),
          )
          .tag(item.key)
          .contextMenu { ItemContextMenu(library: library, item: item) }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .focused($listFocused)
        .focusEffectDisabled()
        .accessibilityLabel("list.label")
        .accessibilityIdentifier("item.list")
      }
    }
    .background(HaspColor.list)
  }

  private var header: some View {
    HStack(alignment: .firstTextBaseline, spacing: HaspSpace.s8) {
      Text(library.title)
        .haspText(HaspFont.bodyLargeMedium)
        .foregroundStyle(HaspColor.text)
        .accessibilityAddTraits(.isHeader)
      Text("list.count \(library.visibleItems.count)")
        .haspText(HaspFont.caption)
        .foregroundStyle(HaspColor.textSecondary)
      Spacer()
      IconButton(systemName: "plus", label: "list.new") { library.beginCreate(kind: "login") }
        .accessibilityIdentifier("item.new")
    }
    .padding(.horizontal, HaspSpace.s16)
    .frame(height: HaspSize.toolbarHeight)
  }
}

struct ItemRowView: View {
  let item: ItemSummary
  let selected: Bool
  var sharedVault: String?

  var body: some View {
    HStack(spacing: HaspSpace.s10) {
      MonogramTile(title: item.title, selected: selected)
      VStack(alignment: .leading, spacing: 0) {
        Text(item.title)
          .haspText(selected ? HaspFont.bodyStrong : HaspFont.bodyMedium)
          .foregroundStyle(HaspColor.text)
        Text(item.subtitle.isEmpty ? "—" : item.subtitle)
          .haspText(HaspFont.caption)
          .foregroundStyle(HaspColor.textSecondary)
          .lineLimit(1)
      }
      Spacer(minLength: 0)
      if let sharedVault {
        Label(sharedVault, systemImage: "person.2")
          .haspText(HaspFont.caption)
          .foregroundStyle(HaspColor.textSecondary)
          .lineLimit(1)
      }
      if item.favourite {
        Image(systemName: "star.fill")
          .font(.system(size: HaspSize.iconSmall))
          .foregroundStyle(HaspColor.textSecondary)
          .accessibilityLabel("list.favourite")
      }
    }
    .frame(minHeight: HaspSize.rowHeight)
    .listRowBackground(
      RoundedRectangle(cornerRadius: HaspRadius.row)
        .fill(selected ? HaspColor.selectedRow : .clear)
        .padding(.horizontal, HaspSpace.s6)
    )
    .accessibilityElement(children: .combine)
    .accessibilityIdentifier("item.row")
    .accessibilityAddTraits(selected ? .isSelected : [])
  }
}

struct EmptyListView: View {
  let isSearching: Bool

  var body: some View {
    VStack {
      Text(isSearching ? "list.empty.search" : "list.empty")
        .haspText(HaspFont.body)
        .foregroundStyle(HaspColor.textSecondary)
        .multilineTextAlignment(.center)
        .padding(HaspSpace.s24)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }
}

struct ItemContextMenu: View {
  let library: LibraryModel
  let item: ItemSummary

  var body: some View {
    Button(item.favourite ? "item.unfavourite" : "item.favourite") {
      Task { await library.toggleFavourite(item) }
    }
    switch item.status {
    case .active:
      Button("item.archive") { Task { await library.setStatus(item.key, .archived) } }
      Button("item.trash") { Task { await library.setStatus(item.key, .trashed) } }
    case .archived, .trashed:
      Button("item.restore") { Task { await library.setStatus(item.key, .active) } }
      if item.status == .trashed {
        Button("item.deleteForever") { Task { await library.deletePermanently(item.key) } }
      }
    }
  }
}
