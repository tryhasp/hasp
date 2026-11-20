#if os(macOS)
  import HaspDesign
  import HaspKit
  import SwiftUI

  struct SidebarView: View {
    @Bindable var library: LibraryModel

    var body: some View {
      VStack(spacing: 0) {
        List(selection: $library.selection) {
          Section("sidebar.vaults") {
            ForEach(library.vaults) { vault in
              SidebarRow(
                title: vault.displayName,
                systemImage: vault.members > 1 ? "person.2" : "person",
                count: library.count(for: .vault(vault.id)),
              )
              .tag(SidebarSelection.vault(vault.id))
            }
          }
          Section("sidebar.categories") {
            SidebarRow(
              title: String(localized: "sidebar.all"),
              systemImage: "square.grid.2x2",
              count: library.count(for: .all),
            )
            .tag(SidebarSelection.all)
            SidebarRow(
              title: String(localized: "sidebar.favourites"),
              systemImage: "star",
              count: library.count(for: .favourites),
            )
            .tag(SidebarSelection.favourites)
            ForEach(usedCategories) { category in
              SidebarRow(
                title: LibraryModel.name(category),
                systemImage: CategoryIcon.symbol(category.icon),
                count: library.count(for: .category(category.id)),
              )
              .tag(SidebarSelection.category(category.id))
            }
          }
          watchtowerSection
          Section {
            SidebarRow(
              title: String(localized: "sidebar.archive"),
              systemImage: "archivebox",
              count: library.count(for: .archive),
            )
            .tag(SidebarSelection.archive)
            SidebarRow(
              title: String(localized: "sidebar.trash"),
              systemImage: "trash",
              count: library.count(for: .trash),
            )
            .tag(SidebarSelection.trash)
          }
        }
        .listStyle(.sidebar)
        .scrollContentBackground(.hidden)
        SyncFooter(lastSync: library.lastSync)
      }
      .background(HaspColor.sidebar)
      .accessibilityElement(children: .contain)
      .accessibilityLabel("sidebar.label")
    }

    private var usedCategories: [ItemCategory] {
      library.categories.filter { library.count(for: .category($0.id)) > 0 }
    }

    private var watchtowerSection: some View {
      Section("sidebar.watchtower") {
        SidebarRow(
          title: String(localized: "sidebar.watchtower.reused"),
          systemImage: "shield",
          count: findingCount(.reused),
        )
        .tag(SidebarSelection.watchtower(.reused))
        SidebarRow(
          title: String(localized: "sidebar.watchtower.weak"),
          systemImage: "exclamationmark.triangle",
          count: findingCount(.weak),
        )
        .tag(SidebarSelection.watchtower(.weak))
        SidebarRow(
          title: String(localized: "sidebar.watchtower.all"),
          systemImage: "checkmark.shield",
          count: library.count(for: .watchtower(nil)),
        )
        .tag(SidebarSelection.watchtower(nil))
      }
    }

    private func findingCount(_ kind: WatchKind) -> Int {
      library.count(for: .watchtower(kind))
    }
  }

  struct SidebarRow: View {
    let title: String
    let systemImage: String
    let count: Int

    var body: some View {
      HStack {
        Label(title, systemImage: systemImage)
          .haspText(HaspFont.body)
        Spacer()
        Text("\(count)")
          .haspText(HaspFont.captionTabular)
          .foregroundStyle(HaspColor.textSecondary)
      }
      .accessibilityElement(children: .combine)
    }
  }

  struct SyncFooter: View {
    let lastSync: Date?

    var body: some View {
      HStack(spacing: HaspSpace.s6) {
        Image(systemName: "arrow.triangle.2.circlepath")
        Text("sidebar.synced")
      }
      .haspText(HaspFont.caption)
      .foregroundStyle(HaspColor.textSecondary)
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(HaspSpace.s14)
      .opacity(lastSync == nil ? 0.5 : 1)
      .accessibilityElement(children: .combine)
    }
  }
#endif
