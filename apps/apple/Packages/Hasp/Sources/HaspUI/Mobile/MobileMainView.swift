#if os(iOS)
  import HaspDesign
  import HaspKit
  import SwiftUI

  enum MobileTab: Hashable {
    case vault, watchtower, settings
  }

  struct MobileMainView: View {
    let app: AppModel
    @Bindable var library: LibraryModel
    @State private var tab = MobileTab.vault

    var body: some View {
      TabView(selection: $tab) {
        MobileVaultView(app: app, library: library, active: tab == .vault)
          .tabItem { Label("m.tab.vault", systemImage: "key") }
          .tag(MobileTab.vault)
        MobileWatchtowerView(app: app, library: library, active: tab == .watchtower)
          .tabItem { Label("m.tab.watchtower", systemImage: "checkmark.shield") }
          .tag(MobileTab.watchtower)
        MobileSettingsView(app: app)
          .tabItem { Label("m.tab.settings", systemImage: "gearshape") }
          .tag(MobileTab.settings)
      }
      .tint(HaspColor.accent)
      .sheet(item: $library.editor) { editor in
        MobileEditorView(model: editor, categories: library.categories)
      }
    }
  }

  struct MobileVaultView: View {
    let app: AppModel
    @Bindable var library: LibraryModel
    let active: Bool

    var body: some View {
      NavigationStack {
        Group {
          if library.visibleItems.isEmpty {
            EmptyListView(isSearching: !library.searchText.isEmpty)
          } else {
            list
          }
        }
        .background(HaspColor.list)
        .navigationTitle(library.title)
        .navigationBarTitleDisplayMode(.large)
        .searchable(
          text: $library.searchText,
          placement: .navigationBarDrawer(displayMode: .always),
          prompt: "search.prompt",
        )
        .toolbar { toolbar }
        .navigationDestination(item: detailBinding) { _ in
          if let detail = library.detail { MobileDetailView(model: detail, library: library) }
        }
        .refreshable { await app.syncNow() }
      }
    }

    private var detailBinding: Binding<ItemKey?> {
      Binding(
        get: { active ? library.selectedKey : nil },
        set: { library.selectedKey = $0 },
      )
    }

    private var list: some View {
      List(library.visibleItems) { item in
        Button {
          library.selectedKey = item.key
        } label: {
          MobileItemRow(item: item, sharedVault: library.sharedName(for: item))
        }
        .buttonStyle(.plain)
        .listRowBackground(HaspColor.list)
        .swipeActions(edge: .leading) {
          Button {
            Task { await library.toggleFavourite(item) }
          } label: {
            Label(
              item.favourite ? "item.unfavourite" : "item.favourite",
              systemImage: item.favourite ? "star.slash" : "star",
            )
          }
          .tint(HaspColor.accent)
        }
        .swipeActions(edge: .trailing) { MobileRowActions(library: library, item: item) }
        .accessibilityIdentifier("item.row")
      }
      .listStyle(.plain)
      .scrollContentBackground(.hidden)
      .accessibilityLabel("list.label")
      .accessibilityIdentifier("item.list")
    }

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
      ToolbarItem(placement: .topBarLeading) {
        MobileFilterMenu(library: library)
      }
      ToolbarItem(placement: .topBarTrailing) {
        Button {
          library.beginCreate(kind: "login")
        } label: {
          Image(systemName: "plus")
            .frame(minWidth: MobileMetrics.touchTarget, minHeight: MobileMetrics.touchTarget)
        }
        .accessibilityLabel("list.new")
        .accessibilityIdentifier("item.new")
      }
    }
  }

  struct MobileRowActions: View {
    let library: LibraryModel
    let item: ItemSummary

    var body: some View {
      switch item.status {
      case .active:
        Button(role: .destructive) {
          Task { await library.setStatus(item.key, .trashed) }
        } label: {
          Label("item.trash", systemImage: "trash")
        }
        Button {
          Task { await library.setStatus(item.key, .archived) }
        } label: {
          Label("item.archive", systemImage: "archivebox")
        }
      case .archived, .trashed:
        Button {
          Task { await library.setStatus(item.key, .active) }
        } label: {
          Label("item.restore", systemImage: "arrow.uturn.backward")
        }
        if item.status == .trashed {
          Button(role: .destructive) {
            Task { await library.deletePermanently(item.key) }
          } label: {
            Label("item.deleteForever", systemImage: "trash.slash")
          }
        }
      }
    }
  }

  struct MobileItemRow: View {
    let item: ItemSummary
    var sharedVault: String?

    var body: some View {
      HStack(spacing: HaspSpace.s12) {
        MonogramTile(title: item.title, size: HaspSize.tileQuickAccess)
        VStack(alignment: .leading, spacing: HaspSpace.s2) {
          Text(item.title).haspText(HaspFont.bodyMedium).foregroundStyle(HaspColor.text)
          Text(item.subtitle.isEmpty ? "—" : item.subtitle)
            .haspText(HaspFont.caption)
            .foregroundStyle(HaspColor.textSecondary)
            .lineLimit(1)
        }
        Spacer(minLength: 0)
        if sharedVault != nil {
          Image(systemName: "person.2")
            .foregroundStyle(HaspColor.textSecondary)
            .accessibilityHidden(true)
        }
        if item.favourite {
          Image(systemName: "star.fill")
            .font(.system(size: HaspSize.iconSmall))
            .foregroundStyle(HaspColor.textSecondary)
            .accessibilityLabel("list.favourite")
        }
      }
      .frame(minHeight: MobileMetrics.touchTarget + HaspSpace.s8)
      .contentShape(Rectangle())
      .accessibilityElement(children: .combine)
      .accessibilityAddTraits(.isButton)
    }
  }

  struct MobileFilterMenu: View {
    @Bindable var library: LibraryModel

    var body: some View {
      Menu {
        Picker("m.filter", selection: $library.selection) {
          Label("sidebar.all", systemImage: "square.grid.2x2").tag(SidebarSelection.all)
          Label("sidebar.favourites", systemImage: "star").tag(SidebarSelection.favourites)
          ForEach(library.vaults) { vault in
            Label(vault.displayName, systemImage: vault.members > 1 ? "person.2" : "person")
              .tag(SidebarSelection.vault(vault.id))
          }
          ForEach(usedCategories) { category in
            Label(LibraryModel.name(category), systemImage: CategoryIcon.symbol(category.icon))
              .tag(SidebarSelection.category(category.id))
          }
          Label("sidebar.archive", systemImage: "archivebox").tag(SidebarSelection.archive)
          Label("sidebar.trash", systemImage: "trash").tag(SidebarSelection.trash)
        }
      } label: {
        Image(systemName: "line.3.horizontal.decrease.circle")
          .frame(minWidth: MobileMetrics.touchTarget, minHeight: MobileMetrics.touchTarget)
      }
      .accessibilityLabel("m.filter")
      .accessibilityIdentifier("vault.filter")
    }

    private var usedCategories: [ItemCategory] {
      library.categories.filter { library.count(for: .category($0.id)) > 0 }
    }
  }
#endif
