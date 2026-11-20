import Foundation
import HaspKit
import Observation

@Observable
final class LibraryModel {
  private(set) var vaults: [VaultSummary] = []
  private(set) var categories: [ItemCategory] = []
  private(set) var allItems: [ItemSummary] = []
  private(set) var searchResults: [ItemSummary]?
  private(set) var watchtower: WatchtowerSummary?
  private(set) var detail: ItemDetailModel?
  private(set) var lastSync: Date?
  var editor: ItemEditorModel?
  var searchFocusTick = 0

  var selection = SidebarSelection.all {
    didSet { if selection != oldValue { selectionChanged() } }
  }
  var searchText = "" {
    didSet { if searchText != oldValue { scheduleSearch() } }
  }
  var selectedKey: ItemKey? {
    didSet { if selectedKey != oldValue { loadDetail() } }
  }

  let session: any VaultServing
  weak var app: AppModel?
  private var searchTask: Task<Void, Never>?

  init(session: any VaultServing, app: AppModel?) {
    self.session = session
    self.app = app
  }

  var visibleItems: [ItemSummary] {
    let base = searchResults ?? allItems
    return base.filter(matchesSelection).sorted {
      $0.title.localizedStandardCompare($1.title) == .orderedAscending
    }
  }

  var title: String {
    switch selection {
    case .all: String(localized: "sidebar.all")
    case .favourites: String(localized: "sidebar.favourites")
    case .vault(let id): vaults.first { $0.id == id }?.displayName ?? ""
    case .category(let id): categories.first { $0.id == id }.map(Self.name) ?? id
    case .archive: String(localized: "sidebar.archive")
    case .trash: String(localized: "sidebar.trash")
    case .watchtower: String(localized: "sidebar.watchtower")
    }
  }

  func sharedName(for item: ItemSummary) -> String? {
    let vault = vaults.first { $0.id == item.key.vault }
    return vault.flatMap { $0.members > 1 ? $0.displayName : nil }
  }

  func count(for selection: SidebarSelection) -> Int {
    allItems.filter { matches($0, selection) }.count
  }

  func refresh() async {
    do {
      vaults = try await session.vaults()
      categories = await session.categories()
      allItems = try await session.search(SearchFilter(status: nil))
      watchtower = try? await session.watchtower()
      lastSync = .now
      if !searchText.isEmpty { await runSearch() }
      if let key = selectedKey, !allItems.contains(where: { $0.key == key }) {
        selectedKey = nil
      } else {
        await detail?.reload()
      }
    } catch {
      app?.show(error: error)
    }
  }

  func discard() {
    searchTask?.cancel()
    detail?.discard()
    detail = nil
    editor = nil
    allItems = []
    searchResults = nil
    watchtower = nil
    selectedKey = nil
  }

  func beginCreate(kind: String) {
    let vault = writableVault
    guard let vault else { return }
    editor = ItemEditorModel(
      session: session,
      library: self,
      mode: .create(kind: kind, vault: vault),
    )
  }

  func beginEdit() {
    guard let key = selectedKey else { return }
    editor = ItemEditorModel(session: session, library: self, mode: .edit(key))
  }

  func finishEditing(saved key: ItemKey?) async {
    editor = nil
    await refresh()
    if let key { selectedKey = key }
  }

  func setStatus(_ key: ItemKey, _ status: ItemStatus) async {
    await act { try await self.session.setStatus(key, status: status) }
  }

  func toggleFavourite(_ item: ItemSummary) async {
    await act { try await self.session.setFavourite(item.key, favourite: !item.favourite) }
  }

  func deletePermanently(_ key: ItemKey) async {
    await act { try await self.session.deleteItem(key) }
  }

  func focusSearch() {
    searchFocusTick += 1
  }

  var writableVault: VaultID? {
    if case .vault(let id) = selection, vaults.first(where: { $0.id == id })?.writable == true {
      return id
    }
    return vaults.first { $0.writable }?.id
  }

  static func name(_ category: ItemCategory) -> String {
    Bundle.main.preferredLocalizations.first == "ko" ? category.nameKo : category.nameEn
  }
}

extension LibraryModel {
  private func act(_ work: @escaping () async throws -> Void) async {
    do {
      try await work()
      await refresh()
    } catch {
      app?.show(error: error)
    }
  }

  private func selectionChanged() {
    if let key = selectedKey, !visibleItems.contains(where: { $0.key == key }) {
      selectedKey = nil
    }
  }

  private func scheduleSearch() {
    searchTask?.cancel()
    guard !searchText.isEmpty else {
      searchResults = nil
      return
    }
    searchTask = Task { [weak self] in
      try? await Task.sleep(for: .milliseconds(150))
      if !Task.isCancelled { await self?.runSearch() }
    }
  }

  private func runSearch() async {
    do {
      searchResults = try await session.search(SearchFilter(text: searchText, status: nil))
    } catch {
      app?.show(error: error)
    }
  }

  private func loadDetail() {
    detail?.discard()
    guard let key = selectedKey else {
      detail = nil
      return
    }
    let model = ItemDetailModel(session: session, key: key, app: app, library: self)
    detail = model
    Task { await model.reload() }
  }

  private func matchesSelection(_ item: ItemSummary) -> Bool {
    matches(item, selection)
  }

  private func matches(_ item: ItemSummary, _ selection: SidebarSelection) -> Bool {
    switch selection {
    case .all: item.status == .active
    case .favourites: item.status == .active && item.favourite
    case .vault(let id): item.status == .active && item.key.vault == id
    case .category(let kind): item.status == .active && item.kind == kind
    case .archive: item.status == .archived
    case .trash: item.status == .trashed
    case .watchtower(let kind): flagged(item, kind: kind)
    }
  }

  private func flagged(_ item: ItemSummary, kind: WatchKind?) -> Bool {
    guard item.status == .active, let findings = watchtower?.findings else { return false }
    return findings.contains { $0.key == item.key && (kind == nil || $0.kind == kind) }
  }
}
