#if os(iOS)
  import HaspDesign
  import HaspKit
  import SwiftUI

  struct MobileWatchtowerView: View {
    let app: AppModel
    @Bindable var library: LibraryModel
    let active: Bool

    var body: some View {
      NavigationStack {
        if let session = app.activeSession {
          MobileWatchtowerContent(
            model: WatchtowerModel(library: library, app: app, session: session),
            library: library,
          )
          .navigationTitle("watchtower.title")
          .navigationDestination(item: detailBinding) { _ in
            if let detail = library.detail { MobileDetailView(model: detail, library: library) }
          }
        }
      }
    }

    private var detailBinding: Binding<ItemKey?> {
      Binding(
        get: { active ? library.selectedKey : nil },
        set: { library.selectedKey = $0 },
      )
    }
  }

  struct MobileWatchtowerContent: View {
    let model: WatchtowerModel
    let library: LibraryModel

    private static let kinds: [(WatchKind, LocalizedStringKey)] = [
      (.reused, "watchtower.reused"), (.weak, "watchtower.weak"),
      (.insecureURL, "watchtower.insecureURL"), (.expiring, "watchtower.expiring"),
      (.vulnerable, "watchtower.vulnerable"),
    ]

    var body: some View {
      List {
        ForEach(Array(Self.kinds.enumerated()), id: \.offset) { _, entry in
          let (kind, title) = entry
          let items = flagged(kind)
          if !items.isEmpty {
            Section {
              ForEach(items) { item in
                Button {
                  library.selectedKey = item.key
                } label: {
                  MobileItemRow(item: item)
                }
                .buttonStyle(.plain)
              }
            } header: {
              MobileSectionHeader(title)
            }
          }
        }
        Section {
          breach
        }
      }
      .listStyle(.insetGrouped)
      .accessibilityIdentifier("watchtower.list")
    }

    private func flagged(_ kind: WatchKind) -> [ItemSummary] {
      let keys = Set(
        library.watchtower?.findings.filter { $0.kind == kind }.map(\.key) ?? []
      )
      return library.allItems.filter { keys.contains($0.key) && $0.status == .active }
    }

    @ViewBuilder private var breach: some View {
      if model.breachCheckEnabled {
        Button("watchtower.checkNow") { Task { await model.runBreachCheck() } }
          .disabled(model.checking)
          .frame(minHeight: MobileMetrics.touchTarget)
      } else {
        VStack(alignment: .leading, spacing: HaspSpace.s8) {
          Text("watchtower.disclosure")
            .haspText(HaspFont.caption)
            .foregroundStyle(HaspColor.textSecondary)
          Button("watchtower.optIn") { Task { await model.optIn() } }
            .frame(minHeight: MobileMetrics.touchTarget)
            .accessibilityIdentifier("watchtower.optIn")
        }
      }
    }
  }
#endif
