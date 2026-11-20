#if os(macOS)
  import HaspDesign
  import HaspKit
  import SwiftUI

  struct MainView: View {
    let app: AppModel
    @Bindable var library: LibraryModel
    @FocusState private var searchFocused: Bool
    @FocusState private var listFocused: Bool

    var body: some View {
      NavigationSplitView {
        SidebarView(library: library)
          .navigationSplitViewColumnWidth(HaspSize.sidebarWidth)
      } content: {
        ItemListView(library: library, listFocused: $listFocused)
          .navigationSplitViewColumnWidth(
            min: HaspSize.listWidth - HaspSpace.s40,
            ideal: HaspSize.listWidth,
            max: HaspSize.listWidth + HaspSize.sidebarWidth,
          )
      } detail: {
        DetailPane(app: app, library: library)
      }
      .toolbar { toolbar }
      .searchable(text: $library.searchText, placement: .toolbar, prompt: "search.prompt")
      .searchFocused($searchFocused)
      .onChange(of: library.searchFocusTick) { searchFocused = true }
      .sheet(item: $library.editor) { editor in
        ItemEditorView(model: editor, categories: library.categories)
      }
      .overlay(alignment: .bottom) {
        if let toast = app.toast {
          ToastView(message: toast)
            .padding(.bottom, HaspSpace.s36)
            .transition(.opacity)
        }
      }
      .animation(.default, value: app.toast)
    }

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
      ToolbarItem(placement: .primaryAction) {
        if library.selectedKey != nil {
          Button("detail.edit") { library.beginEdit() }
            .buttonStyle(HaspBorderedButtonStyle())
            .accessibilityIdentifier("item.edit")
        }
      }
      ToolbarItem(placement: .primaryAction) {
        if library.selectedKey != nil {
          Button("detail.history") { Task { await library.detail?.loadHistory() } }
            .buttonStyle(HaspBorderedButtonStyle())
            .accessibilityIdentifier("item.history")
        }
      }
    }
  }

  struct DetailPane: View {
    let app: AppModel
    let library: LibraryModel

    var body: some View {
      if let detail = library.detail {
        ItemDetailView(model: detail, library: library)
      } else if case .watchtower = library.selection, let session = app.activeSession {
        WatchtowerView(model: WatchtowerModel(library: library, app: app, session: session))
      } else {
        Text("detail.empty")
          .haspText(HaspFont.body)
          .foregroundStyle(HaspColor.textSecondary)
          .frame(maxWidth: .infinity, maxHeight: .infinity)
          .background(HaspColor.window)
      }
    }
  }
#endif
