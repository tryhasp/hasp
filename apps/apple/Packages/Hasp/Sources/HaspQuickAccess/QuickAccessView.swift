import HaspDesign
import HaspQuickAccessCore
import SwiftUI

struct QuickAccessView: View {
  @Bindable var model: QuickAccessModel

  var body: some View {
    VStack(spacing: 0) {
      if model.mode == .locked {
        lockedCard
      } else {
        searchBar
        content
        HintBar()
      }
    }
    .frame(width: HaspSize.quickAccessWidth, height: HaspSize.quickAccessHeight)
    .background(HaspColor.window)
    .clipShape(RoundedRectangle(cornerRadius: HaspRadius.panel))
    .overlay(
      RoundedRectangle(cornerRadius: HaspRadius.panel)
        .strokeBorder(HaspColor.quickPanelBorder, lineWidth: HaspBorder.hairline)
    )
  }

  private var searchBar: some View {
    HStack(spacing: HaspSpace.s10) {
      Image(systemName: "magnifyingglass")
        .font(.system(size: HaspSize.iconQuickSearch))
        .foregroundStyle(HaspColor.textSecondary)
        .accessibilityHidden(true)
      SearchField(
        text: $model.query,
        placeholder: Strings.searchPlaceholder,
        focusToken: model.focusToken,
        onMove: { model.moveSelection(by: $0) },
        onReturn: { Task { await model.perform(.fill) } },
        onEscape: { Task { await model.perform(.close) } },
      )
      Text(Strings.resultCount(model.results.count))
        .haspText(HaspFont.caption)
        .foregroundStyle(HaspColor.textSecondary)
    }
    .padding(.horizontal, HaspSpace.s18)
    .frame(height: HaspSize.quickAccessQueryHeight)
    .overlay(alignment: .bottom) { HaspColor.separator.frame(height: HaspBorder.hairline) }
  }

  @ViewBuilder private var content: some View {
    switch model.mode {
    case .confirmTyping(let reason, _):
      PromptCard(
        title: Strings.confirmTitle,
        message: Strings.confirmBody(reason),
        primary: Strings.confirmAction,
        secondary: Strings.cancelAction,
        onPrimary: { Task { await model.confirmTyping() } },
        onSecondary: { model.cancelPrompt() },
      )
    case .needsAccessibility:
      PromptCard(
        title: Strings.accessibilityTitle,
        message: Strings.accessibilityBody,
        primary: Strings.accessibilityOpen,
        secondary: Strings.accessibilityCopy,
        onPrimary: { model.openAccessibilitySettings() },
        onSecondary: { Task { await model.copyPasswordFromPrompt() } },
      )
    case .search, .locked:
      if model.showsActions { ActionsOverlay() } else { panes }
    }
  }

  private var panes: some View {
    HStack(spacing: 0) {
      results
        .frame(width: HaspSize.quickAccessListWidth)
        .overlay(alignment: .trailing) { HaspColor.separator.frame(width: HaspBorder.hairline) }
      if let item = model.selectedItem {
        PreviewPane(item: item, otp: model.otp)
      } else {
        Text(Strings.emptyResults)
          .haspText(HaspFont.body)
          .foregroundStyle(HaspColor.textSecondary)
          .frame(maxWidth: .infinity, maxHeight: .infinity)
      }
    }
  }

  private var results: some View {
    ScrollViewReader { proxy in
      ScrollView {
        LazyVStack(spacing: 0) {
          ForEach(model.results) { item in
            ResultRow(item: item, selected: item.id == model.selection) {
              model.select(item.id)
            }
            .id(item.id)
          }
        }
        .padding(HaspSpace.s8)
      }
      .onChange(of: model.selection) { _, id in
        if let id { proxy.scrollTo(id) }
      }
    }
  }

  private var lockedCard: some View {
    PromptCard(
      title: Strings.lockedTitle,
      message: Strings.lockedBody,
      primary: Strings.lockedAction,
      secondary: Strings.cancelAction,
      onPrimary: { model.requestUnlock() },
      onSecondary: { Task { await model.perform(.close) } },
    )
  }
}
