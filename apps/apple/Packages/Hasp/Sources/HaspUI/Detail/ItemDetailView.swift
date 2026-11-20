#if os(macOS)
  import HaspDesign
  import HaspKit
  import SwiftUI

  struct ItemDetailView: View {
    let model: ItemDetailModel
    let library: LibraryModel

    var body: some View {
      ScrollView {
        if let detail = model.detail {
          let modified = HaspDate.day(detail.summary.modified)
          VStack(alignment: .leading, spacing: HaspSpace.s16) {
            DetailHeader(summary: detail.summary, kindName: kindLine(detail.summary))
            ForEach(detail.sections) { section in
              SectionGroup(section: section, kind: detail.summary.kind, model: model)
            }
            URLGroup(urls: detail.urls)
            AttachmentGroup(model: model, attachments: detail.attachments)
            NotesGroup(summary: detail.summary, notes: detail.notes)
            Text("detail.modified \(modified)")
              .haspText(HaspFont.caption)
              .foregroundStyle(HaspColor.textSecondary)
              .padding(.horizontal, HaspSpace.s14)
          }
          .frame(maxWidth: HaspSize.paneWidth)
          .padding(HaspSpace.s36)
          .frame(maxWidth: .infinity)
        }
      }
      .background(HaspColor.window)
      .sheet(isPresented: Bindable(model).showsHistory) {
        HistorySheet(model: model)
      }
      .overlay { LargeTypeOverlay(model: model) }
    }

    private func kindLine(_ summary: ItemSummary) -> String {
      let kind = library.categories.first { $0.id == summary.kind }.map(LibraryModel.name)
      let vault = library.vaults.first { $0.id == summary.key.vault }?.displayName
      return [kind ?? summary.kind, vault].compactMap { $0 }.joined(separator: " · ")
    }
  }

  struct LargeTypeOverlay: View {
    let model: ItemDetailModel

    var body: some View {
      if let text = model.largeType {
        Text(text)
          .haspText(HaspFont.otpDigits)
          .foregroundStyle(HaspColor.text)
          .padding(HaspSpace.s32)
          .background(HaspColor.window, in: RoundedRectangle(cornerRadius: HaspRadius.panel))
          .overlay(
            RoundedRectangle(cornerRadius: HaspRadius.panel)
              .stroke(HaspColor.separator, lineWidth: HaspBorder.hairline)
          )
          .onTapGesture { model.dismissLargeType() }
          .onExitCommand { model.dismissLargeType() }
          .accessibilityLabel("detail.largeType")
          .accessibilityAddTraits(.isButton)
      }
    }
  }
#endif
