import HaspDesign
import HaspKit
import SwiftUI

struct ItemEditorView: View {
  @Bindable var model: ItemEditorModel
  let categories: [ItemCategory]

  var body: some View {
    VStack(spacing: 0) {
      ScrollView {
        if model.draft != nil {
          VStack(alignment: .leading, spacing: HaspSpace.s16) {
            if model.isCreating { kindPicker }
            titleField
            ForEach(sectionIndices, id: \.self) { index in
              EditorSection(model: model, sectionIndex: index)
            }
            EditorURLs(model: model)
            EditorExtras(model: model)
          }
          .padding(HaspSpace.s24)
        }
      }
      footer
    }
    .frame(width: HaspSize.paneWidth, height: HaspSize.windowHeight * 0.8)
    .background(HaspColor.window)
    .task { await model.load() }
  }

  private var sectionIndices: [Int] {
    Array((model.draft?.sections.indices).map { Array($0) } ?? [])
  }

  private var kindPicker: some View {
    Picker("editor.kind", selection: Binding(get: { model.kind }, set: changeKind)) {
      ForEach(categories) { category in
        Text(LibraryModel.name(category)).tag(category.id)
      }
    }
    .accessibilityIdentifier("editor.kind")
  }

  private var titleField: some View {
    TextField(
      "editor.title",
      text: Binding(get: { model.draft?.title ?? "" }, set: { model.draft?.title = $0 }),
    )
    .haspField()
    .accessibilityLabel("editor.title")
    .accessibilityIdentifier("editor.title")
  }

  private var footer: some View {
    HStack {
      if let failure = model.failure { NoticeText(text: failure) }
      Spacer()
      Button("common.cancel") { model.cancel() }
        .buttonStyle(HaspBorderedButtonStyle())
        .keyboardShortcut(.cancelAction)
      Button("common.save") { Task { await model.save() } }
        .buttonStyle(HaspBorderedButtonStyle())
        .keyboardShortcut(.defaultAction)
        .disabled(!model.canSave)
        .accessibilityIdentifier("editor.save")
    }
    .padding(HaspSpace.s16)
    .background(HaspColor.group)
  }

  private func changeKind(_ kind: String) {
    Task { await model.changeKind(to: kind) }
  }
}
