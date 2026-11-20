import HaspDesign
import HaspKit
import SwiftUI

struct EditorSection: View {
  @Bindable var model: ItemEditorModel
  let sectionIndex: Int

  var body: some View {
    if let section = model.draft?.sections[safe: sectionIndex] {
      DetailGroup {
        ForEach(section.fields) { field in
          EditorFieldRow(
            model: model,
            field: field,
            kind: model.draft?.kind ?? "",
            sectionIndex: sectionIndex,
          )
        }
      }
    }
  }
}

struct EditorFieldRow: View {
  @Bindable var model: ItemEditorModel
  let field: DraftField
  let kind: String
  let sectionIndex: Int

  var body: some View {
    HStack {
      Text(displayLabel)
        .haspText(HaspFont.caption)
        .foregroundStyle(HaspColor.textSecondary)
        .frame(width: HaspSize.settingsFieldWidth / 2, alignment: .leading)
      input
      if field.concealed && field.purpose == "password" {
        IconButton(systemName: "wand.and.stars", label: "editor.generate") {
          Task { await model.generate(into: field.id) }
        }
        .accessibilityIdentifier("editor.generate")
      }
    }
    .padding(.horizontal, HaspSpace.s14)
    .frame(minHeight: HaspSize.formFieldMinHeight)
    .accessibilityElement(children: .contain)
  }

  @ViewBuilder private var input: some View {
    let binding = Binding(
      get: { value },
      set: { newValue in
        update {
          $0.value = newValue; $0.keepValue = false
        }
      },
    )
    if field.concealed {
      SecureField(placeholder, text: binding).haspField()
        .accessibilityLabel(displayLabel)
        .accessibilityIdentifier("editor.field.\(field.purpose ?? field.label)")
    } else {
      TextField(placeholder, text: binding).haspField()
        .accessibilityLabel(displayLabel)
        .accessibilityIdentifier("editor.field.\(field.purpose ?? field.label)")
    }
  }

  private var value: String { field.value }

  private var displayLabel: String {
    TemplateText.fieldLabel(kind: kind, label: field.label)
  }

  private var placeholder: String {
    field.keepValue ? String(localized: "editor.unchanged") : ""
  }

  private func update(_ change: (inout DraftField) -> Void) {
    guard var draft = model.draft,
      let index = draft.sections[sectionIndex].fields.firstIndex(where: { $0.id == field.id })
    else { return }
    change(&draft.sections[sectionIndex].fields[index])
    model.draft = draft
  }
}

struct EditorURLs: View {
  @Bindable var model: ItemEditorModel

  var body: some View {
    DetailGroup {
      ForEach(model.draft?.urls ?? []) { entry in
        HStack {
          TextField(
            "editor.url",
            text: Binding(
              get: { entry.url },
              set: { text in
                if let index = model.draft?.urls.firstIndex(where: { $0.id == entry.id }) {
                  model.draft?.urls[index].url = text
                }
              },
            ),
          )
          .haspField()
          .accessibilityLabel("editor.url")
          .accessibilityIdentifier("editor.url")
          IconButton(systemName: "minus.circle", label: "editor.removeURL") {
            model.removeURL(entry.id)
          }
        }
        .padding(.horizontal, HaspSpace.s14)
        .frame(minHeight: HaspSize.formFieldMinHeight)
      }
      Button("editor.addURL") { model.addURL() }
        .buttonStyle(.plain)
        .foregroundStyle(HaspColor.accentText)
        .padding(HaspSpace.s14)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
  }
}

struct EditorExtras: View {
  @Bindable var model: ItemEditorModel

  var body: some View {
    DetailGroup {
      TextField("editor.tags", text: $model.tagsText)
        .haspField()
        .accessibilityLabel("editor.tags")
        .accessibilityIdentifier("editor.tags")
        .padding(HaspSpace.s14)
      TextField(
        "editor.notes",
        text: Binding(get: { model.draft?.notes ?? "" }, set: { model.draft?.notes = $0 }),
        axis: .vertical,
      )
      .lineLimit(3...8)
      .haspField()
      .accessibilityLabel("editor.notes")
      .accessibilityIdentifier("editor.notes")
      .padding([.horizontal, .bottom], HaspSpace.s14)
    }
  }
}

extension Array {
  subscript(safe index: Int) -> Element? {
    indices.contains(index) ? self[index] : nil
  }
}
