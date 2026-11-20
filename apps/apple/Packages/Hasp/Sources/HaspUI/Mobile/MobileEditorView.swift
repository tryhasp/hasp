#if os(iOS)
  import HaspDesign
  import HaspKit
  import SwiftUI

  struct MobileEditorView: View {
    @Bindable var model: ItemEditorModel
    let categories: [ItemCategory]

    var body: some View {
      NavigationStack {
        ScrollView {
          if model.draft != nil {
            VStack(alignment: .leading, spacing: HaspSpace.s16) {
              if model.isCreating { kindPicker }
              TextField(
                "editor.title",
                text: Binding(get: { model.draft?.title ?? "" }, set: { model.draft?.title = $0 }),
              )
              .mobileField()
              .accessibilityLabel("editor.title")
              .accessibilityIdentifier("editor.title")
              ForEach(sectionIndices, id: \.self) { index in
                MobileEditorSection(model: model, sectionIndex: index)
              }
              MobileEditorURLs(model: model)
              MobileEditorExtras(model: model)
              if let failure = model.failure { NoticeText(text: failure) }
            }
            .frame(maxWidth: MobileMetrics.formWidth)
            .padding(HaspSpace.s16)
            .frame(maxWidth: .infinity)
          }
        }
        .scrollDismissesKeyboard(.interactively)
        .background(HaspColor.window.ignoresSafeArea())
        .navigationTitle(model.isCreating ? "list.new" : "detail.edit")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
          ToolbarItem(placement: .cancellationAction) {
            Button("common.cancel") { model.cancel() }
              .accessibilityIdentifier("editor.cancel")
          }
          ToolbarItem(placement: .confirmationAction) {
            Button("common.save") { Task { await model.save() } }
              .disabled(!model.canSave)
              .accessibilityIdentifier("editor.save")
          }
        }
      }
      .task { await model.load() }
      .tint(HaspColor.accentText)
      .interactiveDismissDisabled()
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

    private func changeKind(_ kind: String) {
      Task { await model.changeKind(to: kind) }
    }
  }

  struct MobileEditorSection: View {
    @Bindable var model: ItemEditorModel
    let sectionIndex: Int

    var body: some View {
      if let section = model.draft?.sections[safe: sectionIndex] {
        VStack(spacing: HaspSpace.s8) {
          ForEach(section.fields) { field in
            MobileEditorField(
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

  struct MobileEditorField: View {
    @Bindable var model: ItemEditorModel
    let field: DraftField
    let kind: String
    let sectionIndex: Int

    var body: some View {
      VStack(alignment: .leading, spacing: HaspSpace.s4) {
        Text(label).haspText(HaspFont.caption).foregroundStyle(HaspColor.textSecondary)
        HStack(spacing: HaspSpace.s8) {
          input
          if field.concealed && field.purpose == "password" {
            MobileIconButton(
              systemName: "wand.and.stars",
              label: "editor.generate",
              identifier: "editor.generate",
            ) { Task { await model.generate(into: field.id) } }
          }
        }
      }
    }

    @ViewBuilder private var input: some View {
      let binding = Binding(
        get: { field.value },
        set: { newValue in
          update {
            $0.value = newValue
            $0.keepValue = false
          }
        },
      )
      let placeholder = field.keepValue ? String(localized: "editor.unchanged") : ""
      if field.concealed {
        SecureField(placeholder, text: binding)
          .mobileField()
          .textContentType(.none)
          .accessibilityLabel(label)
          .accessibilityIdentifier("editor.field.\(field.purpose ?? field.label)")
      } else {
        TextField(placeholder, text: binding)
          .mobileField()
          .textInputAutocapitalization(.never)
          .autocorrectionDisabled()
          .accessibilityLabel(label)
          .accessibilityIdentifier("editor.field.\(field.purpose ?? field.label)")
      }
    }

    private var label: String {
      TemplateText.fieldLabel(kind: kind, label: field.label)
    }

    private func update(_ change: (inout DraftField) -> Void) {
      guard var draft = model.draft,
        let index = draft.sections[sectionIndex].fields.firstIndex(where: { $0.id == field.id })
      else { return }
      change(&draft.sections[sectionIndex].fields[index])
      model.draft = draft
    }
  }

  struct MobileEditorURLs: View {
    @Bindable var model: ItemEditorModel

    var body: some View {
      VStack(alignment: .leading, spacing: HaspSpace.s8) {
        ForEach(model.draft?.urls ?? []) { entry in
          HStack(spacing: HaspSpace.s8) {
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
            .mobileField()
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .keyboardType(.URL)
            .accessibilityLabel("editor.url")
            .accessibilityIdentifier("editor.url")
            MobileIconButton(systemName: "minus.circle", label: "editor.removeURL") {
              model.removeURL(entry.id)
            }
          }
        }
        Button("editor.addURL") { model.addURL() }
          .foregroundStyle(HaspColor.accentText)
          .haspText(HaspFont.bodyMedium)
          .frame(minHeight: MobileMetrics.touchTarget)
          .accessibilityIdentifier("editor.addURL")
      }
    }
  }

  struct MobileEditorExtras: View {
    @Bindable var model: ItemEditorModel

    var body: some View {
      VStack(spacing: HaspSpace.s8) {
        TextField("editor.tags", text: $model.tagsText)
          .mobileField()
          .textInputAutocapitalization(.never)
          .accessibilityLabel("editor.tags")
          .accessibilityIdentifier("editor.tags")
        TextField(
          "editor.notes",
          text: Binding(get: { model.draft?.notes ?? "" }, set: { model.draft?.notes = $0 }),
          axis: .vertical,
        )
        .lineLimit(3...8)
        .padding(.vertical, HaspSpace.s12)
        .mobileField()
        .accessibilityLabel("editor.notes")
        .accessibilityIdentifier("editor.notes")
      }
    }
  }
#endif
