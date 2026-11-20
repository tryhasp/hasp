#if os(iOS)
  import HaspDesign
  import HaspKit
  import SwiftUI

  struct MobileDetailView: View {
    let model: ItemDetailModel
    let library: LibraryModel

    var body: some View {
      ScrollView {
        if let detail = model.detail {
          VStack(alignment: .leading, spacing: HaspSpace.s16) {
            DetailHeader(summary: detail.summary, kindName: kindLine(detail.summary))
              .padding(.horizontal, HaspSpace.s4)
            ForEach(detail.sections) { section in
              MobileSectionGroup(section: section, kind: detail.summary.kind, model: model)
            }
            MobileURLGroup(urls: detail.urls)
            MobileAttachmentGroup(model: model, attachments: detail.attachments)
            NotesGroup(summary: detail.summary, notes: detail.notes)
            let modified = HaspDate.day(detail.summary.modified)
            Text("detail.modified \(modified)")
              .haspText(HaspFont.caption)
              .foregroundStyle(HaspColor.textSecondary)
              .padding(.horizontal, HaspSpace.s14)
          }
          .frame(maxWidth: MobileMetrics.formWidth)
          .padding(HaspSpace.s16)
          .frame(maxWidth: .infinity)
        }
      }
      .background(HaspColor.window)
      .navigationBarTitleDisplayMode(.inline)
      .toolbar { toolbar }
      .sheet(isPresented: Bindable(model).showsHistory) { MobileHistoryView(model: model) }
      .fullScreenCover(item: largeTypeBinding) { text in
        MobileLargeType(text: text.value) { model.dismissLargeType() }
      }
    }

    private var largeTypeBinding: Binding<LargeText?> {
      Binding(
        get: { model.largeType.map(LargeText.init) },
        set: { if $0 == nil { model.dismissLargeType() } },
      )
    }

    @ToolbarContentBuilder private var toolbar: some ToolbarContent {
      ToolbarItem(placement: .topBarTrailing) {
        Button("detail.edit") { library.beginEdit() }
          .accessibilityIdentifier("item.edit")
      }
      ToolbarItem(placement: .topBarTrailing) {
        Menu {
          Button {
            Task { await model.loadHistory() }
          } label: {
            Label("detail.history", systemImage: "clock.arrow.circlepath")
          }
          if let summary = model.detail?.summary {
            Button {
              Task { await library.toggleFavourite(summary) }
            } label: {
              Label(
                summary.favourite ? "item.unfavourite" : "item.favourite",
                systemImage: summary.favourite ? "star.slash" : "star",
              )
            }
            Button(role: .destructive) {
              Task { await library.setStatus(summary.key, .trashed) }
            } label: {
              Label("item.trash", systemImage: "trash")
            }
          }
        } label: {
          Image(systemName: "ellipsis.circle")
            .frame(minWidth: MobileMetrics.touchTarget, minHeight: MobileMetrics.touchTarget)
        }
        .accessibilityLabel("m.detail.more")
        .accessibilityIdentifier("item.more")
      }
    }

    private func kindLine(_ summary: ItemSummary) -> String {
      let kind = library.categories.first { $0.id == summary.kind }.map(LibraryModel.name)
      let vault = library.vaults.first { $0.id == summary.key.vault }?.displayName
      return [kind ?? summary.kind, vault].compactMap { $0 }.joined(separator: " · ")
    }
  }

  struct LargeText: Identifiable, Equatable {
    let value: String
    var id: String { value }
  }

  struct MobileSectionGroup: View {
    let section: SectionValue
    let kind: String
    let model: ItemDetailModel

    var body: some View {
      let fields = section.fields.filter { $0.value != nil || $0.concealed || $0.kind == "otp" }
      if !fields.isEmpty {
        DetailGroup {
          ForEach(fields) { field in
            if field.kind == "otp" {
              MobileOTPRow(field: field, kind: kind, model: model)
            } else {
              MobileFieldRow(field: field, kind: kind, model: model)
            }
            if field.id != fields.last?.id { Divider().overlay(HaspColor.separator) }
          }
        }
      }
    }
  }

  struct MobileFieldRow: View {
    let field: FieldValue
    let kind: String
    let model: ItemDetailModel

    var body: some View {
      HStack(spacing: 0) {
        Button {
          Task { await model.copy(field) }
        } label: {
          VStack(alignment: .leading, spacing: HaspSpace.s2) {
            Text(TemplateText.fieldLabel(kind: kind, label: field.label))
              .haspText(HaspFont.caption)
              .foregroundStyle(HaspColor.textSecondary)
            valueText
          }
          .frame(maxWidth: .infinity, alignment: .leading)
          .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(
          "\(TemplateText.fieldLabel(kind: kind, label: field.label)), \(String(localized: "field.copy"))"
        )
        .accessibilityIdentifier("field.copy.\(field.purpose ?? field.label)")
        if field.concealed {
          MobileIconButton(
            systemName: model.revealed[field.id] == nil ? "eye" : "eye.slash",
            label: model.revealed[field.id] == nil ? "field.reveal" : "field.hide",
            identifier: "field.reveal.\(field.purpose ?? field.label)",
          ) { Task { await model.toggleReveal(field) } }
          if model.revealed[field.id] != nil {
            MobileIconButton(systemName: "textformat.size", label: "field.largeType") {
              Task { await model.showLargeType(field) }
            }
          }
        }
      }
      .padding(.leading, HaspSpace.s14)
      .padding(.trailing, HaspSpace.s4)
      .frame(minHeight: HaspSize.formFieldMinHeight)
    }

    @ViewBuilder private var valueText: some View {
      if let revealed = model.revealed[field.id] {
        Text(revealed).haspText(HaspFont.secretCompact).foregroundStyle(HaspColor.text)
      } else if field.concealed {
        Text(String(repeating: "•", count: 12)).haspText(HaspFont.secretCompact)
          .foregroundStyle(HaspColor.text)
          .accessibilityLabel("field.hidden")
      } else {
        Text(field.value ?? "").haspText(HaspFont.bodyLarge).foregroundStyle(HaspColor.text)
      }
    }
  }

  struct MobileOTPRow: View {
    let field: FieldValue
    let kind: String
    let model: ItemDetailModel

    var body: some View {
      let code = model.codes[field.id]
      let remaining = model.remaining(for: field.id)
      HStack(spacing: 0) {
        VStack(alignment: .leading, spacing: HaspSpace.s2) {
          Text(TemplateText.fieldLabel(kind: kind, label: field.label))
            .haspText(HaspFont.caption)
            .foregroundStyle(HaspColor.textSecondary)
          Text(code.map { OTPRowView.grouped($0.code) } ?? "—")
            .haspText(HaspFont.otpDigits)
            .foregroundStyle(HaspColor.text)
            .accessibilityIdentifier("otp.code")
        }
        Spacer()
        VStack(alignment: .trailing, spacing: HaspSpace.s4) {
          TickRow(remaining: remaining, period: code?.period ?? 30)
          Text("otp.remaining \(remaining)")
            .haspText(HaspFont.captionTabular)
            .foregroundStyle(HaspColor.textSecondary)
            .accessibilityIdentifier("otp.remaining")
        }
        MobileIconButton(systemName: HaspSymbol.copy, label: "field.copyCode") {
          Task { await model.copyCode(field) }
        }
      }
      .padding(.leading, HaspSpace.s14)
      .padding(.trailing, HaspSpace.s4)
      .frame(minHeight: HaspSize.formFieldMinHeightOtp)
      .accessibilityElement(children: .contain)
    }
  }

  struct MobileURLGroup: View {
    let urls: [ItemURL]
    @Environment(\.openURL) private var openURL

    var body: some View {
      if !urls.isEmpty {
        DetailGroup {
          ForEach(urls) { entry in
            Button {
              if let url = URL(string: entry.url) { openURL(url) }
            } label: {
              VStack(alignment: .leading, spacing: HaspSpace.s2) {
                Text("detail.website")
                  .haspText(HaspFont.caption)
                  .foregroundStyle(HaspColor.textSecondary)
                Text(entry.url)
                  .haspText(HaspFont.bodyLarge)
                  .foregroundStyle(HaspColor.accentText)
                  .underline()
              }
              .frame(maxWidth: .infinity, alignment: .leading)
              .padding(.horizontal, HaspSpace.s14)
              .frame(minHeight: HaspSize.formFieldMinHeight)
              .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityHint("detail.openURL")
          }
        }
      }
    }
  }

  struct MobileLargeType: View {
    let text: String
    let dismiss: () -> Void

    var body: some View {
      VStack {
        Spacer()
        Text(text)
          .haspText(HaspFont.otpDigits)
          .foregroundStyle(HaspColor.text)
          .multilineTextAlignment(.center)
          .minimumScaleFactor(0.4)
          .padding(HaspSpace.s24)
        Spacer()
        Button("common.close", action: dismiss)
          .buttonStyle(MobileSecondaryButtonStyle())
          .padding(HaspSpace.s24)
      }
      .frame(maxWidth: .infinity, maxHeight: .infinity)
      .background(HaspColor.window.ignoresSafeArea())
    }
  }

  struct MobileHistoryView: View {
    let model: ItemDetailModel

    var body: some View {
      NavigationStack {
        Group {
          if model.history.isEmpty {
            Text("history.empty")
              .haspText(HaspFont.body)
              .foregroundStyle(HaspColor.textSecondary)
              .frame(maxWidth: .infinity, maxHeight: .infinity)
          } else {
            List(model.history) { entry in
              HStack {
                VStack(alignment: .leading) {
                  Text(entry.title).haspText(HaspFont.bodyMedium)
                  Text(HaspDate.dayAndTime(entry.modified))
                    .haspText(HaspFont.caption)
                    .foregroundStyle(HaspColor.textSecondary)
                }
                Spacer()
                Button("history.restore") { Task { await model.restore(entry) } }
                  .buttonStyle(.bordered)
                  .tint(HaspColor.accent)
              }
              .accessibilityElement(children: .combine)
            }
          }
        }
        .navigationTitle("history.title")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
          ToolbarItem(placement: .topBarTrailing) {
            Button("common.close") { model.showsHistory = false }
          }
        }
      }
      .presentationDetents([.medium, .large])
    }
  }
#endif
