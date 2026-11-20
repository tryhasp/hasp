import HaspDesign
import HaspKit
import SwiftUI

struct SectionGroup: View {
  let section: SectionValue
  let kind: String
  let model: ItemDetailModel

  var body: some View {
    let fields = section.fields.filter { $0.value != nil || $0.concealed || $0.kind == "otp" }
    if !fields.isEmpty {
      DetailGroup {
        ForEach(fields) { field in
          if field.kind == "otp" {
            OTPRowView(field: field, kind: kind, model: model)
          } else {
            FieldRowView(field: field, kind: kind, model: model)
          }
          if field.id != fields.last?.id { Divider().overlay(HaspColor.separator) }
        }
      }
    }
  }
}

struct FieldRowView: View {
  let field: FieldValue
  let kind: String
  let model: ItemDetailModel

  var body: some View {
    HStack {
      VStack(alignment: .leading, spacing: HaspSpace.s2) {
        Text(TemplateText.fieldLabel(kind: kind, label: field.label))
          .haspText(HaspFont.caption)
          .foregroundStyle(HaspColor.textSecondary)
        valueText
      }
      Spacer()
      if field.concealed {
        IconButton(
          systemName: model.revealed[field.id] == nil ? "eye" : "eye.slash",
          label: model.revealed[field.id] == nil ? "field.reveal" : "field.hide",
          identifier: "field.reveal.\(field.purpose ?? field.label)",
        ) { Task { await model.toggleReveal(field) } }
        if model.revealed[field.id] != nil {
          IconButton(systemName: "textformat.size", label: "field.largeType") {
            Task { await model.showLargeType(field) }
          }
        }
      }
      IconButton(
        systemName: HaspSymbol.copy,
        label: "field.copy",
        identifier: "field.copy.\(field.purpose ?? field.label)",
      ) {
        Task { await model.copy(field) }
      }
    }
    .padding(.horizontal, HaspSpace.s14)
    .frame(minHeight: HaspSize.formFieldMinHeight)
    .accessibilityElement(children: .contain)
  }

  @ViewBuilder private var valueText: some View {
    if let revealed = model.revealed[field.id] {
      Text(revealed).haspText(HaspFont.secretCompact).textSelection(.enabled)
    } else if field.concealed {
      Text(String(repeating: "•", count: 12)).haspText(HaspFont.secretCompact)
        .accessibilityLabel("field.hidden")
    } else {
      Text(field.value ?? "").haspText(HaspFont.bodyLarge).textSelection(.enabled)
    }
  }
}

struct OTPRowView: View {
  let field: FieldValue
  let kind: String
  let model: ItemDetailModel

  var body: some View {
    let code = model.codes[field.id]
    let remaining = model.remaining(for: field.id)
    HStack {
      VStack(alignment: .leading, spacing: HaspSpace.s2) {
        Text(TemplateText.fieldLabel(kind: kind, label: field.label))
          .haspText(HaspFont.caption)
          .foregroundStyle(HaspColor.textSecondary)
        Text(code.map { Self.grouped($0.code) } ?? "—")
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
      IconButton(systemName: HaspSymbol.copy, label: "field.copyCode") {
        Task { await model.copyCode(field) }
      }
    }
    .padding(.horizontal, HaspSpace.s14)
    .frame(minHeight: HaspSize.formFieldMinHeightOtp)
    .accessibilityElement(children: .contain)
  }

  static func grouped(_ code: String) -> String {
    guard code.count == 6 else { return code }
    return code.prefix(3) + " " + code.suffix(3)
  }
}
