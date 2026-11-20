import HaspDesign
import HaspKit
import SwiftUI

struct WatchtowerView: View {
  let model: WatchtowerModel

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: HaspSpace.s16) {
        Text("watchtower.title")
          .haspText(HaspFont.title)
          .accessibilityAddTraits(.isHeader)
        DetailGroup {
          CountRow(label: "watchtower.reused", count: model.count(.reused))
          Divider().overlay(HaspColor.separator)
          CountRow(label: "watchtower.weak", count: model.count(.weak))
          Divider().overlay(HaspColor.separator)
          CountRow(label: "watchtower.insecureURL", count: model.count(.insecureURL))
          Divider().overlay(HaspColor.separator)
          CountRow(label: "watchtower.expiring", count: model.count(.expiring))
          Divider().overlay(HaspColor.separator)
          CountRow(label: "watchtower.vulnerable", count: model.count(.vulnerable))
        }
        breachSection
      }
      .frame(maxWidth: HaspSize.paneWidth, alignment: .leading)
      .padding(HaspSpace.s36)
      .frame(maxWidth: .infinity)
    }
    .background(HaspColor.window)
  }

  @ViewBuilder private var breachSection: some View {
    if model.breachCheckEnabled {
      HStack {
        Button("watchtower.checkNow") { Task { await model.runBreachCheck() } }
          .buttonStyle(HaspBorderedButtonStyle())
          .disabled(model.checking)
        if model.checking { ProgressView().controlSize(.small) }
      }
    } else {
      VStack(alignment: .leading, spacing: HaspSpace.s8) {
        Text("watchtower.disclosure")
          .haspText(HaspFont.bodyRelaxed)
          .foregroundStyle(HaspColor.textSecondary)
        Button("watchtower.optIn") { Task { await model.optIn() } }
          .buttonStyle(HaspBorderedButtonStyle())
          .accessibilityIdentifier("watchtower.optIn")
      }
    }
  }
}

struct CountRow: View {
  let label: LocalizedStringKey
  let count: Int

  var body: some View {
    HStack {
      Text(label).haspText(HaspFont.bodyLarge)
      Spacer()
      Text("\(count)").haspText(HaspFont.bodyLargeMedium).monospacedDigit()
    }
    .padding(.horizontal, HaspSpace.s14)
    .frame(minHeight: HaspSize.formFieldMinHeight / 1.4)
    .accessibilityElement(children: .combine)
  }
}
