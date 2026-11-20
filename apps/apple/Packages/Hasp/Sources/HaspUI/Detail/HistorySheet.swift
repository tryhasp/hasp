import HaspDesign
import HaspKit
import SwiftUI

struct HistorySheet: View {
  let model: ItemDetailModel

  var body: some View {
    VStack(alignment: .leading, spacing: HaspSpace.s12) {
      Text("history.title")
        .haspText(HaspFont.titleSmall)
        .accessibilityAddTraits(.isHeader)
      if model.history.isEmpty {
        Text("history.empty").haspText(HaspFont.body).foregroundStyle(HaspColor.textSecondary)
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
              .buttonStyle(HaspBorderedButtonStyle())
          }
          .accessibilityElement(children: .combine)
        }
      }
      HStack {
        Spacer()
        Button("common.close") { model.showsHistory = false }
          .buttonStyle(HaspBorderedButtonStyle())
          .keyboardShortcut(.cancelAction)
      }
    }
    .padding(HaspSpace.s24)
    .frame(width: HaspSize.paneWidth, height: HaspSize.settingsHeight)
  }
}
