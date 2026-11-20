#if os(iOS)
  import HaspDesign
  import HaspPlatform
  import SwiftUI

  struct MobileAutoFillSection: View {
    private let available = SharedState.directory() != nil

    var body: some View {
      Section {
        Text(available ? "m.autofill.enable" : "m.autofill.needsPaidTeam")
          .haspText(HaspFont.caption)
          .foregroundStyle(HaspColor.textSecondary)
          .accessibilityIdentifier("settings.autofill.note")
        if available {
          Text("m.autofill.retention")
            .haspText(HaspFont.caption)
            .foregroundStyle(HaspColor.textSecondary)
            .accessibilityIdentifier("settings.autofill.retention")
        }
      } header: {
        MobileSectionHeader("m.autofill.title")
      }
    }
  }
#endif
