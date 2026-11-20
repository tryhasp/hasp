#if os(macOS)
  import HaspDesign
  import SwiftUI

  struct QuickAccessIntroSheet: View {
    let app: AppModel

    var body: some View {
      VStack(alignment: .leading, spacing: HaspSpace.s16) {
        Text("quick.intro.title")
          .haspText(HaspFont.titleConfirm)
          .accessibilityAddTraits(.isHeader)
        if let chord = app.quickAccess.map({ HotKeyDisplay.text(for: $0.hotKey) }) {
          Text("quick.intro.hotkey \(chord)")
            .haspText(HaspFont.bodyRelaxed)
        }
        Text("quick.access.why")
          .haspText(HaspFont.bodyRelaxed)
          .foregroundStyle(HaspColor.textSecondary)
        Text("quick.intro.without")
          .haspText(HaspFont.caption)
          .foregroundStyle(HaspColor.textSecondary)
        HStack {
          Spacer()
          Button("quick.intro.later") { app.dismissQuickAccessIntro() }
            .buttonStyle(HaspBorderedButtonStyle())
            .keyboardShortcut(.cancelAction)
            .accessibilityIdentifier("quick.intro.later")
          Button("quick.access.allow") {
            app.quickAccess?.requestAccessibility()
            app.quickAccess?.openAccessibilitySettings()
            app.dismissQuickAccessIntro()
          }
          .buttonStyle(HaspBorderedButtonStyle())
          .keyboardShortcut(.defaultAction)
          .accessibilityIdentifier("quick.access.allowIntro")
        }
      }
      .padding(HaspSpace.s24)
      .frame(width: HaspSize.confirmWidth)
    }
  }
#endif
