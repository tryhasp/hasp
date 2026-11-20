import HaspDesign
import HaspQuickAccessCore
import SwiftUI

struct PromptCard: View {
  let title: String
  let message: String
  let primary: String
  let secondary: String
  let onPrimary: () -> Void
  let onSecondary: () -> Void

  var body: some View {
    VStack(spacing: HaspSpace.s12) {
      Text(title).haspText(HaspFont.titleSmall)
      Text(message)
        .haspText(HaspFont.bodyRelaxed)
        .foregroundStyle(HaspColor.textSecondary)
        .multilineTextAlignment(.center)
        .frame(maxWidth: HaspSize.paneWidth / 1.4)
      HStack(spacing: HaspSpace.s10) {
        Button(secondary, action: onSecondary).buttonStyle(PromptButton(prominent: false))
        Button(primary, action: onPrimary).buttonStyle(PromptButton(prominent: true))
      }
      .padding(.top, HaspSpace.s4)
    }
    .padding(HaspSpace.s24)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(HaspColor.window)
    .foregroundStyle(HaspColor.text)
    .accessibilityElement(children: .contain)
  }
}

struct PromptButton: ButtonStyle {
  let prominent: Bool

  func makeBody(configuration: Configuration) -> some View {
    configuration.label
      .haspText(HaspFont.bodyMedium)
      .foregroundStyle(prominent ? HaspColor.onInk : HaspColor.text)
      .padding(.horizontal, HaspSpace.s16)
      .frame(height: HaspSize.controlHeightConfirm)
      .background(
        prominent ? HaspColor.ink : HaspColor.chip,
        in: RoundedRectangle(cornerRadius: HaspRadius.control),
      )
      .opacity(configuration.isPressed ? 0.85 : 1)
  }
}

struct ActionsOverlay: View {
  var body: some View {
    VStack(alignment: .leading, spacing: HaspSpace.s8) {
      Text(Strings.actionsTitle).haspText(HaspFont.bodyStrong)
      ForEach(
        QuickAction.allCases.filter { $0 != .showAllActions },
        id: \.self,
      ) { action in
        HStack(spacing: HaspSpace.s12) {
          Keycap(label: action.shortcutLabel)
          Text(Strings.label(action)).haspText(HaspFont.body)
        }
      }
    }
    .padding(HaspSpace.s20)
    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    .background(HaspColor.window)
    .foregroundStyle(HaspColor.text)
    .accessibilityElement(children: .contain)
  }
}

struct ToastView: View {
  let message: String

  var body: some View {
    Text(message)
      .haspText(HaspFont.bodyMedium)
      .foregroundStyle(HaspColor.onInk)
      .padding(.horizontal, HaspSpace.s16)
      .frame(height: HaspSize.toastHeight)
      .background(HaspColor.ink, in: RoundedRectangle(cornerRadius: HaspRadius.toast))
      .accessibilityAddTraits(.isStaticText)
  }
}
