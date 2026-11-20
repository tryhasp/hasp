import HaspDesign
import SwiftUI

struct HaspPrimaryButtonStyle: ButtonStyle {
  @Environment(\.isEnabled) private var isEnabled

  func makeBody(configuration: Configuration) -> some View {
    configuration.label
      .haspText(HaspFont.bodyMedium)
      .foregroundStyle(HaspColor.onAccent)
      .frame(maxWidth: .infinity, minHeight: HaspSize.controlHeightLarge)
      .background(
        HaspColor.accent.opacity(isEnabled ? (configuration.isPressed ? 0.85 : 1) : 0.5),
        in: RoundedRectangle(cornerRadius: HaspRadius.field),
      )
  }
}

struct HaspBorderedButtonStyle: ButtonStyle {
  func makeBody(configuration: Configuration) -> some View {
    configuration.label
      .haspText(HaspFont.bodyMedium)
      .foregroundStyle(HaspColor.text)
      .padding(.horizontal, HaspSpace.s12)
      .frame(minHeight: HaspSize.controlHeight)
      .background(
        configuration.isPressed ? HaspColor.chip : HaspColor.field,
        in: RoundedRectangle(cornerRadius: HaspRadius.control),
      )
      .overlay(
        RoundedRectangle(cornerRadius: HaspRadius.control)
          .stroke(HaspColor.controlBorder, lineWidth: HaspBorder.hairline)
      )
  }
}

struct HaspFieldModifier: ViewModifier {
  func body(content: Content) -> some View {
    content
      .textFieldStyle(.plain)
      .haspText(HaspFont.body)
      .padding(.horizontal, HaspSpace.s10)
      .frame(minHeight: HaspSize.controlHeightSettings)
      .background(HaspColor.field, in: RoundedRectangle(cornerRadius: HaspRadius.field))
      .overlay(
        RoundedRectangle(cornerRadius: HaspRadius.field)
          .stroke(HaspColor.controlBorder, lineWidth: HaspBorder.hairline)
      )
  }
}

extension View {
  func haspField() -> some View {
    modifier(HaspFieldModifier())
  }
}

struct IconButton: View {
  let systemName: String
  let label: LocalizedStringKey
  var identifier = ""
  let action: () -> Void

  var body: some View {
    Button(action: action) {
      Image(systemName: systemName)
        .font(.system(size: HaspSize.icon))
        .foregroundStyle(HaspColor.textSecondary)
        .frame(width: HaspSize.iconButton, height: HaspSize.iconButton)
        .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
    .accessibilityLabel(label)
    .accessibilityIdentifier(identifier)
    .help(label)
  }
}

enum HaspSymbol {
  static let copy = "square.on.square"
}
