#if os(iOS)
  import HaspDesign
  import SwiftUI

  enum MobileMetrics {
    static let touchTarget: CGFloat = 44
    static let fieldHeight: CGFloat = 50
    static let buttonHeight: CGFloat = 52
    static let formWidth: CGFloat = 520
  }

  struct MobileSectionHeader: View {
    let title: LocalizedStringKey

    init(_ title: LocalizedStringKey) { self.title = title }

    var body: some View {
      Text(title)
        .haspText(HaspFont.caption)
        .foregroundStyle(HaspColor.textSecondary)
        .textCase(nil)
        .accessibilityAddTraits(.isHeader)
    }
  }

  struct MobilePrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
      configuration.label
        .haspText(HaspFont.bodyMedium)
        .foregroundStyle(isEnabled ? HaspColor.onAccent : HaspColor.textSecondary)
        .frame(maxWidth: .infinity, minHeight: MobileMetrics.buttonHeight)
        .background(
          isEnabled ? HaspColor.accent.opacity(configuration.isPressed ? 0.85 : 1) : HaspColor.chip,
          in: RoundedRectangle(cornerRadius: HaspRadius.field),
        )
    }
  }

  struct MobileSecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
      configuration.label
        .haspText(HaspFont.bodyMedium)
        .foregroundStyle(HaspColor.text)
        .frame(maxWidth: .infinity, minHeight: MobileMetrics.touchTarget)
        .background(
          configuration.isPressed ? HaspColor.chip : HaspColor.field,
          in: RoundedRectangle(cornerRadius: HaspRadius.field),
        )
        .overlay(
          RoundedRectangle(cornerRadius: HaspRadius.field)
            .stroke(HaspColor.controlBorder, lineWidth: HaspBorder.hairline)
        )
    }
  }

  struct MobileFieldModifier: ViewModifier {
    func body(content: Content) -> some View {
      content
        .textFieldStyle(.plain)
        .haspText(HaspFont.bodyLarge)
        .padding(.horizontal, HaspSpace.s14)
        .frame(minHeight: MobileMetrics.fieldHeight)
        .background(HaspColor.field, in: RoundedRectangle(cornerRadius: HaspRadius.field))
        .overlay(
          RoundedRectangle(cornerRadius: HaspRadius.field)
            .stroke(HaspColor.controlBorder, lineWidth: HaspBorder.hairline)
        )
    }
  }

  extension View {
    func mobileField() -> some View {
      modifier(MobileFieldModifier())
    }
  }

  struct MobileIconButton: View {
    let systemName: String
    let label: LocalizedStringKey
    var identifier = ""
    let action: () -> Void

    var body: some View {
      Button(action: action) {
        Image(systemName: systemName)
          .font(.system(size: HaspSize.icon))
          .foregroundStyle(HaspColor.textSecondary)
          .frame(width: MobileMetrics.touchTarget, height: MobileMetrics.touchTarget)
          .contentShape(Rectangle())
      }
      .buttonStyle(.plain)
      .accessibilityLabel(label)
      .accessibilityIdentifier(identifier)
    }
  }

  struct PrivacyShield: View {
    var body: some View {
      HaspColor.window
        .ignoresSafeArea()
        .overlay { HaspMark() }
        .accessibilityHidden(true)
    }
  }
#endif
