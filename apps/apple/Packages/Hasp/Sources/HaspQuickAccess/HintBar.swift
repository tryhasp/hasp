import HaspDesign
import HaspQuickAccessCore
import SwiftUI

struct HintBar: View {
  var body: some View {
    HStack(spacing: HaspSpace.s16) {
      hint(.fill)
      hint(.copyPassword)
      hint(.copyOTP)
      Spacer(minLength: 0)
      hint(.showAllActions)
      hint(.close)
    }
    .padding(.horizontal, HaspSpace.s18)
    .frame(height: HaspSize.quickAccessHintHeight)
    .background(HaspColor.group)
    .overlay(alignment: .top) { HaspColor.separator.frame(height: HaspBorder.hairline) }
  }

  private func hint(_ action: QuickAction) -> some View {
    HStack(spacing: HaspSpace.s6) {
      Keycap(label: action.shortcutLabel)
      Text(Strings.label(action)).haspText(HaspFont.caption)
    }
    .foregroundStyle(HaspColor.textSecondary)
    .lineLimit(1)
    .fixedSize()
    .accessibilityElement(children: .combine)
  }
}
