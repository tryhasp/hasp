import HaspDesign
import SwiftUI

struct HaspMark: View {
  var body: some View {
    ZStack {
      RoundedRectangle(cornerRadius: HaspRadius.mark)
        .fill(HaspColor.sidebar)
      RoundedRectangle(cornerRadius: HaspRadius.mark)
        .stroke(HaspColor.separator, lineWidth: HaspBorder.hairline)
      VStack(spacing: 0) {
        clasp(height: HaspSize.iconMark * 0.42)
          .overlay(
            Capsule().fill(HaspColor.accent).frame(
              width: HaspSpace.s14,
              height: HaspBorder.emphasis,
            )
          )
        Rectangle().fill(HaspColor.accent).frame(width: HaspBorder.emphasis, height: HaspSpace.s4)
        clasp(height: HaspSize.iconMark * 0.28)
      }
    }
    .frame(width: HaspSize.markSize, height: HaspSize.markSize)
    .accessibilityHidden(true)
  }

  private func clasp(height: CGFloat) -> some View {
    RoundedRectangle(cornerRadius: HaspRadius.chip)
      .stroke(HaspColor.accent, lineWidth: HaspBorder.emphasis)
      .frame(width: HaspSize.iconMark * 0.72, height: height)
  }
}
