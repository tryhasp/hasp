import HaspDesign
import SwiftUI

struct ToastView: View {
  let message: String

  var body: some View {
    HStack(spacing: HaspSpace.s8) {
      Image(systemName: "checkmark")
        .accessibilityHidden(true)
      Text(message)
    }
    .haspText(HaspFont.bodyMedium)
    .foregroundStyle(HaspColor.onInk)
    .padding(.horizontal, HaspSpace.s16)
    .frame(minHeight: HaspSize.toastHeight)
    .background(HaspColor.ink, in: RoundedRectangle(cornerRadius: HaspRadius.toast))
    .accessibilityElement(children: .combine)
    .accessibilityAddTraits(.isStaticText)
  }
}

struct TickRow: View {
  let remaining: Int
  let period: Int

  var body: some View {
    HStack(alignment: .bottom, spacing: HaspSize.tickGap) {
      ForEach(0..<Int(HaspSize.tickCount), id: \.self) { index in
        RoundedRectangle(cornerRadius: HaspRadius.tick)
          .fill(index < litTicks ? HaspColor.accent : HaspColor.tickOff)
          .frame(
            width: HaspSize.tickWidth,
            height: index < litTicks ? HaspSize.tickHeight : HaspSize.tickHeightOff,
          )
      }
    }
    .accessibilityHidden(true)
  }

  private var litTicks: Int {
    guard period > 0 else { return 0 }
    return Int((Double(remaining) / Double(period) * HaspSize.tickCount).rounded(.up))
  }
}
