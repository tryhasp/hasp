import HaspDesign
import SwiftUI

struct MonogramTile: View {
  let title: String
  var size: CGFloat = HaspSize.tile
  var selected = false

  private var hue: Double {
    let sum = title.unicodeScalars.reduce(0) { ($0 &* 31 &+ Int($1.value)) % 360 }
    return Double(sum)
  }

  var body: some View {
    Text(String(title.first ?? "?").uppercased())
      .haspText(size > HaspSize.tile ? HaspFont.tileLetterHeader : HaspFont.tileLetter)
      .foregroundStyle(selected ? HaspColor.onAccent : HaspTile.foregroundColor(hue: hue))
      .frame(width: size, height: size)
      .background(
        selected ? HaspColor.accent : HaspTile.backgroundColor(hue: hue),
        in: RoundedRectangle(cornerRadius: HaspRadius.tile),
      )
      .accessibilityHidden(true)
  }
}
